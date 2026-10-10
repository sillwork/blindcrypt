package io.github.sillwork.blindcrypt.spring.migration;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Re-encrypts rows in batches for key rotation and legacy data migration, updating each row by {@code id} and {@code version}.
 * <p>
 * When rotating cryptographic keys or populating blind indexes on legacy tables,
 * updating rows one at a time through the ORM issues one statement per row.
 * This service provides:
 * <ul>
 *   <li><b>PostgreSQL Vectorized Updates</b>: sends the whole list passed to one call as parallel
 *       {@code UNNEST(?::type[])} arrays in a single {@code UPDATE} statement, with optimistic concurrency control.
 *       The service does not split the list; callers choose the batch size.</li>
 *   <li><b>Standard JDBC Batch Updates</b>: Multi-database fallback for MySQL, MariaDB, Oracle, SQL Server, and H2.</li>
 *   <li>Support for both binary ({@link io.github.sillwork.blindcrypt.spring.model.EncryptedBytes}) and textual ({@link io.github.sillwork.blindcrypt.spring.model.EncryptedText}) data layouts.</li>
 * </ul>
 */
public class VectorizedReEncryptionService {

    private static final Pattern IDENTIFIER_PATTERN = Pattern.compile("^[a-zA-Z_]\\w*$");
    private static final String TYPE_BIGINT = "bigint";
    private static final String TYPE_BYTEA = "bytea";
    private static final String TYPE_VARCHAR = "varchar";

    private final JdbcTemplate jdbcTemplate;

    /**
     * Constructs a VectorizedReEncryptionService.
     *
     * @param jdbcTemplate the Spring {@link JdbcTemplate} to execute SQL operations
     */
    public VectorizedReEncryptionService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate cannot be null");
    }

    private static void validateSqlIdentifier(String identifier) {
        if (identifier == null || !IDENTIFIER_PATTERN.matcher(identifier).matches()) {
            throw new IllegalArgumentException("Invalid SQL identifier: " + identifier);
        }
    }

    /**
     * Executes a vectorized batch update on PostgreSQL using {@code UNNEST(?::type[])}.
     *
     * @param tableName   the database table name (e.g. {@code "users"})
     * @param valueColumn the name of the column storing the ciphertext (e.g. {@code "email"})
     * @param bidxColumn  the name of the column storing the blind index (e.g. {@code "email_bidx"})
     * @param updates     the list of row updates to apply
     * @return the number of database rows successfully updated
     */
    @SuppressWarnings("java:S2077") // Table and column identifiers are strictly validated against alphanumeric pattern by validateSqlIdentifier
    public int updatePostgreSqlVectorized(String tableName, String valueColumn, String bidxColumn, List<RowUpdate> updates) {
        if (updates == null || updates.isEmpty()) return 0;
        validateSqlIdentifier(tableName);
        validateSqlIdentifier(valueColumn);
        validateSqlIdentifier(bidxColumn);

        int batchSize = updates.size();

        Long[] recordIds = new Long[batchSize];
        Long[] expectedVersions = new Long[batchSize];
        byte[][] encryptedValues = new byte[batchSize][];
        byte[][] blindIndexes = new byte[batchSize][];

        for (int i = 0; i < batchSize; i++) {
            RowUpdate rowUpdate = updates.get(i);
            recordIds[i] = rowUpdate.id();
            expectedVersions[i] = rowUpdate.expectedVersion();
            encryptedValues[i] = rowUpdate.encryptedValue();
            blindIndexes[i] = rowUpdate.blindIndex();
        }

        String sql = """
            UPDATE %s AS target_table
            SET %s = unnested_data.new_value,
                %s = unnested_data.new_bidx,
                version = target_table.version + 1
            FROM (
                SELECT UNNEST(?::bigint[]) AS id,
                       UNNEST(?::bigint[]) AS expected_version,
                       UNNEST(?::bytea[])  AS new_value,
                       UNNEST(?::bytea[])  AS new_bidx
            ) AS unnested_data
            WHERE target_table.id = unnested_data.id AND target_table.version = unnested_data.expected_version
            """.formatted(tableName, valueColumn, bidxColumn);

        Integer result = jdbcTemplate.execute((Connection connection) -> {
            try (PreparedStatement preparedStatement = connection.prepareStatement(sql)) {
                preparedStatement.setArray(1, connection.createArrayOf(TYPE_BIGINT, recordIds));
                preparedStatement.setArray(2, connection.createArrayOf(TYPE_BIGINT, expectedVersions));
                preparedStatement.setArray(3, connection.createArrayOf(TYPE_BYTEA, encryptedValues));
                preparedStatement.setArray(4, connection.createArrayOf(TYPE_BYTEA, blindIndexes));
                return preparedStatement.executeUpdate();
            }
        });
        return result != null ? result : 0;
    }

    /**
     * Overload for backwards compatibility defaulting to "email" and "email_bidx" columns.
     *
     * @param tableName the database table name
     * @param updates   the list of row updates
     * @return the number of updated rows
     */
    public int updatePostgreSqlVectorized(String tableName, List<RowUpdate> updates) {
        return updatePostgreSqlVectorized(tableName, "email", "email_bidx", updates);
    }

    /**
     * Executes standard parameterized JDBC batch updates for binary encrypted columns ({@code byte[]}).
     * Compatible with PostgreSQL, MySQL, MariaDB, Oracle, Microsoft SQL Server, and H2.
     *
     * @param tableName   the database table name
     * @param valueColumn the name of the column storing binary ciphertext
     * @param bidxColumn  the name of the column storing the binary blind index
     * @param updates     the list of binary row updates
     * @return the total number of updated rows across batches
     */
    @SuppressWarnings("java:S2077") // Table and column identifiers are strictly validated against alphanumeric pattern by validateSqlIdentifier
    public int updateStandardBatch(String tableName, String valueColumn, String bidxColumn, List<RowUpdate> updates) {
        if (updates == null || updates.isEmpty()) return 0;
        validateSqlIdentifier(tableName);
        validateSqlIdentifier(valueColumn);
        validateSqlIdentifier(bidxColumn);

        String sql = "UPDATE " + tableName + " SET " + valueColumn + " = ?, " + bidxColumn 
                + " = ?, version = version + 1 WHERE id = ? AND version = ?";

        int[][] batchResults = jdbcTemplate.batchUpdate(sql, updates, updates.size(), (preparedStatement, rowUpdate) -> {
            preparedStatement.setBytes(1, rowUpdate.encryptedValue());
            preparedStatement.setBytes(2, rowUpdate.blindIndex());
            preparedStatement.setLong(3, rowUpdate.id());
            preparedStatement.setLong(4, rowUpdate.expectedVersion());
        });

        int totalRowsUpdated = 0;
        for (int[] batchResult : batchResults) {
            for (int count : batchResult) {
                if (count > 0) {
                    totalRowsUpdated += count;
                } else if (count == Statement.SUCCESS_NO_INFO) {
                    totalRowsUpdated += 1;
                }
            }
        }
        return totalRowsUpdated;
    }

    /**
     * Executes standard parameterized JDBC batch updates for textual encrypted columns ({@link String}).
     * Compatible with PostgreSQL, MySQL, MariaDB, Oracle, Microsoft SQL Server, and H2.
     *
     * @param tableName   the database table name
     * @param valueColumn the name of the column storing textual ciphertext
     * @param bidxColumn  the name of the column storing the textual blind index
     * @param updates     the list of text row updates
     * @return the total number of updated rows across batches
     */
    @SuppressWarnings("java:S2077") // Table and column identifiers are strictly validated against alphanumeric pattern by validateSqlIdentifier
    public int updateStandardTextBatch(String tableName, String valueColumn, String bidxColumn, List<TextRowUpdate> updates) {
        if (updates == null || updates.isEmpty()) return 0;
        validateSqlIdentifier(tableName);
        validateSqlIdentifier(valueColumn);
        validateSqlIdentifier(bidxColumn);

        String sql = "UPDATE " + tableName + " SET " + valueColumn + " = ?, " + bidxColumn 
                + " = ?, version = version + 1 WHERE id = ? AND version = ?";

        int[][] batchResults = jdbcTemplate.batchUpdate(sql, updates, updates.size(), (preparedStatement, textUpdate) -> {
            preparedStatement.setString(1, textUpdate.encryptedValue());
            preparedStatement.setString(2, textUpdate.blindIndex());
            preparedStatement.setLong(3, textUpdate.id());
            preparedStatement.setLong(4, textUpdate.expectedVersion());
        });

        int totalRowsUpdated = 0;
        for (int[] batchResult : batchResults) {
            for (int count : batchResult) {
                if (count > 0) {
                    totalRowsUpdated += count;
                } else if (count == Statement.SUCCESS_NO_INFO) {
                    totalRowsUpdated += 1;
                }
            }
        }
        return totalRowsUpdated;
    }

    /**
     * Executes a vectorized batch update on PostgreSQL for textual columns using {@code UNNEST(?::type[])}.
     *
     * @param tableName   the database table name (e.g. {@code "users"})
     * @param valueColumn the name of the column storing the ciphertext (e.g. {@code "email"})
     * @param bidxColumn  the name of the column storing the blind index (e.g. {@code "email_bidx"})
     * @param updates     the list of text row updates to apply
     * @return the number of database rows successfully updated
     */
    @SuppressWarnings("java:S2077") // Table and column identifiers are strictly validated against alphanumeric pattern by validateSqlIdentifier
    public int updatePostgreSqlTextVectorized(String tableName, String valueColumn, String bidxColumn, List<TextRowUpdate> updates) {
        if (updates == null || updates.isEmpty()) return 0;
        validateSqlIdentifier(tableName);
        validateSqlIdentifier(valueColumn);
        validateSqlIdentifier(bidxColumn);

        int batchSize = updates.size();

        Long[] recordIds = new Long[batchSize];
        Long[] expectedVersions = new Long[batchSize];
        String[] encryptedValues = new String[batchSize];
        String[] blindIndexes = new String[batchSize];

        for (int i = 0; i < batchSize; i++) {
            TextRowUpdate textUpdate = updates.get(i);
            recordIds[i] = textUpdate.id();
            expectedVersions[i] = textUpdate.expectedVersion();
            encryptedValues[i] = textUpdate.encryptedValue();
            blindIndexes[i] = textUpdate.blindIndex();
        }

        String sql = """
            UPDATE %s AS target_table
            SET %s = unnested_data.new_value,
                %s = unnested_data.new_bidx,
                version = target_table.version + 1
            FROM (
                SELECT UNNEST(?::bigint[])  AS id,
                       UNNEST(?::bigint[])  AS expected_version,
                       UNNEST(?::varchar[]) AS new_value,
                       UNNEST(?::varchar[]) AS new_bidx
            ) AS unnested_data
            WHERE target_table.id = unnested_data.id AND target_table.version = unnested_data.expected_version
            """.formatted(tableName, valueColumn, bidxColumn);

        Integer result = jdbcTemplate.execute((Connection connection) -> {
            try (PreparedStatement preparedStatement = connection.prepareStatement(sql)) {
                preparedStatement.setArray(1, connection.createArrayOf(TYPE_BIGINT, recordIds));
                preparedStatement.setArray(2, connection.createArrayOf(TYPE_BIGINT, expectedVersions));
                preparedStatement.setArray(3, connection.createArrayOf(TYPE_VARCHAR, encryptedValues));
                preparedStatement.setArray(4, connection.createArrayOf(TYPE_VARCHAR, blindIndexes));
                return preparedStatement.executeUpdate();
            }
        });
        return result != null ? result : 0;
    }

    /**
     * Overload for text PostgreSQL vectorized batch updates defaulting to "email" and "email_bidx" columns.
     *
     * @param tableName the database table name
     * @param updates   the list of text row updates
     * @return the number of updated rows
     */
    public int updatePostgreSqlTextVectorized(String tableName, List<TextRowUpdate> updates) {
        return updatePostgreSqlTextVectorized(tableName, "email", "email_bidx", updates);
    }

    /**
     * Represents a single entity binary row re-encryption payload.
     *
     * @param id              the database primary key
     * @param expectedVersion the expected entity version for optimistic locking protection
     * @param encryptedValue  the newly re-encrypted binary ciphertext
     * @param blindIndex      the newly computed raw binary blind index
     */
    public record RowUpdate(long id, long expectedVersion, byte[] encryptedValue, byte[] blindIndex) {
        /** Canonical constructor; defensively copies both byte arrays. */
        public RowUpdate {
            encryptedValue = encryptedValue != null ? encryptedValue.clone() : null;
            blindIndex = blindIndex != null ? blindIndex.clone() : null;
        }

        /**
         * Returns a defensive copy of the ciphertext.
         *
         * @return a copy of the encrypted value, or {@code null}
         */
        @Override
        public byte[] encryptedValue() {
            return encryptedValue != null ? encryptedValue.clone() : null;
        }

        /**
         * Returns a defensive copy of the blind index.
         *
         * @return a copy of the blind index, or {@code null}
         */
        @Override
        public byte[] blindIndex() {
            return blindIndex != null ? blindIndex.clone() : null;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o instanceof RowUpdate(long otherId, long otherExpectedVersion, byte[] otherEncryptedValue, byte[] otherBlindIndex)) {
                return id == otherId &&
                       expectedVersion == otherExpectedVersion &&
                       Arrays.equals(encryptedValue, otherEncryptedValue) &&
                       Arrays.equals(blindIndex, otherBlindIndex);
            }
            return false;
        }

        @Override
        public int hashCode() {
            int result = Long.hashCode(id);
            result = 31 * result + Long.hashCode(expectedVersion);
            result = 31 * result + Arrays.hashCode(encryptedValue);
            result = 31 * result + Arrays.hashCode(blindIndex);
            return result;
        }

        @Override
        public String toString() {
            return "RowUpdate[id=" + id + ", expectedVersion=" + expectedVersion +
                   ", encryptedValue=" + Arrays.toString(encryptedValue) +
                   ", blindIndex=" + Arrays.toString(blindIndex) + "]";
        }
    }

    /**
     * Represents a single entity text row re-encryption payload.
     *
     * @param id              the database primary key
     * @param expectedVersion the expected entity version for optimistic locking protection
     * @param encryptedValue  the newly re-encrypted textual ciphertext (e.g. {@code "ENC:v2:..."})
     * @param blindIndex      the newly computed hexadecimal blind index
     */
    public record TextRowUpdate(long id, long expectedVersion, String encryptedValue, String blindIndex) { }
}
