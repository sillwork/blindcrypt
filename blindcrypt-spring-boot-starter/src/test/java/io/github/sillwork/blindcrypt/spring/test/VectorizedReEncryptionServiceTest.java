package io.github.sillwork.blindcrypt.spring.test;

import io.github.sillwork.blindcrypt.spring.migration.VectorizedReEncryptionService;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SpringBootTest(classes = TestApplication.class)
class VectorizedReEncryptionServiceTest {

    @Autowired
    private VectorizedReEncryptionService reEncryptionService;

    @Autowired
    private TestUserRepository userRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void cleanUp() {
        userRepository.deleteAll();
    }

    @Test
    void testStandardTextBatchUpdateSucceedsWithOptimisticLocking() {
        TestUser user = new TestUser("Alice Smith", "alice@company.com", "1112223333", "REG-801");
        TestUser saved = userRepository.saveAndFlush(user);
        Long userId = saved.getId();
        Long initialVersion = 0L;

        String newCiphertext = "ENC:v2:RE_ENCRYPTED_TEXT_PAYLOAD";
        String newBlindIndex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        var update = new VectorizedReEncryptionService.TextRowUpdate(
                userId, initialVersion, newCiphertext, newBlindIndex);

        int updatedCount = reEncryptionService.updateStandardTextBatch(
                "test_users", "email", "email_bidx", List.of(update));

        assertThat(updatedCount).isEqualTo(1);

        Map<String, Object> raw = jdbcTemplate.queryForMap(
                "SELECT email, email_bidx, version FROM test_users WHERE id = ?", userId);

        assertThat(raw)
                .containsEntry("email", newCiphertext)
                .containsEntry("email_bidx", newBlindIndex);
        assertThat(((Number) raw.get("version")).longValue()).isEqualTo(1L);
    }

    @Test
    void testOptimisticLockingMismatchFailsGracefully() {
        TestUser user = new TestUser("Bob Jones", "bob@company.com", "4445556666", "REG-802");
        TestUser saved = userRepository.saveAndFlush(user);
        Long userId = saved.getId();
        Long staleVersion = 999L; // Mismatched version

        var update = new VectorizedReEncryptionService.TextRowUpdate(
                userId, staleVersion, "ENC:v2:STALE", "0000000000000000000000000000000000000000000000000000000000000000");

        int updatedCount = reEncryptionService.updateStandardTextBatch(
                "test_users", "email", "email_bidx", List.of(update));

        assertThat(updatedCount).isZero();
    }

    @Test
    void testRowUpdateRecordMethods() {
        byte[] enc = new byte[]{1, 2, 3};
        byte[] bidx = new byte[]{4, 5, 6};

        var row1 = new VectorizedReEncryptionService.RowUpdate(10L, 0L, enc, bidx);
        var row2 = new VectorizedReEncryptionService.RowUpdate(10L, 0L, enc, bidx);
        var row3 = new VectorizedReEncryptionService.RowUpdate(20L, 0L, enc, bidx);
        var rowNull = new VectorizedReEncryptionService.RowUpdate(30L, 0L, null, null);

        assertThat(row1).isEqualTo(row2).hasSameHashCodeAs(row2).isNotEqualTo(row3).isNotEqualTo(rowNull);
        assertThat(row1.toString()).contains("RowUpdate");
        assertThat(row1.encryptedValue()).isEqualTo(enc);
        assertThat(row1.blindIndex()).isEqualTo(bidx);
        assertThat(rowNull.encryptedValue()).isNull();
        assertThat(rowNull.blindIndex()).isNull();
    }

    @Test
    void testStandardTextBatchEmptyAndInvalidValidation() {
        List<VectorizedReEncryptionService.TextRowUpdate> empty = List.of();
        assertThat(reEncryptionService.updateStandardTextBatch("test_users", "email", "email_bidx", empty)).isZero();
        assertThat(reEncryptionService.updateStandardTextBatch("test_users", "email", "email_bidx", null)).isZero();

        var update = new VectorizedReEncryptionService.TextRowUpdate(1L, 0L, "val", "bidx");
        List<VectorizedReEncryptionService.TextRowUpdate> list = List.of(update);
        assertThatThrownBy(() ->
                reEncryptionService.updateStandardTextBatch("invalid table!", "email", "email_bidx", list)
        ).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testPostgreSqlVectorizedBatchUpdates() throws Exception {
        JdbcTemplate mockJdbc = mock(JdbcTemplate.class);
        Connection mockConn = mock(Connection.class);
        PreparedStatement mockPs = mock(PreparedStatement.class);

        when(mockConn.prepareStatement(anyString())).thenReturn(mockPs);
        when(mockPs.executeUpdate()).thenReturn(1);
        when(mockJdbc.execute(any(ConnectionCallback.class))).thenAnswer(invocation -> {
            ConnectionCallback<?> callback = invocation.getArgument(0);
            return callback.doInConnection(mockConn);
        });

        VectorizedReEncryptionService service = new VectorizedReEncryptionService(mockJdbc);

        var rowUpdate = new VectorizedReEncryptionService.RowUpdate(1L, 0L, new byte[]{1}, new byte[]{2});
        List<VectorizedReEncryptionService.RowUpdate> rowList = List.of(rowUpdate);

        int count1 = service.updatePostgreSqlVectorized("users", "email", "email_bidx", rowList);
        int count2 = service.updatePostgreSqlVectorized("users", rowList);
        assertThat(count1).isEqualTo(1);
        assertThat(count2).isEqualTo(1);

        var textUpdate = new VectorizedReEncryptionService.TextRowUpdate(1L, 0L, "enc", "bidx");
        List<VectorizedReEncryptionService.TextRowUpdate> textList = List.of(textUpdate);

        int count3 = service.updatePostgreSqlTextVectorized("users", "email", "email_bidx", textList);
        int count4 = service.updatePostgreSqlTextVectorized("users", textList);
        assertThat(count3).isEqualTo(1);
        assertThat(count4).isEqualTo(1);

        // Empty and null handling
        List<VectorizedReEncryptionService.RowUpdate> emptyRows = List.of();
        assertThat(service.updatePostgreSqlVectorized("users", emptyRows)).isZero();
        assertThat(service.updatePostgreSqlVectorized("users", null)).isZero();

        List<VectorizedReEncryptionService.TextRowUpdate> emptyTexts = List.of();
        assertThat(service.updatePostgreSqlTextVectorized("users", emptyTexts)).isZero();
        assertThat(service.updatePostgreSqlTextVectorized("users", null)).isZero();
    }
}
