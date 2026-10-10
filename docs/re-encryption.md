# Re-encryption and Key Rotation

[Back to README](../README.md)

## Rotating the encryption key

Every ciphertext records the key version that wrote it (`ENC:v1:...`). New writes use `blindcrypt.active-key-version`; reads use whichever version the value names. To rotate:

1. Add the new key next to the old one and make it active:

   ```yaml
   blindcrypt:
     active-key-version: v2
     keys:
       v1: "<old key>"
       v2: "<new key>"
   ```

2. Re-encrypt existing rows. Saving an entity whose value has not changed does not rewrite it, so use a migration job: read each row, encrypt the plaintext again with `FieldEncryptor.encryptToString(plaintext, null)` (or `encryptToBinary` for `byte[]`), and write the batch with `VectorizedReEncryptionService` as shown below. Pass `null` as the associated data, exactly as the JPA converters do, or the converters cannot read the new values. `FieldEncryptor` always uses the active key. The blind index does not change, because it depends on the separate blind index key.
3. When no row still uses `v1`, remove `blindcrypt.keys.v1`.

Rotating the blind index key is not supported (see [Limitations](../README.md#limitations)).

## Batch updates

For key rotation and legacy data ingestion, BlindCrypt provides `VectorizedReEncryptionService`. Every method updates rows by `id` and `version` (optimistic check) and increments `version`. Table and column names are validated as plain identifiers.

| Column type | PostgreSQL batch (`UNNEST`) | Any database (JDBC batch) |
| :--- | :--- | :--- |
| `EncryptedText` (`VARCHAR` value and `VARCHAR(64)` blind index) | `updatePostgreSqlTextVectorized` with `TextRowUpdate` | `updateStandardTextBatch` |
| `EncryptedBytes` / `byte[]` (`BYTEA` value and `BINARY(32)` blind index) | `updatePostgreSqlVectorized` with `RowUpdate` | `updateStandardBatch` |

The PostgreSQL methods send one statement per call with the whole list as arrays. The statement for text columns:

```sql
UPDATE users AS target_table
SET email = unnested_data.new_value,
    email_bidx = unnested_data.new_bidx,
    version = target_table.version + 1
FROM (
    SELECT UNNEST(?::bigint[])  AS id,
           UNNEST(?::bigint[])  AS expected_version,
           UNNEST(?::varchar[]) AS new_value,
           UNNEST(?::varchar[]) AS new_bidx
) AS unnested_data
WHERE target_table.id = unnested_data.id AND target_table.version = unnested_data.expected_version;
```

For binary columns the same statement is used with `?::bytea[]` for `new_value` and `new_bidx`. The standard methods run `UPDATE ... SET value = ?, bidx = ?, version = version + 1 WHERE id = ? AND version = ?` as a JDBC batch.


