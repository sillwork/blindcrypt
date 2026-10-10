# How BlindCrypt Works

[Back to README](../README.md)

## The problem

Strong encryption and database lookups pull in opposite directions:

- AES-256-GCM uses a fresh random IV for every write, so `alice@corp.com` produces a different ciphertext each time. That is what makes it secure.
- A database index finds rows by comparing stored values. Different ciphertexts for the same email never match, so `WHERE email = ?` cannot work on the encrypted column.
- Decrypting every row to search it means a full table scan on every query.

## The approach

BlindCrypt stores each searchable value in two columns:

1. **Ciphertext column (`field`)**: Each value is encrypted with AES-256-GCM using a fresh random 12-byte IV.
2. **Blind index column (`field_bidx`)**: A one-way, keyed blind index computed with **HMAC-SHA256** and a subkey derived per index name. `EncryptedText` stores it as a 64-character lowercase hex string (`VARCHAR(64)`). `EncryptedBytes` stores it as 32 raw bytes (`BYTEA` / `BINARY(32)`). Either form can be indexed by a standard database B-Tree. The index key is separate from the encryption keys, so a leaked index key does not decrypt ciphertext.

```
                      +---------------------------------------+
                      | Application Service (Java 21)         |
                      +---------------------------------------+
                                          │
                  Plaintext: "  Alex.Morgan@Company.COM  "
                                          │
                    ┌─────────────────────┴─────────────────────┐
                    ▼                                           ▼
      +---------------------------+               +---------------------------+
      |      FieldEncryptor       |               |     UltraBlindIndexer     |
      |   (AES-256-GCM)           |               | (Normalize + HMAC-SHA256) |
      +---------------------------+               +---------------------------+
                    │                                           │
         Randomized Ciphertext                      Deterministic HMAC-SHA256
         "ENC:v1:a8f12..." (Unique)                 3f9a62...c1 (64 hex chars)
                    │                                           │
                    └─────────────────────┬─────────────────────┘
                                          ▼
                      +---------------------------------------+
                      | Relational Database (PostgreSQL/MySQL)|
                      |  • email:      VARCHAR(512)           |
                      |  • email_bidx: VARCHAR(64)            |  <-- B-Tree indexed
                      +---------------------------------------+
```


## Design Notes

- **`FastNormalizer`**: Normalizes ASCII input in a single pass without allocating, and falls back to Unicode NFKC for non-ASCII input.
- **`UltraBlindIndexer`**: Keeps a prototype `Mac` per registered blind index and creates working instances with `Mac.clone()`, so the HMAC key is not re-initialized on every call.
- **`StripedCipherPool`**: Reuses `Cipher` instances without `ThreadLocal`. The pool holds 16 `ConcurrentLinkedQueue` stripes selected by thread id. Each stripe keeps at most 64 idle ciphers. If the selected stripe is empty a new cipher is created, and ciphers returned to a full stripe are discarded.
- **Batch re-encryption**: `VectorizedReEncryptionService` updates rows with PostgreSQL `UPDATE ... FROM UNNEST(...)` (`varchar[]` for `EncryptedText`, `bytea[]` for `EncryptedBytes`) or with a portable JDBC batch. Text and binary columns have separate methods (see below).


## Supported Operational Modes

BlindCrypt supports two complementary operational modes within the same entity:

| Feature | Searchable Encryption | Encryption-Only (No Search) |
| :--- | :--- | :--- |
| **Declaration** | `@BlindIndex private EncryptedText email;` | `@Encrypted private String secretNotes;` |
| **Java Type** | `EncryptedText` or `EncryptedBytes` | Standard Java types (`String`, `byte[]`, etc.) |
| **Database Columns** | **2 columns**: `email` + `email_bidx` | **1 column**: `secret_notes` (ciphertext only) |
| **Search Capability** | Derived queries supported: `findByEmail(plaintext)` | Not searchable |
| **HMAC Overhead** | One HMAC-SHA256 per indexed field per write | None |
| **Index Storage** | 64 characters (`EncryptedText`) or 32 bytes (`EncryptedBytes`), plus the B-Tree index | None (no `_bidx` column, no index) |
| **Information Leakage**| Equal values share a blind index, so equality is visible to anyone who can read the table | No equality leakage (fresh random 12-byte IV per write) |
| **Ideal Use Cases** | Login Email, Phone, SSN, Tax ID, License No. | Secret remarks, Internal notes, Payment CVV, JSON payloads, PDF/image blobs |


## Modules and packages

```
blindcrypt-core                          package io.github.sillwork.blindcrypt.core
│                                        (zero runtime dependencies)
├── KeyRing                              Key versions and subkey derivation
├── FieldEncryptor                       AES-256-GCM field encryption
├── UltraBlindIndexer                    Mac.clone() prototype HMAC engine
├── FastNormalizer, Normalization        Input normalization before hashing
├── StripedCipherPool                    16-stripe Cipher pool without ThreadLocal
├── CompactCiphertextCodec               Binary and text wire codecs
└── BlindCryptException                  Root of CryptoException and BlindCryptConfigurationException

blindcrypt-spring-boot-starter           package io.github.sillwork.blindcrypt.spring
├── annotation/                          @Encrypted, @BlindIndex, @BlindIndexQueries
├── model/                               EncryptedText and EncryptedBytes embeddable value objects
├── config/                              Auto-configuration and blindcrypt.* properties
├── converter/                           EncryptedStringConverter and EncryptedBytesConverter
├── hibernate/                           EncryptedBinder and EncryptedNamingStrategy
├── listener/                            BlindIndexListener, startup validator, EncryptedConverterVerifier
├── repository/                          Derived query rewriter and QueryMethodValidator
├── migration/                           VectorizedReEncryptionService
└── diagnostics/                         Spring Boot failure analysis for misconfiguration
```


