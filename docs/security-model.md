# Security Model

[Back to README](../README.md)


| Threat / Pitfall | BlindCrypt Countermeasure |
| :--- | :--- |
| **Plaintext written by a mis-mapped field** | At startup, BlindCrypt checks Hibernate's runtime mapping and refuses to start if any `@Encrypted` attribute is not converted by the BlindCrypt converter. |
| **Tampered ciphertext** | AES-256-GCM authentication rejects modified ciphertext with `CryptoException`. For `String` columns this also holds when `allow-plaintext-read` is on (see [Limitations](../README.md#limitations) for `byte[]`). |
| **Empty Normalization** | A value that normalizes to an empty string is rejected with `CryptoException`, so no index is written for it. |
| **Hibernate `@DynamicUpdate` Desynchronization** | The startup validator rejects `@DynamicUpdate` on entities with blind indexes. |
| **Silent EntityListener Omission** | At startup, the validator checks that every entity with `@BlindIndex` declares `@EntityListeners(BlindIndexListener.class)`. |
| **Unsupported JPA Query Annotations** | `QueryMethodValidator` rejects `@Lock`, `@EntityGraph` and `@QueryHints` on blind-index query methods at startup. |
| **Multi-Persistence Unit Routing** | `DynamicEntityManagerFactoryResolver` selects the `EntityManagerFactory` that owns the repository's entity. |
| **Unique Constraint Collisions** | Declare a unique database index on the blind index column (see `ux_users_ssn_bidx`). The database enforces uniqueness on the hash. |
| **Driver Log Leakage** | The recommended logging configuration silences Hibernate bind and `SqlExceptionHelper` output so blind index values are not logged. |
| **`ThreadLocal<Cipher>` Growth Under Many Threads** | `StripedCipherPool` shares a bounded set of `Cipher` instances (16 stripes, 64 idle ciphers each) instead of one per thread. |
| **Direct Navigation of Internal Attributes** | `QueryMethodValidator` rejects repository methods that target `encryptedValue` or `blindIndex` directly, and methods that query an `@Encrypted` field that has no `@BlindIndex`. |
| **Secrets in error messages** | Exception messages name the property, entity or method but never include plaintext, key material or blind index hashes. |

For threats BlindCrypt does not cover, see [Limitations](../README.md#limitations).


