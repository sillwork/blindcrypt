# BlindCrypt

Searchable column encryption for Java 21 and Spring Boot. Encrypt JPA entity fields with AES-256-GCM and still find rows with ordinary repository methods such as `findByEmail`.

[![Java 21+](https://img.shields.io/badge/Java-21%2B-orange.svg)](https://openjdk.org/projects/jdk/21/)
[![Spring Boot 3.3](https://img.shields.io/badge/Spring%20Boot-3.3-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Hibernate 6.5](https://img.shields.io/badge/Hibernate%20ORM-6.5-blue.svg)](https://hibernate.org/orm/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Each searchable value is stored in two columns: the ciphertext, which changes on every write, and a blind index (a keyed HMAC-SHA256 of the normalized value), which is the same for equal values and can be indexed by the database. Queries hash the search value and look up the blind index, so the plaintext never reaches the database.

```
email       ENC:v1:zjqhrDQqpJ9q2av6Rv7nxx9...    (AES-256-GCM, new IV per write)
email_bidx  158e698e35e9717173cd781dd2c18cf3...   (HMAC-SHA256, indexed)
```

## Features

- **`@Encrypted`** on `String` and `byte[]` fields for encrypt-only data.
- **`EncryptedText` / `EncryptedBytes` with `@BlindIndex`** for fields you need to search.
- **`@BlindIndexQueries`** turns derived queries (`findByEmail`, `findByEmailIn`, `existsBy`, `countBy`) into blind index lookups.
- **Fails at startup, not in production**: missing or invalid keys, unsupported mappings, repository methods a blind index cannot answer, and any `@Encrypted` attribute that Hibernate would store without encryption all stop the application with a clear message.
- **Versioned keys** for rotation, with a batch re-encryption helper.
- **Zero-dependency core** (`blindcrypt-core`) usable without Spring.

## Requirements

- Java 21 or later
- Spring Boot 3.3 with Spring Data JPA
- Hibernate ORM 6.5.x (tested). BlindCrypt checks the runtime mapping at startup and refuses to start if encryption is not applied.

## Installation

Maven:

```xml
<dependency>
    <groupId>io.github.sillwork</groupId>
    <artifactId>blindcrypt-spring-boot-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

Gradle:

```groovy
implementation 'io.github.sillwork:blindcrypt-spring-boot-starter:1.0.0'
```

Sources and Javadoc are published with every release, so IntelliJ IDEA and VS Code show the documentation on hover.

## Quick start

### 1. Configure keys

The keys below are examples only. Never use them in a real application: anyone who reads this page can decrypt data written with them. Generate your own with `openssl rand -base64 32` and load them from a secret store or environment variables.

```yaml
blindcrypt:
  active-key-version: v1
  keys:
    v1: "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=" # 32-byte Base64 AES-256 key
  blind-index-key: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=" # 32-byte Base64 HMAC root key

# Keep blind index values out of logs on constraint violations
logging:
  level:
    org.hibernate.orm.jdbc.bind: OFF
    org.hibernate.engine.jdbc.spi.SqlExceptionHelper: OFF
```

### 2. Annotate the entity

```java
import io.github.sillwork.blindcrypt.core.Normalization;
import io.github.sillwork.blindcrypt.spring.annotation.BlindIndex;
import io.github.sillwork.blindcrypt.spring.annotation.Encrypted;
import io.github.sillwork.blindcrypt.spring.listener.BlindIndexListener;
import io.github.sillwork.blindcrypt.spring.model.EncryptedText;
import jakarta.persistence.*;

@Entity
@Table(name = "users", indexes = {
    @Index(name = "ix_users_email_bidx", columnList = "email_bidx"),
    @Index(name = "ux_users_ssn_bidx", columnList = "ssn_bidx", unique = true)
})
@EntityListeners(BlindIndexListener.class)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Version
    private Long version;

    // Searchable: stored in the 'email' and 'email_bidx' columns
    @BlindIndex(name = "user_email", normalization = Normalization.TRIM_CASE_INSENSITIVE)
    private EncryptedText email;

    // Searchable, unique through the index on 'ssn_bidx'
    @BlindIndex(name = "user_ssn", normalization = Normalization.DIGITS_ONLY)
    private EncryptedText ssn;

    // Encrypt-only: one column, no blind index
    @Encrypted
    @Column(name = "secret_notes", length = 4096)
    private String secretNotes;

    protected User() { }

    public User(String email, String ssn, String secretNotes) {
        this.email = EncryptedText.of(email);
        this.ssn = EncryptedText.of(ssn);
        this.secretNotes = secretNotes;
    }

    public String getEmail() { return EncryptedText.valueOf(email); }
    public void setEmail(String email) { this.email = EncryptedText.update(this.email, email); }

    public String getSsn() { return EncryptedText.valueOf(ssn); }
    public void setSsn(String ssn) { this.ssn = EncryptedText.update(this.ssn, ssn); }

    public String getSecretNotes() { return secretNotes; }
    public void setSecretNotes(String notes) { this.secretNotes = notes; }
}
```

Use `EncryptedText.update(...)` in setters: it keeps the existing value when the plaintext is unchanged, so Hibernate does not rewrite the row.

### 3. Declare the repository

```java
import io.github.sillwork.blindcrypt.spring.annotation.BlindIndexQueries;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@BlindIndexQueries
public interface UserRepository extends JpaRepository<User, Long> {

    List<User> findByEmail(String email);                    // WHERE email_bidx = hash(email)
    List<User> findByEmailIn(Collection<String> emails);
    Optional<User> findBySsn(String ssn);
    boolean existsBySsn(String ssn);
}
```

### 4. Query with plaintext

```java
// Normalized and hashed before the query; uses the index on email_bidx
List<User> users = userRepository.findByEmail("  Alex.Morgan@Company.COM  ");
```

Blind index columns are `VARCHAR(64)` for `EncryptedText` and `BYTEA` / `BINARY(32)` for `EncryptedBytes`. See [Database schema](docs/database-schema.md) for DDL and Liquibase examples.

## Configuration

| Property | Default | Description |
| :--- | :--- | :--- |
| `blindcrypt.enabled` | `true` | Set to `false` to start without BlindCrypt. |
| `blindcrypt.active-key-version` | `v1` | Key version used for new writes. Must be `v1` to `v127` and present in `blindcrypt.keys`. |
| `blindcrypt.keys.<version>` | none | Base64-encoded 32-byte AES-256 key per version. Keep old versions until all rows are re-encrypted. |
| `blindcrypt.blind-index-key` | none | Base64-encoded 32-byte HMAC root key. Must differ from every encryption key. |
| `blindcrypt.allow-plaintext-read` | `false` | Migration only. Returns stored values without the `ENC:` header unchanged. Values with the header must still decrypt. |

## Error handling

All exceptions BlindCrypt throws on purpose extend `io.github.sillwork.blindcrypt.core.BlindCryptException`.

| Type | When | What to do |
| :--- | :--- | :--- |
| `BlindCryptConfigurationException` | Normally at startup: missing or invalid keys, unsupported entity mapping, an `@Encrypted` attribute not mapped through the BlindCrypt converter, a repository method that cannot use a blind index. At first use instead if BlindCrypt is disabled or not initialised. | Read the "Action" line, fix configuration or code, restart. |
| `CryptoException` | At runtime: ciphertext fails authentication, references a key version not in `blindcrypt.keys`, or is malformed; a value is empty after normalization. | Treat as a data integrity or key management incident. Do not retry. |

Misconfiguration stops the application before it accepts traffic:

```
***************************
APPLICATION FAILED TO START
***************************

Description:

blindcrypt.blind-index-key is not set.

Action:

Set blindcrypt.blind-index-key to a Base64-encoded 32-byte key, for example: openssl rand -base64 32.
```

Exception messages never contain plaintext, key material or blind index hashes.

## Limitations

Read these before using BlindCrypt for sensitive data.

- **Equality is visible.** Equal values have equal blind indexes, so anyone who can read the table can tell which rows share a value. Use `@Encrypted` without `@BlindIndex` for fields you never search.
- The JPA converters do not bind row-specific associated data. A ciphertext copied to another row or column encrypted with the same key decrypts there.
- `allow-plaintext-read` for `byte[]` columns cannot distinguish legacy binary data from damaged ciphertext and returns the stored bytes when decryption fails. Keep the flag off outside migrations.
- With `allow-plaintext-read` on, a legacy plaintext string that literally starts with `ENC:` is treated as ciphertext and fails to decrypt.
- Blind-indexed properties support exact match, `In`, `IsNull` and `IsNotNull` only. Derived methods on them cannot delete, limit (`First`/`Top`), page, sort by parameter or stream; use an explicit `@Query` on the `blindIndex` column instead.
- In a derived method with a blind-index predicate, other properties support only exact match, `Not`, `In`, `IsNull` and `IsNotNull`, without `IgnoreCase`.
- Derived methods with a blind-index predicate return the entity, `Optional`, `List` or `Collection` of it, `long`/`Long` for `countBy` and `boolean`/`Boolean` for `existsBy`.
- Multi-tenant blind indexes are available in the core API (`UltraBlindIndexer`) but not wired into the Spring starter.
- Blind index key rotation and clustered migration locking are not built in.
- Exceptions are not converted into sanitized RFC 7807 problem responses. Handle `BlindCryptException` in your own exception handler.

Repository methods that use an unsupported predicate, query shape or return type on a blind-indexed property are rejected at startup, not on first call.

## Documentation

- [How it works](docs/how-it-works.md): the two-column design, normalization, cipher pooling and the module layout
- [Security model](docs/security-model.md): what BlindCrypt protects against and how
- [Database schema](docs/database-schema.md): PostgreSQL DDL and Liquibase examples
- [Re-encryption and key rotation](docs/re-encryption.md): rotating keys and batch updates
- [CHANGELOG.md](CHANGELOG.md): release notes

## Building from source

Requires JDK 21+ and Maven 3.9+.

```bash
git clone https://github.com/sillwork/blindcrypt.git
cd blindcrypt
mvn clean verify
```

## Contributing

Bug reports and pull requests are welcome on [GitHub](https://github.com/sillwork/blindcrypt/issues). Please report security problems privately as described in [SECURITY.md](SECURITY.md), not in a public issue.

## License

BlindCrypt is licensed under the [Apache License, Version 2.0](LICENSE). Maintained by [Sillwork](https://github.com/sillwork).
