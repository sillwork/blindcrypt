# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-11

### Added
- `BlindCryptException` root type and `BlindCryptConfigurationException` for startup misconfiguration.
- Spring Boot failure analysis: misconfiguration prints a description and an action instead of a stack trace.
- `blindcrypt.enabled` property to switch the starter off.
- Sources and Javadoc jars for IDE documentation.
- `Automatic-Module-Name` manifest entries: `io.github.sillwork.blindcrypt.core`, `io.github.sillwork.blindcrypt.spring`.
- Startup check that every persistent `@Encrypted` attribute, including the ciphertext inside `EncryptedText` and `EncryptedBytes`, is converted by `EncryptedStringConverter` or `EncryptedBytesConverter` in Hibernate's runtime mapping model. If not, the application fails to start instead of writing plaintext.
- `QueryMethodValidator` public methods `validateRepositoryMethod`, `validateBlindIndexQuery` and `validateRewritableShape`.

### Changed
- Maven groupId is `io.github.sillwork` and Java packages are `io.github.sillwork.blindcrypt.*`, so the code lives under a namespace the project owns. The repository moves to `github.com/sillwork/blindcrypt`.
- `central-publishing-maven-plugin` updated to 0.9.0.
- Key and mapping errors are `BlindCryptConfigurationException` instead of `CryptoException`, `IllegalStateException` or `UnsupportedOperationException`. `CryptoException` now means a runtime cryptographic failure only, and extends `BlindCryptException`.
- `@BlindIndexQueries` repository methods are validated when the application starts, not on first call.
- Entity mapping validation runs before the web server starts instead of on `ApplicationReadyEvent`. `BlindIndexStartupValidator` now implements `SmartInitializingSingleton` instead of `ApplicationListener`.
- Restrictions on query shape, `@Lock`, `@EntityGraph`, `@QueryHints`, projections and return types apply only to derived methods with a blind-index predicate. Other methods on a `@BlindIndexQueries` repository keep using `@Lock`, `@EntityGraph`, `@QueryHints`, projections, `Pageable` and `Stream` as before.
- Derived methods with a blind-index predicate accept an allow-list of return types: the entity, `Optional`, `List` or `Collection` of it, `long`/`Long` for `countBy` and `boolean`/`Boolean` for `existsBy`. Other return types, such as projections, `Set`, `Iterable` or `int` counts, are rejected at startup instead of failing on first call.
- Tested versions are stated as Spring Boot 3.3 and Hibernate 6.5.x.
- Exception messages name the property, entity or method involved and say how to fix it.

### Removed
- Unused optional `shedlock-spring` dependency.

### Fixed
- `deleteBy`, `First`/`Top`, `Pageable`/`Sort` and `Stream` methods on blind-indexed properties are rejected at startup. Previously `deleteBy` ran a SELECT and deleted nothing, and `findFirstBy` failed when more than one row matched.
- With `allow-plaintext-read` enabled, a tampered or unreadable `ENC:` value is now rejected instead of being returned as plaintext.
- `@Encrypted` no longer continues silently if the Hibernate binder cannot apply the converter.
- A derived method that combines a blind-index predicate with an unsupported predicate on another property (for example `Containing`, `After`, `Between`) or with `IgnoreCase` is rejected at startup. Previously such predicates were silently rewritten to equality, and `Between` misaligned the method parameters.
- Decryption errors quote the key version only when it looks like one (`v1`, `3`). A legacy plaintext that starts with `ENC:` no longer appears in the exception message.
- A validation failure while preparing a repository method at startup is no longer mistaken for a method name that is not a derived query.
- Invalid Base64 key material no longer echoes key characters in the error message.
- Documentation no longer claims row-bound associated data, ProblemDetail sanitization, ShedLock integration, blind index key rotation or benchmark figures that the code does not provide.
