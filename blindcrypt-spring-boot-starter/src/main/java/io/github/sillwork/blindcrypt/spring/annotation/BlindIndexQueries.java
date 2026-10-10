package io.github.sillwork.blindcrypt.spring.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a Spring Data JPA repository interface for transparent blind index query rewriting.
 * <p>
 * When a repository interface is annotated with {@code @BlindIndexQueries}, Spring Data derived
 * query methods targeting encrypted properties (e.g. {@code findByEmail(String)}) are intercepted
 * at runtime by an AOP method interceptor.
 *
 * <h2>Query Interception Mechanics</h2>
 * <ol>
 *   <li>The interceptor inspects the method signature and maps the queried domain property (e.g. {@code email})
 *       to its configured {@link BlindIndex @BlindIndex} metadata.</li>
 *   <li>The incoming plaintext parameter (e.g. {@code "user@company.com"}) is canonicalized using the field's
 *       {@link io.github.sillwork.blindcrypt.core.Normalization} strategy and hashed with the column's HMAC-SHA256 subkey.</li>
 *   <li>The JPQL criteria are rewritten so that the generated SQL queries the companion B-Tree index column
 *       (e.g. {@code WHERE u.email.blindIndex = :bidx}) instead of attempting an impossible scan against randomized ciphertexts.</li>
 *   <li>The query executes on the database using fast B-Tree index seeks, returning fully populated domain entities.</li>
 * </ol>
 *
 * <h2>Supported Query Patterns</h2>
 * Blind-indexed properties support exact match, {@code In}, {@code IsNull} and {@code IsNotNull}, combined with
 * {@code And}, {@code Or} and an {@code OrderBy} clause in the method name:
 * <ul>
 *   <li><b>Exact Match</b>: {@code findByEmail(String email)}, {@code findByEmailAndStatus(String email, Status s)}</li>
 *   <li><b>Collection Membership</b>: {@code findByEmailIn(Collection<String> emails)}</li>
 *   <li><b>Existence Checks</b>: {@code existsByEmail(String email)}</li>
 *   <li><b>Count Queries</b>: {@code countByEmail(String email)}</li>
 * </ul>
 * In a method with a blind-index predicate, other (non-blind-indexed) properties support exact match, {@code Not},
 * {@code In}, {@code IsNull} and {@code IsNotNull}, without {@code IgnoreCase}.
 * <p>
 * Supported return types are the domain entity, {@code Optional} of it, {@code List} or {@code Collection} of it,
 * {@code long} or {@code Long} for {@code countBy}, and {@code boolean} or {@code Boolean} for {@code existsBy}.
 * <p>
 * Derived methods without a blind-index predicate are executed by Spring Data unchanged, so none of the
 * restrictions below apply to them.
 *
 * <h2>Usage Example</h2>
 * <pre>{@code
 * @Repository
 * @BlindIndexQueries
 * public interface UserRepository extends JpaRepository<User, Long> {
 *
 *     // Transparently hashes plaintext email and queries 'email_bidx'
 *     Optional<User> findByEmail(String email);
 *
 *     // Rewrites batch parameters to hashes
 *     List<User> findByEmailIn(Collection<String> emails);
 *
 *     boolean existsByEmail(String email);
 * }
 * }</pre>
 *
 * <h2>Fail-Fast Bootstrap Validations</h2>
 * Every derived method is validated while the repository is created at startup. On any derived method:
 * <ul>
 *   <li><b>Unindexed Encrypted Fields</b>: querying an {@code @Encrypted} property that lacks {@code @BlindIndex}
 *       is rejected.</li>
 *   <li><b>Direct Embeddable Navigation</b>: direct queries like {@code findByEmailBlindIndex(...)} are rejected.
 *       Query the domain property instead: {@code findByEmail(plaintext)}.</li>
 * </ul>
 * On a method with a blind-index predicate, these are also rejected:
 * <ul>
 *   <li>a predicate on the blind-indexed property other than exact match, {@code In}, {@code IsNull} or
 *       {@code IsNotNull} (for example {@code Containing}, {@code StartingWith}, {@code GreaterThan});</li>
 *   <li>a predicate on another property other than exact match, {@code Not}, {@code In}, {@code IsNull} or
 *       {@code IsNotNull}, or {@code IgnoreCase} on another property;</li>
 *   <li>derived deletes ({@code deleteBy}, {@code removeBy});</li>
 *   <li>{@code First} / {@code Top} limits;</li>
 *   <li>{@code Pageable}, {@code Sort} or {@code Limit} parameters;</li>
 *   <li>{@code @Lock}, {@code @EntityGraph} and {@code @QueryHints};</li>
 *   <li>any return type outside the list above, including {@code Page}, {@code Slice}, {@code Stream},
 *       {@code Set}, {@code Iterable}, {@code int} counts and projections.</li>
 * </ul>
 * Write an explicit {@code @Query} on the {@code blindIndex} column for those cases.
 *
 * @see BlindIndex
 * @see io.github.sillwork.blindcrypt.spring.repository.BlindIndexDerivedQuery
 * @see io.github.sillwork.blindcrypt.spring.repository.QueryMethodValidator
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface BlindIndexQueries {
}
