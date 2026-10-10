package io.github.sillwork.blindcrypt.spring.annotation;

import io.github.sillwork.blindcrypt.core.Normalization;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Configures deterministic blind indexing for an encrypted field.
 * <p>
 * Standard AES-256-GCM ciphertexts cannot be queried with standard SQL clauses (like {@code WHERE email = :val})
 * because their initialization vectors (IVs) are deliberately randomized.
 * {@code @BlindIndex} creates a cryptographically isolated, one-way HMAC-SHA256 hash
 * that is stored in a companion database column and indexed with a standard B-Tree.
 *
 * <h2>How It Works Under the Hood</h2>
 * <ol>
 *   <li><b>Normalization</b>: The plaintext is canonicalized using the configured {@link #normalization()}
 *       strategy (e.g. trimming whitespace, lowercasing) so minor user formatting differences match identically.</li>
 *   <li><b>Subkey Derivation</b>: A dedicated 256-bit HMAC subkey is derived using HKDF-style domain separation:
 *       {@code HMAC(rootKey, "blind-index:v1:" + name)}. Even if the index key is leaked,
 *       the data encryption keys (DEKs) remain secure.</li>
 *   <li><b>Hashing</b>: {@link io.github.sillwork.blindcrypt.core.UltraBlindIndexer} clones a pre-initialised
 *       {@link javax.crypto.Mac} per index instead of calling {@code Mac.getInstance} and {@code init} on every hash.</li>
 *   <li><b>Lifecycle Synchronization</b>: When the entity is persisted or updated, {@link io.github.sillwork.blindcrypt.spring.listener.BlindIndexListener}
 *       synchronously computes the blind index and sets it on the companion column prior to SQL flush.</li>
 * </ol>
 *
 * <h2>Entity Setup Requirement</h2>
 * The declaring entity <b>must</b> specify {@code @EntityListeners(BlindIndexListener.class)}:
 * <pre>{@code
 * @Entity
 * @EntityListeners(BlindIndexListener.class)
 * @Table(name = "users")
 * public class User {
 *
 *     @Id
 *     @GeneratedValue
 *     private Long id;
 *
 *     // Textual blind index: generates columns 'email' (ciphertext) and 'email_bidx' (index)
 *     @BlindIndex(name = "user_email", normalization = Normalization.TRIM_CASE_INSENSITIVE)
 *     private EncryptedText email;
 *
 *     // Phone blind index: digits-only normalization
 *     @BlindIndex(name = "user_phone", normalization = Normalization.DIGITS_ONLY)
 *     private EncryptedText phoneNumber;
 * }
 * }</pre>
 *
 * @see BlindIndexQueries
 * @see io.github.sillwork.blindcrypt.spring.model.EncryptedText
 * @see io.github.sillwork.blindcrypt.spring.model.EncryptedBytes
 * @see io.github.sillwork.blindcrypt.core.Normalization
 * @see io.github.sillwork.blindcrypt.spring.listener.BlindIndexListener
 */
@Target({ElementType.FIELD, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface BlindIndex {

    /**
     * Unique logical name of the index for cryptographic domain separation (e.g. {@code "user_email"}).
     * <p>
     * Subkeys are derived from this name. Two different fields with the same plaintext value but different
     * index names will produce completely distinct blind index hashes.
     *
     * @return the unique logical index identifier
     */
    String name();

    /**
     * Normalization strategy to apply before computing the one-way hash.
     * <p>
     * Defaults to {@link Normalization#TRIM_CASE_INSENSITIVE}, which trims whitespace and lowercases
     * ASCII characters (ideal for email addresses and usernames).
     *
     * @return the canonicalization strategy
     */
    Normalization normalization() default Normalization.TRIM_CASE_INSENSITIVE;
}
