package io.github.sillwork.blindcrypt.spring.annotation;

import io.github.sillwork.blindcrypt.spring.hibernate.EncryptedBinder;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.hibernate.annotations.AttributeBinderType;

/**
 * Declares an entity attribute to be transparently encrypted at rest with AES-256-GCM.
 * <p>
 * When an entity property is annotated with {@code @Encrypted}, BlindCrypt automatically
 * encrypts the value before writing it to the database and decrypts it when reading from the database.
 * <h2>Supported Field Types</h2>
 * <ul>
 *   <li><b>{@link String}</b>: Encrypted into an authenticated textual format:
 *       {@code ENC:<version>:<base64>}, where the Base64 payload holds the IV followed by the ciphertext and tag.</li>
 *   <li><b>{@code byte[]}</b>: Encrypted into a compact binary wire format:
 *       {@code [Version: 1B][IV: 12B][Ciphertext + Tag: NB]}.</li>
 * </ul>
 * {@code @Encrypted} applies to {@code String} and {@code byte[]} fields only.
 * {@link io.github.sillwork.blindcrypt.spring.model.EncryptedText} and
 * {@link io.github.sillwork.blindcrypt.spring.model.EncryptedBytes} are embeddable wrappers that are used
 * with {@link BlindIndex}, not annotated with {@code @Encrypted} by the application.
 *
 * <h2>Cryptographic Invariants &amp; Security Guarantees</h2>
 * <ul>
 *   <li><b>AES-256-GCM</b>: Standard Galois/Counter Mode providing both confidentiality and 128-bit authentication integrity.</li>
 *   <li><b>Randomized Nonces (IVs)</b>: Every encryption operation uses a fresh, cryptographically secure 96-bit
 *       random initialization vector. Identical plaintexts produce completely different ciphertexts, preventing pattern leakage.</li>
 *   <li><b>Associated data</b>: {@link io.github.sillwork.blindcrypt.core.FieldEncryptor} supports binding caller-supplied
 *       associated data into the authentication tag. The JPA converters used by {@code @Encrypted} do not pass
 *       row-specific associated data, so a ciphertext copied to another row or column of the same key decrypts
 *       successfully there.</li>
 * </ul>
 *
 * <h2>Usage Example</h2>
 * <pre>{@code
 * @Entity
 * @Table(name = "customers")
 * public class Customer {
 *
 *     @Id
 *     @GeneratedValue
 *     private Long id;
 *
 *     // Transparently encrypted string column
 *     @Encrypted
 *     @Column(length = 512)
 *     private String taxIdentifier;
 *
 *     // Transparently encrypted binary column
 *     @Encrypted
 *     @Column
 *     private byte[] biometricFingerprint;
 * }
 * }</pre>
 *
 * <h2>Searchability Note</h2>
 * Because AES-256-GCM uses non-deterministic randomized IVs, standard SQL equality queries
 * (e.g. {@code WHERE taxIdentifier = :val}) cannot match encrypted columns. To enable
 * exact-match searches, use {@link BlindIndex @BlindIndex} on an {@link io.github.sillwork.blindcrypt.spring.model.EncryptedText}
 * or {@link io.github.sillwork.blindcrypt.spring.model.EncryptedBytes} field.
 *
 * @see BlindIndex
 * @see io.github.sillwork.blindcrypt.spring.model.EncryptedText
 * @see io.github.sillwork.blindcrypt.spring.model.EncryptedBytes
 */
@Target({ElementType.FIELD, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@AttributeBinderType(binder = EncryptedBinder.class)
@Documented
public @interface Encrypted {
}
