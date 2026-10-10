package io.github.sillwork.blindcrypt.spring.model;

import io.github.sillwork.blindcrypt.spring.annotation.Encrypted;
import io.github.sillwork.blindcrypt.spring.converter.EncryptedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Embeddable;
import java.util.Objects;

/**
 * Standard JPA Embeddable Value Object representing an encrypted textual column with deterministic blind indexing.
 * <p>
 * {@code EncryptedText} encapsulates both the AES-256-GCM ciphertext and its companion 64-character
 * HMAC-SHA256 hexadecimal blind index into a clean, reusable value object.
 *
 * <h2>Database Column Mapping</h2>
 * When used with {@link io.github.sillwork.blindcrypt.spring.hibernate.EncryptedNamingStrategy}:
 * <ul>
 *   <li>The ciphertext is stored in a column named after the field (e.g. {@code email}).</li>
 *   <li>The blind index is stored in a companion column suffixed with {@code _bidx} (e.g. {@code email_bidx}).</li>
 * </ul>
 *
 * <h2>Usage in JPA Entities</h2>
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
 *     @BlindIndex(name = "user_email")
 *     private EncryptedText email;
 *
 *     // Getter returning the decrypted plaintext string
 *     public String getEmail() {
 *         return EncryptedText.valueOf(this.email);
 *     }
 *
 *     // Setter using update() to prevent false-positive dirty checks
 *     public void setEmail(String email) {
 *         this.email = EncryptedText.update(this.email, email);
 *     }
 * }
 * }</pre>
 *
 * <h2>Hibernate Dirty-Checking Protection</h2>
 * Because AES-256-GCM produces a different ciphertext on every encryption call, blindly calling
 * {@code this.email = EncryptedText.of(newValue)} inside entity setters triggers Hibernate dirty-checking
 * even when the underlying string was unchanged. Always use {@link #update(EncryptedText, String)}
 * inside entity setters to preserve reference equality when the plaintext is identical.
 *
 * @see io.github.sillwork.blindcrypt.spring.annotation.BlindIndex
 * @see io.github.sillwork.blindcrypt.spring.model.EncryptedBytes
 */
@Embeddable
public class EncryptedText {

    /**
     * JPA metamodel attribute name for the encrypted ciphertext property.
     */
    public static final String VALUE_ATTRIBUTE = "encryptedValue";

    /**
     * JPA metamodel attribute name for the companion blind index property.
     */
    public static final String INDEX_ATTRIBUTE = "blindIndex";

    /**
     * Default column length for storing Base64-encoded AES-256-GCM ciphertexts.
     */
    public static final int DEFAULT_VALUE_LENGTH = 512;

    /**
     * Length of the companion HMAC-SHA256 lowercase hexadecimal blind index string.
     */
    public static final int INDEX_LENGTH = 64;

    // @Convert is the authoritative mapping and does not depend on Hibernate internals.
    // @Encrypted is kept as a marker so the field is recognised by QueryMethodValidator and readers.
    @Encrypted
    @Convert(converter = EncryptedStringConverter.class)
    @Column(length = DEFAULT_VALUE_LENGTH)
    private String encryptedValue;

    @Column(length = INDEX_LENGTH)
    private String blindIndex;

    /**
     * Protected no-arg constructor required by JPA providers (Hibernate).
     */
    protected EncryptedText() { }

    private EncryptedText(String value) {
        this.encryptedValue = value;
    }

    /**
     * Factory method creating a new {@link EncryptedText} instance from a plaintext string.
     *
     * @param value the plaintext string to encapsulate, or {@code null}
     * @return a new {@code EncryptedText} instance, or {@code null} if the provided string is null
     */
    public static EncryptedText of(String value) {
        return value == null ? null : new EncryptedText(value);
    }

    /**
     * Extracts the plaintext string from an {@link EncryptedText} instance.
     * Safe to call on {@code null} references.
     *
     * @param encryptedText the EncryptedText wrapper, or {@code null}
     * @return the decrypted plaintext string, or {@code null} if the input wrapper or value is null
     */
    public static String valueOf(EncryptedText encryptedText) {
        return encryptedText == null ? null : encryptedText.encryptedValue;
    }

    /**
     * Updates an entity field while preventing Hibernate dirty-checking from generating redundant SQL updates.
     * <p>
     * If {@code newValue} equals the existing plaintext value of {@code current}, the existing
     * {@code current} instance reference is returned. If values differ, a new {@link EncryptedText} instance
     * is created and returned.
     *
     * @param current  the current {@code EncryptedText} field on the entity, or {@code null}
     * @param newValue the proposed new plaintext string value, or {@code null}
     * @return the existing instance if values are equal, or a newly created {@code EncryptedText} instance
     */
    public static EncryptedText update(EncryptedText current, String newValue) {
        return Objects.equals(valueOf(current), newValue) ? current : of(newValue);
    }

    /**
     * Returns the decrypted plaintext string.
     *
     * @return the plaintext string, or {@code null} if uninitialized
     */
    public String value() {
        return encryptedValue;
    }

    /**
     * Returns the 64-character companion lowercase hexadecimal HMAC-SHA256 blind index.
     *
     * @return lowercase hexadecimal blind index string, or {@code null} if not yet calculated
     */
    public String blindIndex() {
        return blindIndex;
    }

    /**
     * Assigns the computed hexadecimal blind index to this value object.
     * Typically invoked by {@link io.github.sillwork.blindcrypt.spring.listener.BlindIndexListener}.
     *
     * @param blindIndex the 64-character hexadecimal HMAC-SHA256 string
     */
    public void assignBlindIndex(String blindIndex) {
        this.blindIndex = blindIndex;
    }

    /**
     * Compares equality based strictly on the decrypted plaintext string.
     *
     * @param other the other object to compare with
     * @return {@code true} if both instances represent the identical plaintext string
     */
    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof EncryptedText otherText)) return false;
        return Objects.equals(encryptedValue, otherText.encryptedValue);
    }

    /**
     * Computes a hash code based on the encapsulated plaintext string.
     *
     * @return integer hash code
     */
    @Override
    public int hashCode() {
        return Objects.hash(encryptedValue);
    }

    /**
     * Returns a redacted string representation to prevent accidental log leakage of sensitive plaintexts.
     *
     * @return always {@code "EncryptedText[REDACTED]"}
     */
    @Override
    public String toString() {
        return "EncryptedText[REDACTED]";
    }
}
