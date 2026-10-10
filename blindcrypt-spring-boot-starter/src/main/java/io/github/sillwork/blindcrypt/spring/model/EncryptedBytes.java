package io.github.sillwork.blindcrypt.spring.model;

import io.github.sillwork.blindcrypt.spring.annotation.Encrypted;
import io.github.sillwork.blindcrypt.spring.converter.EncryptedBytesConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Embeddable;
import java.util.Arrays;

/**
 * Standard JPA Embeddable Value Object representing an encrypted binary column ({@code byte[]}) with blind indexing.
 * <p>
 * {@code EncryptedBytes} stores compact AES-256-GCM binary ciphertext and exact 32-byte raw binary HMAC blind indexes
 * (PostgreSQL {@code BYTEA}, MySQL/MariaDB {@code BINARY(32)}, Oracle {@code RAW(32)}).
 * Storing binary hashes halves B-Tree index footprint and memory consumption compared to hex text representations.
 *
 * <h2>Database Column Mapping</h2>
 * When used with {@link io.github.sillwork.blindcrypt.spring.hibernate.EncryptedNamingStrategy}:
 * <ul>
 *   <li>The binary ciphertext is stored in a column named after the field (e.g. {@code biometric_data}).</li>
 *   <li>The 32-byte binary blind index is stored in a companion column suffixed with {@code _bidx} (e.g. {@code biometric_data_bidx}).</li>
 * </ul>
 *
 * <h2>Usage in JPA Entities</h2>
 * <pre>{@code
 * @Entity
 * @EntityListeners(BlindIndexListener.class)
 * @Table(name = "identities")
 * public class Identity {
 *
 *     @Id
 *     @GeneratedValue
 *     private Long id;
 *
 *     @BlindIndex(name = "biometric_sample", normalization = Normalization.NONE)
 *     private EncryptedBytes biometricSample;
 *
 *     public byte[] getBiometricSample() {
 *         return EncryptedBytes.valueOf(this.biometricSample);
 *     }
 *
 *     public void setBiometricSample(byte[] sample) {
 *         this.biometricSample = EncryptedBytes.update(this.biometricSample, sample);
 *     }
 * }
 * }</pre>
 *
 * <h2>Defensive Copying &amp; Dirty-Checking Protection</h2>
 * All array getters and setters perform defensive copying to maintain immutability.
 * Use {@link #update(EncryptedBytes, byte[])} inside entity setters to prevent Hibernate dirty-checking
 * from generating redundant SQL updates when the byte array content is unchanged.
 *
 * @see io.github.sillwork.blindcrypt.spring.annotation.BlindIndex
 * @see io.github.sillwork.blindcrypt.spring.model.EncryptedText
 */
@Embeddable
public class EncryptedBytes {

    /**
     * JPA metamodel attribute name for the encrypted ciphertext property.
     */
    public static final String VALUE_ATTRIBUTE = "encryptedValue";

    /**
     * JPA metamodel attribute name for the companion blind index property.
     */
    public static final String INDEX_ATTRIBUTE = "blindIndex";

    // @Convert is the authoritative mapping and does not depend on Hibernate internals.
    // @Encrypted is kept as a marker so the field is recognised by QueryMethodValidator and readers.
    @Encrypted
    @Convert(converter = EncryptedBytesConverter.class)
    @Column
    private byte[] encryptedValue;

    @Column
    private byte[] blindIndex;

    /**
     * Protected no-arg constructor required by JPA providers (Hibernate).
     */
    protected EncryptedBytes() { }

    private EncryptedBytes(byte[] value) {
        this.encryptedValue = value != null ? value.clone() : null;
    }

    /**
     * Factory method creating a new {@link EncryptedBytes} instance from raw plaintext bytes.
     * Performs a defensive clone of the input array.
     *
     * @param value the raw plaintext bytes to encapsulate, or {@code null}
     * @return a new {@code EncryptedBytes} instance, or {@code null} if the provided byte array is null
     */
    public static EncryptedBytes of(byte[] value) {
        return value == null ? null : new EncryptedBytes(value);
    }

    /**
     * Extracts a defensive copy of the plaintext byte array from an {@link EncryptedBytes} instance.
     * Safe to call on {@code null} references.
     *
     * @param encryptedBytes the EncryptedBytes wrapper, or {@code null}
     * @return a defensive copy of the encapsulated bytes, or {@code null} if the input wrapper or value is null
     */
    public static byte[] valueOf(EncryptedBytes encryptedBytes) {
        return encryptedBytes == null ? null : encryptedBytes.value();
    }

    /**
     * Updates an entity field while preventing Hibernate dirty-checking from generating redundant SQL updates.
     * <p>
     * If {@code newValue} content equals the existing plaintext bytes of {@code current}, the existing
     * {@code current} instance reference is returned. If bytes differ, a new {@link EncryptedBytes} instance
     * is created and returned.
     *
     * @param current  the current {@code EncryptedBytes} field on the entity, or {@code null}
     * @param newValue the proposed new plaintext byte array, or {@code null}
     * @return the existing instance if bytes match, or a newly constructed {@code EncryptedBytes} instance
     */
    public static EncryptedBytes update(EncryptedBytes current, byte[] newValue) {
        return (current != null && Arrays.equals(current.encryptedValue, newValue)) ? current : of(newValue);
    }

    /**
     * Returns a defensive copy of the decrypted plaintext bytes.
     *
     * @return defensive copy of the plaintext bytes, or {@code null} if uninitialized
     */
    public byte[] value() {
        return encryptedValue != null ? encryptedValue.clone() : null;
    }

    /**
     * Returns a defensive copy of the companion 32-byte raw binary HMAC blind index.
     *
     * @return defensive copy of the 32-byte blind index, or {@code null} if not yet calculated
     */
    public byte[] blindIndex() {
        return blindIndex != null ? blindIndex.clone() : null;
    }

    /**
     * Assigns the computed raw binary HMAC blind index to this value object.
     * Typically invoked by {@link io.github.sillwork.blindcrypt.spring.listener.BlindIndexListener}.
     *
     * @param blindIndex the 32-byte raw binary blind index array
     */
    public void assignBlindIndex(byte[] blindIndex) {
        this.blindIndex = blindIndex != null ? blindIndex.clone() : null;
    }

    /**
     * Compares equality based strictly on the decrypted plaintext byte content.
     *
     * @param other the other object to compare with
     * @return {@code true} if both instances represent identical plaintext bytes
     */
    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof EncryptedBytes otherBytes)) return false;
        return Arrays.equals(encryptedValue, otherBytes.encryptedValue);
    }

    /**
     * Computes an array-content hash code based on the encapsulated plaintext bytes.
     *
     * @return integer hash code
     */
    @Override
    public int hashCode() {
        return Arrays.hashCode(encryptedValue);
    }

    /**
     * Returns a redacted string representation to prevent accidental log leakage of sensitive byte content.
     *
     * @return always {@code "EncryptedBytes[REDACTED]"}
     */
    @Override
    public String toString() {
        return "EncryptedBytes[REDACTED]";
    }
}
