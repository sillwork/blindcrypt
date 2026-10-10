package io.github.sillwork.blindcrypt.spring.converter;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.core.FieldEncryptor;
import java.util.concurrent.atomic.AtomicReference;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/**
 * Standard JPA {@link AttributeConverter} for transparent entity binary ({@code byte[]}) column encryption
 * using compact binary AES-256-GCM wire format.
 */
@Converter
public class EncryptedBytesConverter implements AttributeConverter<byte[], byte[]> {

    private static final AtomicReference<FieldEncryptor> ENCRYPTOR_REF = new AtomicReference<>();
    private static volatile boolean allowPlaintextRead = false;

    /** Creates the instance; Hibernate instantiates the converter, not application code. */
    public EncryptedBytesConverter() {
        // Instantiated by the JPA provider (Hibernate); the encryptor is shared statically.
    }

    /**
     * Injects the global application {@link FieldEncryptor}.
     *
     * @param encryptor the active FieldEncryptor bean
     */
    public static void setEncryptor(FieldEncryptor encryptor) {
        ENCRYPTOR_REF.set(encryptor);
    }

    /**
     * Sets whether unencrypted legacy plaintext is permitted during dual-read migration phases.
     *
     * @param allow true to allow reading unencrypted plaintext, false to require ciphertext
     */
    public static void setAllowPlaintextRead(boolean allow) {
        allowPlaintextRead = allow;
    }

    /**
     * Encrypts the entity plaintext bytes before writing to the database column.
     *
     * @param entityAttribute the raw plaintext bytes, or {@code null}
     * @return the compact binary ciphertext, or {@code null}
     * @throws BlindCryptConfigurationException if BlindCrypt has not been initialised
     * @throws io.github.sillwork.blindcrypt.core.CryptoException if encryption fails
     */
    @Override
    @SuppressWarnings("java:S1168") // Standard JPA AttributeConverter specification requires null to map to SQL NULL
    public byte[] convertToDatabaseColumn(byte[] entityAttribute) {
        if (entityAttribute == null) return null;
        FieldEncryptor encryptor = ENCRYPTOR_REF.get();
        if (encryptor == null) {
            throw new BlindCryptConfigurationException(
                    "BlindCrypt encryption is used before BlindCryptAutoConfiguration initialised the FieldEncryptor.",
                    "Make sure the application is a Spring Boot application with blindcrypt-spring-boot-starter on the classpath "
                            + "and blindcrypt.enabled is not false.");
        }
        return encryptor.encryptToBinary(entityAttribute, null);
    }

    /**
     * Decrypts the database column binary ciphertext when reading into the entity attribute.
     *
     * @param databaseColumnData the binary ciphertext from the database, or {@code null}
     * @return the decrypted raw plaintext bytes, or {@code null}
     * @throws BlindCryptConfigurationException if BlindCrypt has not been initialised
     * @throws io.github.sillwork.blindcrypt.core.CryptoException if decryption fails
     */
    @Override
    @SuppressWarnings("java:S1168") // Standard JPA AttributeConverter specification requires SQL NULL to map to null
    public byte[] convertToEntityAttribute(byte[] databaseColumnData) {
        if (databaseColumnData == null) return null;
        FieldEncryptor encryptor = ENCRYPTOR_REF.get();
        if (encryptor == null) {
            throw new BlindCryptConfigurationException(
                    "BlindCrypt encryption is used before BlindCryptAutoConfiguration initialised the FieldEncryptor.",
                    "Make sure the application is a Spring Boot application with blindcrypt-spring-boot-starter on the classpath "
                            + "and blindcrypt.enabled is not false.");
        }
        return encryptor.decryptFromBinary(databaseColumnData, null, allowPlaintextRead);
    }
}
