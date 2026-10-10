package io.github.sillwork.blindcrypt.spring.converter;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.core.FieldEncryptor;
import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A converter used before the auto-configuration installed the encryptor must fail loudly, never pass the value
 * through (which would store plaintext). The encryptor reference is static and shared with the Spring tests, so it
 * is cleared for the duration of each test and restored afterwards.
 */
class EncryptedConverterInitialisationTest {

    private AtomicReference<FieldEncryptor> stringRef;
    private AtomicReference<FieldEncryptor> bytesRef;
    private FieldEncryptor savedString;
    private FieldEncryptor savedBytes;

    @SuppressWarnings("unchecked")
    private static AtomicReference<FieldEncryptor> encryptorRef(Class<?> converterClass) throws ReflectiveOperationException {
        Field field = converterClass.getDeclaredField("ENCRYPTOR_REF");
        field.setAccessible(true);
        return (AtomicReference<FieldEncryptor>) field.get(null);
    }

    @BeforeEach
    void clearEncryptors() throws ReflectiveOperationException {
        stringRef = encryptorRef(EncryptedStringConverter.class);
        bytesRef = encryptorRef(EncryptedBytesConverter.class);
        savedString = stringRef.getAndSet(null);
        savedBytes = bytesRef.getAndSet(null);
    }

    @AfterEach
    void restoreEncryptors() {
        stringRef.set(savedString);
        bytesRef.set(savedBytes);
    }

    @Test
    void stringConverterRefusesToConvertBeforeInitialisation() {
        EncryptedStringConverter converter = new EncryptedStringConverter();

        assertThatThrownBy(() -> converter.convertToDatabaseColumn("top-secret"))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("before BlindCryptAutoConfiguration initialised")
                .hasMessageNotContaining("top-secret");
        assertThatThrownBy(() -> converter.convertToEntityAttribute("ENC:v1:abc"))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("before BlindCryptAutoConfiguration initialised");
    }

    @Test
    void bytesConverterRefusesToConvertBeforeInitialisation() {
        EncryptedBytesConverter converter = new EncryptedBytesConverter();

        assertThatThrownBy(() -> converter.convertToDatabaseColumn(new byte[] {1}))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("before BlindCryptAutoConfiguration initialised");
        assertThatThrownBy(() -> converter.convertToEntityAttribute(new byte[] {1}))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("before BlindCryptAutoConfiguration initialised");
    }

    @Test
    void nullStaysNullEvenBeforeInitialisation() {
        assertThat(new EncryptedStringConverter().convertToDatabaseColumn(null)).isNull();
        assertThat(new EncryptedStringConverter().convertToEntityAttribute(null)).isNull();
        assertThat(new EncryptedBytesConverter().convertToDatabaseColumn(null)).isNull();
        assertThat(new EncryptedBytesConverter().convertToEntityAttribute(null)).isNull();
    }
}
