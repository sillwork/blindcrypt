package io.github.sillwork.blindcrypt.spring.listener;

import io.github.sillwork.blindcrypt.spring.model.EncryptedBytes;
import io.github.sillwork.blindcrypt.spring.model.EncryptedText;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The value holders are used as entity attributes: they must compare by plaintext, never expose it through
 * {@code toString}, and keep the stored blind index from aliasing caller-owned arrays.
 */
class EncryptedValueTypesTest {

    @Test
    void textHoldersCompareByPlaintext() {
        EncryptedText one = EncryptedText.of("same");
        EncryptedText two = EncryptedText.of("same");

        assertThat(one)
                .isEqualTo(two)
                .hasSameHashCodeAs(two)
                .isEqualTo(one)
                .isNotEqualTo(EncryptedText.of("other"));
        Object differentType = "same";
        Object nothing = null;
        assertThat(one).isNotEqualTo(differentType).isNotEqualTo(nothing);
    }

    @Test
    void textToStringNeverContainsThePlaintext() {
        assertThat(EncryptedText.of("hunter2")).hasToString("EncryptedText[REDACTED]");
    }

    @Test
    void textUpdateKeepsTheSameInstanceWhenValueIsUnchangedSoDirtyCheckingStaysQuiet() {
        EncryptedText current = EncryptedText.of("value");

        assertThat(EncryptedText.update(current, "value")).isSameAs(current);
        assertThat(EncryptedText.update(current, "changed")).isNotSameAs(current);
        assertThat(EncryptedText.update(current, null)).isNull();
        assertThat(EncryptedText.valueOf(null)).isNull();
        assertThat(EncryptedText.of(null)).isNull();
    }

    @Test
    void bytesHoldersCompareByContent() {
        EncryptedBytes one = EncryptedBytes.of(new byte[] {1, 2});
        EncryptedBytes two = EncryptedBytes.of(new byte[] {1, 2});

        assertThat(one)
                .isEqualTo(two)
                .hasSameHashCodeAs(two)
                .isEqualTo(one)
                .isNotEqualTo(EncryptedBytes.of(new byte[] {1, 3}));
        Object differentType = "x";
        Object nothing = null;
        assertThat(one).isNotEqualTo(differentType).isNotEqualTo(nothing);
    }

    @Test
    void bytesToStringNeverContainsTheContent() {
        assertThat(EncryptedBytes.of(new byte[] {42})).hasToString("EncryptedBytes[REDACTED]");
    }

    @Test
    void bytesUpdateKeepsTheSameInstanceWhenContentIsUnchanged() {
        EncryptedBytes current = EncryptedBytes.of(new byte[] {1, 2});

        assertThat(EncryptedBytes.update(current, new byte[] {1, 2})).isSameAs(current);
        assertThat(EncryptedBytes.update(current, new byte[] {9})).isNotSameAs(current);
        assertThat(EncryptedBytes.update(current, null)).isNull();
        assertThat(EncryptedBytes.valueOf(null)).isNull();
        assertThat(EncryptedBytes.of(null)).isNull();
    }

    @Test
    void assignedBlindIndexIsCopiedAndCanBeCleared() {
        EncryptedBytes bytes = EncryptedBytes.of(new byte[] {1});
        byte[] index = {7, 7};
        bytes.assignBlindIndex(index);
        index[0] = 0;

        assertThat(bytes.blindIndex()).containsExactly(7, 7);
        bytes.blindIndex()[0] = 0;
        assertThat(bytes.blindIndex()).containsExactly(7, 7);
        bytes.assignBlindIndex(null);
        assertThat(bytes.blindIndex()).isNull();
    }
}
