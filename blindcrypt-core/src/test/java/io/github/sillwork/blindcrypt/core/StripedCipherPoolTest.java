package io.github.sillwork.blindcrypt.core;

import javax.crypto.Cipher;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StripedCipherPoolTest {

    @Test
    void testBorrowAndReturnCipher() {
        StripedCipherPool pool = new StripedCipherPool("AES/GCM/NoPadding");

        Cipher cipher1 = pool.borrowCipher();
        assertThat(cipher1).isNotNull();

        pool.returnCipher(cipher1);

        Cipher cipher2 = pool.borrowCipher();
        assertThat(cipher2).isSameAs(cipher1);

        pool.returnCipher(null);
    }

    @Test
    void testInvalidTransformationThrowsCryptoException() {
        StripedCipherPool pool = new StripedCipherPool("NON_EXISTENT_TRANSFORMATION");

        assertThatThrownBy(pool::borrowCipher)
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("Failed to initialize Cipher");
    }

    @Test
    void testReturnLimitPerStripe() {
        StripedCipherPool pool = new StripedCipherPool("AES/GCM/NoPadding");

        for (int i = 0; i < 70; i++) {
            pool.returnCipher(pool.borrowCipher());
        }

        Cipher cipher = pool.borrowCipher();
        assertThat(cipher).isNotNull();
    }
}
