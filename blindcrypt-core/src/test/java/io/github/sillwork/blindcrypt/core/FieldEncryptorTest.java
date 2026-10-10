package io.github.sillwork.blindcrypt.core;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FieldEncryptorTest {

    private FieldEncryptor encryptor;

    @BeforeEach
    void setUp() {
        byte[] encKey = new byte[32];
        byte[] blindKey = new byte[32];
        for (int i = 0; i < 32; i++) {
            encKey[i] = (byte) (i + 10);
            blindKey[i] = (byte) (i + 70);
        }

        KeyRing keyRing = new KeyRing(Map.of("v1", encKey), "v1", blindKey);
        StripedCipherPool pool = new StripedCipherPool("AES/GCM/NoPadding");
        encryptor = new FieldEncryptor(keyRing, pool);
    }

    @Test
    void testStringEncryptionRoundTrip() {
        String plaintext = "Confidential Account Record #12345";
        String aad = "accounts:secret_payload:101";

        String ciphertext = encryptor.encryptToString(plaintext, aad);
        assertThat(ciphertext)
                .startsWith("ENC:v1:")
                .doesNotContain(plaintext);

        String decrypted = encryptor.decryptFromString(ciphertext, aad);
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void testBinaryEncryptionRoundTrip() {
        byte[] plaintext = "Raw Binary Payload 998877".getBytes(StandardCharsets.UTF_8);
        String aad = "users:bio:42";

        byte[] packed = encryptor.encryptToBinary(plaintext, aad);
        assertThat(packed)
                .isNotNull()
                .hasSizeGreaterThan(29);

        byte[] decrypted = encryptor.decryptFromBinary(packed, aad);
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void testRandomizedInitializationVectors() {
        String plaintext = "same-input@company.com";
        String aad = "users:email:1";

        String cipher1 = encryptor.encryptToString(plaintext, aad);
        String cipher2 = encryptor.encryptToString(plaintext, aad);

        assertThat(cipher1).isNotEqualTo(cipher2); // Distinct randomized IVs!
        assertThat(encryptor.decryptFromString(cipher1, aad)).isEqualTo(plaintext);
        assertThat(encryptor.decryptFromString(cipher2, aad)).isEqualTo(plaintext);
    }

    @Test
    void testContextualAadAntiSplicingDefense() {
        // Resolves Gap #3: Ciphertext spliced from Row 101 to Row 202
        String plaintext = "alex@company.com";
        String originalAad = "users:email:101";
        String splicedAad = "users:email:202";

        String ciphertext = encryptor.encryptToString(plaintext, originalAad);

        // Attempting to decrypt with different AAD must fail authentication tag check!
        assertThatThrownBy(() -> encryptor.decryptFromString(ciphertext, splicedAad))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("authentication tag mismatch");
    }

    @Test
    void testNullHandlingAndPlaintextFallback() {
        assertThat(encryptor.encryptToString(null, null)).isNull();
        assertThat(encryptor.decryptFromString(null, null)).isNull();
        assertThat(encryptor.encryptToBinary(null, null)).isNull();
        assertThat(encryptor.decryptFromBinary(null, null)).isNull();

        String plain = "NotEncrypted";
        assertThat(encryptor.decryptFromString(plain, "aad", true)).isEqualTo(plain);
        assertThatThrownBy(() -> encryptor.decryptFromString(plain, "aad", false))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("Invalid ciphertext header");
    }

    @Test
    void testBinaryPlaintextFallbackAndShortPayload() {
        byte[] shortPayload = new byte[]{1, 2, 3};
        assertThat(encryptor.decryptFromBinary(shortPayload, "aad", true)).isEqualTo(shortPayload);

        assertThatThrownBy(() -> encryptor.decryptFromBinary(shortPayload, "aad", false))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("smaller than header + tag length");
    }

    @Test
    void testUnknownVersionPlaintextFallback() {
        byte[] unknownVersionPayload = new byte[35];
        unknownVersionPayload[0] = 99; // Version 99 doesn't exist
        assertThat(encryptor.decryptFromBinary(unknownVersionPayload, "aad", true)).isEqualTo(unknownVersionPayload);

        assertThatThrownBy(() -> encryptor.decryptFromBinary(unknownVersionPayload, "aad", false))
                .isInstanceOf(CryptoException.class);
    }

    @Test
    void plaintextPassthroughReturnsLegacyValueThatIsNotCiphertext() {
        assertThat(encryptor.decryptFromString("legacy@corp.com", null, true)).isEqualTo("legacy@corp.com");
    }

    @Test
    void plaintextPassthroughNeverHidesTamperedCiphertext() {
        String ciphertext = encryptor.encryptToString("secret", null);
        char[] chars = ciphertext.toCharArray();
        int target = ciphertext.lastIndexOf(':') + 5;
        chars[target] = chars[target] == 'A' ? 'B' : 'A';
        String tampered = new String(chars);

        assertThatThrownBy(() -> encryptor.decryptFromString(tampered, null, true))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("authentication tag mismatch");
    }

    @Test
    void plaintextPassthroughNeverHidesUnknownKeyVersion() {
        String ciphertext = encryptor.encryptToString("secret", null).replace("ENC:v1:", "ENC:v9:");
        assertThatThrownBy(() -> encryptor.decryptFromString(ciphertext, null, true))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("v9");
    }

    @Test
    void unknownKeyVersionSegmentThatIsNotAVersionIsNeverEchoed() {
        // A legacy plaintext that happens to start with "ENC:" must not leak into the exception message.
        String payload = java.util.Base64.getEncoder().encodeToString(new byte[40]);
        String stored = "ENC:jane.doe@example.com:" + payload;
        assertThatThrownBy(() -> encryptor.decryptFromString(stored, null, true))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("an invalid key version")
                .hasMessageNotContaining("jane.doe");
    }

    @Test
    void tagMismatchMessageNeverEchoesNonVersionSegment() {
        byte[] encKey = new byte[32];
        byte[] blindKey = new byte[32];
        blindKey[0] = 1;
        KeyRing keyRing = new KeyRing(Map.of("v1", encKey, "secret-name", encKey), "v1", blindKey);
        FieldEncryptor custom = new FieldEncryptor(keyRing, new StripedCipherPool("AES/GCM/NoPadding"));
        String payload = java.util.Base64.getEncoder().encodeToString(new byte[40]);
        assertThatThrownBy(() -> custom.decryptFromString("ENC:secret-name:" + payload, null, true))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("authentication tag mismatch")
                .hasMessageNotContaining("secret-name");
    }

    @Test
    void activeKeyVersionOutsideBinaryRangeFailsAtConstruction() {
        byte[] encKey = new byte[32];
        byte[] blindKey = new byte[32];
        blindKey[0] = 1;
        KeyRing keyRing = new KeyRing(Map.of("v200", encKey), "v200", blindKey);
        StripedCipherPool pool = new StripedCipherPool("AES/GCM/NoPadding");
        assertThatThrownBy(() -> new FieldEncryptor(keyRing, pool))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("v200");
    }

    private static FieldEncryptor encryptorWithActiveVersion(String version) {
        byte[] encKey = new byte[32];
        encKey[0] = 5;
        byte[] blindKey = new byte[32];
        blindKey[0] = 1;
        KeyRing ring = new KeyRing(Map.of(version, encKey), version, blindKey);
        return new FieldEncryptor(ring, new StripedCipherPool("AES/GCM/NoPadding"));
    }

    @Test
    void numericKeyVersionRoundTripsThroughBinaryAndString() {
        FieldEncryptor numeric = encryptorWithActiveVersion("7");
        byte[] plaintext = "numeric version".getBytes(StandardCharsets.UTF_8);

        byte[] packed = numeric.encryptToBinary(plaintext, "t:c:1");
        assertThat(numeric.decryptFromBinary(packed, "t:c:1")).isEqualTo(plaintext);

        String token = numeric.encryptToString("numeric version", "t:c:1");
        assertThat(token).startsWith("ENC:7:");
        assertThat(numeric.decryptFromString(token, "t:c:1")).isEqualTo("numeric version");
    }

    @Test
    void activeKeyVersionNotParseableOrOutOfRangeIsRejectedAtConstruction() {
        for (String version : new String[] {"v0", "v128", "vabc", "0", "200", "x1"}) {
            assertThatThrownBy(() -> encryptorWithActiveVersion(version))
                    .as(version)
                    .isInstanceOf(BlindCryptConfigurationException.class)
                    .hasMessageContaining(version)
                    .hasCauseInstanceOf(CryptoException.class);
        }
    }

    @Test
    void stringWithoutCiphertextHeaderIsRejectedUnlessPlaintextIsAllowed() {
        assertThatThrownBy(() -> encryptor.decryptFromString("just text", "aad"))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("expected 'ENC:' prefix");
        assertThat(encryptor.decryptFromString("just text", "aad", true)).isEqualTo("just text");
    }

    @Test
    void malformedCiphertextStringsAreRejectedWithoutEchoingTheStoredValue() {
        assertThatThrownBy(() -> encryptor.decryptFromString("ENC:v1", "aad"))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("Malformed ciphertext");
        assertThatThrownBy(() -> encryptor.decryptFromString("ENC:v1:***not-base64***", "aad"))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("Corrupted base64")
                .hasMessageNotContaining("not-base64");
        assertThatThrownBy(() -> encryptor.decryptFromString("ENC:v1:AAAA", "aad"))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("Truncated ciphertext");
    }

    @Test
    void tamperedStringCiphertextIsRejectedEvenWhenPlaintextIsAllowed() {
        String token = encryptor.encryptToString("value", "aad");
        String tampered = token.substring(0, token.length() - 6) + (token.endsWith("AAAA==") ? "BBBB==" : "AAAA==");
        assertThatThrownBy(() -> encryptor.decryptFromString(tampered, "aad", true))
                .isInstanceOf(CryptoException.class);
    }

    @Test
    void binaryPayloadTooShortIsRejectedUnlessPlaintextIsAllowed() {
        byte[] tooShort = new byte[] {1, 2, 3};
        assertThatThrownBy(() -> encryptor.decryptFromBinary(tooShort, "aad"))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("Corrupted binary payload");
        assertThat(encryptor.decryptFromBinary(tooShort, "aad", true)).isEqualTo(tooShort);
    }

    @Test
    void binaryPayloadWithUnknownVersionIsRejectedUnlessPlaintextIsAllowed() {
        byte[] packed = encryptor.encryptToBinary("value".getBytes(StandardCharsets.UTF_8), "aad");
        packed[0] = 99;
        assertThatThrownBy(() -> encryptor.decryptFromBinary(packed, "aad"))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("key version 'v99'");
        assertThat(encryptor.decryptFromBinary(packed, "aad", true)).isEqualTo(packed);
    }

    @Test
    void tamperedBinaryPayloadFailsAuthenticationUnlessPlaintextIsAllowed() {
        byte[] packed = encryptor.encryptToBinary("value".getBytes(StandardCharsets.UTF_8), "aad");
        packed[packed.length - 1] ^= 0x01;
        assertThatThrownBy(() -> encryptor.decryptFromBinary(packed, "aad"))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("authentication tag mismatch");
        assertThat(encryptor.decryptFromBinary(packed, "aad", true)).isEqualTo(packed);
    }

    @Test
    void nullInputsPassThroughAsNull() {
        assertThat(encryptor.encryptToString(null, "aad")).isNull();
        assertThat(encryptor.decryptFromString(null, "aad")).isNull();
        assertThat(encryptor.encryptToBinary(null, "aad")).isNull();
        assertThat(encryptor.decryptFromBinary(null, "aad")).isNull();
    }

    @Test
    void ciphertextWithoutAadDiffersFromCiphertextBoundToAad() {
        String bound = encryptor.encryptToString("value", "aad");
        assertThatThrownBy(() -> encryptor.decryptFromString(bound, null))
                .isInstanceOf(CryptoException.class);
        String unbound = encryptor.encryptToString("value", null);
        assertThat(encryptor.decryptFromString(unbound, null)).isEqualTo("value");
    }
}
