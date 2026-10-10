package io.github.sillwork.blindcrypt.core;

import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyRingTest {

    private static final byte[] VALID_AES_KEY = "12345678901234567890123456789012".getBytes();
    private static final byte[] VALID_ROOT_KEY = "abcdefghijklmnopqrstuvwxyz123456".getBytes();

    @Test
    void testValidKeyRingCreationAndAccessors() {
        KeyRing keyRing = new KeyRing(Map.of("v1", VALID_AES_KEY), "v1", VALID_ROOT_KEY);

        assertThat(keyRing.getActiveKeyVersion()).isEqualTo("v1");
        assertThat(keyRing.getActiveEncryptionKey()).isEqualTo(VALID_AES_KEY);
        assertThat(keyRing.getEncryptionKey("v1")).isEqualTo(VALID_AES_KEY);
        assertThat(keyRing.getBlindIndexRootKey()).isEqualTo(VALID_ROOT_KEY);
    }

    @Test
    void testFromBase64Factory() {
        String base64Aes = Base64.getEncoder().encodeToString(VALID_AES_KEY);
        String base64Root = Base64.getEncoder().encodeToString(VALID_ROOT_KEY);

        KeyRing keyRing = KeyRing.fromBase64(Map.of("v1", base64Aes), "v1", base64Root);
        assertThat(keyRing.getActiveKeyVersion()).isEqualTo("v1");
        assertThat(keyRing.getActiveEncryptionKey()).isEqualTo(VALID_AES_KEY);
    }

    @Test
    void testDeriveIndexSubkey() {
        KeyRing keyRing = new KeyRing(Map.of("v1", VALID_AES_KEY), "v1", VALID_ROOT_KEY);

        byte[] subkey1 = keyRing.deriveIndexSubkey("email", null);
        byte[] subkey2 = keyRing.deriveIndexSubkey("email", null);
        byte[] subkeyTenant = keyRing.deriveIndexSubkey("email", "tenant-1");

        assertThat(subkey1)
                .hasSize(32)
                .isEqualTo(subkey2);
        assertThat(subkeyTenant).isNotEqualTo(subkey1);
    }

    @Test
    void testValidationFailures() {
        // Missing active key version
        Map<String, byte[]> missingActive = Map.of("v2", VALID_AES_KEY);
        assertThatThrownBy(() -> new KeyRing(missingActive, "v1", VALID_ROOT_KEY))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("Active key version 'v1' has no key");

        // Invalid root key length
        byte[] shortRoot = new byte[16];
        Map<String, byte[]> validMap = Map.of("v1", VALID_AES_KEY);
        assertThatThrownBy(() -> new KeyRing(validMap, "v1", shortRoot))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("blindcrypt.blind-index-key must decode to 32 bytes");

        // Invalid encryption key length
        byte[] shortAes = new byte[16];
        Map<String, byte[]> shortAesMap = Map.of("v1", shortAes);
        assertThatThrownBy(() -> new KeyRing(shortAesMap, "v1", VALID_ROOT_KEY))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("blindcrypt.keys.v1 must decode to 32 bytes");

        // Identical AES and blind root key violation
        assertThatThrownBy(() -> new KeyRing(validMap, "v1", VALID_AES_KEY))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("is identical to blindcrypt.keys.v1");

        // Unknown key version requested
        KeyRing keyRing = new KeyRing(validMap, "v1", VALID_ROOT_KEY);
        assertThatThrownBy(() -> keyRing.getEncryptionKey("v99"))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("key version 'v99'");
    }

    private static final String B64_AES = Base64.getEncoder().encodeToString(VALID_AES_KEY);
    private static final String B64_ROOT = Base64.getEncoder().encodeToString(VALID_ROOT_KEY);

    @Test
    void fromBase64RejectsMissingOrEmptyKeyMap() {
        assertThatThrownBy(() -> KeyRing.fromBase64(null, "v1", B64_ROOT))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("blindcrypt.keys is not set");
        Map<String, String> empty = Map.of();
        assertThatThrownBy(() -> KeyRing.fromBase64(empty, "v1", B64_ROOT))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("blindcrypt.keys is not set");
    }

    @Test
    void fromBase64RejectsBlankActiveVersionAndNamesTheConfiguredVersions() {
        Map<String, String> keys = Map.of("v1", B64_AES);
        assertThatThrownBy(() -> KeyRing.fromBase64(keys, " ", B64_ROOT))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("blindcrypt.active-key-version is blank")
                .satisfies(e -> assertThat(((BlindCryptConfigurationException) e).getAction()).contains("v1"));
        assertThatThrownBy(() -> KeyRing.fromBase64(keys, null, B64_ROOT))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("blindcrypt.active-key-version is blank");
    }

    @Test
    void fromBase64RejectsMissingBlindIndexKey() {
        Map<String, String> keys = Map.of("v1", B64_AES);
        assertThatThrownBy(() -> KeyRing.fromBase64(keys, "v1", null))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("blindcrypt.blind-index-key is not set");
        assertThatThrownBy(() -> KeyRing.fromBase64(keys, "v1", "  "))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("blindcrypt.blind-index-key is not set");
    }

    @Test
    void fromBase64RejectsBlankEncryptionKeyValueNamingTheVersion() {
        Map<String, String> keys = new java.util.HashMap<>();
        keys.put("v1", B64_AES);
        keys.put("v2", " ");
        assertThatThrownBy(() -> KeyRing.fromBase64(keys, "v1", B64_ROOT))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("blindcrypt.keys.v2 is blank");
    }

    @Test
    void fromBase64RejectsInvalidBase64WithoutEchoingKeyMaterial() {
        Map<String, String> keys = Map.of("v1", "not*base64*secret");
        assertThatThrownBy(() -> KeyRing.fromBase64(keys, "v1", B64_ROOT))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("blindcrypt.keys.v1 is not valid Base64")
                .hasMessageNotContaining("secret")
                .hasMessageNotContaining("*")
                .hasNoCause();
    }

    @Test
    void fromBase64RejectsDecodedKeyOfWrongLength() {
        Map<String, String> keys = Map.of("v1", Base64.getEncoder().encodeToString(new byte[16]));
        assertThatThrownBy(() -> KeyRing.fromBase64(keys, "v1", B64_ROOT))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("blindcrypt.keys.v1 must decode to 32 bytes");
    }

    @Test
    void constructorRejectsNullEncryptionKeyValue() {
        Map<String, byte[]> keys = new java.util.HashMap<>();
        keys.put("v1", null);
        assertThatThrownBy(() -> new KeyRing(keys, "v1", VALID_ROOT_KEY))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("blindcrypt.keys.v1 must decode to 32 bytes");
    }

    @Test
    void describeVersionQuotesOnlyVersionShapedValues() {
        assertThat(KeyRing.describeVersion("v1")).isEqualTo("key version 'v1'");
        assertThat(KeyRing.describeVersion("V12")).isEqualTo("key version 'V12'");
        assertThat(KeyRing.describeVersion("3")).isEqualTo("key version '3'");
        assertThat(KeyRing.describeVersion("alice@example.com")).isEqualTo("an invalid key version");
        assertThat(KeyRing.describeVersion(null)).isEqualTo("an invalid key version");
    }
}
