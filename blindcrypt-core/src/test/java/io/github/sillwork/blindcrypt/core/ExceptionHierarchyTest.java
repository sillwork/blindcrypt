package io.github.sillwork.blindcrypt.core;

import java.util.Map;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ExceptionHierarchyTest {

    private static final String VALID_KEY = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=";
    private static final String OTHER_VALID_KEY = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";

    @Test
    void bothSubtypesShareTheLibraryRoot() {
        assertThat(new CryptoException("x")).isInstanceOf(BlindCryptException.class);
        assertThat(new BlindCryptConfigurationException("x", "y")).isInstanceOf(BlindCryptException.class);
        assertThat(new BlindCryptConfigurationException("x", "do y").getAction()).isEqualTo("do y");
    }

    @Test
    void invalidBase64KeyIsConfigurationErrorWithoutEchoingKeyMaterial() {
        Map<String, String> keys = Map.of("v1", "not-base64-%%%");
        assertThatThrownBy(() -> KeyRing.fromBase64(keys, "v1", OTHER_VALID_KEY))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("blindcrypt.keys.v1")
                .hasMessageNotContaining("%%%")
                .hasMessageNotContaining("not-base64");
    }

    @Test
    void invalidBase64BlindIndexKeyNamesTheProperty() {
        Map<String, String> keys = Map.of("v1", VALID_KEY);
        assertThatThrownBy(() -> KeyRing.fromBase64(keys, "v1", "%%%"))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("blindcrypt.blind-index-key");
    }

    @Test
    void missingKeysMapIsConfigurationError() {
        assertThatThrownBy(() -> KeyRing.fromBase64(null, "v1", OTHER_VALID_KEY))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("blindcrypt.keys");
    }

    @Test
    void missingBlindIndexKeyIsConfigurationError() {
        Map<String, String> keys = Map.of("v1", VALID_KEY);
        assertThatThrownBy(() -> KeyRing.fromBase64(keys, "v1", null))
                .isInstanceOf(BlindCryptConfigurationException.class)
                .hasMessageContaining("blindcrypt.blind-index-key");
    }
}
