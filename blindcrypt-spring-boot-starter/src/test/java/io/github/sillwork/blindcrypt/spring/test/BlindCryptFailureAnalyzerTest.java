package io.github.sillwork.blindcrypt.spring.test;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import io.github.sillwork.blindcrypt.spring.diagnostics.BlindCryptFailureAnalyzer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.diagnostics.FailureAnalysis;
import static org.assertj.core.api.Assertions.assertThat;

class BlindCryptFailureAnalyzerTest {

    @Test
    void reportsDescriptionAndActionFromNestedCause() {
        BlindCryptConfigurationException root =
                new BlindCryptConfigurationException("blindcrypt.blind-index-key is not set.", "Set it.");
        FailureAnalysis analysis = new BlindCryptFailureAnalyzer()
                .analyze(new IllegalStateException("bean creation failed", root));

        assertThat(analysis).isNotNull();
        assertThat(analysis.getDescription()).isEqualTo("blindcrypt.blind-index-key is not set.");
        assertThat(analysis.getAction()).isEqualTo("Set it.");
    }
}
