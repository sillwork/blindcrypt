package io.github.sillwork.blindcrypt.spring.diagnostics;

import io.github.sillwork.blindcrypt.core.BlindCryptConfigurationException;
import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

/**
 * Turns a {@link BlindCryptConfigurationException} anywhere in a startup failure's cause chain into
 * Spring Boot's "APPLICATION FAILED TO START" report, with a description and a suggested action.
 */
public class BlindCryptFailureAnalyzer extends AbstractFailureAnalyzer<BlindCryptConfigurationException> {

    /**
     * Creates the analyzer. Instantiated by Spring Boot from {@code META-INF/spring.factories}.
     */
    public BlindCryptFailureAnalyzer() {
        // Registered via spring.factories
    }

    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, BlindCryptConfigurationException cause) {
        return new FailureAnalysis(cause.getMessage(), cause.getAction(), cause);
    }
}
