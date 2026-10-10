package io.github.sillwork.blindcrypt.core;

/**
 * Thrown when BlindCrypt is configured incorrectly: missing or malformed keys, an unsupported entity mapping,
 * or a repository method that cannot be rewritten into a blind index query.
 * <p>
 * BlindCrypt normally raises this during application startup so that misconfiguration does not reach production
 * traffic. It is raised at first use instead when BlindCrypt is disabled or not initialised (for example an
 * {@code @Encrypted} entity is read or written while {@code blindcrypt.enabled=false}). In Spring Boot applications the failure is reported with a description and a suggested {@link #getAction() action}.
 */
public class BlindCryptConfigurationException extends BlindCryptException {

    /**
     * The suggested fix for this misconfiguration, or {@code null} when none was supplied.
     */
    private final String action;

    /**
     * Creates a configuration exception.
     *
     * @param message what is wrong, naming the property, entity or method involved
     * @param action  what the developer should change to fix it
     */
    public BlindCryptConfigurationException(String message, String action) {
        super(message);
        this.action = action;
    }

    /**
     * Creates a configuration exception with an underlying cause.
     *
     * @param message what is wrong, naming the property, entity or method involved
     * @param action  what the developer should change to fix it
     * @param cause   the underlying exception
     */
    public BlindCryptConfigurationException(String message, String action, Throwable cause) {
        super(message, cause);
        this.action = action;
    }

    /**
     * Returns the suggested fix for this misconfiguration.
     *
     * @return a short instruction, never {@code null}
     */
    public String getAction() {
        return action == null ? "Review the BlindCrypt configuration." : action;
    }
}
