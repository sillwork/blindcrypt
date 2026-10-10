package io.github.sillwork.blindcrypt.core;

/**
 * Root of every exception BlindCrypt throws on purpose.
 * <p>
 * Catch this type to handle any BlindCrypt failure. Catch a subtype to tell them apart:
 * <ul>
 *   <li>{@link BlindCryptConfigurationException}: the application is configured incorrectly. Raised normally at startup,
 *       or at first use if BlindCrypt is disabled or not initialised; fix configuration or mapping code and restart.</li>
 *   <li>{@link CryptoException}: a cryptographic operation failed at runtime, for example a ciphertext that
 *       fails authentication or references an unknown key version.</li>
 * </ul>
 * Messages never contain plaintext values, key material, or blind index hashes.
 */
public class BlindCryptException extends RuntimeException {

    /**
     * Creates an exception with a message that is safe to log.
     *
     * @param message description of the failure; must not contain plaintext or key material
     */
    public BlindCryptException(String message) {
        super(message);
    }

    /**
     * Creates an exception with a message that is safe to log and the underlying cause.
     *
     * @param message description of the failure; must not contain plaintext or key material
     * @param cause   the underlying exception
     */
    public BlindCryptException(String message, Throwable cause) {
        super(message, cause);
    }
}
