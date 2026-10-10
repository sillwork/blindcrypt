package io.github.sillwork.blindcrypt.core;

/**
 * Thrown when an encrypt, decrypt or hash operation fails at runtime.
 * <p>
 * <b>Log Safety Guarantee:</b> To prevent accidental security breaches through centralized application logging
 * or monitoring tools (e.g. Datadog, ELK, CloudWatch), {@code CryptoException} exception messages
 * deliberately exclude raw plaintexts, encryption keys, or sensitive values.
 *
 * <h2>Common Failure Scenarios</h2>
 * <ul>
 *   <li><b>Authentication tag mismatch</b>: the ciphertext was modified, moved across rows or columns, or encrypted
 *       with a different key or associated data.</li>
 *   <li><b>Malformed or truncated ciphertext</b>: the payload is shorter than header plus tag length, or has an
 *       invalid header or version.</li>
 *   <li><b>Unknown key version</b>: stored data references a key version that is not registered.</li>
 *   <li><b>Empty value</b>: a non-null value normalized to empty under a blind index.</li>
 *   <li><b>JCA provider failure</b>: the cipher or MAC could not be initialised.</li>
 * </ul>
 * Misconfiguration is reported as {@link BlindCryptConfigurationException} instead.
 */
public class CryptoException extends BlindCryptException {

    /**
     * Constructs a new CryptoException with the specified safe descriptive message.
     *
     * @param message human-readable error explanation (must not contain sensitive plaintexts or keys)
     */
    public CryptoException(String message) {
        super(message);
    }

    /**
     * Constructs a new CryptoException with the specified message and underlying root cause.
     *
     * @param message human-readable error explanation
     * @param cause   the underlying cryptographic cause (e.g. {@link javax.crypto.AEADBadTagException})
     */
    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
