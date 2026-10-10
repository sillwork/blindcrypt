package io.github.sillwork.blindcrypt.spring.config;

import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Spring Boot configuration properties for BlindCrypt under the {@code blindcrypt.*} namespace.
 * <p>
 * Configures the multi-version cryptographic key repository ({@link io.github.sillwork.blindcrypt.core.KeyRing}),
 * active key versioning, blind index HMAC root keys, and migration dual-read compatibility flags.
 *
 * <h2>Example {@code application.yml} Configuration</h2>
 * <pre>{@code
 * blindcrypt:
 *   # Active key version used for newly encrypted writes
 *   active-key-version: v1
 *
 *   # 32-byte Base64-encoded root key for HMAC-SHA256 blind indexing
 *   blind-index-key: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
 *
 *   # Map of all active and historical 32-byte Base64-encoded AES-256 keys
 *   keys:
 *     v1: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
 *     v2: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
 *
 *   # Enable during phased migrations to allow reading legacy unencrypted columns
 *   allow-plaintext-read: false
 * }</pre>
 *
 * <h2>Security Recommendations</h2>
 * <ul>
 *   <li>Store cryptographic keys in secure secret management systems (e.g. AWS Secrets Manager,
 *       HashiCorp Vault, Azure Key Vault, or Kubernetes Secrets) and inject them via environment variables.</li>
 *   <li>The {@link #blindIndexKey} <b>must never</b> be identical to any encryption key in {@link #keys}.
 *       BlindCrypt strictly validates key divergence at bootstrap.</li>
 * </ul>
 *
 * @see io.github.sillwork.blindcrypt.core.KeyRing
 * @see BlindCryptAutoConfiguration
 */
@ConfigurationProperties(prefix = "blindcrypt")
public class CryptoProperties {

    /** Creates the instance; Spring Boot's configuration properties binder instantiates it, not application code. */
    public CryptoProperties() {
        // Instantiated by Spring Boot's configuration properties binder, which then populates the properties.
    }

    /**
     * Whether BlindCrypt auto-configuration is active. Set to {@code false} to start the application
     * without BlindCrypt, for example in a module that has the starter on its classpath but no encrypted entities.
     */
    private boolean enabled = true;

    /**
     * Active AES-256 encryption key version identifier (e.g. {@code "v1"}).
     * Newly created or updated entities will encrypt data using this key.
     */
    private String activeKeyVersion = "v1";

    /**
     * Map of key version identifiers (e.g. {@code "v1"}, {@code "v2"}) to 32-byte Base64-encoded AES-256 keys.
     * Must contain at least the version declared in {@link #activeKeyVersion}.
     */
    private Map<String, String> keys;

    /**
     * 32-byte Base64-encoded root key used for deriving domain-separated HMAC-SHA256 blind index subkeys.
     */
    private String blindIndexKey;

    /**
     * Flag indicating whether unencrypted legacy plaintext is permitted during dual-read migration phases.
     * When {@code false} (the default), reading unencrypted payload triggers a {@link io.github.sillwork.blindcrypt.core.CryptoException}.
     */
    private boolean allowPlaintextRead = false;

    /**
     * Returns whether BlindCrypt auto-configuration is active.
     *
     * @return {@code true} if BlindCrypt is enabled (the default)
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether BlindCrypt auto-configuration is active.
     *
     * @param enabled {@code false} to start the application without BlindCrypt
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Returns the active AES-256 encryption key version identifier.
     *
     * @return the active key version string (e.g. {@code "v1"})
     */
    public String getActiveKeyVersion() {
        return activeKeyVersion;
    }

    /**
     * Sets the active AES-256 encryption key version identifier.
     *
     * @param activeKeyVersion the active key version to use for new encryptions
     */
    public void setActiveKeyVersion(String activeKeyVersion) {
        this.activeKeyVersion = activeKeyVersion;
    }

    /**
     * Returns the map of version identifiers to Base64-encoded AES-256 keys.
     *
     * @return the map of encryption keys
     */
    public Map<String, String> getKeys() {
        return keys;
    }

    /**
     * Sets the map of version identifiers to Base64-encoded AES-256 keys.
     *
     * @param keys the map of encryption keys
     */
    public void setKeys(Map<String, String> keys) {
        this.keys = keys;
    }

    /**
     * Returns the 32-byte Base64-encoded root key for HMAC-SHA256 blind indexing.
     *
     * @return the Base64 root blind index key
     */
    public String getBlindIndexKey() {
        return blindIndexKey;
    }

    /**
     * Sets the 32-byte Base64-encoded root key for HMAC-SHA256 blind indexing.
     *
     * @param blindIndexKey the Base64 root blind index key
     */
    public void setBlindIndexKey(String blindIndexKey) {
        this.blindIndexKey = blindIndexKey;
    }

    /**
     * Returns whether legacy unencrypted plaintext is permitted during dual-read migration phases.
     *
     * @return {@code true} if unencrypted plaintexts can be read without throwing CryptoException
     */
    public boolean isAllowPlaintextRead() {
        return allowPlaintextRead;
    }

    /**
     * Sets whether legacy unencrypted plaintext is permitted during dual-read migration phases.
     *
     * @param allowPlaintextRead {@code true} to permit reading unencrypted data during migrations
     */
    public void setAllowPlaintextRead(boolean allowPlaintextRead) {
        this.allowPlaintextRead = allowPlaintextRead;
    }

    /**
     * Returns a safe string representation redacting sensitive cryptographic keys.
     *
     * @return string displaying the active version with keys protected
     */
    @Override
    public String toString() {
        return "CryptoProperties[activeVersion=" + activeKeyVersion + ", keys=[PROTECTED]]";
    }
}
