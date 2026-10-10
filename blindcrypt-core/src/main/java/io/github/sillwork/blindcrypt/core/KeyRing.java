package io.github.sillwork.blindcrypt.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Multi-version cryptographic key repository.
 * <p>
 * Manages active and historical AES-256 Data Encryption Keys (DEKs) along with the root key
 * for HMAC blind indexing. Enforces cryptographic invariants (32-byte key lengths, key divergence)
 * and pre-computes domain-separated subkeys to eliminate key derivation latency during runtime queries.
 */
public final class KeyRing {

    private static final Pattern VERSION_SHAPE = Pattern.compile("[vV]?\\d{1,3}");

    private final Map<String, byte[]> encryptionKeys;
    private final String activeKeyVersion;
    private final byte[] blindIndexRootKey;
    private final Map<String, byte[]> subkeyCache = new ConcurrentHashMap<>();

    /**
     * Constructs a validated KeyRing.
     *
     * @param encryptionKeys     map of version identifiers to 32-byte AES-256 keys
     * @param activeKeyVersion   the active key version used for new encryption writes
     * @param blindIndexRootKey  the 32-byte root key used for blind index subkey derivation
     * @throws BlindCryptConfigurationException if the active version has no key, a key is not 32 bytes,
     *                                          or the blind index key equals an encryption key
     */
    public KeyRing(Map<String, byte[]> encryptionKeys, String activeKeyVersion, byte[] blindIndexRootKey) {
        Objects.requireNonNull(encryptionKeys, "encryptionKeys cannot be null");
        Objects.requireNonNull(activeKeyVersion, "activeKeyVersion cannot be null");
        Objects.requireNonNull(blindIndexRootKey, "blindIndexRootKey cannot be null");

        if (!encryptionKeys.containsKey(activeKeyVersion)) {
            throw new BlindCryptConfigurationException(
                    "Active key version '" + activeKeyVersion + "' has no key in blindcrypt.keys.",
                    "Add blindcrypt.keys." + activeKeyVersion + " or set blindcrypt.active-key-version to one of " + encryptionKeys.keySet() + ".");
        }
        if (blindIndexRootKey.length != 32) {
            throw new BlindCryptConfigurationException(
                    "blindcrypt.blind-index-key must decode to 32 bytes but decodes to " + blindIndexRootKey.length + " bytes.",
                    "Generate a 256-bit key, for example: openssl rand -base64 32.");
        }
        for (Map.Entry<String, byte[]> entry : encryptionKeys.entrySet()) {
            if (entry.getValue() == null || entry.getValue().length != 32) {
                throw new BlindCryptConfigurationException(
                        "blindcrypt.keys." + entry.getKey() + " must decode to 32 bytes.",
                        "Generate a 256-bit key, for example: openssl rand -base64 32.");
            }
            if (MessageDigest.isEqual(entry.getValue(), blindIndexRootKey)) {
                throw new BlindCryptConfigurationException(
                        "blindcrypt.blind-index-key is identical to blindcrypt.keys." + entry.getKey() + ".",
                        "Use independent keys for encryption and blind indexing. Reusing a key couples the two and weakens both.");
            }
        }

        this.encryptionKeys = Map.copyOf(encryptionKeys);
        this.activeKeyVersion = activeKeyVersion;
        this.blindIndexRootKey = Arrays.copyOf(blindIndexRootKey, blindIndexRootKey.length);
    }

    /**
     * Factory method creating a validated KeyRing from Base64-encoded strings.
     *
     * @param base64EncryptionKeys map of key versions to 32-byte Base64-encoded AES keys
     * @param activeVersion        the active version identifier for new encryptions
     * @param base64BlindIndexKey  the 32-byte Base64-encoded root blind index key
     * @return a fully validated KeyRing instance
     * @throws BlindCryptConfigurationException if any key is missing, blank, not Base64, or not 32 bytes
     */
    public static KeyRing fromBase64(Map<String, String> base64EncryptionKeys, String activeVersion, String base64BlindIndexKey) {
        if (base64EncryptionKeys == null || base64EncryptionKeys.isEmpty()) {
            throw new BlindCryptConfigurationException("blindcrypt.keys is not set.",
                    "Add at least one encryption key, for example blindcrypt.keys.v1=<base64 32-byte key>.");
        }
        if (activeVersion == null || activeVersion.isBlank()) {
            throw new BlindCryptConfigurationException("blindcrypt.active-key-version is blank.",
                    "Set blindcrypt.active-key-version to one of " + base64EncryptionKeys.keySet() + ".");
        }
        if (base64BlindIndexKey == null || base64BlindIndexKey.isBlank()) {
            throw new BlindCryptConfigurationException("blindcrypt.blind-index-key is not set.",
                    "Set blindcrypt.blind-index-key to a Base64-encoded 32-byte key, for example: openssl rand -base64 32.");
        }

        Map<String, byte[]> decodedEncKeys = new LinkedHashMap<>();
        base64EncryptionKeys.forEach((version, base64Key) ->
                decodedEncKeys.put(version, decodeKey(base64Key, "blindcrypt.keys." + version)));
        byte[] decodedBlindKey = decodeKey(base64BlindIndexKey, "blindcrypt.blind-index-key");
        return new KeyRing(decodedEncKeys, activeVersion, decodedBlindKey);
    }

    private static byte[] decodeKey(String base64Key, String propertyName) {
        if (base64Key == null || base64Key.isBlank()) {
            throw new BlindCryptConfigurationException(propertyName + " is blank.",
                    "Set " + propertyName + " to a Base64-encoded 32-byte key.");
        }
        try {
            return Base64.getDecoder().decode(base64Key.trim());
        } catch (IllegalArgumentException e) {
            // The JDK message quotes the offending character, which is key material: do not chain it.
            throw new BlindCryptConfigurationException(propertyName + " is not valid Base64.",
                    "Set " + propertyName + " to a standard Base64-encoded 32-byte key.");
        }
    }

    /**
     * Returns a defensive copy of the currently active AES-256 encryption key.
     *
     * @return a new 32-byte array containing the active encryption key
     */
    public byte[] getActiveEncryptionKey() {
        byte[] key = encryptionKeys.get(activeKeyVersion);
        return Arrays.copyOf(key, key.length);
    }

    /**
     * Returns the version identifier of the active encryption key (e.g., "v1").
     *
     * @return the active key version string
     */
    public String getActiveKeyVersion() {
        return activeKeyVersion;
    }

    /**
     * Returns a defensive copy of the AES-256 encryption key associated with the specified version.
     *
     * @param version the key version identifier (e.g., "v1", "v2")
     * @return a new 32-byte array containing the requested encryption key
     * @throws CryptoException if no key is registered for the specified version
     */
    public byte[] getEncryptionKey(String version) {
        byte[] key = encryptionKeys.get(version);
        if (key == null) {
            throw new CryptoException("No encryption key is configured for " + describeVersion(version)
                    + ". Add it to blindcrypt.keys to read data written with that version.");
        }
        return Arrays.copyOf(key, key.length);
    }

    /**
     * Describes a key version for an error message without echoing arbitrary stored data.
     * <p>
     * The version is read from the stored value, so a legacy plaintext that happens to start with {@code ENC:}
     * would otherwise leak into logs. Only values shaped like a version ({@code v1}, {@code V12}, {@code 3}) are quoted.
     *
     * @param version the version segment read from a stored value
     * @return {@code key version 'v1'} for a version-shaped value, otherwise {@code an invalid key version}
     */
    static String describeVersion(String version) {
        if (version != null && VERSION_SHAPE.matcher(version).matches()) {
            return "key version '" + version + "'";
        }
        return "an invalid key version";
    }

    /**
     * Returns a defensive copy of the 32-byte root blind index HMAC key.
     *
     * @return a new 32-byte array containing the root blind index key
     */
    public byte[] getBlindIndexRootKey() {
        return Arrays.copyOf(blindIndexRootKey, blindIndexRootKey.length);
    }

    /**
     * Derives a dedicated 256-bit HMAC subkey for a specific index column and tenant.
     * <p>
     * Enforces cryptographic domain separation:
     * {@code HMAC(rootKey, "blind-index:v1:" + (tenantId ? tenantId + ":" : "") + indexName)}.
     * Results are cached internally after the first derivation.
     *
     * @param indexName the logical index identifier (e.g., "user_email")
     * @param tenantId  optional tenant identifier, or {@code null}. The Spring starter always passes {@code null}; multi-tenant indexing is available only through the core API.
     * @return a defensive copy of the derived 32-byte HMAC subkey
     * @throws CryptoException if HMAC subkey derivation fails
     */
    public byte[] deriveIndexSubkey(String indexName, String tenantId) {
        String cacheKey = (tenantId != null ? tenantId + ":" : "") + indexName;
        byte[] cachedSubkey = subkeyCache.computeIfAbsent(cacheKey, keyContext -> {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(this.blindIndexRootKey, "HmacSHA256"));
                String context = "blind-index:v1:" + keyContext;
                return mac.doFinal(context.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                throw new CryptoException("Failed to derive the blind index subkey for index '" + keyContext + "'.", e);
            }
        });
        return Arrays.copyOf(cachedSubkey, cachedSubkey.length);
    }
}
