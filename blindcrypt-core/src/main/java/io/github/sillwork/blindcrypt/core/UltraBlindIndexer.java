package io.github.sillwork.blindcrypt.core;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC-SHA256 blind index calculator.
 * <p>
 * Clones a pre-initialised {@link Mac} per index instead of calling {@link Mac#getInstance(String)} and
 * {@link Mac#init(java.security.Key)} on every hash. If the provider's {@code Mac} does not support cloning,
 * a fresh {@code Mac} is created for that hash.
 */
public final class UltraBlindIndexer {

    private final KeyRing keyRing;
    private final Map<String, Mac> macPrototypes = new ConcurrentHashMap<>();
    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    /**
     * Constructs an UltraBlindIndexer backed by the specified cryptographic key repository.
     *
     * @param keyRing the active {@link KeyRing} used to derive HMAC subkeys
     */
    public UltraBlindIndexer(KeyRing keyRing) {
        this.keyRing = Objects.requireNonNull(keyRing, "keyRing cannot be null");
    }

    /**
     * Pre-warms and caches prototype Mac instances for a known index name and optional tenant.
     *
     * @param indexName the logical index identifier (e.g., "user_email")
     * @param tenantId  optional tenant identifier, or {@code null}. The Spring starter always passes {@code null}; multi-tenant indexing is available only through the core API.
     */
    public void registerIndex(String indexName, String tenantId) {
        String cacheKey = (tenantId != null ? tenantId + ":" : "") + indexName;
        macPrototypes.put(cacheKey, createPrototype(indexName, tenantId));
    }

    private Mac createPrototype(String indexName, String tenantId) {
        byte[] subkey = keyRing.deriveIndexSubkey(indexName, tenantId);
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(subkey, "HmacSHA256"));
            return mac;
        } catch (Exception e) {
            String cacheKey = (tenantId != null ? tenantId + ":" : "") + indexName;
            throw new CryptoException("Failed to initialise HmacSHA256 for blind index '" + cacheKey + "'.", e);
        }
    }

    /**
     * Computes a 32-byte raw binary blind index.
     * <p>
     * Rejects non-null values that normalize to an empty string to prevent NULL insertions
     * that bypass database UNIQUE constraints (Resolves Gap #2).
     *
     * @param indexName     the logical index identifier
     * @param value         the plaintext string
     * @param normalization the canonicalization strategy
     * @param tenantId      optional tenant ID, or {@code null}. The Spring starter always passes {@code null}; multi-tenant indexing is available only through the core API.
     * @return 32-byte raw HMAC-SHA256 binary hash, or null if value is null
     */
    @SuppressWarnings("java:S1168") // Returning null preserves database NULL semantics for unpopulated indexed fields
    public byte[] computeBinary(String indexName, String value, Normalization normalization, String tenantId) {
        if (value == null) return null;

        String normalized = normalization.normalize(value);
        if (normalized.isEmpty()) {
            throw new CryptoException("Value for blind index '" + indexName + "' is empty after " + normalization
                    + " normalization. Store null instead, or reject the input before saving.");
        }

        byte[] inputBytes = normalized.getBytes(StandardCharsets.UTF_8);
        return computeBinaryInternal(indexName, inputBytes, tenantId);
    }

    /**
     * Computes a 32-byte raw binary blind index directly from raw bytes.
     *
     * @param indexName the logical index identifier
     * @param value     raw bytes to hash
     * @param tenantId  optional tenant ID, or {@code null}. The Spring starter always passes {@code null}; multi-tenant indexing is available only through the core API.
     * @return 32-byte raw HMAC-SHA256 binary hash, or null if value is null
     */
    @SuppressWarnings("java:S1168")
    public byte[] computeBinary(String indexName, byte[] value, String tenantId) {
        if (value == null) return null;
        if (value.length == 0) {
            throw new CryptoException("Value for blind index '" + indexName + "' is an empty byte array. Store null instead.");
        }
        return computeBinaryInternal(indexName, value, tenantId);
    }

    private byte[] computeBinaryInternal(String indexName, byte[] data, String tenantId) {
        String cacheKey = (tenantId != null ? tenantId + ":" : "") + indexName;
        Mac prototype = macPrototypes.computeIfAbsent(cacheKey, keyContext -> createPrototype(indexName, tenantId));

        try {
            Mac mac = (Mac) prototype.clone();
            return mac.doFinal(data);
        } catch (CloneNotSupportedException e) {
            Mac fallback = createPrototype(indexName, tenantId);
            return fallback.doFinal(data);
        }
    }

    /**
     * Computes a deterministic 64-character lowercase hexadecimal blind index.
     *
     * @param indexName     the logical index identifier (e.g., "user_email")
     * @param value         the raw plaintext input string
     * @param normalization the canonicalization strategy applied prior to hashing
     * @param tenantId      optional tenant ID, or {@code null}. The Spring starter always passes {@code null}; multi-tenant indexing is available only through the core API.
     * @return 64-character lowercase hexadecimal HMAC-SHA256 string, or {@code null} if value is null
     * @throws CryptoException if normalization yields an empty string or hashing fails
     */
    public String computeHex(String indexName, String value, Normalization normalization, String tenantId) {
        byte[] binaryHash = computeBinary(indexName, value, normalization, tenantId);
        return binaryHash == null ? null : bytesToHex(binaryHash);
    }

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int unsignedByte = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_CHARS[unsignedByte >>> 4];
            hexChars[i * 2 + 1] = HEX_CHARS[unsignedByte & 0x0F];
        }
        return new String(hexChars);
    }
}
