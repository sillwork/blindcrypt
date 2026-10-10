package io.github.sillwork.blindcrypt.core;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM field encryptor with optional caller-supplied associated data.
 * <p>
 * Supports both compact binary wire formats and standard Base64 string formats.
 * Associated data (AAD) passed by the caller is bound into the GCM authentication tag, so a ciphertext
 * moved to a different row or column is detected when callers pass row-specific associated data
 * (for example a table, column and record identifier). If callers pass {@code null}, no such binding exists.
 */
public final class FieldEncryptor {

    /**
     * Standard ciphertext string prefix {@code "ENC"} denoting an encrypted BlindCrypt payload.
     */
    public static final String PREFIX = "ENC";

    /**
     * Standard AES-GCM Initialization Vector (nonce) length in bytes (12 bytes = 96 bits).
     */
    public static final int GCM_IV_LENGTH_BYTES = 12;

    /**
     * Standard AES-GCM Authentication Tag length in bits (128 bits = 16 bytes).
     */
    public static final int GCM_TAG_LENGTH_BITS = 128;

    private final KeyRing keyRing;
    private final StripedCipherPool cipherPool;
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Constructs a FieldEncryptor with the given key repository and cipher pool.
     *
     * @param keyRing    the multi-version {@link KeyRing} providing active and historical keys
     * @param cipherPool the virtual-thread-safe {@link StripedCipherPool} for AES/GCM/NoPadding ciphers
     * @throws BlindCryptConfigurationException if the active key version is outside the binary range v1 to v127
     */
    public FieldEncryptor(KeyRing keyRing, StripedCipherPool cipherPool) {
        this.keyRing = Objects.requireNonNull(keyRing, "keyRing cannot be null");
        this.cipherPool = Objects.requireNonNull(cipherPool, "cipherPool cannot be null");
        String activeVersion = keyRing.getActiveKeyVersion();
        try {
            parseVersionByte(activeVersion);
        } catch (CryptoException e) {
            throw new BlindCryptConfigurationException(
                    "blindcrypt.active-key-version '" + activeVersion + "' is not valid.",
                    "Use a version between v1 and v127.", e);
        }
    }

    /**
     * Encrypts plaintext bytes into a compact binary layout:
     * {@code [Version: 1B][IV: 12B][Ciphertext + 16B Tag]}.
     *
     * @param plaintext     raw plaintext bytes to encrypt
     * @param contextualAad contextual metadata (e.g. "users:email:101") bound into GCM authentication tag
     * @return packed binary ciphertext, or null if plaintext is null
     */
    @SuppressWarnings("java:S1168") // Returning null preserves database NULL semantics for nullable columns
    public byte[] encryptToBinary(byte[] plaintext, String contextualAad) {
        if (plaintext == null) return null;

        String versionStr = keyRing.getActiveKeyVersion();
        byte versionByte = parseVersionByte(versionStr);
        byte[] keyBytes = keyRing.getActiveEncryptionKey();

        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);

        byte[] aadBytes = buildAad(versionStr, contextualAad);
        byte[] cipherAndTag;

        Cipher cipher = cipherPool.borrowCipher();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            cipher.updateAAD(aadBytes);
            cipherAndTag = cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new CryptoException("AES-256-GCM encryption failed for key version '" + versionStr + "'.", e);
        } finally {
            cipherPool.returnCipher(cipher);
        }

        return CompactCiphertextCodec.packBinary(versionByte, iv, cipherAndTag);
    }

    /**
     * Decrypts compact binary ciphertext and verifies AAD integrity.
     *
     * @param packedPayload binary ciphertext produced by {@link #encryptToBinary(byte[], String)}
     * @param contextualAad the identical contextual metadata used during encryption
     * @return decrypted plaintext bytes
     * @throws CryptoException if the authentication tag does not match or the ciphertext is corrupted
     */
    @SuppressWarnings("java:S1168") // Returning null preserves database NULL semantics for nullable columns
    public byte[] decryptFromBinary(byte[] packedPayload, String contextualAad) {
        return decryptFromBinary(packedPayload, contextualAad, false);
    }

    /**
     * Decrypts compact binary ciphertext and verifies AAD integrity, with optional legacy plaintext passthrough.
     * <p>
     * Binary payloads have no unambiguous header, so passthrough here is best effort: a payload that is too short
     * or names an unknown key version is returned unchanged. This is not tightened because it would break legacy
     * rows whose first byte happens to equal a key version.
     *
     * @param packedPayload  binary ciphertext produced by {@link #encryptToBinary(byte[], String)}
     * @param contextualAad  the identical contextual metadata used during encryption
     * @param allowPlaintext whether unencrypted binary payload is permitted during migration
     * @return decrypted plaintext bytes
     * @throws CryptoException if the authentication tag does not match or the ciphertext is corrupted
     */
    @SuppressWarnings("java:S1168") // Returning null preserves database NULL semantics for nullable columns
    public byte[] decryptFromBinary(byte[] packedPayload, String contextualAad, boolean allowPlaintext) {
        if (packedPayload == null) return null;
        if (packedPayload.length < CompactCiphertextCodec.MIN_PACKED_LENGTH) {
            if (allowPlaintext) {
                return packedPayload;
            }
            throw new CryptoException("Corrupted binary payload: smaller than header + tag length");
        }

        byte versionByte = packedPayload[0];
        String versionStr = "v" + versionByte;
        byte[] keyBytes;
        try {
            keyBytes = keyRing.getEncryptionKey(versionStr);
        } catch (CryptoException e) {
            try {
                keyBytes = keyRing.getEncryptionKey(String.valueOf(versionByte));
                versionStr = String.valueOf(versionByte);
            } catch (CryptoException ignored) {
                if (allowPlaintext) {
                    return packedPayload;
                }
                throw e;
            }
        }

        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        System.arraycopy(packedPayload, 1, iv, 0, GCM_IV_LENGTH_BYTES);

        int cipherLen = packedPayload.length - CompactCiphertextCodec.HEADER_LENGTH;
        byte[] cipherAndTag = new byte[cipherLen];
        System.arraycopy(packedPayload, CompactCiphertextCodec.HEADER_LENGTH, cipherAndTag, 0, cipherLen);

        byte[] aadBytes = buildAad(versionStr, contextualAad);

        Cipher cipher = cipherPool.borrowCipher();
        try {
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            cipher.updateAAD(aadBytes);
            return cipher.doFinal(cipherAndTag);
        } catch (Exception e) {
            if (allowPlaintext) {
                return packedPayload;
            }
            throw new CryptoException("Decryption failed for " + KeyRing.describeVersion(versionStr) + ": authentication tag mismatch. "
                    + "The ciphertext was modified, was encrypted with a different key, or was written with different associated data.", e);
        } finally {
            cipherPool.returnCipher(cipher);
        }
    }

    /**
     * Encrypts a plaintext string into an interoperable formatted string:
     * {@code ENC:<version>:<base64(iv || ciphertext || tag)>}.
     *
     * @param plaintext     the plaintext UTF-8 string to encrypt
     * @param contextualAad contextual metadata (e.g. "users:email:101") bound into the GCM authentication tag
     * @return formatted ciphertext string, or {@code null} if plaintext is null
     * @throws CryptoException if encryption fails
     */
    public String encryptToString(String plaintext, String contextualAad) {
        if (plaintext == null) return null;
        byte[] plainBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] binaryPacked = encryptToBinary(plainBytes, contextualAad);
        if (binaryPacked == null) {
            return null;
        }

        // Skip 1-byte version for Base64 payload: payload = IV (12B) + CipherAndTag
        int payloadLen = binaryPacked.length - 1;
        byte[] ivAndCipher = new byte[payloadLen];
        System.arraycopy(binaryPacked, 1, ivAndCipher, 0, payloadLen);
        String base64 = Base64.getEncoder().encodeToString(ivAndCipher);

        return PREFIX + ":" + keyRing.getActiveKeyVersion() + ":" + base64;
    }

    /**
     * Decrypts a formatted ciphertext string and verifies the authentication tag, which covers
     * the ciphertext and the supplied associated data.
     *
     * @param storedValue   the encrypted string in format {@code ENC:<version>:<base64>}
     * @param contextualAad the identical contextual metadata used during encryption
     * @return decrypted plaintext UTF-8 string, or {@code null} if storedValue is null
     * @throws CryptoException if ciphertext is malformed, truncated, references an unknown key version, or fails authentication
     */
    public String decryptFromString(String storedValue, String contextualAad) {
        return decryptFromString(storedValue, contextualAad, false);
    }

    /**
     * Decrypts a formatted ciphertext string, with optional legacy plaintext passthrough.
     * <p>
     * When {@code allowPlaintext} is {@code true}, values without the {@code ENC:} header are returned unchanged.
     * Values with the header must decrypt successfully or a {@link CryptoException} is thrown.
     *
     * @param storedValue    the encrypted string in format {@code ENC:<version>:<base64>}
     * @param contextualAad  the identical contextual metadata used during encryption
     * @param allowPlaintext whether unencrypted plaintext is permitted during dual-read migration
     * @return decrypted plaintext UTF-8 string, or {@code null} if storedValue is null
     * @throws CryptoException if ciphertext is malformed, truncated, references an unknown key version, or fails authentication
     */
    public String decryptFromString(String storedValue, String contextualAad, boolean allowPlaintext) {
        if (storedValue == null) {
            return null;
        }
        // Passthrough is only for values that were never encrypted. A value carrying the ENC: header is
        // ciphertext; if it fails to decrypt it is tampered, truncated or keyed with a missing version,
        // and returning it as data would hide that.
        if (allowPlaintext && !storedValue.startsWith(PREFIX + ":")) {
            return storedValue;
        }
        return performDecryptString(storedValue, contextualAad);
    }

    private String performDecryptString(String storedValue, String contextualAad) {
        if (!storedValue.startsWith(PREFIX + ":")) {
            throw new CryptoException("Invalid ciphertext header: expected 'ENC:' prefix");
        }

        // Split-free scanner: avoids String.split(":") young-gen GC allocations
        int firstColon = storedValue.indexOf(':');
        int secondColon = storedValue.indexOf(':', firstColon + 1);
        if (firstColon == -1 || secondColon == -1) {
            throw new CryptoException("Malformed ciphertext tokens: expected 3 colon-separated segments");
        }

        String versionStr = storedValue.substring(firstColon + 1, secondColon);
        String base64Payload = storedValue.substring(secondColon + 1);

        byte[] rawPayload;
        try {
            rawPayload = Base64.getDecoder().decode(base64Payload);
        } catch (IllegalArgumentException e) {
            throw new CryptoException("Corrupted base64 payload in ciphertext", e);
        }

        if (rawPayload.length < GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8)) {
            throw new CryptoException("Truncated ciphertext: payload smaller than IV + Tag length");
        }

        byte[] keyBytes = keyRing.getEncryptionKey(versionStr);
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        System.arraycopy(rawPayload, 0, iv, 0, GCM_IV_LENGTH_BYTES);

        int cipherLen = rawPayload.length - GCM_IV_LENGTH_BYTES;
        byte[] cipherBytes = new byte[cipherLen];
        System.arraycopy(rawPayload, GCM_IV_LENGTH_BYTES, cipherBytes, 0, cipherLen);

        byte[] aadBytes = buildAad(versionStr, contextualAad);

        Cipher cipher = cipherPool.borrowCipher();
        try {
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            cipher.updateAAD(aadBytes);
            byte[] decrypted = cipher.doFinal(cipherBytes);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new CryptoException("Decryption failed for " + KeyRing.describeVersion(versionStr) + ": authentication tag mismatch. "
                    + "The ciphertext was modified, was encrypted with a different key, or was written with different associated data.", e);
        } finally {
            cipherPool.returnCipher(cipher);
        }
    }

    private byte[] buildAad(String version, String contextualAad) {
        String aad = PREFIX + ":" + version + (contextualAad != null ? ":" + contextualAad : "");
        return aad.getBytes(StandardCharsets.UTF_8);
    }

    private byte parseVersionByte(String versionStr) {
        try {
            if (versionStr.startsWith("v") || versionStr.startsWith("V")) {
                int val = Integer.parseInt(versionStr.substring(1));
                if (val < 1 || val > 127) {
                    throw new CryptoException("Key version '" + versionStr + "' is not valid for binary ciphertext. Use 'v1' to 'v127'.");
                }
                return (byte) val;
            }
            int val = Integer.parseInt(versionStr);
            if (val < 1 || val > 127) {
                throw new CryptoException("Key version '" + versionStr + "' is not valid for binary ciphertext. Use 'v1' to 'v127'.");
            }
            return (byte) val;
        } catch (NumberFormatException e) {
            throw new CryptoException("Key version '" + versionStr + "' is not valid for binary ciphertext. Use 'v1' to 'v127'.", e);
        }
    }
}
