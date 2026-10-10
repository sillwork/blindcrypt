package io.github.sillwork.blindcrypt.core;

/**
 * Binary codec for compact ciphertext serialization.
 * <p>
 * Encodes AES-256-GCM ciphertexts into an efficient, contiguous binary wire format:
 * <pre>
 * +--------------------+----------------------------+----------------------------------+
 * | Version (1 byte)   | Initialization Vector (12B)| Ciphertext + Tag (N + 16 bytes)  |
 * +--------------------+----------------------------+----------------------------------+
 * </pre>
 * <p>
 * Compared to string Base64 representations (which incur 33% storage inflation and string allocation overhead),
 * compact binary payloads store the exact minimum byte footprint.
 * Minimum packed length is 1 + 12 + 16 = 29 bytes.
 */
public final class CompactCiphertextCodec {

    /**
     * Size of the key version identifier prefix in bytes (1 byte).
     */
    public static final int VERSION_LENGTH = 1;

    /**
     * Size of the AES-GCM standard initialization vector in bytes (12 bytes = 96 bits).
     */
    public static final int IV_LENGTH = 12;

    /**
     * Size of the AES-GCM authentication tag in bytes (16 bytes = 128 bits).
     */
    public static final int TAG_LENGTH = 16;

    /**
     * Total combined header length (version + IV) in bytes (13 bytes).
     */
    public static final int HEADER_LENGTH = VERSION_LENGTH + IV_LENGTH; // 13 bytes

    /**
     * Minimum valid packed binary length: header (13 bytes) + authentication tag (16 bytes) = 29 bytes.
     */
    public static final int MIN_PACKED_LENGTH = HEADER_LENGTH + TAG_LENGTH; // 29 bytes

    private CompactCiphertextCodec() { }

    /**
     * Packs key version, IV, and combined ciphertext/authentication tag into a single contiguous byte array.
     *
     * @param version      the key version byte identifier
     * @param iv           the 12-byte initialization vector
     * @param cipherAndTag the combined encrypted ciphertext and 16-byte authentication tag
     * @return contiguous packed byte array suitable for binary database persistence
     */
    public static byte[] packBinary(byte version, byte[] iv, byte[] cipherAndTag) {
        byte[] payload = new byte[HEADER_LENGTH + cipherAndTag.length];
        payload[0] = version;
        System.arraycopy(iv, 0, payload, VERSION_LENGTH, iv.length);
        System.arraycopy(cipherAndTag, 0, payload, HEADER_LENGTH, cipherAndTag.length);
        return payload;
    }
}
