package io.github.sillwork.blindcrypt.core;

import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UltraBlindIndexerTest {

    private KeyRing keyRing;
    private UltraBlindIndexer indexer;

    @BeforeEach
    void setUp() {
        byte[] encKey = new byte[32];
        byte[] blindKey = new byte[32];
        for (int i = 0; i < 32; i++) {
            encKey[i] = (byte) (i + 1);
            blindKey[i] = (byte) (i + 50);
        }

        keyRing = new KeyRing(Map.of("v1", encKey), "v1", blindKey);
        indexer = new UltraBlindIndexer(keyRing);
        indexer.registerIndex("user_email", null);
    }

    @Test
    void testComputeBinaryDeterministic() {
        byte[] hash1 = indexer.computeBinary("user_email", "Alex@Company.com", Normalization.TRIM_CASE_INSENSITIVE, null);
        byte[] hash2 = indexer.computeBinary("user_email", "  alex@company.com ", Normalization.TRIM_CASE_INSENSITIVE, null);

        assertThat(hash1)
                .isNotNull()
                .hasSize(32)
                .isEqualTo(hash2);
    }

    @Test
    void testComputeHexDeterministic() {
        String hex1 = indexer.computeHex("user_email", "Alex@Company.com", Normalization.TRIM_CASE_INSENSITIVE, null);
        String hex2 = indexer.computeHex("user_email", "  alex@company.com ", Normalization.TRIM_CASE_INSENSITIVE, null);

        assertThat(hex1)
                .matches("^[0-9a-f]{64}$")
                .isEqualTo(hex2);
    }

    @Test
    void testDomainSeparationAcrossIndexes() {
        String emailHash = indexer.computeHex("user_email", "alex@company.com", Normalization.TRIM_CASE_INSENSITIVE, null);
        String auditHash = indexer.computeHex("audit_email", "alex@company.com", Normalization.TRIM_CASE_INSENSITIVE, null);

        assertThat(emailHash).isNotEqualTo(auditHash);
    }

    @Test
    void testTenantSaltIsolation() {
        String tenantAHash = indexer.computeHex("user_email", "alex@company.com", Normalization.TRIM_CASE_INSENSITIVE, "tenant-A");
        String tenantBHash = indexer.computeHex("user_email", "alex@company.com", Normalization.TRIM_CASE_INSENSITIVE, "tenant-B");

        assertThat(tenantAHash).isNotEqualTo(tenantBHash);
    }

    @Test
    void testValuesNormalizingToEmptyAreRejected() {
        // Resolves Gap #2
        assertThatThrownBy(() -> indexer.computeHex("user_email", "   ", Normalization.TRIM_CASE_INSENSITIVE, null))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("is empty after");
    }

    @Test
    void testComputeBinaryWithBytes() {
        byte[] raw = new byte[]{1, 2, 3, 4};
        byte[] hash1 = indexer.computeBinary("user_email", raw, null);
        byte[] hash2 = indexer.computeBinary("user_email", raw, null);

        assertThat(hash1).isNotNull().hasSize(32).isEqualTo(hash2);
        assertThat(indexer.computeBinary("user_email", (byte[]) null, null)).isNull();
        assertThat(indexer.computeBinary("user_email", (String) null, Normalization.NONE, null)).isNull();
        assertThat(indexer.computeHex("user_email", null, Normalization.NONE, null)).isNull();

        assertThatThrownBy(() -> indexer.computeBinary("user_email", new byte[0], null))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("is an empty byte array");
    }

    @Test
    void testUnregisteredIndexComputesOnDemand() {
        // Index not explicitly pre-registered; should dynamically compute and cache
        byte[] hash = indexer.computeBinary("unregistered_field", "test_val", Normalization.NONE, "tenant_x");
        assertThat(hash).isNotNull().hasSize(32);
    }

    @Test
    void registeredIndexProducesTheSameValueAsOnDemandComputation() {
        UltraBlindIndexer other = new UltraBlindIndexer(new KeyRing(
                Map.of("v1", new byte[32]), "v1", rootKey()));
        other.registerIndex("email", "tenant-a");
        byte[] registered = other.computeBinary("email", "a@b.com", Normalization.NONE, "tenant-a");

        UltraBlindIndexer onDemand = new UltraBlindIndexer(new KeyRing(
                Map.of("v1", new byte[32]), "v1", rootKey()));
        assertThat(registered)
                .isEqualTo(onDemand.computeBinary("email", "a@b.com", Normalization.NONE, "tenant-a"))
                .isNotEqualTo(onDemand.computeBinary("email", "a@b.com", Normalization.NONE, null));
    }

    private static byte[] rootKey() {
        byte[] key = new byte[32];
        key[0] = 9;
        return key;
    }
}
