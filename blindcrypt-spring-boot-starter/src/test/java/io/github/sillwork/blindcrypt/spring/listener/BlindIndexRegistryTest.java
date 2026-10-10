package io.github.sillwork.blindcrypt.spring.listener;

import io.github.sillwork.blindcrypt.core.KeyRing;
import io.github.sillwork.blindcrypt.core.Normalization;
import io.github.sillwork.blindcrypt.core.UltraBlindIndexer;
import io.github.sillwork.blindcrypt.spring.annotation.BlindIndex;
import io.github.sillwork.blindcrypt.spring.model.EncryptedBytes;
import io.github.sillwork.blindcrypt.spring.model.EncryptedText;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BlindIndexRegistryTest {

    static class Base {
        @BlindIndex(name = "base_text", normalization = Normalization.TRIM_CASE_INSENSITIVE)
        EncryptedText inherited;
    }

    static class Sample extends Base {
        @BlindIndex(name = "raw_bytes", normalization = Normalization.NONE)
        EncryptedBytes raw;

        @BlindIndex(name = "normalized_bytes", normalization = Normalization.TRIM_CASE_INSENSITIVE)
        EncryptedBytes normalized;

        @BlindIndex(name = "text", normalization = Normalization.DIGITS_ONLY)
        EncryptedText text;

        @BlindIndex(name = "unused_text", normalization = Normalization.NONE)
        EncryptedText absentText;

        @BlindIndex(name = "unused_bytes", normalization = Normalization.NONE)
        EncryptedBytes absentBytes;

        @BlindIndex(name = "not_encrypted", normalization = Normalization.NONE)
        String wrongType = "ignored";

        String unindexed;
    }

    private UltraBlindIndexer indexer;
    private BlindIndexRegistry registry;

    @BeforeEach
    void setUp() {
        byte[] blindKey = new byte[32];
        blindKey[0] = 3;
        indexer = new UltraBlindIndexer(new KeyRing(Map.of("v1", new byte[32]), "v1", blindKey));
        registry = new BlindIndexRegistry(indexer);
    }

    @Test
    void assignsIndexesFromTheNormalisedPlaintextForEveryFieldKind() {
        Sample sample = new Sample();
        sample.inherited = EncryptedText.of("  Mixed Case ");
        sample.raw = EncryptedBytes.of(new byte[] {1, 2, 3});
        sample.normalized = EncryptedBytes.of("  Mixed Case ".getBytes(StandardCharsets.UTF_8));
        sample.text = EncryptedText.of("(555) 010-0");

        registry.computeAndAssignIndexes(sample);

        assertThat(sample.inherited.blindIndex())
                .isEqualTo(indexer.computeHex("base_text", "mixed case", Normalization.TRIM_CASE_INSENSITIVE, null));
        assertThat(sample.raw.blindIndex()).isEqualTo(indexer.computeBinary("raw_bytes", new byte[] {1, 2, 3}, null));
        assertThat(sample.normalized.blindIndex())
                .isEqualTo(indexer.computeBinary("normalized_bytes", "  Mixed Case ", Normalization.TRIM_CASE_INSENSITIVE, null));
        assertThat(sample.text.blindIndex()).isEqualTo(indexer.computeHex("text", "5550100", Normalization.DIGITS_ONLY, null));
    }

    @Test
    void indexIsClearedWhenTheValueIsNullAndNullFieldsAreSkipped() {
        Sample sample = new Sample();
        sample.text = EncryptedText.of("555");
        sample.text.assignBlindIndex("stale");
        sample.absentText = EncryptedText.update(null, null);
        sample.raw = EncryptedBytes.update(null, null);

        assertThatCode(() -> registry.computeAndAssignIndexes(sample)).doesNotThrowAnyException();
        assertThat(sample.text.blindIndex()).isNotEqualTo("stale");
        assertThat(sample.absentText).isNull();
        assertThat(sample.raw).isNull();
    }

    @Test
    void nullEntityIsIgnored() {
        assertThatCode(() -> registry.computeAndAssignIndexes(null)).doesNotThrowAnyException();
    }

    @Test
    void entityWithoutBlindIndexFieldsIsLeftAlone() {
        assertThatCode(() -> registry.computeAndAssignIndexes(new Object())).doesNotThrowAnyException();
    }

    @Test
    void findsAnnotationsIncludingInheritedOnesAndOnlyOnIndexedFields() {
        assertThat(registry.findBlindIndexAnnotation(Sample.class, "text")).get().extracting(BlindIndex::name).isEqualTo("text");
        assertThat(registry.findBlindIndexAnnotation(Sample.class, "inherited")).get()
                .extracting(BlindIndex::name).isEqualTo("base_text");
        assertThat(registry.findBlindIndexAnnotation(Sample.class, "unindexed")).isEmpty();
        assertThat(registry.findBlindIndexAnnotation(Sample.class, "missing")).isEmpty();
    }

    @Test
    void constructorRejectsNullIndexer() {
        assertThatThrownBy(() -> new BlindIndexRegistry(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("blindIndexer");
    }
}
