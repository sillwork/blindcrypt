package io.github.sillwork.blindcrypt.core;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class FastNormalizerTest {

    @Test
    void testNormalizeEmailAsciiFastPath() {
        assertThat(FastNormalizer.normalizeEmail("  Alex.Morgan@Company.COM  ")).isEqualTo("alex.morgan@company.com");
        assertThat(FastNormalizer.normalizeEmail("test@example.com")).isEqualTo("test@example.com");
        assertThat(FastNormalizer.normalizeEmail("   ")).isEmpty();
        assertThat(FastNormalizer.normalizeEmail(null)).isEmpty();
    }

    @Test
    void testNormalizeEmailUnicodeFallback() {
        // Accented characters (e.g. é -> e with NFKC decomposition)
        String input = "  René@Company.FR ";
        String normalized = FastNormalizer.normalizeEmail(input);
        assertThat(normalized).contains("company.fr");
    }

    @Test
    void testNormalizeDigits() {
        assertThat(FastNormalizer.normalizeDigits("+91 (98450) 12345")).isEqualTo("919845012345");
        assertThat(FastNormalizer.normalizeDigits("abc-123-xyz-456")).isEqualTo("123456");
        assertThat(FastNormalizer.normalizeDigits("no digits")).isEmpty();
        assertThat(FastNormalizer.normalizeDigits(null)).isEmpty();
    }

    @Test
    void testNormalizeLast4Digits() {
        assertThat(FastNormalizer.normalizeLast4Digits("+91 98450 12345")).isEqualTo("2345");
        assertThat(FastNormalizer.normalizeLast4Digits("123")).isEmpty();
        assertThat(FastNormalizer.normalizeLast4Digits(null)).isEmpty();
    }

    @Test
    void testNormalizeTrim() {
        assertThat(FastNormalizer.normalizeTrim("  hello world  ")).isEqualTo("hello world");
        assertThat(FastNormalizer.normalizeTrim("hello")).isEqualTo("hello");
        assertThat(FastNormalizer.normalizeTrim("   ")).isEmpty();
        assertThat(FastNormalizer.normalizeTrim("")).isEmpty();
        assertThat(FastNormalizer.normalizeTrim(null)).isEmpty();
    }

    @Test
    void testNormalizeDigitsEdgeCases() {
        assertThat(FastNormalizer.normalizeDigits("123456")).isEqualTo("123456");
        assertThat(FastNormalizer.normalizeDigits("")).isEmpty();
    }

    @Test
    void testNormalizationEnumStrategies() {
        assertThat(Normalization.NONE.normalize(" Raw Input ")).isEqualTo(" Raw Input ");
        assertThat(Normalization.NONE.normalize(null)).isEmpty();

        assertThat(Normalization.TRIM.normalize("  spaced  ")).isEqualTo("spaced");
        assertThat(Normalization.TRIM_CASE_INSENSITIVE.normalize("  USER@DOMAIN.COM  ")).isEqualTo("user@domain.com");
        assertThat(Normalization.DIGITS_ONLY.normalize("+1-800-555-0199")).isEqualTo("18005550199");
        assertThat(Normalization.LAST4_DIGITS.normalize("9876543210")).isEqualTo("3210");
    }
}
