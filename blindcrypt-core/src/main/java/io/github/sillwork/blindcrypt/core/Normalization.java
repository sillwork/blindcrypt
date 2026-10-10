package io.github.sillwork.blindcrypt.core;

/**
 * Standard normalization strategies for blind indexing.
 * Ensures consistent canonicalization before one-way hashing so that equivalent inputs
 * (e.g., casing differences, punctuation, whitespace) match reliably in B-Tree index lookups.
 */
public enum Normalization {

    /**
     * No transformation applied. Hash is computed directly on raw input bytes.
     */
    NONE {
        @Override
        public String normalize(String input) {
            return input == null ? "" : input;
        }
    },

    /**
     * Leading/trailing whitespace trimmed, but casing preserved.
     */
    TRIM {
        @Override
        public String normalize(String input) {
            return FastNormalizer.normalizeTrim(input);
        }
    },

    /**
     * Leading/trailing whitespace trimmed, converted to lowercase.
     * Ideal for email addresses, usernames, and domain names.
     */
    TRIM_CASE_INSENSITIVE {
        @Override
        public String normalize(String input) {
            return FastNormalizer.normalizeEmail(input);
        }
    },

    /**
     * Strips all non-digit characters.
     * Ideal for phone numbers, national IDs, and credit card numbers.
     */
    DIGITS_ONLY {
        @Override
        public String normalize(String input) {
            return FastNormalizer.normalizeDigits(input);
        }
    },

    /**
     * Strips non-digits and takes the final 4 digits.
     * Used for customer support lookups (e.g., searching by last 4 digits of phone or SSN).
     */
    LAST4_DIGITS {
        @Override
        public String normalize(String input) {
            return FastNormalizer.normalizeLast4Digits(input);
        }
    };

    /**
     * Normalizes the specified input string according to this strategy.
     *
     * @param input the raw input string
     * @return the normalized canonical string (never null)
     */
    public abstract String normalize(String input);
}
