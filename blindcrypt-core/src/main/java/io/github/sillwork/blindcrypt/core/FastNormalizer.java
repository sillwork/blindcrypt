package io.github.sillwork.blindcrypt.core;

import java.text.Normalizer;
import java.util.Locale;

/**
 * String normalization for blind index inputs with an ASCII fast path.
 * <p>
 * Identifiers such as emails, phone numbers and UUIDs are usually plain ASCII. For those inputs
 * {@link FastNormalizer} uses a single-pass scan and avoids {@link Normalizer#normalize(CharSequence, Normalizer.Form)};
 * when the input is already normalized it returns the original {@code String}. Inputs containing
 * non-ASCII characters fall back to {@link Normalizer}.
 */
public final class FastNormalizer {

    private FastNormalizer() { }

    /**
     * Normalizes an email or general alphanumeric string.
     * <p>
     * Trims leading/trailing ASCII whitespace and converts uppercase 'A'-'Z' to lowercase 'a'-'z'.
     * Bypasses heavy Unicode tables for pure ASCII inputs. Falls back to NFKC normalization
     * only when high-order non-ASCII characters (> 127) are encountered.
     *
     * @param input the raw input string
     * @return the normalized lowercase string, or an empty string if null or whitespace
     */
    public static String normalizeEmail(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }

        int length = input.length();
        int start = findTrimStart(input, length);
        int end = findTrimEnd(input, start, length);

        if (start >= end) {
            return "";
        }

        return processNormalizedRange(input, start, end, length);
    }

    private static int findTrimStart(String input, int length) {
        int index = 0;
        while (index < length && input.charAt(index) <= ' ') {
            index++;
        }
        return index;
    }

    private static int findTrimEnd(String input, int start, int length) {
        int index = length;
        while (index > start && input.charAt(index - 1) <= ' ') {
            index--;
        }
        return index;
    }

    private static String processNormalizedRange(String input, int start, int end, int totalLength) {
        boolean hasUppercase = false;
        boolean isPureAscii = true;

        for (int i = start; i < end; i++) {
            char character = input.charAt(i);
            if (character > 127) {
                isPureAscii = false;
                break;
            }
            if (character >= 'A' && character <= 'Z') {
                hasUppercase = true;
            }
        }

        if (isPureAscii) {
            return toAsciiLowercase(input, start, end, totalLength, hasUppercase);
        }

        // Unicode fallback
        String trimmed = input.substring(start, end);
        return Normalizer.normalize(trimmed, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
    }

    private static String toAsciiLowercase(String input, int start, int end, int totalLength, boolean hasUppercase) {
        // If already trimmed and lowercase, return original String reference
        if (!hasUppercase && start == 0 && end == totalLength) {
            return input;
        }

        char[] chars = new char[end - start];
        for (int i = start; i < end; i++) {
            char character = input.charAt(i);
            chars[i - start] = (character >= 'A' && character <= 'Z') ? (char) (character + 32) : character;
        }
        return new String(chars);
    }

    /**
     * Extracts only digits ('0' to '9') into a new string without regular expressions.
     *
     * @param input the raw string (e.g. phone number "+1 (555) 123-4567")
     * @return a clean string containing only numeric digits (e.g. "15551234567")
     */
    public static String normalizeDigits(String input) {
        if (input == null) return "";
        int len = input.length();
        int nonDigitCount = 0;
        for (int i = 0; i < len; i++) {
            char c = input.charAt(i);
            if (c < '0' || c > '9') {
                nonDigitCount++;
            }
        }
        if (nonDigitCount == 0) {
            return input; // Fast path for already normalized numeric inputs
        }
        if (nonDigitCount == len) {
            return "";
        }
        char[] digits = new char[len - nonDigitCount];
        int count = 0;
        for (int i = 0; i < len; i++) {
            char c = input.charAt(i);
            if (c >= '0' && c <= '9') {
                digits[count++] = c;
            }
        }
        return new String(digits);
    }

    /**
     * Extracts the last 4 digits for suffix blind indexing (e.g., last 4 of phone or SSN/Aadhaar).
     *
     * @param input the raw string
     * @return the last 4 digits, or an empty string if fewer than 4 digits are present
     */
    public static String normalizeLast4Digits(String input) {
        String digits = normalizeDigits(input);
        int len = digits.length();
        return len >= 4 ? digits.substring(len - 4) : "";
    }

    /**
     * Trims leading and trailing whitespace without case alteration.
     *
     * @param input the raw string
     * @return trimmed string, or empty string if input is null or whitespace
     */
    public static String normalizeTrim(String input) {
        if (input == null) return "";
        int len = input.length();
        int start = findTrimStart(input, len);
        int end = findTrimEnd(input, start, len);
        if (start >= end) return "";
        if (start == 0 && end == len) return input;
        return input.substring(start, end);
    }
}
