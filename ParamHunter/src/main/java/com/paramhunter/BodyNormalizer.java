package com.paramhunter;

import java.util.regex.Pattern;

/**
 * High-performance body normalizer that strips dynamic content (timestamps,
 * tokens, UUIDs, nonces) so that comparisons are not polluted by volatile
 * values that change on every request.
 *
 * All regex patterns are pre-compiled as static finals so they are created
 * once per class-load, never per call.  The public API is a single
 * static method with no allocation beyond the result string.
 */
public final class BodyNormalizer {

    private BodyNormalizer() {} // utility class

    // --- Pre-compiled patterns (class-load cost only) ---

    // ISO-8601 timestamps: 2025-03-11T14:22:01Z, 2025-03-11T14:22:01.123+00:00
    private static final Pattern ISO_TIMESTAMP = Pattern.compile(
            "\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+\\-]\\d{2}:?\\d{2})?");

    // RFC-2822 / HTTP date fragments: 11 Mar 2026 14:22:01
    private static final Pattern RFC_DATE = Pattern.compile(
            "\\d{1,2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \\d{4} \\d{2}:\\d{2}:\\d{2}",
            Pattern.CASE_INSENSITIVE);

    // Epoch millis (13 digits) and epoch seconds (10 digits) standing alone
    private static final Pattern EPOCH = Pattern.compile(
            "(?<=[\"':= ,\\[])\\d{10,13}(?=[\"', }\\])])");

    // UUID v4: 8-4-4-4-12 hex
    private static final Pattern UUID_V4 = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            Pattern.CASE_INSENSITIVE);

    // Hex tokens >= 32 chars (CSRF tokens, session IDs)
    private static final Pattern HEX_TOKEN = Pattern.compile(
            "(?<=[\"'= ])[0-9a-f]{32,}(?=[\"' ,;\\]}&])",
            Pattern.CASE_INSENSITIVE);

    // Base64 blobs >= 24 chars (tokens, JWTs fragments)
    private static final Pattern BASE64_BLOB = Pattern.compile(
            "(?<=[\"'= ])[A-Za-z0-9+/]{24,}={0,2}(?=[\"' ,;\\]}&])");

    // HTML nonce / csrf attributes: nonce="abc123" csrf_token="xyz"
    private static final Pattern NONCE_ATTR = Pattern.compile(
            "((?:nonce|csrf[_-]?token|_token|authenticity.token)\\s*[=:]\\s*[\"']?)[^\"'\\s>]+",
            Pattern.CASE_INSENSITIVE);

    // Simple clock patterns: HH:MM:SS or HH:MM
    private static final Pattern CLOCK = Pattern.compile(
            "\\b\\d{2}:\\d{2}(?::\\d{2})?\\b");

    // Placeholder strings — short, fixed-length so they don't shift byte-counts much
    private static final String PH = "~V~";

    /**
     * Replace all known volatile patterns with a fixed placeholder.
     * Designed to be called on every response body in the hot path.
     */
    public static String normalize(String body) {
        if (body == null || body.isEmpty()) return "";

        // Apply in order of specificity (most specific first to avoid partial matches)
        String s = ISO_TIMESTAMP.matcher(body).replaceAll(PH);
        s = RFC_DATE.matcher(s).replaceAll(PH);
        s = UUID_V4.matcher(s).replaceAll(PH);
        s = HEX_TOKEN.matcher(s).replaceAll(PH);
        s = BASE64_BLOB.matcher(s).replaceAll(PH);
        s = NONCE_ATTR.matcher(s).replaceAll("$1" + PH);
        s = EPOCH.matcher(s).replaceAll(PH);
        s = CLOCK.matcher(s).replaceAll(PH);
        return s;
    }

    /**
     * Tokenize a normalized body into words for diff counting.
     * Splits on whitespace and common delimiters.  Returns a compact
     * String[] — no intermediate List allocation.
     */
    private static final Pattern SPLIT = Pattern.compile("[\\s,;:={}<>\\[\\]\"'`/|&]+");

    public static String[] tokenize(String normalizedBody) {
        if (normalizedBody == null || normalizedBody.isEmpty()) return EMPTY;
        return SPLIT.split(normalizedBody);
    }

    private static final String[] EMPTY = new String[0];

    /**
     * Count the number of token-level differences between two normalized bodies.
     * Uses a simple LCS-free approach: count tokens in A not matched in B, and
     * vice-versa, using frequency maps.  O(n+m) time, O(n+m) space.
     */
    public static int countTokenDiffs(String[] tokensA, String[] tokensB) {
        if (tokensA.length == 0 && tokensB.length == 0) return 0;
        if (tokensA.length == 0) return tokensB.length;
        if (tokensB.length == 0) return tokensA.length;

        // Build frequency map for A
        java.util.HashMap<String, Integer> freqA = new java.util.HashMap<>(tokensA.length * 2);
        for (String t : tokensA) {
            freqA.merge(t, 1, Integer::sum);
        }

        // Subtract tokens found in B
        int matched = 0;
        for (String t : tokensB) {
            Integer count = freqA.get(t);
            if (count != null && count > 0) {
                freqA.put(t, count - 1);
                matched++;
            }
        }

        // Unmatched from A + unmatched from B
        int unmatchedA = tokensA.length - matched;
        int unmatchedB = tokensB.length - matched;
        return unmatchedA + unmatchedB;
    }
}
