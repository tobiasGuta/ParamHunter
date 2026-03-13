package com.paramhunter;

/**
 * Immutable calibration snapshot built from multiple baseline responses.
 * Stores pre-normalized, pre-tokenized data so the hot diff path does
 * zero redundant work.
 */
public final class BaselineProfile {

    public final int statusCode;
    public final String rawBody;
    public final String location;

    // Pre-computed for the hot path
    public final String normalizedBody;
    public final String[] tokens;
    public final int noiseFloor;     // token diffs between baseline samples
    public final int lengthJitter;   // max body-length variance across samples

    private BaselineProfile(int statusCode, String rawBody, String location,
                            String normalizedBody, String[] tokens,
                            int noiseFloor, int lengthJitter) {
        this.statusCode = statusCode;
        this.rawBody = rawBody;
        this.location = location;
        this.normalizedBody = normalizedBody;
        this.tokens = tokens;
        this.noiseFloor = noiseFloor;
        this.lengthJitter = lengthJitter;
    }

    /**
     * Build a profile from 3 baseline response bodies.
     * The third response is used as the canonical baseline; the first two
     * are compared against it to measure noise.
     */
    public static BaselineProfile build(int statusCode, String body1, String body2, String body3,
                                        String location) {
        String norm1 = BodyNormalizer.normalize(body1);
        String norm2 = BodyNormalizer.normalize(body2);
        String norm3 = BodyNormalizer.normalize(body3);

        String[] tok1 = BodyNormalizer.tokenize(norm1);
        String[] tok2 = BodyNormalizer.tokenize(norm2);
        String[] tok3 = BodyNormalizer.tokenize(norm3);

        int diff12 = BodyNormalizer.countTokenDiffs(tok1, tok2);
        int diff13 = BodyNormalizer.countTokenDiffs(tok1, tok3);
        int diff23 = BodyNormalizer.countTokenDiffs(tok2, tok3);
        int noiseFloor = Math.max(diff12, Math.max(diff13, diff23));

        int len1 = body1 != null ? body1.length() : 0;
        int len2 = body2 != null ? body2.length() : 0;
        int len3 = body3 != null ? body3.length() : 0;
        int lengthJitter = Math.max(Math.abs(len1 - len2),
                           Math.max(Math.abs(len1 - len3), Math.abs(len2 - len3)));

        return new BaselineProfile(statusCode, body3, location,
                norm3, tok3, noiseFloor, lengthJitter);
    }
}
