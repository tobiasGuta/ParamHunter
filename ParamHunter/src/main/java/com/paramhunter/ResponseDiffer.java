package com.paramhunter;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ResponseDiffer {

    // Margin added on top of the measured noise floor / length jitter
    private static final int TOKEN_MARGIN = 3;
    private static final int LENGTH_MARGIN = 5;

    public static class DiffResult {
        public boolean isDifferent;
        public List<String> evidenceList = new ArrayList<>();

        public String getEvidence() {
            return String.join("; ", evidenceList);
        }
    }

    /**
     * Primary diff entry point using a pre-built BaselineProfile.
     * The profile carries pre-normalized tokens and the calibrated noise floor,
     * so this method only normalizes the fuzz body once.
     */
    public DiffResult diff(BaselineProfile profile, int fuzzStatus, String fuzzBody,
                           String fuzzLocation, List<String> testedParams) {
        DiffResult result = new DiffResult();

        // 1. Status code change
        if (profile.statusCode != fuzzStatus) {
            result.isDifferent = true;
            result.evidenceList.add("Status changed: " + profile.statusCode + " → " + fuzzStatus);
        }

        // 2. Normalized word-level diff (replaces raw byte-length threshold)
        String fuzzNorm = BodyNormalizer.normalize(fuzzBody);
        String[] fuzzTokens = BodyNormalizer.tokenize(fuzzNorm);
        int tokenDiffs = BodyNormalizer.countTokenDiffs(profile.tokens, fuzzTokens);
        int tokenThreshold = profile.noiseFloor + TOKEN_MARGIN;
        if (tokenDiffs > tokenThreshold) {
            result.isDifferent = true;
            result.evidenceList.add("Structural diff: " + tokenDiffs + " token changes (noise floor "
                    + profile.noiseFloor + ", threshold " + tokenThreshold + ")");
        }

        // 3. Body length diff (still useful as a fast secondary signal)
        int baseLen = profile.rawBody != null ? profile.rawBody.length() : 0;
        int fuzzLen = fuzzBody != null ? fuzzBody.length() : 0;
        int lenDiff = Math.abs(fuzzLen - baseLen);
        int lenThreshold = profile.lengthJitter + LENGTH_MARGIN;
        if (lenDiff > lenThreshold) {
            result.isDifferent = true;
            result.evidenceList.add("Body length diff: " + lenDiff + " bytes (jitter "
                    + profile.lengthJitter + ", threshold " + lenThreshold + ")");
        }

        // 4. New JSON keys
        if (fuzzBody != null && profile.rawBody != null) {
            Set<String> newKeys = findNewJsonKeys(profile.rawBody, fuzzBody);
            if (!newKeys.isEmpty()) {
                result.isDifferent = true;
                result.evidenceList.add("New JSON keys: " + newKeys);
            }
        }

        // 5. Redirect location change
        if (profile.location != null && fuzzLocation != null
                && !profile.location.equals(fuzzLocation)) {
            result.isDifferent = true;
            result.evidenceList.add("Redirect changed: " + profile.location + " → " + fuzzLocation);
        } else if (profile.location == null && fuzzLocation != null) {
            result.isDifferent = true;
            result.evidenceList.add("New redirect: " + fuzzLocation);
        }

        // 6. Reflected parameter names in response body
        if (fuzzBody != null && testedParams != null) {
            for (String param : testedParams) {
                if (fuzzBody.contains(param) && (profile.rawBody == null || !profile.rawBody.contains(param))) {
                    result.isDifferent = true;
                    result.evidenceList.add("Reflected param: " + param);
                }
            }
        }

        return result;
    }

    /**
     * Deep-extract all keys from a JSON structure, returning keys present in
     * fuzzJson but not in baselineJson.
     */
    public Set<String> findNewJsonKeys(String baselineJson, String fuzzJson) {
        Set<String> baseKeys = new HashSet<>();
        Set<String> fuzzKeys = new HashSet<>();

        try {
            JsonElement baseEl = JsonParser.parseString(baselineJson);
            extractKeys(baseEl, "", baseKeys);
        } catch (JsonSyntaxException e) {
            return Set.of();
        }

        try {
            JsonElement fuzzEl = JsonParser.parseString(fuzzJson);
            extractKeys(fuzzEl, "", fuzzKeys);
        } catch (JsonSyntaxException e) {
            return Set.of();
        }

        fuzzKeys.removeAll(baseKeys);
        return fuzzKeys;
    }

    private void extractKeys(JsonElement element, String prefix, Set<String> keys) {
        if (element == null || element.isJsonNull()) {
            return;
        }
        if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                String fullKey = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
                keys.add(fullKey);
                extractKeys(entry.getValue(), fullKey, keys);
            }
        } else if (element.isJsonArray()) {
            for (int i = 0; i < element.getAsJsonArray().size(); i++) {
                extractKeys(element.getAsJsonArray().get(i), prefix + "[" + i + "]", keys);
            }
        }
    }
}
