package com.paramhunter;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class EndpointRegistry {

    private final Set<String> fuzzedEndpoints = ConcurrentHashMap.newKeySet();
    private final Set<String> pendingEndpoints = ConcurrentHashMap.newKeySet();
    private final AtomicInteger parametersTested = new AtomicInteger(0);

    /**
     * Creates a unique signature for an endpoint: METHOD|host|path
     */
    public static String makeSignature(String method, String host, String path) {
        // Normalize: strip query string from path if present
        int qIdx = path.indexOf('?');
        if (qIdx >= 0) {
            path = path.substring(0, qIdx);
        }
        // Strip trailing slash for consistency
        if (path.length() > 1 && path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return method.toUpperCase() + "|" + host.toLowerCase() + "|" + path;
    }

    /**
     * Returns true if this endpoint has not been fuzzed and is not currently pending.
     * Marks it as pending atomically.
     */
    public boolean tryMarkPending(String signature) {
        if (fuzzedEndpoints.contains(signature)) {
            return false;
        }
        return pendingEndpoints.add(signature);
    }

    /**
     * Marks an endpoint as fully fuzzed.
     */
    public void markFuzzed(String signature) {
        fuzzedEndpoints.add(signature);
        pendingEndpoints.remove(signature);
    }

    /**
     * Remove from pending without marking fuzzed (e.g., on error).
     */
    public void removePending(String signature) {
        pendingEndpoints.remove(signature);
    }

    public boolean isFuzzed(String signature) {
        return fuzzedEndpoints.contains(signature);
    }

    public int getFuzzedCount() {
        return fuzzedEndpoints.size();
    }

    public void addParametersTested(int count) {
        parametersTested.addAndGet(count);
    }

    public int getParametersTested() {
        return parametersTested.get();
    }

    public void reset() {
        fuzzedEndpoints.clear();
        pendingEndpoints.clear();
        parametersTested.set(0);
    }
}
