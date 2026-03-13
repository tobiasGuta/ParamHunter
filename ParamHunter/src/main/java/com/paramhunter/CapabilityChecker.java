package com.paramhunter;

import burp.api.montoya.MontoyaApi;

public final class CapabilityChecker {

    private CapabilityChecker() {
    }

    /**
     * Detects whether Burp Suite Professional is running by attempting
     * to access a Pro-only API. Returns true for Pro, false for Community.
     */
    public static boolean detectEdition(MontoyaApi api) {
        try {
            api.siteMap().issues();
            return true;
        } catch (UnsupportedOperationException e) {
            return false;
        } catch (Exception e) {
            api.logging().logToOutput("Edition detection encountered an unexpected error: " + e.getMessage());
            return false;
        }
    }
}
