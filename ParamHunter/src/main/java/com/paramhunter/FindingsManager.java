package com.paramhunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.sitemap.SiteMapFilter;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class FindingsManager {

    private static final DateTimeFormatter TIMESTAMP_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final MontoyaApi api;
    private final boolean isPro;
    private final List<Finding> findings = new CopyOnWriteArrayList<>();

    public FindingsManager(MontoyaApi api, boolean isPro) {
        this.api = api;
        this.isPro = isPro;
    }

    public static class Finding {
        public final String timestamp;
        public final String host;
        public final String endpoint;
        public final String method;
        public final String parameter;
        public final String evidence;
        public final HttpRequestResponse requestResponse;

        public Finding(String timestamp, String host, String endpoint, String method,
                       String parameter, String evidence, HttpRequestResponse requestResponse) {
            this.timestamp = timestamp;
            this.host = host;
            this.endpoint = endpoint;
            this.method = method;
            this.parameter = parameter;
            this.evidence = evidence;
            this.requestResponse = requestResponse;
        }
    }

    public void addFinding(String host, String endpoint, String method,
                           String parameter, String evidence,
                           HttpRequestResponse requestResponse) {
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FMT);

        Finding finding = new Finding(timestamp, host, endpoint, method,
                parameter, evidence, requestResponse);
        findings.add(finding);

        // Always log to extension output
        api.logging().logToOutput(String.format(
                "[%s] FOUND hidden param: %s on %s %s%s — Evidence: %s",
                timestamp, parameter, method, host, endpoint, evidence));

        // Attempt to create Burp Issue if Pro
        if (isPro) {
            createBurpIssue(host, endpoint, method, parameter, evidence, requestResponse);
        }
    }

    private void createBurpIssue(String host, String endpoint, String method,
                                 String parameter, String evidence,
                                 HttpRequestResponse requestResponse) {
        try {
            String detail = String.format(
                    "<p>ParamHunter discovered a hidden/undocumented parameter on this endpoint.</p>"
                    + "<p><b>Parameter:</b> %s</p>"
                    + "<p><b>Method:</b> %s</p>"
                    + "<p><b>Endpoint:</b> %s%s</p>"
                    + "<p><b>Evidence:</b> %s</p>",
                    escapeHtml(parameter), escapeHtml(method),
                    escapeHtml(host), escapeHtml(endpoint), escapeHtml(evidence));

            var auditIssue = burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue(
                    "Hidden Parameter Discovered",
                    detail,
                    null,
                    requestResponse.request().url(),
                    burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.INFORMATION,
                    burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.FIRM,
                    null,
                    null,
                    burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.INFORMATION,
                    requestResponse
            );
            api.siteMap().add(auditIssue);
        } catch (Exception e) {
            // Silently ignore — Community Edition or API change
            api.logging().logToOutput("Note: Could not create Burp Issue (expected on Community): " + e.getMessage());
        }
    }

    private static String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;");
    }

    public List<Finding> getFindings() {
        return new ArrayList<>(findings);
    }

    public int getFindingsCount() {
        return findings.size();
    }

    public void clearFindings() {
        findings.clear();
    }

    public boolean isPro() {
        return isPro;
    }
}
