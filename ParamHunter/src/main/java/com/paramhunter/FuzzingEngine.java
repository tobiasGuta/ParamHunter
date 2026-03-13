package com.paramhunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.paramhunter.ui.ParamHunterTab;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.time.format.DateTimeFormatter;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;

public class FuzzingEngine {
    private volatile boolean paused = false;
    private volatile boolean cancelled = false;

    public void pauseFuzzing() {
        paused = true;
        if (tab != null) tab.addNotification("Fuzzing paused.");
    }

    public void resumeFuzzing() {
        paused = false;
        if (tab != null) tab.addNotification("Fuzzing resumed.");
    }

    public void cancelFuzzing() {
        cancelled = true;
        if (tab != null) tab.addNotification("Fuzzing cancelled.");
    }

    private void checkPauseCancel() {
        while (paused && !cancelled && !Thread.currentThread().isInterrupted()) {
            sleep(500);
        }
        if (cancelled || Thread.currentThread().isInterrupted()) {
            throw new RuntimeException("Fuzzing cancelled");
        }
    }

    private static final int BATCH_SIZE = 15;
    private static final String FUZZ_VALUE = "paramhunter1337";

    private final MontoyaApi api;
    private final WordlistManager wordlistManager;
    private final EndpointRegistry endpointRegistry;
    private final FindingsManager findingsManager;
    private final ResponseDiffer responseDiffer;
    private volatile ExecutorService threadPool;
    private volatile int requestDelayMs = 200;
    private volatile ParamHunterTab tab;

    private enum ContentType {
        GET_QUERY,
        FORM_URLENCODED,
        JSON,
        XML,
        OTHER
    }

    public FuzzingEngine(MontoyaApi api, WordlistManager wordlistManager,
                         EndpointRegistry endpointRegistry, FindingsManager findingsManager,
                         ResponseDiffer responseDiffer, ExecutorService threadPool) {
        this.api = api;
        this.wordlistManager = wordlistManager;
        this.endpointRegistry = endpointRegistry;
        this.findingsManager = findingsManager;
        this.responseDiffer = responseDiffer;
        this.threadPool = threadPool;
    }

    public void setTab(ParamHunterTab tab) {
        this.tab = tab;
    }

    public void setThreadPool(ExecutorService threadPool) {
        this.threadPool = threadPool;
    }

    public void setRequestDelayMs(int delayMs) {
        this.requestDelayMs = delayMs;
    }

    public int getRequestDelayMs() {
        return requestDelayMs;
    }

    /**
     * Queue a request for background fuzzing.
     */
    public void queueFuzzing(burp.api.montoya.http.message.requests.HttpRequest originalRequest,
                             HttpResponse originalResponse) {
        ExecutorService pool = this.threadPool;
        if (pool == null || pool.isShutdown()) {
            api.logging().logToOutput("[ParamHunter] Thread pool unavailable, cannot fuzz.");
            return;
        }

        // Mark as pending to prevent the HTTP handler from re-queuing
        // during calibration (our sendWithRetry calls flow through Burp's
        // HTTP client and are visible to the handler).
        String sig = EndpointRegistry.makeSignature(
                originalRequest.method(),
                originalRequest.httpService().host(),
                originalRequest.path());
        endpointRegistry.tryMarkPending(sig);

        pool.submit(() -> {
            try {
                fuzzEndpoint(originalRequest, originalResponse);
            } catch (Throwable e) {
                api.logging().logToOutput("[ParamHunter] Fuzzing task failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                api.logging().logToError("Fuzzing error: " + e.getMessage());
                endpointRegistry.removePending(sig);
            }
        });
    }

    private void fuzzEndpoint(HttpRequest originalRequest, HttpResponse originalResponse) {
        String method = originalRequest.method();
        String host = originalRequest.httpService().host();
        String path = originalRequest.path();
        String signature = EndpointRegistry.makeSignature(method, host, path);

        api.logging().logToOutput("[ParamHunter] Starting fuzz: " + method + " " + host + path);

        try {
            paused = false;
            cancelled = false;
            // Extract known parameters to exclude them
            Set<String> knownParams = extractKnownParams(originalRequest);

            // Get filtered wordlist
            List<String> wordlist = wordlistManager.getFilteredWordlist(knownParams);
            if (wordlist.isEmpty()) {
                api.logging().logToOutput("[ParamHunter] Wordlist empty after filtering, skipping: " + signature);
                endpointRegistry.markFuzzed(signature);
                return;
            }

            ContentType contentType = detectContentType(originalRequest);
            api.logging().logToOutput("[ParamHunter] Content type: " + contentType
                    + ", wordlist size: " + wordlist.size()
                    + ", known params excluded: " + knownParams.size());

            // === Calibration: send original request 3 times to build a BaselineProfile ===
            api.logging().logToOutput("[ParamHunter] Sending 3 calibration requests...");
            checkPauseCancel();
            HttpRequestResponse baselineRR1 = sendWithRetry(originalRequest);
            if (baselineRR1 == null || baselineRR1.response() == null) {
                api.logging().logToOutput("[ParamHunter] Baseline #1 failed (null response), aborting: " + signature);
                endpointRegistry.removePending(signature);
                return;
            }
            checkPauseCancel();
            sleep(requestDelayMs);
            HttpRequestResponse baselineRR2 = sendWithRetry(originalRequest);
            if (baselineRR2 == null || baselineRR2.response() == null) {
                api.logging().logToOutput("[ParamHunter] Baseline #2 failed (null response), aborting: " + signature);
                endpointRegistry.removePending(signature);
                return;
            }
            checkPauseCancel();
            sleep(requestDelayMs);
            HttpRequestResponse baselineRR3 = sendWithRetry(originalRequest);
            if (baselineRR3 == null || baselineRR3.response() == null) {
                api.logging().logToOutput("[ParamHunter] Baseline #3 failed (null response), aborting: " + signature);
                endpointRegistry.removePending(signature);
                return;
            }
            checkPauseCancel();

            BaselineProfile profile = BaselineProfile.build(
                    baselineRR3.response().statusCode(),
                    baselineRR1.response().bodyToString(),
                    baselineRR2.response().bodyToString(),
                    baselineRR3.response().bodyToString(),
                    getLocationHeader(baselineRR3.response()));

            api.logging().logToOutput("[ParamHunter] Calibration complete — status: " + profile.statusCode
                    + ", noise floor: " + profile.noiseFloor + " tokens"
                    + ", length jitter: " + profile.lengthJitter + " bytes");

            String cleanPath = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;

            // Split wordlist into batches
            List<List<String>> batches = partition(wordlist, BATCH_SIZE);
            int totalBatches = batches.size();

            // === Phase 1: key=value fuzzing ===
            api.logging().logToOutput("[ParamHunter] Phase 1: key=value fuzzing (" + totalBatches + " batches)");
            int batchNum = 0;
            for (List<String> batch : batches) {
                batchNum++;
                checkPauseCancel();
                if (Thread.currentThread().isInterrupted()) {
                    api.logging().logToOutput("[ParamHunter] Interrupted, stopping: " + signature);
                    return;
                }

                HttpRequest fuzzedRequest = buildFuzzedRequest(originalRequest, batch, contentType);
                if (fuzzedRequest == null) continue;

                endpointRegistry.addParametersTested(batch.size());

                HttpRequestResponse fuzzRR = sendWithRetry(fuzzedRequest);
                if (fuzzRR == null || fuzzRR.response() == null) continue;

                ResponseDiffer.DiffResult diff = responseDiffer.diff(
                        profile, fuzzRR.response().statusCode(),
                        fuzzRR.response().bodyToString(),
                        getLocationHeader(fuzzRR.response()), batch);

                if (diff.isDifferent) {
                    api.logging().logToOutput("[ParamHunter] Batch " + batchNum + "/" + totalBatches
                            + " triggered diff, isolating...");
                    List<String> culprits = binarySearchParams(originalRequest, batch,
                            contentType, profile);

                    confirmAndReport(culprits, originalRequest, contentType,
                            host, cleanPath, method, profile);
                }

                if (tab != null) {
                    tab.refreshStats();
                }
                sleep(requestDelayMs);
            }

            // === Phase 2: value-less flag fuzzing (GET and form only) ===
            if (contentType == ContentType.GET_QUERY || contentType == ContentType.FORM_URLENCODED) {
                api.logging().logToOutput("[ParamHunter] Phase 2: flag fuzzing (" + totalBatches + " batches)");
                batchNum = 0;
                for (List<String> batch : batches) {
                    batchNum++;
                    checkPauseCancel();
                    if (Thread.currentThread().isInterrupted()) {
                        api.logging().logToOutput("[ParamHunter] Interrupted, stopping: " + signature);
                        return;
                    }

                    HttpRequest flagRequest = buildFlagRequest(originalRequest, batch, contentType);
                    if (flagRequest == null) continue;

                    endpointRegistry.addParametersTested(batch.size());

                    HttpRequestResponse flagRR = sendWithRetry(flagRequest);
                    if (flagRR == null || flagRR.response() == null) continue;

                    ResponseDiffer.DiffResult flagDiff = responseDiffer.diff(
                            profile, flagRR.response().statusCode(),
                            flagRR.response().bodyToString(),
                            getLocationHeader(flagRR.response()), batch);

                    if (flagDiff.isDifferent) {
                        api.logging().logToOutput("[ParamHunter] Flag batch " + batchNum + "/" + totalBatches
                                + " triggered diff, isolating...");
                        List<String> flagCulprits = binarySearchFlagParams(originalRequest, batch,
                                contentType, profile);

                        confirmAndReportFlags(flagCulprits, originalRequest, contentType,
                                host, cleanPath, method, profile);
                    }

                    if (tab != null) {
                        tab.refreshStats();
                    }
                    sleep(requestDelayMs);
                }
            }

            endpointRegistry.markFuzzed(signature);
            api.logging().logToOutput("[ParamHunter] Fuzzing complete: " + signature);

        } catch (Throwable e) {
            api.logging().logToOutput("[ParamHunter] Error fuzzing " + signature + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
            api.logging().logToError("Error fuzzing " + signature + ": " + e.getMessage());
            endpointRegistry.removePending(signature);
        }

        if (tab != null) {
            tab.refreshStats();
        }
    }

    /**
     * Confirm individual parameters from the culprits list and report findings.
     */
    private void confirmAndReport(List<String> culprits, HttpRequest originalRequest,
                                  ContentType contentType, String host, String cleanPath,
                                  String method, BaselineProfile profile) {
        for (String param : culprits) {
            HttpRequest confirmReq = buildFuzzedRequest(originalRequest,
                    Collections.singletonList(param), contentType);
            if (confirmReq == null) continue;

            HttpRequestResponse confirmRR = sendWithRetry(confirmReq);
            if (confirmRR == null || confirmRR.response() == null) continue;

            ResponseDiffer.DiffResult confirmDiff = responseDiffer.diff(
                    profile, confirmRR.response().statusCode(),
                    confirmRR.response().bodyToString(),
                    getLocationHeader(confirmRR.response()),
                    Collections.singletonList(param));

            if (confirmDiff.isDifferent) {
                findingsManager.addFinding(host, cleanPath, method,
                        param, confirmDiff.getEvidence(), confirmRR);
                if (tab != null) {
                    tab.refreshFindings();
                    tab.refreshStats();
                }
            }
        }
    }

    /**
     * Confirm individual flag parameters and report findings.
     */
    private void confirmAndReportFlags(List<String> culprits, HttpRequest originalRequest,
                                       ContentType contentType, String host, String cleanPath,
                                       String method, BaselineProfile profile) {
        for (String param : culprits) {
            HttpRequest confirmReq = buildFlagRequest(originalRequest,
                    Collections.singletonList(param), contentType);
            if (confirmReq == null) continue;

            HttpRequestResponse confirmRR = sendWithRetry(confirmReq);
            if (confirmRR == null || confirmRR.response() == null) continue;

            ResponseDiffer.DiffResult confirmDiff = responseDiffer.diff(
                    profile, confirmRR.response().statusCode(),
                    confirmRR.response().bodyToString(),
                    getLocationHeader(confirmRR.response()),
                    Collections.singletonList(param));

            if (confirmDiff.isDifferent) {
                findingsManager.addFinding(host, cleanPath, method,
                        param + " (flag)", confirmDiff.getEvidence(), confirmRR);
                if (tab != null) {
                    tab.refreshFindings();
                    tab.refreshStats();
                }
            }
        }
    }

    /**
     * Binary search within a batch to exhaustively isolate ALL parameters that cause a diff.
     * Both halves are always tested so multiple hits in one batch are all found.
     */
    private List<String> binarySearchParams(HttpRequest originalRequest, List<String> params,
                                            ContentType contentType,
                                            BaselineProfile profile) {
        if (params.size() <= 1) {
            return new ArrayList<>(params);
        }

        int mid = params.size() / 2;
        List<String> left = params.subList(0, mid);
        List<String> right = params.subList(mid, params.size());

        List<String> results = new ArrayList<>();

        // Always test BOTH halves to find all culprits (exhaustive search)
        results.addAll(testSubBatch(originalRequest, left, contentType, profile));
        results.addAll(testSubBatch(originalRequest, right, contentType, profile));

        return results;
    }

    private List<String> testSubBatch(HttpRequest originalRequest, List<String> params,
                                      ContentType contentType, BaselineProfile profile) {
        if (params.isEmpty()) return Collections.emptyList();
        if (params.size() == 1) return new ArrayList<>(params); // Will be confirmed individually

        HttpRequest req = buildFuzzedRequest(originalRequest, params, contentType);
        if (req == null) return Collections.emptyList();

        HttpRequestResponse rr = sendWithRetry(req);
        if (rr == null || rr.response() == null) return Collections.emptyList();

        ResponseDiffer.DiffResult diff = responseDiffer.diff(
                profile, rr.response().statusCode(),
                rr.response().bodyToString(),
                getLocationHeader(rr.response()), params);

        if (diff.isDifferent) {
            return binarySearchParams(originalRequest, params, contentType, profile);
        }

        return Collections.emptyList();
    }

    /**
     * Binary search for flag (value-less) params.
     */
    private List<String> binarySearchFlagParams(HttpRequest originalRequest, List<String> params,
                                                ContentType contentType,
                                                BaselineProfile profile) {
        if (params.size() <= 1) {
            return new ArrayList<>(params);
        }

        int mid = params.size() / 2;
        List<String> left = params.subList(0, mid);
        List<String> right = params.subList(mid, params.size());

        List<String> results = new ArrayList<>();

        results.addAll(testFlagSubBatch(originalRequest, left, contentType, profile));
        results.addAll(testFlagSubBatch(originalRequest, right, contentType, profile));

        return results;
    }

    private List<String> testFlagSubBatch(HttpRequest originalRequest, List<String> params,
                                          ContentType contentType, BaselineProfile profile) {
        if (params.isEmpty()) return Collections.emptyList();
        if (params.size() == 1) return new ArrayList<>(params);

        HttpRequest req = buildFlagRequest(originalRequest, params, contentType);
        if (req == null) return Collections.emptyList();

        HttpRequestResponse rr = sendWithRetry(req);
        if (rr == null || rr.response() == null) return Collections.emptyList();

        ResponseDiffer.DiffResult diff = responseDiffer.diff(
                profile, rr.response().statusCode(),
                rr.response().bodyToString(),
                getLocationHeader(rr.response()), params);

        if (diff.isDifferent) {
            return binarySearchFlagParams(originalRequest, params, contentType, profile);
        }

        return Collections.emptyList();
    }

    /**
     * Build a request with the fuzz parameters injected according to content type.
     */
    private HttpRequest buildFuzzedRequest(HttpRequest original, List<String> params, ContentType contentType) {
        try {
            switch (contentType) {
                case GET_QUERY:
                    return buildGetFuzzRequest(original, params);
                case FORM_URLENCODED:
                    return buildFormFuzzRequest(original, params);
                case JSON:
                    return buildJsonFuzzRequest(original, params);
                case XML:
                    return buildXmlFuzzRequest(original, params);
                default:
                    // Default to GET query style
                    return buildGetFuzzRequest(original, params);
            }
        } catch (Exception e) {
            api.logging().logToError("Error building fuzzed request: " + e.getMessage());
            return null;
        }
    }

    private HttpRequest buildGetFuzzRequest(HttpRequest original, List<String> params) {
        String currentPath = original.path();
        StringBuilder extra = new StringBuilder();
        for (String param : params) {
            String encoded = URLEncoder.encode(param, StandardCharsets.UTF_8);
            extra.append(encoded).append("=").append(FUZZ_VALUE).append("&");
        }
        if (extra.length() > 0) {
            extra.setLength(extra.length() - 1); // Remove trailing &
        }

        String newPath;
        if (currentPath.contains("?")) {
            newPath = currentPath + "&" + extra;
        } else {
            newPath = currentPath + "?" + extra;
        }

        return HttpRequest.httpRequest(original.httpService(),
                rebuildRequestLine(original, newPath));
    }

    private HttpRequest buildFormFuzzRequest(HttpRequest original, List<String> params) {
        String body = original.bodyToString();
        StringBuilder extra = new StringBuilder();
        for (String param : params) {
            String encoded = URLEncoder.encode(param, StandardCharsets.UTF_8);
            extra.append(encoded).append("=").append(FUZZ_VALUE).append("&");
        }
        if (extra.length() > 0) {
            extra.setLength(extra.length() - 1);
        }

        String newBody;
        if (body != null && !body.isEmpty()) {
            newBody = body + "&" + extra;
        } else {
            newBody = extra.toString();
        }

        return original.withBody(newBody);
    }

    private HttpRequest buildJsonFuzzRequest(HttpRequest original, List<String> params) {
        String body = original.bodyToString();
        JsonObject jsonObj;
        try {
            JsonElement el = JsonParser.parseString(body);
            if (el.isJsonObject()) {
                jsonObj = el.getAsJsonObject().deepCopy();
            } else {
                jsonObj = new JsonObject();
            }
        } catch (JsonSyntaxException e) {
            jsonObj = new JsonObject();
        }

        // Inject at root level
        for (String param : params) {
            jsonObj.addProperty(param, FUZZ_VALUE);
        }

        // Recursively inject into all nested objects
        injectIntoNestedObjects(jsonObj, params);

        HttpRequest updated = original.withBody(jsonObj.toString());
        if (!hasHeader(updated, "Content-Type")) {
            updated = updated.withAddedHeader("Content-Type", "application/json");
        }
        return updated;
    }

    /**
     * Recursively walk a JsonObject and inject fuzz params into every nested object.
     * Skips the root (caller handles root injection) by only processing children.
     */
    private void injectIntoNestedObjects(JsonObject obj, List<String> params) {
        for (String key : new ArrayList<>(obj.keySet())) {
            JsonElement child = obj.get(key);
            if (child != null && child.isJsonObject()) {
                JsonObject nested = child.getAsJsonObject();
                for (String param : params) {
                    if (!nested.has(param)) {
                        nested.addProperty(param, FUZZ_VALUE);
                    }
                }
                // Continue recursing into deeper levels
                injectIntoNestedObjects(nested, params);
            } else if (child != null && child.isJsonArray()) {
                for (int i = 0; i < child.getAsJsonArray().size(); i++) {
                    JsonElement arrEl = child.getAsJsonArray().get(i);
                    if (arrEl != null && arrEl.isJsonObject()) {
                        JsonObject nested = arrEl.getAsJsonObject();
                        for (String param : params) {
                            if (!nested.has(param)) {
                                nested.addProperty(param, FUZZ_VALUE);
                            }
                        }
                        injectIntoNestedObjects(nested, params);
                    }
                }
            }
        }
    }

    private HttpRequest buildXmlFuzzRequest(HttpRequest original, List<String> params) {
        String body = original.bodyToString();
        if (body == null) body = "";

        // Find the last closing tag and insert new nodes before it
        StringBuilder nodes = new StringBuilder();
        for (String param : params) {
            // Sanitize param name for XML tag validity
            String safeName = param.replaceAll("[^a-zA-Z0-9_\\-]", "_");
            if (safeName.isEmpty() || !Character.isLetter(safeName.charAt(0))) {
                safeName = "p_" + safeName;
            }
            nodes.append("<").append(safeName).append(">")
                 .append(FUZZ_VALUE)
                 .append("</").append(safeName).append(">");
        }

        // Try to insert before the last closing root tag
        int lastClose = body.lastIndexOf("</");
        String newBody;
        if (lastClose >= 0) {
            newBody = body.substring(0, lastClose) + nodes + body.substring(lastClose);
        } else {
            // If no closing tag, just append
            newBody = body + nodes;
        }

        return original.withBody(newBody);
    }

    private String rebuildRequestLine(HttpRequest original, String newPath) {
        // Build the full raw request with the new path
        StringBuilder sb = new StringBuilder();
        sb.append(original.method()).append(" ").append(newPath).append(" ")
          .append(original.httpVersion()).append("\r\n");

        for (HttpHeader header : original.headers()) {
            sb.append(header.name()).append(": ").append(header.value()).append("\r\n");
        }
        sb.append("\r\n");

        String body = original.bodyToString();
        if (body != null && !body.isEmpty()) {
            sb.append(body);
        }

        return sb.toString();
    }

    private ContentType detectContentType(HttpRequest request) {
        String method = request.method().toUpperCase();

        if ("GET".equals(method) || "HEAD".equals(method) || "OPTIONS".equals(method)) {
            return ContentType.GET_QUERY;
        }

        String ct = getHeaderValue(request, "Content-Type");
        if (ct == null) {
            return ContentType.GET_QUERY;
        }

        ct = ct.toLowerCase();
        if (ct.contains("application/x-www-form-urlencoded")) {
            return ContentType.FORM_URLENCODED;
        } else if (ct.contains("application/json") || ct.contains("text/json")) {
            return ContentType.JSON;
        } else if (ct.contains("application/xml") || ct.contains("text/xml")) {
            return ContentType.XML;
        }

        return ContentType.FORM_URLENCODED; // default for POST
    }

    /**
     * Extract parameters already present in the request.
     */
    private Set<String> extractKnownParams(HttpRequest request) {
        Set<String> known = new HashSet<>();

        // From query string
        String path = request.path();
        int qIdx = path.indexOf('?');
        if (qIdx >= 0) {
            String queryString = path.substring(qIdx + 1);
            extractParamNames(queryString, known);
        }

        // From body
        ContentType ct = detectContentType(request);
        String body = request.bodyToString();
        if (body != null && !body.isEmpty()) {
            switch (ct) {
                case FORM_URLENCODED:
                    extractParamNames(body, known);
                    break;
                case JSON:
                    extractJsonKeys(body, known);
                    break;
                case XML:
                    extractXmlTags(body, known);
                    break;
                default:
                    break;
            }
        }

        return known;
    }

    private void extractParamNames(String queryOrBody, Set<String> dest) {
        String[] pairs = queryOrBody.split("&");
        for (String pair : pairs) {
            int eqIdx = pair.indexOf('=');
            String name = eqIdx >= 0 ? pair.substring(0, eqIdx) : pair;
            name = name.trim().toLowerCase();
            if (!name.isEmpty()) {
                dest.add(name);
            }
        }
    }

    private void extractJsonKeys(String json, Set<String> dest) {
        try {
            JsonElement el = JsonParser.parseString(json);
            if (el.isJsonObject()) {
                for (String key : el.getAsJsonObject().keySet()) {
                    dest.add(key.toLowerCase());
                }
            }
        } catch (JsonSyntaxException e) {
            // ignore
        }
    }

    private void extractXmlTags(String xml, Set<String> dest) {
        Pattern tagPattern = Pattern.compile("<([a-zA-Z][a-zA-Z0-9_\\-]*)(?:\\s|>|/)");
        Matcher m = tagPattern.matcher(xml);
        while (m.find()) {
            dest.add(m.group(1).toLowerCase());
        }
    }

    /**
     * Send a request with intelligent backoff on 429 responses.
     * Respects Retry-After header if present, and waits indefinitely until success
     * or manual stop, as per user requirement.
     */
    private HttpRequestResponse sendWithRetry(HttpRequest request) {
        long backoff = 1000;
        String target = request.httpService().host() + ":" + request.httpService().port() + request.path();

        // While loop to retry indefinitely on 429
        int errorRetries = 0;
        int maxErrorRetries = 3;

        while (!Thread.currentThread().isInterrupted()) {
            try {
                HttpRequestResponse rr = api.http().sendRequest(request);
                if (rr == null) {
                    api.logging().logToOutput("[ParamHunter]   sendRequest returned null object");
                    return null;
                }
                if (rr.response() == null) {
                    api.logging().logToOutput("[ParamHunter]   got response object but response() is null (connection failed?)");
                    if (errorRetries < maxErrorRetries) {
                        errorRetries++;
                        sleep(backoff);
                        backoff *= 2;
                        continue;
                    }
                    return rr;
                }

                int statusCode = rr.response().statusCode();
                // If 429, wait and retry
                if (statusCode == 429) {
                    long waitMs = getRetryAfterWaitMs(rr.response());
                    if (waitMs <= 0) {
                        waitMs = backoff;
                        // Cap exponential backoff at 60s
                        backoff = Math.min(backoff * 2, 60000);
                    } else {
                        // Reset backoff if we have explicit instruction
                        backoff = 1000;
                    }

                    String msg = "Rate limited (429) on " + target + ", waiting " + (waitMs / 1000) + "s before retry.";
                    api.logging().logToOutput("[ParamHunter] " + msg);
                    if (tab != null) {
                        tab.addNotification(msg);
                    }

                    sleep(waitMs);
                    // Reset error retries on valid 429 response
                    errorRetries = 0;
                    continue;
                }

                return rr;

            } catch (Exception e) {
                api.logging().logToOutput("[ParamHunter]   sendRequest error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                if (errorRetries < maxErrorRetries) {
                    errorRetries++;
                    sleep(backoff);
                    backoff *= 2;
                } else {
                    api.logging().logToError("Failed to send request after retries: " + e.getMessage());
                    return null;
                }
            }
        }
        return null;
    }

    private long getRetryAfterWaitMs(HttpResponse response) {
        String val = getHeaderValue(response, "Retry-After");
        if (val == null) return 0;
        val = val.trim();

        // 1. Try seconds
        try {
            long seconds = Long.parseLong(val);
            if (seconds < 0) return 0;
            return seconds * 1000L;
        } catch (NumberFormatException e) {
            // Not an integer, try date
        }

        // 2. Try HTTP Date
        try {
            ZonedDateTime retryDate = ZonedDateTime.parse(val, DateTimeFormatter.RFC_1123_DATE_TIME);
            long diff = ChronoUnit.MILLIS.between(ZonedDateTime.now(), retryDate);
            return diff > 0 ? diff : 0;
        } catch (Exception e) {
            // Invalid date format
        }
        return 0;
    }

    private String getHeaderValue(HttpResponse response, String name) {
        if (response == null) return null;
        for (HttpHeader h : response.headers()) {
            if (name.equalsIgnoreCase(h.name())) {
                return h.value();
            }
        }
        return null;
    }

    private String getLocationHeader(HttpResponse response) {
        if (response == null) return null;
        for (HttpHeader h : response.headers()) {
            if ("Location".equalsIgnoreCase(h.name())) {
                return h.value();
            }
        }
        return null;
    }

    private String getHeaderValue(HttpRequest request, String name) {
        for (HttpHeader h : request.headers()) {
            if (name.equalsIgnoreCase(h.name())) {
                return h.value();
            }
        }
        return null;
    }

    private boolean hasHeader(HttpRequest request, String name) {
        return getHeaderValue(request, name) != null;
    }

    // ================================================================
    // Value-less flag request builders
    // ================================================================

    /**
     * Build a request with parameters as value-less flags (no =value).
     * Only applicable to GET query and form-urlencoded content types.
     */
    private HttpRequest buildFlagRequest(HttpRequest original, List<String> params, ContentType contentType) {
        try {
            switch (contentType) {
                case GET_QUERY:
                    return buildGetFlagRequest(original, params);
                case FORM_URLENCODED:
                    return buildFormFlagRequest(original, params);
                default:
                    return null;
            }
        } catch (Exception e) {
            api.logging().logToError("Error building flag request: " + e.getMessage());
            return null;
        }
    }

    private HttpRequest buildGetFlagRequest(HttpRequest original, List<String> params) {
        String currentPath = original.path();
        StringBuilder extra = new StringBuilder();
        for (String param : params) {
            String encoded = URLEncoder.encode(param, StandardCharsets.UTF_8);
            extra.append(encoded).append("&");
        }
        if (extra.length() > 0) {
            extra.setLength(extra.length() - 1);
        }

        String newPath;
        if (currentPath.contains("?")) {
            newPath = currentPath + "&" + extra;
        } else {
            newPath = currentPath + "?" + extra;
        }

        return HttpRequest.httpRequest(original.httpService(),
                rebuildRequestLine(original, newPath));
    }

    private HttpRequest buildFormFlagRequest(HttpRequest original, List<String> params) {
        String body = original.bodyToString();
        StringBuilder extra = new StringBuilder();
        for (String param : params) {
            String encoded = URLEncoder.encode(param, StandardCharsets.UTF_8);
            extra.append(encoded).append("&");
        }
        if (extra.length() > 0) {
            extra.setLength(extra.length() - 1);
        }

        String newBody;
        if (body != null && !body.isEmpty()) {
            newBody = body + "&" + extra;
        } else {
            newBody = extra.toString();
        }

        return original.withBody(newBody);
    }

    private void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private <T> List<List<T>> partition(List<T> list, int size) {
        List<List<T>> partitions = new ArrayList<>();
        for (int i = 0; i < list.size(); i += size) {
            partitions.add(list.subList(i, Math.min(i + size, list.size())));
        }
        return partitions;
    }
}
