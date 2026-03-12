package com.paramhunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;

public class HttpTrafficHandler implements HttpHandler {

    private final MontoyaApi api;
    private final ParamHunterExtension extension;
    private final EndpointRegistry registry;
    private final FuzzingEngine fuzzingEngine;
    private volatile boolean onlyInScope = true;
    private volatile boolean skipFuzzed = true;

    public HttpTrafficHandler(MontoyaApi api, ParamHunterExtension extension,
                              EndpointRegistry registry, FuzzingEngine fuzzingEngine) {
        this.api = api;
        this.extension = extension;
        this.registry = registry;
        this.fuzzingEngine = fuzzingEngine;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Passive — never modify requests
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (!extension.isEnabled()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        try {
            // Skip traffic sent by this extension (calibration / fuzz requests)
            if (responseReceived.toolSource().isFromTool(ToolType.EXTENSIONS)) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            var request = responseReceived.initiatingRequest();

            // Skip if we only want in-scope and this isn't
            if (onlyInScope && !api.scope().isInScope(request.url())) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            String method = request.method();
            String host = request.httpService().host();
            String path = request.path();

            String signature = EndpointRegistry.makeSignature(method, host, path);

            if (skipFuzzed && registry.isFuzzed(signature)) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            // Queue for fuzzing (tryMarkPending ensures dedup)
            if (registry.tryMarkPending(signature)) {
                fuzzingEngine.queueFuzzing(request, responseReceived);
            }

        } catch (Exception e) {
            api.logging().logToError("ParamHunter traffic handler error: " + e.getMessage());
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    public void setOnlyInScope(boolean onlyInScope) {
        this.onlyInScope = onlyInScope;
    }

    public void setSkipFuzzed(boolean skipFuzzed) {
        this.skipFuzzed = skipFuzzed;
    }

    public boolean isOnlyInScope() {
        return onlyInScope;
    }

    public boolean isSkipFuzzed() {
        return skipFuzzed;
    }
}
