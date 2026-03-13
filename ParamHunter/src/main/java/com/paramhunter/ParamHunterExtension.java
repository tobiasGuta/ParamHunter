package com.paramhunter;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.paramhunter.ui.ParamHunterTab;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class ParamHunterExtension implements BurpExtension {

    private MontoyaApi api;
    private ExecutorService threadPool;
    private FuzzingEngine fuzzingEngine;
    private HttpTrafficHandler trafficHandler;
    private volatile boolean enabled = true;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("ParamHunter");

        boolean isPro = CapabilityChecker.detectEdition(api);

        WordlistManager wordlistManager = new WordlistManager();
        EndpointRegistry endpointRegistry = new EndpointRegistry();
        FindingsManager findingsManager = new FindingsManager(api, isPro);

        threadPool = Executors.newFixedThreadPool(5);

        ResponseDiffer responseDiffer = new ResponseDiffer();

        fuzzingEngine = new FuzzingEngine(api, wordlistManager, endpointRegistry,
                findingsManager, responseDiffer, threadPool);

        trafficHandler = new HttpTrafficHandler(api, this, endpointRegistry, fuzzingEngine);

        ParamHunterTab tab = new ParamHunterTab(api, this, wordlistManager,
                endpointRegistry, findingsManager, fuzzingEngine, trafficHandler);

        fuzzingEngine.setTab(tab);

        api.http().registerHttpHandler(trafficHandler);

        api.userInterface().registerSuiteTab("ParamHunter", tab.getPanel());

        api.userInterface().registerContextMenuItemsProvider(
                new ParamHunterContextMenu(api, fuzzingEngine, this));

        api.extension().registerUnloadingHandler(() -> shutdown());

        api.logging().logToOutput("==============================================");
        api.logging().logToOutput("  ParamHunter v1.0.0 loaded successfully");
        api.logging().logToOutput("  Mode: " + (isPro
                ? "Professional — Burp Issues enabled"
                : "Community Edition"));
        api.logging().logToOutput("  Default wordlist: " + wordlistManager.getWordlistSize() + " parameters");
        api.logging().logToOutput("==============================================");
    }

    private void shutdown() {
        enabled = false;
        if (threadPool != null) {
            threadPool.shutdownNow();
            try {
                threadPool.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        api.logging().logToOutput("ParamHunter unloaded.");
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public ExecutorService getThreadPool() {
        return threadPool;
    }

    public void setThreadPool(ExecutorService threadPool) {
        ExecutorService old = this.threadPool;
        this.threadPool = threadPool;
        fuzzingEngine.setThreadPool(threadPool);
        if (old != null) {
            old.shutdownNow();
        }
    }
}
