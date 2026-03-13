package com.paramhunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class ParamHunterContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final FuzzingEngine fuzzingEngine;
    private final ParamHunterExtension extension;

    public ParamHunterContextMenu(MontoyaApi api, FuzzingEngine fuzzingEngine,
                                  ParamHunterExtension extension) {
        this.api = api;
        this.fuzzingEngine = fuzzingEngine;
        this.extension = extension;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        JMenuItem sendToParamHunter = new JMenuItem("Send to ParamHunter");
        sendToParamHunter.addActionListener(e -> {
            if (!extension.isEnabled()) {
                api.logging().logToOutput("ParamHunter is disabled. Enable it first.");
                return;
            }

            // Collect request/responses from all possible sources
            List<HttpRequestResponse> toFuzz = new ArrayList<>();

            // Source 1: selected rows in HTTP history / site map list
            List<HttpRequestResponse> selected = event.selectedRequestResponses();
            if (selected != null && !selected.isEmpty()) {
                toFuzz.addAll(selected);
            }

            // Source 2: message editor (when right clicking inside request/response viewer)
            Optional<MessageEditorHttpRequestResponse> editorRR = event.messageEditorRequestResponse();
            if (editorRR.isPresent()) {
                HttpRequestResponse rr = editorRR.get().requestResponse();
                if (rr != null) {
                    toFuzz.add(rr);
                }
            }

            if (toFuzz.isEmpty()) {
                api.logging().logToOutput("No request selected for ParamHunter.");
                return;
            }

            for (HttpRequestResponse rr : toFuzz) {
                if (rr.request() != null) {
                    api.logging().logToOutput("Manually queued: "
                            + rr.request().method() + " " + rr.request().url());
                    fuzzingEngine.queueFuzzing(rr.request(), rr.response());
                }
            }
        });

        menuItems.add(sendToParamHunter);
        return menuItems;
    }
}
