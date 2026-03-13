package com.paramhunter.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.paramhunter.*;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

public class ParamHunterTab {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final MontoyaApi api;
    private final ParamHunterExtension extension;
    private final WordlistManager wordlistManager;
    private final EndpointRegistry endpointRegistry;
    private final FindingsManager findingsManager;
    private final FuzzingEngine fuzzingEngine;
    private final HttpTrafficHandler trafficHandler;

    private JPanel mainPanel;
    private JToggleButton enableToggle;
    private JLabel wordlistSizeLabel;
    private JSpinner threadsSpinner;
    private JSpinner delaySpinner;
    private JCheckBox inScopeCheckbox;
    private JCheckBox skipFuzzedCheckbox;
    private JTable findingsJTable;
    private FindingsTable findingsTableModel;
    private JLabel statsLabel;

    // Request/response editors
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;

    // Notification log
    private JTextArea notificationArea;

    public ParamHunterTab(MontoyaApi api, ParamHunterExtension extension,
                          WordlistManager wordlistManager, EndpointRegistry endpointRegistry,
                          FindingsManager findingsManager, FuzzingEngine fuzzingEngine,
                          HttpTrafficHandler trafficHandler) {
        this.api = api;
        this.extension = extension;
        this.wordlistManager = wordlistManager;
        this.endpointRegistry = endpointRegistry;
        this.findingsManager = findingsManager;
        this.fuzzingEngine = fuzzingEngine;
        this.trafficHandler = trafficHandler;
        buildUI();
    }

    public JPanel getPanel() {
        return mainPanel;
    }

    private void buildUI() {
        mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // ============================================================
        // TOP: Controls
        // ============================================================
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));

        // Row 1: Enable toggle
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        enableToggle = new JToggleButton("Enabled", true);
        enableToggle.setPreferredSize(new Dimension(120, 30));
        enableToggle.addActionListener(e -> {
            boolean on = enableToggle.isSelected();
            extension.setEnabled(on);
            enableToggle.setText(on ? "Enabled" : "Disabled");
            enableToggle.setBackground(on ? new Color(76, 175, 80) : new Color(244, 67, 54));
        });
        enableToggle.setBackground(new Color(76, 175, 80));
        enableToggle.setForeground(Color.WHITE);
        enableToggle.setOpaque(true);
        row1.add(new JLabel("Status: "));
        row1.add(enableToggle);
        topPanel.add(row1);

        // Row 2: Wordlist controls
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        wordlistSizeLabel = new JLabel("Wordlist: " + wordlistManager.getWordlistSize() + " parameters");
        wordlistSizeLabel.setFont(wordlistSizeLabel.getFont().deriveFont(Font.BOLD));
        row2.add(wordlistSizeLabel);

        JButton loadWordlistBtn = new JButton("Load Custom Wordlist");
        loadWordlistBtn.addActionListener(e -> loadCustomWordlist());
        row2.add(loadWordlistBtn);

        JButton resetWordlistBtn = new JButton("Reset to Default");
        resetWordlistBtn.addActionListener(e -> {
            wordlistManager.resetToDefault();
            wordlistSizeLabel.setText("Wordlist: " + wordlistManager.getWordlistSize() + " parameters");
            api.logging().logToOutput("Wordlist reset to default (" + wordlistManager.getWordlistSize() + " params).");
        });
        row2.add(resetWordlistBtn);
        topPanel.add(row2);

        // Row 3: Settings
        JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT));

        row3.add(new JLabel("Threads:"));
        threadsSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 20, 1));
        threadsSpinner.setPreferredSize(new Dimension(60, 25));
        threadsSpinner.addChangeListener(e -> {
            int threads = (int) threadsSpinner.getValue();
            ExecutorService newPool = Executors.newFixedThreadPool(threads);
            extension.setThreadPool(newPool);
            api.logging().logToOutput("Thread pool resized to " + threads);
        });
        row3.add(threadsSpinner);

        row3.add(Box.createHorizontalStrut(15));

        row3.add(new JLabel("Delay (ms):"));
        delaySpinner = new JSpinner(new SpinnerNumberModel(200, 0, 10000, 50));
        delaySpinner.setPreferredSize(new Dimension(80, 25));
        delaySpinner.addChangeListener(e -> {
            int delay = (int) delaySpinner.getValue();
            fuzzingEngine.setRequestDelayMs(delay);
        });
        row3.add(delaySpinner);

        row3.add(Box.createHorizontalStrut(15));

        inScopeCheckbox = new JCheckBox("Only fuzz in-scope targets", true);
        inScopeCheckbox.addActionListener(e -> trafficHandler.setOnlyInScope(inScopeCheckbox.isSelected()));
        row3.add(inScopeCheckbox);

        skipFuzzedCheckbox = new JCheckBox("Skip endpoints already fuzzed", true);
        skipFuzzedCheckbox.addActionListener(e -> trafficHandler.setSkipFuzzed(skipFuzzedCheckbox.isSelected()));
        row3.add(skipFuzzedCheckbox);
        topPanel.add(row3);

        // Row 4: Action buttons
        JPanel row4 = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton exportBtn = new JButton("Export Findings (CSV)");
        exportBtn.addActionListener(e -> exportFindings());
        row4.add(exportBtn);

        JButton clearBtn = new JButton("Clear Findings");
        clearBtn.addActionListener(e -> {
            findingsManager.clearFindings();
            findingsTableModel.clear();
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
            refreshStats();
        });
        row4.add(clearBtn);

        JButton clearNotificationsBtn = new JButton("Clear Notifications");
        clearNotificationsBtn.addActionListener(e -> {
            if (notificationArea != null) {
                notificationArea.setText("");
            }
        });
        row4.add(clearNotificationsBtn);

        // Pause and Cancel buttons
        JButton pauseBtn = new JButton("Pause Fuzzing");
        pauseBtn.addActionListener(e -> fuzzingEngine.pauseFuzzing());
        row4.add(pauseBtn);

        JButton cancelBtn = new JButton("Cancel Fuzzing");
        cancelBtn.addActionListener(e -> fuzzingEngine.cancelFuzzing());
        row4.add(cancelBtn);

        topPanel.add(row4);

        mainPanel.add(topPanel, BorderLayout.NORTH);

        // ============================================================
        // CENTER: Findings table + Request/Response editors (vertical split)
        // ============================================================

        // Findings table
        findingsTableModel = new FindingsTable();
        findingsJTable = new JTable(findingsTableModel);
        findingsJTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        findingsJTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        findingsJTable.setRowHeight(22);
        findingsJTable.getTableHeader().setReorderingAllowed(false);

        findingsJTable.getColumnModel().getColumn(0).setPreferredWidth(140);  // Timestamp
        findingsJTable.getColumnModel().getColumn(1).setPreferredWidth(150);  // Host
        findingsJTable.getColumnModel().getColumn(2).setPreferredWidth(250);  // Endpoint
        findingsJTable.getColumnModel().getColumn(3).setPreferredWidth(60);   // Method
        findingsJTable.getColumnModel().getColumn(4).setPreferredWidth(150);  // Parameter
        findingsJTable.getColumnModel().getColumn(5).setPreferredWidth(350);  // Evidence

        // Selection listener: update request/response editors on row click
        findingsJTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = findingsJTable.getSelectedRow();
                if (row >= 0) {
                    FindingsManager.Finding f = findingsTableModel.getFindingAt(row);
                    if (f != null && f.requestResponse != null) {
                        if (f.requestResponse.request() != null) {
                            requestEditor.setRequest(f.requestResponse.request());
                        } else {
                            requestEditor.setRequest(null);
                        }
                        if (f.requestResponse.response() != null) {
                            responseEditor.setResponse(f.requestResponse.response());
                        } else {
                            responseEditor.setResponse(null);
                        }
                    } else {
                        requestEditor.setRequest(null);
                        responseEditor.setResponse(null);
                    }
                }
            }
        });

        // Right-click context menu on findings table
        JPopupMenu tablePopup = new JPopupMenu();
        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> {
            int row = findingsJTable.getSelectedRow();
            if (row >= 0) {
                FindingsManager.Finding f = findingsTableModel.getFindingAt(row);
                if (f != null && f.requestResponse != null && f.requestResponse.request() != null) {
                    api.repeater().sendToRepeater(f.requestResponse.request(),
                            "PH: " + f.parameter);
                }
            }
        });
        tablePopup.add(sendToRepeater);

        JMenuItem copyAsCurl = new JMenuItem("Copy as curl");
        copyAsCurl.addActionListener(e -> {
            int row = findingsJTable.getSelectedRow();
            if (row >= 0) {
                FindingsManager.Finding f = findingsTableModel.getFindingAt(row);
                if (f != null && f.requestResponse != null && f.requestResponse.request() != null) {
                    String curl = buildCurlCommand(f.requestResponse.request());
                    Toolkit.getDefaultToolkit().getSystemClipboard()
                            .setContents(new java.awt.datatransfer.StringSelection(curl), null);
                    api.logging().logToOutput("Copied curl command to clipboard.");
                }
            }
        });
        tablePopup.add(copyAsCurl);

        findingsJTable.setComponentPopupMenu(tablePopup);

        JScrollPane tableScrollPane = new JScrollPane(findingsJTable);
        tableScrollPane.setPreferredSize(new Dimension(0, 250));

        // Request/Response editors using Burp's built in components
        requestEditor = api.userInterface().createHttpRequestEditor(READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(READ_ONLY);

        // Side by side: request on the left, response on the right
        JSplitPane editorSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                requestEditor.uiComponent(), responseEditor.uiComponent());
        editorSplit.setResizeWeight(0.5);

        // Vertical split: findings table (top) / editors (bottom)
        JSplitPane centerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                tableScrollPane, editorSplit);
        centerSplit.setResizeWeight(0.4);
        centerSplit.setDividerLocation(250);

        // ============================================================
        // BOTTOM: Notification log + Stats bar
        // ============================================================

        // Notification area
        notificationArea = new JTextArea(4, 0);
        notificationArea.setEditable(false);
        notificationArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));

        JScrollPane notificationScroll = new JScrollPane(notificationArea);
        notificationScroll.setBorder(BorderFactory.createTitledBorder("Notifications"));
        notificationScroll.setPreferredSize(new Dimension(0, 100));

        // Stats bar
        JPanel statsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statsLabel = new JLabel(buildStatsText());
        statsLabel.setFont(statsLabel.getFont().deriveFont(Font.BOLD, 12f));
        statsPanel.add(statsLabel);

        // Combine notifications + stats in a south panel
        JPanel southPanel = new JPanel(new BorderLayout());
        southPanel.add(notificationScroll, BorderLayout.CENTER);
        southPanel.add(statsPanel, BorderLayout.SOUTH);

        // Main split: center content / bottom notifications
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                centerSplit, southPanel);
        mainSplit.setResizeWeight(0.8);

        mainPanel.add(mainSplit, BorderLayout.CENTER);
    }

    private void loadCustomWordlist() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter("Text files (*.txt)", "txt"));
        chooser.setDialogTitle("Load Custom Wordlist");
        int result = chooser.showOpenDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                Path path = chooser.getSelectedFile().toPath();
                wordlistManager.loadCustomWordlist(path);
                wordlistSizeLabel.setText("Wordlist: " + wordlistManager.getWordlistSize() + " parameters");
                api.logging().logToOutput("Loaded custom wordlist from " + path
                        + " (total: " + wordlistManager.getWordlistSize() + " params)");
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(mainPanel,
                        "Error loading wordlist: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportFindings() {
        if (findingsManager.getFindingsCount() == 0) {
            JOptionPane.showMessageDialog(mainPanel, "No findings to export.",
                    "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter("CSV files (*.csv)", "csv"));
        chooser.setDialogTitle("Export Findings");
        chooser.setSelectedFile(new java.io.File("paramhunter_findings.csv"));
        int result = chooser.showSaveDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            Path path = chooser.getSelectedFile().toPath();
            try (BufferedWriter writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
                writer.write("Timestamp,Host,Endpoint,Method,Parameter,Evidence");
                writer.newLine();
                for (FindingsManager.Finding f : findingsManager.getFindings()) {
                    writer.write(String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"",
                            escapeCsv(f.timestamp), escapeCsv(f.host),
                            escapeCsv(f.endpoint), escapeCsv(f.method),
                            escapeCsv(f.parameter), escapeCsv(f.evidence)));
                    writer.newLine();
                }
                api.logging().logToOutput("Findings exported to " + path);
                JOptionPane.showMessageDialog(mainPanel,
                        "Exported " + findingsManager.getFindingsCount() + " findings to " + path,
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(mainPanel,
                        "Error exporting: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private static String escapeCsv(String value) {
        if (value == null) return "";
        return value.replace("\"", "\"\"");
    }

    public void refreshFindings() {
        SwingUtilities.invokeLater(() ->
                findingsTableModel.updateFindings(findingsManager.getFindings()));
    }

    public void refreshStats() {
        SwingUtilities.invokeLater(() -> statsLabel.setText(buildStatsText()));
    }

    /**
     * Called from the FuzzingEngine when a rate limit or other notable event occurs.
     */
    public void addNotification(String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = LocalTime.now().format(TIME_FMT);
            notificationArea.append("[" + timestamp + "] " + message + "\n");
            // Auto scroll to bottom
            notificationArea.setCaretPosition(notificationArea.getDocument().getLength());
        });
    }

    private String buildStatsText() {
        String mode = findingsManager.isPro()
                ? "Professional — Burp Issues enabled"
                : "Community Edition";
        return String.format("Endpoints fuzzed: %d | Parameters tested: %d | Findings: %d | Mode: %s",
                endpointRegistry.getFuzzedCount(),
                endpointRegistry.getParametersTested(),
                findingsManager.getFindingsCount(),
                mode);
    }

    private String buildCurlCommand(HttpRequest request) {
        StringBuilder curl = new StringBuilder("curl");

        String method = request.method();
        if (!"GET".equalsIgnoreCase(method)) {
            curl.append(" -X ").append(method);
        }

        // URL
        String url = request.url();
        curl.append(" '").append(url.replace("'", "'\\''")).append("'");

        // Headers (skip Host, Content-Length)
        for (HttpHeader h : request.headers()) {
            String name = h.name();
            if ("Host".equalsIgnoreCase(name) || "Content-Length".equalsIgnoreCase(name)) continue;
            curl.append(" -H '").append(name).append(": ")
                .append(h.value().replace("'", "'\\''")).append("'");
        }

        // Body
        String body = request.bodyToString();
        if (body != null && !body.isEmpty()) {
            curl.append(" -d '").append(body.replace("'", "'\\''")).append("'");
        }

        return curl.toString();
    }

    public boolean isOnlyInScope() {
        return inScopeCheckbox != null && inScopeCheckbox.isSelected();
    }

    public boolean isSkipFuzzed() {
        return skipFuzzedCheckbox != null && skipFuzzedCheckbox.isSelected();
    }
}
