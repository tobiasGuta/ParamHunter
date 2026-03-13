package com.paramhunter.ui;

import com.paramhunter.FindingsManager;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class FindingsTable extends AbstractTableModel {

    private static final String[] COLUMNS = {
            "Timestamp", "Host", "Endpoint", "Method", "Discovered Parameter", "Evidence"
    };

    private List<FindingsManager.Finding> data = new ArrayList<>();

    @Override
    public int getRowCount() {
        return data.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= data.size()) return "";
        FindingsManager.Finding f = data.get(rowIndex);
        switch (columnIndex) {
            case 0: return f.timestamp;
            case 1: return f.host;
            case 2: return f.endpoint;
            case 3: return f.method;
            case 4: return f.parameter;
            case 5: return f.evidence;
            default: return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    public void updateFindings(List<FindingsManager.Finding> findings) {
        this.data = new ArrayList<>(findings);
        fireTableDataChanged();
    }

    public FindingsManager.Finding getFindingAt(int row) {
        if (row >= 0 && row < data.size()) {
            return data.get(row);
        }
        return null;
    }

    public void clear() {
        data.clear();
        fireTableDataChanged();
    }
}
