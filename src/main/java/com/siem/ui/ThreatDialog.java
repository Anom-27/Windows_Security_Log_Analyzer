package com.siem.ui;

import com.siem.model.Alert;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.List;

/** Dialog window listing all Alert objects produced by the ThreatDetectionEngine. */
public class ThreatDialog extends JDialog {

    public ThreatDialog(JFrame parent, List<Alert> alerts) {
        super(parent, "Threat Detection Results (" + alerts.size() + " alert(s))", true);
        setSize(800, 500);
        setLocationRelativeTo(parent);

        AbstractTableModel model = new AbstractTableModel() {
            private final String[] columns = {"Rule", "Severity", "Description", "Detected At"};

            @Override
            public int getRowCount() {
                return alerts.size();
            }

            @Override
            public int getColumnCount() {
                return columns.length;
            }

            @Override
            public String getColumnName(int column) {
                return columns[column];
            }

            @Override
            public Object getValueAt(int rowIndex, int columnIndex) {
                Alert alert = alerts.get(rowIndex);
                return switch (columnIndex) {
                    case 0 -> alert.getRuleName();
                    case 1 -> alert.getSeverity();
                    case 2 -> alert.getDescription();
                    case 3 -> alert.getDetectedAt();
                    default -> "";
                };
            }
        };

        JTable table = new JTable(model);
        add(new JScrollPane(table), BorderLayout.CENTER);

        if (alerts.isEmpty()) {
            JLabel emptyLabel = new JLabel("No threats detected in the imported events.", SwingConstants.CENTER);
            add(emptyLabel, BorderLayout.NORTH);
        }
    }
}
