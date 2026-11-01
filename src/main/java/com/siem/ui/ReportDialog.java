package com.siem.ui;

import com.siem.model.Alert;
import com.siem.model.SecurityEvent;
import com.siem.report.ReportService;
import com.siem.service.Statistics;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.util.List;

/** Dialog window for generating and exporting the four report types (Summary, Auth, Threat, User Activity). */
public class ReportDialog extends JDialog {

    private final ReportService reportService = new ReportService();
    private final List<SecurityEvent> events;
    private final JTextArea previewArea = new JTextArea();
    private String currentReportContent = "";

    public ReportDialog(JFrame parent, List<SecurityEvent> events, List<Alert> alerts, Statistics stats) {
        super(parent, "Reports", true);
        this.events = events;
        setSize(700, 550);
        setLocationRelativeTo(parent);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton summaryBtn = new JButton("Summary Report");
        JButton authBtn = new JButton("Authentication Report");
        JButton threatBtn = new JButton("Threat Report");
        JButton userActivityBtn = new JButton("User Activity Report");
        JTextField usernameField = new JTextField(12);
        usernameField.setToolTipText("Username for User Activity Report");

        buttonPanel.add(summaryBtn);
        buttonPanel.add(authBtn);
        buttonPanel.add(threatBtn);
        buttonPanel.add(new JLabel("Username:"));
        buttonPanel.add(usernameField);
        buttonPanel.add(userActivityBtn);

        previewArea.setEditable(false);
        previewArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        JPanel exportPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton exportTxtBtn = new JButton("Export as TXT");
        JButton exportCsvBtn = new JButton("Export Events as CSV");
        exportPanel.add(exportTxtBtn);
        exportPanel.add(exportCsvBtn);

        summaryBtn.addActionListener(e -> showReport(reportService.generateSummaryReport(stats)));
        authBtn.addActionListener(e -> showReport(reportService.generateAuthenticationReport(events)));
        threatBtn.addActionListener(e -> showReport(reportService.generateThreatReport(alerts)));
        userActivityBtn.addActionListener(e -> {
            String username = usernameField.getText().trim();
            if (username.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please enter a username.", "Missing Input", JOptionPane.WARNING_MESSAGE);
                return;
            }
            showReport(reportService.generateUserActivityReport(events, username));
        });

        exportTxtBtn.addActionListener(e -> exportText());
        exportCsvBtn.addActionListener(e -> exportCsv());

        add(buttonPanel, BorderLayout.NORTH);
        add(new JScrollPane(previewArea), BorderLayout.CENTER);
        add(exportPanel, BorderLayout.SOUTH);
    }

    private void showReport(String content) {
        currentReportContent = content;
        previewArea.setText(content);
        previewArea.setCaretPosition(0);
    }

    private void exportText() {
        if (currentReportContent.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please generate a report first.", "No Report", JOptionPane.WARNING_MESSAGE);
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("report.txt"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                reportService.exportAsText(currentReportContent, chooser.getSelectedFile().getAbsolutePath());
                JOptionPane.showMessageDialog(this, "Report exported successfully.", "Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportCsv() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("events.csv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                reportService.exportAsCsv(events, chooser.getSelectedFile().getAbsolutePath());
                JOptionPane.showMessageDialog(this, "Events exported successfully.", "Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
