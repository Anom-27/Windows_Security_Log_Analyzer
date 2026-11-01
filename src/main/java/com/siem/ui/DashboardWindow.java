package com.siem.ui;

import com.siem.analyzer.EventAnalyzer;
import com.siem.detector.ThreatDetectionEngine;
import com.siem.exception.SiemException;
import com.siem.model.Alert;
import com.siem.model.SecurityEvent;
import com.siem.model.User;
import com.siem.parser.CsvLogParser;
import com.siem.parser.LogParser;
import com.siem.parser.XmlLogParser;
import com.siem.report.ReportService;
import com.siem.repository.EventRepository;
import com.siem.service.SearchService;
import com.siem.service.Statistics;
import com.siem.service.StatisticsService;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * DashboardWindow is the main screen after login. It hosts the toolbar
 * (Import, Search, Statistics, Threat Detection, Reports, Logout) and a
 * JTable showing whatever events are currently loaded.
 */
public class DashboardWindow extends JFrame {

    private final User currentUser;
    private final EventRepository repository = new EventRepository();
    private final EventTableModel tableModel = new EventTableModel(List.of());
    private final JLabel statusLabel = new JLabel("No file imported yet.");

    public DashboardWindow(User user) {
        this.currentUser = user;

        setTitle("Windows Security Log Analysis Tool - Dashboard (" + user + ")");
        setSize(1000, 600);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        add(buildToolbar(), BorderLayout.NORTH);
        add(buildTablePanel(), BorderLayout.CENTER);
        add(statusLabel, BorderLayout.SOUTH);
    }

    private JToolBar buildToolbar() {
        JToolBar toolBar = new JToolBar();
        toolBar.setFloatable(false);

        JButton importButton = new JButton("Import");
        JButton searchButton = new JButton("Search");
        JButton statsButton = new JButton("Statistics");
        JButton threatButton = new JButton("Threat Detection");
        JButton reportButton = new JButton("Reports");
        JButton logoutButton = new JButton("Logout");

        importButton.addActionListener(e -> handleImport());
        searchButton.addActionListener(e -> handleSearch());
        statsButton.addActionListener(e -> handleStatistics());
        threatButton.addActionListener(e -> handleThreatDetection());
        reportButton.addActionListener(e -> handleReports());
        logoutButton.addActionListener(e -> handleLogout());

        toolBar.add(importButton);
        toolBar.add(searchButton);
        toolBar.add(statsButton);
        toolBar.add(threatButton);
        toolBar.add(reportButton);
        toolBar.addSeparator();
        toolBar.add(logoutButton);

        return toolBar;
    }

    private JScrollPane buildTablePanel() {
        JTable table = new JTable(tableModel);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        return new JScrollPane(table);
    }

    private void handleImport() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter("Security Log Files (*.csv, *.xml)", "csv", "xml"));

        int result = chooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return; // user clicked Cancel
        }

        File file = chooser.getSelectedFile();
        LogParser parser = file.getName().toLowerCase().endsWith(".xml")
                ? new XmlLogParser()
                : new CsvLogParser();

        try {
            List<SecurityEvent> events = parser.parse(file);
            repository.clear();
            repository.addAll(events);
            tableModel.setEvents(repository.getAllEvents());

            List<String> skipped = parser.getSkippedRows();
            if (skipped.isEmpty()) {
                statusLabel.setText("Imported " + events.size() + " events from " + file.getName());
            } else {
                // Some rows had bad data (e.g. a missing timestamp) and
                // were skipped rather than failing the whole import.
                // The user is told exactly how many and can review details.
                statusLabel.setText("Imported " + events.size() + " events from " + file.getName()
                        + " (" + skipped.size() + " row(s) skipped due to errors - click Import again to see details)");
                JOptionPane.showMessageDialog(this,
                        skipped.size() + " row(s) were skipped because of data errors:\n\n"
                                + String.join("\n", skipped.subList(0, Math.min(10, skipped.size())))
                                + (skipped.size() > 10 ? "\n...and " + (skipped.size() - 10) + " more." : ""),
                        "Some Rows Skipped", JOptionPane.WARNING_MESSAGE);
            }
        } catch (SiemException ex) {
            // Catching by the abstract base type here means ONE catch
            // block handles MissingFileException, EmptyFileException, and
            // InvalidFileFormatException all at once, polymorphically.
            // (Row-level parsing/date errors no longer reach this point -
            // they are now skipped individually inside the parser instead.)
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Import Failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void handleSearch() {
        if (repository.size() == 0) {
            JOptionPane.showMessageDialog(this, "Please import a log file first.", "No Data", JOptionPane.WARNING_MESSAGE);
            return;
        }
        new SearchDialog(this, new SearchService(repository)).setVisible(true);
    }

    private void handleStatistics() {
        if (repository.size() == 0) {
            JOptionPane.showMessageDialog(this, "Please import a log file first.", "No Data", JOptionPane.WARNING_MESSAGE);
            return;
        }
        Statistics stats = new StatisticsService().computeStatistics(repository.getAllEvents());
        new StatisticsDialog(this, stats).setVisible(true);
    }

    private void handleThreatDetection() {
        if (repository.size() == 0) {
            JOptionPane.showMessageDialog(this, "Please import a log file first.", "No Data", JOptionPane.WARNING_MESSAGE);
            return;
        }
        List<Alert> alerts = new ThreatDetectionEngine().runAll(repository.getAllEvents());
        new ThreatDialog(this, alerts).setVisible(true);
    }

    private void handleReports() {
        if (repository.size() == 0) {
            JOptionPane.showMessageDialog(this, "Please import a log file first.", "No Data", JOptionPane.WARNING_MESSAGE);
            return;
        }
        List<Alert> alerts = new ThreatDetectionEngine().runAll(repository.getAllEvents());
        Statistics stats = new StatisticsService().computeStatistics(repository.getAllEvents());
        new ReportDialog(this, repository.getAllEvents(), alerts, stats).setVisible(true);
    }

    private void handleLogout() {
        dispose();
        SwingUtilities.invokeLater(() -> new LoginWindow().setVisible(true));
    }
}
