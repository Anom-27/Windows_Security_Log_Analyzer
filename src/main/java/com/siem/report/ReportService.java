package com.siem.report;

import com.siem.model.*;
import com.siem.service.Statistics;

import java.io.FileWriter;
import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * ReportService builds human-readable reports as plain text, and exports
 * either arbitrary text content or a list of SecurityEvents to disk.
 *
 * It implements Exportable<SecurityEvent> - a GENERIC interface. This
 * means the same interface (Exportable<T>) could later be reused for
 * exporting a List<Alert> as well, just by writing a class that implements
 * Exportable<Alert> instead - generics let us write the CONTRACT once and
 * reuse it for different data types.
 */
public class ReportService implements Exportable<SecurityEvent> {

    private static final DateTimeFormatter TS_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public String generateSummaryReport(Statistics stats) {
        StringBuilder sb = new StringBuilder();
        sb.append("========== SECURITY SUMMARY REPORT ==========\n\n");
        sb.append(stats.toString());
        return sb.toString();
    }

    public String generateAuthenticationReport(List<SecurityEvent> events) {
        StringBuilder sb = new StringBuilder();
        sb.append("========== AUTHENTICATION REPORT ==========\n\n");
        for (SecurityEvent event : events) {
            if (event instanceof AuthenticationEvent) {
                sb.append(event.display()).append("\n");
            }
        }
        return sb.toString();
    }

    public String generateThreatReport(List<Alert> alerts) {
        StringBuilder sb = new StringBuilder();
        sb.append("========== THREAT DETECTION REPORT ==========\n\n");
        sb.append("Total alerts: ").append(alerts.size()).append("\n\n");
        for (Alert alert : alerts) {
            sb.append(alert.display()).append("\n");
        }
        return sb.toString();
    }

    public String generateUserActivityReport(List<SecurityEvent> events, String username) {
        StringBuilder sb = new StringBuilder();
        sb.append("========== USER ACTIVITY REPORT: ").append(username).append(" ==========\n\n");
        for (SecurityEvent event : events) {
            if (event.getUsername().equalsIgnoreCase(username)) {
                sb.append(event.display()).append("\n");
            }
        }
        return sb.toString();
    }

    @Override
    public void exportAsText(String content, String filePath) throws IOException {
        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(content);
        }
    }

    @Override
    public void exportAsCsv(List<SecurityEvent> events, String filePath) throws IOException {
        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write("EventID,Timestamp,Username,ComputerName,Level,IPAddress,Message\n");
            for (SecurityEvent event : events) {
                writer.write(String.join(",",
                        String.valueOf(event.getEventId()),
                        event.getTimestamp().format(TS_FORMAT),
                        escapeCsv(event.getUsername()),
                        escapeCsv(event.getComputerName()),
                        event.getEventLevel().toString(),
                        event.getIpAddress() != null ? event.getIpAddress() : "",
                        escapeCsv(event.getMessage())
                ));
                writer.write("\n");
            }
        }
    }

    /** Wraps a value in quotes if it contains a comma, so the CSV structure stays valid. */
    private String escapeCsv(String value) {
        if (value == null) return "";
        return value.contains(",") ? "\"" + value + "\"" : value;
    }
}
