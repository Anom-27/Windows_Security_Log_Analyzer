package com.siem.model;

import java.time.LocalDateTime;

/**
 * Represents a single finding produced by a ThreatDetector - e.g. "5 failed
 * logins from the same IP" or "Privilege assignment detected". This is a
 * separate concept from SecurityEvent: a SecurityEvent is one raw log
 * entry, while an Alert is a conclusion drawn by analyzing one or more
 * SecurityEvents together.
 */
public class Alert {
    private final String ruleName;
    private final String description;
    private final AlertSeverity severity;
    private final SecurityEvent relatedEvent; // may be null if the alert covers many events, not just one
    private final LocalDateTime detectedAt;

    public Alert(String ruleName, String description, AlertSeverity severity, SecurityEvent relatedEvent) {
        this.ruleName = ruleName;
        this.description = description;
        this.severity = severity;
        this.relatedEvent = relatedEvent;
        this.detectedAt = LocalDateTime.now();
    }

    public String getRuleName() {
        return ruleName;
    }

    public String getDescription() {
        return description;
    }

    public AlertSeverity getSeverity() {
        return severity;
    }

    public SecurityEvent getRelatedEvent() {
        return relatedEvent;
    }

    public LocalDateTime getDetectedAt() {
        return detectedAt;
    }

    public String display() {
        return String.format("[%s] %s - %s", severity, ruleName, description);
    }
}
