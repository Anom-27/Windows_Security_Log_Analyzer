package com.siem.detector;

import com.siem.model.Alert;
import com.siem.model.AlertSeverity;
import com.siem.model.AuthenticationEvent;
import com.siem.model.SecurityEvent;

import java.util.*;

/**
 * Detects users (not IPs - see BruteForceDetector for the IP-based version)
 * with an unusually high number of failed login attempts (Event ID 4625).
 */
public class MultipleFailedLoginDetector implements ThreatDetector {

    private static final int THRESHOLD = 3;

    @Override
    public List<Alert> detect(List<SecurityEvent> events) {
        Map<String, Integer> failuresByUser = new HashMap<>();
        Map<String, SecurityEvent> sampleEventByUser = new HashMap<>();

        for (SecurityEvent event : events) {
            if (event instanceof AuthenticationEvent auth && auth.getEventId() == 4625) {
                failuresByUser.merge(auth.getUsername(), 1, Integer::sum);
                sampleEventByUser.putIfAbsent(auth.getUsername(), event);
            }
        }

        List<Alert> alerts = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : failuresByUser.entrySet()) {
            if (entry.getValue() >= THRESHOLD) {
                alerts.add(new Alert(getRuleName(),
                        "User '" + entry.getKey() + "' has " + entry.getValue() + " failed login attempts",
                        AlertSeverity.MEDIUM, sampleEventByUser.get(entry.getKey())));
            }
        }
        return alerts;
    }

    @Override
    public String getRuleName() {
        return "Multiple Failed Login Detection";
    }
}
