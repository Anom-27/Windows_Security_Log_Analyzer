package com.siem.detector;

import com.siem.model.Alert;
import com.siem.model.AlertSeverity;
import com.siem.model.AuthenticationEvent;
import com.siem.model.SecurityEvent;

import java.util.*;

/** Detects repeated failed login attempts (Event ID 4625) from the same IP address. */
public class BruteForceDetector implements ThreatDetector {

    private static final int THRESHOLD = 5;

    @Override
    public List<Alert> detect(List<SecurityEvent> events) {
        Map<String, List<SecurityEvent>> failuresByIp = new HashMap<>();

        for (SecurityEvent event : events) {
            if (event instanceof AuthenticationEvent auth && auth.getEventId() == 4625 && auth.getIpAddress() != null) {
                failuresByIp.computeIfAbsent(auth.getIpAddress(), k -> new ArrayList<>()).add(event);
            }
        }

        List<Alert> alerts = new ArrayList<>();
        for (Map.Entry<String, List<SecurityEvent>> entry : failuresByIp.entrySet()) {
            if (entry.getValue().size() >= THRESHOLD) {
                alerts.add(new Alert(getRuleName(),
                        entry.getValue().size() + " failed login attempts detected from IP " + entry.getKey(),
                        AlertSeverity.HIGH, entry.getValue().get(0)));
            }
        }
        return alerts;
    }

    @Override
    public String getRuleName() {
        return "Brute Force Detection";
    }
}
