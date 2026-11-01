package com.siem.detector;

import com.siem.model.Alert;
import com.siem.model.AlertSeverity;
import com.siem.model.AuthenticationEvent;
import com.siem.model.SecurityEvent;
import com.siem.util.DateUtil;

import java.util.ArrayList;
import java.util.List;

/** Detects successful logins (Event ID 4624) that happen outside normal working hours. */
public class SuspiciousLoginTimeDetector implements ThreatDetector {

    @Override
    public List<Alert> detect(List<SecurityEvent> events) {
        List<Alert> alerts = new ArrayList<>();
        for (SecurityEvent event : events) {
            if (event instanceof AuthenticationEvent auth && auth.getEventId() == 4624
                    && DateUtil.isOutsideWorkingHours(auth.getTimestamp())) {
                alerts.add(new Alert(getRuleName(),
                        "Successful login by " + auth.getUsername() + " outside working hours at " + auth.getTimestamp(),
                        AlertSeverity.MEDIUM, event));
            }
        }
        return alerts;
    }

    @Override
    public String getRuleName() {
        return "Suspicious Login Time Detection";
    }
}
