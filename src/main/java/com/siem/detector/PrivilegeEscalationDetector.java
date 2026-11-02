package com.siem.detector;

import com.siem.model.Alert;
import com.siem.model.AlertSeverity;
import com.siem.model.PrivilegeEvent;
import com.siem.model.SecurityEvent;

import java.util.ArrayList;
import java.util.List;

/** Detects and highlights administrative privilege assignments (Event ID 4672). */
public class PrivilegeEscalationDetector implements ThreatDetector {

    @Override
    public List<Alert> detect(List<SecurityEvent> events) {
        List<Alert> alerts = new ArrayList<>();
        for (SecurityEvent event : events) {
            if (event instanceof PrivilegeEvent priv) {
                alerts.add(new Alert(getRuleName(),
                        "Special privileges assigned to " + priv.getUsername() + ": " + priv.getPrivilegeList(),
                        AlertSeverity.MEDIUM, event));
            }
        }
        return alerts;
    }

    @Override
    public String getRuleName() {
        return "Privilege Escalation Detection";
    }
}
