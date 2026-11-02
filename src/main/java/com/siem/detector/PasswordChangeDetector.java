package com.siem.detector;

import com.siem.model.*;

import java.util.ArrayList;
import java.util.List;

/** Tracks password change/reset attempts (Event ID 4723). */
public class PasswordChangeDetector implements ThreatDetector {

    @Override
    public List<Alert> detect(List<SecurityEvent> events) {
        List<Alert> alerts = new ArrayList<>();
        for (SecurityEvent event : events) {
            if (event instanceof AccountEvent account && account.getAccountAction() == AccountAction.PASSWORD_CHANGED) {
                alerts.add(new Alert(getRuleName(),
                        "Password changed for account: " + account.getTargetAccount(),
                        AlertSeverity.LOW, event));
            }
        }
        return alerts;
    }

    @Override
    public String getRuleName() {
        return "Password Change Detection";
    }
}
