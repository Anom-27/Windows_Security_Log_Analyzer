package com.siem.detector;

import com.siem.model.*;

import java.util.ArrayList;
import java.util.List;

/** Detects deleted accounts (Event ID 4726). */
public class DeletedUserDetector implements ThreatDetector {

    @Override
    public List<Alert> detect(List<SecurityEvent> events) {
        List<Alert> alerts = new ArrayList<>();
        for (SecurityEvent event : events) {
            if (event instanceof AccountEvent account && account.getAccountAction() == AccountAction.DELETED) {
                alerts.add(new Alert(getRuleName(),
                        "Account deleted: " + account.getTargetAccount() + " by " + account.getUsername(),
                        AlertSeverity.HIGH, event));
            }
        }
        return alerts;
    }

    @Override
    public String getRuleName() {
        return "Deleted User Detection";
    }
}
