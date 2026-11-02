package com.siem.detector;

import com.siem.model.*;

import java.util.ArrayList;
import java.util.List;

/** Detects newly created accounts (Event ID 4720). */
public class NewUserDetector implements ThreatDetector {

    @Override
    public List<Alert> detect(List<SecurityEvent> events) {
        List<Alert> alerts = new ArrayList<>();
        for (SecurityEvent event : events) {
            if (event instanceof AccountEvent account && account.getAccountAction() == AccountAction.CREATED) {
                alerts.add(new Alert(getRuleName(),
                        "New account created: " + account.getTargetAccount() + " by " + account.getUsername(),
                        AlertSeverity.LOW, event));
            }
        }
        return alerts;
    }

    @Override
    public String getRuleName() {
        return "New User Detection";
    }
}
