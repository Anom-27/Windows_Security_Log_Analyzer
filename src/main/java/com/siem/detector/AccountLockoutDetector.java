package com.siem.detector;

import com.siem.model.*;

import java.util.ArrayList;
import java.util.List;

/** Detects accounts that became locked (Event ID 4740). */
public class AccountLockoutDetector implements ThreatDetector {

    @Override
    public List<Alert> detect(List<SecurityEvent> events) {
        List<Alert> alerts = new ArrayList<>();
        for (SecurityEvent event : events) {
            if (event instanceof AccountEvent account && account.getAccountAction() == AccountAction.LOCKED) {
                alerts.add(new Alert(getRuleName(),
                        "Account locked: " + account.getTargetAccount(),
                        AlertSeverity.HIGH, event));
            }
        }
        return alerts;
    }

    @Override
    public String getRuleName() {
        return "Account Lockout Detection";
    }
}
