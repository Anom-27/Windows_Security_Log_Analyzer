package com.siem.detector;

import com.siem.model.Alert;
import com.siem.model.SecurityEvent;

import java.util.ArrayList;
import java.util.List;

/**
 * ThreatDetectionEngine holds a list of ALL threat detectors and runs
 * every one of them against the imported events, combining all the
 * resulting alerts into a single list.
 *
 * This is POLYMORPHISM again: the engine holds a List<ThreatDetector>
 * (the interface type), and calls detector.detect(events) on each one
 * without caring which specific rule it is - each concrete detector
 * plugs in the same way. Adding a new rule later means writing one new
 * class and adding it to the constructor below - nothing else changes.
 */
public class ThreatDetectionEngine {

    private final List<ThreatDetector> detectors = new ArrayList<>();

    public ThreatDetectionEngine() {
        detectors.add(new BruteForceDetector());
        detectors.add(new AccountLockoutDetector());
        detectors.add(new PrivilegeEscalationDetector());
        detectors.add(new SuspiciousLoginTimeDetector());
        detectors.add(new NewUserDetector());
        detectors.add(new DeletedUserDetector());
        detectors.add(new PasswordChangeDetector());
        detectors.add(new MultipleFailedLoginDetector());
    }

    public List<Alert> runAll(List<SecurityEvent> events) {
        List<Alert> allAlerts = new ArrayList<>();
        for (ThreatDetector detector : detectors) {
            allAlerts.addAll(detector.detect(events));
        }
        return allAlerts;
    }
}
