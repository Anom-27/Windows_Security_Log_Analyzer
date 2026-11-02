package com.siem.detector;

import com.siem.model.Alert;
import com.siem.model.SecurityEvent;

import java.util.List;

/**
 * Contract for a single threat-detection rule. Each concrete detector
 * implements one specific rule (brute force, lockout, privilege escalation,
 * etc.), examining the FULL list of events (not just one at a time) so it
 * can spot patterns across multiple log entries - unlike
 * SecurityEvent.analyze(), which only judges one event in isolation.
 */
public interface ThreatDetector {
    List<Alert> detect(List<SecurityEvent> events);
    String getRuleName();
}
