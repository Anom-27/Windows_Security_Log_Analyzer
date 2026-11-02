package com.siem.analyzer;

import com.siem.model.SecurityEvent;

import java.util.ArrayList;
import java.util.List;

/**
 * EventAnalyzer filters a list of events down to just the ones that are
 * individually suspicious. This relies entirely on POLYMORPHISM: it calls
 * event.analyze() on each event without caring whether it is really an
 * AuthenticationEvent, AccountEvent, or PrivilegeEvent - the correct
 * subclass-specific logic runs automatically.
 */
public class EventAnalyzer implements Analyzer {

    @Override
    public List<SecurityEvent> analyzeAll(List<SecurityEvent> events) {
        List<SecurityEvent> flagged = new ArrayList<>();
        for (SecurityEvent event : events) {
            if (event.analyze()) {
                flagged.add(event);
            }
        }
        return flagged;
    }
}
