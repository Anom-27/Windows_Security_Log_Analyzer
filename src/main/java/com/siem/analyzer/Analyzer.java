package com.siem.analyzer;

import com.siem.model.SecurityEvent;

import java.util.List;

/**
 * Contract for anything that can analyze a batch of events and return the
 * ones worth a closer look.
 */
public interface Analyzer {
    List<SecurityEvent> analyzeAll(List<SecurityEvent> events);
}
