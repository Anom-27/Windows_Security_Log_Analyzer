package com.siem.model;

/**
 * Represents the severity level of a Windows Security Event, matching
 * the "Level" column found in the Windows Event Viewer.
 *
 * Using an enum instead of a plain String (e.g. "Warning") is safer:
 * the compiler will reject typos like EventLevel.WARNIGN at compile time,
 * whereas a String typo would only be discovered when the program runs.
 */
public enum EventLevel {
    INFO,
    WARNING,
    ERROR,
    CRITICAL
}
