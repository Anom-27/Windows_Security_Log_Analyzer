package com.siem.model;

import java.time.LocalDateTime;

/**
 * Represents authentication-related events:
 * 4624 (Successful Login), 4625 (Failed Login), 4634 (Logoff),
 * 4648 (Logon using Explicit Credentials).
 *
 * INHERITANCE: extends SecurityEvent, so it automatically gets eventId,
 * timestamp, username, computerName, etc. We only need to add the fields
 * that are SPECIFIC to authentication events.
 */
public class AuthenticationEvent extends SecurityEvent {

    // Extra fields specific to authentication events, not present in the base class.
    private final int logonType;                // e.g. 2 = interactive, 3 = network, 10 = remote desktop
    private final String authenticationPackage;  // e.g. "NTLM", "Kerberos"

    public AuthenticationEvent(int eventId, LocalDateTime timestamp, String username,
                                String computerName, String eventSource, EventLevel eventLevel,
                                String message, String ipAddress,
                                int logonType, String authenticationPackage) {
        // 'super(...)' calls the SecurityEvent constructor to set up all
        // the shared fields. It must be the first line in this constructor.
        super(eventId, timestamp, username, computerName, eventSource, eventLevel, message, ipAddress);
        this.logonType = logonType;
        this.authenticationPackage = authenticationPackage;
    }

    public int getLogonType() {
        return logonType;
    }

    public String getAuthenticationPackage() {
        return authenticationPackage;
    }

    /**
     * POLYMORPHISM in action: this OVERRIDES the abstract display() method
     * from SecurityEvent. The @Override annotation isn't required by Java,
     * but it's a best practice - the compiler will warn you if you typo
     * the method signature and accidentally create a new method instead of
     * overriding the parent one.
     */
    @Override
    public String display() {
        return String.format("[AUTH] %s | EventID=%d | User=%s | LogonType=%d | IP=%s | %s",
                getTimestamp(), getEventId(), getUsername(), logonType,
                getIpAddress() != null ? getIpAddress() : "N/A", getMessage());
    }

    @Override
    public boolean analyze() {
        // A simple per-event rule: a failed login (4625) is always
        // individually worth flagging. Successful logins are not flagged
        // here - PATTERNS of successful logins (e.g. odd hours) are handled
        // later by the ThreatDetector, which needs to look across many
        // events, not just this one.
        return getEventId() == 4625;
    }
}
