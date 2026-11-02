package com.siem.model;

import java.time.LocalDateTime;

/**
 * Represents security events that do not fit the three specialized categories
 * (AuthenticationEvent, AccountEvent, PrivilegeEvent) but are still worth
 * importing and displaying, such as:
 * <ul>
 *   <li>4688 - A new process has been created</li>
 *   <li>4798 - A user's local group membership was enumerated</li>
 *   <li>4799 - A security-enabled local group membership was enumerated</li>
 *   <li>4907 - Auditing settings on an object were changed</li>
 *   <li>5379 - Credential Manager credentials were read</li>
 *   <li>5058/5059/5061 - Cryptographic operations</li>
 * </ul>
 *
 * These events still carry a timestamp, user, computer and message, so they
 * belong in the same table as every other event. They just do not have the
 * extra structured fields (logon type, target account, privileges, etc.) that
 * the specialized subclasses add. Wrapping them in a concrete subclass lets
 * EventFactory return them without throwing, so a real log file is never
 * silently truncated - every row that can be read is imported.
 */
public class SystemEvent extends SecurityEvent {

    public SystemEvent(int eventId, LocalDateTime timestamp, String username,
                       String computerName, String eventSource, EventLevel eventLevel,
                       String message, String ipAddress) {
        super(eventId, timestamp, username, computerName, eventSource, eventLevel, message, ipAddress);
    }

    @Override
    public String display() {
        return String.format("[SYSTEM] %s | EventID=%d | User=%s | Computer=%s | %s",
                getTimestamp(), getEventId(), getUsername(), getComputerName(), getMessage());
    }

    @Override
    public boolean analyze() {
        // These are individually interesting enough to flag for review.
        return isIndividuallySuspicious(getEventId());
    }

    /**
     * Returns true for the event IDs that, on their own, are worth a
     * security analyst's attention regardless of surrounding context.
     */
    public static boolean isIndividuallySuspicious(int eventId) {
        return eventId == 4907      // audit policy changed
                || eventId == 5379  // credentials read from Credential Manager
                || eventId == 4798  // user's group membership enumerated
                || eventId == 4799; // security-enabled group membership enumerated
    }
}