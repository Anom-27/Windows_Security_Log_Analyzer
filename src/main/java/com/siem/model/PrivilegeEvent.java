package com.siem.model;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

/**
 * Represents privilege-related events: 4672 (Special Privileges Assigned
 * to New Logon). This fires whenever an account with administrative-level
 * rights logs on, so it's a high-value signal for detecting privilege
 * escalation or admin account misuse.
 */
public class PrivilegeEvent extends SecurityEvent {

    private final List<String> privilegeList; // e.g. ["SeDebugPrivilege", "SeBackupPrivilege"]

    public PrivilegeEvent(int eventId, LocalDateTime timestamp, String username,
                           String computerName, String eventSource, EventLevel eventLevel,
                           String message, String ipAddress, List<String> privilegeList) {
        super(eventId, timestamp, username, computerName, eventSource, eventLevel, message, ipAddress);
        // Collections.unmodifiableList wraps the list so it can't be
        // changed after construction - reinforcing the same immutability
        // principle we used for the other fields, but for a List field.
        this.privilegeList = Collections.unmodifiableList(privilegeList);
    }

    public List<String> getPrivilegeList() {
        return privilegeList;
    }

    @Override
    public String display() {
        return String.format("[PRIVILEGE] %s | EventID=%d | User=%s | Privileges=%s | %s",
                getTimestamp(), getEventId(), getUsername(), privilegeList, getMessage());
    }

    @Override
    public boolean analyze() {
        // Every privilege assignment event is individually worth flagging -
        // this is exactly the kind of event a security analyst wants to
        // see at a glance, without waiting for a pattern to emerge.
        return true;
    }
}
