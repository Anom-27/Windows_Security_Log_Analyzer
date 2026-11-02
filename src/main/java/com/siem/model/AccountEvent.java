package com.siem.model;

import java.time.LocalDateTime;

/**
 * Represents account management events:
 * 4720 (Created), 4722 (Enabled), 4723 (Password Change Attempt),
 * 4725 (Disabled), 4726 (Deleted), 4740 (Locked).
 */
public class AccountEvent extends SecurityEvent {

    private final String targetAccount;   // the account being acted upon (may differ from 'username', who performed the action)
    private final AccountAction accountAction;

    public AccountEvent(int eventId, LocalDateTime timestamp, String username,
                         String computerName, String eventSource, EventLevel eventLevel,
                         String message, String ipAddress,
                         String targetAccount, AccountAction accountAction) {
        super(eventId, timestamp, username, computerName, eventSource, eventLevel, message, ipAddress);
        this.targetAccount = targetAccount;
        this.accountAction = accountAction;
    }

    public String getTargetAccount() {
        return targetAccount;
    }

    public AccountAction getAccountAction() {
        return accountAction;
    }

    @Override
    public String display() {
        return String.format("[ACCOUNT] %s | EventID=%d | PerformedBy=%s | Target=%s | Action=%s | %s",
                getTimestamp(), getEventId(), getUsername(), targetAccount, accountAction, getMessage());
    }

    @Override
    public boolean analyze() {
        // Account deletions and lockouts are individually significant
        // enough to always flag for a human to review.
        return accountAction == AccountAction.DELETED || accountAction == AccountAction.LOCKED;
    }
}
