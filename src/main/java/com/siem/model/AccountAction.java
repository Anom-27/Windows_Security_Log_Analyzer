package com.siem.model;

/**
 * Represents what happened to a user account in an Account Management event
 * (Event IDs 4720, 4722, 4723, 4725, 4726, 4740).
 */
public enum AccountAction {
    CREATED,
    ENABLED,
    DISABLED,
    DELETED,
    PASSWORD_CHANGED,
    LOCKED
}
