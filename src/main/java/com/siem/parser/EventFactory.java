package com.siem.parser;

import com.siem.exception.InvalidDateFormatException;
import com.siem.exception.LogParsingException;
import com.siem.model.*;
import com.siem.util.DateUtil;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * EventFactory decides, based on the Event ID, which SecurityEvent
 * subclass to build (AuthenticationEvent, AccountEvent, PrivilegeEvent,
 * or SystemEvent).
 *
 * This is the "Factory" design pattern: instead of scattering
 * "if eventId == 4624 then new AuthenticationEvent(...)" logic across
 * CsvLogParser AND XmlLogParser separately (duplicated code), a put that
 * decision in ONE place. Both parsers call the same createEvent() method,
 * so if we ever need to recognize a new Event ID, we only change it here.
 *
 * NOTE ON UNKNOWN IDs: every row in a real Windows Security export is
 * imported, not silently dropped. Event IDs that are not one of the
 * recognized categories are wrapped in a SystemEvent, which still carries
 * the timestamp, user, computer and message - so they show up in the
 * table and can be searched, even though they do not have the extra
 * structured fields (logon type, target account, privileges, etc.) that
 * the specialized subclasses add.
 */

/**
 * EventFactory decides, based on the Event ID, which SecurityEvent
 * subclass to build (AuthenticationEvent, AccountEvent, or PrivilegeEvent).
 *
 * This is the "Factory" design pattern: instead of scattering
 * "if eventId == 4624 then new AuthenticationEvent(...)" logic across
 * CsvLogParser AND XmlLogParser separately (duplicated code), we put that
 * decision in ONE place. Both parsers call the same createEvent() method,
 * so if we ever need to recognize a new Event ID, we only change it here.
 */
public final class EventFactory {

    private static final Set<Integer> AUTH_EVENT_IDS = Set.of(4624, 4625, 4634, 4648);
    private static final Set<Integer> ACCOUNT_EVENT_IDS = Set.of(4720, 4722, 4723, 4725, 4726, 4740);
    private static final int PRIVILEGE_EVENT_ID = 4672;
    private static final Set<Integer> SYSTEM_EVENT_IDS = Set.of(4688, 4798, 4799, 4907, 5058, 5059, 5061, 5379);

    private EventFactory() {
        // Utility class - object creation not allowed.
    }

    /**
     * Builds the correct SecurityEvent subclass from raw field values
     * (typically read from a CSV row or an XML <Event> element).
     *
     * @param lineNumber      which row/element this came from (for error messages)
     * @param eventIdRaw      raw Event ID text, e.g. "4625"
     * @param timestampRaw    raw timestamp text, e.g. "7/10/2026 2:15:00 AM"
     * @param username        the username field
     * @param computerName    the computer name field
     * @param eventSource     the event source field
     * @param levelRaw        raw level text, e.g. "WARNING"
     * @param message         the free-text message field
     * @param ipAddress       the IP address field (may be null/empty)
     * @param logonTypeRaw    raw logon type number (used only for auth events)
     * @param authPackage     authentication package name (used only for auth events)
     * @param targetAccount   the account being acted upon (used only for account events)
     * @param privilegesRaw   semicolon-separated privilege names (used only for privilege events)
     */
    public static SecurityEvent createEvent(int lineNumber, String eventIdRaw, String timestampRaw,
                                             String username, String computerName, String eventSource,
                                             String levelRaw, String message, String ipAddress,
                                             String logonTypeRaw, String authPackage,
                                             String targetAccount, String privilegesRaw)
            throws LogParsingException, InvalidDateFormatException {

        int eventId;
        try {
            eventId = Integer.parseInt(eventIdRaw.trim());
        } catch (NumberFormatException | NullPointerException ex) {
            throw new LogParsingException(lineNumber, String.valueOf(eventIdRaw), "Event ID is not a valid number");
        }

        LocalDateTime timestamp = DateUtil.parseWindowsTimestamp(timestampRaw);

        EventLevel level;
        try {
            level = EventLevel.valueOf(levelRaw.trim().toUpperCase());
        } catch (Exception ex) {
            level = EventLevel.INFO; // default gracefully instead of failing the whole line
        }

        String cleanIp = (ipAddress == null || ipAddress.isBlank()) ? null : ipAddress.trim();

        if (AUTH_EVENT_IDS.contains(eventId)) {
            int logonType = parseIntSafely(logonTypeRaw);
            String pkg = (authPackage == null || authPackage.isBlank()) ? "Unknown" : authPackage.trim();
            return new AuthenticationEvent(eventId, timestamp, username, computerName, eventSource,
                    level, message, cleanIp, logonType, pkg);
        }

        if (ACCOUNT_EVENT_IDS.contains(eventId)) {
            AccountAction action = mapAccountAction(eventId);
            String target = (targetAccount == null || targetAccount.isBlank()) ? username : targetAccount.trim();
            return new AccountEvent(eventId, timestamp, username, computerName, eventSource,
                    level, message, cleanIp, target, action);
        }

        if (eventId == PRIVILEGE_EVENT_ID) {
            List<String> privileges = (privilegesRaw == null || privilegesRaw.isBlank())
                    ? List.of()
                    : Arrays.stream(privilegesRaw.split(";")).map(String::trim).toList();
            return new PrivilegeEvent(eventId, timestamp, username, computerName, eventSource,
                    level, message, cleanIp, privileges);
        }

        // Every row in a real Windows Security export is imported, never
        // silently dropped. IDs we do not recognize are wrapped in a
        // SystemEvent - they still carry timestamp, user, computer and
        // message, so they show up in the table and are searchable.
        return new SystemEvent(eventId, timestamp, username, computerName, eventSource,
                level, message, cleanIp);
    }

    private static AccountAction mapAccountAction(int eventId) {
        return switch (eventId) {
            case 4720 -> AccountAction.CREATED;
            case 4722 -> AccountAction.ENABLED;
            case 4723 -> AccountAction.PASSWORD_CHANGED;
            case 4725 -> AccountAction.DISABLED;
            case 4726 -> AccountAction.DELETED;
            case 4740 -> AccountAction.LOCKED;
            default -> throw new IllegalStateException("Unmapped account event ID: " + eventId);
        };
    }

    private static int parseIntSafely(String value) {
        try {
            return Integer.parseInt(value.trim());
        } catch (Exception ex) {
            return 0;
        }
    }
}
