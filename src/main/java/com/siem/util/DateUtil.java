package com.siem.util;

import com.siem.exception.InvalidDateFormatException;

import java.time.DayOfWeek;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.util.List;
import java.util.Locale;

/**
 * DateUtil is a "Utility Class" - no object needs to be created from it,
 * every method is static, so it can be called directly as DateUtil.methodName(...).
 *
 * The class is marked 'final' - this means no other class can extend
 * (inherit from) it. Since this is just a collection of static helper
 * methods, inheritance doesn't make sense here - so we let the compiler
 * enforce that.
 */
public final class DateUtil {

    // Windows Event Log exports usually come in one of these formats.
    // We try each format one by one until one of them matches.
    //
    // Event Viewer's default CSV export drops the seconds ("10/29/2026 18:00"),
    // so the minute-precision variants are listed first - they match a wider
    // range of real-world exports and never accidentally match a value that
    // has seconds (a shorter pattern always wins for a given input).
    //
    // IMPORTANT: Locale.ENGLISH is specified explicitly for every formatter.
    // Without this, DateTimeFormatter uses the operating system's default
    // locale, and if that locale isn't English, text like "AM"/"PM" will
    // not match the literal English text in the log file, causing a
    // DateTimeParseException even though the pattern looks correct.
    //
    // NOTE: Windows' own regional settings can change which character .NET
    // uses as the date separator (some regions use '-' instead of '/'), so
    // both variants are supported here.
    private static final List<DateTimeFormatter> SUPPORTED_FORMATS = List.of(
            DateTimeFormatter.ofPattern("M/d/yyyy h:mm:ss a", Locale.ENGLISH), // e.g. 7/10/2026 2:15:00 AM
            DateTimeFormatter.ofPattern("M/d/yyyy h:mm a", Locale.ENGLISH),     // e.g. 7/10/2026 2:15 AM
            DateTimeFormatter.ofPattern("M/d/yyyy H:mm:ss", Locale.ENGLISH),    // e.g. 7/10/2026 14:15:00
            DateTimeFormatter.ofPattern("M/d/yyyy H:mm", Locale.ENGLISH),       // e.g. 7/10/2026 14:15
            DateTimeFormatter.ofPattern("M-d-yyyy h:mm:ss a", Locale.ENGLISH), // e.g. 7-10-2026 2:15:00 AM
            // Indian/Bangladeshi format: dd-MM-yyyy HH:mm:ss (e.g. 15-07-2026 11:05:08)
            DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss", Locale.ENGLISH),
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.ENGLISH), // e.g. 2026-07-10 02:15:00
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm", Locale.ENGLISH),    // e.g. 2026-07-10 02:15
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss", Locale.ENGLISH), // e.g. 2026-07-10T02:15:00 (XML export format)
            // ISO 8601 with optional fractional seconds and a trailing Z
            // (or +/-HH:MM offset) - this is the format Windows writes into
            // real event-log XML exports, e.g. 2026-10-31T01:21:35.6223342Z
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss[.SSSSSSSSS][.SSSSSSSS][.SSSSSSS][.SSSSSS][.SSSSS][.SSSS][.SSS]", Locale.ENGLISH),
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss[.SSSSSSSSS][.SSSSSSSS][.SSSSSSS][.SSSSSS][.SSSSS][.SSSS][.SSS]X", Locale.ENGLISH)
    );

    /**
     * Private constructor - deliberately prevents any external code from
     * calling 'new DateUtil()'. There is no need to create an object of
     * this class, because it has no state (no instance fields).
     */
    private DateUtil() {
        // Left empty - this should never be called, so there's nothing to do.
    }

    /**
     * Converts a raw Windows log timestamp string into a Java LocalDateTime
     * object. Tries several possible formats.
     *
     * @param raw   the timestamp text taken directly from the log file
     * @return      a LocalDateTime if parsing succeeds
     * @throws InvalidDateFormatException if the value is empty, or if none
     *         of the supported formats match. This is a CHECKED exception
     *         (it extends SiemException, which extends Exception), so any
     *         code calling this method is forced by the compiler to either
     *         catch it or declare it with 'throws'. This makes sense here:
     *         a single bad timestamp in an otherwise valid log file is a
     *         normal, recoverable situation - not a reason to crash - so we
     *         want the caller (the future Parsing Layer) to be reminded to
     *         handle it explicitly, for example by skipping that one line
     *         and continuing with the rest of the file.
     */
    public static LocalDateTime parseWindowsTimestamp(String raw) throws InvalidDateFormatException {
        if (raw == null || raw.isBlank()) {
            throw new InvalidDateFormatException(raw, null);
        }

        String trimmed = raw.trim();

        // ISO 8601 timestamps from real event-log XML exports carry a
        // trailing timezone designator ("Z" or "+HH:MM"). LocalDateTime
        // cannot parse those, so strip the suffix before trying the
        // formatters - the local date/time is what we actually store.
        String candidate = trimmed;
        if (candidate.endsWith("Z") || candidate.endsWith("z")) {
            candidate = candidate.substring(0, candidate.length() - 1);
        } else {
            int plus = candidate.lastIndexOf('+');
            int minus = candidate.lastIndexOf('-');
            int tzMarker = Math.max(plus, minus);
            // Only treat a trailing sign as a timezone if it comes after the
            // seconds (i.e. after a "T"), otherwise a date like "7-10-2026"
            // would be truncated. The ISO formatters always use 'T'.
            int t = candidate.indexOf('T');
            if (tzMarker > t && tzMarker >= candidate.length() - 6) {
                candidate = candidate.substring(0, tzMarker);
            }
        }

        // Each format is tried one by one.
        for (DateTimeFormatter formatter : SUPPORTED_FORMATS) {
            try {
                return LocalDateTime.parse(candidate, formatter);
            } catch (DateTimeParseException ex) {
                // This format didn't match, try the next one.
                // We catch the exception here and silently move on to the
                // next attempt - this is called a "silent retry pattern".
                // If ALL formats fail, we still throw a clear exception below,
                // so staying silent here is safe.
            }
        }

        // None of the formats matched. We wrap the situation in our own
        // custom checked exception instead of leaking Java's built-in
        // DateTimeParseException to the rest of the application. This way,
        // every other layer only ever needs to know about OUR exception
        // types (from com.siem.exception), not Java's internal ones.
        throw new InvalidDateFormatException(raw, null);
    }

    /**
     * Checks whether a login happened outside normal working hours
     * (9 AM - 6 PM). This will be used later in the ThreatDetector's
     * "Suspicious Login Time" rule.
     */
    public static boolean isOutsideWorkingHours(LocalDateTime dateTime) {
        int hour = dateTime.getHour();
        return hour < 9 || hour >= 18; // "outside" if before 9 AM or at/after 6 PM
    }

    /**
     * Checks whether the given date falls on a Saturday or Sunday.
     */
    public static boolean isWeekend(LocalDateTime dateTime) {
        DayOfWeek day = dateTime.getDayOfWeek();
        return day == DayOfWeek.SATURDAY || day == DayOfWeek.SUNDAY;
    }
}
