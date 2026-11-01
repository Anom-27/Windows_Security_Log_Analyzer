package com.siem.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RegexUtil - a utility class for extracting and validating information
 * from text using regular expressions.
 */
public final class RegexUtil {

    // Pattern for an IPv4 address: four numbers (0-255 each), separated by dots.
    // Pattern.compile() is done only once (as a static field), not repeatedly -
    // because compiling a regex is a costly operation. If we recompiled it
    // every time the method was called, performance would suffer.
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "\\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}" +
            "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"
    );

    private RegexUtil() {
        // Utility class - object creation not allowed.
    }

    /**
     * Finds the first IPv4 address inside a log message.
     * Returns null if none is found (does not throw an exception, because
     * a missing IP address is not abnormal - many events don't have one).
     *
     * @param text  the text to search for an IP address (e.g. an event's message)
     * @return      the first matching IP address, or null if none found
     */
    public static String extractIpAddress(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }

        Matcher matcher = IPV4_PATTERN.matcher(text);
        if (matcher.find()) {
            return matcher.group(); // return the first match
        }
        return null;
    }

    /**
     * Checks whether a string is genuinely a valid IPv4 address
     * (the whole string must match the address format exactly, not just
     * contain one somewhere inside).
     */
    public static boolean isValidIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return false;
        }
        return IPV4_PATTERN.matcher(ip.trim()).matches();
    }
}
