package com.siem.util;

import java.io.File;

/**
 * ValidationUtil - a utility class for checking whether an imported file
 * or other input is valid.
 *
 * These methods return true/false (they do not throw exceptions) - because
 * "asking whether a file is valid" and "stopping the program if it isn't"
 * are two separate responsibilities. What the caller (e.g. ImportModule)
 * does with the result (show an error, ask for another file, etc.) is not
 * this class's concern. This follows the Single Responsibility Principle (SOLID).
 */
public final class ValidationUtil {

    private ValidationUtil() {
        // Utility class - object creation not allowed.
    }

    /**
     * Checks that the file actually exists, is a real file (not a folder),
     * and is not empty (not 0 bytes).
     */
    public static boolean isValidFile(File file) {
        if (file == null) {
            return false;
        }
        return file.exists() && file.isFile() && file.length() > 0;
    }

    /**
     * Checks, case-insensitively, whether a filename's extension matches
     * one of the given allowed extensions.
     *
     * Example: hasValidExtension("security_log.CSV", "csv", "xml") -> true
     *
     * Varargs ('...') is used so that any number of extensions can be
     * passed when calling this method: hasValidExtension(name, "csv") or
     * hasValidExtension(name, "csv", "xml", "evtx") are both valid calls.
     */
    public static boolean hasValidExtension(String filename, String... allowedExtensions) {
        if (filename == null || filename.isBlank() || allowedExtensions == null) {
            return false;
        }

        int lastDot = filename.lastIndexOf('.');
        if (lastDot == -1 || lastDot == filename.length() - 1) {
            return false; // no extension at all
        }

        String actualExtension = filename.substring(lastDot + 1).toLowerCase();

        for (String allowed : allowedExtensions) {
            if (actualExtension.equals(allowed.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks that a string is not null and not made up of only whitespace.
     * Small as it looks, this will be reused throughout the project
     * (username validation, search input validation, etc.), so writing it
     * once here is good practice - it avoids code duplication.
     */
    public static boolean isNotEmpty(String value) {
        return value != null && !value.isBlank();
    }
}
