package com.siem.exception;

/**
 * Thrown when a timestamp string from a log entry cannot be parsed into
 * a valid LocalDateTime using any of the supported formats.
 */
public class InvalidDateFormatException extends SiemException {

    private final String rawValue;

    public InvalidDateFormatException(String rawValue, Throwable cause) {
        super("Could not parse date/time value: '" + rawValue + "'", cause);
        this.rawValue = rawValue;
    }

    public String getRawValue() {
        return rawValue;
    }
}
