package com.siem.exception;

/**
 * Thrown when a specific line/entry inside an otherwise valid log file
 * fails to be parsed into a SecurityEvent object (e.g. a required field
 * is missing, or an Event ID is not recognized).
 *
 * Carrying the line number and the raw line content makes it much easier
 * for the user to go find and fix the problem in the original file,
 * instead of just being told "parsing failed" with no further detail.
 */
public class LogParsingException extends SiemException {

    private final int lineNumber;
    private final String rawLine;

    public LogParsingException(int lineNumber, String rawLine, String reason) {
        super("Failed to parse line " + lineNumber + ": " + reason + " | Raw content: " + rawLine);
        this.lineNumber = lineNumber;
        this.rawLine = rawLine;
    }

    public int getLineNumber() {
        return lineNumber;
    }

    public String getRawLine() {
        return rawLine;
    }
}
