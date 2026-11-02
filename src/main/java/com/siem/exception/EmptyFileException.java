package com.siem.exception;

/**
 * Thrown when the imported file exists but contains no data (0 bytes,
 * or has a header row but no actual log entries).
 */
public class EmptyFileException extends SiemException {

    private final String filePath;

    public EmptyFileException(String filePath) {
        super("File is empty: " + filePath);
        this.filePath = filePath;
    }

    public String getFilePath() {
        return filePath;
    }
}
