package com.siem.exception;

/**
 * Thrown when the user tries to import a log file that does not exist at
 * the given path.
 */
public class MissingFileException extends SiemException {

    private final String filePath;

    public MissingFileException(String filePath) {
        super("File not found: " + filePath);
        this.filePath = filePath;
    }

    public String getFilePath() {
        return filePath;
    }
}
