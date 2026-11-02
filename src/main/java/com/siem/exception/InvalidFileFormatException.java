package com.siem.exception;

import java.util.Arrays;

/**
 * Thrown when the imported file's format is not supported (e.g. wrong
 * extension) or its internal structure does not match what a CSV/XML
 * log export is expected to look like.
 */
public class InvalidFileFormatException extends SiemException {

    private final String filePath;
    private final String[] expectedExtensions;

    public InvalidFileFormatException(String filePath, String... expectedExtensions) {
        super("Invalid file format for '" + filePath + "'. Expected one of: "
                + Arrays.toString(expectedExtensions));
        this.filePath = filePath;
        this.expectedExtensions = expectedExtensions;
    }

    public String getFilePath() {
        return filePath;
    }

    public String[] getExpectedExtensions() {
        return expectedExtensions;
    }
}
