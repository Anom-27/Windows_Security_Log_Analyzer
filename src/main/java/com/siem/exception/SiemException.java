package com.siem.exception;

/**
 * SiemException is the abstract base class for every custom exception in
 * this project.
 *
 * WHY ABSTRACT?
 * Just like SecurityEvent in the model layer, we never want to throw a
 * plain "SiemException" directly - it should always be one of the specific
 * subtypes (MissingFileException, InvalidDateFormatException, etc.) so
 * that the code catching it knows exactly what went wrong.
 *
 * WHY EXTEND Exception (NOT RuntimeException)?
 * This makes SiemException and all its subclasses CHECKED exceptions.
 * A checked exception forces any method that might throw it to either
 * catch it or declare it with 'throws' in its own signature. We want this
 * here because these errors (a missing file, a bad date format, etc.) are
 * recoverable - the program can ask the user to choose a different file
 * instead of crashing. Checked exceptions make sure this handling is never
 * accidentally forgotten, because the compiler itself enforces it.
 */
public abstract class SiemException extends Exception {

    protected SiemException(String message) {
        super(message);
    }

    protected SiemException(String message, Throwable cause) {
        super(message, cause);
    }
}
