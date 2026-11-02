package com.siem;

import com.siem.exception.*;
import com.siem.util.DateUtil;

/**
 * ExceptionDemo - demonstrates how our custom exception hierarchy is used
 * in practice: throwing specific exceptions, catching specific exceptions,
 * and catching multiple different exception types through their common
 * abstract base class (SiemException) - which is POLYMORPHISM applied to
 * exception handling, not just to normal objects.
 */
public class ExceptionDemo {
    public static void main(String[] args) {

        System.out.println("===== Test 1: Catching a SPECIFIC exception type =====");
        try {
            throw new MissingFileException("C:\\logs\\security_export.csv");
        } catch (MissingFileException e) {
            System.out.println("Caught MissingFileException: " + e.getMessage());
            System.out.println("The missing path was: " + e.getFilePath());
        }

        System.out.println();
        System.out.println("===== Test 2: Catching an InvalidDateFormatException from DateUtil =====");
        try {
            DateUtil.parseWindowsTimestamp("not-a-real-date");
        } catch (InvalidDateFormatException e) {
            System.out.println("Caught InvalidDateFormatException: " + e.getMessage());
        }

        System.out.println();
        System.out.println("===== Test 3: Catching several DIFFERENT exception types through their common parent (SiemException) =====");
        // simulateImportCheck() can throw any ONE of three different
        // exception subtypes depending on the simulated scenario, but we
        // only need ONE catch block below because we catch by the
        // abstract base type. This is the same idea as
        // "SecurityEvent event : events" in ModelDemo - a single reference
        // type (SiemException) can refer to objects of several different
        // subclasses, and the real type is only known at runtime.
        String[] scenarios = {"missing", "empty", "wrong_extension", "valid"};
        for (String scenario : scenarios) {
            try {
                simulateImportCheck(scenario);
                System.out.println("[" + scenario + "] -> valid, ready to import.");
            } catch (SiemException e) {
                // 'e' is declared as the ABSTRACT base type SiemException,
                // but e.getClass().getSimpleName() proves the REAL object
                // is one of the specific subclasses, decided at runtime.
                System.out.println("[" + scenario + "] -> rejected ("
                        + e.getClass().getSimpleName() + "): " + e.getMessage());
            }
        }
    }

    /**
     * Simulates the kind of validation the future Import Module will
     * perform, throwing the matching specific exception for each scenario.
     * This lets us demonstrate the exception hierarchy without depending
     * on real files existing on disk.
     */
    private static void simulateImportCheck(String scenario)
            throws MissingFileException, EmptyFileException, InvalidFileFormatException {
        switch (scenario) {
            case "missing" -> throw new MissingFileException("security_export.csv");
            case "empty" -> throw new EmptyFileException("security_export.csv");
            case "wrong_extension" -> throw new InvalidFileFormatException("security_export.pdf", "csv", "xml");
            case "valid" -> { /* no exception - file passes all checks */ }
            default -> throw new IllegalArgumentException("Unknown test scenario: " + scenario);
        }
    }
}
