package com.siem.parser;

import com.siem.exception.*;
import com.siem.model.SecurityEvent;

import java.io.File;
import java.util.List;

/**
 * Contract for anything that can turn a log file into a list of
 * SecurityEvent objects. CsvLogParser and XmlLogParser both implement this
 * the same way from the outside (parse a File, get back events), but
 * internally use completely different logic - this is ABSTRACTION and
 * POLYMORPHISM applied to file parsing.
 *
 * DESIGN NOTE: parse() no longer aborts the ENTIRE import just because one
 * row/element in an otherwise valid file is malformed (e.g. a blank
 * timestamp). Instead, a bad row is skipped and recorded, and the rest of
 * the file is still imported. getSkippedRows() lets the caller (the UI)
 * report how many rows were skipped and why, instead of losing an entire
 * real-world log file over a single messy line.
 */
public interface LogParser {
    List<SecurityEvent> parse(File file)
            throws MissingFileException, EmptyFileException, InvalidFileFormatException, LogParsingException;

    /** Returns a description of every row/element skipped during the most recent parse() call. */
    List<String> getSkippedRows();
}

