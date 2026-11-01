package com.siem.parser;

import com.siem.exception.*;
import com.siem.model.SecurityEvent;
import com.siem.util.ValidationUtil;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Parses a CSV log export into a List of SecurityEvent objects.
 *
 * <b>Two source formats are supported:</b>
 * <ul>
 *   <li>The tool's own canonical export:
 *     {@code EventID,TimeCreated,Username,ComputerName,EventSource,Level,Message,IPAddress,LogonType,AuthPackage,TargetAccount,Privileges}</li>
 *   <li>A raw Windows Event Viewer Security-log export:
 *     {@code TimeCreated,Id,LevelDisplayName,ProviderName,MachineName,Message}</li>
 * </ul>
 * Event Viewer's export only has six columns, but the account name, source IP,
 * logon type, target account and privileges are all embedded inside the free-text
 * {@code Message} field (which may span multiple lines). Those fields are extracted
 * from the message with small regexes; anything that cannot be extracted is left
 * blank so the row is still imported rather than discarded.
 *
 * RESILIENCE: real-world exported log files (especially from PowerShell)
 * often contain a stray malformed row - a blank trailing line, a missing
 * timestamp, a corrupted field, etc. Failing the ENTIRE import because of
 * ONE bad row would make the tool nearly unusable on real data. Instead,
 * each row is parsed inside its own try-catch: a bad row is skipped and
 * recorded (see getSkippedRows()), and parsing continues with the rest of
 * the file. This is "graceful degradation" - a real SIEM tool should never
 * lose an entire log file over a single messy line.
 */
public class CsvLogParser implements LogParser {

    /** The tool's own canonical export header (12 columns). */
    private static final String[] CANONICAL_HEADER = {
            "EventID", "TimeCreated", "Username", "ComputerName", "EventSource", "Level",
            "Message", "IPAddress", "LogonType", "AuthPackage", "TargetAccount", "Privileges"
    };
    /** Windows Event Viewer Security-log export header (the six real columns). */
    private static final String[] EVENTVIEWER_HEADER =
            {"TimeCreated", "Id", "LevelDisplayName", "ProviderName", "MachineName", "Message"};
    /**
     * Event Viewer's "Save All Events As..." GUI export uses a different
     * five-column layout with the event body embedded in the lines that
     * follow each header row (no Message column of its own):
     * {@code Level,Date and Time,Source,Event ID,Task Category}
     */
    private static final String[] GUI_HEADER =
            {"Level", "Date and Time", "Source", "Event ID", "Task Category", "Message"};

    private final List<String> skippedRows = new ArrayList<>();

    /** Matches e.g. {@code Account Name:\s*ANOM$} inside a message body. */
    private static final Pattern ACCOUNT_NAME = Pattern.compile("Account Name:\\s*(\\S+)");
    /** Matches e.g. {@code Target Account Name:\s*Pritom Sen} inside a message body. */
    private static final Pattern TARGET_ACCOUNT = Pattern.compile("Target Account Name:\\s*(\\S+)");
    /** Matches e.g. {@code Source Network Address:\s*10.10.10.5} inside a message body. */
    private static final Pattern SOURCE_IP = Pattern.compile("Source Network Address:\\s*([0-9]+(?:\\.[0-9]+){3})");
    /** Matches e.g. {@code Logon Type:\s*5} inside a message body. */
    private static final Pattern LOGON_TYPE = Pattern.compile("Logon Type:\\s*(\\d+)");
    /** Matches the privilege list block inside a 4672 message body. */
    private static final Pattern PRIVILEGES_BLOCK = Pattern.compile(
            "^Privileges:[ \\t]*(.*)", Pattern.MULTILINE);

    /**
     * Extracts the semicolon-separated privilege list from a 4672 (privilege
     * assignment) message body, e.g. {@code SeAssignPrimaryTokenPrivilege;
     * SeTcbPrivilege}. Returns "" when no privilege block is present.
     *
     * Event Viewer formats this block two ways:
     * <pre>
     * Privileges:\t\tSeAssignPrimaryTokenPrivilege
     * \t\t\tSeTcbPrivilege
     * ...
     * </pre>
     * or
     * <pre>
     * Privileges:
     * \t\tSeAssignPrimaryTokenPrivilege
     * \t\t\tSeTcbPrivilege
     * ...
     * </pre>
     * i.e. the first privilege may sit on the same line as "Privileges:" or on
     * the next line, and every privilege is indented with tabs/spaces. Each
     * privilege name starts with "Se", so the block ends at the first line
     * that is blank or does not start with "Se".
     */
    private static String extractPrivileges(String text) {
        if (text == null) {
            return "";
        }
        int idx = text.indexOf("Privileges:");
        if (idx < 0) {
            return "";
        }
        String rest = text.substring(idx + "Privileges:".length());

        List<String> privs = new ArrayList<>();
        boolean foundPrivilege = false;
        for (String line : rest.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                if (foundPrivilege) {
                    break; // blank line after the list = end of block
                }
                continue; // skip blank lines before the first privilege
            }
            if (trimmed.startsWith("Se")) {
                privs.add(trimmed);
                foundPrivilege = true;
            } else if (foundPrivilege) {
                break; // a non-privilege line after the list = end of block
            }
            // Lines before the first privilege that are not "Se..." are
            // ignored - they are just more of the message body.
        }
        return String.join(";", privs);
    }

    @Override
    public List<SecurityEvent> parse(File file)
            throws MissingFileException, EmptyFileException, InvalidFileFormatException, LogParsingException {

        skippedRows.clear();

        if (!file.exists()) {
            throw new MissingFileException(file.getPath());
        }
        if (!ValidationUtil.isValidFile(file)) {
            throw new EmptyFileException(file.getPath());
        }
        if (!ValidationUtil.hasValidExtension(file.getName(), "csv")) {
            throw new InvalidFileFormatException(file.getPath(), "csv");
        }

        List<SecurityEvent> events = new ArrayList<>();

        // Peek at the header row to decide which schema this file uses.
        // Event Viewer's export has only six columns and buries the account
        // name, IP, logon type, target account and privileges inside the
        // free-text Message field. The tool's own export has all twelve
        // columns as separate fields.
        boolean isEventViewer = false;
        boolean isGuiExport = false;
        String[] header = new String[0];
        try {
            header = readHeader(file);
            isEventViewer = header.length <= 6
                    && contains(header, "TimeCreated")
                    && contains(header, "Id")
                    && contains(header, "Message");
            // Event Viewer's "Save All Events As..." GUI export uses a
            // different five-column layout with the event body embedded in
            // the lines that follow each header row.
            isGuiExport = header.length <= 6
                    && contains(header, "Event ID")
                    && contains(header, "Date and Time");
        } catch (IOException ex) {
            // If header peek fails, fall through to default CSVParser below which will report the I/O error.
        }

        try (Reader reader = openBomAwareReader(file);
             CSVParser csvParser = new CSVParser(reader, CSVFormat.DEFAULT.builder()
                     .setHeader(isGuiExport ? GUI_HEADER
                             : isEventViewer ? EVENTVIEWER_HEADER : CANONICAL_HEADER)
                     .setSkipHeaderRecord(true)
                     .setRecordSeparator("\n")
                     .setIgnoreSurroundingSpaces(true)
                     .setTrim(true)
                     .setIgnoreEmptyLines(false)
                     .build())) {

            for (CSVRecord record : csvParser) {
                long lineNumber = record.getRecordNumber();

                String eventIdRaw = isGuiExport ? getOrEmpty(record, "Event ID")
                        : isEventViewer ? getOrEmpty(record, "Id")
                        : getOrEmpty(record, "EventID");
                if (eventIdRaw.isBlank()) {
                    boolean wholeRowIsBlank = record.stream().allMatch(String::isBlank);
                    if (wholeRowIsBlank) {
                        continue; // genuinely empty trailing line - nothing to report
                    }
                    skippedRows.add("Line " + lineNumber
                            + ": Row has data but no EventID could be read - check that the CSV header"
                            + " row matches the expected column names exactly (a hidden BOM character"
                            + " at the very start of the file is a common cause).");
                    continue;
                }

                try {
                    String message = getOrEmpty(record, "Message");
                    String username, ip, logonType, target, privileges;
                    if (isEventViewer || isGuiExport) {
                        // Both Event Viewer exports bury the account name, IP,
                        // logon type, target account and privileges inside
                        // the free-text Message body.
                        username = extractFirst(message, ACCOUNT_NAME);
                        ip = extractFirst(message, SOURCE_IP);
                        logonType = extractFirst(message, LOGON_TYPE);
                        target = extractFirst(message, TARGET_ACCOUNT);
                        if (target.isBlank()) {
                            target = username;
                        }
                        privileges = extractPrivileges(message);
                    } else {
                        // The tool's own export has them as separate columns.
                        username = getOrEmpty(record, "Username");
                        ip = getOrEmpty(record, "IPAddress");
                        logonType = getOrEmpty(record, "LogonType");
                        target = getOrEmpty(record, "TargetAccount");
                        privileges = getOrEmpty(record, "Privileges");
                    }

                    SecurityEvent event = EventFactory.createEvent(
                            (int) lineNumber,
                            eventIdRaw,
                            isGuiExport ? getOrEmpty(record, "Date and Time") : getOrEmpty(record, "TimeCreated"),
                            username,
                            isGuiExport ? getOrEmpty(record, "Source") : isEventViewer ? getOrEmpty(record, "MachineName") : getOrEmpty(record, "ComputerName"),
                            isGuiExport ? getOrEmpty(record, "Source") : isEventViewer ? getOrEmpty(record, "ProviderName") : getOrEmpty(record, "EventSource"),
                            isGuiExport ? getOrEmpty(record, "Level") : isEventViewer ? getOrEmpty(record, "LevelDisplayName") : getOrEmpty(record, "Level"),
                            message,
                            ip,
                            logonType,
                            getOrEmpty(record, "AuthPackage"),
                            target,
                            privileges
                    );
                    events.add(event);
                } catch (LogParsingException | InvalidDateFormatException ex) {
                    // This ONE row is bad - record why, then move on to the
                    // next row instead of aborting the whole file.
                    skippedRows.add("Line " + lineNumber + ": " + ex.getMessage());
                }
            }

        } catch (IOException ex) {
            throw new IllegalStateException("I/O error while reading file: " + ex.getMessage(), ex);
        }

        if (events.isEmpty()) {
            if (skippedRows.isEmpty()) {
                throw new EmptyFileException(file.getPath());
            }
            String sample = String.join("\n", skippedRows.subList(0, Math.min(5, skippedRows.size())));
            throw new LogParsingException(0, file.getName(),
                    "All " + skippedRows.size() + " row(s) in this file failed to parse. Sample errors:\n" + sample);
        }

        return events;
    }

    @Override
    public List<String> getSkippedRows() {
        return skippedRows;
    }

    /**
     * Returns the first regex match group from the message, or "" if none matches.
     */
    private static String extractFirst(String text, Pattern pattern) {
        if (text == null) {
            return "";
        }
        java.util.regex.Matcher m = pattern.matcher(text);
        return m.find() ? m.group(1).trim() : "";
    }

    private Reader openBomAwareReader(File file) throws IOException {
        InputStream in = new FileInputStream(file);
        byte[] bom = new byte[3];
        int read = in.read(bom);
        boolean hasUtf8Bom = read == 3
                && (bom[0] & 0xFF) == 0xEF
                && (bom[1] & 0xFF) == 0xBB
                && (bom[2] & 0xFF) == 0xBF;

        if (!hasUtf8Bom) {
            // No BOM found - close this stream and start over from the beginning.
            in.close();
            in = new FileInputStream(file);
        }
        // If a BOM WAS found, 'in' has already advanced past those 3 bytes,
        // so reading continues right after them.

        return new InputStreamReader(in, StandardCharsets.UTF_8);
    }

    /** Safely reads a CSV column, returning an empty string if the column is missing for this row. */
    private String getOrEmpty(CSVRecord record, String column) {
        try {
            return record.isMapped(column) ? record.get(column) : "";
        } catch (IllegalArgumentException ex) {
            return "";
        }
    }

    /**
     * Reads the first line of the file (the CSV header row) so the parser
     * can decide which schema the file uses before opening the full parser.
     * The BOM is stripped first, otherwise it would corrupt the first column
     * name and make the schema check fail.
     */
    private String[] readHeader(File file) throws IOException {
        InputStream in = new FileInputStream(file);
        byte[] bom = new byte[3];
        int read = in.read(bom);
        if (!(read == 3 && (bom[0] & 0xFF) == 0xEF && (bom[1] & 0xFF) == 0xBB && (bom[2] & 0xFF) == 0xBF)) {
            in.close();
            in = new FileInputStream(file);
        }
        try (BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line = br.readLine();
            if (line == null || line.isBlank()) return new String[0];
            return parseCsvLine(line).toArray(new String[0]);
        }
    }

    private static boolean contains(String[] header, String name) {
        for (String h : header) if (h.trim().equalsIgnoreCase(name)) return true;
        return false;
    }

    // Maps columns by name regardless of order, handling Event Viewer variants.
    private static int getColumnIndex(String[] header, String... names) {
        for (String name : names) {
            for (int i = 0; i < header.length; i++) {
                if (header[i].trim().equalsIgnoreCase(name)) return i;
            }
        }
        return -1;
    }

    /** Minimal CSV line parser: handles quoted fields and "" escapes. */
    private static List<String> parseCsvLine(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inQuotes) {
                if (c == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        sb.append('"');
                        i++;
                    } else {
                        inQuotes = false;
                    }
                } else {
                    sb.append(c);
                }
            } else {
                if (c == '"') {
                    inQuotes = true;
                } else if (c == ',') {
                    fields.add(sb.toString());
                    sb.setLength(0);
                } else {
                    sb.append(c);
                }
            }
        }
        fields.add(sb.toString());
        return fields;
    }
}
