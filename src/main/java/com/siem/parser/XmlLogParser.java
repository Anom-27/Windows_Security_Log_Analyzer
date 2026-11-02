package com.siem.parser;

import com.siem.exception.*;
import com.siem.model.SecurityEvent;
import com.siem.util.ValidationUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses an XML log export into a List of SecurityEvent objects.
 *
 * Expected XML structure (tool's simple format):
 * <pre>
 * &lt;Events&gt;
 *   &lt;Event&gt;
 *     &lt;EventID&gt;4625&lt;/EventID&gt;
 *     &lt;TimeCreated&gt;7/10/2026 2:15:00 AM&lt;/TimeCreated&gt;
 *     ...
 *   &lt;/Event&gt;
 * &lt;/Events&gt;
 * </pre>
 *
 * Real Windows Event Log XML is also supported (Event Viewer export):
 * - <Event><System><TimeCreated SystemTime='2026-10-31T06:14:40.2783005Z'/></System>
 * - Fields live under <System>, <EventData><Data Name='...'/>, and <RenderingInfo>.
 * The parser falls back through these locations so both formats work.
 *
 * RESILIENCE: just like CsvLogParser, one malformed &lt;Event&gt; element
 * does not abort the entire import - it is skipped and recorded (see
 * getSkippedRows()), and parsing continues with the rest of the file.
 */
public class XmlLogParser implements LogParser {

    private final List<String> skippedRows = new ArrayList<>();

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
        if (!ValidationUtil.hasValidExtension(file.getName(), "xml")) {
            throw new InvalidFileFormatException(file.getPath(), "xml");
        }

        List<SecurityEvent> events = new ArrayList<>();

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(file);
            document.getDocumentElement().normalize();

            NodeList eventNodes = document.getElementsByTagName("Event");

            for (int i = 0; i < eventNodes.getLength(); i++) {
                Element eventElement = (Element) eventNodes.item(i);
                int lineNumber = i + 1;

                try {
                    SecurityEvent event = EventFactory.createEvent(
                            lineNumber,
                            getEventId(eventElement),
                            getTimeCreated(eventElement),
                            getUserName(eventElement),
                            getComputerName(eventElement),
                            getEventSource(eventElement),
                            getLevel(eventElement),
                            getMessage(eventElement),
                            getIpAddress(eventElement),
                            getLogonType(eventElement),
                            getAuthPackage(eventElement),
                            getTargetAccount(eventElement),
                            getPrivileges(eventElement)
                    );
                    events.add(event);
                } catch (LogParsingException | InvalidDateFormatException ex) {
                    skippedRows.add("Event #" + lineNumber + ": " + ex.getMessage());
                }
            }

        } catch (Exception ex) {
            throw new IllegalStateException("XML parsing error: " + ex.getMessage(), ex);
        }

        if (events.isEmpty()) {
            if (skippedRows.isEmpty()) {
                throw new EmptyFileException(file.getPath());
            }
            String sample = String.join("\n", skippedRows.subList(0, Math.min(5, skippedRows.size())));
            throw new LogParsingException(0, file.getName(),
                    "All " + skippedRows.size() + " event(s) in this file failed to parse. Sample errors:\n" + sample);
        }

        return events;
    }

    @Override
    public List<String> getSkippedRows() {
        return skippedRows;
    }

    private String getTagValue(Element parent, String tagName) {
        NodeList nodes = parent.getElementsByTagName(tagName);
        if (nodes.getLength() == 0) {
            return "";
        }
        Element el = (Element) nodes.item(0);
        String text = el.getTextContent();
        if (text != null && !text.trim().isEmpty()) {
            return text.trim();
        }
        // TimeCreated in real Windows XML stores the timestamp in SystemTime attribute
        if ("TimeCreated".equals(tagName)) {
            String sys = el.getAttribute("SystemTime");
            if (sys != null && !sys.isBlank()) return sys.trim();
        }
        return "";
    }

    private String getDataValue(Element event, String dataName) {
        NodeList datas = event.getElementsByTagName("Data");
        for (int i = 0; i < datas.getLength(); i++) {
            Element d = (Element) datas.item(i);
            if (dataName.equalsIgnoreCase(d.getAttribute("Name"))) {
                String v = d.getTextContent();
                if (v != null) return v.trim();
            }
        }
        return "";
    }

    private String getEventId(Element event) {
        String v = getTagValue(event, "EventID");
        if (!v.isEmpty()) return v;
        return "";
    }

    private String getTimeCreated(Element event) {
        String v = getTagValue(event, "TimeCreated");
        if (!v.isEmpty()) return v;
        // fallback: try System/TimeCreated attribute
        Element sys = getFirstChild(event, "System");
        if (sys != null) {
            NodeList tcs = sys.getElementsByTagName("TimeCreated");
            if (tcs.getLength() > 0) {
                Element tc = (Element) tcs.item(0);
                String sysTime = tc.getAttribute("SystemTime");
                if (sysTime != null && !sysTime.isBlank()) return sysTime.trim();
            }
        }
        return "";
    }

    private String getUserName(Element event) {
        String v = getTagValue(event, "Username");
        if (!v.isEmpty()) return v;
        v = getDataValue(event, "SubjectUserName");
        if (!v.isEmpty()) return v;
        v = getDataValue(event, "TargetUserName");
        if (!v.isEmpty()) return v;
        // fallback: parse from message Account Name
        String msg = getMessage(event);
        if (!msg.isEmpty()) {
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("Account Name:\\s*([\\S]+)").matcher(msg);
            if (m.find()) return m.group(1).trim();
        }
        return "";
    }

    private String getComputerName(Element event) {
        String v = getTagValue(event, "ComputerName");
        if (!v.isEmpty()) return v;
        // System/Computer
        Element sys = getFirstChild(event, "System");
        if (sys != null) {
            v = getTagValue(sys, "Computer");
            if (!v.isEmpty()) return v;
        }
        return "";
    }

    private String getEventSource(Element event) {
        String v = getTagValue(event, "EventSource");
        if (!v.isEmpty()) return v;
        // System/Provider/@Name
        Element sys = getFirstChild(event, "System");
        if (sys != null) {
            NodeList prov = sys.getElementsByTagName("Provider");
            if (prov.getLength() > 0) {
                Element p = (Element) prov.item(0);
                String name = p.getAttribute("Name");
                if (name != null && !name.isBlank()) return name.trim();
            }
        }
        return "";
    }

    private String getLevel(Element event) {
        String v = getTagValue(event, "Level");
        if (!v.isEmpty()) return v;
        // RenderingInfo/Level
        Element ri = getFirstChild(event, "RenderingInfo");
        if (ri != null) {
            v = getTagValue(ri, "Level");
            if (!v.isEmpty()) return v;
        }
        // System/Level numeric mapping
        Element sys = getFirstChild(event, "System");
        if (sys != null) {
            v = getTagValue(sys, "Level");
            if (!v.isEmpty()) {
                try {
                    int lvl = Integer.parseInt(v);
                    return switch (lvl) {
                        case 1 -> "CRITICAL";
                        case 2 -> "ERROR";
                        case 3 -> "WARNING";
                        case 4 -> "INFO";
                        default -> "INFO";
                    };
                } catch (NumberFormatException ignored) {}
            }
        }
        return "INFO";
    }

    private String getMessage(Element event) {
        String v = getTagValue(event, "Message");
        if (!v.isEmpty()) return v;
        Element ri = getFirstChild(event, "RenderingInfo");
        if (ri != null) {
            v = getTagValue(ri, "Message");
            if (!v.isEmpty()) return v;
        }
        return "";
    }

    private String getIpAddress(Element event) {
        String v = getTagValue(event, "IPAddress");
        if (!v.isEmpty()) return v;
        v = getDataValue(event, "IpAddress");
        if (!v.isEmpty()) return v;
        v = getDataValue(event, "SourceNetworkAddress");
        if (!v.isEmpty()) return v;
        return "";
    }

    private String getLogonType(Element event) {
        String v = getTagValue(event, "LogonType");
        if (!v.isEmpty()) return v;
        v = getDataValue(event, "LogonType");
        if (!v.isEmpty()) return v;
        return "";
    }

    private String getAuthPackage(Element event) {
        String v = getTagValue(event, "AuthPackage");
        if (!v.isEmpty()) return v;
        v = getDataValue(event, "AuthPackageName");
        if (!v.isEmpty()) return v;
        return "";
    }

    private String getTargetAccount(Element event) {
        String v = getTagValue(event, "TargetAccount");
        if (!v.isEmpty()) return v;
        v = getDataValue(event, "TargetUserName");
        if (!v.isEmpty()) return v;
        v = getDataValue(event, "TargetAccountName");
        if (!v.isEmpty()) return v;
        return "";
    }

    private String getPrivileges(Element event) {
        String v = getTagValue(event, "Privileges");
        if (!v.isEmpty()) return v;
        // Privileges can be in Data Name='Privileges'
        v = getDataValue(event, "Privileges");
        if (!v.isEmpty()) return v;
        return "";
    }

    private Element getFirstChild(Element parent, String tagName) {
        NodeList nodes = parent.getElementsByTagName(tagName);
        if (nodes.getLength() > 0) return (Element) nodes.item(0);
        return null;
    }
}
