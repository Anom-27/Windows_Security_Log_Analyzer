# Windows Security Log Analysis Tool

A desktop Java Swing application that analyzes Windows Security Event Logs (exported as CSV or XML), detects suspicious activity using rule-based threat detection, and generates professional security investigation reports.

---

## Features

- **Dual Format Parsing** — Imports both CSV and XML Windows Security log exports
- **8 Threat Detection Rules** — Brute Force, Account Lockout, Privilege Escalation, Suspicious Login Time, New User, Deleted User, Password Change, and Multiple Failed Login detection
- **Professional Reports** — Summary, Authentication, Threat, and User Activity reports
- **Swing GUI** — Clean, responsive desktop interface with login, dashboard, search, statistics, and threat detection dialogs
- **Layered Architecture** — Model-DAO-Controller design with clear separation of concerns

---

## Requirements

- **Java JDK 17** or later
- **Maven** (bundled with IntelliJ IDEA, or installed separately)
- **IntelliJ IDEA** (or any IDE that supports Maven)

---

## How to Run

1. Open this folder as a Maven project in IntelliJ IDEA.
2. Let Maven download dependencies (`commons-csv`, `junit`).
3. Open `src/main/java/com/siem/Main.java`.
4. Click the green Run button next to `public static void main`.
5. Log in with one of the demo accounts:

   | Username | Password | Role |
   |----------|----------|------|
   | `admin` | `admin123` | ADMIN |
   | `analyst` | `analyst123` | ANALYST |

6. Click **Import** and select a file from the `sample-data/` folder (`sample_security_log.csv` or `sample_security_log.xml`) to try the tool immediately with test data.

---

## Supported Log Formats

### CSV Formats
- **Tool's canonical export** — 12-column format with separate fields
- **Windows Event Viewer export** — 6-column format with embedded message fields
- **Event Viewer GUI export** — 5-column format with body in subsequent lines
- **Regional date formats** — Supports `M/d/yyyy`, `dd-MM-yyyy`, `yyyy-MM-dd`, and ISO 8601

### XML Formats
- **Tool's simple format** — `<Event><EventID>`, `<TimeCreated>`, etc.
- **Real Windows Event Log XML** — Full schema with `<System>`, `<EventData>`, and `<RenderingInfo>` sections

---

## Using Your Own Windows Security Log

Windows' native log export format is complex. To generate a CSV file this tool understands directly from your own PC's Security log:

1. Open PowerShell **as Administrator**.
2. Run: `sample-data\Export-SecurityLog.ps1 -MaxEvents 500`
3. Import the resulting CSV file using the Import button.

---

## Recognized Event IDs

| Event ID | Meaning |
|----------|---------|
| 4624 | Successful Login |
| 4625 | Failed Login |
| 4634 | Logoff |
| 4648 | Logon using Explicit Credentials |
| 4720 | User Account Created |
| 4722 | User Account Enabled |
| 4723 | Password Change Attempt |
| 4725 | User Account Disabled |
| 4726 | User Account Deleted |
| 4740 | Account Locked |
| 4672 | Special Privileges Assigned |

---

## Project Structure (Layered Architecture)

```
com.siem
├── model       - SecurityEvent hierarchy, User, Alert, enums
├── exception   - Custom checked exceptions (SiemException hierarchy)
├── util        - DateUtil, RegexUtil, ValidationUtil
├── parser      - CsvLogParser, XmlLogParser, EventFactory
├── repository  - EventRepository (in-memory storage + indices)
├── analyzer    - Per-event analysis (Analyzer interface)
├── detector    - 8 threat detection rules + ThreatDetectionEngine
├── service     - AuthenticationService, SearchService, StatisticsService
├── report      - ReportService (Summary/Auth/Threat/User Activity reports)
├── ui          - Swing GUI (LoginWindow, DashboardWindow, dialogs)
└── Main        - application entry point
```

---

## Threat Detection Rules Implemented

1. **Brute Force Detection** — Repeated failed logins (4625) from the same IP address
2. **Account Lockout Detection** — Accounts that became locked (Event ID 4740)
3. **Privilege Escalation Detection** — Administrative privilege assignments (4672)
4. **Suspicious Login Time Detection** — Successful logins (4624) outside working hours
5. **New User Detection** — Newly created accounts (4720)
6. **Deleted User Detection** — Removed accounts (4726)
7. **Password Change Detection** — Password change/reset attempts (4723)
8. **Multiple Failed Login Detection** — Per-user failed login count threshold

---

## OOP Concepts Applied

| Concept | Implementation |
|---------|---------------|
| **Encapsulation** | Private fields with getters/setters |
| **Abstraction** | Interfaces hide implementation details |
| **Polymorphism** | `List<ThreatDetector>` pattern |
| **Inheritance** | `SecurityEvent` subclasses |
| **Layering** | Model-DAO-Controller pattern |

---

## Demo Accounts

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | ADMIN |
| `analyst` | `analyst123` | ANALYST |

---

## Authors

- **Pritom Kumar Sen Anom** — IT 24061
- **Mohitul Islam** — IT 24065
- Department of Information and Communication Technology, MBSTU

## Supervisor

- **Dr. Sajjad Waheed** — Professor, Dept. of ICT, MBSTU

---

## Source Code

[github.com/Anom-27/Windows_Security_Log_Analyzer](https://github.com/Anom-27/Windows_Security_Log_Analyzer)

---

## References

1. Apache Commons CSV — [https://commons.apache.org/proper/commons-csv/](https://commons.apache.org/proper/commons-csv/)
2. Java Swing Documentation — [https://docs.oracle.com/javase/tutorial/uiswing/](https://docs.oracle.com/javase/tutorial/uiswing/)
3. Windows Event Log XML Schema — Microsoft Docs