# Windows Security Log Analysis Tool

A desktop Java Swing application that analyzes Windows Security Event Logs
(exported as CSV or XML), detects suspicious activity using rule-based
threat detection, and generates security investigation reports.

## Requirements
- Java JDK 17 or later
- IntelliJ IDEA (or any IDE that supports Maven)
- Maven (bundled with IntelliJ)

## How to Run
1. Open this folder as a Maven project in IntelliJ IDEA.
2. Let Maven download dependencies (`commons-csv`, `junit`).
3. Open `src/main/java/com/siem/Main.java`.
4. Click the green Run button next to `public static void main`.
5. Log in with one of the demo accounts:
   - Username: `admin`    Password: `admin123`   (Role: ADMIN)
   - Username: `analyst`  Password: `analyst123` (Role: ANALYST)
6. Click **Import** and select a file from the `sample-data/` folder
   (`sample_security_log.csv` or `sample_security_log.xml`) to try the tool
   immediately with test data.

## Using Your Own Windows Security Log
Windows' native log export format is complex. To generate a CSV file this
tool understands directly from your own PC's Security log:

1. Open PowerShell **as Administrator**.
2. Run: `sample-data\Export-SecurityLog.ps1 -MaxEvents 500`
3. Import the resulting CSV file using the Import button.

## Recognized Event IDs
| Event ID | Meaning                              |
|----------|---------------------------------------|
| 4624     | Successful Login                      |
| 4625     | Failed Login                          |
| 4634     | Logoff                                |
| 4648     | Logon using Explicit Credentials      |
| 4720     | User Account Created                  |
| 4722     | User Account Enabled                  |
| 4723     | Password Change Attempt               |
| 4725     | User Account Disabled                 |
| 4726     | User Account Deleted                  |
| 4740     | Account Locked                        |
| 4672     | Special Privileges Assigned           |

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
└── Main         - application entry point
```

## Threat Detection Rules Implemented
1. Brute Force Detection (repeated failed logins from one IP)
2. Account Lockout Detection
3. Privilege Escalation Detection
4. Suspicious Login Time Detection (outside working hours)
5. New User Detection
6. Deleted User Detection
7. Password Change Detection
8. Multiple Failed Login Detection (per user)
