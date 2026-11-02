# Export-SecurityLog.ps1
#
# Exports real Windows Security Event Log entries into a CSV file matching
# the exact column format expected by the Windows Security Log Analysis Tool.
#
# USAGE (run PowerShell "as Administrator" - the Security log is protected):
#   .\Export-SecurityLog.ps1 -MaxEvents 500 -OutputPath "C:\logs\my_security_log.csv"
#
# Recognized Event IDs (all others are skipped):
#   4624, 4625, 4634, 4648  (Authentication)
#   4720, 4722, 4723, 4725, 4726, 4740  (Account Management)
#   4672  (Privilege Use)

param(
    [int]$MaxEvents = 500,
    [string]$OutputPath = "$env:USERPROFILE\Desktop\security_log_export.csv"
)

$recognizedIds = @(4624, 4625, 4634, 4648, 4720, 4722, 4723, 4725, 4726, 4740, 4672)

Write-Host "Reading Security event log (this may take a moment)..."

$events = Get-WinEvent -LogName Security -MaxEvents $MaxEvents |
    Where-Object { $recognizedIds -contains $_.Id }

$rows = foreach ($event in $events) {
    $message = $event.Message

    # Try to pull the account name and source IP out of the free-text
    # message body using regex, since not every event exposes these as
    # separate structured properties in the same way.
    $username = if ($message -match "Account Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
    $ip       = if ($message -match "Source Network Address:\s*([\d\.]+)") { $matches[1] } else { "" }
    $target   = if ($message -match "Target Account Name:\s*(\S+)") { $matches[1] } else { $username }

    [PSCustomObject]@{
        EventID       = $event.Id
        TimeCreated   = $event.TimeCreated.ToString("M/d/yyyy h:mm:ss tt", [System.Globalization.CultureInfo]::InvariantCulture)
        Username      = $username
        ComputerName  = $event.MachineName
        EventSource   = $event.ProviderName
        Level         = ($event.LevelDisplayName).ToUpper()
        Message       = (($message -split "`n")[0]).TrimEnd("`r")  # first line only, keeps CSV readable
        IPAddress     = $ip
        LogonType     = ""
        AuthPackage   = ""
        TargetAccount = $target
        Privileges    = ""
    }
}

$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Exported $($rows.Count) matching events to: $OutputPath"
Write-Host "You can now use the Import button in the SIEM tool to load this file."
