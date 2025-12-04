# PULSE - Technical Documentation

> Comprehensive technical guide for engineers deploying, using, and extending PULSE.

---

## Table of Contents

| Section | Topics |
|---------|--------|
| [Architecture Overview](#architecture-overview) | Code Structure, Data Flow, Results Object |
| [Installation & Setup](#installation--setup) | Requirements, Deployment, Execution Policy |
| [Usage](#usage) | Parameters, Examples, Running as Admin |
| [Data Collection Modules](#data-collection-modules) | System Info, Performance, Processes, Browser, Config, Events |
| [Health Status Logic](#health-status-logic) | Thresholds, Philosophy, Status Determination |
| [Output Formats](#output-formats) | JSON Schema, HTML Report, Markdown, Clipboard |
| [File Paths & Logging](#file-paths--logging) | Output Location, Error Logging |
| [Extending PULSE](#extending-pulse) | Adding Modules, Adding Counters, Modifying Thresholds |
| [Troubleshooting](#troubleshooting) | Common Issues, Debug Mode |
| [Performance Thresholds Reference](#performance-thresholds-reference) | Documented Microsoft Thresholds |

---

## Architecture Overview

### Single-File Design

PULSE is a single PowerShell script (~4000 lines) organized into regions for maintainability. This design ensures:
- No external dependencies
- Easy deployment (copy one file)
- Simple version management

### Code Structure

```
PULSE.ps1
├── Script Configuration (lines 55-97)
│   ├── Global configuration variables
│   ├── $Script:Results ordered hashtable
│   └── $Script:InternalErrors collection
│
├── Helper Functions (lines 98-317)
│   ├── Write-Log
│   ├── Add-InternalError
│   ├── Get-SafeCimInstance
│   ├── Get-SafeCounter
│   └── Get-Statistics
│
├── Module: System Information (lines 318-710)
│   └── Get-SystemInformation
│
├── Module: Performance Sampling (lines 711-994)
│   └── Get-PerformanceSampling
│
├── Module: Process Analysis (lines 995-1226)
│   └── Get-ProcessAnalysis
│
├── Module: Browser Analysis (lines 1227-1428)
│   └── Get-BrowserAnalysis
│
├── Module: Configuration Health (lines 1429-2046)
│   └── Get-ConfigurationHealth
│
├── Module: Event Log Summary (lines 2047-2283)
│   └── Get-EventLogSummary
│
├── Output Functions (lines 2284-3838)
│   ├── Export-JsonReport
│   ├── Export-MarkdownReport
│   ├── Export-HtmlReport
│   └── Copy-WorkNoteToClipboard
│
└── Main Execution (lines 3839-end)
    └── Invoke-PULSE
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         PULSE Execution Flow                         │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Invoke-    │    │   Collect    │    │   Evaluate   │
│    PULSE     │───▶│    Data      │───▶│   Health     │
│              │    │              │    │              │
└──────────────┘    └──────────────┘    └──────────────┘
                           │                    │
                           ▼                    ▼
              ┌────────────────────┐  ┌──────────────────┐
              │  $Script:Results   │  │  HealthSummary   │
              │                    │  │  OverallStatus   │
              │  - SystemInfo      │  │  Issues[]        │
              │  - Performance     │  └──────────────────┘
              │  - Processes       │           │
              │  - Browser         │           │
              │  - Config          │           │
              │  - Events          │           ▼
              └────────────────────┘  ┌──────────────────┐
                           │          │  Export Reports  │
                           │          │                  │
                           └─────────▶│  - JSON          │
                                      │  - HTML          │
                                      │  - Markdown      │
                                      │  - Clipboard     │
                                      └──────────────────┘
```

### Results Object Structure

All collected data flows into a single ordered hashtable:

```powershell
$Script:Results = [ordered]@{
    Metadata            = @{}  # Script version, timestamps, parameters
    SystemInformation   = @{}  # Hardware, OS, volumes
    PerformanceSampling = @{}  # CPU, memory, disk counters over time
    ProcessAnalysis     = @{}  # Top processes, observations
    BrowserAnalysis     = @{}  # Chrome/Edge resource usage
    ConfigurationHealth = @{}  # Pending reboot, installs, Intune, etc.
    EventLogSummary     = @{}  # 48-hour event log scan
    HealthSummary       = @{}  # Overall status and issues
    InternalErrors      = @[]  # Non-fatal collection errors
}
```

---

## Installation & Setup

### Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| PowerShell | 5.1+ | Built into Windows 10/11 |
| Operating System | Windows 10/11 | Optimized for Windows 11 |
| Privileges | Administrator | Required for full data collection |
| Disk Space | ~5 MB | For report output |

### Built-in Cmdlets Used

No external modules required. PULSE uses only built-in cmdlets:

| Cmdlet | Purpose |
|--------|---------|
| `Get-CimInstance` | WMI/CIM queries for hardware info |
| `Get-Counter` | Performance counter collection |
| `Get-Process` | Process enumeration |
| `Get-WinEvent` | Event log queries |
| `Get-NetAdapter` | Network adapter information |
| `Get-PhysicalDisk` | Storage subsystem info |

### Deployment Options

**Option 1: Direct Copy**
```powershell
# Copy to technician's tools folder
Copy-Item PULSE.ps1 C:\Tools\
```

**Option 2: Network Share**
```powershell
# Run directly from network share
\\fileserver\tools\PULSE.ps1
```

**Option 3: Intune Win32 App**
Package as a Win32 app for deployment to technician workstations.

### Execution Policy

```powershell
# Option 1: Set policy for current user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Option 2: Bypass for single session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

---

## Usage

### Parameters

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `-OutputPath` | String | `C:\ProgramData\PULSE\` | Valid path | Report output directory |
| `-SampleDuration` | Int | 60 | 10-300 | Performance sampling duration in seconds |
| `-SampleInterval` | Int | 2 | 1-10 | Interval between samples in seconds |
| `-SkipElevationCheck` | Switch | False | - | Allow non-admin execution (limited data) |

### Examples

```powershell
# Standard execution (recommended)
.\PULSE.ps1

# Quick scan (30 seconds)
.\PULSE.ps1 -SampleDuration 30 -SampleInterval 1

# Custom output location
.\PULSE.ps1 -OutputPath "D:\Diagnostics"

# Non-admin execution (limited functionality)
.\PULSE.ps1 -SkipElevationCheck
```

### Running as Administrator

The script enforces elevation by default. If not running as admin, it exits with instructions.

```powershell
# Option 1: Right-click PowerShell > Run as Administrator
.\PULSE.ps1

# Option 2: Elevate from within PowerShell
Start-Process powershell -Verb RunAs -ArgumentList "-File `"$PWD\PULSE.ps1`""
```

### Data Collection Without Admin

| Data | Available | Notes |
|------|-----------|-------|
| Basic CPU/memory/OS info | Yes | |
| Process enumeration | Partial | I/O metrics limited |
| Browser analysis | Yes | |
| Volume information | Yes | |
| Event logs | Partial | Some sources restricted |
| SMART disk health | No | Requires admin |
| TPM information | No | Requires admin |
| Intune registry queries | No | Requires admin |

---

## Data Collection Modules

### System Information Module

**Function:** `Get-SystemInformation`

Collects hardware and OS configuration data.

| Data Point | WMI/CIM Class | Admin Required |
|------------|---------------|----------------|
| CPU model, cores, speed | `Win32_Processor` | No |
| Physical memory | `Win32_PhysicalMemory` | No |
| Total/available RAM | `Win32_OperatingSystem` | No |
| Disk drives | `Win32_DiskDrive` | No |
| Physical disk type (SSD/HDD) | `MSFT_PhysicalDisk` | Partial |
| SMART status | `MSStorageDriver_FailurePredictStatus` | Yes |
| BIOS version | `Win32_BIOS` | No |
| TPM status | `Win32_Tpm` | Yes |
| OS version, build, uptime | `Win32_OperatingSystem` | No |
| Volume free space | `Win32_LogicalDisk` | No |

### Performance Sampling Module

**Function:** `Get-PerformanceSampling`

Collects performance counters over the configured sampling window.

**Counters Collected:**

| Counter Path | Category | Metric |
|--------------|----------|--------|
| `\Processor(_Total)\% Processor Time` | CPU | Overall utilization |
| `\Processor(_Total)\% DPC Time` | CPU | Deferred procedure call time |
| `\Processor(_Total)\% Interrupt Time` | CPU | Hardware interrupt time |
| `\System\Processor Queue Length` | CPU | Thread queue depth |
| `\Memory\Available MBytes` | Memory | Free memory |
| `\Memory\Committed Bytes` | Memory | Committed memory |
| `\Memory\Page Faults/sec` | Memory | Hard page faults |
| `\PhysicalDisk(_Total)\Avg. Disk sec/Read` | Disk | Read latency |
| `\PhysicalDisk(_Total)\Avg. Disk sec/Write` | Disk | Write latency |
| `\PhysicalDisk(_Total)\Current Disk Queue Length` | Disk | I/O queue |
| `\Network Interface(*)\Bytes Total/sec` | Network | Throughput |
| `\Network Interface(*)\Packets Received Errors` | Network | Errors |

**Statistics Calculated:**
- Minimum
- Maximum
- Average
- Sample count

### Process Analysis Module

**Function:** `Get-ProcessAnalysis`

Analyzes running processes for resource consumption patterns.

| Analysis | Description | Output |
|----------|-------------|--------|
| Top 10 by CPU | Processes with highest CPU time | Ranked list |
| Top 10 by Memory | Processes with highest working set | Ranked list |
| Top 10 by Disk I/O | Processes with highest I/O operations | Ranked list |
| Peak CPU during sampling | Highest CPU consumer during sample window | Single process |
| Peak Memory during sampling | Highest memory consumer during sample window | Single process |
| Observations | Contextual notes (high memory apps, active scans) | Text list |

**Observation Triggers:**
- Non-browser app using >2 GB memory
- Windows Update processes active (TiWorker, TrustedInstaller)
- Defender scan in progress
- Unresponsive applications detected

### Browser Analysis Module

**Function:** `Get-BrowserAnalysis`

Analyzes Chrome and Edge browser resource usage.

| Data Point | Chrome | Edge |
|------------|--------|------|
| Running status | Yes | Yes |
| Process count | Yes | Yes |
| Total memory usage | Yes | Yes |
| Average memory per process | Yes | Yes |
| GPU process memory | Yes | Yes |
| Extension count | Yes | Yes |
| Extension names/versions | Yes | Yes |
| Per-process breakdown | Yes | Yes |

**Extension Enumeration:**
Extensions are discovered by reading `manifest.json` files from:
- Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions\`
- Edge: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions\`

### Configuration Health Module

**Function:** `Get-ConfigurationHealth`

Collects system configuration and diagnostic data.

| Check | Data Source | Description |
|-------|-------------|-------------|
| Pending Reboot | Registry keys | CBS, Windows Update, file rename, computer rename, SCCM |
| Recently Installed Software | Registry (Uninstall) | Apps installed in last 7 days |
| Recent Windows Updates | WMI QuickFixEngineering | Updates installed in last 7 days |
| Page File Configuration | WMI Win32_PageFileSetting | Size and location |
| Pending Windows Updates | COM Update.Session | Count of pending updates |
| Intune Enrollment | Registry MDM keys | Status, UPN, last sync with "X days ago" |
| Company Portal | Service/App check | Installation and service status |
| GPO Remnants | Registry PolicyInfo | Domain policy detection |
| User Profile Size | File system | Total size and largest folders breakdown |
| Startup Programs | Registry Run keys | Name, location, scope, type |

**Pending Reboot Detection Sources:**

| Registry Path | Condition |
|---------------|-----------|
| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending` | Key exists |
| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired` | Key exists |
| `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations` | Value exists |
| `HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName` vs `ComputerName` | Names differ |
| `HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData` | Key exists |

### Event Log Summary Module

**Function:** `Get-EventLogSummary`

Scans event logs for significant events in the last 48 hours.

| Event Category | Log Source | Event IDs/Providers |
|----------------|------------|---------------------|
| Disk events | System | disk, storage, ntfs, volmgr providers |
| Kernel/driver errors | System | Microsoft-Windows-Kernel-*, WHEA-Logger |
| Application crashes | Application | Event IDs 1000, 1001, 1002 (WER, App Hang) |
| Update failures | System | Microsoft-Windows-WindowsUpdateClient |
| Browser crashes | Application | Chrome, Edge providers |
| Security events | Security | Event IDs 4625, 4771, 4776 (failed logons) |

---

## Health Status Logic

### Philosophy

**PULSE only flags metrics with documented Microsoft thresholds.**

Informational data is presented neutrally without Pass/Warning/Fail judgments:
- Startup programs
- Profile size
- Browser extensions
- Intune sync age
- Event log entries

Technicians apply their own judgment based on context.

### Status Determination

The overall health status is determined in the main execution block (~line 3900+):

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Health Status Determination                       │
└─────────────────────────────────────────────────────────────────────┘

                    ┌─────────────────┐
                    │  Pending Reboot │
                    │    detected?    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │       Yes       │───────────▶ FAIL
                    └────────┬────────┘
                             │ No
                    ┌────────▼────────┐
                    │   CPU > 90%     │
                    │  or Mem > 90%   │───────────▶ FAIL
                    │ or Disk > 50ms  │
                    │ or DPC/ISR >30% │
                    │ or Space <10%   │
                    └────────┬────────┘
                             │ No
                    ┌────────▼────────┐
                    │   CPU > 80%     │
                    │ or Disk > 25ms  │───────────▶ WARNING
                    │ or Space <15%   │
                    │ or DPC/ISR >15% │
                    └────────┬────────┘
                             │ No
                    ┌────────▼────────┐
                    │      PASS       │
                    └─────────────────┘
```

### Health Summary Output

```json
{
  "HealthSummary": {
    "OverallStatus": "Warning",
    "Issues": [
      "High average CPU usage (82%)",
      "Elevated disk latency (28ms average)"
    ]
  }
}
```

---

## Output Formats

### File Naming Convention

```
PULSE_<hostname>_<yyyyMMdd-HHmmss>.json
PULSE_<hostname>_<yyyyMMdd-HHmmss>.html
PULSE_<hostname>_<yyyyMMdd-HHmmss>.md
PULSE_<hostname>_<yyyyMMdd-HHmmss>_errors.log  (if errors occurred)
```

### JSON Schema

```json
{
  "Metadata": {
    "ScriptVersion": "1.1.0",
    "ScanTimestamp": "2025-12-03T14:30:00.000Z",
    "ScanId": "abc123",
    "Hostname": "WORKSTATION01",
    "SampleDuration": 60,
    "SampleInterval": 2,
    "IsElevated": true,
    "ScanDurationSeconds": 75.5
  },
  "SystemInformation": {
    "CollectionTimestamp": "...",
    "CPU": { "Name": "...", "Cores": 8, "LogicalProcessors": 16 },
    "Memory": { "TotalGB": 32, "AvailableGB": 16 },
    "OS": { "Caption": "...", "Build": "...", "UptimeDays": 5.2 },
    "Volumes": [{ "Letter": "C:", "SizeGB": 500, "FreeGB": 150, "FreePercent": 30 }]
  },
  "PerformanceSampling": {
    "CollectionTimestamp": "...",
    "CPU": {
      "Statistics": {
        "ProcessorTime": { "Min": 5, "Max": 85, "Average": 42, "SampleCount": 30 }
      }
    },
    "Memory": { "Statistics": { ... } },
    "Disk": { "Statistics": { ... } }
  },
  "ProcessAnalysis": {
    "CollectionTimestamp": "...",
    "TopByCPU": [{ "Name": "...", "PID": 1234, "CPUPercent": 25 }],
    "TopByMemory": [{ "Name": "...", "PID": 1234, "MemoryMB": 1500 }],
    "Observations": ["Windows Update is currently active"]
  },
  "BrowserAnalysis": {
    "Chrome": { "Running": true, "ProcessCount": 45, "TotalMemoryMB": 3200 },
    "Edge": { "Running": false }
  },
  "ConfigurationHealth": {
    "PendingReboot": { "Required": true, "Reasons": ["Windows Update"] },
    "RecentlyInstalled": { "Software": [...], "Updates": [...] },
    "IntuneEnrollment": { "Enrolled": true, "LastSync": "2 days ago" },
    "UserProfile": { "TotalSizeGB": 15.2, "LargestFolders": [...] },
    "StartupPrograms": [...]
  },
  "EventLogSummary": {
    "DiskEvents": [...],
    "ApplicationCrashes": [...],
    "UpdateFailures": [...]
  },
  "HealthSummary": {
    "OverallStatus": "Pass",
    "Issues": []
  },
  "InternalErrors": []
}
```

### HTML Report Features

| Feature | Description |
|---------|-------------|
| Color-coded status | Pass (green), Warning (yellow), Fail (red) |
| Pending reboot alert | Prominent banner when restart needed |
| Collapsible sections | Expand/collapse for easy navigation |
| Summary cards | Quick status overview at top |
| Detailed tables | Drill-down data for each module |
| Browser extensions | Names and versions listed |
| Recent changes | Software/updates from last 7 days |
| JSON link | Direct link to raw data file |
| Mobile responsive | Works on tablets and phones |

### Markdown Report

Comprehensive text format suitable for:
- Ticket attachments
- Email sharing
- Version control
- Offline viewing

### Clipboard (ServiceNow Work Note)

Automatically copied to clipboard on completion:

```
=== PULSE Diagnostic Summary ===
Status: ⚠️ WARNING
Hostname: WORKSTATION01
Scan Time: 2025-12-03 14:30

System: Windows 11 Pro 23H2 (Build 22631)
CPU: Intel Core i7-1265U (12 cores)
RAM: 16 GB (8.2 GB available)
Uptime: 5 days

Intune: Enrolled (Last sync: 2 days ago)

Issues:
- High average CPU usage (82%)
- Pending reboot required (Windows Update)

Recent Changes (7 days):
- Microsoft Teams 24.1.1 (installed 2025-12-01)
- KB5034441 (installed 2025-11-30)

Scan ID: abc123
```

---

## File Paths & Logging

### Output Location

| Purpose | Default Path |
|---------|--------------|
| Reports | `C:\ProgramData\PULSE\` |
| JSON output | `C:\ProgramData\PULSE\PULSE_<hostname>_<timestamp>.json` |
| HTML output | `C:\ProgramData\PULSE\PULSE_<hostname>_<timestamp>.html` |
| Markdown output | `C:\ProgramData\PULSE\PULSE_<hostname>_<timestamp>.md` |
| Error log | `C:\ProgramData\PULSE\PULSE_<hostname>_<timestamp>_errors.log` |

### Error Handling

Non-fatal errors are collected via `Add-InternalError`:

```powershell
Add-InternalError -Module "SystemInformation" -Message "Failed to query TPM" -ErrorRecord $_
```

Errors are:
1. Stored in `$Script:InternalErrors`
2. Included in JSON output
3. Written to `*_errors.log` file

This allows the scan to continue even when individual data sources fail.

### Console Logging

The `Write-Log` function provides colored console output:

| Level | Color | Use |
|-------|-------|-----|
| Info | Cyan | Progress messages |
| Success | Green | Completion messages |
| Warning | Yellow | Non-fatal issues |
| Error | Red | Failures |

---

## Extending PULSE

### Adding a New Module

**Step 1: Create the function**

```powershell
#region Module: Custom Analysis
function Get-CustomAnalysis {
    [CmdletBinding()]
    param()

    Write-Log -Message "Running custom analysis..." -Level Info

    $data = [ordered]@{
        CollectionTimestamp = (Get-Date).ToString("o")
    }

    try {
        # Your collection logic here
        $data.MyData = Get-Something
    }
    catch {
        Add-InternalError -Module "CustomAnalysis" -Message "Failed to collect data" -ErrorRecord $_
    }

    Write-Log -Message "Custom analysis complete" -Level Success
    return $data
}
#endregion
```

**Step 2: Add to Invoke-PULSE**

```powershell
# In Invoke-PULSE function, after other modules:
$Script:Results.CustomAnalysis = Get-CustomAnalysis
```

**Step 3: Update HTML template**

Add a section in the `Export-HtmlReport` function to display your data.

### Adding New Performance Counters

In `Get-PerformanceSampling`, add counters to the `$counters` array:

```powershell
$counters = @(
    # Existing counters...
    '\GPU Engine(*)\Utilization Percentage'
    '\Your\Custom Counter'
)
```

### Modifying Health Thresholds

Health evaluation is in the main execution block. Example modification:

```powershell
# Change CPU warning threshold from 80% to 75%
if ($cpuAverage -gt 75) {
    [void]$issues.Add("High average CPU usage ($([math]::Round($cpuAverage))%)")
    $status = "Warning"
}
```

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Execution policy restriction" | Script blocked | `Set-ExecutionPolicy Bypass -Scope Process` |
| "Access denied" errors | Not running as admin | Right-click PowerShell > Run as Administrator |
| Counter collection fails | Counter doesn't exist | Script handles gracefully; check error log |
| Slow performance during scan | 60-second sampling | Use `-SampleDuration 30` for faster scans |
| Empty browser extensions | Browser not installed in default location | Extensions still counted, names unavailable |
| "Intune not detected" | Registry access denied | Must run as admin |

### Debug Mode

```powershell
# Enable verbose output
$VerbosePreference = "Continue"
.\PULSE.ps1 -Verbose
```

### Checking Internal Errors

```powershell
# View error log
Get-Content "C:\ProgramData\PULSE\PULSE_*_errors.log" | Select-Object -Last 50

# Parse JSON for errors
$report = Get-Content "C:\ProgramData\PULSE\PULSE_*.json" | ConvertFrom-Json
$report.InternalErrors | Format-Table Module, Message, Timestamp
```

---

## Performance Thresholds Reference

All thresholds are based on documented Microsoft guidance.

### CPU Utilization

| Threshold | Status | Source |
|-----------|--------|--------|
| < 80% | Normal | |
| 80-90% | Warning | Microsoft TechNet |
| > 90% | Fail | Microsoft TechNet |

**Source:** [Microsoft Learn: Troubleshoot issues using Performance Monitor](https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/troubleshoot-issues-performance-monitor)

### Memory Usage

| Threshold | Status | Source |
|-----------|--------|--------|
| < 85% | Normal | |
| 85-90% | Warning | Active paging threshold |
| > 90% | Fail | Active paging threshold |

### Disk Latency

| Threshold | Status | Source |
|-----------|--------|--------|
| < 15ms | Normal | |
| 15-25ms | Warning | Microsoft PAL tool |
| 25-50ms | High | Microsoft Exchange team |
| > 50ms | Fail | "Extremely underperforming" |

**Source:** [Microsoft Learn: Measuring Disk Latency](https://learn.microsoft.com/en-us/archive/blogs/askcore/measuring-disk-latency-with-windows-performance-monitor-perfmon)

### Disk Space

| Threshold | Status | Source |
|-----------|--------|--------|
| > 15% free | Normal | |
| 10-15% free | Warning | |
| < 10% free | Fail | Windows Explorer red bar |

### DPC/ISR Time

| Threshold | Status | Source |
|-----------|--------|--------|
| < 15% combined | Normal | |
| 15-30% combined | Warning | Microsoft SCOM |
| > 30% combined | Fail | Microsoft SCOM |

**Source:** [Microsoft SCOM: CPU DPC Time Monitor](https://systemcenter.wiki/?GetElement=Microsoft.Windows.Server.10.0.Processor.PercentDPCTime)

### Pending Reboot

| Condition | Status |
|-----------|--------|
| No reboot pending | Pass |
| Any reboot pending | Fail |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.1.0 | 2025-12-01 | ServiceNow integration, pending reboot detection, recent installs, user profile size, browser extensions, Intune sync recency |
| 1.0.0 | 2025-11-22 | Initial release |

---

*Documentation for PULSE. For executive overview, see [README.md](README.md).*
