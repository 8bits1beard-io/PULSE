# PULSE

**Performance Utilization & Latency Sampling Engine**

A comprehensive, modular PowerShell diagnostic tool for Windows 11 Enterprise workstations. Designed for on-demand use by IT technicians and engineers to diagnose workstation performance issues.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Module Documentation](#module-documentation)
- [Output Files](#output-files)
- [Permissions](#permissions)
- [Known Limitations](#known-limitations)
- [Extending the Tool](#extending-the-tool)
- [Troubleshooting](#troubleshooting)
- [Checks and Thresholds Summary](#checks-and-thresholds-summary)
- [Performance Thresholds Reference](#performance-thresholds-reference)

## Overview

PULSE collects detailed system performance data over a configurable sampling period (default: 60 seconds). It analyzes hardware, processes, browsers, system configuration, and event logs to identify potential causes of workstation performance issues.

### Key Characteristics

- **On-demand execution** - Not scheduled, run when needed
- **Offline capable** - No internet connectivity required
- **Enterprise-ready** - Designed for Intune-managed Windows 11 machines
- **Non-disruptive** - Runs quietly without user interruption
- **Comprehensive** - Collects hardware, performance, process, and event data

## Features

| Feature | Description |
|---------|-------------|
| Hardware Inventory | CPU, memory, disk, BIOS, TPM information |
| Performance Sampling | 60-second collection of CPU, memory, disk, and network metrics |
| Process Analysis | Top processes by CPU, memory, disk I/O; contextual observations |
| Browser Analysis | Chrome/Edge resource usage, extension names and versions |
| Configuration Health | Pending reboot detection, recent installs, page file, Windows Update, Intune sync, user profile size, startup programs |
| Event Log Analysis | 48-hour scan for errors, crashes, and failures |
| ServiceNow Integration | Work note summary auto-copied to clipboard; markdown report for attachments |
| Multi-Format Output | JSON (data), HTML (visual), Markdown (ticket attachment) |

## Requirements

### System Requirements

| Requirement | Minimum |
|-------------|---------|
| PowerShell | 5.1 or higher |
| Operating System | Windows 10/11 |
| Memory | No specific requirement (runs in-memory) |
| Disk Space | ~5 MB for reports |

### PowerShell Modules

The script uses built-in cmdlets and does not require external modules:

- `Get-CimInstance` (CIM/WMI queries)
- `Get-Counter` (Performance counters)
- `Get-Process` (Process enumeration)
- `Get-WinEvent` (Event log queries)
- `Get-NetAdapter` (Network adapter info)
- `Get-PhysicalDisk` (Storage info)

## Installation

### Manual Installation

1. Download `PULSE.ps1` to a local directory
2. Ensure execution policy allows running scripts:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

### Enterprise Deployment

1. Host the script on a network share accessible to technicians
2. Deploy to a known location on workstations (e.g., `C:\Tools\PULSE.ps1`)

## Usage

### Basic Usage

```powershell
# Run with default settings (60-second sample, 2-second interval)
.\PULSE.ps1
```

### Advanced Usage

```powershell
# Custom sample duration (30 seconds) and interval (1 second)
.\PULSE.ps1 -SampleDuration 30 -SampleInterval 1

# Custom output path
.\PULSE.ps1 -OutputPath "D:\Diagnostics"

# Skip elevation check (some modules may fail)
.\PULSE.ps1 -SkipElevationCheck
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-OutputPath` | String | `C:\ProgramData\PULSE\` | Directory for report output |
| `-SampleDuration` | Int | 60 | Performance sampling duration (10-300 seconds) |
| `-SampleInterval` | Int | 2 | Interval between samples (1-10 seconds) |
| `-SkipElevationCheck` | Switch | False | Skip admin privilege check |

## Module Documentation

### 1. System Information Module

**Function:** `Get-SystemInformation`

Collects comprehensive hardware and OS information.

| Data Collected | Source | Admin Required |
|----------------|--------|----------------|
| CPU details | `Win32_Processor` | No |
| Memory configuration | `Win32_PhysicalMemory`, `Win32_OperatingSystem` | No |
| Disk information | `Win32_DiskDrive`, `Get-PhysicalDisk` | Partial |
| SMART status | `MSStorageDriver_FailurePredictStatus` | Yes |
| BIOS version | `Win32_BIOS` | No |
| TPM status | `Win32_Tpm` | Yes |
| OS version/uptime | `Win32_OperatingSystem` | No |
| Volume free space | `Win32_LogicalDisk` | No |

### 2. Performance Sampling Module

**Function:** `Get-PerformanceSampling`

Collects performance counters over the sampling window.

| Counter | Category | Metric |
|---------|----------|--------|
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

### 3. Process Analysis Module

**Function:** `Get-ProcessAnalysis`

Analyzes running processes for resource consumption and issues.

| Analysis | Description |
|----------|-------------|
| Top 10 by CPU | Processes with highest CPU time |
| Top 10 by Memory | Processes with highest working set |
| Top 10 by Disk I/O | Processes with highest I/O operations |
| High CPU detection | Processes > 1 hour CPU time |
| High memory detection | Processes > 2 GB memory |
| Handle leak detection | Processes > 10,000 handles |
| Unresponsive apps | Applications not responding |

### 4. Browser Analysis Module

**Function:** `Get-BrowserAnalysis`

Analyzes Chrome and Edge browser resource usage. Firefox memory usage is monitored in Process Analysis for potential issues.

| Data Collected | Chrome | Edge |
|----------------|--------|------|
| Running status | Yes | Yes |
| Process count | Yes | Yes |
| Total memory | Yes | Yes |
| Average memory per process | Yes | Yes |
| GPU process memory | Yes | Yes |
| Extension count | Yes | Yes |
| Per-process breakdown | Yes | Yes |

### 5. Configuration Health Module

**Function:** `Get-ConfigurationHealth`

Checks system configuration and collects diagnostic data.

| Check | Description |
|-------|-------------|
| Pending Reboot | CBS, Windows Update, file rename operations, computer rename, SCCM client |
| Recently Installed | Software and Windows Updates from last 7 days |
| Page File | Configuration and current usage |
| Windows Update | Pending updates count |
| Intune Enrollment | MDM status, UPN, last sync time with human-readable "X days ago" |
| Company Portal | Installation and service status |
| GPO Remnants | Domain policy detection for cloud-only environments |
| User Profile | Total size and largest folders breakdown |
| Startup Programs | Name, location, scope, type |

### 6. Event Log Summary Module

**Function:** `Get-EventLogSummary`

Scans event logs for significant events (default: last 48 hours).

| Event Category | Log Source | Event Types |
|----------------|------------|-------------|
| Disk events | System | Warnings, errors from disk/storage providers |
| Kernel/driver errors | System | Critical errors from kernel/driver/WHEA |
| Application crashes | Application | Application Error, WER, App Hang |
| Update failures | System | WindowsUpdateClient warnings/errors |
| Browser crashes | Application | Chrome/Edge related errors |
| Security events | Security | Failed logons (4625, 4771, 4776) |

## Output Files

### File Naming Convention

```
PULSE_<hostname>_<yyyyMMdd-HHmmss>.json      # Structured data
PULSE_<hostname>_<yyyyMMdd-HHmmss>.html      # Visual report for technician
PULSE_<hostname>_<yyyyMMdd-HHmmss>.md        # Comprehensive markdown for ticket attachments
PULSE_<hostname>_<yyyyMMdd-HHmmss>_errors.log # Internal errors (if any)
```

### Output Location

Default: `C:\ProgramData\PULSE\`

### ServiceNow Integration

When the scan completes, a brief work note summary is automatically copied to the clipboard. Technicians can immediately paste (Ctrl+V) into ServiceNow work notes. The summary includes:
- Health status and key metrics
- System info (OS, CPU, RAM, uptime)
- Intune enrollment and sync status
- Observations (if any)
- Recent changes (last 7 days)
- Scan ID for audit trail

For detailed documentation, attach the `.md` markdown file to the ticket.

### JSON Schema

```json
{
  "Metadata": {
    "ScriptVersion": "1.0.0",
    "ScanTimestamp": "2025-11-22T10:30:00.000Z",
    "Hostname": "WORKSTATION01",
    "SampleDuration": 60,
    "SampleInterval": 2,
    "IsElevated": true,
    "ScanDurationSeconds": 75.5
  },
  "SystemInformation": { ... },
  "PerformanceSampling": { ... },
  "ProcessAnalysis": { ... },
  "BrowserAnalysis": { ... },
  "ConfigurationHealth": { ... },
  "EventLogSummary": { ... },
  "HealthSummary": {
    "OverallStatus": "Pass|Warning|Fail",
    "Issues": [ ... ]
  },
  "InternalErrors": [ ... ]
}
```

### HTML Report Features

- Color-coded health indicators (Pass/Warning/Fail) for documented thresholds only
- Prominent pending reboot alert when restart is needed
- Collapsible sections for easy navigation
- Summary cards for quick status overview
- Detailed tables for drill-down analysis
- Browser extension lists with names
- Recently installed software/updates section
- Link to JSON file for raw data access
- Mobile-responsive design

## Permissions

### Without Admin Rights

The following data can be collected:
- Basic CPU, memory, OS information
- Process enumeration (limited)
- Browser analysis
- Volume information
- Event logs (may be limited)
- Network adapter information

### With Admin Rights (Recommended)

Full access to:
- SMART disk health data
- TPM information
- Complete process metrics including I/O
- All event log sources
- Intune/MDM registry queries
- Service status queries

### Running as Administrator

```powershell
# Option 1: Right-click PowerShell > Run as Administrator
.\PULSE.ps1

# Option 2: Elevate from within PowerShell
Start-Process powershell -Verb RunAs -ArgumentList "-File `"$PWD\PULSE.ps1`""
```

## Known Limitations

### General Limitations

| Limitation | Description | Workaround |
|------------|-------------|------------|
| No real-time monitoring | Point-in-time snapshot only | Run during slowness |
| Network counter names | Must match adapter names exactly | Uses physical adapters only |
| SMART data | Requires admin + compatible drivers | Run elevated |
| Process I/O | May not include all metrics | Best effort collection |

### Environment-Specific

1. **Virtual machines** - Some hardware queries may return limited data
2. **Locked-down systems** - Execution policy may block scripts
3. **Non-English locales** - Counter names may differ
4. **Legacy systems** - Windows 10 1809+ recommended

### Data Accuracy

- CPU utilization is sampled, not continuous
- Process CPU time is cumulative since process start
- Memory values may fluctuate during sampling

## Extending the Tool

### Adding a New Module

1. Create a new function following the pattern:

```powershell
function Get-CustomAnalysis {
    [CmdletBinding()]
    param()

    Write-Log -Message "Running custom analysis..." -Level Info

    $data = [ordered]@{
        CollectionTimestamp = (Get-Date).ToString("o")
        # Your data structure here
    }

    try {
        # Your collection logic here
    }
    catch {
        Add-InternalError -Module "CustomAnalysis" -Message "Failed" -ErrorRecord $_
    }

    Write-Log -Message "Custom analysis complete" -Level Success
    return $data
}
```

2. Add the module call in `Invoke-PULSE`:

```powershell
$Script:Results.CustomAnalysis = Get-CustomAnalysis
```

3. Update the HTML report template to include your new section

### Adding New Counters

In `Get-PerformanceSampling`, add counters to the `$counters` array:

```powershell
$counters = @(
    # Existing counters...
    '\Your\New Counter Path'
)
```

### Modifying Health Thresholds

Health status logic is in `Get-HealthStatus` and the main execution block:

```powershell
# Example: Change CPU warning threshold from 80% to 70%
if ($Script:Results.PerformanceSampling.CPU.Statistics.ProcessorTime.Average -gt 70) {
    [void]$issues.Add("High average CPU usage detected")
}
```

## Troubleshooting

### Common Issues

#### "Execution policy restriction"

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\PULSE.ps1
```

#### "Access denied" errors

Run PowerShell as Administrator for full functionality.

#### Counter collection fails

Some counters may not exist on all systems. The script handles these gracefully and logs errors.

#### Slow performance during scan

The 60-second sampling is intentional. Use `-SampleDuration 30` for faster scans.

### Debug Mode

For verbose output during troubleshooting:

```powershell
$VerbosePreference = "Continue"
.\PULSE.ps1 -Verbose
```

### Checking Internal Errors

Review the `*_errors.log` file in the output directory for any collection failures.

---

## Checks and Thresholds Summary

**Quick reference** for technicians. For detailed threshold documentation with sources, see [Performance Thresholds Reference](#performance-thresholds-reference).

### Health Status Philosophy

PULSE only flags metrics with **documented Microsoft thresholds**. Informational data (startup programs, profile size, browser extensions, Intune sync age) is presented neutrally without Pass/Warning/Fail judgments - technicians apply their own judgment based on context.

### Health Summary Checks

These checks determine the overall **Pass / Warning / Fail** status.

| Check | Warning Trigger | Fail Trigger | Source |
|-------|-----------------|--------------|--------|
| Pending Reboot | - | Any reboot pending | Windows registry |
| CPU Usage | Average >80% | Average >90% | Microsoft docs |
| Memory Usage | Average >85% | Average >90% | Active paging threshold |
| Disk Space | Any volume <15% free | Any volume <10% free | Windows red bar |
| Disk Latency | Read or Write >25ms avg | >50ms avg | Microsoft: "extremely underperforming" |
| Disk Health | - | SMART status not "Healthy" | Drive self-reporting |
| DPC/ISR Time | Combined >15% | Combined >30% | Microsoft docs |

### Observations (Informational)

These are presented for technician awareness without health status judgments:

| Observation | When Shown |
|-------------|------------|
| Browser Memory | Chrome/Edge using >8GB or >50% of system RAM |
| High Memory Application | Non-browser app using >2GB |
| Windows Update Active | TiWorker, TrustedInstaller, or wuauclt running |
| Defender Scan Active | Full or Quick scan in progress |
| High DPC/ISR Time | Combined >15% (context for potential driver issues) |

### Informational Data (No Thresholds)

This data is collected and displayed for context but does not trigger warnings:

| Section | Data Collected |
|---------|----------------|
| Pending Reboot | Reasons why a reboot is required |
| Recently Installed | Software and Windows Updates from last 7 days |
| User Profile | Total size and breakdown by folder |
| Browser Extensions | Chrome/Edge extension names and versions |
| Intune Sync | Last sync time with "X days ago" format |
| Startup Programs | Name, location, scope, type |
| Event Log Summary | Disk events, kernel errors, app crashes, update failures (48 hours) |
| Top Processes | Top 10 by CPU time, memory, and disk I/O |
| Peak Processes | Processes with highest resource usage during sampling |

---

## Performance Thresholds Reference

**Detailed documentation** of all thresholds with authoritative sources for peer review and validation. For a quick reference, see [Checks and Thresholds Summary](#checks-and-thresholds-summary).

### CPU Utilization

| Threshold | Status | Description |
|-----------|--------|-------------|
| < 80% | Normal | System operating within acceptable limits |
| 80-90% | Warning | Elevated CPU usage, may impact responsiveness |
| > 90% | Critical | Severe CPU constraint, likely user-visible impact |

**Source:** Microsoft TechNet - "A sustained processor queue of greater than two threads generally indicates processor congestion" and general guidance that sustained >85% utilization indicates a bottleneck.
- [Microsoft Learn: Troubleshoot issues using Performance Monitor](https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/troubleshoot-issues-performance-monitor)

### Processor Queue Length

| Threshold | Status | Description |
|-----------|--------|-------------|
| < 2 per processor | Normal | No processor congestion |
| 2-10 per processor | Warning | Elevated queue, potential bottleneck |
| > 10 per processor | Critical | Significant processor congestion |

**Source:** Microsoft documentation states "A sustained processor queue of greater than two threads generally indicates processor congestion. Therefore, if a computer has multiple processors, you need to divide this value by the number of processors servicing the workload."
- [Microsoft Learn: Observing Processor Queue Length](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc940375(v=technet.10))

### Memory (Available MBytes)

| Threshold | Status | Description |
|-----------|--------|-------------|
| > 1 GB | Normal | Adequate free memory |
| 500 MB - 1 GB | Warning | Low available memory |
| < 500 MB | Critical | Memory exhaustion imminent |

**Source:** Microsoft System Center Operations Manager (SCOM) default thresholds and general Windows performance guidance. Windows begins aggressive paging when available memory drops below ~500MB.
- [Microsoft Learn: Memory Performance Counters](https://learn.microsoft.com/en-us/archive/blogs/askcore/measuring-memory-usage-in-windows)

### Disk Space (Free Space %)

| Threshold | Status | Description |
|-----------|--------|-------------|
| > 15% | Normal | Adequate free space |
| 10-15% | Warning | Low disk space |
| < 10% | Critical | Windows displays red bar in Explorer |

**Source:** Windows Explorer displays a red capacity bar when free space drops below 10%. This is hardcoded Windows behavior indicating critical low space.
- Built-in Windows behavior (verifiable in File Explorer)

### Disk Latency (Avg. Disk sec/Read, Avg. Disk sec/Write)

| Threshold | Status | Description |
|-----------|--------|-------------|
| < 10 ms | Excellent | Optimal disk performance |
| 10-15 ms | Good | Acceptable for most workloads |
| 15-25 ms | Warning | Degraded performance, investigate |
| > 25 ms | Critical | Significant storage bottleneck |
| > 50 ms | Severe | Extremely underperforming storage |

**Source:** Microsoft PAL (Performance Analysis of Logs) tool uses 15ms for warning and 25ms for critical alerts. Microsoft Exchange team documentation confirms "Latency above 25 ms can cause noticeable performance issues. Latency above 50 ms is indicative of extremely underperforming storage."
- [Microsoft Learn: Measuring Disk Latency with Windows Performance Monitor](https://learn.microsoft.com/en-us/archive/blogs/askcore/measuring-disk-latency-with-windows-performance-monitor-perfmon)
- [Microsoft TechNet: PerfGuide - Analyzing Poor Disk Response Times](https://social.technet.microsoft.com/wiki/contents/articles/1516.perfguide-analyzing-poor-disk-response-times.aspx)

### Disk Queue Length

| Threshold | Status | Description |
|-----------|--------|-------------|
| < 2x disk count | Normal | I/O requests processing efficiently |
| 2-3x disk count | Warning | Elevated I/O queuing |
| > 3x disk count | Critical | Storage subsystem overwhelmed |

**Note:** For virtualized or cloud storage where physical disk count is unknown, use a threshold of 10.

**Source:** Microsoft guidance states "Disk queues should be no greater than twice the number of physical disks serving the drive."
- [Microsoft Learn: Windows Performance Monitor Disk Counters Explained](https://learn.microsoft.com/en-us/archive/blogs/askcore/windows-performance-monitor-disk-counters-explained)

### DPC/ISR Time (% DPC Time + % Interrupt Time)

| Threshold | Status | Description |
|-----------|--------|-------------|
| < 15% | Normal | Hardware/drivers processing efficiently |
| 15-30% | Warning | Elevated interrupt processing, potential driver issue |
| > 30% | Critical | Significant driver or hardware problem |
| > 50% DPC alone | Severe | Critical driver issue, investigate immediately |

**Source:** Microsoft documentation states "If a processor instance is running a sustained % Processor Time that is > 85% and it is also spending > 15% of that time servicing Interrupts and/or DPCs, the processor is probably the source of a performance bottleneck" and "If the processor is running a sustained % Processor Time of < 85% and it is also spending > 15% of that time servicing interrupts and/or DPCs, the performance issue may be the result of either an application or hardware related issue."
- [Microsoft SCOM: CPU DPC Time Percentage Monitor](https://systemcenter.wiki/?GetElement=Microsoft.Windows.Server.10.0.Processor.PercentDPCTime&ManagementPack=Microsoft.Windows.Server.2016.Monitoring&Type=UnitMonitor)

### High Memory Application

| Threshold | Status | Description |
|-----------|--------|-------------|
| < 2 GB | Normal | Typical application memory usage |
| 2-4 GB | Medium | Elevated but may be expected for some apps |
| > 4 GB | High | Significant memory consumer, investigate |

**Note:** Excludes browsers (handled separately), Memory Compression, and vmmem (WSL). Context-aware messaging is provided for known applications (Teams, Outlook, Visual Studio, Defender).

**Source:** General application performance guidance. Most business applications should not exceed 2GB unless performing intensive operations.

### Page File Usage

| Threshold | Status | Description |
|-----------|--------|-------------|
| < 70% | Normal | Adequate virtual memory headroom |
| 70-90% | Warning | High page file usage |
| > 90% | Critical | Virtual memory exhaustion risk |

**Source:** General Windows performance guidance. High page file usage combined with low available memory indicates memory pressure.

### System Uptime

| Threshold | Status | Description |
|-----------|--------|-------------|
| < 30 days | Normal | System rebooted recently |
| 30-60 days | Info | Consider scheduling restart |
| > 60 days | Warning | Extended uptime may accumulate issues |

**Source:** Microsoft best practice recommendations for Windows client systems to receive updates and clear accumulated state.

### Browser Memory Usage

| Threshold | Status | Description |
|-----------|--------|-------------|
| < 8 GB and < 50% RAM | Normal | Typical browser usage, even with many tabs |
| > 8 GB or > 50% RAM (whichever is higher) | Warning | Potentially excessive, investigate |
| > 12 GB or > 60% RAM | High | Likely memory leak or extreme usage |

**Note:** Process count is NOT a meaningful indicator of browser problems. Modern browsers create many processes by design (one per tab, per extension, plus utility processes). 75+ processes is normal.

**Source:** Industry research shows ~1GB per 10 tabs is typical. 3-5GB with extensions is normal for office workers. Chrome/Edge multi-process architecture creates significantly more processes than tabs.
- [MakeUseOf: Why Is Chrome Using So Much RAM?](https://www.makeuseof.com/tag/chrome-using-much-ram-fix-right-now/)
- [Microsoft Support: Edge Performance Features](https://support.microsoft.com/en-us/topic/learn-about-performance-features-in-microsoft-edge-7b36f363-2119-448a-8de6-375cfd88ab25)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.1.0 | 2025-12-01 | ServiceNow integration (clipboard + markdown), pending reboot detection, recent installs, user profile size, browser extension names, Intune sync recency, health status philosophy update |
| 1.0.0 | 2025-11-22 | Initial release |

## Author

**Joshua Walderbach**

---

*This tool is designed for internal IT use in enterprise environments.*
