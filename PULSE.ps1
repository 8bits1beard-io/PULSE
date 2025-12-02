#Requires -Version 5.1
<#
.SYNOPSIS
    PULSE - Performance Utilization & Latency Sampling Engine

.DESCRIPTION
    A comprehensive, modular PowerShell diagnostic tool that collects detailed system
    performance data including 60-second sampling of key metrics. Designed for on-demand
    use by IT technicians and engineers to diagnose workstation performance issues.

.PARAMETER OutputPath
    Path where reports will be saved. Default: C:\ProgramData\PULSE\

.PARAMETER SampleDuration
    Duration in seconds for performance sampling. Default: 60

.PARAMETER SampleInterval
    Interval in seconds between samples. Default: 2

.PARAMETER SkipElevationCheck
    Skip the elevation requirement check (some modules may fail)

.EXAMPLE
    .\PULSE.ps1
    Runs a full diagnostic scan with default settings.

.EXAMPLE
    .\PULSE.ps1 -SampleDuration 30 -SampleInterval 1
    Runs a 30-second scan with 1-second sampling intervals.

.NOTES
    Version:        1.0.0
    Author:         Joshua Walderbach
    Creation Date:  2025-11-22
    Purpose:        On-demand workstation performance diagnostics for Windows 11
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = "C:\ProgramData\PULSE",

    [Parameter()]
    [ValidateRange(10, 300)]
    [int]$SampleDuration = 60,

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]$SampleInterval = 2,

    [Parameter()]
    [switch]$SkipElevationCheck
)

#region Script Configuration
$Script:Config = @{
    Version = "1.1.0"
    ScriptName = "PULSE"
    OutputPath = $OutputPath
    SampleDuration = $SampleDuration
    SampleInterval = $SampleInterval
    Timestamp = Get-Date
    TimestampString = (Get-Date -Format "yyyyMMdd-HHmmss")
    Hostname = $env:COMPUTERNAME
    IsElevated = $false
    ErrorLogPath = $null
}

# Set file paths
$Script:Config.JsonPath = Join-Path $OutputPath "PULSE_$($Script:Config.Hostname)_$($Script:Config.TimestampString).json"
$Script:Config.HtmlPath = Join-Path $OutputPath "PULSE_$($Script:Config.Hostname)_$($Script:Config.TimestampString).html"
$Script:Config.ErrorLogPath = Join-Path $OutputPath "PULSE_$($Script:Config.Hostname)_$($Script:Config.TimestampString)_errors.log"

# Initialize results object
$Script:Results = [ordered]@{
    Metadata = [ordered]@{
        ScriptVersion = $Script:Config.Version
        ScanTimestamp = $Script:Config.Timestamp.ToString("o")
        Hostname = $Script:Config.Hostname
        SampleDuration = $SampleDuration
        SampleInterval = $SampleInterval
        IsElevated = $false
        ScanDurationSeconds = 0
    }
    SystemInformation = $null
    PerformanceSampling = $null
    ProcessAnalysis = $null
    BrowserAnalysis = $null
    ConfigurationHealth = $null
    EventLogSummary = $null
    HealthSummary = $null
}

# Internal error collection
$Script:InternalErrors = [System.Collections.ArrayList]::new()
#endregion

#region Helper Functions
function Write-Log {
    <#
    .SYNOPSIS
        Writes a log message to console and optionally to file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug')]
        [string]$Level = 'Info',

        [Parameter()]
        [switch]$ToErrorLog
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        'Info'    { Write-Host $logMessage -ForegroundColor Cyan }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        'Debug'   { Write-Verbose $logMessage }
    }

    if ($ToErrorLog -and $Script:Config.ErrorLogPath) {
        Add-Content -Path $Script:Config.ErrorLogPath -Value $logMessage -ErrorAction SilentlyContinue
    }
}

function Add-InternalError {
    <#
    .SYNOPSIS
        Records an internal error for later reporting
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Module,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $errorEntry = [ordered]@{
        Timestamp = (Get-Date).ToString("o")
        Module = $Module
        Message = $Message
        Exception = if ($ErrorRecord) { $ErrorRecord.Exception.Message } else { $null }
        ScriptStackTrace = if ($ErrorRecord) { $ErrorRecord.ScriptStackTrace } else { $null }
    }

    [void]$Script:InternalErrors.Add($errorEntry)
    Write-Log -Message "$Module : $Message" -Level Error -ToErrorLog
}

function Test-IsElevated {
    <#
    .SYNOPSIS
        Tests if the current process is running with elevated privileges
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SafeCimInstance {
    <#
    .SYNOPSIS
        Safely retrieves CIM instances with error handling
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ClassName,

        [Parameter()]
        [string]$Namespace = "root/cimv2",

        [Parameter()]
        [string]$Filter,

        [Parameter()]
        [string[]]$Property
    )

    try {
        $params = @{
            ClassName = $ClassName
            Namespace = $Namespace
            ErrorAction = 'Stop'
        }
        if ($Filter) { $params.Filter = $Filter }
        if ($Property) { $params.Property = $Property }

        return Get-CimInstance @params
    }
    catch {
        Add-InternalError -Module "CIM" -Message "Failed to get $ClassName" -ErrorRecord $_
        return $null
    }
}

function Get-SafeCounter {
    <#
    .SYNOPSIS
        Safely retrieves performance counter with error handling
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Counter,

        [Parameter()]
        [int]$SampleInterval = 1,

        [Parameter()]
        [int]$MaxSamples = 1
    )

    try {
        return Get-Counter -Counter $Counter -SampleInterval $SampleInterval -MaxSamples $MaxSamples -ErrorAction Stop
    }
    catch {
        Add-InternalError -Module "Counter" -Message "Failed to get counter: $($Counter -join ', ')" -ErrorRecord $_
        return $null
    }
}

function Calculate-Statistics {
    <#
    .SYNOPSIS
        Calculates min, max, average statistics for a numeric array
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [double[]]$Values
    )

    if (-not $Values -or $Values.Count -eq 0) {
        return [ordered]@{
            Min = 0
            Max = 0
            Average = 0
            Count = 0
        }
    }

    $stats = $Values | Measure-Object -Minimum -Maximum -Average
    return [ordered]@{
        Min = [math]::Round($stats.Minimum, 2)
        Max = [math]::Round($stats.Maximum, 2)
        Average = [math]::Round($stats.Average, 2)
        Count = $stats.Count
    }
}

function Convert-BytesToReadable {
    <#
    .SYNOPSIS
        Converts bytes to human-readable format
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [double]$Bytes
    )

    $sizes = 'Bytes', 'KB', 'MB', 'GB', 'TB'
    $index = 0
    while ($Bytes -ge 1024 -and $index -lt $sizes.Count - 1) {
        $Bytes = $Bytes / 1024
        $index++
    }
    return "{0:N2} {1}" -f $Bytes, $sizes[$index]
}

function Get-HealthStatus {
    <#
    .SYNOPSIS
        Determines health status based on value and thresholds
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [double]$Value,

        [Parameter(Mandatory)]
        [double]$WarningThreshold,

        [Parameter(Mandatory)]
        [double]$CriticalThreshold,

        [Parameter()]
        [switch]$LowerIsBetter
    )

    if ($LowerIsBetter) {
        if ($Value -le $WarningThreshold) { return "Pass" }
        elseif ($Value -le $CriticalThreshold) { return "Warning" }
        else { return "Fail" }
    }
    else {
        if ($Value -ge $WarningThreshold) { return "Pass" }
        elseif ($Value -ge $CriticalThreshold) { return "Warning" }
        else { return "Fail" }
    }
}
#endregion

#region Module: System Information
function Get-SystemInformation {
    <#
    .SYNOPSIS
        Collects comprehensive hardware and system information
    #>
    [CmdletBinding()]
    param()

    Write-Log -Message "Collecting system information..." -Level Info

    $systemInfo = [ordered]@{
        CollectionTimestamp = (Get-Date).ToString("o")
        CPU = $null
        Memory = $null
        Disks = @()
        BIOS = $null
        TPM = $null
        OperatingSystem = $null
        Volumes = @()
    }

    # CPU Information
    Write-Host "    Collecting CPU info..." -NoNewline -ForegroundColor Gray
    try {
        $cpu = Get-SafeCimInstance -ClassName Win32_Processor
        if ($cpu) {
            $systemInfo.CPU = [ordered]@{
                Name = $cpu.Name
                Manufacturer = $cpu.Manufacturer
                Cores = $cpu.NumberOfCores
                LogicalProcessors = $cpu.NumberOfLogicalProcessors
                MaxClockSpeedMHz = $cpu.MaxClockSpeed
                CurrentClockSpeedMHz = $cpu.CurrentClockSpeed
                L2CacheSizeKB = $cpu.L2CacheSize
                L3CacheSizeKB = $cpu.L3CacheSize
                Architecture = switch ($cpu.Architecture) {
                    0 { "x86" }
                    5 { "ARM" }
                    9 { "x64" }
                    12 { "ARM64" }
                    default { "Unknown" }
                }
                VirtualizationEnabled = $cpu.VirtualizationFirmwareEnabled
            }
        }
        Write-Host " done" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "SystemInfo" -Message "Failed to get CPU info" -ErrorRecord $_
    }

    # Memory Information
    Write-Host "    Collecting memory info..." -NoNewline -ForegroundColor Gray
    try {
        $os = Get-SafeCimInstance -ClassName Win32_OperatingSystem
        $physMem = Get-SafeCimInstance -ClassName Win32_PhysicalMemory

        if ($os) {
            $totalPhysical = ($physMem | Measure-Object -Property Capacity -Sum).Sum
            $systemInfo.Memory = [ordered]@{
                TotalPhysicalGB = [math]::Round($totalPhysical / 1GB, 2)
                AvailableGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
                UsedGB = [math]::Round(($totalPhysical - ($os.FreePhysicalMemory * 1KB)) / 1GB, 2)
                UsedPercent = [math]::Round((1 - ($os.FreePhysicalMemory * 1KB / $totalPhysical)) * 100, 1)
                TotalVirtualGB = [math]::Round($os.TotalVirtualMemorySize / 1MB, 2)
                AvailableVirtualGB = [math]::Round($os.FreeVirtualMemory / 1MB, 2)
                MemoryModules = @($physMem | ForEach-Object {
                    [ordered]@{
                        Manufacturer = $_.Manufacturer
                        CapacityGB = [math]::Round($_.Capacity / 1GB, 2)
                        Speed = $_.Speed
                        FormFactor = $_.FormFactor
                    }
                })
            }
        }
        Write-Host " done" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "SystemInfo" -Message "Failed to get memory info" -ErrorRecord $_
    }

    # Disk Information
    Write-Host "    Collecting disk info..." -NoNewline -ForegroundColor Gray
    try {
        $disks = Get-SafeCimInstance -ClassName Win32_DiskDrive

        # Get all physical disks once for matching
        $physicalDisks = @{}
        try {
            Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
                $physicalDisks[$_.DeviceId] = $_
            }
        }
        catch {
            # Physical disk enumeration not available
        }

        $systemInfo.Disks = @($disks | ForEach-Object {
            $disk = $_
            $diskType = "Unknown"
            $healthStatus = "Unknown"

            # Try to get info from Get-PhysicalDisk (more reliable on modern systems)
            try {
                $physDisk = $physicalDisks[$disk.Index.ToString()]
                if (-not $physDisk) {
                    # Try matching by other methods
                    $physDisk = $physicalDisks.Values | Where-Object {
                        $_.FriendlyName -eq $disk.Model -or $_.SerialNumber -eq $disk.SerialNumber
                    } | Select-Object -First 1
                }

                if ($physDisk) {
                    $diskType = $physDisk.MediaType
                    if ($physDisk.BusType -eq "NVMe") {
                        $diskType = "NVMe SSD"
                    }
                    elseif ($diskType -eq "Unspecified" -or $diskType -eq 0) {
                        # Fallback to model name detection
                        if ($disk.Model -match "NVMe") { $diskType = "NVMe SSD" }
                        elseif ($disk.Model -match "SSD") { $diskType = "SSD" }
                        else { $diskType = "Unknown" }
                    }

                    # Use HealthStatus from Get-PhysicalDisk (works on NVMe and modern drives)
                    $healthStatus = $physDisk.HealthStatus
                    if ($healthStatus -eq "Healthy") {
                        $healthStatus = "Healthy"
                    }
                    elseif ($healthStatus -eq "Warning") {
                        $healthStatus = "Warning"
                    }
                    elseif ($healthStatus -eq "Unhealthy") {
                        $healthStatus = "Unhealthy - Check Drive"
                    }
                }
            }
            catch {
                # Fall back to model name detection
                if ($disk.Model -match "NVMe") { $diskType = "NVMe SSD" }
                elseif ($disk.Model -match "SSD") { $diskType = "SSD" }
                elseif ($disk.Model -match "HDD") { $diskType = "HDD" }
            }

            # If health status still unknown, try legacy SMART WMI (silently)
            if ($healthStatus -eq "Unknown") {
                try {
                    $smartData = Get-CimInstance -ClassName MSStorageDriver_FailurePredictStatus -Namespace "root/wmi" -ErrorAction SilentlyContinue |
                        Where-Object { $_.InstanceName -match [regex]::Escape($disk.PNPDeviceID) }
                    if ($smartData) {
                        $healthStatus = if ($smartData.PredictFailure) { "Warning - Failure Predicted" } else { "Healthy" }
                    }
                    else {
                        $healthStatus = "Not Available"
                    }
                }
                catch {
                    $healthStatus = "Not Available"
                }
            }

            [ordered]@{
                Model = $disk.Model
                SerialNumber = $disk.SerialNumber
                InterfaceType = $disk.InterfaceType
                MediaType = $diskType
                SizeGB = [math]::Round($disk.Size / 1GB, 2)
                Partitions = $disk.Partitions
                FirmwareRevision = $disk.FirmwareRevision
                Status = $disk.Status
                HealthStatus = $healthStatus
            }
        })
        Write-Host " done" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "SystemInfo" -Message "Failed to get disk info" -ErrorRecord $_
    }

    # BIOS Information
    Write-Host "    Collecting BIOS info..." -NoNewline -ForegroundColor Gray
    try {
        $bios = Get-SafeCimInstance -ClassName Win32_BIOS
        if ($bios) {
            $systemInfo.BIOS = [ordered]@{
                Manufacturer = $bios.Manufacturer
                Name = $bios.Name
                Version = $bios.SMBIOSBIOSVersion
                ReleaseDate = if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString("yyyy-MM-dd") } else { "Unknown" }
                SerialNumber = $bios.SerialNumber
            }
        }
        Write-Host " done" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "SystemInfo" -Message "Failed to get BIOS info" -ErrorRecord $_
    }

    # TPM Information
    Write-Host "    Collecting TPM info..." -NoNewline -ForegroundColor Gray
    try {
        $tpm = Get-SafeCimInstance -ClassName Win32_Tpm -Namespace "root/cimv2/Security/MicrosoftTpm"
        if ($tpm) {
            $systemInfo.TPM = [ordered]@{
                IsPresent = $true
                IsEnabled = $tpm.IsEnabled_InitialValue
                IsActivated = $tpm.IsActivated_InitialValue
                ManufacturerId = $tpm.ManufacturerId
                ManufacturerVersion = $tpm.ManufacturerVersion
                SpecVersion = $tpm.SpecVersion
            }
            Write-Host " done" -ForegroundColor Gray
        }
        else {
            $systemInfo.TPM = [ordered]@{
                IsPresent = $false
            }
            Write-Host " not present" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host " skipped" -ForegroundColor Yellow
        $systemInfo.TPM = [ordered]@{
            IsPresent = $false
            Error = "Unable to query TPM"
        }
    }

    # Operating System Information
    Write-Host "    Collecting OS info..." -NoNewline -ForegroundColor Gray
    try {
        $osInfo = Get-SafeCimInstance -ClassName Win32_OperatingSystem
        $cs = Get-SafeCimInstance -ClassName Win32_ComputerSystem

        if ($osInfo) {
            $uptime = (Get-Date) - $osInfo.LastBootUpTime
            $systemInfo.OperatingSystem = [ordered]@{
                Caption = $osInfo.Caption
                Version = $osInfo.Version
                BuildNumber = $osInfo.BuildNumber
                Architecture = $osInfo.OSArchitecture
                InstallDate = if ($osInfo.InstallDate) { $osInfo.InstallDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                LastBootTime = if ($osInfo.LastBootUpTime) { $osInfo.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                UptimeDays = [math]::Round($uptime.TotalDays, 2)
                UptimeFormatted = "{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
                SystemType = $cs.SystemType
                Manufacturer = $cs.Manufacturer
                Model = $cs.Model
                Domain = $cs.Domain
                DomainRole = switch ($cs.DomainRole) {
                    0 { "Standalone Workstation" }
                    1 { "Member Workstation" }
                    2 { "Standalone Server" }
                    3 { "Member Server" }
                    4 { "Backup Domain Controller" }
                    5 { "Primary Domain Controller" }
                    default { "Unknown" }
                }
            }
        }
        Write-Host " done" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "SystemInfo" -Message "Failed to get OS info" -ErrorRecord $_
    }

    # Volume Information
    Write-Host "    Collecting volume info..." -NoNewline -ForegroundColor Gray
    try {
        $volumes = Get-SafeCimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
        $systemInfo.Volumes = @($volumes | ForEach-Object {
            $freePercent = if ($_.Size -gt 0) { [math]::Round(($_.FreeSpace / $_.Size) * 100, 1) } else { 0 }
            [ordered]@{
                DriveLetter = $_.DeviceID
                Label = $_.VolumeName
                FileSystem = $_.FileSystem
                SizeGB = [math]::Round($_.Size / 1GB, 2)
                FreeSpaceGB = [math]::Round($_.FreeSpace / 1GB, 2)
                FreeSpacePercent = $freePercent
                HealthStatus = Get-HealthStatus -Value $freePercent -WarningThreshold 20 -CriticalThreshold 10
            }
        })
        Write-Host " done" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "SystemInfo" -Message "Failed to get volume info" -ErrorRecord $_
    }

    # Power Plan
    Write-Host "    Collecting power plan..." -NoNewline -ForegroundColor Gray
    try {
        $powerOutput = powercfg /getactivescheme 2>$null
        if ($powerOutput -match 'GUID:\s*(\S+)\s+\(([^)]+)\)') {
            $planGuid = $matches[1]
            $planName = $matches[2]

            # Determine if power plan might throttle performance
            $isHighPerformance = $planName -match 'High performance|Ultimate'
            $isPowerSaver = $planName -match 'Power saver'

            $systemInfo.PowerPlan = [ordered]@{
                Name = $planName
                GUID = $planGuid
                HealthStatus = if ($isPowerSaver) { "Warning" } elseif ($isHighPerformance) { "Pass" } else { "Pass" }
                Note = if ($isPowerSaver) { "Power Saver mode throttles CPU performance" } else { $null }
            }
        } else {
            $systemInfo.PowerPlan = [ordered]@{
                Name = "Unknown"
                GUID = $null
                HealthStatus = "Unknown"
            }
        }
        Write-Host " done" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "SystemInfo" -Message "Failed to get power plan" -ErrorRecord $_
    }

    # Problem Devices (devices with errors in Device Manager)
    Write-Host "    Checking for problem devices..." -NoNewline -ForegroundColor Gray
    try {
        $problemDevices = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue |
            Where-Object { $_.ConfigManagerErrorCode -ne 0 } |
            Select-Object Name, DeviceID, ConfigManagerErrorCode, Status

        $errorCodeDescriptions = @{
            1 = "Device not configured correctly"
            3 = "Driver may be corrupted"
            10 = "Device cannot start"
            12 = "Not enough free resources"
            14 = "Device requires restart"
            18 = "Reinstall drivers"
            19 = "Registry problem"
            21 = "Windows is removing device"
            22 = "Device is disabled"
            24 = "Device not present"
            28 = "Drivers not installed"
            29 = "Device disabled by firmware"
            31 = "Device not working properly"
            32 = "Driver service disabled"
            33 = "Cannot determine required resources"
            34 = "Cannot determine required resources"
            35 = "Firmware missing resource information"
            36 = "IRQ conflict"
            37 = "Driver cannot initialize"
            38 = "Driver previously crashed"
            39 = "Driver corrupted or missing"
            40 = "Registry service key missing"
            41 = "Unknown device"
            42 = "Duplicate device"
            43 = "Driver failure"
            44 = "Stopped by another device"
            45 = "Device not connected"
            46 = "Device unavailable (shutting down)"
            47 = "Needs safe removal"
            48 = "Driver blocked"
            49 = "Registry too large"
            52 = "Driver not signed"
        }

        $systemInfo.ProblemDevices = @($problemDevices | ForEach-Object {
            [ordered]@{
                Name = $_.Name
                DeviceID = $_.DeviceID
                ErrorCode = $_.ConfigManagerErrorCode
                ErrorDescription = $errorCodeDescriptions[[int]$_.ConfigManagerErrorCode]
                Status = $_.Status
            }
        })

        $count = $systemInfo.ProblemDevices.Count
        Write-Host " found $count" -ForegroundColor $(if ($count -gt 0) { "Yellow" } else { "Gray" })
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "SystemInfo" -Message "Failed to check problem devices" -ErrorRecord $_
    }

    Write-Log -Message "System information collection complete" -Level Success
    return $systemInfo
}
#endregion

#region Module: Performance Sampling
function Get-PerformanceSampling {
    <#
    .SYNOPSIS
        Collects 60-second performance samples for key metrics
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$Duration = $Script:Config.SampleDuration,

        [Parameter()]
        [int]$Interval = $Script:Config.SampleInterval
    )

    Write-Log -Message "Starting $Duration-second performance sampling (interval: ${Interval}s)..." -Level Info

    $perfData = [ordered]@{
        SamplingStartTime = (Get-Date).ToString("o")
        SamplingEndTime = $null
        DurationSeconds = $Duration
        IntervalSeconds = $Interval
        TotalSamples = 0
        CPU = [ordered]@{
            ProcessorTime = @()
            ProcessorQueueLength = @()
            Statistics = $null
        }
        Memory = [ordered]@{
            AvailableMB = @()
            CommittedBytes = @()
            HardFaultsPerSec = @()
            Statistics = $null
        }
        Disk = [ordered]@{
            ReadLatency = @()
            WriteLatency = @()
            QueueLength = @()
            Statistics = $null
        }
        Network = [ordered]@{
            AdapterMetrics = @{}
            Statistics = $null
        }
        InterruptDPC = [ordered]@{
            DPCTime = @()
            InterruptTime = @()
            Statistics = $null
        }
        PeakProcesses = @{
            ByCPU = @()
            ByMemory = @()
            ByDiskIO = @()
        }
    }

    # Define counters to collect
    $counters = @(
        '\Processor(_Total)\% Processor Time',
        '\Processor(_Total)\% DPC Time',
        '\Processor(_Total)\% Interrupt Time',
        '\System\Processor Queue Length',
        '\Memory\Available MBytes',
        '\Memory\Committed Bytes',
        '\Memory\Page Faults/sec',
        '\PhysicalDisk(_Total)\Avg. Disk sec/Read',
        '\PhysicalDisk(_Total)\Avg. Disk sec/Write',
        '\PhysicalDisk(_Total)\Current Disk Queue Length'
    )

    # Get network adapters
    # Note: Performance counter instance names use different character encoding than Get-NetAdapter
    # (e.g., counters use "Intel[R]" while NetAdapter uses "Intel(R)")
    # So we get the actual counter instance names from the counter set
    try {
        $counterSet = Get-Counter -ListSet 'Network Interface' -ErrorAction SilentlyContinue
        $counterInstances = $counterSet.PathsWithInstances | ForEach-Object {
            if ($_ -match '\\Network Interface\((.+)\)\\') { $matches[1] }
        } | Select-Object -Unique

        # Get active physical adapters to filter the counter instances
        $activeAdapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq 'Up' } |
            Select-Object -ExpandProperty InterfaceDescription

        foreach ($instance in $counterInstances) {
            # Check if this counter instance matches an active adapter (fuzzy match due to character differences)
            $isActive = $false
            $friendlyName = $instance
            foreach ($adapter in (Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
                # Compare without special characters to handle [R] vs (R) differences
                $normalizedInstance = $instance -replace '[\[\]\(\)]', ''
                $normalizedAdapter = $adapter.InterfaceDescription -replace '[\[\]\(\)]', ''
                if ($normalizedInstance -eq $normalizedAdapter) {
                    $isActive = $true
                    $friendlyName = $adapter.Name
                    break
                }
            }

            if ($isActive) {
                $counters += "\Network Interface($instance)\Bytes Total/sec"
                $counters += "\Network Interface($instance)\Packets Received Errors"
                $perfData.Network.AdapterMetrics[$friendlyName] = @{
                    BytesPerSec = @()
                    Errors = @()
                    CounterInstanceName = $instance
                }
            }
        }
    }
    catch {
        Add-InternalError -Module "PerfSampling" -Message "Failed to enumerate network adapters" -ErrorRecord $_
    }

    # Sampling loop
    $samples = [math]::Floor($Duration / $Interval)
    $sampleCount = 0
    $startTime = Get-Date

    # Track peak processes
    $cpuSamples = @{}
    $memorySamples = @{}

    # Progress bar settings
    $progressBarWidth = 40
    $lastProgressUpdate = -1

    for ($i = 0; $i -lt $samples; $i++) {
        $progress = [math]::Round((($i + 1) / $samples) * 100)
        $elapsedSeconds = $Interval * ($i + 1)
        $remainingSeconds = $Duration - $elapsedSeconds

        # Update console progress bar (only when percentage changes to reduce flicker)
        if ($progress -ne $lastProgressUpdate) {
            $filledWidth = [math]::Floor($progressBarWidth * $progress / 100)
            $emptyWidth = $progressBarWidth - $filledWidth
            $progressBar = "[" + ("#" * $filledWidth) + ("-" * $emptyWidth) + "]"
            $statusLine = "`r    $progressBar $progress% | Sample $($i+1)/$samples | ${remainingSeconds}s remaining"
            Write-Host $statusLine -NoNewline -ForegroundColor Cyan
            $lastProgressUpdate = $progress
        }

        # Also update Write-Progress for terminals that support it
        Write-Progress -Activity "Collecting Performance Samples" -Status "$progress% Complete - Sample $($i+1) of $samples" -PercentComplete $progress

        try {
            # Get counter data
            $counterData = Get-Counter -Counter $counters -ErrorAction SilentlyContinue

            if ($counterData) {
                foreach ($sample in $counterData.CounterSamples) {
                    $path = $sample.Path
                    $value = $sample.CookedValue

                    switch -Regex ($path) {
                        '% Processor Time' { $perfData.CPU.ProcessorTime += [math]::Round($value, 2) }
                        '% DPC Time' { $perfData.InterruptDPC.DPCTime += [math]::Round($value, 2) }
                        '% Interrupt Time' { $perfData.InterruptDPC.InterruptTime += [math]::Round($value, 2) }
                        'Processor Queue Length' { $perfData.CPU.ProcessorQueueLength += [math]::Round($value, 2) }
                        'Available MBytes' { $perfData.Memory.AvailableMB += [math]::Round($value, 2) }
                        'Committed Bytes' { $perfData.Memory.CommittedBytes += [math]::Round($value / 1GB, 2) }
                        'Page Faults/sec' { $perfData.Memory.HardFaultsPerSec += [math]::Round($value, 2) }
                        'Avg. Disk sec/Read' { $perfData.Disk.ReadLatency += [math]::Round($value * 1000, 3) }
                        'Avg. Disk sec/Write' { $perfData.Disk.WriteLatency += [math]::Round($value * 1000, 3) }
                        'Current Disk Queue Length' { $perfData.Disk.QueueLength += [math]::Round($value, 2) }
                        'Bytes Total/sec' {
                            foreach ($adapter in $perfData.Network.AdapterMetrics.Keys) {
                                $counterInstance = $perfData.Network.AdapterMetrics[$adapter].CounterInstanceName
                                if ($path -match [regex]::Escape($counterInstance)) {
                                    $perfData.Network.AdapterMetrics[$adapter].BytesPerSec += [math]::Round($value / 1MB, 3)
                                }
                            }
                        }
                        'Packets Received Errors' {
                            foreach ($adapter in $perfData.Network.AdapterMetrics.Keys) {
                                $counterInstance = $perfData.Network.AdapterMetrics[$adapter].CounterInstanceName
                                if ($path -match [regex]::Escape($counterInstance)) {
                                    $perfData.Network.AdapterMetrics[$adapter].Errors += [math]::Round($value, 0)
                                }
                            }
                        }
                    }
                }
                $sampleCount++
            }

            # Sample processes for peak tracking (every 4th sample to reduce overhead)
            if ($i % 4 -eq 0) {
                $procs = Get-Process -ErrorAction SilentlyContinue |
                    Where-Object { $_.Id -ne 0 -and $_.ProcessName -ne 'Idle' }

                foreach ($proc in $procs) {
                    $name = $proc.ProcessName
                    if (-not $cpuSamples.ContainsKey($name)) {
                        $cpuSamples[$name] = @{ CPU = 0; Count = 0 }
                        $memorySamples[$name] = @{ Memory = 0; Count = 0 }
                    }
                    $cpuSamples[$name].CPU += $proc.CPU
                    $cpuSamples[$name].Count++
                    $memorySamples[$name].Memory += $proc.WorkingSet64
                    $memorySamples[$name].Count++
                }
            }
        }
        catch {
            Add-InternalError -Module "PerfSampling" -Message "Error during sample $i" -ErrorRecord $_
        }

        Start-Sleep -Seconds $Interval
    }

    # Clear progress indicators
    Write-Host ""  # New line after progress bar
    Write-Progress -Activity "Collecting Performance Samples" -Completed

    $perfData.SamplingEndTime = (Get-Date).ToString("o")
    $perfData.TotalSamples = $sampleCount

    # Calculate statistics
    $perfData.CPU.Statistics = [ordered]@{
        ProcessorTime = Calculate-Statistics -Values $perfData.CPU.ProcessorTime
        ProcessorQueueLength = Calculate-Statistics -Values $perfData.CPU.ProcessorQueueLength
    }

    $perfData.Memory.Statistics = [ordered]@{
        AvailableMB = Calculate-Statistics -Values $perfData.Memory.AvailableMB
        CommittedBytesGB = Calculate-Statistics -Values $perfData.Memory.CommittedBytes
        HardFaultsPerSec = Calculate-Statistics -Values $perfData.Memory.HardFaultsPerSec
    }

    $perfData.Disk.Statistics = [ordered]@{
        ReadLatencyMs = Calculate-Statistics -Values $perfData.Disk.ReadLatency
        WriteLatencyMs = Calculate-Statistics -Values $perfData.Disk.WriteLatency
        QueueLength = Calculate-Statistics -Values $perfData.Disk.QueueLength
    }

    # Network statistics per adapter
    $networkStats = [ordered]@{}
    foreach ($adapter in $perfData.Network.AdapterMetrics.Keys) {
        $networkStats[$adapter] = [ordered]@{
            BytesPerSecMB = Calculate-Statistics -Values $perfData.Network.AdapterMetrics[$adapter].BytesPerSec
            Errors = Calculate-Statistics -Values $perfData.Network.AdapterMetrics[$adapter].Errors
        }
    }
    $perfData.Network.Statistics = $networkStats

    # Interrupt/DPC statistics
    $perfData.InterruptDPC.Statistics = [ordered]@{
        DPCTime = Calculate-Statistics -Values $perfData.InterruptDPC.DPCTime
        InterruptTime = Calculate-Statistics -Values $perfData.InterruptDPC.InterruptTime
        CombinedTime = Calculate-Statistics -Values @(
            for ($j = 0; $j -lt [math]::Min($perfData.InterruptDPC.DPCTime.Count, $perfData.InterruptDPC.InterruptTime.Count); $j++) {
                $perfData.InterruptDPC.DPCTime[$j] + $perfData.InterruptDPC.InterruptTime[$j]
            }
        )
    }

    # Calculate peak processes
    $perfData.PeakProcesses.ByCPU = @($cpuSamples.GetEnumerator() |
        Sort-Object { $_.Value.CPU } -Descending |
        Select-Object -First 5 |
        ForEach-Object {
            [ordered]@{
                ProcessName = $_.Key
                TotalCPUSeconds = [math]::Round($_.Value.CPU, 2)
            }
        })

    $perfData.PeakProcesses.ByMemory = @($memorySamples.GetEnumerator() |
        Sort-Object { $_.Value.Memory / $_.Value.Count } -Descending |
        Select-Object -First 5 |
        ForEach-Object {
            [ordered]@{
                ProcessName = $_.Key
                AverageMemoryMB = [math]::Round(($_.Value.Memory / $_.Value.Count) / 1MB, 2)
            }
        })

    Write-Log -Message "Performance sampling complete ($sampleCount samples collected)" -Level Success
    return $perfData
}
#endregion

#region Module: Process Analysis
function Get-ProcessAnalysis {
    <#
    .SYNOPSIS
        Analyzes running processes for resource consumption and issues
    #>
    [CmdletBinding()]
    param()

    Write-Log -Message "Analyzing processes..." -Level Info

    $processData = [ordered]@{
        CollectionTimestamp = (Get-Date).ToString("o")
        TotalProcessCount = 0
        TotalThreadCount = 0
        TotalHandleCount = 0
        TopByCPU = @()
        TopByMemory = @()
        TopByDiskIO = @()
        Observations = @()
    }

    try {
        Write-Host "    Enumerating processes..." -NoNewline -ForegroundColor Gray

        # Get all processes with detailed info
        $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne 0 }

        $processData.TotalProcessCount = $processes.Count
        $processData.TotalThreadCount = ($processes | ForEach-Object { $_.Threads.Count } | Measure-Object -Sum).Sum
        $processData.TotalHandleCount = ($processes | Measure-Object -Property HandleCount -Sum).Sum

        Write-Host " found $($processes.Count) processes" -ForegroundColor Gray

        # Top 10 by CPU
        Write-Host "    Analyzing CPU usage..." -NoNewline -ForegroundColor Gray
        $processData.TopByCPU = @($processes |
            Sort-Object CPU -Descending |
            Select-Object -First 10 |
            ForEach-Object {
                [ordered]@{
                    Name = $_.ProcessName
                    PID = $_.Id
                    CPUSeconds = [math]::Round($_.CPU, 2)
                    ThreadCount = $_.Threads.Count
                    HandleCount = $_.HandleCount
                    StartTime = if ($_.StartTime) { $_.StartTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                }
            })
        Write-Host " done" -ForegroundColor Gray

        # Top 10 by Memory
        Write-Host "    Analyzing memory usage..." -NoNewline -ForegroundColor Gray
        $processData.TopByMemory = @($processes |
            Sort-Object WorkingSet64 -Descending |
            Select-Object -First 10 |
            ForEach-Object {
                [ordered]@{
                    Name = $_.ProcessName
                    PID = $_.Id
                    WorkingSetMB = [math]::Round($_.WorkingSet64 / 1MB, 2)
                    PrivateMemoryMB = [math]::Round($_.PrivateMemorySize64 / 1MB, 2)
                    VirtualMemoryMB = [math]::Round($_.VirtualMemorySize64 / 1MB, 2)
                }
            })
        Write-Host " done" -ForegroundColor Gray

        # Get disk IO using process properties (fast method)
        Write-Host "    Analyzing disk I/O..." -NoNewline -ForegroundColor Gray
        try {
            # Filter out processes with null IO counts before sorting
            $processData.TopByDiskIO = @($processes |
                Where-Object { $null -ne $_.ReadOperationCount -and $null -ne $_.WriteOperationCount } |
                Sort-Object { $_.ReadOperationCount + $_.WriteOperationCount } -Descending -ErrorAction SilentlyContinue |
                Select-Object -First 10 |
                ForEach-Object {
                    [ordered]@{
                        Name = $_.ProcessName
                        PID = $_.Id
                        ReadOperations = $_.ReadOperationCount
                        WriteOperations = $_.WriteOperationCount
                        TotalIOOperations = $_.ReadOperationCount + $_.WriteOperationCount
                    }
                })
            Write-Host " done" -ForegroundColor Gray
        }
        catch {
            Write-Host " skipped" -ForegroundColor Yellow
            Add-InternalError -Module "ProcessAnalysis" -Message "Failed to get disk IO metrics" -ErrorRecord $_
        }

        # Identify potential issues with actionable context
        # Each issue includes: What happened, Why it matters, What to do about it
        Write-Host "    Analyzing for actionable issues..." -NoNewline -ForegroundColor Gray
        $issues = [System.Collections.ArrayList]::new()

        # Browser resource consumption - only flag if truly excessive
        # Research shows: ~1GB/10 tabs is normal, 3-5GB with extensions is typical
        # Process count is NOT a meaningful metric (varies by extensions, tabs, site isolation)
        # Only flag if: >8GB (suggests memory leak) OR >50% of system RAM (competing for resources)
        $browsers = @{
            'msedge' = 'Microsoft Edge'
            'chrome' = 'Google Chrome'
            'firefox' = 'Firefox'
        }

        $totalSystemMemoryGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
        $browserMemoryThresholdGB = [math]::Max(8, $totalSystemMemoryGB * 0.5)  # Whichever is higher

        foreach ($browserProc in $browsers.Keys) {
            $browserProcesses = $processes | Where-Object { $_.ProcessName -eq $browserProc }
            if ($browserProcesses.Count -gt 0) {
                $totalMemoryGB = [math]::Round(($browserProcesses | Measure-Object -Property WorkingSet64 -Sum).Sum / 1GB, 2)
                $processCount = $browserProcesses.Count
                $memoryPercent = [math]::Round(($totalMemoryGB / $totalSystemMemoryGB) * 100, 1)

                # Only flag if browser memory is truly excessive (>8GB or >50% of system RAM)
                if ($totalMemoryGB -gt $browserMemoryThresholdGB) {
                    [void]$issues.Add([ordered]@{
                        Category = "Browser Resource Usage"
                        Process = $browsers[$browserProc]
                        What = "$($browsers[$browserProc]) is using $totalMemoryGB GB of memory ($memoryPercent% of system RAM)"
                        Why = "Browser memory usage this high suggests a possible memory leak, excessive tabs, or problematic extensions"
                        Action = "Restart the browser to clear memory. If it quickly grows again, investigate extensions or consider memory-saver features"
                        EnvironmentalNote = "If seen frequently, investigate browser policies, extension whitelists, or consider deploying browser memory-saver settings"
                        Severity = if ($totalMemoryGB -gt 12 -or $memoryPercent -gt 60) { "High" } else { "Medium" }
                    })
                }
            }
        }

        # Individual high memory applications (excluding browsers, handled above)
        $highMemApps = $processes | Where-Object {
            $_.WorkingSet64 -gt 2GB -and
            $_.ProcessName -notin @('msedge', 'chrome', 'firefox', 'Memory Compression', 'vmmem')
        }
        foreach ($proc in $highMemApps) {
            $memGB = [math]::Round($proc.WorkingSet64 / 1GB, 2)
            $friendlyName = $proc.ProcessName

            # Provide context based on known applications
            $context = switch -Wildcard ($proc.ProcessName) {
                'Teams*' { @{ Why = "Microsoft Teams is known to consume significant memory, especially with many chats/channels open"; Action = "Restart Teams, or reduce number of open chats and channels" } }
                'Outlook*' { @{ Why = "Outlook memory usage grows with mailbox size and open windows"; Action = "Restart Outlook, archive old emails, or reduce open windows" } }
                '*studio*' { @{ Why = "Development tools often require significant memory for projects and debugging"; Action = "This may be normal for development work; close if not actively needed" } }
                'MsMpEng' { @{ Why = "Windows Defender is performing intensive scanning operations"; Action = "Wait for scan to complete, or check if a full scan is running" } }
                default { @{ Why = "This application is using more memory than typical"; Action = "Restart the application if performance is impacted" } }
            }

            [void]$issues.Add([ordered]@{
                Category = "High Memory Application"
                Process = $friendlyName
                What = "$friendlyName is using $memGB GB of memory"
                Why = $context.Why
                Action = $context.Action
                EnvironmentalNote = "If this application consistently uses high memory across machines, consider updating it or reviewing its configuration"
                Severity = if ($memGB -gt 4) { "High" } else { "Medium" }
            })
        }

        # Check for Windows Update activity (common cause of background slowness)
        $wuProcesses = $processes | Where-Object { $_.ProcessName -in @('TiWorker', 'TrustedInstaller', 'wuauclt') }
        if ($wuProcesses.Count -gt 0) {
            [void]$issues.Add([ordered]@{
                Category = "System Maintenance"
                Process = "Windows Update"
                What = "Windows Update processes are actively running"
                Why = "Windows Update can cause temporary slowness while downloading or installing updates"
                Action = "This is normal maintenance. If urgent, the user can continue working and updates will complete in the background"
                EnvironmentalNote = "If updates consistently cause issues, review update deployment schedules and maintenance windows"
                Severity = "Info"
            })
        }

        # Check for active antivirus scanning (accurate detection via Defender status)
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($defenderStatus) {
                $scanType = $null
                if ($defenderStatus.FullScanInProgress) {
                    $scanType = "full"
                } elseif ($defenderStatus.QuickScanInProgress) {
                    $scanType = "quick"
                }

                if ($scanType) {
                    [void]$issues.Add([ordered]@{
                        Category = "Security Scanning"
                        Process = "Windows Defender"
                        What = "Windows Defender is currently running a $scanType scan"
                        Why = "Active scans increase CPU and disk usage, which can cause temporary system slowness"
                        Action = "The scan will complete automatically. If urgent, the user can pause the scan in Windows Security settings"
                        EnvironmentalNote = "If scans frequently cause slowness complaints, review scan schedules and consider adding exclusions for known-safe paths"
                        Severity = "Info"
                    })
                }
            }
        }
        catch {
            # Silently continue if we can't query Defender status
        }

        # Check for elevated DPC/ISR time (indicates driver issues)
        # This data comes from performance sampling which runs before process analysis
        if ($Script:Results.PerformanceSampling.InterruptDPC.Statistics.CombinedTime.Average) {
            $combinedDpcIsr = $Script:Results.PerformanceSampling.InterruptDPC.Statistics.CombinedTime.Average
            if ($combinedDpcIsr -gt 15) {
                $severity = if ($combinedDpcIsr -gt 30) { "High" } else { "Medium" }
                [void]$issues.Add([ordered]@{
                    Category = "Driver/Hardware Issue"
                    Process = "System Drivers"
                    What = "Combined DPC/Interrupt time is $([math]::Round($combinedDpcIsr, 1))% (threshold: 15%)"
                    Why = "High DPC/ISR time means device drivers are consuming excessive CPU for interrupt processing, causing system-wide slowness. This typically indicates a problematic driver or hardware device."
                    Action = "Check Device Manager for problem devices. Review recently installed drivers/hardware. Use Windows Performance Recorder (WPR) or LatencyMon to identify the specific driver."
                    EnvironmentalNote = "If seen across multiple machines with similar hardware, investigate common drivers (network, audio, USB). Consider driver rollback or updates from hardware vendors."
                    Severity = $severity
                })
            }
        }

        $processData.Observations = @($issues)
        Write-Host " found $($issues.Count) observations" -ForegroundColor Gray
    }
    catch {
        Add-InternalError -Module "ProcessAnalysis" -Message "Failed to analyze processes" -ErrorRecord $_
    }

    Write-Log -Message "Process analysis complete" -Level Success
    return $processData
}
#endregion

#region Module: Browser Analysis
function Get-BrowserAnalysis {
    <#
    .SYNOPSIS
        Analyzes Chrome and Edge browser resource usage
    #>
    [CmdletBinding()]
    param()

    Write-Log -Message "Analyzing browsers..." -Level Info

    $browserData = [ordered]@{
        CollectionTimestamp = (Get-Date).ToString("o")
        Chrome = $null
        Edge = $null
    }

    # Chrome Analysis
    Write-Host "    Checking Chrome..." -NoNewline -ForegroundColor Gray
    try {
        $chromeProcesses = Get-Process -Name "chrome" -ErrorAction SilentlyContinue
        if ($chromeProcesses) {
            $totalMemory = ($chromeProcesses | Measure-Object -Property WorkingSet64 -Sum).Sum
            $gpuProcess = $chromeProcesses | Where-Object { $_.MainWindowTitle -eq '' } |
                Sort-Object WorkingSet64 -Descending | Select-Object -First 1

            $browserData.Chrome = [ordered]@{
                IsRunning = $true
                ProcessCount = $chromeProcesses.Count
                TotalMemoryMB = [math]::Round($totalMemory / 1MB, 2)
                AverageMemoryPerProcessMB = [math]::Round(($totalMemory / $chromeProcesses.Count) / 1MB, 2)
                GPUProcessMemoryMB = if ($gpuProcess) { [math]::Round($gpuProcess.WorkingSet64 / 1MB, 2) } else { 0 }
                Processes = @($chromeProcesses | ForEach-Object {
                    [ordered]@{
                        PID = $_.Id
                        MemoryMB = [math]::Round($_.WorkingSet64 / 1MB, 2)
                        CPU = [math]::Round($_.CPU, 2)
                    }
                } | Sort-Object MemoryMB -Descending | Select-Object -First 10)
            }

            # Try to enumerate extensions with names
            try {
                $chromeExtPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
                if (Test-Path $chromeExtPath) {
                    $extensionDirs = Get-ChildItem -Path $chromeExtPath -Directory -ErrorAction SilentlyContinue
                    $browserData.Chrome.ExtensionCount = $extensionDirs.Count
                    $extensionList = [System.Collections.ArrayList]::new()

                    foreach ($extDir in $extensionDirs) {
                        # Each extension has version subdirectories, get the latest
                        $versionDir = Get-ChildItem -Path $extDir.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
                        if ($versionDir) {
                            $manifestPath = Join-Path $versionDir.FullName "manifest.json"
                            if (Test-Path $manifestPath) {
                                try {
                                    $manifest = Get-Content -Path $manifestPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                                    if ($manifest.name) {
                                        # Handle localized names (start with __)
                                        $extName = $manifest.name
                                        if ($extName -match '^__MSG_(.+)__$') {
                                            # Try to get localized name from _locales
                                            $localePath = Join-Path $versionDir.FullName "_locales\en\messages.json"
                                            if (Test-Path $localePath) {
                                                $localeData = Get-Content -Path $localePath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                                                $msgKey = $matches[1]
                                                if ($localeData.$msgKey.message) {
                                                    $extName = $localeData.$msgKey.message
                                                }
                                            }
                                        }
                                        [void]$extensionList.Add([ordered]@{
                                            Name = $extName
                                            Version = $manifest.version
                                            Description = if ($manifest.description -and $manifest.description -notmatch '^__MSG_') { $manifest.description.Substring(0, [Math]::Min(100, $manifest.description.Length)) } else { $null }
                                        })
                                    }
                                }
                                catch {
                                    # Skip extensions we can't parse
                                }
                            }
                        }
                    }
                    $browserData.Chrome.Extensions = @($extensionList | Sort-Object Name)
                }
            }
            catch {
                $browserData.Chrome.ExtensionCount = "Unable to determine"
            }
            Write-Host " running ($($chromeProcesses.Count) processes)" -ForegroundColor Gray
        }
        else {
            $browserData.Chrome = [ordered]@{
                IsRunning = $false
                ProcessCount = 0
                TotalMemoryMB = 0
            }
            Write-Host " not running" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "BrowserAnalysis" -Message "Failed to analyze Chrome" -ErrorRecord $_
        $browserData.Chrome = [ordered]@{ IsRunning = $false; Error = "Analysis failed" }
    }

    # Edge Analysis
    Write-Host "    Checking Edge..." -NoNewline -ForegroundColor Gray
    try {
        $edgeProcesses = Get-Process -Name "msedge" -ErrorAction SilentlyContinue
        if ($edgeProcesses) {
            $totalMemory = ($edgeProcesses | Measure-Object -Property WorkingSet64 -Sum).Sum
            $gpuProcess = $edgeProcesses | Where-Object { $_.MainWindowTitle -eq '' } |
                Sort-Object WorkingSet64 -Descending | Select-Object -First 1

            $browserData.Edge = [ordered]@{
                IsRunning = $true
                ProcessCount = $edgeProcesses.Count
                TotalMemoryMB = [math]::Round($totalMemory / 1MB, 2)
                AverageMemoryPerProcessMB = [math]::Round(($totalMemory / $edgeProcesses.Count) / 1MB, 2)
                GPUProcessMemoryMB = if ($gpuProcess) { [math]::Round($gpuProcess.WorkingSet64 / 1MB, 2) } else { 0 }
                Processes = @($edgeProcesses | ForEach-Object {
                    [ordered]@{
                        PID = $_.Id
                        MemoryMB = [math]::Round($_.WorkingSet64 / 1MB, 2)
                        CPU = [math]::Round($_.CPU, 2)
                    }
                } | Sort-Object MemoryMB -Descending | Select-Object -First 10)
            }

            # Try to enumerate extensions with names
            try {
                $edgeExtPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
                if (Test-Path $edgeExtPath) {
                    $extensionDirs = Get-ChildItem -Path $edgeExtPath -Directory -ErrorAction SilentlyContinue
                    $browserData.Edge.ExtensionCount = $extensionDirs.Count
                    $extensionList = [System.Collections.ArrayList]::new()

                    foreach ($extDir in $extensionDirs) {
                        # Each extension has version subdirectories, get the latest
                        $versionDir = Get-ChildItem -Path $extDir.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
                        if ($versionDir) {
                            $manifestPath = Join-Path $versionDir.FullName "manifest.json"
                            if (Test-Path $manifestPath) {
                                try {
                                    $manifest = Get-Content -Path $manifestPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                                    if ($manifest.name) {
                                        # Handle localized names (start with __)
                                        $extName = $manifest.name
                                        if ($extName -match '^__MSG_(.+)__$') {
                                            # Try to get localized name from _locales
                                            $localePath = Join-Path $versionDir.FullName "_locales\en\messages.json"
                                            if (Test-Path $localePath) {
                                                $localeData = Get-Content -Path $localePath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                                                $msgKey = $matches[1]
                                                if ($localeData.$msgKey.message) {
                                                    $extName = $localeData.$msgKey.message
                                                }
                                            }
                                        }
                                        [void]$extensionList.Add([ordered]@{
                                            Name = $extName
                                            Version = $manifest.version
                                            Description = if ($manifest.description -and $manifest.description -notmatch '^__MSG_') { $manifest.description.Substring(0, [Math]::Min(100, $manifest.description.Length)) } else { $null }
                                        })
                                    }
                                }
                                catch {
                                    # Skip extensions we can't parse
                                }
                            }
                        }
                    }
                    $browserData.Edge.Extensions = @($extensionList | Sort-Object Name)
                }
            }
            catch {
                $browserData.Edge.ExtensionCount = "Unable to determine"
            }
            Write-Host " running ($($edgeProcesses.Count) processes)" -ForegroundColor Gray
        }
        else {
            $browserData.Edge = [ordered]@{
                IsRunning = $false
                ProcessCount = 0
                TotalMemoryMB = 0
            }
            Write-Host " not running" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "BrowserAnalysis" -Message "Failed to analyze Edge" -ErrorRecord $_
        $browserData.Edge = [ordered]@{ IsRunning = $false; Error = "Analysis failed" }
    }

    Write-Log -Message "Browser analysis complete" -Level Success
    return $browserData
}
#endregion

#region Module: Configuration Health
function Get-ConfigurationHealth {
    <#
    .SYNOPSIS
        Checks system configuration and policy health
    #>
    [CmdletBinding()]
    param()

    Write-Log -Message "Checking configuration health..." -Level Info

    $configData = [ordered]@{
        CollectionTimestamp = (Get-Date).ToString("o")
        PendingReboot = $null
        RecentlyInstalled = $null
        PageFile = $null
        WindowsUpdate = $null
        IntuneEnrollment = $null
        CompanyPortal = $null
        GPOCheck = $null
        UserProfile = $null
    }

    # Pending Reboot Detection
    Write-Host "    Checking pending reboot..." -NoNewline -ForegroundColor Gray
    try {
        $rebootRequired = $false
        $rebootReasons = [System.Collections.ArrayList]::new()

        # Check Component Based Servicing
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            $rebootRequired = $true
            [void]$rebootReasons.Add("Component Based Servicing (CBS) has pending operations")
        }

        # Check Windows Update
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
            $rebootRequired = $true
            [void]$rebootReasons.Add("Windows Update requires a reboot")
        }

        # Check Pending File Rename Operations
        $pendingFileRename = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($pendingFileRename.PendingFileRenameOperations) {
            $rebootRequired = $true
            [void]$rebootReasons.Add("Pending file rename operations")
        }

        # Check Computer Rename Pending
        $activeComputerName = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -Name "ComputerName" -ErrorAction SilentlyContinue
        $pendingComputerName = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" -Name "ComputerName" -ErrorAction SilentlyContinue
        if ($activeComputerName.ComputerName -ne $pendingComputerName.ComputerName) {
            $rebootRequired = $true
            [void]$rebootReasons.Add("Computer rename pending")
        }

        # Check SCCM Client (if installed)
        try {
            $sccmReboot = Invoke-CimMethod -Namespace "root\ccm\ClientSDK" -ClassName "CCM_ClientUtilities" -MethodName "DetermineIfRebootPending" -ErrorAction SilentlyContinue
            if ($sccmReboot -and $sccmReboot.RebootPending) {
                $rebootRequired = $true
                [void]$rebootReasons.Add("SCCM client reports reboot pending")
            }
        }
        catch {
            # SCCM not installed, ignore
        }

        $configData.PendingReboot = [ordered]@{
            IsRebootPending = $rebootRequired
            Reasons = @($rebootReasons)
            HealthStatus = if ($rebootRequired) { "Warning" } else { "Pass" }
        }

        if ($rebootRequired) {
            Write-Host " REBOOT NEEDED" -ForegroundColor Yellow
        }
        else {
            Write-Host " none" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "ConfigHealth" -Message "Failed to check pending reboot" -ErrorRecord $_
    }

    # Recently Installed Software/Updates (Last 7 Days)
    Write-Host "    Checking recent installations..." -NoNewline -ForegroundColor Gray
    try {
        $sevenDaysAgo = (Get-Date).AddDays(-7)
        $recentItems = [ordered]@{
            Software = @()
            Updates = @()
        }

        # Get recently installed software from registry
        $uninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )

        $recentSoftware = $(foreach ($path in $uninstallPaths) {
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                Where-Object { $_.InstallDate -and $_.DisplayName } |
                ForEach-Object {
                    $installDateStr = $_.InstallDate
                    $installDate = $null
                    if ($installDateStr -match '^\d{8}$') {
                        $installDate = [DateTime]::ParseExact($installDateStr, "yyyyMMdd", $null)
                    }
                    if ($installDate -and $installDate -ge $sevenDaysAgo) {
                        [PSCustomObject]@{
                            Name = $_.DisplayName
                            Version = $_.DisplayVersion
                            InstallDate = $installDate.ToString("yyyy-MM-dd")
                            Publisher = $_.Publisher
                        }
                    }
                }
        }) | Sort-Object InstallDate -Descending | Select-Object -Unique -Property Name, Version, InstallDate, Publisher

        $recentItems.Software = @($recentSoftware | ForEach-Object {
            [ordered]@{
                Name = $_.Name
                Version = $_.Version
                InstallDate = $_.InstallDate
                Publisher = $_.Publisher
            }
        })

        # Get recently installed Windows Updates
        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $historyCount = $updateSearcher.GetTotalHistoryCount()
            if ($historyCount -gt 0) {
                $history = $updateSearcher.QueryHistory(0, $historyCount)
                $recentUpdates = $history | Where-Object {
                    $_.Date -ge $sevenDaysAgo -and $_.ResultCode -eq 2  # 2 = Succeeded
                } | ForEach-Object {
                    [ordered]@{
                        Title = $_.Title
                        Date = $_.Date.ToString("yyyy-MM-dd HH:mm")
                        Type = switch ($_.Categories | Select-Object -First 1 -ExpandProperty Name -ErrorAction SilentlyContinue) {
                            "Security Updates" { "Security" }
                            "Critical Updates" { "Critical" }
                            "Definition Updates" { "Definitions" }
                            "Feature Packs" { "Feature" }
                            "Update Rollups" { "Rollup" }
                            "Updates" { "Update" }
                            "Drivers" { "Driver" }
                            default { "Other" }
                        }
                    }
                }
                $recentItems.Updates = @($recentUpdates)
            }
        }
        catch {
            # Windows Update COM object may not be available
        }

        $configData.RecentlyInstalled = [ordered]@{
            TimeframeDays = 7
            SoftwareCount = $recentItems.Software.Count
            UpdateCount = $recentItems.Updates.Count
            Software = $recentItems.Software
            Updates = $recentItems.Updates
        }

        $totalRecent = $recentItems.Software.Count + $recentItems.Updates.Count
        Write-Host " $totalRecent items in last 7 days" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "ConfigHealth" -Message "Failed to get recent installations" -ErrorRecord $_
    }

    # Page File Configuration
    Write-Host "    Checking page file..." -NoNewline -ForegroundColor Gray
    try {
        $pageFile = Get-SafeCimInstance -ClassName Win32_PageFileSetting
        $pageFileUsage = Get-SafeCimInstance -ClassName Win32_PageFileUsage

        $configData.PageFile = [ordered]@{
            IsConfigured = ($null -ne $pageFile)
            Settings = @($pageFile | ForEach-Object {
                [ordered]@{
                    Path = $_.Name
                    InitialSizeMB = $_.InitialSize
                    MaximumSizeMB = $_.MaximumSize
                    IsSystemManaged = ($_.InitialSize -eq 0 -and $_.MaximumSize -eq 0)
                }
            })
            CurrentUsage = @($pageFileUsage | ForEach-Object {
                [ordered]@{
                    Path = $_.Name
                    AllocatedMB = $_.AllocatedBaseSize
                    CurrentUsageMB = $_.CurrentUsage
                    PeakUsageMB = $_.PeakUsage
                    UsagePercent = if ($_.AllocatedBaseSize -gt 0) {
                        [math]::Round(($_.CurrentUsage / $_.AllocatedBaseSize) * 100, 1)
                    } else { 0 }
                }
            })
        }
        Write-Host " done" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "ConfigHealth" -Message "Failed to get page file info" -ErrorRecord $_
    }

    # Windows Update Status
    Write-Host "    Checking Windows Update..." -NoNewline -ForegroundColor Gray
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $updateSearcher = $updateSession.CreateUpdateSearcher()

        # Get update history
        $historyCount = $updateSearcher.GetTotalHistoryCount()
        $history = $updateSearcher.QueryHistory(0, [Math]::Min($historyCount, 10))

        $recentUpdates = @($history | ForEach-Object {
            [ordered]@{
                Title = $_.Title
                Date = $_.Date.ToString("yyyy-MM-dd HH:mm:ss")
                ResultCode = switch ($_.ResultCode) {
                    0 { "Not Started" }
                    1 { "In Progress" }
                    2 { "Succeeded" }
                    3 { "Succeeded With Errors" }
                    4 { "Failed" }
                    5 { "Aborted" }
                    default { "Unknown" }
                }
            }
        })

        # Check for pending updates
        $pendingSearch = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")

        $configData.WindowsUpdate = [ordered]@{
            LastCheckTime = if ($history.Count -gt 0) { $history[0].Date.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
            PendingUpdates = $pendingSearch.Updates.Count
            RecentHistory = $recentUpdates
            HealthStatus = if ($pendingSearch.Updates.Count -eq 0) { "Pass" }
                          elseif ($pendingSearch.Updates.Count -le 5) { "Warning" }
                          else { "Fail" }
        }
        Write-Host " $($pendingSearch.Updates.Count) pending" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "ConfigHealth" -Message "Failed to get Windows Update status" -ErrorRecord $_
        $configData.WindowsUpdate = [ordered]@{
            Error = "Unable to query Windows Update"
            HealthStatus = "Unknown"
        }
    }

    # Intune MDM Enrollment State
    Write-Host "    Checking Intune enrollment..." -NoNewline -ForegroundColor Gray
    try {
        $mdmInfo = Get-SafeCimInstance -ClassName MDM_DevDetail_Ext01 -Namespace "root/cimv2/mdm/dmmap"
        $enrollmentInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\*" -ErrorAction SilentlyContinue |
            Where-Object { $_.ProviderID -eq "MS DM Server" }

        if ($enrollmentInfo) {
            $configData.IntuneEnrollment = [ordered]@{
                IsEnrolled = $true
                EnrollmentType = $enrollmentInfo.EnrollmentType
                UPN = $enrollmentInfo.UPN
                AADResourceID = $enrollmentInfo.AADResourceID
                LastSyncTime = $null
                LastSyncAgo = $null
            }

            # Try to get last sync time
            try {
                $scheduleKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\$($enrollmentInfo.PSChildName)\DMClient\MS DM Server" -ErrorAction SilentlyContinue
                if ($scheduleKey.LastSuccessfulSync) {
                    $lastSyncDateTime = [DateTime]::FromFileTime($scheduleKey.LastSuccessfulSync)
                    $configData.IntuneEnrollment.LastSyncTime = $lastSyncDateTime.ToString("yyyy-MM-dd HH:mm:ss")

                    # Calculate time since last sync
                    $syncAge = (Get-Date) - $lastSyncDateTime
                    if ($syncAge.TotalDays -ge 1) {
                        $configData.IntuneEnrollment.LastSyncAgo = "$([math]::Floor($syncAge.TotalDays)) days ago"
                    }
                    elseif ($syncAge.TotalHours -ge 1) {
                        $configData.IntuneEnrollment.LastSyncAgo = "$([math]::Floor($syncAge.TotalHours)) hours ago"
                    }
                    else {
                        $configData.IntuneEnrollment.LastSyncAgo = "$([math]::Floor($syncAge.TotalMinutes)) minutes ago"
                    }
                }
            }
            catch {
                $configData.IntuneEnrollment.LastSyncTime = "Unable to determine"
            }

            $syncStatus = if ($configData.IntuneEnrollment.LastSyncAgo) { " (synced $($configData.IntuneEnrollment.LastSyncAgo))" } else { "" }
            Write-Host " enrolled$syncStatus" -ForegroundColor Gray
        }
        else {
            $configData.IntuneEnrollment = [ordered]@{
                IsEnrolled = $false
            }
            Write-Host " not enrolled" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "ConfigHealth" -Message "Failed to get Intune enrollment status" -ErrorRecord $_
        $configData.IntuneEnrollment = [ordered]@{
            IsEnrolled = $false
            Error = "Unable to query enrollment status"
            HealthStatus = "Unknown"
        }
    }

    # Company Portal Agent Health
    Write-Host "    Checking Company Portal..." -NoNewline -ForegroundColor Gray
    try {
        $companyPortal = Get-AppxPackage -Name "Microsoft.CompanyPortal" -ErrorAction SilentlyContinue
        $intuneAgent = Get-Service -Name "IntuneManagementExtension" -ErrorAction SilentlyContinue

        $configData.CompanyPortal = [ordered]@{
            IsInstalled = ($null -ne $companyPortal)
            Version = if ($companyPortal) { $companyPortal.Version } else { "N/A" }
            IntuneManagementExtension = [ordered]@{
                ServiceExists = ($null -ne $intuneAgent)
                Status = if ($intuneAgent) { $intuneAgent.Status.ToString() } else { "Not Found" }
                StartType = if ($intuneAgent) { $intuneAgent.StartType.ToString() } else { "N/A" }
            }
            HealthStatus = if ($intuneAgent -and $intuneAgent.Status -eq "Running") { "Pass" }
                          elseif ($intuneAgent) { "Warning" }
                          else { "Fail" }
        }
        Write-Host " done" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "ConfigHealth" -Message "Failed to check Company Portal" -ErrorRecord $_
    }

    # GPO Remnants Check (for cloud-only machines)
    Write-Host "    Checking GPO remnants..." -NoNewline -ForegroundColor Gray
    try {
        $gpoCheck = [ordered]@{
            HasLocalGPO = $false
            HasDomainGPO = $false
            GPOPaths = @()
            HealthStatus = "Pass"
        }

        # Check for GPO registry keys
        $gpoPaths = @(
            "HKLM:\SOFTWARE\Policies\Microsoft",
            "HKCU:\SOFTWARE\Policies\Microsoft",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"
        )

        foreach ($path in $gpoPaths) {
            if (Test-Path $path) {
                $items = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
                if ($items.Count -gt 0) {
                    $gpoCheck.HasLocalGPO = $true
                    $gpoCheck.GPOPaths += $path
                }
            }
        }

        # Check for domain GPO
        $rsopPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History"
        if (Test-Path $rsopPath) {
            $rsop = Get-ChildItem -Path $rsopPath -ErrorAction SilentlyContinue
            if ($rsop.Count -gt 0) {
                $gpoCheck.HasDomainGPO = $true
            }
        }

        if ($gpoCheck.HasDomainGPO) {
            $gpoCheck.HealthStatus = "Warning"
            $gpoCheck.Message = "Domain GPO remnants detected - may cause conflicts with cloud-only management"
        }

        $configData.GPOCheck = $gpoCheck
        Write-Host " done" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "ConfigHealth" -Message "Failed to check GPO status" -ErrorRecord $_
    }

    # Startup Programs
    Write-Host "    Enumerating startup programs..." -NoNewline -ForegroundColor Gray
    try {
        $startupItems = [System.Collections.ArrayList]::new()

        # Registry Run keys (HKLM - all users)
        $hklmRun = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        if (Test-Path $hklmRun) {
            $props = Get-ItemProperty -Path $hklmRun -ErrorAction SilentlyContinue
            $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                [void]$startupItems.Add([ordered]@{
                    Name = $_.Name
                    Command = $_.Value
                    Location = "HKLM\...\Run"
                    Scope = "All Users"
                    Type = "Registry"
                })
            }
        }

        # Registry Run keys (HKCU - current user)
        $hkcuRun = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        if (Test-Path $hkcuRun) {
            $props = Get-ItemProperty -Path $hkcuRun -ErrorAction SilentlyContinue
            $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                [void]$startupItems.Add([ordered]@{
                    Name = $_.Name
                    Command = $_.Value
                    Location = "HKCU\...\Run"
                    Scope = "Current User"
                    Type = "Registry"
                })
            }
        }

        # Registry RunOnce keys
        @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
          "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce") | ForEach-Object {
            if (Test-Path $_) {
                $props = Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue
                $scope = if ($_ -match 'HKLM') { "All Users" } else { "Current User" }
                $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                    [void]$startupItems.Add([ordered]@{
                        Name = $_.Name
                        Command = $_.Value
                        Location = "RunOnce"
                        Scope = $scope
                        Type = "Registry (One-time)"
                    })
                }
            }
        }

        # Common Startup folders
        $startupFolders = @(
            [Environment]::GetFolderPath('Startup'),
            [Environment]::GetFolderPath('CommonStartup')
        )

        foreach ($folder in $startupFolders) {
            if (Test-Path $folder) {
                $scope = if ($folder -match 'Common') { "All Users" } else { "Current User" }
                Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue | ForEach-Object {
                    [void]$startupItems.Add([ordered]@{
                        Name = $_.BaseName
                        Command = $_.FullName
                        Location = "Startup Folder"
                        Scope = $scope
                        Type = "Shortcut/File"
                    })
                }
            }
        }

        # Task Scheduler - logon triggers (common source of startup bloat)
        try {
            $scheduledTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
                Where-Object { $_.State -ne 'Disabled' } |
                ForEach-Object {
                    $task = $_
                    $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                    $triggers = $task.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' }
                    if ($triggers) {
                        [ordered]@{
                            Name = $task.TaskName
                            Command = ($task.Actions | Select-Object -First 1).Execute
                            Location = $task.TaskPath
                            Scope = "Scheduled Task"
                            Type = "Logon Trigger"
                        }
                    }
                } | Where-Object { $_ }

            foreach ($task in $scheduledTasks) {
                [void]$startupItems.Add($task)
            }
        }
        catch {
            # Silently continue if we can't enumerate scheduled tasks
        }

        # Get startup impact from Task Manager's startup data (if available)
        $startupAppInfo = @{}
        try {
            $startupApps = Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction SilentlyContinue
            # Also try to get startup impact from registry where Task Manager stores it
            $startupApprovedPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
            if (Test-Path $startupApprovedPath) {
                $approvedItems = Get-ItemProperty -Path $startupApprovedPath -ErrorAction SilentlyContinue
                # Disabled items have first byte != 02 or 06
            }
        }
        catch {
            # Startup impact data not available
        }

        # Categorize startup items by known impact
        $highImpactKeywords = @('Teams', 'Spotify', 'Discord', 'Steam', 'Epic', 'Origin', 'Slack', 'Zoom', 'Skype', 'iTunes', 'Adobe', 'Dropbox', 'OneDrive', 'GoogleDrive', 'iCloud')
        $knownLowImpact = @('SecurityHealth', 'Windows Security', 'Microsoft Edge', 'CTFMon', 'igfxTray')

        $highImpactCount = 0
        foreach ($item in $startupItems) {
            $impact = "Unknown"
            $itemName = $item.Name
            $itemCommand = $item.Command

            # Check against known high-impact applications
            foreach ($keyword in $highImpactKeywords) {
                if ($itemName -match $keyword -or $itemCommand -match $keyword) {
                    $impact = "High"
                    $highImpactCount++
                    break
                }
            }

            # Check known low-impact items
            if ($impact -eq "Unknown") {
                foreach ($lowItem in $knownLowImpact) {
                    if ($itemName -match $lowItem -or $itemCommand -match $lowItem) {
                        $impact = "Low"
                        break
                    }
                }
            }

            $item.Impact = $impact
        }

        $configData.StartupPrograms = [ordered]@{
            TotalCount = $startupItems.Count
            HighImpactCount = $highImpactCount
            Items = @($startupItems)
        }

        Write-Host " found $($startupItems.Count)" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "ConfigHealth" -Message "Failed to enumerate startup programs" -ErrorRecord $_
    }

    # User Profile Size
    Write-Host "    Checking user profile size..." -NoNewline -ForegroundColor Gray
    try {
        $userProfile = $env:USERPROFILE
        $profileSizeBytes = 0
        $largestFolders = @()

        # Get total profile size (this can take a moment on large profiles)
        # We'll use a faster method by sampling key folders
        $keyFolders = @(
            @{ Name = "Desktop"; Path = Join-Path $userProfile "Desktop" },
            @{ Name = "Documents"; Path = Join-Path $userProfile "Documents" },
            @{ Name = "Downloads"; Path = Join-Path $userProfile "Downloads" },
            @{ Name = "AppData\Local"; Path = Join-Path $userProfile "AppData\Local" },
            @{ Name = "AppData\Roaming"; Path = Join-Path $userProfile "AppData\Roaming" },
            @{ Name = "Pictures"; Path = Join-Path $userProfile "Pictures" },
            @{ Name = "Videos"; Path = Join-Path $userProfile "Videos" },
            @{ Name = "Music"; Path = Join-Path $userProfile "Music" }
        )

        $folderSizes = foreach ($folder in $keyFolders) {
            if (Test-Path $folder.Path) {
                $size = (Get-ChildItem -Path $folder.Path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                if ($null -eq $size) { $size = 0 }
                $profileSizeBytes += $size
                [PSCustomObject]@{
                    Name = $folder.Name
                    SizeBytes = $size
                    SizeGB = [math]::Round($size / 1GB, 2)
                }
            }
        }

        $largestFolders = @($folderSizes | Sort-Object SizeBytes -Descending | Select-Object -First 5 | ForEach-Object {
            [ordered]@{
                Folder = $_.Name
                SizeGB = $_.SizeGB
            }
        })

        $profileSizeGB = [math]::Round($profileSizeBytes / 1GB, 2)

        $configData.UserProfile = [ordered]@{
            Path = $userProfile
            Username = $env:USERNAME
            TotalSizeGB = $profileSizeGB
            LargestFolders = $largestFolders
        }

        Write-Host " $profileSizeGB GB" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "ConfigHealth" -Message "Failed to check user profile size" -ErrorRecord $_
    }

    Write-Log -Message "Configuration health check complete" -Level Success
    return $configData
}
#endregion

#region Module: Event Log Summary
function Get-EventLogSummary {
    <#
    .SYNOPSIS
        Scans event logs for significant events in the last 24-48 hours
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$HoursBack = 48
    )

    Write-Log -Message "Scanning event logs (last $HoursBack hours)..." -Level Info

    $eventData = [ordered]@{
        CollectionTimestamp = (Get-Date).ToString("o")
        TimeRange = [ordered]@{
            StartTime = (Get-Date).AddHours(-$HoursBack).ToString("yyyy-MM-dd HH:mm:ss")
            EndTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            HoursScanned = $HoursBack
        }
        DiskEvents = @()
        KernelDriverErrors = @()
        ApplicationCrashes = @()
        UpdateFailures = @()
        BrowserCrashes = @()
        SecurityEvents = @()
        Summary = $null
    }

    $startTime = (Get-Date).AddHours(-$HoursBack)

    # Disk Events (System log)
    Write-Host "    Scanning disk events..." -NoNewline -ForegroundColor Gray
    try {
        $diskEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            StartTime = $startTime
            Level = @(1, 2, 3)  # Critical, Error, Warning
        } -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'disk|storage|ntfs|partition' } |
        Select-Object -First 50

        $eventData.DiskEvents = @($diskEvents | ForEach-Object {
            [ordered]@{
                TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Level = switch ($_.Level) { 1 { "Critical" } 2 { "Error" } 3 { "Warning" } default { "Info" } }
                Provider = $_.ProviderName
                Id = $_.Id
                Message = ($_.Message -split "`n")[0]  # First line only
            }
        })
        Write-Host " found $($eventData.DiskEvents.Count)" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "EventLog" -Message "Failed to query disk events" -ErrorRecord $_
    }

    # Kernel/Driver Errors
    Write-Host "    Scanning kernel/driver errors..." -NoNewline -ForegroundColor Gray
    try {
        $kernelEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            StartTime = $startTime
            Level = @(1, 2)  # Critical, Error
        } -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'kernel|driver|bugcheck|bluescreen|whea' } |
        Select-Object -First 50

        $eventData.KernelDriverErrors = @($kernelEvents | ForEach-Object {
            [ordered]@{
                TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Level = switch ($_.Level) { 1 { "Critical" } 2 { "Error" } default { "Unknown" } }
                Provider = $_.ProviderName
                Id = $_.Id
                Message = ($_.Message -split "`n")[0]
            }
        })
        Write-Host " found $($eventData.KernelDriverErrors.Count)" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "EventLog" -Message "Failed to query kernel events" -ErrorRecord $_
    }

    # Application Crashes
    # Note: We exclude 'Windows Error Reporting' (WER) as it only provides "Fault bucket" telemetry
    # which is not actionable. We focus on 'Application Error' which names the crashing executable.
    Write-Host "    Scanning application crashes..." -NoNewline -ForegroundColor Gray
    try {
        $appCrashes = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            StartTime = $startTime
            ProviderName = 'Application Error', 'Application Hang'
        } -ErrorAction SilentlyContinue |
        Select-Object -First 50

        $eventData.ApplicationCrashes = @($appCrashes | ForEach-Object {
            # Extract application name from the message for Application Error events
            $appName = "Unknown"
            $message = $_.Message
            if ($message -match 'Faulting application name:\s*([^,]+)') {
                $appName = $matches[1].Trim()
            }
            elseif ($message -match 'The program\s+([^\s]+)\s+') {
                $appName = $matches[1].Trim()
            }
            else {
                $appName = ($message -split "`n")[0]
            }

            [ordered]@{
                TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Provider = $_.ProviderName
                Id = $_.Id
                Application = $appName
                Message = ($message -split "`n")[0]
            }
        })
        Write-Host " found $($eventData.ApplicationCrashes.Count)" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "EventLog" -Message "Failed to query application crashes" -ErrorRecord $_
    }

    # Windows Update Failures
    Write-Host "    Scanning update failures..." -NoNewline -ForegroundColor Gray
    try {
        $updateEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            StartTime = $startTime
            ProviderName = 'Microsoft-Windows-WindowsUpdateClient'
            Level = @(1, 2, 3)
        } -ErrorAction SilentlyContinue |
        Select-Object -First 30

        $eventData.UpdateFailures = @($updateEvents | ForEach-Object {
            [ordered]@{
                TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Level = switch ($_.Level) { 1 { "Critical" } 2 { "Error" } 3 { "Warning" } default { "Info" } }
                Id = $_.Id
                Message = ($_.Message -split "`n")[0]
            }
        })
        Write-Host " found $($eventData.UpdateFailures.Count)" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "EventLog" -Message "Failed to query update events" -ErrorRecord $_
    }

    # Browser Crashes (Chrome and Edge)
    Write-Host "    Scanning browser crashes..." -NoNewline -ForegroundColor Gray
    try {
        $browserCrashes = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            StartTime = $startTime
        } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'chrome|msedge|edge' -and $_.ProviderName -match 'Error|Crash|Hang' } |
        Select-Object -First 20

        $eventData.BrowserCrashes = @($browserCrashes | ForEach-Object {
            [ordered]@{
                TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Provider = $_.ProviderName
                Id = $_.Id
                Message = ($_.Message -split "`n")[0]
            }
        })
        Write-Host " found $($eventData.BrowserCrashes.Count)" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "EventLog" -Message "Failed to query browser crashes" -ErrorRecord $_
    }

    # Security Events (authentication failures)
    Write-Host "    Scanning security events..." -NoNewline -ForegroundColor Gray
    try {
        $securityEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            StartTime = $startTime
            Id = @(4625, 4771, 4776)  # Failed logons
        } -ErrorAction SilentlyContinue |
        Select-Object -First 20

        $eventData.SecurityEvents = @($securityEvents | ForEach-Object {
            [ordered]@{
                TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Id = $_.Id
                EventType = switch ($_.Id) {
                    4625 { "Failed Logon" }
                    4771 { "Kerberos Pre-Auth Failed" }
                    4776 { "NTLM Auth Failed" }
                    default { "Security Event" }
                }
                Message = ($_.Message -split "`n")[0]
            }
        })
        Write-Host " found $($eventData.SecurityEvents.Count)" -ForegroundColor Gray
    }
    catch {
        Write-Host " error" -ForegroundColor Yellow
        Add-InternalError -Module "EventLog" -Message "Failed to query security events" -ErrorRecord $_
    }

    # Generate Summary
    $eventData.Summary = [ordered]@{
        TotalDiskEvents = $eventData.DiskEvents.Count
        TotalKernelErrors = $eventData.KernelDriverErrors.Count
        TotalAppCrashes = $eventData.ApplicationCrashes.Count
        TotalUpdateFailures = $eventData.UpdateFailures.Count
        TotalBrowserCrashes = $eventData.BrowserCrashes.Count
        TotalSecurityEvents = $eventData.SecurityEvents.Count
        OverallHealthStatus = "Pass"
    }

    # Determine overall health
    $criticalCount = $eventData.KernelDriverErrors.Count +
                     ($eventData.DiskEvents | Where-Object { $_.Level -eq "Critical" }).Count
    $errorCount = $eventData.ApplicationCrashes.Count +
                  $eventData.UpdateFailures.Count

    if ($criticalCount -gt 0) {
        $eventData.Summary.OverallHealthStatus = "Fail"
    }
    elseif ($errorCount -gt 10) {
        $eventData.Summary.OverallHealthStatus = "Warning"
    }

    Write-Log -Message "Event log scan complete" -Level Success
    return $eventData
}
#endregion

#region Output Functions
function Export-JsonReport {
    <#
    .SYNOPSIS
        Exports results to JSON file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Data,

        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        $Data | ConvertTo-Json -Depth 10 -Compress:$false | Out-File -FilePath $Path -Encoding UTF8 -Force
        Write-Log -Message "JSON report saved: $Path" -Level Success
        return $true
    }
    catch {
        Add-InternalError -Module "Export" -Message "Failed to save JSON report" -ErrorRecord $_
        return $false
    }
}

function Get-WorkNoteSummary {
    <#
    .SYNOPSIS
        Generates a brief text summary suitable for ServiceNow work notes
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Data
    )

    $sb = [System.Text.StringBuilder]::new()

    # Header
    [void]$sb.AppendLine("════════════════════════════════════════════════════════════")
    [void]$sb.AppendLine("PULSE REPORT | $($Data.Metadata.Hostname) | $($Data.Metadata.ScanTimestamp)")
    [void]$sb.AppendLine("════════════════════════════════════════════════════════════")
    [void]$sb.AppendLine()

    # Health Status
    [void]$sb.AppendLine("HEALTH STATUS: $($Data.HealthSummary.OverallStatus)")

    # Pending Reboot
    if ($Data.ConfigurationHealth.PendingReboot.IsRebootPending) {
        [void]$sb.AppendLine("  !! REBOOT PENDING - $($Data.ConfigurationHealth.PendingReboot.Reasons -join '; ')")
    }

    # Key metrics
    if ($Data.PerformanceSampling.CPU.Statistics) {
        $cpuAvg = $Data.PerformanceSampling.CPU.Statistics.ProcessorTime.Average
        $cpuIcon = if ($cpuAvg -lt 80) { "[OK]" } else { "[!!]" }
        [void]$sb.AppendLine("  $cpuIcon CPU: $cpuAvg% avg")
    }

    if ($Data.SystemInformation.Memory) {
        $memUsed = $Data.SystemInformation.Memory.UsedPercent
        $memIcon = if ($memUsed -lt 90) { "[OK]" } else { "[!!]" }
        [void]$sb.AppendLine("  $memIcon Memory: $memUsed% used ($($Data.SystemInformation.Memory.AvailableGB) GB free)")
    }

    if ($Data.SystemInformation.Volumes) {
        $lowestFree = ($Data.SystemInformation.Volumes | Sort-Object FreeSpacePercent | Select-Object -First 1)
        $diskIcon = if ($lowestFree.FreeSpacePercent -gt 10) { "[OK]" } else { "[!!]" }
        [void]$sb.AppendLine("  $diskIcon Disk: $($lowestFree.FreeSpacePercent)% free on $($lowestFree.DriveLetter)")
    }

    if ($Data.PerformanceSampling.Disk.Statistics) {
        $avgLatency = [math]::Max($Data.PerformanceSampling.Disk.Statistics.ReadLatencyMs.Average, $Data.PerformanceSampling.Disk.Statistics.WriteLatencyMs.Average)
        $latencyIcon = if ($avgLatency -lt 50) { "[OK]" } else { "[!!]" }
        [void]$sb.AppendLine("  $latencyIcon Disk Latency: $([math]::Round($avgLatency, 1))ms avg")
    }

    if ($Data.PerformanceSampling.InterruptDPC.Statistics.CombinedTime) {
        $dpcIsr = $Data.PerformanceSampling.InterruptDPC.Statistics.CombinedTime.Average
        if ($dpcIsr -gt 15) {
            $dpcIcon = if ($dpcIsr -lt 30) { "[??]" } else { "[!!]" }
            [void]$sb.AppendLine("  $dpcIcon DPC/ISR: $([math]::Round($dpcIsr, 1))%")
        }
    }

    [void]$sb.AppendLine()

    # System Info
    [void]$sb.AppendLine("SYSTEM")
    if ($Data.SystemInformation.OperatingSystem) {
        [void]$sb.AppendLine("  OS: $($Data.SystemInformation.OperatingSystem.Caption) ($($Data.SystemInformation.OperatingSystem.BuildNumber))")
        [void]$sb.AppendLine("  Uptime: $($Data.SystemInformation.OperatingSystem.UptimeFormatted)")
    }
    if ($Data.SystemInformation.CPU) {
        [void]$sb.AppendLine("  CPU: $($Data.SystemInformation.CPU.Name)")
    }
    if ($Data.SystemInformation.Memory) {
        [void]$sb.AppendLine("  RAM: $($Data.SystemInformation.Memory.TotalPhysicalGB) GB")
    }
    [void]$sb.AppendLine()

    # Intune Status
    if ($Data.ConfigurationHealth.IntuneEnrollment) {
        [void]$sb.AppendLine("INTUNE")
        if ($Data.ConfigurationHealth.IntuneEnrollment.IsEnrolled) {
            $syncInfo = if ($Data.ConfigurationHealth.IntuneEnrollment.LastSyncAgo) { " (Last sync: $($Data.ConfigurationHealth.IntuneEnrollment.LastSyncAgo))" } else { "" }
            [void]$sb.AppendLine("  Enrolled: Yes$syncInfo")
        }
        else {
            [void]$sb.AppendLine("  Enrolled: No")
        }
        [void]$sb.AppendLine()
    }

    # Observations (if any significant ones)
    if ($Data.ProcessAnalysis.Observations -and $Data.ProcessAnalysis.Observations.Count -gt 0) {
        [void]$sb.AppendLine("OBSERVATIONS")
        foreach ($obs in $Data.ProcessAnalysis.Observations | Select-Object -First 5) {
            [void]$sb.AppendLine("  - $($obs.What)")
        }
        [void]$sb.AppendLine()
    }

    # Recent Changes
    if ($Data.ConfigurationHealth.RecentlyInstalled) {
        $recentSw = $Data.ConfigurationHealth.RecentlyInstalled.Software | Select-Object -First 3
        $recentUpd = $Data.ConfigurationHealth.RecentlyInstalled.Updates | Select-Object -First 3
        if ($recentSw.Count -gt 0 -or $recentUpd.Count -gt 0) {
            [void]$sb.AppendLine("RECENT CHANGES (Last 7 Days)")
            foreach ($sw in $recentSw) {
                [void]$sb.AppendLine("  - $($sw.InstallDate): $($sw.Name) installed")
            }
            foreach ($upd in $recentUpd) {
                [void]$sb.AppendLine("  - $($upd.Date): $($upd.Title)")
            }
            [void]$sb.AppendLine()
        }
    }

    # Footer
    [void]$sb.AppendLine("────────────────────────────────────────────────────────────")
    [void]$sb.AppendLine("Scan ID: PULSE_$($Data.Metadata.Hostname)_$($Data.Metadata.ScanTimestamp -replace '[\s:]', '')")
    [void]$sb.AppendLine("════════════════════════════════════════════════════════════")

    return $sb.ToString()
}

function Export-MarkdownReport {
    <#
    .SYNOPSIS
        Generates a comprehensive markdown report suitable for ticket attachments
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Data,

        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        $sb = [System.Text.StringBuilder]::new()

        # Header
        [void]$sb.AppendLine("# PULSE Diagnostic Report")
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("| Field | Value |")
        [void]$sb.AppendLine("|-------|-------|")
        [void]$sb.AppendLine("| Hostname | $($Data.Metadata.Hostname) |")
        [void]$sb.AppendLine("| Scan Time | $($Data.Metadata.ScanTimestamp) |")
        [void]$sb.AppendLine("| Duration | $($Data.Metadata.ScanDurationSeconds) seconds |")
        [void]$sb.AppendLine("| Elevated | $($Data.Metadata.IsElevated) |")
        [void]$sb.AppendLine("| Overall Status | **$($Data.HealthSummary.OverallStatus)** |")
        [void]$sb.AppendLine()

        # Health Summary
        [void]$sb.AppendLine("## Health Summary")
        [void]$sb.AppendLine()
        if ($Data.HealthSummary.Issues -and $Data.HealthSummary.Issues.Count -gt 0) {
            [void]$sb.AppendLine("### Issues Detected")
            foreach ($issue in $Data.HealthSummary.Issues) {
                [void]$sb.AppendLine("- $issue")
            }
            [void]$sb.AppendLine()
        }

        # Pending Reboot
        if ($Data.ConfigurationHealth.PendingReboot.IsRebootPending) {
            [void]$sb.AppendLine("### ⚠️ Reboot Required")
            [void]$sb.AppendLine()
            foreach ($reason in $Data.ConfigurationHealth.PendingReboot.Reasons) {
                [void]$sb.AppendLine("- $reason")
            }
            [void]$sb.AppendLine()
        }

        # System Information
        [void]$sb.AppendLine("## System Information")
        [void]$sb.AppendLine()

        if ($Data.SystemInformation.OperatingSystem) {
            [void]$sb.AppendLine("### Operating System")
            [void]$sb.AppendLine("| Property | Value |")
            [void]$sb.AppendLine("|----------|-------|")
            [void]$sb.AppendLine("| Name | $($Data.SystemInformation.OperatingSystem.Caption) |")
            [void]$sb.AppendLine("| Build | $($Data.SystemInformation.OperatingSystem.BuildNumber) |")
            [void]$sb.AppendLine("| Install Date | $($Data.SystemInformation.OperatingSystem.InstallDate) |")
            [void]$sb.AppendLine("| Uptime | $($Data.SystemInformation.OperatingSystem.UptimeFormatted) |")
            [void]$sb.AppendLine()
        }

        if ($Data.SystemInformation.CPU) {
            [void]$sb.AppendLine("### CPU")
            [void]$sb.AppendLine("| Property | Value |")
            [void]$sb.AppendLine("|----------|-------|")
            [void]$sb.AppendLine("| Name | $($Data.SystemInformation.CPU.Name) |")
            [void]$sb.AppendLine("| Cores | $($Data.SystemInformation.CPU.Cores) |")
            [void]$sb.AppendLine("| Logical Processors | $($Data.SystemInformation.CPU.LogicalProcessors) |")
            [void]$sb.AppendLine()
        }

        if ($Data.SystemInformation.Memory) {
            [void]$sb.AppendLine("### Memory")
            [void]$sb.AppendLine("| Property | Value |")
            [void]$sb.AppendLine("|----------|-------|")
            [void]$sb.AppendLine("| Total | $($Data.SystemInformation.Memory.TotalPhysicalGB) GB |")
            [void]$sb.AppendLine("| Available | $($Data.SystemInformation.Memory.AvailableGB) GB |")
            [void]$sb.AppendLine("| Used | $($Data.SystemInformation.Memory.UsedPercent)% |")
            [void]$sb.AppendLine()
        }

        if ($Data.SystemInformation.Volumes) {
            [void]$sb.AppendLine("### Storage Volumes")
            [void]$sb.AppendLine("| Drive | Label | Size | Free | Free % |")
            [void]$sb.AppendLine("|-------|-------|------|------|--------|")
            foreach ($vol in $Data.SystemInformation.Volumes) {
                [void]$sb.AppendLine("| $($vol.DriveLetter) | $($vol.Label) | $($vol.SizeGB) GB | $($vol.FreeSpaceGB) GB | $($vol.FreeSpacePercent)% |")
            }
            [void]$sb.AppendLine()
        }

        # Performance Sampling
        [void]$sb.AppendLine("## Performance Sampling ($($Data.PerformanceSampling.DurationSeconds) seconds)")
        [void]$sb.AppendLine()

        if ($Data.PerformanceSampling.CPU.Statistics) {
            [void]$sb.AppendLine("### CPU")
            [void]$sb.AppendLine("| Metric | Min | Avg | Max |")
            [void]$sb.AppendLine("|--------|-----|-----|-----|")
            [void]$sb.AppendLine("| Processor Time | $($Data.PerformanceSampling.CPU.Statistics.ProcessorTime.Min)% | $($Data.PerformanceSampling.CPU.Statistics.ProcessorTime.Average)% | $($Data.PerformanceSampling.CPU.Statistics.ProcessorTime.Max)% |")
            [void]$sb.AppendLine("| Queue Length | $($Data.PerformanceSampling.CPU.Statistics.ProcessorQueueLength.Min) | $($Data.PerformanceSampling.CPU.Statistics.ProcessorQueueLength.Average) | $($Data.PerformanceSampling.CPU.Statistics.ProcessorQueueLength.Max) |")
            [void]$sb.AppendLine()
        }

        if ($Data.PerformanceSampling.Memory.Statistics) {
            [void]$sb.AppendLine("### Memory")
            [void]$sb.AppendLine("| Metric | Min | Avg | Max |")
            [void]$sb.AppendLine("|--------|-----|-----|-----|")
            [void]$sb.AppendLine("| Available MB | $($Data.PerformanceSampling.Memory.Statistics.AvailableMB.Min) | $($Data.PerformanceSampling.Memory.Statistics.AvailableMB.Average) | $($Data.PerformanceSampling.Memory.Statistics.AvailableMB.Max) |")
            [void]$sb.AppendLine("| Hard Faults/sec | $($Data.PerformanceSampling.Memory.Statistics.HardFaultsPerSec.Min) | $($Data.PerformanceSampling.Memory.Statistics.HardFaultsPerSec.Average) | $($Data.PerformanceSampling.Memory.Statistics.HardFaultsPerSec.Max) |")
            [void]$sb.AppendLine()
        }

        if ($Data.PerformanceSampling.Disk.Statistics) {
            [void]$sb.AppendLine("### Disk")
            [void]$sb.AppendLine("| Metric | Min | Avg | Max |")
            [void]$sb.AppendLine("|--------|-----|-----|-----|")
            [void]$sb.AppendLine("| Read Latency (ms) | $($Data.PerformanceSampling.Disk.Statistics.ReadLatencyMs.Min) | $($Data.PerformanceSampling.Disk.Statistics.ReadLatencyMs.Average) | $($Data.PerformanceSampling.Disk.Statistics.ReadLatencyMs.Max) |")
            [void]$sb.AppendLine("| Write Latency (ms) | $($Data.PerformanceSampling.Disk.Statistics.WriteLatencyMs.Min) | $($Data.PerformanceSampling.Disk.Statistics.WriteLatencyMs.Average) | $($Data.PerformanceSampling.Disk.Statistics.WriteLatencyMs.Max) |")
            [void]$sb.AppendLine("| Queue Length | $($Data.PerformanceSampling.Disk.Statistics.QueueLength.Min) | $($Data.PerformanceSampling.Disk.Statistics.QueueLength.Average) | $($Data.PerformanceSampling.Disk.Statistics.QueueLength.Max) |")
            [void]$sb.AppendLine()
        }

        if ($Data.PerformanceSampling.InterruptDPC.Statistics) {
            [void]$sb.AppendLine("### DPC/Interrupt")
            [void]$sb.AppendLine("| Metric | Min | Avg | Max |")
            [void]$sb.AppendLine("|--------|-----|-----|-----|")
            [void]$sb.AppendLine("| DPC Time | $($Data.PerformanceSampling.InterruptDPC.Statistics.DPCTime.Min)% | $($Data.PerformanceSampling.InterruptDPC.Statistics.DPCTime.Average)% | $($Data.PerformanceSampling.InterruptDPC.Statistics.DPCTime.Max)% |")
            [void]$sb.AppendLine("| Interrupt Time | $($Data.PerformanceSampling.InterruptDPC.Statistics.InterruptTime.Min)% | $($Data.PerformanceSampling.InterruptDPC.Statistics.InterruptTime.Average)% | $($Data.PerformanceSampling.InterruptDPC.Statistics.InterruptTime.Max)% |")
            [void]$sb.AppendLine("| Combined | $($Data.PerformanceSampling.InterruptDPC.Statistics.CombinedTime.Min)% | $($Data.PerformanceSampling.InterruptDPC.Statistics.CombinedTime.Average)% | $($Data.PerformanceSampling.InterruptDPC.Statistics.CombinedTime.Max)% |")
            [void]$sb.AppendLine()
        }

        # Top Processes
        if ($Data.ProcessAnalysis.TopByMemory) {
            [void]$sb.AppendLine("### Top Processes by Memory")
            [void]$sb.AppendLine("| Process | PID | Working Set | Private Memory |")
            [void]$sb.AppendLine("|---------|-----|-------------|----------------|")
            foreach ($proc in $Data.ProcessAnalysis.TopByMemory | Select-Object -First 10) {
                [void]$sb.AppendLine("| $($proc.Name) | $($proc.PID) | $($proc.WorkingSetMB) MB | $($proc.PrivateMemoryMB) MB |")
            }
            [void]$sb.AppendLine()
        }

        # Observations
        if ($Data.ProcessAnalysis.Observations -and $Data.ProcessAnalysis.Observations.Count -gt 0) {
            [void]$sb.AppendLine("## Observations")
            [void]$sb.AppendLine()
            foreach ($obs in $Data.ProcessAnalysis.Observations) {
                [void]$sb.AppendLine("### $($obs.Category): $($obs.Process)")
                [void]$sb.AppendLine("- **What:** $($obs.What)")
                [void]$sb.AppendLine("- **Context:** $($obs.Why)")
                [void]$sb.AppendLine("- **Possible Action:** $($obs.Action)")
                [void]$sb.AppendLine()
            }
        }

        # Browser Analysis
        [void]$sb.AppendLine("## Browser Analysis")
        [void]$sb.AppendLine()

        if ($Data.BrowserAnalysis.Chrome) {
            [void]$sb.AppendLine("### Chrome")
            [void]$sb.AppendLine("| Property | Value |")
            [void]$sb.AppendLine("|----------|-------|")
            [void]$sb.AppendLine("| Running | $(if ($Data.BrowserAnalysis.Chrome.IsRunning) { 'Yes' } else { 'No' }) |")
            if ($Data.BrowserAnalysis.Chrome.IsRunning) {
                [void]$sb.AppendLine("| Processes | $($Data.BrowserAnalysis.Chrome.ProcessCount) |")
                [void]$sb.AppendLine("| Memory | $($Data.BrowserAnalysis.Chrome.TotalMemoryMB) MB |")
            }
            [void]$sb.AppendLine("| Extensions | $($Data.BrowserAnalysis.Chrome.ExtensionCount) |")
            [void]$sb.AppendLine()

            if ($Data.BrowserAnalysis.Chrome.Extensions -and $Data.BrowserAnalysis.Chrome.Extensions.Count -gt 0) {
                [void]$sb.AppendLine("#### Chrome Extensions")
                foreach ($ext in $Data.BrowserAnalysis.Chrome.Extensions) {
                    [void]$sb.AppendLine("- $($ext.Name) (v$($ext.Version))")
                }
                [void]$sb.AppendLine()
            }
        }

        if ($Data.BrowserAnalysis.Edge) {
            [void]$sb.AppendLine("### Edge")
            [void]$sb.AppendLine("| Property | Value |")
            [void]$sb.AppendLine("|----------|-------|")
            [void]$sb.AppendLine("| Running | $(if ($Data.BrowserAnalysis.Edge.IsRunning) { 'Yes' } else { 'No' }) |")
            if ($Data.BrowserAnalysis.Edge.IsRunning) {
                [void]$sb.AppendLine("| Processes | $($Data.BrowserAnalysis.Edge.ProcessCount) |")
                [void]$sb.AppendLine("| Memory | $($Data.BrowserAnalysis.Edge.TotalMemoryMB) MB |")
            }
            [void]$sb.AppendLine("| Extensions | $($Data.BrowserAnalysis.Edge.ExtensionCount) |")
            [void]$sb.AppendLine()

            if ($Data.BrowserAnalysis.Edge.Extensions -and $Data.BrowserAnalysis.Edge.Extensions.Count -gt 0) {
                [void]$sb.AppendLine("#### Edge Extensions")
                foreach ($ext in $Data.BrowserAnalysis.Edge.Extensions) {
                    [void]$sb.AppendLine("- $($ext.Name) (v$($ext.Version))")
                }
                [void]$sb.AppendLine()
            }
        }

        # Configuration Health
        [void]$sb.AppendLine("## Configuration Health")
        [void]$sb.AppendLine()

        # Intune
        if ($Data.ConfigurationHealth.IntuneEnrollment) {
            [void]$sb.AppendLine("### Intune Enrollment")
            [void]$sb.AppendLine("| Property | Value |")
            [void]$sb.AppendLine("|----------|-------|")
            [void]$sb.AppendLine("| Enrolled | $(if ($Data.ConfigurationHealth.IntuneEnrollment.IsEnrolled) { 'Yes' } else { 'No' }) |")
            if ($Data.ConfigurationHealth.IntuneEnrollment.IsEnrolled) {
                [void]$sb.AppendLine("| UPN | $($Data.ConfigurationHealth.IntuneEnrollment.UPN) |")
                if ($Data.ConfigurationHealth.IntuneEnrollment.LastSyncTime) {
                    [void]$sb.AppendLine("| Last Sync | $($Data.ConfigurationHealth.IntuneEnrollment.LastSyncTime) ($($Data.ConfigurationHealth.IntuneEnrollment.LastSyncAgo)) |")
                }
            }
            [void]$sb.AppendLine()
        }

        # Recently Installed
        if ($Data.ConfigurationHealth.RecentlyInstalled) {
            [void]$sb.AppendLine("### Recently Installed (Last 7 Days)")
            [void]$sb.AppendLine()

            if ($Data.ConfigurationHealth.RecentlyInstalled.Software.Count -gt 0) {
                [void]$sb.AppendLine("#### Software")
                [void]$sb.AppendLine("| Name | Version | Install Date | Publisher |")
                [void]$sb.AppendLine("|------|---------|--------------|-----------|")
                foreach ($sw in $Data.ConfigurationHealth.RecentlyInstalled.Software) {
                    [void]$sb.AppendLine("| $($sw.Name) | $($sw.Version) | $($sw.InstallDate) | $($sw.Publisher) |")
                }
                [void]$sb.AppendLine()
            }

            if ($Data.ConfigurationHealth.RecentlyInstalled.Updates.Count -gt 0) {
                [void]$sb.AppendLine("#### Windows Updates")
                [void]$sb.AppendLine("| Title | Date | Type |")
                [void]$sb.AppendLine("|-------|------|------|")
                foreach ($upd in $Data.ConfigurationHealth.RecentlyInstalled.Updates) {
                    [void]$sb.AppendLine("| $($upd.Title) | $($upd.Date) | $($upd.Type) |")
                }
                [void]$sb.AppendLine()
            }
        }

        # User Profile
        if ($Data.ConfigurationHealth.UserProfile) {
            [void]$sb.AppendLine("### User Profile")
            [void]$sb.AppendLine("| Property | Value |")
            [void]$sb.AppendLine("|----------|-------|")
            [void]$sb.AppendLine("| Path | $($Data.ConfigurationHealth.UserProfile.Path) |")
            [void]$sb.AppendLine("| Total Size | $($Data.ConfigurationHealth.UserProfile.TotalSizeGB) GB |")
            [void]$sb.AppendLine()

            if ($Data.ConfigurationHealth.UserProfile.LargestFolders) {
                [void]$sb.AppendLine("#### Largest Folders")
                [void]$sb.AppendLine("| Folder | Size |")
                [void]$sb.AppendLine("|--------|------|")
                foreach ($folder in $Data.ConfigurationHealth.UserProfile.LargestFolders) {
                    [void]$sb.AppendLine("| $($folder.Folder) | $($folder.SizeGB) GB |")
                }
                [void]$sb.AppendLine()
            }
        }

        # Startup Programs
        if ($Data.ConfigurationHealth.StartupPrograms) {
            [void]$sb.AppendLine("### Startup Programs ($($Data.ConfigurationHealth.StartupPrograms.TotalCount) items)")
            [void]$sb.AppendLine("| Name | Location | Scope | Type |")
            [void]$sb.AppendLine("|------|----------|-------|------|")
            foreach ($item in $Data.ConfigurationHealth.StartupPrograms.Items) {
                [void]$sb.AppendLine("| $($item.Name) | $($item.Location) | $($item.Scope) | $($item.Type) |")
            }
            [void]$sb.AppendLine()
        }

        # Event Log Summary
        if ($Data.EventLogSummary.Summary) {
            [void]$sb.AppendLine("## Event Log Summary (Last $($Data.EventLogSummary.TimeRange.HoursScanned) Hours)")
            [void]$sb.AppendLine()
            [void]$sb.AppendLine("| Event Type | Count |")
            [void]$sb.AppendLine("|------------|-------|")
            [void]$sb.AppendLine("| Disk Events | $($Data.EventLogSummary.Summary.TotalDiskEvents) |")
            [void]$sb.AppendLine("| Kernel/Driver Errors | $($Data.EventLogSummary.Summary.TotalKernelErrors) |")
            [void]$sb.AppendLine("| Application Crashes | $($Data.EventLogSummary.Summary.TotalAppCrashes) |")
            [void]$sb.AppendLine("| Update Failures | $($Data.EventLogSummary.Summary.TotalUpdateFailures) |")
            [void]$sb.AppendLine("| Browser Crashes | $($Data.EventLogSummary.Summary.TotalBrowserCrashes) |")
            [void]$sb.AppendLine()
        }

        # Footer
        [void]$sb.AppendLine("---")
        [void]$sb.AppendLine("*Report generated by PULSE v$($Data.Metadata.ScriptVersion)*")

        $sb.ToString() | Out-File -FilePath $Path -Encoding UTF8 -Force
        Write-Log -Message "Markdown report saved: $Path" -Level Success
        return $true
    }
    catch {
        Add-InternalError -Module "Export" -Message "Failed to save Markdown report" -ErrorRecord $_
        return $false
    }
}

function Export-HtmlReport {
    <#
    .SYNOPSIS
        Generates an HTML report from collected data
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Data,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [string]$JsonPath
    )

    try {
        $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PULSE Report - $($Data.Metadata.Hostname)</title>
    <style>
        :root {
            --pass-color: #28a745;
            --warning-color: #ffc107;
            --fail-color: #dc3545;
            --info-color: #17a2b8;
            --bg-color: #f8f9fa;
            --card-bg: #ffffff;
            --text-color: #212529;
            --border-color: #dee2e6;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        header h1 {
            font-size: 2rem;
            margin-bottom: 10px;
        }

        header .meta {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            font-size: 0.9rem;
            opacity: 0.9;
        }

        .health-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .health-card {
            background: var(--card-bg);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            border-left: 4px solid var(--border-color);
        }

        .health-card.pass { border-left-color: var(--pass-color); }
        .health-card.warning { border-left-color: var(--warning-color); }
        .health-card.fail { border-left-color: var(--fail-color); }

        .health-card h3 {
            font-size: 0.85rem;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 10px;
        }

        .health-card .value {
            font-size: 1.8rem;
            font-weight: 700;
        }

        .health-card .status {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-top: 10px;
        }

        .status.pass { background: #d4edda; color: #155724; }
        .status.warning { background: #fff3cd; color: #856404; }
        .status.fail { background: #f8d7da; color: #721c24; }
        .status.unknown { background: #e2e3e5; color: #383d41; }

        .section {
            background: var(--card-bg);
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            overflow: hidden;
        }

        .section-header {
            background: #f1f3f4;
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
        }

        .section-header:hover {
            background: #e8eaed;
        }

        .section-header h2 {
            font-size: 1.1rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .section-header .toggle {
            font-size: 1.2rem;
            transition: transform 0.3s;
        }

        .section-content {
            padding: 20px;
        }

        .section.collapsed .section-content {
            display: none;
        }

        .section.collapsed .toggle {
            transform: rotate(-90deg);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }

        tr:hover {
            background: #f8f9fa;
        }

        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }

        .metric-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
        }

        .metric-item label {
            display: block;
            font-size: 0.8rem;
            color: #6c757d;
            margin-bottom: 5px;
        }

        .metric-item .value {
            font-size: 1.2rem;
            font-weight: 600;
        }

        .subsection {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
        }

        .subsection h3 {
            font-size: 1rem;
            color: #495057;
            margin-bottom: 15px;
        }

        .json-link {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background: var(--info-color);
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-size: 0.9rem;
        }

        .json-link:hover {
            background: #138496;
        }

        .error-list {
            background: #fff3f3;
            border: 1px solid #ffcdd2;
            border-radius: 6px;
            padding: 15px;
            margin-top: 10px;
        }

        .error-item {
            padding: 8px 0;
            border-bottom: 1px solid #ffcdd2;
            font-size: 0.9rem;
        }

        .error-item:last-child {
            border-bottom: none;
        }

        footer {
            text-align: center;
            padding: 20px;
            color: #6c757d;
            font-size: 0.85rem;
        }

        @media (max-width: 768px) {
            .health-summary {
                grid-template-columns: 1fr 1fr;
            }

            .metric-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>PULSE Report</h1>
            <div class="meta">
                <span><strong>Hostname:</strong> $($Data.Metadata.Hostname)</span>
                <span><strong>Scan Time:</strong> $($Data.Metadata.ScanTimestamp)</span>
                <span><strong>Duration:</strong> $($Data.Metadata.ScanDurationSeconds) seconds</span>
                <span><strong>Elevated:</strong> $($Data.Metadata.IsElevated)</span>
            </div>
        </header>

        <!-- Health Summary Cards - Only showing metrics with documented thresholds -->
        <div class="health-summary">
            $(
                $healthItems = @()

                # Pending Reboot - Clear signal that needs addressing
                if ($Data.ConfigurationHealth.PendingReboot) {
                    $rebootStatus = if ($Data.ConfigurationHealth.PendingReboot.IsRebootPending) { "fail" } else { "pass" }
                    $rebootText = if ($Data.ConfigurationHealth.PendingReboot.IsRebootPending) { "YES" } else { "No" }
                    $healthItems += "<div class='health-card $rebootStatus'><h3>Reboot Pending</h3><div class='value'>$rebootText</div><span class='status $rebootStatus'>$($rebootStatus.ToUpper())</span></div>"
                }

                # CPU Health - Microsoft docs: sustained >80% indicates bottleneck
                if ($Data.PerformanceSampling.CPU.Statistics) {
                    $cpuAvg = $Data.PerformanceSampling.CPU.Statistics.ProcessorTime.Average
                    $cpuStatus = if ($cpuAvg -lt 80) { "pass" } elseif ($cpuAvg -lt 90) { "warning" } else { "fail" }
                    $healthItems += "<div class='health-card $cpuStatus'><h3>CPU Average</h3><div class='value'>$cpuAvg%</div><span class='status $cpuStatus'>$($cpuStatus.ToUpper())</span></div>"
                }

                # Memory Health - >90% means active paging, measurable degradation
                if ($Data.SystemInformation.Memory) {
                    $memUsed = $Data.SystemInformation.Memory.UsedPercent
                    $memStatus = if ($memUsed -lt 85) { "pass" } elseif ($memUsed -lt 90) { "warning" } else { "fail" }
                    $healthItems += "<div class='health-card $memStatus'><h3>Memory Used</h3><div class='value'>$memUsed%</div><span class='status $memStatus'>$($memStatus.ToUpper())</span></div>"
                }

                # Disk Space - Windows shows red bar at <10%, documented threshold
                if ($Data.SystemInformation.Volumes) {
                    $lowestFree = ($Data.SystemInformation.Volumes | Sort-Object FreeSpacePercent | Select-Object -First 1).FreeSpacePercent
                    $diskStatus = if ($lowestFree -gt 15) { "pass" } elseif ($lowestFree -gt 10) { "warning" } else { "fail" }
                    $healthItems += "<div class='health-card $diskStatus'><h3>Disk Free (Min)</h3><div class='value'>$lowestFree%</div><span class='status $diskStatus'>$($diskStatus.ToUpper())</span></div>"
                }

                # Disk Latency - Microsoft docs: >50ms is "extremely underperforming"
                if ($Data.PerformanceSampling.Disk.Statistics) {
                    $avgLatency = [math]::Max($Data.PerformanceSampling.Disk.Statistics.ReadLatencyMs.Average, $Data.PerformanceSampling.Disk.Statistics.WriteLatencyMs.Average)
                    $latencyStatus = if ($avgLatency -lt 25) { "pass" } elseif ($avgLatency -lt 50) { "warning" } else { "fail" }
                    $healthItems += "<div class='health-card $latencyStatus'><h3>Disk Latency</h3><div class='value'>$([math]::Round($avgLatency, 1)) ms</div><span class='status $latencyStatus'>$($latencyStatus.ToUpper())</span></div>"
                }

                # DPC/ISR Time - Microsoft docs: >30% indicates driver/hardware issue
                if ($Data.PerformanceSampling.InterruptDPC.Statistics.CombinedTime) {
                    $dpcIsr = $Data.PerformanceSampling.InterruptDPC.Statistics.CombinedTime.Average
                    $dpcStatus = if ($dpcIsr -lt 15) { "pass" } elseif ($dpcIsr -lt 30) { "warning" } else { "fail" }
                    $healthItems += "<div class='health-card $dpcStatus'><h3>DPC/ISR Time</h3><div class='value'>$([math]::Round($dpcIsr, 1))%</div><span class='status $dpcStatus'>$($dpcStatus.ToUpper())</span></div>"
                }

                $healthItems -join "`n"
            )
        </div>

        <!-- System Information Section -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>System Information</h2>
                <span class="toggle">&#9660;</span>
            </div>
            <div class="section-content">
                <div class="metric-grid">
                    $(if ($Data.SystemInformation.CPU) { @"
                    <div class="metric-item">
                        <label>CPU</label>
                        <div class="value">$($Data.SystemInformation.CPU.Name)</div>
                    </div>
                    <div class="metric-item">
                        <label>Cores / Logical Processors</label>
                        <div class="value">$($Data.SystemInformation.CPU.Cores) / $($Data.SystemInformation.CPU.LogicalProcessors)</div>
                    </div>
"@ })
                    $(if ($Data.SystemInformation.Memory) { @"
                    <div class="metric-item">
                        <label>Total Memory</label>
                        <div class="value">$($Data.SystemInformation.Memory.TotalPhysicalGB) GB</div>
                    </div>
                    <div class="metric-item">
                        <label>Available Memory</label>
                        <div class="value">$($Data.SystemInformation.Memory.AvailableGB) GB</div>
                    </div>
"@ })
                    $(if ($Data.SystemInformation.OperatingSystem) { @"
                    <div class="metric-item">
                        <label>Operating System</label>
                        <div class="value">$($Data.SystemInformation.OperatingSystem.Caption)</div>
                    </div>
                    <div class="metric-item">
                        <label>Build</label>
                        <div class="value">$($Data.SystemInformation.OperatingSystem.BuildNumber)</div>
                    </div>
                    <div class="metric-item">
                        <label>Uptime</label>
                        <div class="value">$($Data.SystemInformation.OperatingSystem.UptimeFormatted)</div>
                    </div>
"@ })
                </div>

                <!-- Volumes Subsection -->
                $(if ($Data.SystemInformation.Volumes) { @"
                <div class="subsection">
                    <h3>Storage Volumes</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Drive</th>
                                <th>Label</th>
                                <th>Size</th>
                                <th>Free Space</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            $($Data.SystemInformation.Volumes | ForEach-Object { @"
                            <tr>
                                <td>$($_.DriveLetter)</td>
                                <td>$($_.Label)</td>
                                <td>$($_.SizeGB) GB</td>
                                <td>$($_.FreeSpaceGB) GB ($($_.FreeSpacePercent)%)</td>
                                <td><span class="status $($_.HealthStatus.ToLower())">$($_.HealthStatus)</span></td>
                            </tr>
"@ })
                        </tbody>
                    </table>
                </div>
"@ })

                <!-- Disks Subsection -->
                $(if ($Data.SystemInformation.Disks) { @"
                <div class="subsection">
                    <h3>Physical Disks</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Model</th>
                                <th>Type</th>
                                <th>Size</th>
                                <th>Health Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            $($Data.SystemInformation.Disks | ForEach-Object { @"
                            <tr>
                                <td>$($_.Model)</td>
                                <td>$($_.MediaType)</td>
                                <td>$($_.SizeGB) GB</td>
                                <td>$($_.HealthStatus)</td>
                            </tr>
"@ })
                        </tbody>
                    </table>
                </div>
"@ })

                <!-- Power Plan -->
                $(if ($Data.SystemInformation.PowerPlan) { @"
                <div class="subsection">
                    <h3>Power Plan</h3>
                    <div class="metric-grid">
                        <div class="metric-item">
                            <label>Active Power Plan</label>
                            <div class="value">$($Data.SystemInformation.PowerPlan.Name)</div>
                        </div>
                        $(if ($Data.SystemInformation.PowerPlan.Note) { @"
                        <div class="metric-item">
                            <label>Note</label>
                            <div class="value warning">$($Data.SystemInformation.PowerPlan.Note)</div>
                        </div>
"@ })
                    </div>
                </div>
"@ })

                <!-- Problem Devices -->
                $(if ($Data.SystemInformation.ProblemDevices -and $Data.SystemInformation.ProblemDevices.Count -gt 0) { @"
                <div class="subsection">
                    <h3>Problem Devices</h3>
                    <p style="color: #f0ad4e; margin-bottom: 10px;">Devices with errors in Device Manager may cause performance issues or driver problems.</p>
                    <table>
                        <thead>
                            <tr>
                                <th>Device Name</th>
                                <th>Error Code</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            $($Data.SystemInformation.ProblemDevices | ForEach-Object { @"
                            <tr>
                                <td>$($_.Name)</td>
                                <td>$($_.ErrorCode)</td>
                                <td>$($_.ErrorDescription)</td>
                            </tr>
"@ })
                        </tbody>
                    </table>
                </div>
"@ })
            </div>
        </div>

        <!-- Performance Sampling Section -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>Performance Sampling ($($Data.PerformanceSampling.DurationSeconds)s)</h2>
                <span class="toggle">&#9660;</span>
            </div>
            <div class="section-content">
                <div class="metric-grid">
                    $(if ($Data.PerformanceSampling.CPU.Statistics) { @"
                    <div class="metric-item">
                        <label>CPU - Min / Avg / Max</label>
                        <div class="value">$($Data.PerformanceSampling.CPU.Statistics.ProcessorTime.Min)% / $($Data.PerformanceSampling.CPU.Statistics.ProcessorTime.Average)% / $($Data.PerformanceSampling.CPU.Statistics.ProcessorTime.Max)%</div>
                    </div>
                    <div class="metric-item">
                        <label>Processor Queue Length (Avg)</label>
                        <div class="value">$($Data.PerformanceSampling.CPU.Statistics.ProcessorQueueLength.Average)</div>
                    </div>
"@ })
                    $(if ($Data.PerformanceSampling.Memory.Statistics) { @"
                    <div class="metric-item">
                        <label>Available Memory - Min / Avg / Max</label>
                        <div class="value">$($Data.PerformanceSampling.Memory.Statistics.AvailableMB.Min) MB / $($Data.PerformanceSampling.Memory.Statistics.AvailableMB.Average) MB / $($Data.PerformanceSampling.Memory.Statistics.AvailableMB.Max) MB</div>
                    </div>
                    <div class="metric-item">
                        <label>Hard Faults/sec (Avg)</label>
                        <div class="value">$($Data.PerformanceSampling.Memory.Statistics.HardFaultsPerSec.Average)</div>
                    </div>
"@ })
                    $(if ($Data.PerformanceSampling.Disk.Statistics) { @"
                    <div class="metric-item">
                        <label>Disk Read Latency (Avg)</label>
                        <div class="value">$($Data.PerformanceSampling.Disk.Statistics.ReadLatencyMs.Average) ms</div>
                    </div>
                    <div class="metric-item">
                        <label>Disk Write Latency (Avg)</label>
                        <div class="value">$($Data.PerformanceSampling.Disk.Statistics.WriteLatencyMs.Average) ms</div>
                    </div>
                    <div class="metric-item">
                        <label>Disk Queue Length (Avg)</label>
                        <div class="value">$($Data.PerformanceSampling.Disk.Statistics.QueueLength.Average)</div>
                    </div>
"@ })
                    $(if ($Data.PerformanceSampling.Network.Statistics) {
                        $networkHtml = ""
                        foreach ($adapter in $Data.PerformanceSampling.Network.Statistics.Keys) {
                            $stats = $Data.PerformanceSampling.Network.Statistics[$adapter]
                            $networkHtml += @"
                    <div class="metric-item">
                        <label>Network ($adapter) - Throughput</label>
                        <div class="value">$($stats.BytesPerSecMB.Average) MB/s avg (Max: $($stats.BytesPerSecMB.Max) MB/s)</div>
                    </div>
                    <div class="metric-item">
                        <label>Network ($adapter) - Errors</label>
                        <div class="value">$($stats.Errors.Max) (max during sampling)</div>
                    </div>
"@
                        }
                        $networkHtml
                    })
                    $(if ($Data.PerformanceSampling.InterruptDPC.Statistics) { @"
                    <div class="metric-item">
                        <label>DPC Time (Avg)</label>
                        <div class="value">$($Data.PerformanceSampling.InterruptDPC.Statistics.DPCTime.Average)%</div>
                    </div>
                    <div class="metric-item">
                        <label>Interrupt Time (Avg)</label>
                        <div class="value">$($Data.PerformanceSampling.InterruptDPC.Statistics.InterruptTime.Average)%</div>
                    </div>
                    <div class="metric-item">
                        <label>Combined DPC/ISR Time (Avg)</label>
                        <div class="value $(if ($Data.PerformanceSampling.InterruptDPC.Statistics.CombinedTime.Average -gt 15) { 'warning' } elseif ($Data.PerformanceSampling.InterruptDPC.Statistics.CombinedTime.Average -gt 30) { 'fail' })">$($Data.PerformanceSampling.InterruptDPC.Statistics.CombinedTime.Average)%</div>
                    </div>
"@ })
                </div>

                <!-- Peak Processes -->
                $(if ($Data.PerformanceSampling.PeakProcesses.ByCPU) { @"
                <div class="subsection">
                    <h3>Peak Processes by CPU</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Process</th>
                                <th>Total CPU (seconds)</th>
                            </tr>
                        </thead>
                        <tbody>
                            $($Data.PerformanceSampling.PeakProcesses.ByCPU | ForEach-Object { @"
                            <tr>
                                <td>$($_.ProcessName)</td>
                                <td>$($_.TotalCPUSeconds)</td>
                            </tr>
"@ })
                        </tbody>
                    </table>
                </div>
"@ })

                $(if ($Data.PerformanceSampling.PeakProcesses.ByMemory) { @"
                <div class="subsection">
                    <h3>Peak Processes by Memory</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Process</th>
                                <th>Average Memory (MB)</th>
                            </tr>
                        </thead>
                        <tbody>
                            $($Data.PerformanceSampling.PeakProcesses.ByMemory | ForEach-Object { @"
                            <tr>
                                <td>$($_.ProcessName)</td>
                                <td>$($_.AverageMemoryMB)</td>
                            </tr>
"@ })
                        </tbody>
                    </table>
                </div>
"@ })
            </div>
        </div>

        <!-- Process Analysis Section -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>Process Analysis</h2>
                <span class="toggle">&#9660;</span>
            </div>
            <div class="section-content">
                <div class="metric-grid">
                    <div class="metric-item">
                        <label>Total Processes</label>
                        <div class="value">$($Data.ProcessAnalysis.TotalProcessCount)</div>
                    </div>
                    <div class="metric-item">
                        <label>Total Threads</label>
                        <div class="value">$($Data.ProcessAnalysis.TotalThreadCount)</div>
                    </div>
                    <div class="metric-item">
                        <label>Total Handles</label>
                        <div class="value">$($Data.ProcessAnalysis.TotalHandleCount)</div>
                    </div>
                </div>

                <!-- Top by Memory -->
                $(if ($Data.ProcessAnalysis.TopByMemory) { @"
                <div class="subsection">
                    <h3>Top 10 Processes by Memory</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Process</th>
                                <th>PID</th>
                                <th>Working Set</th>
                                <th>Private Memory</th>
                            </tr>
                        </thead>
                        <tbody>
                            $($Data.ProcessAnalysis.TopByMemory | ForEach-Object { @"
                            <tr>
                                <td>$($_.Name)</td>
                                <td>$($_.PID)</td>
                                <td>$($_.WorkingSetMB) MB</td>
                                <td>$($_.PrivateMemoryMB) MB</td>
                            </tr>
"@ })
                        </tbody>
                    </table>
                </div>
"@ })

                <!-- Observations -->
                $(if ($Data.ProcessAnalysis.Observations -and $Data.ProcessAnalysis.Observations.Count -gt 0) { @"
                <div class="subsection">
                    <h3>Observations</h3>
                    <p style="color: #6c757d; margin-bottom: 15px;">These are observations that may be relevant to performance. Use your judgment to determine if they apply to the user's issue.</p>
                    $($Data.ProcessAnalysis.Observations | ForEach-Object { @"
                    <div class="issue-card" style="background: #f8f9fa; border-left: 4px solid #6c757d; padding: 15px; margin-bottom: 15px; border-radius: 4px;">
                        <div style="font-weight: bold; font-size: 1.1em; margin-bottom: 8px;">$($_.Category): $($_.Process)</div>
                        <div style="margin-bottom: 8px;"><strong>What:</strong> $($_.What)</div>
                        <div style="margin-bottom: 8px;"><strong>Context:</strong> $($_.Why)</div>
                        <div style="margin-bottom: 8px;"><strong>Possible action:</strong> $($_.Action)</div>
                    </div>
"@ })
                </div>
"@ })
            </div>
        </div>

        <!-- Browser Analysis Section -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>Browser Analysis</h2>
                <span class="toggle">&#9660;</span>
            </div>
            <div class="section-content">
                <div class="metric-grid">
                    $(if ($Data.BrowserAnalysis.Chrome) { @"
                    <div class="metric-item">
                        <label>Chrome Status</label>
                        <div class="value">$(if ($Data.BrowserAnalysis.Chrome.IsRunning) { "Running" } else { "Not Running" })</div>
                    </div>
                    $(if ($Data.BrowserAnalysis.Chrome.IsRunning) { @"
                    <div class="metric-item">
                        <label>Chrome Processes</label>
                        <div class="value">$($Data.BrowserAnalysis.Chrome.ProcessCount)</div>
                    </div>
                    <div class="metric-item">
                        <label>Chrome Memory</label>
                        <div class="value">$($Data.BrowserAnalysis.Chrome.TotalMemoryMB) MB</div>
                    </div>
                    <div class="metric-item">
                        <label>Chrome Extensions</label>
                        <div class="value">$($Data.BrowserAnalysis.Chrome.ExtensionCount)</div>
                    </div>
"@ })
"@ })
                    $(if ($Data.BrowserAnalysis.Edge) { @"
                    <div class="metric-item">
                        <label>Edge Status</label>
                        <div class="value">$(if ($Data.BrowserAnalysis.Edge.IsRunning) { "Running" } else { "Not Running" })</div>
                    </div>
                    $(if ($Data.BrowserAnalysis.Edge.IsRunning) { @"
                    <div class="metric-item">
                        <label>Edge Processes</label>
                        <div class="value">$($Data.BrowserAnalysis.Edge.ProcessCount)</div>
                    </div>
                    <div class="metric-item">
                        <label>Edge Memory</label>
                        <div class="value">$($Data.BrowserAnalysis.Edge.TotalMemoryMB) MB</div>
                    </div>
                    <div class="metric-item">
                        <label>Edge Extensions</label>
                        <div class="value">$($Data.BrowserAnalysis.Edge.ExtensionCount)</div>
                    </div>
"@ })
"@ })
                </div>

                <!-- Chrome Extensions List -->
                $(if ($Data.BrowserAnalysis.Chrome.Extensions -and $Data.BrowserAnalysis.Chrome.Extensions.Count -gt 0) { @"
                <div class="subsection">
                    <h3>Chrome Extensions ($($Data.BrowserAnalysis.Chrome.Extensions.Count))</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Extension Name</th>
                                <th>Version</th>
                            </tr>
                        </thead>
                        <tbody>
                            $($Data.BrowserAnalysis.Chrome.Extensions | ForEach-Object { @"
                            <tr>
                                <td>$($_.Name)</td>
                                <td>$($_.Version)</td>
                            </tr>
"@ })
                        </tbody>
                    </table>
                </div>
"@ })

                <!-- Edge Extensions List -->
                $(if ($Data.BrowserAnalysis.Edge.Extensions -and $Data.BrowserAnalysis.Edge.Extensions.Count -gt 0) { @"
                <div class="subsection">
                    <h3>Edge Extensions ($($Data.BrowserAnalysis.Edge.Extensions.Count))</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Extension Name</th>
                                <th>Version</th>
                            </tr>
                        </thead>
                        <tbody>
                            $($Data.BrowserAnalysis.Edge.Extensions | ForEach-Object { @"
                            <tr>
                                <td>$($_.Name)</td>
                                <td>$($_.Version)</td>
                            </tr>
"@ })
                        </tbody>
                    </table>
                </div>
"@ })
            </div>
        </div>

        <!-- Configuration Health Section -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>Configuration &amp; Policy Health</h2>
                <span class="toggle">&#9660;</span>
            </div>
            <div class="section-content">
                <!-- Pending Reboot Alert -->
                $(if ($Data.ConfigurationHealth.PendingReboot -and $Data.ConfigurationHealth.PendingReboot.IsRebootPending) { @"
                <div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 15px; margin-bottom: 20px;">
                    <h3 style="color: #856404; margin-bottom: 10px;">&#9888; Reboot Required</h3>
                    <p style="margin-bottom: 10px;">This system requires a restart. This is often the cause of performance issues and unexpected behavior.</p>
                    <ul style="margin: 0; padding-left: 20px;">
                        $($Data.ConfigurationHealth.PendingReboot.Reasons | ForEach-Object { "<li>$_</li>" })
                    </ul>
                </div>
"@ })

                <div class="metric-grid">
                    $(if ($Data.ConfigurationHealth.PendingReboot) { @"
                    <div class="metric-item">
                        <label>Reboot Pending</label>
                        <div class="value" style="color: $(if ($Data.ConfigurationHealth.PendingReboot.IsRebootPending) { '#dc3545' } else { '#28a745' })">$(if ($Data.ConfigurationHealth.PendingReboot.IsRebootPending) { "YES - Restart Needed" } else { "No" })</div>
                    </div>
"@ })
                    $(if ($Data.ConfigurationHealth.IntuneEnrollment) { @"
                    <div class="metric-item">
                        <label>Intune Enrolled</label>
                        <div class="value">$(if ($Data.ConfigurationHealth.IntuneEnrollment.IsEnrolled) { "Yes" } else { "No" })</div>
                    </div>
                    $(if ($Data.ConfigurationHealth.IntuneEnrollment.LastSyncTime) { @"
                    <div class="metric-item">
                        <label>Last Intune Sync</label>
                        <div class="value">$(if ($Data.ConfigurationHealth.IntuneEnrollment.LastSyncAgo) { "$($Data.ConfigurationHealth.IntuneEnrollment.LastSyncAgo) ($($Data.ConfigurationHealth.IntuneEnrollment.LastSyncTime))" } else { $Data.ConfigurationHealth.IntuneEnrollment.LastSyncTime })</div>
                    </div>
"@ })
"@ })
                    $(if ($Data.ConfigurationHealth.CompanyPortal) { @"
                    <div class="metric-item">
                        <label>Company Portal</label>
                        <div class="value">$(if ($Data.ConfigurationHealth.CompanyPortal.IsInstalled) { "Installed" } else { "Not Installed" })</div>
                    </div>
                    <div class="metric-item">
                        <label>Intune Management Extension</label>
                        <div class="value">$($Data.ConfigurationHealth.CompanyPortal.IntuneManagementExtension.Status)</div>
                    </div>
"@ })
                    $(if ($Data.ConfigurationHealth.WindowsUpdate) { @"
                    <div class="metric-item">
                        <label>Pending Updates</label>
                        <div class="value">$($Data.ConfigurationHealth.WindowsUpdate.PendingUpdates)</div>
                    </div>
"@ })
                    $(if ($Data.ConfigurationHealth.GPOCheck) { @"
                    <div class="metric-item">
                        <label>Domain GPO Detected</label>
                        <div class="value">$(if ($Data.ConfigurationHealth.GPOCheck.HasDomainGPO) { "Yes (Warning)" } else { "No" })</div>
                    </div>
"@ })
                    $(if ($Data.ConfigurationHealth.UserProfile) { @"
                    <div class="metric-item">
                        <label>User Profile Size</label>
                        <div class="value">$($Data.ConfigurationHealth.UserProfile.TotalSizeGB) GB</div>
                    </div>
"@ })
                </div>

                <!-- Page File -->
                $(if ($Data.ConfigurationHealth.PageFile.CurrentUsage) { @"
                <div class="subsection">
                    <h3>Page File Configuration</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Path</th>
                                <th>Allocated</th>
                                <th>Current Usage</th>
                                <th>Peak Usage</th>
                            </tr>
                        </thead>
                        <tbody>
                            $($Data.ConfigurationHealth.PageFile.CurrentUsage | ForEach-Object { @"
                            <tr>
                                <td>$($_.Path)</td>
                                <td>$($_.AllocatedMB) MB</td>
                                <td>$($_.CurrentUsageMB) MB ($($_.UsagePercent)%)</td>
                                <td>$($_.PeakUsageMB) MB</td>
                            </tr>
"@ })
                        </tbody>
                    </table>
                </div>
"@ })

                <!-- Recently Installed -->
                $(if ($Data.ConfigurationHealth.RecentlyInstalled -and ($Data.ConfigurationHealth.RecentlyInstalled.SoftwareCount -gt 0 -or $Data.ConfigurationHealth.RecentlyInstalled.UpdateCount -gt 0)) { @"
                <div class="subsection">
                    <h3>Recently Installed (Last 7 Days)</h3>
                    <p style="color: #6c757d; margin-bottom: 15px;">If the user reports "it was working fine until recently", check these installations.</p>
                    $(if ($Data.ConfigurationHealth.RecentlyInstalled.Software.Count -gt 0) { @"
                    <h4 style="margin: 15px 0 10px 0; font-size: 0.95em;">Software ($($Data.ConfigurationHealth.RecentlyInstalled.SoftwareCount) items)</h4>
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Version</th>
                                <th>Install Date</th>
                                <th>Publisher</th>
                            </tr>
                        </thead>
                        <tbody>
                            $($Data.ConfigurationHealth.RecentlyInstalled.Software | Select-Object -First 15 | ForEach-Object { @"
                            <tr>
                                <td>$($_.Name)</td>
                                <td>$($_.Version)</td>
                                <td>$($_.InstallDate)</td>
                                <td>$($_.Publisher)</td>
                            </tr>
"@ })
                        </tbody>
                    </table>
"@ })
                    $(if ($Data.ConfigurationHealth.RecentlyInstalled.Updates.Count -gt 0) { @"
                    <h4 style="margin: 15px 0 10px 0; font-size: 0.95em;">Windows Updates ($($Data.ConfigurationHealth.RecentlyInstalled.UpdateCount) items)</h4>
                    <table>
                        <thead>
                            <tr>
                                <th>Title</th>
                                <th>Date</th>
                                <th>Type</th>
                            </tr>
                        </thead>
                        <tbody>
                            $($Data.ConfigurationHealth.RecentlyInstalled.Updates | Select-Object -First 10 | ForEach-Object { @"
                            <tr>
                                <td>$($_.Title)</td>
                                <td>$($_.Date)</td>
                                <td>$($_.Type)</td>
                            </tr>
"@ })
                        </tbody>
                    </table>
"@ })
                </div>
"@ })

                <!-- User Profile Size -->
                $(if ($Data.ConfigurationHealth.UserProfile -and $Data.ConfigurationHealth.UserProfile.LargestFolders) { @"
                <div class="subsection">
                    <h3>User Profile ($($Data.ConfigurationHealth.UserProfile.TotalSizeGB) GB total)</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Folder</th>
                                <th>Size (GB)</th>
                            </tr>
                        </thead>
                        <tbody>
                            $($Data.ConfigurationHealth.UserProfile.LargestFolders | ForEach-Object { @"
                            <tr>
                                <td>$($_.Folder)</td>
                                <td>$($_.SizeGB)</td>
                            </tr>
"@ })
                        </tbody>
                    </table>
                </div>
"@ })

                <!-- Startup Programs -->
                $(if ($Data.ConfigurationHealth.StartupPrograms) { @"
                <div class="subsection">
                    <h3>Startup Programs ($($Data.ConfigurationHealth.StartupPrograms.TotalCount) items)</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Location</th>
                                <th>Scope</th>
                                <th>Type</th>
                            </tr>
                        </thead>
                        <tbody>
                            $($Data.ConfigurationHealth.StartupPrograms.Items | ForEach-Object { @"
                            <tr>
                                <td>$($_.Name)</td>
                                <td>$($_.Location)</td>
                                <td>$($_.Scope)</td>
                                <td>$($_.Type)</td>
                            </tr>
"@ })
                        </tbody>
                    </table>
                </div>
"@ })
            </div>
        </div>

        <!-- Event Log Summary Section -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>Event Log Summary (Last $($Data.EventLogSummary.TimeRange.HoursScanned) Hours)</h2>
                <span class="toggle">&#9660;</span>
            </div>
            <div class="section-content">
                <div class="metric-grid">
                    <div class="metric-item">
                        <label>Disk Events</label>
                        <div class="value">$($Data.EventLogSummary.Summary.TotalDiskEvents)</div>
                    </div>
                    <div class="metric-item">
                        <label>Kernel/Driver Errors</label>
                        <div class="value">$($Data.EventLogSummary.Summary.TotalKernelErrors)</div>
                    </div>
                    <div class="metric-item">
                        <label>Application Crashes</label>
                        <div class="value">$($Data.EventLogSummary.Summary.TotalAppCrashes)</div>
                    </div>
                    <div class="metric-item">
                        <label>Update Failures</label>
                        <div class="value">$($Data.EventLogSummary.Summary.TotalUpdateFailures)</div>
                    </div>
                    <div class="metric-item">
                        <label>Browser Crashes</label>
                        <div class="value">$($Data.EventLogSummary.Summary.TotalBrowserCrashes)</div>
                    </div>
                </div>

                $(if ($Data.EventLogSummary.KernelDriverErrors -and $Data.EventLogSummary.KernelDriverErrors.Count -gt 0) { @"
                <div class="subsection">
                    <h3>Kernel/Driver Errors</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Level</th>
                                <th>Provider</th>
                                <th>Message</th>
                            </tr>
                        </thead>
                        <tbody>
                            $($Data.EventLogSummary.KernelDriverErrors | Select-Object -First 10 | ForEach-Object { @"
                            <tr>
                                <td>$($_.TimeCreated)</td>
                                <td><span class="status fail">$($_.Level)</span></td>
                                <td>$($_.Provider)</td>
                                <td>$($_.Message)</td>
                            </tr>
"@ })
                        </tbody>
                    </table>
                </div>
"@ })

                $(if ($Data.EventLogSummary.ApplicationCrashes -and $Data.EventLogSummary.ApplicationCrashes.Count -gt 0) { @"
                <div class="subsection">
                    <h3>Application Crashes</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Application</th>
                                <th>Type</th>
                            </tr>
                        </thead>
                        <tbody>
                            $($Data.EventLogSummary.ApplicationCrashes | Select-Object -First 10 | ForEach-Object { @"
                            <tr>
                                <td>$($_.TimeCreated)</td>
                                <td>$($_.Application)</td>
                                <td>$(if ($_.Provider -eq 'Application Hang') { 'Hang' } else { 'Crash' })</td>
                            </tr>
"@ })
                        </tbody>
                    </table>
                </div>
"@ })
            </div>
        </div>

        <!-- Raw JSON Link -->
        $(if ($JsonPath) { @"
        <div style="text-align: center; margin: 30px 0;">
            <a href="$(Split-Path $JsonPath -Leaf)" class="json-link">Download Raw JSON Data</a>
        </div>
"@ })

        <footer>
            <p>Performance Scan v$($Data.Metadata.ScriptVersion) | Generated on $($Data.Metadata.ScanTimestamp)</p>
            <p>For internal IT use only</p>
        </footer>
    </div>

    <script>
        function toggleSection(header) {
            const section = header.parentElement;
            section.classList.toggle('collapsed');
        }

        // Collapse all sections except summary by default
        document.addEventListener('DOMContentLoaded', function() {
            // Keep first section (System Info) expanded
        });
    </script>
</body>
</html>
"@

        $html | Out-File -FilePath $Path -Encoding UTF8 -Force
        Write-Log -Message "HTML report saved: $Path" -Level Success
        return $true
    }
    catch {
        Add-InternalError -Module "Export" -Message "Failed to save HTML report" -ErrorRecord $_
        return $false
    }
}
#endregion

#region Main Execution
function Invoke-PULSE {
    <#
    .SYNOPSIS
        Main entry point for the performance scan
    #>
    [CmdletBinding()]
    param()

    $scanStartTime = Get-Date

    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "  PULSE v$($Script:Config.Version)" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""

    # Check elevation
    $Script:Config.IsElevated = Test-IsElevated
    $Script:Results.Metadata.IsElevated = $Script:Config.IsElevated

    if (-not $Script:Config.IsElevated -and -not $SkipElevationCheck) {
        Write-Log -Message "PULSE requires administrator privileges for full functionality." -Level Error
        Write-Log -Message "Please run PowerShell as Administrator, or use -SkipElevationCheck for limited data collection." -Level Error
        return
    }

    # Create output directory
    try {
        if (-not (Test-Path $Script:Config.OutputPath)) {
            New-Item -Path $Script:Config.OutputPath -ItemType Directory -Force | Out-Null
            Write-Log -Message "Created output directory: $($Script:Config.OutputPath)" -Level Info
        }
    }
    catch {
        Write-Log -Message "Failed to create output directory: $($_.Exception.Message)" -Level Error
        return
    }

    # Run all modules
    Write-Host ""
    $Script:Results.SystemInformation = Get-SystemInformation

    Write-Host ""
    $Script:Results.PerformanceSampling = Get-PerformanceSampling

    Write-Host ""
    $Script:Results.ProcessAnalysis = Get-ProcessAnalysis

    Write-Host ""
    $Script:Results.BrowserAnalysis = Get-BrowserAnalysis

    Write-Host ""
    $Script:Results.ConfigurationHealth = Get-ConfigurationHealth

    Write-Host ""
    $Script:Results.EventLogSummary = Get-EventLogSummary

    # Calculate total scan duration
    $scanEndTime = Get-Date
    $Script:Results.Metadata.ScanDurationSeconds = [math]::Round(($scanEndTime - $scanStartTime).TotalSeconds, 2)

    # Generate health summary
    # NOTE: This summary reflects PERFORMANCE health only, not compliance/configuration status.
    # Intune enrollment, event log history, and other non-performance items are shown in the report
    # for context but do not affect the overall performance status.
    $Script:Results.HealthSummary = [ordered]@{
        OverallStatus = "Pass"
        Issues = @()
    }

    # Helper function to escalate status (Pass < Warning < Fail)
    function Set-WorstStatus {
        param([string]$NewStatus)
        $statusOrder = @{ "Pass" = 0; "Warning" = 1; "Fail" = 2; "Unknown" = 0 }
        $currentOrder = $statusOrder[$Script:Results.HealthSummary.OverallStatus]
        $newOrder = $statusOrder[$NewStatus]
        if ($null -eq $newOrder) { $newOrder = 0 }
        if ($newOrder -gt $currentOrder) {
            $Script:Results.HealthSummary.OverallStatus = $NewStatus
        }
    }

    # Check for PERFORMANCE issues only
    $issues = [System.Collections.ArrayList]::new()

    # CPU: High sustained usage indicates bottleneck
    if ($Script:Results.PerformanceSampling.CPU.Statistics.ProcessorTime.Average -gt 80) {
        [void]$issues.Add("High average CPU usage ($($Script:Results.PerformanceSampling.CPU.Statistics.ProcessorTime.Average)%)")
        Set-WorstStatus -NewStatus "Warning"
    }

    # CPU: High processor queue indicates CPU contention
    if ($Script:Results.PerformanceSampling.CPU.Statistics.ProcessorQueueLength.Average -gt 2) {
        [void]$issues.Add("High processor queue length (avg $($Script:Results.PerformanceSampling.CPU.Statistics.ProcessorQueueLength.Average))")
        Set-WorstStatus -NewStatus "Warning"
    }

    # Memory: Low available memory causes slowness
    if ($Script:Results.SystemInformation.Memory.UsedPercent -gt 90) {
        [void]$issues.Add("High memory usage ($($Script:Results.SystemInformation.Memory.UsedPercent)%)")
        Set-WorstStatus -NewStatus "Warning"
    }

    # Disk: Low free space causes performance degradation
    $lowDiskVolumes = $Script:Results.SystemInformation.Volumes | Where-Object { $_.FreeSpacePercent -lt 10 }
    if ($lowDiskVolumes) {
        [void]$issues.Add("Low disk space on: $($lowDiskVolumes.DriveLetter -join ', ')")
        Set-WorstStatus -NewStatus "Fail"
    }

    # Disk: High latency indicates I/O bottleneck
    $avgReadLatency = $Script:Results.PerformanceSampling.Disk.Statistics.ReadLatencyMs.Average
    $avgWriteLatency = $Script:Results.PerformanceSampling.Disk.Statistics.WriteLatencyMs.Average
    if ($avgReadLatency -gt 50 -or $avgWriteLatency -gt 50) {
        [void]$issues.Add("High disk latency (Read: ${avgReadLatency}ms, Write: ${avgWriteLatency}ms)")
        Set-WorstStatus -NewStatus "Warning"
    }

    # Disk: Health issues indicate potential hardware failure
    $diskHealthIssues = $Script:Results.SystemInformation.Disks | Where-Object { $_.HealthStatus -ne "Healthy" -and $_.HealthStatus -ne "Unknown" }
    if ($diskHealthIssues) {
        [void]$issues.Add("Disk health issues detected")
        Set-WorstStatus -NewStatus "Fail"
    }

    # DPC/ISR: High interrupt processing time indicates driver issues
    # Microsoft documented threshold: >30% combined DPC+Interrupt time indicates driver/hardware issue
    $combinedDpcIsr = $Script:Results.PerformanceSampling.InterruptDPC.Statistics.CombinedTime.Average
    if ($combinedDpcIsr -gt 30) {
        [void]$issues.Add("High DPC/Interrupt time ($([math]::Round($combinedDpcIsr, 1))%) - potential driver issue")
        Set-WorstStatus -NewStatus "Fail"
    } elseif ($combinedDpcIsr -gt 15) {
        [void]$issues.Add("Elevated DPC/Interrupt time ($([math]::Round($combinedDpcIsr, 1))%) - investigate drivers")
        Set-WorstStatus -NewStatus "Warning"
    }

    $Script:Results.HealthSummary.Issues = @($issues)

    # Add internal errors to results
    $Script:Results.InternalErrors = @($Script:InternalErrors)

    # Export reports
    Write-Host ""
    Write-Log -Message "Generating reports..." -Level Info

    $jsonSuccess = Export-JsonReport -Data $Script:Results -Path $Script:Config.JsonPath
    $htmlSuccess = Export-HtmlReport -Data $Script:Results -Path $Script:Config.HtmlPath -JsonPath $Script:Config.JsonPath

    # Generate markdown report for ticket attachments
    $markdownPath = $Script:Config.JsonPath -replace '\.json$', '.md'
    $markdownSuccess = Export-MarkdownReport -Data $Script:Results -Path $markdownPath

    # Generate work note summary and copy to clipboard
    $workNoteSummary = Get-WorkNoteSummary -Data $Script:Results
    try {
        $workNoteSummary | Set-Clipboard -ErrorAction Stop
        $clipboardSuccess = $true
    }
    catch {
        $clipboardSuccess = $false
        Add-InternalError -Module "Export" -Message "Failed to copy summary to clipboard" -ErrorRecord $_
    }

    # Write error log if there were any internal errors
    if ($Script:InternalErrors.Count -gt 0) {
        Write-Log -Message "Encountered $($Script:InternalErrors.Count) internal errors during scan" -Level Warning
    }

    # Summary
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "  Scan Complete" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Duration: $($Script:Results.Metadata.ScanDurationSeconds) seconds" -ForegroundColor White
    Write-Host "Status: $($Script:Results.HealthSummary.OverallStatus)" -ForegroundColor $(
        switch ($Script:Results.HealthSummary.OverallStatus) {
            "Pass" { "Green" }
            "Warning" { "Yellow" }
            "Fail" { "Red" }
            default { "White" }
        }
    )

    if ($issues.Count -gt 0) {
        Write-Host ""
        Write-Host "Issues Found:" -ForegroundColor Yellow
        foreach ($issue in $issues) {
            Write-Host "  - $issue" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "Reports saved to:" -ForegroundColor White
    if ($jsonSuccess) { Write-Host "  JSON: $($Script:Config.JsonPath)" -ForegroundColor Gray }
    if ($htmlSuccess) { Write-Host "  HTML: $($Script:Config.HtmlPath)" -ForegroundColor Green }
    if ($markdownSuccess) { Write-Host "  Markdown: $markdownPath" -ForegroundColor Green }
    if ($Script:InternalErrors.Count -gt 0) {
        Write-Host "  Errors: $($Script:Config.ErrorLogPath)" -ForegroundColor Yellow
    }

    Write-Host ""
    if ($clipboardSuccess) {
        Write-Host "Work note summary copied to clipboard - ready to paste into ServiceNow!" -ForegroundColor Cyan
    }
    else {
        Write-Host "Note: Could not copy summary to clipboard" -ForegroundColor Yellow
    }
    Write-Host ""

    # Return path to HTML report for easy access
    return $Script:Config.HtmlPath
}

# Run the scan
$reportPath = Invoke-PULSE

# Open HTML report if running interactively
if ($Host.Name -eq 'ConsoleHost' -and $reportPath -and (Test-Path $reportPath)) {
    $openReport = Read-Host "Open HTML report in browser? (Y/N)"
    if ($openReport -eq 'Y' -or $openReport -eq 'y') {
        Start-Process $reportPath
    }
}
#endregion
