# PULSE

**Performance Utilization & Latency Sampling Engine**

**Technicians spend hours diagnosing "slowness" complaints. This gives them answers in 60 seconds.**

When a user reports their workstation is slow, technicians face a time-consuming process: manually checking Task Manager, event logs, disk space, pending updates, and running processes. PULSE automates this entire diagnostic workflow, collecting comprehensive performance data and generating a ready-to-paste summary for ServiceNow tickets.

---

**How it works:**

1. Technician runs `.\PULSE.ps1` on the affected workstation (requires Administrator)
2. Script collects 60 seconds of performance samples plus system configuration data
3. Script generates HTML report for visual analysis
4. Script copies work note summary to clipboard for immediate ServiceNow paste
5. Technician attaches markdown report to ticket for documentation

---

**What this tool does:**
- Identifies CPU, memory, and disk bottlenecks with documented Microsoft thresholds
- Detects pending reboots that may be causing issues
- Shows recent software/update installs that correlate with slowness onset
- Lists top resource-consuming processes and browser extensions
- Provides Intune enrollment and sync status
- Generates ServiceNow-ready work notes automatically

**What this tool does not do:**
- Modify, delete, or alter the system in any way (read-only)
- Run continuously or as a scheduled task (on-demand only)
- Require internet connectivity or external dependencies

---

**Key characteristics:**

| Characteristic | Description |
|----------------|-------------|
| Read-only | Discovery only; creates reports, nothing else |
| Self-contained | Single PowerShell file, no modules required |
| Enterprise-ready | Designed for Intune-managed Windows 11 workstations |
| Offline capable | No internet required |
| Non-disruptive | Runs quietly without user interruption |

---

For technical implementation details, see [DOCUMENTATION.md](DOCUMENTATION.md).

---

**Developed by:** Joshua Walderbach
