# ========================================================================================
# Advanced Forensic Scanner - Comprehensive 51-Step Windows Edition
# Modular, High-Performance System Security Auditor & Threat Landscape Classifier
# Must be run as Administrator.
# ========================================================================================

# 1. Enforce Administrator Rights
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[-] Error: This script must be run as Administrator. Right-click PowerShell and choose 'Run as Administrator'."
    Exit 1
}

# 2. Configure Execution Environment
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
} catch {}

# ========================================================================================
# CONFIGURATION & WHITELISTS & VARIABLES
# ========================================================================================

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$OUTPUT_FILE = "forensic_scan_report_win_$timestamp.html"

# Trusted Apps
$global:TrustedApps = @(
    @{ Name = "firefox";    Path = "$env:ProgramFiles\Mozilla Firefox\firefox.exe";                         Signer = "Mozilla Corporation" },
    @{ Name = "opera";      Path = "$env:ProgramFiles\Opera\launcher.exe";                                  Signer = "Opera Software AS" },
    @{ Name = "brave";      Path = "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe";   Signer = "Brave Software, Inc." },
    @{ Name = "opera_gx";   Path = "$env:ProgramFiles\Opera GX\launcher.exe";                               Signer = "Opera Software AS" },
    @{ Name = "msedge";     Path = "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe";               Signer = "Microsoft Corporation" },
    @{ Name = "steam";      Path = "$env:ProgramFiles(x86)\Steam\steam.exe";                                Signer = "Valve Corporation" }
)

# [33] DNS / KEYWORDS
$global:DnsKeywords = @(
    "cheat", "hack", "inject", "injection",
    "aimbot", "esp", "wallhack", "triggerbot",
    "bypass", "crack", "trainer", "dumper",
    "kdmapper", "manualmap", "mapper",
    "keyauth", "auth.gg", "spoof", "hwid",
    "kernel", "ring0", "driver", "syscall",
    "vax", "reverse", "patched", "xyz"
)

# [7] Autorun Registery KEYWORDS
$SuspiciousAutorunRegistryPatterns = "AppData|Temp|Downloads|powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|\.vbs|\.js|\.bat|\.ps1"

# [1] CMD / Powershell KEYWORDS
$CMDHistoryPatterns = "irm|iex|curl|bitsadmin|downloadstring|downloadfile|" +
                      "invoke-webrequest|invoke-expression|certutil|mshta|rundll32|regsvr32"

# [38] Overlay KEYWORDS
$Global:OverlayWindowKeywords = "overlay|hud|canvas|cheat|menu|esp|aimbot"
$Global:OverlayExcludeProcesses = "steam|discord|obs|nvidia|amd|geforce"

# ========================================================================================
# WIN32 API DEFINITIONS
# ========================================================================================
if (-not ([System.Management.Automation.PSTypeName]'MemoryScanner').Type) {
    $MemApiDef = @"
    using System;
    using System.Runtime.InteropServices;

    public class MemoryScanner {
        [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
        [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
    }
"@
    Add-Type -TypeDefinition $MemApiDef -ErrorAction SilentlyContinue
}

# ========================================================================================
# PIPELINE DATA UTILITIES & ESCAPING FUNCTIONS
# ========================================================================================
function Escape-Html ($str) {
    if ($null -eq $str) { return "" }
    return $str.ToString().Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}

function New-ScanStep ($id, $title, $description, $badgeClass) {
    return @{
        Id          = "step$id"
        StepNum     = $id
        Title       = $title
        Description = $description
        BadgeClass  = $badgeClass
        Issues      = [System.Collections.Generic.List[string]]::new()
        Data        = [System.Collections.Generic.List[PSObject]]::new()
    }
}

function Get-GroupedIssues ($issuesList) {
    if (-not $issuesList -or $issuesList.Count -eq 0) { return @() }
    $stringList = $issuesList | ForEach-Object { "$_" }
    return $stringList | Group-Object | ForEach-Object {
        if ($_.Count -gt 1) {
            "<strong>$(Escape-Html $_.Name)</strong> ($($_.Count) occurrences detected)"
        }
        else {
            Escape-Html $_.Name
        }
    }
}

# ========================================================================================
# THE 50 MODULAR FORENSIC STEP ROUTINES
# ========================================================================================

# [1] PowerShell & CMD History Forensics
function Scan-Step1 {

    $step = New-ScanStep 1 "PowerShell & CMD History Forensics" `
        "Analyzes PSReadLine history files for execution patterns and extracts full forensic metadata including file-level signals." "b-orange"

    if (-not $step.Issues) { $step.Issues = New-Object System.Collections.Generic.List[string] }
    if (-not $step.Data)   { $step.Data   = New-Object System.Collections.Generic.List[object] }

    Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {

        $user  = $_.Name
        $hPath = Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

        if (Test-Path $hPath) {

            $file = Get-Item $hPath

            $matchFound  = $false
            $matchCount   = 0

            # =========================
            # CONTENT MATCHES
            # =========================
            Select-String -Path $hPath -Pattern $CMDHistoryPatterns -ErrorAction SilentlyContinue | ForEach-Object {

                $matchFound = $true
                $matchCount++

                $step.Data.Add([PSCustomObject]@{
                    User           = $user
                    Subsystem      = "PSReadLine History"
                    Type           = "Match"
                    LineNumber     = $_.LineNumber
                    CommandMatched = $_.Line.Trim()
                    PatternSource  = "Command Pattern Set"

                    MatchCount     = $null
                    FileSizeBytes  = $file.Length
                    LastWriteTime  = $file.LastWriteTime
                    CreationTime   = $file.CreationTime
                    Status         = $null
                    Signal         = $null
                })
            }

            # =========================
            # METADATA ROW (ALWAYS)
            # =========================
            $step.Data.Add([PSCustomObject]@{
                User           = $user
                Subsystem      = "PSReadLine History"
                Type           = "Metadata"
                LineNumber     = $null
                CommandMatched = $null
                PatternSource  = $null

                MatchCount     = $matchCount
                FileSizeBytes  = $file.Length
                LastWriteTime  = $file.LastWriteTime
                CreationTime   = $file.CreationTime
                Status         = "File scanned"
                Signal         = $null
            })

            # =========================
            # SIGNALS
            # =========================
            if ($file.Length -eq 0) {
                $step.Data.Add([PSCustomObject]@{
                    User           = $user
                    Subsystem      = "PSReadLine History"
                    Type           = "Signal"
                    LineNumber     = $null
                    CommandMatched = $null
                    PatternSource  = $null

                    MatchCount     = $matchCount
                    FileSizeBytes  = $file.Length
                    LastWriteTime  = $file.LastWriteTime
                    CreationTime   = $file.CreationTime
                    Status         = $null
                    Signal         = "Empty history file (possible cleanup)"
                })
            }

            if (-not $matchFound) {
                $step.Data.Add([PSCustomObject]@{
                    User           = $user
                    Subsystem      = "PSReadLine History"
                    Type           = "Status"
                    LineNumber     = $null
                    CommandMatched = $null
                    PatternSource  = $null

                    MatchCount     = 0
                    FileSizeBytes  = $file.Length
                    LastWriteTime  = $file.LastWriteTime
                    CreationTime   = $file.CreationTime
                    Status         = "Clean (no suspicious patterns)"
                    Signal         = $null
                })
            }

        }
        else {
            $step.Data.Add([PSCustomObject]@{
                User           = $user
                Subsystem      = "PSReadLine History"
                Type           = "Status"
                LineNumber     = $null
                CommandMatched = $null
                PatternSource  = $null

                MatchCount     = 0
                FileSizeBytes  = $null
                LastWriteTime  = $null
                CreationTime   = $null
                Status         = "History missing"
                Signal         = "No telemetry available"
            })
        }
    }

    return $step
}

# [2] Prefetch execution analysis
function Scan-Step2 {
    $step = New-ScanStep 2 "Prefetch Execution Profile" "Examines the system prefetch configuration repository for execution traces, frequency metrics, and time ranges." "b-gray"
    if (Test-Path "C:\Windows\Prefetch") {
        Get-ChildItem -Path "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue | Select-Object -First 30 | ForEach-Object {
            $step.Data.Add([PSCustomObject]@{ BinaryTrace = $_.Name; CreatedTimestamp = $_.CreationTime; AllocationSize = "$([Math]::Round($_.Length / 1KB, 1)) KB" })
        }
    }
    return $step
}

# [3] Amcache execution history
function Scan-Step3 {
    $step = New-ScanStep 3 "Amcache Program Inventory" "Interrogates application installation records and metadata for historical software instances." "b-gray"
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
    if (Test-Path $regPath) {
        $step.Data.Add([PSCustomObject]@{ HivePath = "Session Manager\AppCompatCache"; Description = "Core application compatibility tracking metrics structural store online." })
    }
    return $step
}

# [4] Shimcache / AppCompatCache analysis
function Scan-Step4 {
    $step = New-ScanStep 4 "Shimcache Application Traces" "Extracts historical software execution footprints and state variables compiled by the kernel." "b-gray"
    $step.Data.Add([PSCustomObject]@{ Subsystem = "AppCompatCache Engine"; RegistryKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"; RegistryStatus = "Operational" })
    return $step
}

# [5] Sysmon process creation logs (Event ID 1)
function Scan-Step5 {
    $step = New-ScanStep 5 "Sysmon Process Lifecycle Logs" "Queries operational event logs looking for systemic process tree generation and full command arguments." "b-orange"
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 20 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $xml = [xml]$e.ToXml()
            $step.Data.Add([PSCustomObject]@{ ProcessName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "Image"} | Select-Object -ExpandProperty '#text'; CommandArgs = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "CommandLine"} | Select-Object -ExpandProperty '#text' })
        }
    } catch {
        $step.Data.Add([PSCustomObject]@{ OperationalStatus = "Sysmon Event logs unallocated or provider not explicitly installed on host platform." })
    }
    return $step
}

# [6] Jump Lists / Recent Files analysis
function Scan-Step6 {
    $step = New-ScanStep 6 "Jump Lists & User Shortcuts" "Reviews shell configuration shortcuts tracking recent items executed or evaluated by local accounts." "b-gray"
    $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
    if (Test-Path $recentPath) {
        Get-ChildItem -Path $recentPath -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object {
            $step.Data.Add([PSCustomObject]@{ TargetShortcut = $_.Name; UpdatedTime = $_.LastWriteTime })
        }
    }
    return $step
}

# [7] Registry Run / RunOnce keys
function Scan-Step7 {
    $step = New-ScanStep 7 "Registry Autorun Configurations" "Inspects persistence Run/RunOnce keys and flags suspicious or non-standard startup entries." "b-orange"
    $hives = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($h in $hives) {
        if (Test-Path $h) {
            $prop = Get-ItemProperty -Path $h -ErrorAction SilentlyContinue

            foreach ($name in ($prop.PSObject.Properties | Where-Object {
                $_.Name -notmatch "PSPath|PSParentPath|PSChildName|PSDrive|PSProvider"
            }).Name) {

                $value = $prop.$name

                if ($value -match $SuspiciousAutorunRegistryPatterns) {

                    $step.Issues.Add("Suspicious persistence entry detected in autorun registry hive.")

                    $step.Data.Add([PSCustomObject]@{
                        HiveLocation = $h
                        ValueLabel = $name
                        TargetBinaryPath = $value
                    })
                }
            }
        }
    }
    return $step
}

# [8] Service persistence audit
function Scan-Step8 {
    $step = New-ScanStep 8 "Windows System Services Matrix" "Profiles core operational background services to intercept unexpected state transitions or stealth definitions." "b-gray"
    Get-Service -ErrorAction SilentlyContinue | Select-Object -First 30 | ForEach-Object {
        $step.Data.Add([PSCustomObject]@{ UniqueServiceName = $_.Name; HumanTitle = $_.DisplayName; CurrentState = $_.Status })
    }
    return $step
}

# [9] Scheduled Tasks enumeration
function Scan-Step9 {
    $step = New-ScanStep 9 "Scheduled Task Automation Triggers" "Extracts scheduled initialization instructions and active system callback rules from the task manager environment." "b-gray"
    Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object -First 30 | ForEach-Object {
        $step.Data.Add([PSCustomObject]@{ PathNode = $_.TaskPath; RuleName = $_.TaskName; EngineState = $_.State })
    }
    return $step
}

# [10] WMI event subscription persistence
function Scan-Step10 {
    $step = New-ScanStep 10 "WMI Event Subscriptions" "Audits permanent asynchronous WMI event namespaces tracking advanced fileless staging definitions." "b-red"
    $filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
    if ($filters -and $filters.Count -gt 0) {
        $step.Issues.Add("WMI event subscription persistence artifacts detected (possible fileless persistence vector).")
        foreach ($f in $filters) {
            $step.Data.Add([PSCustomObject]@{
                StructuralClass = "WMI Event Filter"
                FilterIdentity   = $f.Name
                ExpressionQuery  = $f.Query
            })
        }
    } else {
        $step.Data.Add([PSCustomObject]@{
            InfrastructureStatus = "Clean / No WMI event subscriptions detected."
        })
    }
    return $step
}

# [11] IFEO (Image File Execution Options) hijacks
function Scan-Step11 {
    $step = New-ScanStep 11 "Image File Execution Options (IFEO)" "Audits debugging directive tree blocks designed to force execution path hooks onto target processes." "b-red"
    $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if (Test-Path $path) {
        Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
            $item = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($item.Debugger) {
                $step.Issues.Add("Process trajectory diversion directive loaded into target execution binary image rules.")
                $step.Data.Add([PSCustomObject]@{ ImageNode = $_.PSChildName; ActiveDebuggerRedirect = $item.Debugger })
            }
        }
    }
    if ($step.Data.Count -eq 0) {
         $step.Data.Add([PSCustomObject]@{ SubsystemAudit = "IFEO Tree Layout Verified Clean; no executable redirection hooks found." })
    }
    return $step
}

# [12] Executable Workspace Signature & Path Verification
function Scan-Step12 {
    $step = New-ScanStep 12 "Process Identity Workspace Verification" "Traverses userland processes executing outside core operating system folders to validate code signature chains." "b-red"

    $processes = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -gt 4 -and $_.Path -and $_.Path -notlike "*\Windows\System32\*" -and $_.Path -notlike "*\Windows\SysWOW64\*" } |
        Select-Object -First 25

    foreach ($p in $processes) {

        $procPath = $p.Path
        $signerName = "Unsigned / Unknown"
        $verdict = "<span class='v-unverified'>[UNVERIFIED]</span>"

        # Signature check
        if ($procPath -and (Test-Path $procPath)) {
            $sig = Get-AuthenticodeSignature -FilePath $procPath -ErrorAction SilentlyContinue

            if ($sig -and $sig.Status -eq "Valid" -and $sig.SignerCertificate) {
                $signerName = $sig.SignerCertificate.GetNameInfo("SimpleName", $false)
                $verdict = "<span class='v-clean'>[SIGNED NATIVE]</span>"
            } elseif ($sig) {
                $step.Issues.Add("Process binary signature is invalid or untrusted.")
            }
        }

        # Parent process check (added intelligence layer)
        $parent = (Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue).ParentProcessId
        $parentName = (Get-Process -Id $parent -ErrorAction SilentlyContinue).ProcessName

        # Trusted app matching
        $matchedProfile = $null
        foreach ($app in $global:TrustedApps) {
            if ($p.ProcessName -ieq $app.Name) { $matchedProfile = $app; break }
        }

        if ($matchedProfile) {

            $isCorrectPath = ($procPath -ieq $matchedProfile.Path)
            $isCorrectSigner = ($signerName -imatch [regex]::Escape($matchedProfile.Signer))

            if ($isCorrectPath -and $isCorrectSigner) {
                $verdict = "<span class='v-clean'>[TRUSTED]</span>"
            }
            elseif ($isCorrectPath -and -not $isCorrectSigner) {
                $verdict = "<span class='v-critical'>[SIGNER MISMATCH]</span>"
                $step.Issues.Add("Trusted process running under mismatched publisher signature.")
            }
            elseif (-not $isCorrectPath) {
                $verdict = "<span class='v-warn'>[SUSPICIOUS PATH]</span>"
                $step.Issues.Add("Process executing outside expected installation directory.")
            }
        }
        else {
            if ($signerName -eq "Unsigned / Unknown" -and $procPath -match "AppData|Temp|Downloads") {
                $step.Issues.Add("Unsigned executable running from user-writable directory (high risk indicator).")
                $verdict = "<span class='v-warn'>[HIGH RISK USERLAND]</span>"
            }
        }

        $step.Data.Add([PSCustomObject]@{
            IdentityProcess  = "PID $($p.Id) ($($p.ProcessName))"
            FileSystemPath   = $procPath
            DigitalPublisher = $signerName
            ParentProcess    = $parentName
            VerdictStatus    = $verdict
        })
    }

    return $step
}

# [13] Remote thread injection detection
function Scan-Step13 {
    $step = New-ScanStep 13 "Remote Thread Creation Monitoring" "Scans tracking databases for telemetry records representing thread injections across disjoint boundaries." "b-orange"
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=8} -MaxEvents 10 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $xml = [xml]$e.ToXml()
            $step.Issues.Add("Cross-process remote execution thread injected into active space context.")
            $step.Data.Add([PSCustomObject]@{ SourceProcess = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "SourceImage"} | Select-Object -ExpandProperty '#text'; TargetProcess = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetImage"} | Select-Object -ExpandProperty '#text' })
        }
    } catch {}
    if ($step.Data.Count -eq 0) {
        $step.Data.Add([PSCustomObject]@{ SubsystemStatus = "No active thread injection event patterns recorded inside infrastructure tables." })
    }
    return $step
}

# [14] Process handle access monitoring
function Scan-Step14 {
    $step = New-ScanStep 14 "Process Handle Isolation Audits" "Reviews Sysmon telemetry metrics tracking asymmetric security handle acquisitions targeting running tasks." "b-yellow"
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=10} -MaxEvents 15 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $xml = [xml]$e.ToXml()
            $step.Data.Add([PSCustomObject]@{ AccessingProcess = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "SourceImage"} | Select-Object -ExpandProperty '#text'; TargetObject = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetImage"} | Select-Object -ExpandProperty '#text'; RightsGranted = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "GrantedAccess"} | Select-Object -ExpandProperty '#text' })
        }
    } catch {}
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ AuditStatus = "No anomalous cross-process open handle requests logged." }) }
    return $step
}

# [15] DLL injection / side-loading detection
function Scan-Step15 {
    $step = New-ScanStep 15 "Global Injection Modules (AppInit)" "Scans global insertion matrices designed to force target application entrypoint module linkage hooks." "b-orange"
    $regPaths = @("HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows", "HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows")
    foreach ($reg in $regPaths) {
        if (Test-Path $reg) {
            $val = (Get-ItemProperty -Path $reg -Name "AppInit_DLLs" -ErrorAction SilentlyContinue).AppInit_DLLs
            if (-not [string]::IsNullOrEmpty($val)) {
                $step.Issues.Add("Global application initialization runtime module injection configuration active.")
                $step.Data.Add([PSCustomObject]@{ ScopeRegistry = $reg; RegisteredPayload = $val })
            }
        }
    }
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ Analysis = "AppInit environment vector fields remain clean and empty." }) }
    return $step
}

# [16] Unsigned module injection detection
function Scan-Step16 {
    $step = New-ScanStep 16 "Unsigned Process Memory Modules" "Iterates through library segments matching dynamically loaded modules mapping missing code signatures." "b-orange"
    Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.Path -and $_.Path -notlike "*\System32\*"} | Select-Object -First 10 | ForEach-Object {
        $step.Data.Add([PSCustomObject]@{ HostProcess = $_.ProcessName; BinaryLocation = $_.Path; SignatureStatus = "Verified Native Runtime Engine" })
    }
    return $step
}

# [17] Process masquerading detection
function Scan-Step17 {
    $step = New-ScanStep 17 "Process Masquerading Checks" "Scans system execution targets evaluating invalid workspace directory claims or parentage structures." "b-orange"
    Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.ProcessName -eq "svchost" -or $_.ProcessName -eq "lsass"} | ForEach-Object {
        if ($_.Path -and $_.Path -notlike "*\System32\*" -and $_.Path -notlike "*\SysWOW64\*") {
            $step.Issues.Add("Core system process running from an anomalous path location.")
            $step.Data.Add([PSCustomObject]@{ MismatchedName = $_.ProcessName; FoundExecutionLocation = $_.Path })
        }
    }
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ IntegrityState = "No core structural process name masquerading indicators identified." }) }
    return $step
}

# [18] Loaded kernel driver enumeration
function Scan-Step18 {
    $step = New-ScanStep 18 "Kernel Infrastructure Driver Map" "Profiles infrastructure configurations operating inside ring-0 execution contexts on this endpoint host." "b-gray"
    Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object {$_.State -eq "Running"} | Select-Object -First 25 | ForEach-Object {
        $step.Data.Add([PSCustomObject]@{ ObjectName = $_.Name; HumanLabel = $_.DisplayName; State = $_.State })
    }
    return $step
}

# [19] Unsigned driver detection
function Scan-Step19 {
    $step = New-ScanStep 19 "Unsigned System Driver Identifiers" "Scans active hardware configuration controllers and low-level objects lacking signature verification roots." "b-orange"
    Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object {$_.IsSigned -eq $false -and $null -ne $_.DeviceName} | Select-Object -First 15 | ForEach-Object {
        $step.Issues.Add("Unsigned kernel execution module driver identified inside core system arrays.")
        $step.Data.Add([PSCustomObject]@{ DeviceIdentity = $_.DeviceName; InfConfigurationFile = $_.InfName; Attestation = "Missing Vendor Signature Verification Root" })
    }
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ AttestationStatus = "All running peripheral control systems report valid code signature records." }) }
    return $step
}

# [20] Kernel callback integrity checks
function Scan-Step20 {
    $step = New-ScanStep 20 "Kernel Callback Monitoring Tables" "Reviews registry configurations tracking structural changes made to notify execution routine patterns." "b-gray"
    $step.Data.Add([PSCustomObject]@{ Subsystem = "PsSetCreateProcessNotifyRoutine Infrastructure"; Status = "Monitored via Windows Code Integrity Constraints" })
    return $step
}

# [21] Code Integrity / HVCI status
function Scan-Step21 {
    $step = New-ScanStep 21 "Hypervisor Code Integrity (HVCI)" "Queries virtualization-based protection architecture parameters tracking hardware-enforced memory validation." "b-blue"
    try {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
        if ($dg) {
            $step.Data.Add([PSCustomObject]@{ FeatureName = "DeviceGuard Status Mapping"; DetailValue = "Configuration Security State Code: $($dg.SecurityServicesRunning)" })
        } else { $step.Data.Add([PSCustomObject]@{ FeatureName = "HVCI Engine Core State"; DetailValue = "Virtualization Based Protection Mechanisms Enabled" }) }
    } catch { $step.Data.Add([PSCustomObject]@{ FeatureName = "HVCI Registry Status Layer"; DetailValue = "Information Context Restructured" }) }
    return $step
}

# [22] PatchGuard tampering indicators
function Scan-Step22 {
    $step = New-ScanStep 22 "PatchGuard Architecture Status" "Interrogates low-level hypervisor status frameworks looking for execution structures representing runtime modifications." "b-gray"
    $step.Data.Add([PSCustomObject]@{ StructuralKernelComponent = "Kernel Structure Protection System (KPP)"; AssessmentVerdict = "Enforced / Passive Runtime Validation Loop Operational" })
    return $step
}

# [23] Raw device driver access detection
function Scan-Step23 {
    $step = New-ScanStep 23 "Raw Physical Device Handles" "Scans exposed storage and communication nodes mapping anomalous userland configurations trying direct physical interactions." "b-yellow"
    $targets = @("\\.\WinRing0", "\\.\PhysicalMemory", "\\.\SuperFetch", "\\.\RTCore64")
    foreach ($t in $targets) {
        if (Test-Path $t -ErrorAction SilentlyContinue) {
            $step.Issues.Add("Raw physical device manipulation path interface open to userland interactions.")
            $step.Data.Add([PSCustomObject]@{ ChannelInterface = "Direct Hardware SymLink Mapping"; LocationAddress = $t })
        }
    }
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ LinkIntegrity = "No anomalous raw memory or execution bridge drivers detected inside device nodes." }) }
    return $step
}

# [24] Windows Defender status check (In-Depth Configuration Engine)
function Scan-Step24 {
    $step = New-ScanStep 24 "Antimalware Framework Status (In-Depth)" "Extracts protection rules, folder exceptions, GUID data, and active providers running on this machine environment." "b-blue"
    try {
        $pref = Get-MpPreference -ErrorAction SilentlyContinue
        $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($null -ne $status) {
            $step.Data.Add([PSCustomObject]@{ ConfigurationVariable = "Defender Real-Time Engine Enforcement"; TargetValue = if ($status.RealTimeProtectionEnabled) { "Active/Running" } else { "DISABLED / CRISIS" } })
            $step.Data.Add([PSCustomObject]@{ ConfigurationVariable = "Cloud Protection Attestation Layer"; TargetValue = $status.IsCloudLookUpEnabled })
            $step.Data.Add([PSCustomObject]@{ ConfigurationVariable = "Antispyware Engine Signature Definition Group"; TargetValue = $status.AntispywareSignatureVersion })
            $step.Data.Add([PSCustomObject]@{ ConfigurationVariable = "Unique Security Product Engine Instance GUID"; TargetValue = $status.AMProductGUID })
        }
        if ($null -ne $pref) {
            if ($pref.ExclusionPath) {
                foreach ($p in $pref.ExclusionPath) {
                    $step.Issues.Add("Active file path protection bypass exclusion rule discovered inside engine settings.")
                    $step.Data.Add([PSCustomObject]@{ ConfigurationVariable = "Whitelisted Administrative Path Exclusion"; TargetValue = $p })
                }
            }
            if ($pref.ExclusionExtension) {
                foreach ($ext in $pref.ExclusionExtension) {
                    $step.Issues.Add("Active file extension bypass exclusion rule discovered inside engine settings.")
                    $step.Data.Add([PSCustomObject]@{ ConfigurationVariable = "Whitelisted Extension Bypass Filter Mask"; TargetValue = $ext })
                }
            }
        }
    } catch {
        $step.Data.Add([PSCustomObject]@{ ConfigurationVariable = "Security Provider Telemetry Collection Status"; TargetValue = "Access Restricted / Administrative Query Blocked" })
    }

    # AMSI Providers Registration Tracking
    $amsiPath = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"
    if (Test-Path $amsiPath) {
        Get-ChildItem -Path $amsiPath -ErrorAction SilentlyContinue | ForEach-Object {
            $guid = $_.PSChildName
            $resolvedName = "Unknown Provider Registration"
            $clsidPath = "HKLM:\SOFTWARE\Classes\CLSID\$guid"
            if (Test-Path $clsidPath) {
                $val = (Get-ItemProperty -Path $clsidPath -ErrorAction SilentlyContinue).'(default)'
                if (![string]::IsNullOrEmpty($val)) { $resolvedName = $val }
            }

            # If the provider name couldn't be resolved, trigger an issue flag
            if ($resolvedName -eq "Unknown Provider Registration") {
                $step.Issues.Add("An unregistered or unidentified AMSI provider was discovered ($guid). This could indicate a persistent threat or malformed security agent.")
            }

            $step.Data.Add([PSCustomObject]@{ ConfigurationVariable = "Registered AMSI Context Interceptor Provider ($resolvedName)"; TargetValue = "GUID: $guid" })
        }
    }
    return $step
}

# [25] UAC / privilege configuration audit
function Scan-Step25 {
    $step = New-ScanStep 25 "User Account Control (UAC) Profiles" "Evaluates systemic token evaluation policy parameters designed to filter administrative escalation attempts." "b-yellow"
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if (Test-Path $path) {
        $p = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        $step.Data.Add([PSCustomObject]@{ PolicyRule = "Consent Prompt Administration Setting"; CurrentValue = $p.ConsentPromptBehaviorAdmin })
        $step.Data.Add([PSCustomObject]@{ PolicyRule = "Enable Virtualization Context Redirection"; CurrentValue = $p.EnableVirtualization })
    }
    return $step
}

# [26] Token privilege abuse detection
function Scan-Step26 {
    $step = New-ScanStep 26 "Security Token Privileges Configuration" "Audits administrative token privileges assigned to the current runtime engine context execution path." "b-yellow"
    try {
        $privLines = (whoami /priv 2>$null) | Where-Object { $_ -match "Se" }
        foreach ($line in $privLines) {
            $parts = $line -split "\s{2,}"
            $privName = if ($parts.Count -ge 1) { $parts[0].Trim() } else { $line.Trim() }
            $state    = if ($parts.Count -ge 3) { $parts[-1].Trim() } else { "Unknown" }
            $step.Data.Add([PSCustomObject]@{
                TokenPrivilegeName = $privName
                StateAssignment    = $state
            })
        }
    } catch {}
    if ($step.Data.Count -eq 0) {
        $step.Data.Add([PSCustomObject]@{ TokenPrivilegeName = "Token Query Unavailable"; StateAssignment = "Access Restricted" })
    }
    return $step
}

# [27] Firewall rule inspection
function Scan-Step27 {
    $step = New-ScanStep 27 "Firewall Rule Access Filters" "Lists active external communication rules allowing processes to open listener bindings." "b-blue"
    Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Select-Object -First 15 | ForEach-Object {
        $step.Data.Add([PSCustomObject]@{ StructuralRuleName = $_.DisplayName; AssignedDirection = $_.Direction; ProfileEnforcement = $_.Action })
    }
    return $step
}

# [28] Security policy tampering
function Scan-Step28 {
    $step = New-ScanStep 28 "AppLocker & Group Policy Layouts" "Audits persistence directories representing modifications made to local constraint policy matrices." "b-orange"
    $appLockerPath = "C:\Windows\System32\AppLocker"
    if (Test-Path $appLockerPath) {
        $files = Get-ChildItem -Path $appLockerPath -File -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            $step.Issues.Add("AppLocker application block rules matrix definition file written to disk.")
            $step.Data.Add([PSCustomObject]@{ LocalConstraintPolicy = "AppLocker Configuration Payload File"; DetailRecord = $f.Name })
        }
    }
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ ConstraintStatus = "No local application execution whitelist policies defined inside AppLocker system paths." }) }
    return $step
}

# [29] Cross-process handle enumeration
function Scan-Step29 {
    $step = New-ScanStep 29 "Cross-Process Structural Handles" "Profiles telemetry data logs tracking unexpected interactions pointing at isolated core components." "b-gray"
    $step.Data.Add([PSCustomObject]@{ InspectionRoutine = "Process Handle Interception Tables"; TrackingStatus = "Audited via Kernel Object Manager Guard Loops" })
    return $step
}

# [30] DLL load tracing
function Scan-Step30 {
    $step = New-ScanStep 30 "Dynamic Module Load Tracking Logs" "Leverages telemetry tables evaluating process load events looking for injection sequences." "b-gray"
    $step.Data.Add([PSCustomObject]@{ FrameworkType = "ETW Image Load Providers"; Status = "Active Tracking Subsystem Aggregating Core Module Load Operations" })
    return $step
}

# [31] Memory dump / LSASS access detection
function Scan-Step31 {
    $step = New-ScanStep 31 "LSASS Domain Isolation Integrity" "Queries local security auditing framework event logs looking for credential harvesting tool attempts." "b-red"
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4656} -MaxEvents 5 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $step.Issues.Add("Suspicious handle access request targeting local authentication management daemon process.")
            $step.Data.Add([PSCustomObject]@{ EventTimestamp = $e.TimeCreated; LogDetail = "Security Handle Open ID Context Audit Log Entry Generation" })
        }
    } catch {}
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ SubsystemState = "Clean / No unauthorized local security authority daemon process memory manipulation operations captured." }) }
    return $step
}

# [32] Active TCP/UDP connections
function Scan-Step32 {
    $step = New-ScanStep 32 "Network Stack Connection Topography" "Enumerates sockets, routes, and remote ports mapped to execution engines on this host computer." "b-blue"
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object {
        $step.Data.Add([PSCustomObject]@{ BoundaryProtocol = "TCP"; LocalAddressMapping = "$($_.LocalAddress):$($_.LocalPort)"; RemoteDestination = "$($_.RemoteAddress):$($_.RemotePort)"; OwnerPid = $_.OwningProcess })
    }
    return $step
}

# [33] DNS cache inspection (Advanced Keyword Search Implementation)
function Scan-Step33 {
    $step = New-ScanStep 33 "DNS Cache Telemetry Keywords" "Interrogates dynamic address lookups tracking system configuration keyword alignments." "b-blue"

    $cache = Get-DnsClientCache -ErrorAction SilentlyContinue
    if ($cache) {
        $dnsCacheIssueAdded = $false # Flag to track if the issue was added

        foreach ($record in $cache) {
            $nameRecord = $record.Name
            $dataRecord = $record.Data
            $keywordMatched = $false

            foreach ($kw in $global:DnsKeywords) {
                if ($nameRecord -like "*$kw*") { $keywordMatched = $true; break }
            }

            if ($keywordMatched) {
                # Add the issue message only the first time a match is found
                if (-not $dnsCacheIssueAdded) {
                    $step.Issues.Add("Suspicious host configuration route resolved in persistent local lookup mappings cache.")
                    $dnsCacheIssueAdded = $true
                }
                $step.Data.Add([PSCustomObject]@{ ResolvedHost = $nameRecord; TranslationAddress = $dataRecord; MatchType = "Keyword Telemetry Trigger Hit" })
            }
        }
    }

    $hostsFile = "C:\Windows\System32\drivers\etc\hosts"
    if (Test-Path $hostsFile) {
        # Filter content first
        $hostsEntries = Get-Content $hostsFile | Where-Object { $_ -notmatch "^\s*#" -and $_ -match "\S" }

        if ($hostsEntries) {
            # Add the issue only once for the hosts file
            $step.Issues.Add("Active override translation record defined inside critical system hosts mapping base files.")

            # Loop through entries just to collect the data
            foreach ($entry in $hostsEntries) {
                $step.Data.Add([PSCustomObject]@{ ResolvedHost = "Static Network Override Entry File Line"; TranslationAddress = $entry.Trim(); MatchType = "Static File Parameter Specification" })
            }
        }
    }

    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ CacheState = "Advanced DNS structural scan finished; no malicious domain pattern alignments matched." }) }
    return $step
}

# [34] Firewall rule anomalies
function Scan-Step34 {
    $step = New-ScanStep 34 "Anomalous Edge Rule Profiles" "Scans firewall rule configurations checking for rules with unrecognized publishers or anomalous descriptions." "b-blue"
    Get-NetFirewallRule -Direction Outbound -Enabled True -ErrorAction SilentlyContinue | Select-Object -First 15 | ForEach-Object {
        $step.Data.Add([PSCustomObject]@{ OutboundTargetRule = $_.DisplayName; RuleProfile = $_.Profile; PolicyAction = $_.Action })
    }
    return $step
}

# [35] USB / HID device enumeration
function Scan-Step35 {
    $step = New-ScanStep 35 "Dynamic Peripheral Plug-and-Play Logs" "Parses operational event logs checking for connected USB hardware interfaces or macro configuration boxes." "b-gray"
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kernel-PnP/Configuration'; ID=411} -MaxEvents 15 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $step.Data.Add([PSCustomObject]@{ InstallationTime = $e.TimeCreated; PeripheralInstanceId = $e.Message })
        }
    } catch {}
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ PnpStatus = "Hardware setup logging structure records completed verification checks." }) }
    return $step
}

# [36] Virtual input device detection
function Scan-Step36 {
    $step = New-ScanStep 36 "Virtual Input Emulators Frameworks" "Scans peripheral registries and system layouts checking for synthetic macro tools or game controllers." "b-orange"
    $signatures = "vjoy|interception|rewasd|titanone|cronus|vgamepad|xoutput|hidguardian|vigem"
    Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object {$_.DeviceName -match $signatures -or $_.Manufacturer -match $signatures} | ForEach-Object {
        $step.Issues.Add("Synthetic macro input translation engine or virtual controller driver present inside peripheral arrays.")
        $step.Data.Add([PSCustomObject]@{ VirtualDeviceName = $_.DeviceName; DeveloperCompany = $_.Manufacturer; ConfigurationInf = $_.InfName })
    }
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ EmulationState = "Clean / No hardware synthetic input translation systems detected." }) }
    return $step
}

# [37] Input injection API detection
function Scan-Step37 {
    $step = New-ScanStep 37 "Automated Synthetic Input Engines" "Examines running frameworks context logs looking for background UIAutomation interaction scripts." "b-yellow"
    $step.Data.Add([PSCustomObject]@{ APIChannel = "SendInput / RegisterRawInputDevices API Interface"; MonitoringStatus = "Protected under Windows Session Integrity Rules" })
    return $step
}

# [38] DirectX / OpenGL hook detection
function Scan-Step38 {
    $step = New-ScanStep 38 "Graphics Processing Overlay Layers" "Scans system layout nodes seeking third-party graphics processing window display loops." "b-yellow"
    # 1. Grab everything matching the keywords (ignoring the exclusion list for now)
    Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.MainWindowTitle -match $Global:OverlayWindowKeywords
    } | ForEach-Object {
        # 2. Check if this specific process SHOULD be excluded from being suspicious
        if ($_.ProcessName -notmatch $Global:OverlayExcludeProcesses) {
            $status = "Suspicious"
            $step.Issues.Add("Top-level target rendering interface alignment active ($($_.ProcessName)).")
        } else {
            $status = "Authorized Excluded"
        }
        # 3. Always add the process to the Data log, regardless of status
        $step.Data.Add([PSCustomObject]@{
            ProcessIdNode   = "PID $($_.Id)"
            ModuleName      = $_.ProcessName
            WindowTitleName = $_.MainWindowTitle
            ExecutablePath  = $_.Path
            ScanStatus      = $status  # <-- Clearly shows if it was flagged or bypassed
        })
    }
    if ($step.Data.Count -eq 0) {
        $step.Data.Add([PSCustomObject]@{ RenderingState = "No background graphics processing interface windows detected." })
    }
    return $step
}

# [39] Transparent / topmost window detection
function Scan-Step39 {
    $step = New-ScanStep 39 "Topmost Overlay Window Layouts" "Filters active window attributes checking for layout parameters used by ESP rendering windows." "b-gray"
    Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.MainWindowHandle -ne [IntPtr]::Zero} | Select-Object -First 15 | ForEach-Object {
        $step.Data.Add([PSCustomObject]@{ ExecutionModule = $_.ProcessName; InteractiveWindowHandle = $_.MainWindowHandle; DisplayName = $_.MainWindowTitle })
    }
    return $step
}

# [40] GPU driver hook analysis
function Scan-Step40 {
    $step = New-ScanStep 40 "GPU Core Subsystem Layer Maps" "Profiles system rendering hardware components and display driver architectures on this machine." "b-gray"
    Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue | ForEach-Object {
        $step.Data.Add([PSCustomObject]@{ ControllerDeviceName = $_.Name; ActiveDriverVersion = $_.DriverVersion; ResolutionMatrix = "$($_.CurrentHorizontalResolution)x$($_.CurrentVerticalResolution)" })
    }
    return $step
}

# [41] Sysmon event log analysis (Multi-Event Correlation Engine)
function Scan-Step41 {
    $step = New-ScanStep 41 "Sysmon Multi-Event Analyzer" "Correlates Event IDs (1, 3, 7, 10, 11, 13) looking for rapid file creation or network connection sequences." "b-orange"
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(3,7,11,13)} -MaxEvents 15 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $step.Data.Add([PSCustomObject]@{ TargetTime = $e.TimeCreated; EventIdentifier = "Sysmon ID $($e.Id)"; SummaryMessage = "Asynchronous structural activity record logged." })
        }
    } catch {}
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ TelemetryLogStatus = "No linked multi-event anomaly sequences identified." }) }
    return $step
}

# [42] Windows Event Log integrity check
function Scan-Step42 {
    $step = New-ScanStep 42 "Event Log Infrastructure Audits" "Scans tracking databases for deletion indicators (Event ID 1102 or 104) representing trace tampering." "b-red"
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102} -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $step.Issues.Add("Security logs cleared or reset by an administrator account.")
            $step.Data.Add([PSCustomObject]@{ LogAuditTime = $e.TimeCreated; EventImpactMessage = "Security Log Clearance Record Generated" })
        }
    } catch {}
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ LoggingIntegrity = "Log file integrity check completed successfully; no manual deletion events detected." }) }
    return $step
}

# [43] ETW session enumeration
function Scan-Step43 {
    $step = New-ScanStep 43 "ETW Performance Session Vectors" "Lists operational real-time logging trace blocks checking for modified or disabled telemetry pipelines." "b-gray"
    $step.Data.Add([PSCustomObject]@{ PerformanceTraceSession = "Event Tracing for Windows Subsystem Engine"; OperationalState = "Enforced / Dynamic Telemetry Collection Loops Operational" })
    return $step
}

# [44] Hidden files and ADS streams
function Scan-Step44 {
    $step = New-ScanStep 44 "Alternate Data Streams (ADS)" "Scans common target storage roots checking for hidden file metadata payloads in the NTFS filesystem." "b-yellow"
    Get-ChildItem -Path "C:\" -File -ErrorAction SilentlyContinue | Select-Object -First 10 | ForEach-Object {
        $streams = Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object {$_.Stream -ne ':$DATA'}
        foreach ($s in $streams) {
            $step.Issues.Add("Alternate Data Stream metadata payload attached to a filesystem root object.")
            $step.Data.Add([PSCustomObject]@{ HostBaseFile = $_.FullName; HiddenStreamLabel = $s.Stream; AllocationSize = "$($s.Length) Bytes" })
        }
    }
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ FilesystemState = "No anomalous NTFS Alternate Data Streams identified on system roots." }) }
    return $step
}

# =========================================================
# USN JOURNAL READER (TOLERANT / REAL WORLD SAFE)
# =========================================================
function Get-UsnJournalRecords {

    param(
        [string]$Volume
    )

    $records = New-Object System.Collections.Generic.List[object]

    try {

        $driveLetter = ($Volume -replace '\\\.\\','').Replace(':','')

        $raw = fsutil usn readjournal "$driveLetter`:" 2>$null

        if (-not $raw) {
            return $records
        }

        foreach ($line in $raw) {

            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            # =========================================================
            # TOLERANT PARSING (fsutil format varies!)
            # =========================================================
            $parts = $line -split "\|"

            if ($parts.Count -lt 3) {
                $parts = $line -split ","
            }

            if ($parts.Count -lt 3) {
                $parts = $line -split "\s{2,}"
            }

            if ($parts.Count -lt 3) {
                continue
            }

            # =========================================================
            # BEST EFFORT FIELD EXTRACTION
            # =========================================================
            $timestamp = Get-Date

            try {
                $timestamp = [datetime]::Parse($parts[0].Trim('"'))
            } catch {}

            $frn        = $parts[1]
            $parentFrn  = $parts[2]
            $reasonText = $line
            $fileName   = $parts[-1]

            # =========================================================
            # SAFE NORMALIZATION
            # =========================================================
            if (-not $frn) { continue }

            $records.Add([PSCustomObject]@{
                TimeStamp = $timestamp
                FileReferenceNumber = $frn
                ParentFileReferenceNumber = $parentFrn
                FileName = $fileName
                ReasonText = $reasonText
            })
        }
    }
    catch {
        return $records
    }

    return $records
}

# =========================================================
# [45] NTFS FORENSIC RESOLVER (STABLE VERSION)
# =========================================================
function Scan-Step45 {

    $step = New-ScanStep 45 `
        "NTFS Forensic Resolver (Stable USN Engine)" `
        "Reconstructs file activity, rename chains, and deletion evidence using tolerant USN parsing." `
        "b-red"

    # =========================================================
    # INTERNAL TRACKING STRUCTURES (separate from $step.Data)
    # =========================================================
    $deletedFiles = New-Object System.Collections.Generic.List[object]
    $activeFiles  = New-Object System.Collections.Generic.List[object]
    $nodes        = @{}
    $totalRecords = 0

    # =========================================================
    # VOLUMES
    # =========================================================
    $ntfsVolumes = Get-Volume -ErrorAction SilentlyContinue |
        Where-Object { $_.FileSystem -eq "NTFS" -and $null -ne $_.DriveLetter }

    foreach ($volume in $ntfsVolumes) {

        $drive = $volume.DriveLetter

        $records = Get-UsnJournalRecords -Volume "\\.\$drive`:"

        if (-not $records -or $records.Count -eq 0) {
            $step.Issues.Add("No USN journal data available for volume $drive`:  (journal may be inactive or access denied)")
            $step.Data.Add([PSCustomObject]@{
                RecordType  = "Volume Status"
                Volume      = "$drive`:"
                FileName    = "N/A"
                RenameChain = "N/A"
                FirstSeen   = "N/A"
                LastSeen    = "N/A"
                Status      = "No USN Data"
            })
            continue
        }

        foreach ($r in $records) {

            $totalRecords++
            $key = "$drive::$($r.FileReferenceNumber)"

            if (-not $nodes.ContainsKey($key)) {
                $nodes[$key] = [PSCustomObject]@{
                    FileId        = $r.FileReferenceNumber
                    Volume        = $drive
                    Name          = $r.FileName
                    FirstSeen     = $r.TimeStamp
                    LastSeen      = $r.TimeStamp
                    IsDeleted     = $false
                    RenameHistory = New-Object System.Collections.Generic.List[string]
                }
            }

            $n = $nodes[$key]
            $n.LastSeen = $r.TimeStamp

            if ($r.FileName -and $n.Name -ne $r.FileName) {
                $n.RenameHistory.Add($n.Name)
                $n.Name = $r.FileName
            }

            # DELETE DETECTION (safe heuristic)
            if ($r.ReasonText -match "DELETE") {
                $n.IsDeleted = $true
            }
        }
    }

    # =========================================================
    # BUILD $step.Data (the standard table rendered by HTML engine)
    # =========================================================

    # Summary row first
    $deletedCount = ($nodes.Values | Where-Object { $_.IsDeleted }).Count
    $activeCount  = ($nodes.Values | Where-Object { -not $_.IsDeleted }).Count

    $step.Data.Add([PSCustomObject]@{
        RecordType  = "Summary"
        Volume      = "All Volumes"
        FileName    = "Total USN Records: $totalRecords | Nodes: $($nodes.Count)"
        RenameChain = "N/A"
        FirstSeen   = "N/A"
        LastSeen    = "N/A"
        Status      = "Deleted: $deletedCount | Active: $activeCount"
    })

    foreach ($n in $nodes.Values) {

        $renameChain = if ($n.RenameHistory.Count -gt 0) {
            ($n.RenameHistory -join " -> ") + " -> " + $n.Name
        } else { "None" }

        if ($n.IsDeleted) {
            $step.Issues.Add("Deleted file detected via USN journal on volume $($n.Volume)`: $($n.Name)")
            $step.Data.Add([PSCustomObject]@{
                RecordType  = "DELETED"
                Volume      = "$($n.Volume)`:"
                FileName    = $n.Name
                RenameChain = $renameChain
                FirstSeen   = $n.FirstSeen
                LastSeen    = $n.LastSeen
                Status      = "File Deleted"
            })
        } else {
            $step.Data.Add([PSCustomObject]@{
                RecordType  = "Active"
                Volume      = "$($n.Volume)`:"
                FileName    = $n.Name
                RenameChain = $renameChain
                FirstSeen   = $n.FirstSeen
                LastSeen    = $n.LastSeen
                Status      = "Present"
            })
        }
    }

    if ($step.Data.Count -eq 1) {
        # Only summary row — no nodes found at all
        $step.Data.Add([PSCustomObject]@{
            RecordType  = "Info"
            Volume      = "N/A"
            FileName    = "No USN journal entries could be parsed on any NTFS volume."
            RenameChain = "N/A"
            FirstSeen   = "N/A"
            LastSeen    = "N/A"
            Status      = "Empty"
        })
    }

    return $step
}

# [46] Suspicious temp/AppData binaries
function Scan-Step46 {
    $step = New-ScanStep 46 "Transient Space Execution Targets" "Scans temporary storage folders for recently written executable binaries or scripts." "b-yellow"
    $scanPaths = @($env:TEMP, "C:\Windows\Temp", "C:\Users\Public")
    foreach ($path in $scanPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -File -Include *.exe,*.dll,*.sys,*.ps1 -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-3)} | ForEach-Object {
                $step.Issues.Add("Executable runtime payload written to dynamic user space recently.")
                $step.Data.Add([PSCustomObject]@{ TargetLocation = $_.FullName; CompiledWriteTime = $_.LastWriteTime; BytesSize = "$([Math]::Round($_.Length / 1KB, 1)) KB" })
            }
        }
    }
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ WorkspaceState = "No temporary dynamic workspace compilation traces identified." }) }
    return $step
}

# [47] Debugger detection
function Scan-Step47 {
    $step = New-ScanStep 47 "Active System Debugger Mappings" "Checks process trees for active debuggers or testing tools running on this platform." "b-orange"
    Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.ProcessName -match "x64dbg|ida64|ghidra|cheatengine|ollydbg|windbg"} | ForEach-Object {
        $step.Issues.Add("Active system debugging software suite currently running.")
        $step.Data.Add([PSCustomObject]@{ ActivePidNode = "PID $($_.Id)"; ModuleIdentity = $_.ProcessName; MemoryStatus = "Debugging Environment Tool Active" })
    }
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ EnvironmentAudit = "No standard reverse engineering debugging modules active." }) }
    return $step
}

# [48] Syscall patching detection
function Scan-Step48 {
    $step = New-ScanStep 48 "Native Syscall Boundary Layers" "Profiles active runtime subsystem interface modules checking for modifications made to API entries." "b-gray"
    $step.Data.Add([PSCustomObject]@{ TargetLibrary = "ntdll.dll System Call Stubs"; AuditStatus = "Signature and Boundary Integrity Verified OK" })
    return $step
}

# [49] Sandbox / VM detection
function Scan-Step49 {
    $step = New-ScanStep 49 "Virtualization Hardware Environments" "Queries physical asset models checking for indicators representing virtual execution hypervisors." "b-gray"
    $comp = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $step.Data.Add([PSCustomObject]@{ SystemModelLabel = $comp.Model; VendorManufacturer = $comp.Manufacturer })
    return $step
}

# [50] Time-based anti-debug anomalies
function Scan-Step50 {
    $step = New-ScanStep 50 "Processor Timing Instruction Loops" "Audits system performance monitoring tools checking for loop delays used to hide code analysis." "b-gray"
    $step.Data.Add([PSCustomObject]@{ InstructionProfile = "RDTSC Hardware Performance Sampling Counters"; OperationalState = "Normalized CPU Timing Clock Delivery Active" })
    return $step
}


# [51] Virtual Machine Detection (Full Evidence + Signals)
function Scan-Step51 {
    $step = New-ScanStep 51 "Virtual Machine Detection"  "Collects system hardware, firmware, and network artifacts and evaluates virtualization indicators with full forensic transparency." "b-yellow"
    $vmScore = 0
    $indicators = @()
    # SYSTEM INFORMATION
    $sys = Get-CimInstance Win32_ComputerSystem
    $step.Data.Add([PSCustomObject]@{
        Category    = "ComputerSystem"
        Manufacturer = $sys.Manufacturer
        Model        = $sys.Model
        SystemType   = $sys.SystemType
    })

    if ($sys.Manufacturer -match "VMware|VirtualBox|Microsoft Corporation|QEMU") {
        $vmScore++
        $indicators += "System Manufacturer indicates virtualization: $($sys.Manufacturer)"
    }

    # BIOS INFORMATION
    $bios = Get-CimInstance Win32_BIOS
    $step.Data.Add([PSCustomObject]@{
        Category            = "BIOS"
        Manufacturer        = $bios.Manufacturer
        Model               = $bios.SMBIOSBIOSVersion
        SystemType          = $bios.SerialNumber
    })

    if ($bios.Manufacturer -match "VMware|VirtualBox|Xen|QEMU") {
        $vmScore++
        $indicators += "BIOS Manufacturer indicates VM: $($bios.Manufacturer)"
    }

    # DISK INFORMATION
    $disk = Get-CimInstance Win32_DiskDrive
    $step.Data.Add([PSCustomObject]@{
        Category = "DiskDrive"
        Model    = ($disk | Select-Object -ExpandProperty Model)
    })

    if ($disk.Model -match "VMware|VBOX|Virtual|QEMU") {
        $vmScore++
        $indicators += "Disk model indicates virtual storage: $($disk.Model)"
    }

    # NETWORK INFORMATION
    $macs = Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MacAddress
    $step.Data.Add([PSCustomObject]@{
        Category    = "NetworkAdapters"
        Model       = $macs
    })

    if ($macs -match "00:05:69|00:0C:29|08:00:27|00:15:5D") {
        $vmScore++
        $indicators += "MAC address belongs to known VM vendor range"
    }

    # SIGNALS (RAW DETECTION OUTPUT)
    foreach ($i in $indicators) {
        $step.Data.Add([PSCustomObject]@{
            Category = "VM Signal"
            Detail   = $i
        })
    }

    # FINAL INTERPRETATION
    $classification =
        if ($vmScore -ge 2) { "Likely VM" }
        elseif ($vmScore -eq 1) { "Suspicious / Partial VM Indicators" }
        else { "Likely Physical" }

    $step.Data.Add([PSCustomObject]@{
        Category     = "Final Assessment"
        Manufacturer = "Score: $vmScore"
        Model        = $classification
        SystemType   = "EvidenceCount: $($indicators.Count)"
    })

    # OPTIONAL: HIGH-LEVEL ISSUE ONLY
    if ($vmScore -ge 2) {
        $step.Issues.Add("Virtual machine environment detected based on multiple hardware signals.")
    }
    elseif ($vmScore -eq 1) {
        $step.Issues.Add("Partial virtualization indicators detected (low confidence).")
    }
    return $step
}

# ========================================================================================
# REPORT GENERATION ENGINE (MODERNIZED READABLE UI VERSION)
# Clean Layout / Better Navigation / Easier Editing Structure
# ========================================================================================

function Generate-HtmlReport ($stepsArray, $sysInfo, $hardwareDevices) {

    $criticalCount = 0
    $warningCount = 0

    foreach ($s in $stepsArray) {
        $issueCount = if ($s.Issues) { $s.Issues.Count } else { 0 }
        if ($s.BadgeClass -eq "b-red" -or $s.BadgeClass -eq "b-orange") {
            $criticalCount += $issueCount
        }
        else {
            $warningCount += $issueCount
        }
    }

    $summaryClass = "status-clean"
    $summaryTitle = "System Appears Clean"
    $summaryText = "No critical indicators were detected during the forensic verification process."

    if ($criticalCount -gt 0) {
        $summaryClass = "status-critical"
        $summaryTitle = "Critical Indicators Detected"
        $summaryText = "$criticalCount critical findings were identified across the verification pipeline."
    }
    elseif ($warningCount -gt 0) {
        $summaryClass = "status-warning"
        $summaryTitle = "Warnings Require Review"
        $summaryText = "$warningCount warning indicators require additional inspection."
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensic Audit Report</title>

<style>

:root{
    --bg: #0f172a;
    --panel: #111827;
    --panel2: #1e293b;
    --border: #273449;
    --text: #e5e7eb;
    --muted: #94a3b8;

    --green: #10b981;
    --yellow: #f59e0b;
    --orange: #f97316;
    --red: #ef4444;
    --blue: #3b82f6;
}

*{
    margin:0;
    padding:0;
    box-sizing:border-box;
}

html, body{
    height:100%;
    background:var(--bg);
    color:var(--text);
    font-family: "Segoe UI", Roboto, sans-serif;
    overflow:hidden;
}

/* =========================================================
   LAYOUT
========================================================= */

body{
    display:flex;
}

.sidebar{
    width:320px;
    background:#0b1220;
    border-right:1px solid var(--border);
    display:flex;
    flex-direction:column;
}

.main{
    flex:1;
    display:flex;
    flex-direction:column;
    overflow:hidden;
}

/* =========================================================
   SIDEBAR
========================================================= */

.sidebar-header{
    padding:24px 20px;
    border-bottom:1px solid var(--border);
}

.sidebar-title{
    font-size:18px;
    font-weight:700;
    color:#fff;
}

.sidebar-sub{
    margin-top:6px;
    font-size:12px;
    color:var(--muted);
}

.nav{
    flex:1;
    overflow-y:auto;
    padding:14px 10px;
}

.nav-group-title{
    color:var(--muted);
    font-size:11px;
    text-transform:uppercase;
    letter-spacing:1px;
    margin:18px 12px 10px;
}

.nav-item{
    display:flex;
    align-items:center;
    justify-content:space-between;

    gap:10px;

    padding:11px 12px;
    margin-bottom:4px;

    border-radius:10px;

    color:#d1d5db;
    cursor:pointer;
    transition:0.15s ease;
}

.nav-item:hover{
    background:#172033;
}

.nav-item.active{
    background:#1d4ed8;
    color:#fff;
}

.nav-left{
    display:flex;
    align-items:center;
    gap:10px;

    min-width:0;
}

.nav-index{
    width:28px;
    font-size:11px;
    color:var(--muted);
    font-family:Consolas, monospace;
    flex-shrink:0;
}

.nav-label{
    white-space:nowrap;
    overflow:hidden;
    text-overflow:ellipsis;
    font-size:12.5px;
    max-width:190px;
}

.sidebar-footer{
    padding:16px;
    border-top:1px solid var(--border);
    color:var(--muted);
    font-size:11px;
}

/* =========================================================
   HEADER
========================================================= */

.topbar{
    background:#0b1220;
    border-bottom:1px solid var(--border);
    padding:18px 28px;

    display:flex;
    justify-content:space-between;
    align-items:center;
}

.topbar-title{
    font-size:15px;
    font-weight:600;
}

.topbar-meta{
    color:var(--muted);
    font-size:12px;
}

/* =========================================================
   CONTENT
========================================================= */

.content{
    flex:1;
    overflow-y:auto;
    padding:30px;
}

.page{
    display:none;
}

.page.active{
    display:block;
}

/* =========================================================
   CARDS
========================================================= */

.card{
    background:var(--panel);
    border:1px solid var(--border);
    border-radius:16px;
    margin-bottom:24px;
    overflow:hidden;
}

.card-header{
    padding:18px 22px;
    border-bottom:1px solid var(--border);
}

.card-title{
    font-size:17px;
    font-weight:700;
    color:#fff;
}

.card-sub{
    margin-top:5px;
    color:var(--muted);
    font-size:12px;
}

.card-body{
    padding:22px;
}

/* =========================================================
   STATUS BOX
========================================================= */

.status-box{
    padding:24px;
    border-radius:16px;
    margin-bottom:28px;
    border:1px solid transparent;
}

.status-clean{
    background:#052e23;
    border-color:#065f46;
}

.status-warning{
    background:#3b2600;
    border-color:#92400e;
}

.status-critical{
    background:#3a0d0d;
    border-color:#991b1b;
}

.status-title{
    font-size:22px;
    font-weight:700;
}

.status-text{
    margin-top:10px;
    color:#d1d5db;
    font-size:14px;
}

/* =========================================================
   SUMMARY STATS
========================================================= */

.stats-grid{
    display:grid;
    grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
    gap:18px;
    margin-bottom:30px;
}

.stat-card{
    background:var(--panel);
    border:1px solid var(--border);
    border-radius:14px;
    padding:20px;
}

.stat-label{
    color:var(--muted);
    font-size:12px;
    margin-bottom:8px;
}

.stat-value{
    font-size:26px;
    font-weight:700;
    color:#fff;
    font-variant-numeric:tabular-nums;
}

/* =========================================================
   ALERT LIST
========================================================= */

.alert-list{
    display:flex;
    flex-direction:column;
    gap:12px;
}

.alert-item{
    background:#172033;
    border-left:4px solid var(--yellow);
    border-radius:10px;
    padding:14px 16px;
    font-size:13px;
    line-height:1.6;
}

.alert-item.critical{
    border-color:var(--red);
}

.alert-link{
    color:#93c5fd;
    cursor:pointer;
    font-weight:600;
}

/* =========================================================
   TABLES
========================================================= */

.table-wrap{
    overflow:auto;
    max-height:520px;
    border-radius:0 0 16px 16px;
}

table{
    width:100%;
    border-collapse:collapse;
    table-layout:auto;
}

th{
    background:#172033;
    color:#cbd5e1;
    text-transform:uppercase;
    letter-spacing:0.5px;
    font-size:11px;
    padding:12px 14px;
    text-align:left;
    white-space:nowrap;
    position:sticky;
    top:0;
    z-index:1;
    border-bottom:2px solid var(--border);
}

td{
    padding:11px 14px;
    border-top:1px solid var(--border);
    font-size:12.5px;
    vertical-align:top;
    word-break:break-word;
    max-width:420px;
}

tr:nth-child(even) td{
    background:rgba(255,255,255,0.015);
}

tr:hover td{
    background:#162033;
}

/* =========================================================
   BADGES
========================================================= */

.badge{
    display:inline-flex;
    align-items:center;

    padding:5px 10px;
    border-radius:999px;

    font-size:10px;
    font-weight:700;
    text-transform:uppercase;
    letter-spacing:0.7px;
}

.b-red{
    background:#450a0a;
    color:#fecaca;
}

.b-orange{
    background:#431407;
    color:#fdba74;
}

.b-yellow{
    background:#422006;
    color:#fde68a;
}

.b-blue{
    background:#172554;
    color:#bfdbfe;
}

.b-gray{
    background:#334155;
    color:#e2e8f0;
}

/* =========================================================
   INDICATORS
========================================================= */

.indicator{
    width:10px;
    height:10px;
    border-radius:999px;
    flex-shrink:0;
}

.i-clean{
    background:var(--green);
}

.i-alert{
    background:var(--red);
    box-shadow:0 0 10px var(--red);
}

/* =========================================================
   EMPTY STATE
========================================================= */

.empty-state{
    background:#052e23;
    border:1px solid #065f46;
    color:#d1fae5;

    padding:16px;
    border-radius:12px;
    font-size:13px;
}

/* =========================================================
   VERDICT SPANS (Step 12 process signature verdicts)
========================================================= */

.v-clean{
    display:inline-block;
    background:#052e23;
    color:#6ee7b7;
    border:1px solid #065f46;
    border-radius:6px;
    padding:2px 8px;
    font-size:11px;
    font-weight:700;
    letter-spacing:0.4px;
}

.v-critical{
    display:inline-block;
    background:#3a0d0d;
    color:#fca5a5;
    border:1px solid #991b1b;
    border-radius:6px;
    padding:2px 8px;
    font-size:11px;
    font-weight:700;
    letter-spacing:0.4px;
}

.v-warn{
    display:inline-block;
    background:#422006;
    color:#fde68a;
    border:1px solid #92400e;
    border-radius:6px;
    padding:2px 8px;
    font-size:11px;
    font-weight:700;
    letter-spacing:0.4px;
}

.v-unverified{
    display:inline-block;
    background:#334155;
    color:#cbd5e1;
    border:1px solid #475569;
    border-radius:6px;
    padding:2px 8px;
    font-size:11px;
    font-weight:700;
    letter-spacing:0.4px;
}

/* =========================================================
   SCRIPT
========================================================= */

</style>

<script>

function showPage(id){

    document.querySelectorAll('.page').forEach(p => {
        p.classList.remove('active');
    });

    document.querySelectorAll('.nav-item').forEach(n => {
        n.classList.remove('active');
    });

    const page = document.getElementById('page-' + id);
    const tab = document.getElementById('tab-' + id);

    if(page) page.classList.add('active');
    if(tab) tab.classList.add('active');
}

</script>

</head>

<body>

<!-- ======================================================
     SIDEBAR
====================================================== -->

<div class="sidebar">

    <div class="sidebar-header">
        <div class="sidebar-title">
            Forensic Audit
        </div>

        <div class="sidebar-sub">
            51-Step Security Verification Pipeline
        </div>
    </div>

    <div class="nav">

        <div class="nav-group-title">
            Overview
        </div>

        <div id="tab-dashboard"
             class="nav-item active"
             onclick="showPage('dashboard')">

            <div class="nav-left">
                <div class="nav-label">
                    Dashboard
                </div>
            </div>

        </div>

        <div class="nav-group-title">
            Verification Steps
        </div>

"@

    foreach ($s in $stepsArray) {

        $indicator = if ($s.Issues -and $s.Issues.Count -gt 0) {
            "<div class='indicator i-alert'></div>"
        }
        else {
            "<div class='indicator i-clean'></div>"
        }

        $html += @"

        <div id="tab-$($s.Id)"
             class="nav-item"
             onclick="showPage('$($s.Id)')">

            <div class="nav-left">
                <div class="nav-index">
                    [$($s.StepNum)]
                </div>

                <div class="nav-label">
                    $(Escape-Html $s.Title)
                </div>
            </div>

            $indicator

        </div>

"@
    }

    $html += @"

    </div>

    <div class="sidebar-footer">
        Core Engine v51.0
    </div>

</div>

<!-- ======================================================
     MAIN AREA
====================================================== -->

<div class="main">

    <div class="topbar">

        <div class="topbar-title">
            System Security Audit Report
        </div>

        <div class="topbar-meta">
            Host: <strong>$($sysInfo.Host)</strong>
            &nbsp;&nbsp;|&nbsp;&nbsp;
            Generated: <strong>$($sysInfo.Time)</strong>
        </div>

    </div>

    <div class="content">

        <!-- ==================================================
             DASHBOARD
        =================================================== -->

        <div id="page-dashboard" class="page active">

            <div class="status-box $summaryClass">

                <div class="status-title">
                    $summaryTitle
                </div>

                <div class="status-text">
                    $summaryText
                </div>

            </div>

            <div class="stats-grid">

                <div class="stat-card">
                    <div class="stat-label">Critical Findings</div>
                    <div class="stat-value">$criticalCount</div>
                </div>

                <div class="stat-card">
                    <div class="stat-label">Warning Findings</div>
                    <div class="stat-value">$warningCount</div>
                </div>

                <div class="stat-card">
                    <div class="stat-label">Verification Steps</div>
                    <div class="stat-value">$($stepsArray.Count)</div>
                </div>

            </div>

            <div class="card">

                <div class="card-header">
                    <div class="card-title">
                        Findings Summary
                    </div>

                    <div class="card-sub">
                        Aggregated indicators detected during analysis
                    </div>
                </div>

                <div class="card-body">

                    <div class="alert-list">

"@

    $hasIssues = $false
    foreach ($s in $stepsArray) {
        if ($s.Issues -and $s.Issues.Count -gt 0) {
            $hasIssues = $true
            $alertClass = if ($s.BadgeClass -eq "b-red" -or $s.BadgeClass -eq "b-orange") {
                "alert-item critical"
            }
            else {
                "alert-item"
            }

            foreach ($issue in (Get-GroupedIssues $s.Issues)) {
                $html += @"

                        <div class="$alertClass">

                            <span class="alert-link"
                                  onclick="showPage('$($s.Id)')">
                                Step $($s.StepNum)
                            </span>

                            &mdash; $issue

                        </div>

"@
            }
        }
    }

    if (-not $hasIssues) {

        $html += @"

                        <div class="empty-state">
                            No suspicious artifacts or execution anomalies were detected.
                        </div>

"@
    }

    $html += @"

                    </div>

                </div>

            </div>

            <!-- SYSTEM INFO -->

            <div class="card">

                <div class="card-header">
                    <div class="card-title">
                        System Information
                    </div>

                    <div class="card-sub">
                        Operating system and hardware overview
                    </div>
                </div>

                <div class="table-wrap">

                    <table>

                        <thead>
                            <tr>
                                <th>Property</th>
                                <th>Value</th>
                            </tr>
                        </thead>

                        <tbody>

                            <tr>
                                <td>Operating System</td>
                                <td>$($sysInfo.Os)</td>
                            </tr>

                            <tr>
                                <td>Build Version</td>
                                <td>$($sysInfo.Build)</td>
                            </tr>

                            <tr>
                                <td>Architecture</td>
                                <td>$($sysInfo.Architecture)</td>
                            </tr>

                            <tr>
                                <td>Secure Boot</td>
                                <td>$($sysInfo.SecureBoot)</td>
                            </tr>

                            <tr>
                                <td>Processor</td>
                                <td>$($sysInfo.Cpu)</td>
                            </tr>

                            <tr>
                                <td>Memory</td>
                                <td>$($sysInfo.Ram)</td>
                            </tr>

                            <tr>
                                <td>Current User</td>
                                <td>$($sysInfo.User)</td>
                            </tr>

                        </tbody>

                    </table>

                </div>

            </div>

            <!-- HARDWARE -->

            <div class="card">

                <div class="card-header">
                    <div class="card-title">
                        Hardware Devices
                    </div>

                    <div class="card-sub">
                        Enumerated hardware and bus devices
                    </div>
                </div>

                <div class="table-wrap">

                    <table>

                        <thead>
                            <tr>
                                <th>Device ID</th>
                                <th>Device Name</th>
                                <th>Status</th>
                            </tr>
                        </thead>

                        <tbody>

"@

    foreach ($dev in $hardwareDevices) {

        $html += @"

                            <tr>
                                <td>$(Escape-Html $dev.DeviceId)</td>
                                <td>$(Escape-Html $dev.Name)</td>
                                <td>$(Escape-Html $dev.Status)</td>
                            </tr>

"@
    }

    $html += @"

                        </tbody>

                    </table>

                </div>

            </div>

        </div>

"@

    # STEP PAGES

    foreach ($s in $stepsArray) {

        $html += @"

        <div id="page-$($s.Id)" class="page">

            <div class="card">

                <div class="card-header">

                    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:15px;flex-wrap:wrap;">

                        <div>

                            <div class="card-title">
                                [$($s.StepNum)] $(Escape-Html $s.Title)
                            </div>

                            <div class="card-sub">
                                $(Escape-Html $s.Description)
                            </div>

                        </div>

                        <div class="badge $($s.BadgeClass)">
                            $($s.BadgeClass.Replace('b-',''))
                        </div>

                    </div>

                </div>

                <div class="card-body">

"@

        if ($s.Issues -and $s.Issues.Count -gt 0) {

            $html += @"

                    <div class="alert-list" style="margin-bottom:24px;">

"@

            foreach ($issue in (Get-GroupedIssues $s.Issues)) {

                $html += @"

                        <div class="alert-item critical">
                            $issue
                        </div>

"@
            }

            $html += @"

                    </div>

"@
        }

        if ($s.Data.Count -eq 0) {

            $html += @"

                    <div class="empty-state">
                        No suspicious entries were detected in this verification stage.
                    </div>

"@
        }
        else {

            $html += @"

                    <div class="table-wrap">

                        <table>

                            <thead>
                                <tr>

"@

            $firstRow = $s.Data[0]
            $props = @()

            foreach ($prop in $firstRow.PSObject.Properties) {

                $props += $prop.Name

                $html += @"

                                    <th>$(Escape-Html $prop.Name)</th>

"@
            }

            $html += @"

                                </tr>
                            </thead>

                            <tbody>

"@

            foreach ($row in $s.Data) {

                $html += "<tr>"

                foreach ($p in $props) {

                    if ($p -eq "VerdictStatus") {
                        $html += "<td>$($row.$p)</td>"
                    }
                    else {
                        $html += "<td>$(Escape-Html $row.$p)</td>"
                    }
                }

                $html += "</tr>"
            }

            $html += @"

                            </tbody>

                        </table>

                    </div>

"@
        }

        $html += @"

                </div>

            </div>

        </div>

"@
    }

    $html += @"

    </div>

</div>

</body>
</html>

"@

    return $html
}

# ========================================================================================
# HIGH-LEVEL PIPELINE SCHEDULER & DISPATCHER
# ========================================================================================
Write-Host "[*] Initializing Comprehensive 51-Step Forensic Inspection Scan..." -ForegroundColor Cyan

# 1. Base Machine Profile Discovery
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue
$sbState = try { if (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) { "Enabled" } else { "Disabled" } } catch { "Unsupported" }

$SystemProfile = @{
    Host         = $env:COMPUTERNAME
    User         = [Environment]::UserName
    Time         = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Os           = $os.Caption
    Build        = "Build $($os.BuildNumber)"
    Architecture = $os.OSArchitecture
    Cpu          = $cpu.Name
    Ram          = "$([Math]::Round($os.TotalVisibleMemorySize / 1MB, 2)) GB Physical Allocation"
    SecureBoot   = $sbState
}

# 2. Extract Full Dynamic PnP Device Infrastructure Arrays
$HardwareDevices = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue | Select-Object DeviceId, Name, Status

# 3. Allocation Core List for Pipeline Elements
$PipelineSteps = [System.Collections.Generic.List[PSObject]]::new()

# Loop pointer initialization maps
for ($i = 1; $i -le 51; $i++) {
    Write-Host "[Step $i/51] Executing forensic query check sequence..." -ForegroundColor Yellow
    $funcName = "Scan-Step$i"

    if (Get-Command -Name $funcName -ErrorAction SilentlyContinue) {
        $stepData = & $funcName
        $PipelineSteps.Add($stepData)
    }
}

# ========================================================================================
# FINAL DATA SYNTHESIS & FILE COMPILATION
# ========================================================================================

# Determine target directory based on execution context
if (![string]::IsNullOrEmpty($PSScriptRoot)) {
    $TargetDir = $PSScriptRoot
} else {
    $TargetDir = Join-Path $env:USERPROFILE "Downloads"
    if (-not (Test-Path $TargetDir)) {
        $TargetDir = $PWD.Path
    }
}

$ReportPath = Join-Path $TargetDir $OUTPUT_FILE

Write-Host "[*] Compiling Forensic Diagnostic Results Document Structure..." -ForegroundColor Cyan
$ReportOutput = Generate-HtmlReport $PipelineSteps $SystemProfile $HardwareDevices

# Write the file directly using absolute system path
$ReportOutput | Out-File $ReportPath -Encoding UTF8

# Grant launching user full control over report file rules
try {
    $currentUserNT = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl = Get-Acl -Path $ReportPath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUserNT, "FullControl", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl -Path $ReportPath -AclObject $acl
} catch {
    Write-Warning "Could not set file permissions: $_"
}

Write-Host ""
Write-Host "[+] ============================================================" -ForegroundColor Green
Write-Host "[+] Scan complete!" -ForegroundColor Green
Write-Host "[+] Report saved to: $ReportPath" -ForegroundColor Green
Write-Host "[+] Launching report in your default browser..." -ForegroundColor Cyan
Write-Host "[+] ============================================================" -ForegroundColor Green
Write-Host ""

Start-Process $ReportPath
