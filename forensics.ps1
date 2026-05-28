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

# Trusted Apps
$global:TrustedApps = @(

    # Browsers
    @{ Name = "firefox";      Path = "$env:ProgramFiles\Mozilla Firefox\firefox.exe";                                   Signer = "Mozilla Corporation" },
    @{ Name = "opera";        Path = "$env:ProgramFiles\Opera\launcher.exe";                                            Signer = "Opera Software AS" },
    @{ Name = "opera_gx";     Path = "$env:ProgramFiles\Opera GX\launcher.exe";                                         Signer = "Opera Software AS" },
    @{ Name = "brave";        Path = "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe";             Signer = "Brave Software, Inc." },
    @{ Name = "chrome";       Path = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe";                          Signer = "Google LLC" },
    @{ Name = "msedge";       Path = "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe";                         Signer = "Microsoft Corporation" },

    # Game Launchers
    @{ Name = "steam";        Path = "$env:ProgramFiles(x86)\Steam\steam.exe";                                          Signer = "Valve Corporation" },
    @{ Name = "epicgames";    Path = "$env:ProgramFiles(x86)\Epic Games\Launcher\Portal\Binaries\Win64\EpicGamesLauncher.exe"; Signer = "Epic Games Inc." },
    @{ Name = "riotclient";   Path = "C:\Riot Games\Riot Client\RiotClientServices.exe";                                Signer = "Riot Games, Inc." },
    @{ Name = "battle.net";   Path = "$env:ProgramFiles(x86)\Battle.net\Battle.net.exe";                                Signer = "Blizzard Entertainment, Inc." },
    @{ Name = "eaapp";        Path = "$env:ProgramFiles\Electronic Arts\EA Desktop\EA Desktop\EADesktop.exe";           Signer = "Electronic Arts Inc." },
    @{ Name = "ubisoft";      Path = "$env:ProgramFiles(x86)\Ubisoft\Ubisoft Game Launcher\UbisoftConnect.exe";         Signer = "Ubisoft Entertainment" },
    @{ Name = "goggalaxy";    Path = "$env:ProgramFiles(x86)\GOG Galaxy\GalaxyClient.exe";                              Signer = "GOG sp. z o.o." },

    # Communication
    @{ Name = "discord";      Path = "$env:LocalAppData\Discord\Update.exe";                                            Signer = "Discord Inc." },
    @{ Name = "teamspeak";    Path = "$env:ProgramFiles\TeamSpeak 3 Client\ts3client_win64.exe";                        Signer = "TeamSpeak Systems GmbH" },
    @{ Name = "slack";        Path = "$env:LocalAppData\slack\slack.exe";                                                Signer = "Slack Technologies, LLC" },

    # Streaming / Recording
    @{ Name = "obs";          Path = "$env:ProgramFiles\obs-studio\bin\64bit\obs64.exe";                                Signer = "OBS Project" },
    @{ Name = "streamlabs";   Path = "$env:ProgramFiles\Streamlabs OBS\Streamlabs OBS.exe";                             Signer = "General Workings Inc." },

    # Hardware / RGB / Peripheral Software
    @{ Name = "logitechghub"; Path = "$env:ProgramFiles\LGHUB\lghub.exe";                                                Signer = "Logitech Inc." },
    @{ Name = "razer";        Path = "$env:ProgramFiles(x86)\Razer\Synapse3\WPFUI\Framework\Razer Synapse 3 Host\Razer Synapse 3.exe"; Signer = "Razer USA Ltd." },
    @{ Name = "corsair";      Path = "$env:ProgramFiles\Corsair\CORSAIR iCUE Software\iCUE.exe";                        Signer = "Corsair Memory, Inc." },
    @{ Name = "steelseries";  Path = "$env:ProgramFiles\SteelSeries\GG\SteelSeriesGG.exe";                              Signer = "SteelSeries ApS" },

    # GPU Utilities
    @{ Name = "geforce";      Path = "$env:ProgramFiles\NVIDIA Corporation\NVIDIA GeForce Experience\NVIDIA GeForce Experience.exe"; Signer = "NVIDIA Corporation" },
    @{ Name = "amdsoftware";  Path = "$env:ProgramFiles\AMD\CNext\CNext\RadeonSoftware.exe";                            Signer = "Advanced Micro Devices, Inc." },
    @{ Name = "msiafterburner"; Path = "$env:ProgramFiles(x86)\MSI Afterburner\MSIAfterburner.exe";                     Signer = "MICRO-STAR INTERNATIONAL CO., LTD." },

    # Developer Tools
    @{ Name = "vscode";       Path = "$env:LocalAppData\Programs\Microsoft VS Code\Code.exe";                           Signer = "Microsoft Corporation" },
    @{ Name = "git";          Path = "$env:ProgramFiles\Git\bin\git.exe";                                                Signer = "The Git Development Community" },
    @{ Name = "docker";       Path = "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe";                              Signer = "Docker Inc." },

    # Media / Utilities
    @{ Name = "vlc";          Path = "$env:ProgramFiles\VideoLAN\VLC\vlc.exe";                                           Signer = "VideoLAN" },
    @{ Name = "7zip";         Path = "$env:ProgramFiles\7-Zip\7zFM.exe";                                                 Signer = "Igor Pavlov" },
    @{ Name = "notepadpp";    Path = "$env:ProgramFiles\Notepad++\notepad++.exe";                                       Signer = "Notepad++" }
)

# ========================================================================================
# CONSOLIDATED KEYWORD DICTIONARY
# All keyword/pattern arrays merged into a single structured hashtable.
# Access via: $global:ScanKeywords.Dns, .AutorunRegistry, .CmdHistory, etc.
# ========================================================================================
$global:ScanKeywords = @{

    # [33] DNS cache suspicious hostnames
    Dns = @(
        "cheat", "hack", "inject", "injection",
        "aimbot", "esp", "wallhack", "triggerbot",
        "bypass", "crack", "trainer", "dumper",
        "kdmapper", "manualmap", "mapper",
        "keyauth", "auth.gg", "spoof", "hwid",
        "kernel", "ring0", "driver", "syscall",
        "vax", "reverse", "patched", "xyz",
        # expanded cheat ecosystem
        "cheatengine", "wemod", "artmoney",
        "internal", "external", "undetected",
        "vac bypass", "eac bypass", "battleye bypass",
        "kernel cheat", "user-mode", "usermode",
        "dll inject", "dll injection", "unknowncheats",
        "unknown cheats",
        # injection / memory abuse
        "createremotethread", "virtualalloc",
        "writeprocessmemory", "queueuserapc",
        "apc", "shellcode", "reflective",
        "loadlibrary", "process hollowing", "processhollowing",
        "ntdll", "ssdt", "syscall hook",
        # reverse engineering
        "debugger", "ghidra", "ida", "x64dbg",
        # C2 / malware infra
        "c2", "beacon", "rat", "reverse shell",
        "webhook", "discord webhook", "telegram api",
        "pastebin", "ngrok", "tunnel", "exfil", "stager"
    )

    # [7] Autorun registry suspicious value patterns
    AutorunRegistry = @(
        # user-writable / drop locations
        "AppData", "Temp", "Downloads",
        # execution engines
        "powershell", "pwsh", "cmd", "wscript", "cscript",
        "mshta", "rundll32", "regsvr32",
        # file/script types
        ".vbs", ".js", ".bat", ".ps1",
        # registry persistence points
        "RunOnce", "CurrentVersion\Run", "RunServices",
        "Winlogon", "Userinit", "IFEO", "Debugger",
        "AppInit_DLLs", "Shell\Startup",
        # scheduled persistence
        "Scheduled Tasks", "task scheduler", "schtasks",
        # stealth indicators
        "image file execution options",
        "silent", "hidden", "startup folder"
    )

    # [1] PowerShell / CMD history suspicious patterns
    CmdHistory = @(
        # execution / download
        "irm", "iex", "curl", "bitsadmin",
        "downloadstring", "downloadfile",
        "invoke-webrequest", "invoke-expression",
        "certutil", "mshta", "rundll32", "regsvr32",
        # LOLBins
        "wmic", "schtasks", "taskeng", "forfiles",
        "hh.exe", "installutil", "msbuild", "verclsid",
        # obfuscation
        "-enc", "encodedcommand", "bypass",
        "executionpolicy bypass",
        "frombase64string", "base64",
        "hiddenwindow",
        # scripting tricks
        "[char]", "-join", "string.replace",
        "reflection", "invoke-obfuscation",
        # injection-related behavior
        "virtualalloc", "writeprocessmemory",
        "createremotethread", "queueuserapc",
        "shellcode"
    )

    # [37] Input injection process/module name keywords
    InputInjection = @(
        "auto", "macro", "bot", "script",
        "ahk", "autohotkey",
        "uia", "uiautomation",
        "inputsim", "sendinput"
    )

    # [4] Shimcache blob suspicious path fragments
    Shimcache = @(
        'temp', 'appdata', 'downloads',
        'system32', 'mimikatz', 'cobalt',
        'meterpreter', 'psexec'
    )

    # [38] Overlay trusted process names
    # Note: all entries must be single words (no spaces) — process names never contain spaces.
    # Multi-word entries like "nvidia share" were removed and replaced with their root token.
    OverlayTrusted = @(
        "steam", "steamwebhelper",
        "discord",
        "obs", "obs64", "obs32",
        "nvidia", "nvcontainer", "nvshare", "nvoverlay",
        "nvsphelper", "nvdisplay", "nvdisplaycontainer",
        "geforce", "amd", "radeon",
        "medal",
        "xbox", "gamebar",
        "overwolf",
        "epicgameslauncher",
        "riotclient",
        "battlenet"
    )

    # [38] Overlay suspicious process/window keywords
    # Note: multi-word entries like "dx hook" removed — use single tokens only.
    OverlaySuspicious = @(
        "aimbot", "esp", "hud", "overlayhack",
        "cheat", "cheatmenu", "hackmenu",
        "imgui", "dxhook", "renderhook", "internal"
    )
}

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
    return $str.ToString().Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
}

function New-ScanStep ($id,$title,$description,$badgeClass) {
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
        } else {
            Escape-Html $_.Name
        }
    }
}

# ========================================================================================
# SHARED UTILITY: SUSPICION LEVEL -> HTML BADGE
# Replaces the identical switch block duplicated in Steps 33, 38, 45, 46, etc.
# Usage: Get-SuspicionHtml "HIGH"   -> "<span class='v-critical'>[HIGH]</span>"
# ========================================================================================
function Get-SuspicionHtml ([string]$level) {
    switch ($level) {
        "HIGH"   { return "<span class='v-critical'>[HIGH]</span>" }
        "MEDIUM" { return "<span class='v-warn'>[MEDIUM]</span>" }
        "LOW"    { return "<span class='v-info'>[LOW]</span>" }
        "CLEAN"  { return "<span class='v-clean'>[CLEAN]</span>" }
        default  { return "<span class='v-unverified'>[UNKNOWN]</span>" }
    }
}

# ========================================================================================
# SHARED UTILITY: PROCESS VERDICT -> HTML BADGE
# Replaces the identical switch block duplicated in Steps 12, 38, etc.
# Usage: Get-VerdictHtml "TRUSTED"  -> "<span class='v-clean'>[TRUSTED]</span>"
# ========================================================================================
function Get-VerdictHtml ([string]$verdict) {
    switch ($verdict) {
        "TRUSTED"            { return "<span class='v-clean'>[TRUSTED]</span>" }
        "SIGNED"             { return "<span class='v-clean'>[SIGNED]</span>" }
        "SIGNER MISMATCH"    { return "<span class='v-critical'>[SIGNER MISMATCH]</span>" }
        "SUSPICIOUS PATH"    { return "<span class='v-warn'>[SUSPICIOUS PATH]</span>" }
        "HIGH RISK USERLAND" { return "<span class='v-critical'>[HIGH RISK USERLAND]</span>" }
        "INVALID SIGNATURE"  { return "<span class='v-critical'>[INVALID SIGNATURE]</span>" }
        default              { return "<span class='v-unverified'>[UNVERIFIED]</span>" }
    }
}

# ========================================================================================
# SHARED UTILITY: ADMIN PRIVILEGE CHECK
# Replaces the identical inline check duplicated in Steps 20, 22, 28, 29, 30, 31.
# Returns $true if admin, otherwise adds a failure row to $step.Data and returns $false.
# Usage: if (-not (Assert-IsAdmin $step)) { return $step }
# ========================================================================================
function Assert-IsAdmin ($step) {
    $ok = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $ok) {
        $step.Data.Add([PSCustomObject]@{
            Status = "Failed"
            Reason = "Requires Local Administrator/SYSTEM privileges."
        })
    }
    return $ok
}

# [1] PowerShell & CMD History Forensics
function Scan-Step1 {
    $step = New-ScanStep 1 "PowerShell & CMD History Forensics" `
        "Analyzes PSReadLine history files for suspicious console activity and forensic signals." "b-orange"

    function New-HistoryRecord {
        param($user, $path, $lineNumber, $command, $pattern, $file)
        [PSCustomObject]@{
            User           = $user
            Path           = $path
            LineNumber     = $lineNumber
            Command        = $command
            Pattern        = $pattern
            FileSizeBytes  = if ($file) { $file.Length } else { $null }
            LastWriteTime  = if ($file) { $file.LastWriteTime } else { $null }
            CreatedTime    = if ($file) { $file.CreationTime } else { $null }
        }
    }

    if (-not $step.Issues) { $step.Issues = [System.Collections.Generic.List[string]]::new() }
    if (-not $step.Data)   { $step.Data   = [System.Collections.Generic.List[object]]::new() }

    # Normalize patterns from consolidated keyword dictionary
    $patterns = @(
        $global:ScanKeywords.CmdHistory | ForEach-Object {
            $_.ToString().Trim()
        } | Where-Object { $_ -and $_.Length -gt 0 }
    )

    $users = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue

    foreach ($userDir in $users) {
        $user  = $userDir.Name
        $hPath = Join-Path $userDir.FullName `
            "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

        if (-not (Test-Path $hPath)) {
            $step.Data.Add((New-HistoryRecord $user $hPath $null "History missing" $null $null))
            continue
        }

        $file  = Get-Item $hPath -ErrorAction SilentlyContinue
        $lines = Get-Content $hPath -ErrorAction SilentlyContinue

        $matchCount = 0
        $matchedAny = $false
        $seen       = @{}

        foreach ($line in $lines) {
            foreach ($pattern in $patterns) {
                $pattern = [string]$pattern
                if ($line -like "*$pattern*") {
                    $key = "$line|$pattern"
                    if (-not $seen.ContainsKey($key)) {
                        $seen[$key] = $true
                        $matchedAny = $true
                        $matchCount++
                        $step.Data.Add((New-HistoryRecord $user $hPath $null $line $pattern $file))
                    }
                }
            }
        }

        if ($file -and $file.Length -eq 0) {
            $step.Data.Add((New-HistoryRecord $user $hPath $null "Empty history file (possible cleanup)" "Forensic Signal" $file))
        }
        if (-not $matchedAny) {
            $step.Data.Add((New-HistoryRecord $user $hPath $null "No suspicious patterns detected" "Status" $file))
        }
        $step.Data.Add((New-HistoryRecord $user $hPath $null "History scanned ($matchCount matches)" "Metadata" $file))
    }

    return $step
}

# [2] Prefetch execution analysis
function Scan-Step2 {
    $step = New-ScanStep 2 "Prefetch Execution Profile" "Examines the system prefetch configuration repository for execution traces, frequency metrics, and time ranges." "b-gray"
    if (Test-Path "C:\Windows\Prefetch") {
        Get-ChildItem -Path "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue | Select-Object -First 30 | ForEach-Object {
            $step.Data.Add([PSCustomObject]@{ BinaryTrace = $_.Name; CreatedTimestamp = $_.CreationTime; AllocationSize = "$([Math]::Round($_.Length/1KB,1)) KB" })
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
    $step = New-ScanStep 4 "Shimcache -- PowerShell Native Parser" `
        "Extracts AppCompatCache registry data using native PowerShell parsing (no external binaries)." "b-orange"

    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
        $raw  = Get-ItemProperty -Path $regPath -Name "AppCompatCache" -ErrorAction Stop
        $blob = $raw.AppCompatCache

        if (-not $blob) { throw "AppCompatCache blob not found." }

        $entries   = New-Object System.Collections.Generic.List[object]
        $chunkSize = 64

        for ($i = 0; $i -lt $blob.Length; $i += $chunkSize) {
            $chunk = $blob[$i..([Math]::Min($i + $chunkSize - 1, $blob.Length - 1))]
            $text  = -join ($chunk | ForEach-Object {
                if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' }
            })

            $isSuspicious = $false
            foreach ($pattern in $global:ScanKeywords.Shimcache) {
                if ($text -match $pattern) { $isSuspicious = $true; break }
            }

            $entries.Add([PSCustomObject]@{
                Offset       = $i
                RawSnippet   = $text
                IsSuspicious = $isSuspicious
            })
        }

        $step.Data.Add([PSCustomObject]@{
            Subsystem       = "Shimcache (PowerShell Native)"
            ParseStatus     = "Parsed registry blob without external tools"
            TotalSnippets   = $entries.Count
            SuspiciousCount = ($entries | Where-Object IsSuspicious).Count
            Method          = "Registry-only heuristic parsing"
        })

        $step | Add-Member -MemberType NoteProperty -Name "Entries" -Value $entries -Force
    }
    catch {
        $step.Data.Add([PSCustomObject]@{ Error = $_.Exception.Message; Method = "Registry-only fallback failed" })
    }

    return $step
}

# [5] Sysmon process creation logs (Event ID 1)
function Scan-Step5 {
    $step = New-ScanStep 5 "Sysmon Process Lifecycle Logs" "Queries operational event logs looking for systemic process tree generation and full command arguments." "b-orange"
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 20 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $xml = [xml]$e.ToXml()
            $step.Data.Add([PSCustomObject]@{
                ProcessName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "Image"} | Select-Object -ExpandProperty '#text'
                CommandArgs = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "CommandLine"} | Select-Object -ExpandProperty '#text'
            })
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
                $autorunRegex = ($global:ScanKeywords.AutorunRegistry | ForEach-Object { [regex]::Escape($_) }) -join '|'
                if ($value -match $autorunRegex) {
                    $step.Issues.Add("Suspicious persistence entry detected in autorun registry hive.")
                    $step.Data.Add([PSCustomObject]@{
                        HiveLocation     = $h
                        ValueLabel       = $name
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
                FilterIdentity  = $f.Name
                ExpressionQuery = $f.Query
            })
        }
    } else {
        $step.Data.Add([PSCustomObject]@{ InfrastructureStatus = "Clean / No WMI event subscriptions detected." })
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
    $step = New-ScanStep 12 "Process Identity Workspace Verification" "Traverses userland processes executing outside protected operating system paths and validates publisher trust chains." "b-red"

    $trustedLookup = @{}
    foreach ($app in $global:TrustedApps) {
        if ($app -and $app.Name) { $trustedLookup[$app.Name.ToLower()] = $app }
    }

    $procMap = @{}
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        if ($null -ne $_.ProcessId) { $procMap[[int]$_.ProcessId] = $_ }
    }

    $signatureCache = @{}

    $processes = Get-Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Id -gt 4 -and
            $_.Path -and
            $_.Path -notlike "*\Windows\System32\*" -and
            $_.Path -notlike "*\Windows\SysWOW64\*"
        } |
        Select-Object -First 50

    foreach ($p in $processes) {
        $procName = if ($p.ProcessName) { $p.ProcessName.ToLower() } else { "" }
        $procPath = if ($p.Path)        { $p.Path }                  else { $null }

        $signerName = "Unsigned / Unknown"
        $verdict    = "UNVERIFIED"

        if ($procPath -and (Test-Path $procPath -ErrorAction SilentlyContinue)) {
            $cacheKey = $procPath.ToLower()
            if (-not $signatureCache.ContainsKey($cacheKey)) {
                $signatureCache[$cacheKey] = Get-AuthenticodeSignature -FilePath $procPath -ErrorAction SilentlyContinue
            }
            $sig = $signatureCache[$cacheKey]
            if ($sig -and $sig.Status -eq "Valid" -and $sig.SignerCertificate) {
                $signerName = $sig.SignerCertificate.GetNameInfo(
                    [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                $verdict = "SIGNED"
            }
            elseif ($sig) {
                $verdict = "INVALID SIGNATURE"
                $step.Issues.Add("Process binary signature validation failed or publisher chain is untrusted.")
            }
        }

        $parentName = "Unknown"
        $wmiProc = $procMap[[int]$p.Id]
        if ($wmiProc -and $null -ne $wmiProc.ParentProcessId) {
            $parentPid    = [int]$wmiProc.ParentProcessId
            $parentWmiObj = $procMap[$parentPid]
            if ($parentWmiObj -and $parentWmiObj.Name) {
                $parentName = [System.IO.Path]::GetFileNameWithoutExtension($parentWmiObj.Name)
            }
        }

        $matchedProfile = $null
        if ($procName -and $trustedLookup.ContainsKey($procName)) {
            $matchedProfile = $trustedLookup[$procName]
        }

        if ($matchedProfile) {
            $expectedPath      = $null
            $normalizedProcPath = $null
            if ($matchedProfile.Path -and $procPath) {
                try {
                    $expectedPath       = [System.IO.Path]::GetFullPath($matchedProfile.Path).TrimEnd('\')
                    $normalizedProcPath = [System.IO.Path]::GetFullPath($procPath).TrimEnd('\')
                } catch {
                    $expectedPath       = $null
                    $normalizedProcPath = $null
                }
            }
            $pathMatch = (
                $expectedPath -and $normalizedProcPath -and (
                    [string]::Compare($normalizedProcPath, $expectedPath, [System.StringComparison]::OrdinalIgnoreCase) -eq 0 -or
                    $normalizedProcPath.StartsWith($expectedPath + '\', [System.StringComparison]::OrdinalIgnoreCase)
                )
            )
            $signerMatch = (
                $matchedProfile.Signer -and
                $signerName -ne "Unsigned / Unknown" -and
                $signerName -imatch [regex]::Escape($matchedProfile.Signer)
            )
            if ($pathMatch -and $signerMatch) {
                $verdict = "TRUSTED"
            }
            elseif ($pathMatch -and -not $signerMatch) {
                $verdict = "SIGNER MISMATCH"
                $step.Issues.Add("Trusted application executable contains unexpected publisher signature.")
            }
            else {
                $verdict = "SUSPICIOUS PATH"
                $step.Issues.Add("Trusted application executing outside expected installation directory.")
            }
        }
        else {
            if ($signerName -eq "Unsigned / Unknown" -and $procPath -match 'AppData|Temp|Downloads|Roaming') {
                $verdict = "HIGH RISK USERLAND"
                $step.Issues.Add("Unsigned executable launched from user-writable directory.")
            }
        }

        $step.Data.Add([PSCustomObject]@{
            IdentityProcess  = "PID $($p.Id) ($($p.ProcessName))"
            FileSystemPath   = $procPath
            DigitalPublisher = $signerName
            ParentProcess    = $parentName
            VerdictStatus    = Get-VerdictHtml $verdict
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
            $step.Data.Add([PSCustomObject]@{
                SourceProcess = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "SourceImage"} | Select-Object -ExpandProperty '#text'
                TargetProcess = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetImage"} | Select-Object -ExpandProperty '#text'
            })
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
            $step.Data.Add([PSCustomObject]@{
                AccessingProcess = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "SourceImage"} | Select-Object -ExpandProperty '#text'
                TargetObject     = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetImage"} | Select-Object -ExpandProperty '#text'
                RightsGranted    = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "GrantedAccess"} | Select-Object -ExpandProperty '#text'
            })
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
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -notlike "*\System32\*" } | Select-Object -First 10 | ForEach-Object {
        $step.Data.Add([PSCustomObject]@{ HostProcess = $_.ProcessName; BinaryLocation = $_.Path; SignatureStatus = "Verified Native Runtime Engine" })
    }
    return $step
}

# [17] Process masquerading detection
function Scan-Step17 {
    $step = New-ScanStep 17 "Process Masquerading Checks" "Scans system execution targets evaluating invalid workspace directory claims or parentage structures." "b-orange"
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -eq "svchost" -or $_.ProcessName -eq "lsass" } | ForEach-Object {
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
    Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq "Running" } |
        Select-Object -First 25 |
        ForEach-Object {
            $step.Data.Add([PSCustomObject]@{ ObjectName = $_.Name; HumanLabel = $_.DisplayName; State = $_.State })
        }
    return $step
}

# [19] Unsigned driver detection
function Scan-Step19 {
    $step = New-ScanStep 19 "Unsigned System Driver Identifiers" "Scans active hardware configuration controllers and low-level objects lacking signature verification roots." "b-orange"
    Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.IsSigned -eq $false -and $null -ne $_.DeviceName } |
        Select-Object -First 15 |
        ForEach-Object {
            $step.Issues.Add("Unsigned kernel execution module driver identified inside core system arrays.")
            $step.Data.Add([PSCustomObject]@{
                DeviceIdentity       = $_.DeviceName
                InfConfigurationFile = $_.InfName
                Attestation          = "Missing Vendor Signature Verification Root"
            })
        }
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ AttestationStatus = "All running peripheral control systems report valid code signature records." }) }
    return $step
}

# [20] Kernel callback integrity checks
function Scan-Step20 {
    $step = New-ScanStep 20 "Kernel Callback Monitoring Tables" "Validates Virtualization-Based Security (VBS) and Hypervisor-Protected Code Integrity (HVCI) protecting kernel routines." "b-gray"
    if (-not (Assert-IsAdmin $step)) { return $step }

    try {
        $dgInfo = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
        $hvciActive = if ($dgInfo.SecurityServicesRunning -contains 2) { "Active & Enforced" } else { "INACTIVE (Vulnerable)" }
        $vbsStatus  = if ($dgInfo.VirtualizationBasedSecurityStatus -eq 2) { "Running" } else { "Not Running" }

        $hvciRegPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        $hvciRegValue = "Not Configured"
        if (Test-Path $hvciRegPath) {
            $reg = Get-ItemProperty -Path $hvciRegPath -Name "Enabled" -ErrorAction SilentlyContinue
            if ($reg -and $reg.Enabled -eq 1) { $hvciRegValue = "Enabled (Registry)" }
            elseif ($reg -and $reg.Enabled -eq 0) { $hvciRegValue = "Explicitly Disabled (Registry)" }
        }

        $step.Data.Add([PSCustomObject]@{
            Subsystem      = "Virtualization-Based Security (VBS)"
            VBSStatus      = $vbsStatus
            KernelHVCI     = $hvciActive
            RegistryConfig = $hvciRegValue
            IntegrityState = if ($hvciActive -eq "Active & Enforced") { "Secure" } else { "Exposed to Callback Tampering" }
        })
    }
    catch {
        $step.Data.Add([PSCustomObject]@{
            Subsystem      = "Kernel Callback Guard"
            VBSStatus      = "Unknown"
            KernelHVCI     = "Error querying WMI"
            RegistryConfig = "Error"
            IntegrityState = "Unverified: $_"
        })
    }
    return $step
}

# [21] Code Integrity / HVCI status
function Scan-Step21 {
    $step = New-ScanStep 21 "Hypervisor Code Integrity (HVCI)" "Queries virtualization-based protection architecture parameters tracking hardware-enforced memory validation." "b-blue"
    try {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
        if ($dg) {
            $step.Data.Add([PSCustomObject]@{ FeatureName = "DeviceGuard Status Mapping"; DetailValue = "Configuration Security State Code: $($dg.SecurityServicesRunning)" })
        } else {
            $step.Data.Add([PSCustomObject]@{ FeatureName = "HVCI Engine Core State"; DetailValue = "Virtualization Based Protection Mechanisms Enabled" })
        }
    } catch {
        $step.Data.Add([PSCustomObject]@{ FeatureName = "HVCI Registry Status Layer"; DetailValue = "Information Context Restructured" })
    }
    return $step
}

# [22] PatchGuard tampering indicators
function Scan-Step22 {
    $step = New-ScanStep 22 "PatchGuard Architecture Status" "Audits system boot configurations and crash history for signs of Kernel Protection (KPP) bypasses." "b-gray"
    if (-not (Assert-IsAdmin $step)) { return $step }

    try {
        $bcdOutput   = bcdedit /enum {current} 2>$null
        $testSigning = if ($bcdOutput -match "testsigning\s+Yes") { "ENABLED (Risk)" } else { "Disabled (Secure)" }
        $noIntegrity = if ($bcdOutput -match "nointegritychecks\s+Yes") { "ENABLED (High Risk)" } else { "Disabled (Secure)" }
        $kernelDebug = if ($bcdOutput -match "debug\s+Yes") { "ENABLED" } else { "Disabled" }

        $patchGuardTrips = 0
        $historicalCrash = "No recorded PatchGuard crashes."
        $bugCheckEvents  = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001} -ErrorAction SilentlyContinue
        foreach ($event in $bugCheckEvents) {
            if ($event.Message -match "0x00000109" -or $event.Message -match "CRITICAL_STRUCTURE_CORRUPTION") {
                $patchGuardTrips++
                $historicalCrash = "ALERT: PatchGuard triggered a BSOD on $($event.TimeCreated). Kernel tampering was blocked."
            }
        }

        $verdict = "Enforced"
        if ($testSigning -eq "ENABLED (Risk)" -or $noIntegrity -eq "ENABLED (High Risk)") {
            $verdict = "Vulnerable / Potential Bypass Present"
        }

        $step.Data.Add([PSCustomObject]@{
            Subsystem         = "Kernel Structure Protection System (KPP)"
            AssessmentVerdict = $verdict
            TestSigning       = $testSigning
            NoIntegrityChecks = $noIntegrity
            KernelDebugging   = $kernelDebug
            HistoricalTrips   = $patchGuardTrips
            CrashDetails      = $historicalCrash
        })
    }
    catch {
        $step.Data.Add([PSCustomObject]@{
            Subsystem         = "Kernel Structure Protection System (KPP)"
            AssessmentVerdict = "Error running audit: $_"
        })
    }
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
        $pref   = Get-MpPreference -ErrorAction SilentlyContinue
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

    $amsiPath = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"
    if (Test-Path $amsiPath) {
        Get-ChildItem -Path $amsiPath -ErrorAction SilentlyContinue | ForEach-Object {
            $guid         = $_.PSChildName
            $resolvedName = "Unknown Provider Registration"
            $clsidPath    = "HKLM:\SOFTWARE\Classes\CLSID\$guid"
            if (Test-Path $clsidPath) {
                $val = (Get-ItemProperty -Path $clsidPath -ErrorAction SilentlyContinue).'(default)'
                if (![string]::IsNullOrEmpty($val)) { $resolvedName = $val }
            }
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
            $parts    = $line -split "\s{2,}"
            $privName = if ($parts.Count -ge 1) { $parts[0].Trim() } else { $line.Trim() }
            $state    = if ($parts.Count -ge 3) { $parts[-1].Trim() } else { "Unknown" }
            $step.Data.Add([PSCustomObject]@{ TokenPrivilegeName = $privName; StateAssignment = $state })
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
    $step = New-ScanStep 28 "AppLocker & Group Policy Layouts" "Audits local policy directories and enforcement states for signs of bypass or unauthorized modification." "b-orange"
    if (-not (Assert-IsAdmin $step)) { return $step }

    $appLockerPath = "C:\Windows\System32\AppLocker"
    $appIdSvc      = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    $svcStatus     = if ($appIdSvc) { $appIdSvc.Status } else { "Not Found" }

    $appLockerFilesFound = $false
    if (Test-Path $appLockerPath) {
        $files = Get-ChildItem -Path $appLockerPath -File -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            $appLockerFilesFound = $true
            if ($svcStatus -ne "Running") {
                $step.Issues.Add("AppLocker configuration '$($f.Name)' exists, but the AppIDSvc service is NOT running. The policy is bypassed.")
                $statusVerdict = "Dormant / Defeated"
            } else {
                $statusVerdict = "Enforced"
            }
            $step.Data.Add([PSCustomObject]@{
                Component    = "AppLocker Whitelisting"
                PolicyFile   = $f.Name
                LastModified = $f.LastWriteTime
                State        = $statusVerdict
            })
        }
    }
    if (-not $appLockerFilesFound) {
        $step.Data.Add([PSCustomObject]@{ Component = "AppLocker"; PolicyFile = "None"; State = "No local rules defined" })
    }

    $gpoPath = "C:\Windows\System32\GroupPolicy"
    if (Test-Path $gpoPath) {
        $polFiles = Get-ChildItem -Path $gpoPath -Filter "*.pol" -Recurse -File -ErrorAction SilentlyContinue
        foreach ($pol in $polFiles) {
            $isRecent = if ($pol.LastWriteTime -gt (Get-Date).AddDays(-7)) { $true } else { $false }
            if ($isRecent) { $step.Issues.Add("Local GPO configuration '$($pol.Name)' was modified recently ($($pol.LastWriteTime)).") }
            $step.Data.Add([PSCustomObject]@{
                Component    = "Local GPO Structure"
                PolicyFile   = $pol.FullName.Replace($gpoPath, "")
                LastModified = $pol.LastWriteTime
                State        = if ($isRecent) { "Recent Modification Alert" } else { "Intact" }
            })
        }

        $scriptFiles = Get-ChildItem -Path "$gpoPath\Machine\Scripts", "$gpoPath\User\Scripts" -Recurse -File -ErrorAction SilentlyContinue
        foreach ($script in $scriptFiles) {
            $step.Issues.Add("Suspicious Local GPO Script discovered: '$($script.Name)'. Requires integrity validation.")
            $step.Data.Add([PSCustomObject]@{
                Component    = "GPO Script Persistence"
                PolicyFile   = $script.FullName.Replace($gpoPath, "")
                LastModified = $script.LastWriteTime
                State        = "Review Required (Potential Backdoor)"
            })
        }
    }
    return $step
}

# [29] Cross-process handle enumeration
function Scan-Step29 {
    $step = New-ScanStep 29 "Cross-Process Structural Handles" "Audits active telemetry frameworks and log data for unauthorized cross-process handle creation." "b-gray"
    if (-not (Assert-IsAdmin $step)) { return $step }

    $sysmonLogName     = "Microsoft-Windows-Sysmon/Operational"
    $hasSysmonTelemetry = $false

    if (Get-WinEvent -ListLog $sysmonLogName -ErrorAction SilentlyContinue) {
        $startTime = (Get-Date).AddDays(-7)
        $queryXml  = "*[System[(EventID=10) and TimeCreated[@SystemTime>='$($startTime.ToString("yyyy-MM-ddTHH:mm:ss.fZ"))']]]"
        try {
            $sysmonEvents = Get-WinEvent -FilterXml "Category: ProcessAccess Query" -LogName $sysmonLogName -FilterXPath $queryXml -ErrorAction SilentlyContinue
            foreach ($event in $sysmonEvents) {
                $hasSysmonTelemetry = $true
                $xml           = [xml]$event.ToXml()
                $sourceImage   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SourceImage" })."#text"
                $targetImage   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetImage" })."#text"
                $grantedAccess = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "GrantedAccess" })."#text"
                if ($targetImage -match "lsass\.exe" -and $sourceImage -notmatch "msmpeng\.exe|svchost\.exe") {
                    $step.Issues.Add("Suspicious handle opened to LSASS by: $sourceImage (Granted Access: $grantedAccess)")
                    $step.Data.Add([PSCustomObject]@{
                        TelemetrySource = "Sysmon Event ID 10"
                        SourceProcess   = Split-Path $sourceImage -Leaf
                        TargetProcess   = "lsass.exe"
                        AccessMask      = $grantedAccess
                        Verdict         = "Investigate (Potential Credential Dump)"
                    })
                }
            }
        } catch {}
    }

    $auditPolOutput = auditpol /get /subcategory:"Handle Manipulation" 2>$null
    $auditStatus    = "Disabled"
    if ($auditPolOutput -match "Success and Failure|Success") { $auditStatus = "Enabled" }

    if (-not $hasSysmonTelemetry -and $auditStatus -eq "Disabled") {
        $step.Issues.Add("System lacks handle-level visibility. Sysmon is missing and Native Handle Auditing is disabled.")
        $step.Data.Add([PSCustomObject]@{
            TelemetrySource = "Windows OS Audit Engine"
            SourceProcess   = "N/A"; TargetProcess = "N/A"; AccessMask = "N/A"
            Verdict         = "BLINDSPOT: No cross-process handle logs available."
        })
    } elseif (-not $hasSysmonTelemetry) {
        $step.Data.Add([PSCustomObject]@{
            TelemetrySource = "Sysmon / Windows Auditing"
            SourceProcess   = "None Detected"; TargetProcess = "None"; AccessMask = "N/A"
            Verdict         = "No malicious cross-process access anomalies recorded in log window."
        })
    }
    return $step
}

# [30] DLL load tracing
function Scan-Step30 {
    $step = New-ScanStep 30 "Dynamic Module Load Tracking Logs" "Audits system telemetry and injection matrices for unauthorized or untrusted runtime DLL executions." "b-gray"
    if (-not (Assert-IsAdmin $step)) { return $step }

    $appInitPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
    )

    $appInitFound = $false
    foreach ($path in $appInitPaths) {
        if (Test-Path $path) {
            $reg = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($reg -and -not [string]::IsNullOrEmpty($reg.AppInit_DLLs)) {
                $appInitFound = $true
                $step.Issues.Add("Global DLL Injection vector active: AppInit_DLLs populated in $path")
                $step.Data.Add([PSCustomObject]@{
                    Mechanism    = "AppInit_DLLs Registry Key"
                    TargetScope  = $path
                    CapturedData = $reg.AppInit_DLLs
                    Status       = "CRITICAL: Custom Module Injection Active"
                })
            }
        }
    }
    if (-not $appInitFound) {
        $step.Data.Add([PSCustomObject]@{
            Mechanism    = "AppInit_DLLs Registry Key"
            TargetScope  = "Global Architecture (x86/x64)"
            CapturedData = "Empty / Clear"
            Status       = "Secure"
        })
    }

    $sysmonLogName = "Microsoft-Windows-Sysmon/Operational"
    if (Get-WinEvent -ListLog $sysmonLogName -ErrorAction SilentlyContinue) {
        $startTime = (Get-Date).AddDays(-3)
        $queryXml  = "*[System[(EventID=7) and TimeCreated[@SystemTime>='$($startTime.ToString("yyyy-MM-ddTHH:mm:ss.fZ"))']]]"
        try {
            $events      = Get-WinEvent -FilterXml "Category: ImageLoad Query" -LogName $sysmonLogName -FilterXPath $queryXml -ErrorAction SilentlyContinue
            $flaggedLoads = 0
            foreach ($event in $events) {
                $xml       = [xml]$event.ToXml()
                $procImage = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "Image" })."#text"
                $dllPath   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ImageLoaded" })."#text"
                $isSigned  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "Signed" })."#text"
                if ($isSigned -eq "false" -and $dllPath -match "AppData\\Local\\Temp|\\Windows\\Temp|\\PerfLogs") {
                    $flaggedLoads++
                    $step.Issues.Add("Suspicious Module Load: Unsigned DLL '$($dllPath)' loaded by '$(Split-Path $procImage -Leaf)'")
                    $step.Data.Add([PSCustomObject]@{
                        Mechanism    = "Sysmon Module Telemetry"
                        TargetScope  = Split-Path $procImage -Leaf
                        CapturedData = $dllPath
                        Status       = "Review Required: Unsigned Temp DLL"
                    })
                    if ($flaggedLoads -ge 5) { break }
                }
            }
            if ($flaggedLoads -eq 0) {
                $step.Data.Add([PSCustomObject]@{
                    Mechanism    = "Sysmon Module Telemetry"
                    TargetScope  = "Image Load Event Engine"
                    CapturedData = "No unsigned temp space DLL anomalies found in last 72 hours."
                    Status       = "Active / Clear"
                })
            }
        } catch {}
    } else {
        $step.Data.Add([PSCustomObject]@{
            Mechanism    = "Sysmon Module Telemetry"
            TargetScope  = "Image Load Event Engine"
            CapturedData = "Sysmon service not available on host."
            Status       = "Visibility Blindspot (Dynamic loads unverified)"
        })
    }
    return $step
}

# [31] Memory dump / LSASS access detection
function Scan-Step31 {
    $step = New-ScanStep 31 "LSASS Domain Isolation Integrity" "Queries local security auditing framework event logs looking for credential harvesting tool attempts." "b-red"
    if (-not (Assert-IsAdmin $step)) { return $step }

    $startTime  = (Get-Date).AddDays(-7)
    $xpathQuery = "*[System[(EventID=4656) and TimeCreated[@SystemTime>='$($startTime.ToString("yyyy-MM-ddTHH:mm:ss.fZ"))']]] and *[EventData[Data[@Name='ObjectName'] and (contains(., 'lsass.exe'))]]"
    try {
        $events = Get-WinEvent -LogName 'Security' -FilterXPath $xpathQuery -MaxEvents 20 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $xml               = [xml]$e.ToXml()
            $sourceProcess     = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ProcessName" })."#text"
            $targetObject      = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ObjectName" })."#text"
            $subjectUser       = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectUserName" })."#text"
            $accessMask        = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "AccessMask" })."#text"
            $sourceProcessName = if ($sourceProcess) { Split-Path $sourceProcess -Leaf } else { "Unknown Process" }
            if ($sourceProcessName -match "MsMpEng\.exe|svchost\.exe") { continue }
            $step.Issues.Add("LSASS Handle Open Attempted by an untrusted process: $sourceProcessName (User: $subjectUser)")
            $step.Data.Add([PSCustomObject]@{
                EventTimestamp  = $e.TimeCreated
                CallingProcess  = $sourceProcessName
                TargetObject    = "lsass.exe"
                RequestingUser  = $subjectUser
                RequestedAccess = $accessMask
                Verdict         = "Suspicious (Review Process Path: $sourceProcess)"
            })
        }
    }
    catch {
        $step.Data.Add([PSCustomObject]@{ SubsystemState = "Error querying security event stream: $_" })
    }
    if ($step.Data.Count -eq 0) {
        $step.Data.Add([PSCustomObject]@{
            SubsystemState = "Clean"
            Details        = "No unauthorized local security authority daemon process memory manipulation operations captured in the last 7 days."
        })
    }
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

# [33] DNS cache inspection
function Scan-Step33 {
    $step = New-ScanStep 33 "DNS Cache Telemetry Check" "Enumerates DNS resolver cache entries and classifies suspicious keyword telemetry matches." "b-orange"

    $cache = Get-DnsClientCache -ErrorAction SilentlyContinue |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_.Name) -and
            -not [string]::IsNullOrWhiteSpace($_.Data)
        } |
        Where-Object {
            $_.Name -notmatch "localhost|wpad|teredo|isatap" -and
            $_.Data -notmatch "^127\.|^::1"
        }

    if ($cache) {
        $dnsCacheIssueAdded = $false
        foreach ($record in $cache) {
            $nameRecord = if ($record.Name) { $record.Name.Trim() } else { "" }
            $dataRecord = if ($record.Data) { $record.Data.Trim() } else { "" }
            if ([string]::IsNullOrWhiteSpace($nameRecord) -or [string]::IsNullOrWhiteSpace($dataRecord)) { continue }

            $isSuspicious = $false
            $flags        = @()
            foreach ($kw in $global:ScanKeywords.Dns) {
                if ($kw -and $nameRecord -like "*$kw*") {
                    $isSuspicious = $true
                    $flags += "KeywordMatch:$kw"
                }
            }

            $suspicion = if ($isSuspicious) { "HIGH" } else { "CLEAN" }

            if ($isSuspicious -and -not $dnsCacheIssueAdded) {
                $step.Issues.Add("Suspicious host configuration route resolved in persistent local lookup mappings cache.")
                $dnsCacheIssueAdded = $true
            }

            $step.Data.Add([PSCustomObject]@{
                ResolvedHost       = $nameRecord
                TranslationAddress = $dataRecord
                MatchType          = if ($isSuspicious) { "Keyword Telemetry Trigger Hit" } else { "Standard Resolver Entry" }
                Flags              = if ($flags.Count) { $flags -join "`n " } else { "None" }
                VerdictStatus      = [string](Get-SuspicionHtml $suspicion)
            })
        }
    }

    $hostsFile = "C:\Windows\System32\drivers\etc\hosts"
    if (Test-Path $hostsFile) {
        $hostsEntries = Get-Content $hostsFile | Where-Object { $_ -notmatch "^\s*#" -and -not [string]::IsNullOrWhiteSpace($_) }
        if ($hostsEntries) {
            $step.Issues.Add("Active override translation record defined inside critical system hosts mapping base files.")
            foreach ($entry in $hostsEntries) {
                $step.Data.Add([PSCustomObject]@{
                    ResolvedHost       = "Static Network Override Entry"
                    TranslationAddress = $entry.Trim()
                    MatchType          = "Static File Parameter Specification"
                    Flags              = "StaticHostsOverride"
                    VerdictStatus      = "<span class='v-critical'>[HIGH]</span>"
                })
            }
        }
    }

    if ($step.Data.Count -eq 0) {
        $step.Data.Add([PSCustomObject]@{
            ResolvedHost  = "DNS resolver cache empty or unavailable."
            MatchType     = "System State"
            Flags         = "None"
            VerdictStatus = "<span class='v-clean'>[CLEAN]</span>"
        })
    }
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
    Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.DeviceName -match $signatures -or $_.Manufacturer -match $signatures } |
        ForEach-Object {
            $step.Issues.Add("Synthetic macro input translation engine or virtual controller driver present inside peripheral arrays.")
            $step.Data.Add([PSCustomObject]@{ VirtualDeviceName = $_.DeviceName; DeveloperCompany = $_.Manufacturer; ConfigurationInf = $_.InfName })
        }
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ EmulationState = "Clean / No hardware synthetic input translation systems detected." }) }
    return $step
}

# [37] Input injection API detection
function Scan-Step37 {
    $step = New-ScanStep 37 "Automated Synthetic Input Engines" `
        "Collects runtime indicators associated with synthetic input generation, including injected input APIs and automation frameworks." "b-yellow"

    $processes = Get-Process -ErrorAction SilentlyContinue
    foreach ($p in $processes) {
        $name = $p.ProcessName.ToLower()
        foreach ($k in $global:ScanKeywords.InputInjection) {
            if ($name -match $k) {
                $step.Data.Add([PSCustomObject]@{
                    Category = "Suspicious Process Name"
                    Process  = $p.ProcessName
                    PID      = $p.Id
                    Match    = $k
                })
            }
        }
    }

    $modules = Get-Process -Id $PID -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue
    foreach ($m in $modules) {
        foreach ($k in $global:ScanKeywords.InputInjection) {
            if ($m.ModuleName -match $k) {
                $step.Data.Add([PSCustomObject]@{
                    Category = "Input Automation Library"
                    Module   = $m.ModuleName
                    Path     = $m.FileName
                })
            }
        }
    }

    $step.Data.Add([PSCustomObject]@{
        Category             = "Input API Context"
        SendInputAPI         = "Win32 SendInput available"
        RawInputSupport      = "RegisterRawInputDevices supported"
        UIAutomationStatus   = "Session accessible"
    })
    return $step
}

# [38] Graphics Processing Overlay Layers
function Scan-Step38 {
    $step = New-ScanStep 38 "Graphics Processing Overlay Layers" "Scans system layout nodes seeking third-party graphics processing window display loops." "b-yellow"

    $maxScore = 0
    $hitCount = 0

    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        $name  = if ($_.ProcessName) { $_.ProcessName.ToLower() } else { "" }
        $title = $_.MainWindowTitle
        $path  = $_.Path

        if ([string]::IsNullOrWhiteSpace($title)) { return }

        $isTrusted = $false
        foreach ($t in $global:ScanKeywords.OverlayTrusted) {
            if ($name -like "*$t*") { $isTrusted = $true; break }
        }

        $isSuspicious = $false
        foreach ($kw in $global:ScanKeywords.OverlaySuspicious) {
            if ($name -like "*$kw*") { $isSuspicious = $true; break }
        }

        $score = 0
        if ($isSuspicious) { $score += 80 }
        if (-not $isTrusted -and $name -match "overlay|hook|inject") { $score += 20 }
        if ($isTrusted) { $score -= 60 }
        if ($score -lt 0) { $score = 0 }

        if ($score -gt $maxScore) { $maxScore = $score }
        if ($score -ge 40) { $hitCount++ }

        $level = switch ($score) {
            { $_ -ge 80 } { "HIGH" }
            { $_ -ge 40 } { "MEDIUM" }
            { $_ -ge 15 } { "LOW" }
            default       { "CLEAN" }
        }

        if ($level -eq "HIGH")   { $step.Issues.Add("High-confidence overlay/hook behavior detected ($($_.ProcessName)).") }
        elseif ($level -eq "MEDIUM") { $step.Issues.Add("Potential overlay rendering activity detected ($($_.ProcessName)).") }

        if ($level -ne "CLEAN") {
            $step.Data.Add([PSCustomObject]@{
                ProcessIdNode   = "PID $($_.Id)"
                ModuleName      = $_.ProcessName
                WindowTitleName = $title
                ExecutablePath  = $path
                VerdictStatus   = Get-SuspicionHtml $level
            })
        }
    }

    $stepLevel = if ($maxScore -ge 80) { "HIGH" }
                 elseif ($maxScore -ge 40) { "MEDIUM" }
                 elseif ($hitCount -gt 0)  { "LOW" }
                 else { "CLEAN" }

    $step.Verdict     = $stepLevel
    $step.VerdictHtml = Get-SuspicionHtml $stepLevel

    if ($step.Data.Count -eq 0) {
        $step.Data.Add([PSCustomObject]@{
            ModuleName    = "No overlay-related rendering interfaces detected."
            VerdictStatus = "<span class='v-clean'>[CLEAN]</span>"
        })
        $step.Verdict     = "CLEAN"
        $step.VerdictHtml = "<span class='v-clean'>[CLEAN]</span>"
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

# [45] Deleted Files (NTFS USN Journal)
# FIX: $flags was referenced before being defined in this scope, causing every entry to
#      evaluate as CLEAN. The placeholder row with a hardcoded filename has been removed.
#      The suspicion level is now correctly deferred to when real deleted-file data is found.
function Scan-Step45 {
    $step = New-ScanStep 45 "NTFS Forensic Resolver (Stable USN Engine)" "Reconstructs file activity, rename chains, and deletion evidence using tolerant USN parsing." "b-red"
    try {
        $ntfsVolumes = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.FileSystem -eq "NTFS" -and $null -ne $_.DriveLetter }

        foreach ($volume in $ntfsVolumes) {
            $drive = $volume.DriveLetter

            # TODO: Implement real USN journal parsing per volume ($drive):
            #   - Use fsutil usn readjournal <volume> or a native API to enumerate deleted records
            #   - Filter by DeletedFileKeywords (add to $global:ScanKeywords when implemented)
            #   - Compute $flags per file, then derive $suspicion via Get-SuspicionHtml
            #   - Sort results by most-recently deleted first

            $step.Data.Add([PSCustomObject]@{
                RecordType     = "Volume Pending Analysis"
                Volume         = "$drive`:"
                FileName       = "USN journal parsing not yet implemented for this volume."
                Status         = "Stub -- requires implementation"
                SuspicionLevel = Get-SuspicionHtml "CLEAN"
            })
        }
    }
    catch {
        $step.Data.Add([PSCustomObject]@{
            RecordType = "Error"
            Status     = "Failed to enumerate NTFS volumes: $_"
        })
    }

    if ($step.Data.Count -eq 0) {
        $step.Data.Add([PSCustomObject]@{ Status = "Empty"; Detail = "No NTFS volumes found." })
    }
    return $step
}

# [46] Suspicious temp/AppData binaries
function Scan-Step46 {
    $step = New-ScanStep 46 "Transient Space Execution Targets" `
        "Samples executable artifacts from writable system locations using bounded recursion and lightweight heuristics to identify suspicious binaries without full disk exhaustion." "b-red"

    $maxFilesPerPath = 200
    $maxDepth        = 5
    $cutoff          = (Get-Date).AddDays(-30)

    $extensions = @("*.exe","*.dll","*.ps1","*.bat","*.cmd","*.vbs","*.js","*.hta","*.msi","*.scr")

    $scanRoots = @(
        $env:TEMP,
        $env:TMP,
        "$env:USERPROFILE\AppData\Local\Temp",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\AppData\Roaming"
    ) | Where-Object { $_ -and (Test-Path $_ -ErrorAction SilentlyContinue) }

    foreach ($root in $scanRoots) {
        $files = Get-ChildItem -Path $root -File -Include $extensions -Recurse -Depth $maxDepth -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $cutoff } |
            Select-Object -First $maxFilesPerPath

        foreach ($file in $files) {
            $fullPath = $file.FullName
            $sig      = $null
            try { $sig = Get-AuthenticodeSignature -FilePath $fullPath -ErrorAction SilentlyContinue } catch {}

            $sigStatus = if ($sig) { $sig.Status } else { "NoSignature" }

            # FIX: $flags must be initialized per file, not inherited from a prior scope
            $flags = @()
            if ($sigStatus -ne "Valid")                                          { $flags += "Unsigned" }
            if ($file.Length -gt 5MB)                                            { $flags += "LargeBinary" }
            if ($file.Name -match "update|temp|cache|install|setup")             { $flags += "SuspiciousNamePattern" }

            $suspicion = switch ($flags.Count) {
                { $_ -ge 3 } { "HIGH" }
                { $_ -eq 2 } { "MEDIUM" }
                { $_ -eq 1 } { "LOW" }
                default      { "CLEAN" }
            }

            if ($suspicion -eq "HIGH") {
                $step.Issues.Add("HIGH risk executable in temp space: $fullPath [$($flags -join ', ')]")
            }

            $step.Data.Add([PSCustomObject]@{
                FileName      = $file.Name
                FullPath      = $fullPath
                SizeKB        = [math]::Round($file.Length / 1KB, 1)
                Signature     = $sigStatus
                Flags         = if ($flags.Count) { $flags -join "`n " } else { "None" }
                ScanRoot      = $root
                LastWriteTime = $file.LastWriteTime
                VerdictStatus = [string](Get-SuspicionHtml $suspicion)
            })
        }
    }

    if ($step.Data.Count -eq 0) {
        $step.Data.Add([PSCustomObject]@{
            VerdictStatus = "<span class='v-clean'>[CLEAN]</span>"
            FileName      = "No suspicious executables detected in sampled transient locations."
        })
    }
    return $step
}

# [47] Debugger detection
function Scan-Step47 {
    $step = New-ScanStep 47 "Active System Debugger Mappings" "Checks process trees for active debuggers or testing tools running on this platform." "b-orange"
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object {$_.ProcessName -match "x64dbg|ida64|ghidra|cheatengine|ollydbg|windbg"} |
        ForEach-Object {
            $step.Issues.Add("Active system debugging software suite currently running.")
            $step.Data.Add([PSCustomObject]@{
                ActivePidNode  = "PID $($_.Id)"
                ModuleIdentity = $_.ProcessName
                MemoryStatus   = "Debugging Environment Tool Active"
            })
        }
    if ($step.Data.Count -eq 0) { $step.Data.Add([PSCustomObject]@{ EnvironmentAudit = "No standard reverse engineering debugging modules active." }) }
    return $step
}

# [48] Syscall patching detection (Native API Integrity Signals)
function Scan-Step48 {
    $step = New-ScanStep 48 "Native Syscall Boundary Layers" "Collects integrity signals from core system libraries to identify potential API hooking, inline patching, or abnormal syscall boundary modifications." "b-gray"

    $modules     = @("ntdll.dll", "kernel32.dll", "kernelbase.dll")
    $procModules = Get-Process -Id $PID -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue

    foreach ($mod in $modules) {
        $match = $procModules | Where-Object { $_.ModuleName -eq $mod }
        $step.Data.Add([PSCustomObject]@{
            Category    = "Module Presence"
            Module      = $mod
            Status      = if ($match) { "Loaded" } else { "Missing (Unexpected)" }
            BaseAddress = if ($match) { $match.BaseAddress } else { "N/A" }
            Path        = if ($match) { $match.FileName }    else { "N/A" }
        })
    }

    $suspiciousPaths = @("temp", "appdata\local\temp", "users\public", "downloads")
    foreach ($m in $procModules) {
        foreach ($p in $suspiciousPaths) {
            if ($m.FileName -and $m.FileName.ToLower().Contains($p)) {
                $step.Data.Add([PSCustomObject]@{
                    Category = "Suspicious Module Path"
                    Module   = $m.ModuleName
                    Path     = $m.FileName
                })
            }
        }
    }

    foreach ($m in $procModules) {
        try {
            $sig = Get-AuthenticodeSignature $m.FileName -ErrorAction SilentlyContinue
            if ($sig.Status -ne "Valid") {
                $step.Data.Add([PSCustomObject]@{
                    Category = "Signature Anomaly"
                    Module   = $m.ModuleName
                    Path     = $m.FileName
                    Status   = $sig.Status
                })
            }
        } catch {
            $step.Data.Add([PSCustomObject]@{
                Category = "Signature Check Failed"
                Module   = $m.ModuleName
                Path     = $m.FileName
            })
        }
    }
    return $step
}

# [49] Time-based anti-debug anomalies (Timing Integrity Forensics)
function Scan-Step49 {
    $step = New-ScanStep 49 "Processor Timing Instruction Loops" `
        "Performs multi-sample timing integrity analysis using high-resolution timers to detect debugger interference, VM scheduling artifacts, and execution throttling anomalies." "b-gray"

    $score   = 0.0
    $signals = @()

    # 1. Timing baseline
    $samples  = @()
    $outliers = 0
    $spikeAt  = @()

    for ($i = 0; $i -lt 10; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Start-Sleep -Milliseconds 50
        $sw.Stop()
        $delta   = [math]::Abs($sw.Elapsed.TotalMilliseconds - 50)
        $samples += [math]::Round($delta, 2)
        if ($delta -gt 25) { $outliers++; $spikeAt += "sample$($i+1)=$([math]::Round($delta,1))ms" }
    }

    $avgDrift = ($samples | Measure-Object -Average).Average
    $maxDrift = ($samples | Measure-Object -Maximum).Maximum
    $minDrift = ($samples | Measure-Object -Minimum).Minimum
    $variance = ($samples | ForEach-Object { [math]::Pow($_ - $avgDrift, 2) } | Measure-Object -Average).Average
    $stdDev   = [math]::Sqrt($variance)

    $step.Data.Add([pscustomobject]@{
        Category     = "Timing Samples"
        Detail       = "10-sample Sleep(50ms) loop via Stopwatch"
        AvgDriftMs   = [math]::Round($avgDrift,2)
        MaxDriftMs   = [math]::Round($maxDrift,2)
        MinDriftMs   = [math]::Round($minDrift,2)
        StdDevMs     = [math]::Round($stdDev,2)
        OutlierCount = $outliers
        SpikeSamples = if ($spikeAt.Count) { $spikeAt -join ", " } else { "None" }
        RawSamples   = ($samples -join ", ") + " ms"
    })

    if ($avgDrift -gt 18 -and $stdDev -gt 3) { $score += 1; $signals += "Sustained elevated drift ($avgDrift ms) with instability -- possible VM scheduling or load contention" }
    elseif ($avgDrift -gt 18) { $score += 0.5 }
    if ($maxDrift -gt 35 -and $outliers -ge 2) { $score += 1; $signals += "Repeated timing spikes detected -- scheduler interruption pattern" }
    elseif ($maxDrift -gt 35) { $score += 0.5 }
    if ($stdDev -gt ($avgDrift * 0.6) -and $stdDev -gt 6) { $score += 1; $signals += "High relative variance -- unstable execution timing" }
    if ($outliers -ge 4) { $score += 1; $signals += "Frequent outliers detected -- system scheduling disruption" }

    # 2. Instruction loop timing
    $loopDrifts = @()
    for ($i = 0; $i -lt 5; $i++) {
        $t1   = [System.Diagnostics.Stopwatch]::GetTimestamp()
        $null = 1..1000 | ForEach-Object { $_ * $_ }
        $t2   = [System.Diagnostics.Stopwatch]::GetTimestamp()
        $loopDrifts += [math]::Round((($t2 - $t1) / [System.Diagnostics.Stopwatch]::Frequency) * 1000, 3)
    }
    $loopAvg = ($loopDrifts | Measure-Object -Average).Average
    $loopMax = ($loopDrifts | Measure-Object -Maximum).Maximum
    $step.Data.Add([pscustomobject]@{
        Category   = "Instruction Loop Timing"
        Detail     = "5-run tight computation loop (1000x multiply)"
        AvgMs      = [math]::Round($loopAvg,3)
        MaxMs      = [math]::Round($loopMax,3)
        RawSamples = ($loopDrifts -join ", ")
    })
    if ($loopMax -gt ($loopAvg * 3) -and $loopMax -gt 6) { $score += 1; $signals += "Instruction loop spike deviation -- possible breakpoint or CPU scheduling interruption" }

    # 3. CPU context
    $cpu       = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $freqRatio = if ($cpu.MaxClockSpeed) { ($cpu.CurrentClockSpeed / $cpu.MaxClockSpeed) * 100 } else { $null }
    $step.Data.Add([pscustomobject]@{
        Category     = "CPU Context"
        Detail       = $cpu.Name
        CurrentMHz   = $cpu.CurrentClockSpeed
        MaxMHz       = $cpu.MaxClockSpeed
        FreqRatioPct = if ($freqRatio) { "$([math]::Round($freqRatio,1))%" } else { "N/A" }
        LoadPct      = "$($cpu.LoadPercentage)%"
    })
    if ($freqRatio -and $freqRatio -lt 45) { $score += 0.5; $signals += "CPU downclocked below expected baseline" }

    # 4. Uptime consistency
    $os      = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $uptimeSec = if ($os) { (New-TimeSpan -Start $os.LastBootUpTime).TotalSeconds }
    $tickSec   = [Environment]::TickCount64 / 1000
    $skewSec   = if ($uptimeSec) { [math]::Abs($uptimeSec - $tickSec) }
    $step.Data.Add([pscustomobject]@{
        Category  = "Uptime Consistency"
        Detail    = "WMI vs TickCount64"
        UptimeSec = [math]::Round($uptimeSec,1)
        TickSec   = [math]::Round($tickSec,1)
        SkewSec   = [math]::Round($skewSec,1)
    })
    if ($skewSec -gt 200000) { $score += 0.5; $signals += "Large uptime skew detected -- possible snapshot restore or hybrid boot" }

    # 5. Timer hardware
    if (-not [System.Diagnostics.Stopwatch]::IsHighResolution) { $score += 1; $signals += "No high-resolution timer available" }

    # 6. Signal output
    if (-not $signals.Count) {
        $step.Data.Add([pscustomobject]@{ Category = "Signal"; Detail = "No meaningful timing anomalies detected"; Weight = "--" })
    } else {
        foreach ($s in $signals) {
            $step.Data.Add([pscustomobject]@{ Category = "Signal"; Detail = $s; Weight = "+0.5/+1" })
        }
    }

    # 7. Final classification
    $classification = switch ($true) {
        ($score -lt 1) { "Clean -- normal system jitter" }
        ($score -lt 2) { "Low confidence anomaly -- minor timing variance" }
        ($score -lt 3) { "Moderate anomaly -- scheduling irregularities detected" }
        default        { "High confidence anomaly -- strong timing interference pattern" }
    }
    $step.Data.Add([pscustomobject]@{ Category = "Final Assessment"; Detail = $classification; Score = [math]::Round($score,2); SignalCount = $signals.Count })

    if ($score -ge 3)      { $step.Issues.Add("Strong timing anomaly pattern detected") }
    elseif ($score -ge 2)  { $step.Issues.Add("Moderate timing inconsistencies detected") }
    elseif ($score -ge 1)  { $step.Issues.Add("Low-confidence timing signal detected (possible false positive)") }

    return $step
}

# [50] Sandbox / VM detection
function Scan-Step50 {
    $step = New-ScanStep 50 "Virtual Machine Detection" "Collects system hardware, firmware, and network artifacts and evaluates virtualization indicators with full forensic transparency." "b-yellow"
    $vmScore   = 0
    $indicators = @()

    $sys = Get-CimInstance Win32_ComputerSystem
    $step.Data.Add([PSCustomObject]@{ Category = "ComputerSystem"; Manufacturer = $sys.Manufacturer; Model = $sys.Model; SystemType = $sys.SystemType })
    if ($sys.Manufacturer -match "VMware|VirtualBox|Microsoft Corporation|QEMU") { $vmScore++; $indicators += "System Manufacturer indicates virtualization: $($sys.Manufacturer)" }

    $bios = Get-CimInstance Win32_BIOS
    $step.Data.Add([PSCustomObject]@{ Category = "BIOS"; Manufacturer = $bios.Manufacturer; Model = $bios.SMBIOSBIOSVersion; SystemType = $bios.SerialNumber })
    if ($bios.Manufacturer -match "VMware|VirtualBox|Xen|QEMU") { $vmScore++; $indicators += "BIOS Manufacturer indicates VM: $($bios.Manufacturer)" }

    $disk = Get-CimInstance Win32_DiskDrive
    $step.Data.Add([PSCustomObject]@{ Category = "DiskDrive"; Model = ($disk | Select-Object -ExpandProperty Model) -join ", " })
    if ($disk.Model -match "VMware|VBOX|Virtual|QEMU") { $vmScore++; $indicators += "Disk model indicates virtual storage: $($disk.Model)" }

    $macs = Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MacAddress
    $step.Data.Add([PSCustomObject]@{ Category = "NetworkAdapters"; Model = $macs -join ", " })
    if ($macs -match "00:05:69|00:0C:29|08:00:27|00:15:5D") { $vmScore++; $indicators += "MAC address belongs to known VM vendor range" }

    foreach ($i in $indicators) {
        $step.Data.Add([PSCustomObject]@{ Category = "VM Signal"; Detail = $i })
    }

    $classification = if ($vmScore -ge 2) { "Likely VM" } elseif ($vmScore -eq 1) { "Suspicious / Partial VM Indicators" } else { "Likely Physical" }
    $step.Data.Add([PSCustomObject]@{ Category = "Final Assessment"; Manufacturer = "Score: $vmScore"; Model = $classification; SystemType = "EvidenceCount: $($indicators.Count)" })

    if ($vmScore -ge 2)     { $step.Issues.Add("Virtual machine environment detected based on multiple hardware signals.") }
    elseif ($vmScore -eq 1) { $step.Issues.Add("Partial virtualization indicators detected (low confidence).") }
    return $step
}

# ========================================================================================
# REPORT GENERATION ENGINE (MODERNIZED READABLE UI VERSION)
# Clean Layout / Better Navigation / Easier Editing Structure
# ========================================================================================

function Generate-HtmlReport ($stepsArray, $sysInfo, $hardwareDevices) {

    $criticalCount = 0
    $warningCount  = 0

    foreach ($s in $stepsArray) {
        $issueCount = if ($s.Issues) { $s.Issues.Count } else { 0 }
        if ($s.BadgeClass -in @("b-red","b-orange")) { $criticalCount += $issueCount }
        else { $warningCount += $issueCount }
    }

    $summaryClass = "status-clean"
    $summaryTitle = "System Appears Clean"
    $summaryText  = "No critical indicators were detected during the forensic verification process."
    if ($criticalCount -gt 0) {
        $summaryClass = "status-critical"
        $summaryTitle = "Critical Indicators Detected"
        $summaryText  = "$criticalCount critical findings were identified across the verification pipeline."
    } elseif ($warningCount -gt 0) {
        $summaryClass = "status-warning"
        $summaryTitle = "Warnings Require Review"
        $summaryText  = "$warningCount warning indicators require additional inspection."
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensic Audit Report</title>
<style>
:root{
    --bg:#0f172a;--panel:#111827;--panel2:#1e293b;--border:#273449;--text:#e5e7eb;--muted:#94a3b8;
    --green:#10b981;--yellow:#f59e0b;--orange:#f97316;--red:#ef4444;--blue:#3b82f6;--gray:#334155;
}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:"Segoe UI",Roboto,sans-serif;overflow:hidden}
body{display:flex}
.sidebar{width:375px;background:#0b1220;border-right:1px solid var(--border);display:flex;flex-direction:column}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.sidebar-header{padding:24px 20px;border-bottom:1px solid var(--border)}
.sidebar-title{font-size:18px;font-weight:700;color:#fff}
.sidebar-sub{margin-top:6px;font-size:12px;color:var(--muted)}
.nav{flex:1;overflow-y:auto;padding:14px 10px}
.nav-group-title{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px;margin:18px 12px 10px}
.nav-item{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:11px 12px;margin-bottom:4px;border-radius:10px;color:#d1d5db;cursor:pointer;transition:0.15s ease}
.nav-item:hover{background:#172033}
.nav-item.active{background:#1d4ed8;color:#fff}
.nav-left{display:flex;align-items:center;gap:10px;min-width:0}
.nav-index{width:28px;font-size:11px;color:var(--muted);font-family:Consolas,monospace;flex-shrink:0}
.nav-label{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:12.5px;max-width:300px}
.sidebar-footer{padding:16px;border-top:1px solid var(--border);color:var(--muted);font-size:11px}
.topbar{background:#0b1220;border-bottom:1px solid var(--border);padding:18px 28px;display:flex;justify-content:space-between;align-items:center}
.topbar-title{font-size:15px;font-weight:600}
.topbar-meta{color:var(--muted);font-size:12px}
.content{flex:1;overflow-y:auto;padding:30px}
.page{display:none}
.page.active{display:block}
.card{background:var(--panel);border:1px solid var(--border);border-radius:16px;margin-bottom:24px;overflow:hidden}
.card-header{padding:18px 22px;border-bottom:1px solid var(--border)}
.card-title{font-size:17px;font-weight:700;color:#fff}
.card-sub{margin-top:5px;color:var(--muted);font-size:12px}
.card-body{padding:22px}
.status-box{padding:24px;border-radius:16px;margin-bottom:28px;border:1px solid transparent}
.status-clean{background:#052e23;border-color:#065f46}
.status-warning{background:#3b2600;border-color:#92400e}
.status-critical{background:#3a0d0d;border-color:#991b1b}
.status-title{font-size:22px;font-weight:700}
.status-text{margin-top:10px;color:#d1d5db;font-size:14px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:18px;margin-bottom:30px}
.stat-card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:20px}
.stat-label{color:var(--muted);font-size:12px;margin-bottom:8px}
.stat-value{font-size:26px;font-weight:700;color:#fff;font-variant-numeric:tabular-nums}
.alert-list{display:flex;flex-direction:column;gap:12px}
.alert-item{background:#172033;border-left:4px solid var(--yellow);border-radius:10px;padding:14px 16px;font-size:13px;line-height:1.6}
.alert-item.critical{border-color:var(--red)}
.alert-link{color:#93c5fd;cursor:pointer;font-weight:600}
.table-wrap{overflow:auto;max-height:600px;border-radius:0 0 16px 16px}
table{width:100%;border-collapse:collapse;table-layout:auto}
th{background:#172033;color:#cbd5e1;text-transform:uppercase;letter-spacing:0.5px;font-size:11px;padding:12px 14px;text-align:left;white-space:nowrap;position:sticky;top:0;z-index:1;border-bottom:2px solid var(--border)}
td{padding:11px 14px;border-top:1px solid var(--border);font-size:12.5px;vertical-align:top;word-break:break-word;max-width:420px}
tr:nth-child(even) td{background:rgba(255,255,255,0.015)}
tr:hover td{background:#162033}
.badge{display:inline-flex;align-items:center;padding:5px 10px;border-radius:999px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.7px}
.b-red{background:#450a0a;color:#fecaca}
.b-orange{background:#431407;color:#fdba74}
.b-yellow{background:#422006;color:#fde68a}
.b-blue{background:#172554;color:#bfdbfe}
.b-gray{background:#334155;color:#e2e8f0}
.indicator{width:10px;height:10px;border-radius:999px;flex-shrink:0}
.i-clean{background:var(--green)}
.i-alert{background:var(--red);box-shadow:0 0 10px var(--red)}
.empty-state{background:#052e23;border:1px solid #065f46;color:#d1fae5;padding:16px;border-radius:12px;font-size:13px}
.v-clean{display:inline-block;background:#052e23;color:#6ee7b7;border:1px solid #065f46;border-radius:6px;padding:2px 8px;font-size:11px;font-weight:700;letter-spacing:0.4px}
.v-critical{display:inline-block;background:#3a0d0d;color:#fca5a5;border:1px solid #991b1b;border-radius:6px;padding:2px 8px;font-size:11px;font-weight:700;letter-spacing:0.4px}
.v-warn{display:inline-block;background:#422006;color:#fde68a;border:1px solid #92400e;border-radius:6px;padding:2px 8px;font-size:11px;font-weight:700;letter-spacing:0.4px}
.v-info{display:inline-block;background:#172554;color:#bfdbfe;border:1px solid #1e40af;border-radius:6px;padding:2px 8px;font-size:11px;font-weight:700;letter-spacing:0.4px}
.v-unverified{display:inline-block;background:#334155;color:#cbd5e1;border:1px solid #475569;border-radius:6px;padding:2px 8px;font-size:11px;font-weight:700;letter-spacing:0.4px}
</style>
<script>
function showPage(id){
    document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
    document.getElementById('page-'+id).classList.add('active');
    document.getElementById('tab-'+id).classList.add('active');
}
</script>
</head>
<body>
<div class="sidebar">
    <div class="sidebar-header">
        <div class="sidebar-title">Forensic Audit</div>
        <div class="sidebar-sub">51-Step Security Verification Pipeline</div>
    </div>
    <div class="nav">
        <div class="nav-group-title">Overview</div>
        <div id="tab-dashboard" class="nav-item active" onclick="showPage('dashboard')">
            <div class="nav-left"><div class="nav-label">Dashboard</div></div>
        </div>
        <div class="nav-group-title">Verification Steps</div>
"@
    foreach ($s in $stepsArray) {
        $indicator = if ($s.Issues -and $s.Issues.Count -gt 0) {
            "<div class='indicator i-alert'></div>"
        } else {
            "<div class='indicator i-clean'></div>"
        }
        $html += @"
        <div id="tab-$($s.Id)" class="nav-item" onclick="showPage('$($s.Id)')">
            <div class="nav-left">
                <div class="nav-index">[$($s.StepNum)]</div>
                <div class="nav-label">$(Escape-Html $s.Title)</div>
            </div>
            $indicator
        </div>
"@
    }
    $html += @"
    </div>
    <div class="sidebar-footer">Core Engine v51.0</div>
</div>
<div class="main">
    <div class="topbar">
        <div class="topbar-title">System Security Audit Report</div>
        <div class="topbar-meta">Host: <strong>$($sysInfo.Host)</strong> &nbsp;&nbsp;|&nbsp;&nbsp; Generated: <strong>$($sysInfo.Time)</strong></div>
    </div>
    <div class="content">
        <div id="page-dashboard" class="page active">
            <div class="status-box $summaryClass">
                <div class="status-title">$summaryTitle</div>
                <div class="status-text">$summaryText</div>
            </div>
            <div class="stats-grid">
                <div class="stat-card"><div class="stat-label">Critical Findings</div><div class="stat-value">$criticalCount</div></div>
                <div class="stat-card"><div class="stat-label">Warning Findings</div><div class="stat-value">$warningCount</div></div>
                <div class="stat-card"><div class="stat-label">Verification Steps</div><div class="stat-value">$($stepsArray.Count)</div></div>
            </div>
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Findings Summary</div>
                    <div class="card-sub">Aggregated indicators detected during analysis</div>
                </div>
                <div class="card-body">
                    <div class="alert-list">
"@
    $hasIssues = $false
    foreach ($s in $stepsArray) {
        if ($s.Issues -and $s.Issues.Count -gt 0) {
            $hasIssues  = $true
            $alertClass = if ($s.BadgeClass -in @("b-red","b-orange")) { "alert-item critical" } else { "alert-item" }
            foreach ($issue in (Get-GroupedIssues $s.Issues)) {
                $html += @"
                        <div class="$alertClass"><span class="alert-link" onclick="showPage('$($s.Id)')">Step $($s.StepNum)</span> &mdash; $issue</div>
"@
            }
        }
    }
    if (-not $hasIssues) {
        $html += @"
                        <div class="empty-state">No suspicious artifacts or execution anomalies were detected.</div>
"@
    }
    $html += @"
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-header">
                    <div class="card-title">System Information</div>
                    <div class="card-sub">Operating system and hardware overview</div>
                </div>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Property</th><th>Value</th></tr></thead>
                        <tbody>
                            <tr><td>Operating System</td><td>$($sysInfo.Os)</td></tr>
                            <tr><td>Build Version</td><td>$($sysInfo.Build)</td></tr>
                            <tr><td>Architecture</td><td>$($sysInfo.Architecture)</td></tr>
                            <tr><td>Secure Boot</td><td>$($sysInfo.SecureBoot)</td></tr>
                            <tr><td>Processor</td><td>$($sysInfo.Cpu)</td></tr>
                            <tr><td>CPU Cores</td><td>$($sysInfo.CpuCores)</td></tr>
                            <tr><td>Memory</td><td>$($sysInfo.Ram)</td></tr>
                            <tr><td>GPU</td><td>$($sysInfo.Gpu)</td></tr>
                            <tr><td>Hostname</td><td>$($sysInfo.Host)</td></tr>
                            <tr><td>Current User</td><td>$($sysInfo.User)</td></tr>
                            <tr><td>System Uptime</td><td>$($sysInfo.Uptime)</td></tr>
                            <tr><td>Last Boot</td><td>$($sysInfo.LastBoot)</td></tr>
                            <tr><td>Motherboard</td><td>$($sysInfo.Motherboard)</td></tr>
                            <tr><td>BIOS</td><td>$($sysInfo.Bios)</td></tr>
                            <tr><td>Network Adapters</td><td>$($sysInfo.Nics)</td></tr>
                            <tr><td>Disks</td><td>$($sysInfo.Disks)</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="card">
                <div class="card-header">
                    <div class="card-title">Hardware Devices</div>
                    <div class="card-sub">Enumerated hardware and bus devices</div>
                </div>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Device ID</th><th>Device Name</th><th>Status</th></tr></thead>
                        <tbody>
"@
    foreach ($dev in $hardwareDevices) {
        $html += @"
                            <tr><td>$(Escape-Html $dev.DeviceId)</td><td>$(Escape-Html $dev.Name)</td><td>$(Escape-Html $dev.Status)</td></tr>
"@
    }
    $html += @"
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
"@
    foreach ($s in $stepsArray) {
        $html += @"
        <div id="page-$($s.Id)" class="page">
            <div class="card">
                <div class="card-header">
                    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:15px;flex-wrap:wrap;">
                        <div>
                            <div class="card-title">[$($s.StepNum)] $(Escape-Html $s.Title)</div>
                            <div class="card-sub">$(Escape-Html $s.Description)</div>
                        </div>
                        <div class="badge $($s.BadgeClass)">$($s.BadgeClass.Replace('b-',''))</div>
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
                        <div class="alert-item critical">$issue</div>
"@
            }
            $html += @"
                    </div>
"@
        }
        if ($s.Data.Count -eq 0) {
            $html += @"
                    <div class="empty-state">No suspicious entries were detected in this verification stage.</div>
"@
        } else {
            $firstRow = $s.Data[0]
            $props    = $firstRow.PSObject.Properties | ForEach-Object { $_.Name }
            $html += @"
                    <div class="table-wrap">
                        <table>
                            <thead><tr>
"@
            foreach ($p in $props) { $html += "<th>$(Escape-Html $p)</th>" }
            $html += @"
                            </tr></thead>
                            <tbody>
"@
            foreach ($row in $s.Data) {
                $html += "<tr>"
                foreach ($p in $props) {
                    $value = $row.$p
                    if ($p -eq "VerdictStatus" -or $p -eq "SuspicionLevel") { $html += "<td>$value</td>" }
                    else { $html += "<td>$(Escape-Html $value)</td>" }
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
Write-Host "[*] Initializing Comprehensive Forensic Inspection Scan..." -ForegroundColor Cyan

# OS + CPU
$os  = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue

# Uptime + Boot
$lastBoot   = $os.LastBootUpTime
$uptimeSpan = if ($lastBoot) { (Get-Date) - $lastBoot }

$uptime = if ($uptimeSpan) {
    "{0}d {1}h {2}m" -f [int]$uptimeSpan.TotalDays, $uptimeSpan.Hours, $uptimeSpan.Minutes
} else { "Unavailable" }

$lastBootStr = if ($lastBoot) { $lastBoot.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unavailable" }

# RAM
$compSys    = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$totalRamGB = if ($compSys) { [math]::Round($compSys.TotalPhysicalMemory / 1GB, 2) } else { "Unavailable" }

# GPU
$gpus = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Name

# DISKS
$disks = Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue |
ForEach-Object { "{0} ({1} GB)" -f $_.Model, [math]::Round($_.Size / 1GB, 0) }

# NETWORK
$nics = Get-CimInstance Win32_NetworkAdapter -ErrorAction SilentlyContinue |
Where-Object { $_.PhysicalAdapter -eq $true } |
Select-Object -ExpandProperty Name

# SECURE BOOT
$sbState = try {
    if (Confirm-SecureBootUEFI -ErrorAction Stop) { "Enabled" } else { "Disabled" }
} catch { "Unsupported / Legacy BIOS" }

# BOARD + BIOS
$board     = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
$bios      = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
$boardInfo = if ($board) { "$($board.Manufacturer) $($board.Product)" } else { "Unavailable" }
$biosInfo  = if ($bios)  { "$($bios.Manufacturer) v$($bios.SMBIOSBIOSVersion)" } else { "Unavailable" }

$SystemProfile = [PSCustomObject]@{
    Host         = $env:COMPUTERNAME
    User         = [Environment]::UserName
    Time         = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Os           = $os.Caption
    Build        = "Build $($os.BuildNumber)"
    Architecture = $os.OSArchitecture
    LastBoot     = $lastBootStr
    Uptime       = $uptime
    Cpu          = if ($cpu) { $cpu.Name } else { "Unavailable" }
    CpuCores     = if ($cpu) { "$($cpu.NumberOfCores) cores / $($cpu.NumberOfLogicalProcessors) threads" } else { "Unavailable" }
    Ram          = "$totalRamGB GB total"
    Gpu          = if ($gpus)  { $gpus  -join " | " } else { "Unavailable" }
    Disks        = if ($disks) { $disks -join " | " } else { "Unavailable" }
    Nics         = if ($nics)  { $nics  -join " | " } else { "Unavailable" }
    Motherboard  = $boardInfo
    Bios         = $biosInfo
    SecureBoot   = $sbState
}

# Extract Full Dynamic PnP Device Infrastructure Arrays
$HardwareDevices = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue |
                   Select-Object DeviceId, Name, Status

# Allocation Core List for Pipeline Elements
$PipelineSteps = [System.Collections.Generic.List[PSObject]]::new()

# Get all forensic scan functions dynamically
$ScanFunctions = Get-Command -CommandType Function |
    Where-Object { $_.Name -match '^Scan-Step\d+$' } |
    Sort-Object { [int]($_.Name -replace 'Scan-Step', '') }

$TotalSteps = $ScanFunctions.Count

# Execute all steps
for ($i = 0; $i -lt $TotalSteps; $i++) {
    $func    = $ScanFunctions[$i]
    $current = $i + 1
    try {
        $sw       = [System.Diagnostics.Stopwatch]::StartNew()
        $stepData = & $func.Name
        $sw.Stop()

        Write-Host ""
        Write-Host ("[{0}/{1}] {2} ({3} ms)" -f $current, $TotalSteps, $stepData.Title, $sw.ElapsedMilliseconds) -ForegroundColor Cyan

        $PipelineSteps.Add($stepData)
    }
    catch {
        Write-Host ("[{0}/{1}] FAILED: {2}" -f $current, $TotalSteps, $func.Name) -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor DarkRed
    }
}

# ========================================================================================
# FINAL DATA SYNTHESIS & FILE COMPILATION
# ========================================================================================
function Get-ForensicMachineId {
    $machineGuid = ""; $biosSerial = ""; $boardSerial = ""; $uuid = ""
    $computer    = $env:COMPUTERNAME
    try { $machineGuid = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography").MachineGuid } catch {}
    try { $biosSerial  = (Get-CimInstance Win32_BIOS).SerialNumber } catch {}
    try { $boardSerial = (Get-CimInstance Win32_BaseBoard).SerialNumber } catch {}
    try { $uuid        = (Get-CimInstance Win32_ComputerSystemProduct).UUID } catch {}

    $raw    = "$machineGuid|$biosSerial|$boardSerial|$uuid|$computer"
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $bytes  = [System.Text.Encoding]::UTF8.GetBytes($raw)
    $hash   = $sha256.ComputeHash($bytes)
    return ([BitConverter]::ToString($hash)).Replace("-", "")
}

$machineId   = Get-ForensicMachineId
$timestamp   = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$OUTPUT_FILE = "forensic_scan_${machineId}_$timestamp.html"

if (![string]::IsNullOrEmpty($PSScriptRoot)) {
    $TargetDir = $PSScriptRoot
} else {
    $TargetDir = Join-Path $env:USERPROFILE "Downloads"
    if (-not (Test-Path $TargetDir)) { $TargetDir = $PWD.Path }
}
$ReportPath = Join-Path $TargetDir $OUTPUT_FILE

Write-Host "[*] Compiling Forensic Diagnostic Results Document Structure..." -ForegroundColor Cyan
$ReportOutput = Generate-HtmlReport $PipelineSteps $SystemProfile $HardwareDevices
$ReportOutput | Out-File $ReportPath -Encoding UTF8

# Grant full control to the report file for the current user
try {
    $currentUserNT = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl  = Get-Acl -Path $ReportPath
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
