# ========================================================================================
# Forensic Scanner - Windows Edition (PowerShell)
# Performs a 23-step system audit and saves a clean HTML report.
# Must be run as Administrator.
# ========================================================================================

# 1. Enforce Administrator Rights
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[-] Error: This script must be run as Administrator. Right-click PowerShell and choose 'Run as Administrator'."
    Exit 1
}

# 2. Set Execution Policy for the current process session
# This ensures that any dynamically loaded modules or dot-sourced scripts run smoothly
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
    Write-Host "[+] Process execution policy successfully configured to Bypass." -ForegroundColor Green
} catch {
    Write-Warning "[-] Could not adjust local execution policy automatically: $_"
    Write-Warning "[-] If the script fails to run, execute via: powershell.exe -ExecutionPolicy Bypass -File deepscan.ps1"
}

# 3. Initialize Output Configurations
$OUTPUT_FILE = "forensic_scan_report_win.html"
$TMP_DIR = Join-Path $env:TEMP "forensic_scan_$(Get-Random)"
New-Item -ItemType Directory -Path $TMP_DIR -Force | Out-Null

function Escape-Html ($str) {
    if ([string]::IsNullOrEmpty($str)) { return "" }
    $str = $str -replace '&', '&amp;'
    $str = $str -replace '<', '&lt;'
    $str = $str -replace '>', '&gt;'
    $str = $str -replace '"', '&quot;'
    return $str
}

function Get-FileContent ($filePath) {
    if (Test-Path $filePath) { return Get-Content $filePath -Raw -ErrorAction SilentlyContinue }
    return ""
}

Write-Host ""
Write-Host "[*] Starting Forensic Scan (Windows)..." -ForegroundColor Cyan
Write-Host ""

# Counters for the summary dashboard
$RWX_ANOM_COUNT   = 0
$UNLINKED_COUNT   = 0
$TEST_SIGN_STATUS = 0
$SYNTH_COUNT      = 0
$DRV_OVERRIDES    = 0
$ENV_INJECT_COUNT = 0
$INPUT_SPOOFS     = 0
$OVERLAYS_COUNT   = 0
$PIPE_COUNT       = 0

# Whitelist definition for known applications that legitimately allocate RWX memory (e.g., JIT engines)
$TrustedApps = @(
    @{
        Name = "Brave Browser"
        Paths = @(
            "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe",
            "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe"
        )
        Signers = @("CN=Brave Software, Inc.")
    },
    @{
        Name = "Google Chrome"
        Paths = @(
            "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
            "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
        )
        Signers = @("CN=Google LLC")
    },
    @{
        Name = "Microsoft Edge"
        Paths = @(
            "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe",
            "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
        )
        Signers = @("CN=Microsoft Corporation")
    },
    @{
        Name = "Steam"
        Paths = @(
            "$env:ProgramFiles(x86)\Steam\steam.exe",
            "$env:ProgramFiles\Steam\steam.exe"
        )
        Signers = @("CN=Valve Corporation", "CN=Valve Corp.")
    },
    @{
        Name = "Discord"
        Paths = @(
            "$env:LOCALAPPDATA\Discord\Update.exe",
            # Note: Discord paths can dynamically change based on versioning,
            # so wildcards or exact executable tracking may apply, but exact matches are safest:
            "$env:LOCALAPPDATA\Discord\app-1.0.9143\Discord.exe"
        )
        Signers = @("CN=Discord Inc.")
    },
    @{
        Name = "Spotify"
        Paths = @(
            "$env:ProgramFiles\Spotify\Spotify.exe",
            "$env:AppData\Spotify\Spotify.exe"
        )
        Signers = @("CN=Spotify AB")
    },
    @{
        Name = "OBS Studio"
        Paths = @(
            "$env:ProgramFiles\obs-studio\bin\64bit\obs64.exe"
        )
        Signers = @("CN=Wizardry and Steamworks")
    }
)

# ==========================================
# STEP 1 - PowerShell Command History
# Check if the user ever typed cheat-related commands
# ==========================================
Write-Host "[1/23] Checking PowerShell command history for suspicious keywords..." -ForegroundColor Yellow
$step1File = Join-Path $TMP_DIR "step1.txt"
$historyPatterns = "gdb|strace|ptrace|inject|memfd|cheat|trainer|cheatengine|kdmapper|mapdriver|gh0stinjector|readprocessmemory|writeprocessmemory|vmm|drvmap|gamehack"

Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $user = $_.Name
    $historyPath = Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $historyPath) {
        Select-String -Path $historyPath -Pattern $historyPatterns -ErrorAction SilentlyContinue | ForEach-Object {
            "<tr><td>$user - PSReadLine history</td><td>$(Escape-Html $_.Line)</td></tr>" | Out-File $step1File -Append -Encoding UTF8
            $ENV_INJECT_COUNT++
        }
    }
}

# ==========================================
# STEP 2 - Suspicious Executables in Temp Folders
# Executables dropped in temp folders recently are suspicious
# ==========================================
Write-Host "[2/23] Looking for recently created executables in temporary folders..." -ForegroundColor Yellow
$step2File = Join-Path $TMP_DIR "step2.txt"
$scanPaths = @($env:TEMP, "C:\Windows\Temp", "C:\Users\Public")
foreach ($path in $scanPaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -File -Include *.exe, *.dll, *.sys, *.bat, *.ps1 -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-3) } | ForEach-Object {
            "<tr><td>$(Escape-Html $_.FullName)</td><td>$($_.Attributes)</td><td>$($_.Length) bytes</td></tr>" | Out-File $step2File -Append -Encoding UTF8
        }
    }
}

# ==========================================
# STEP 3 - Loaded Kernel Drivers
# Unusual or unsigned kernel drivers can hide cheats or bypass anti-cheat
# ==========================================
Write-Host "[3/23] Listing all running kernel drivers..." -ForegroundColor Yellow
$step3File = Join-Path $TMP_DIR "step3.txt"
Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue |
Where-Object { $_.State -eq "Running" } | ForEach-Object {
    "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.DisplayName)</td><td>$($_.State)</td></tr>" | Out-File $step3File -Append -Encoding UTF8
}

# ==========================================
# STEP 4 - Running Windows Services
# Suspicious services may run cheat loaders in the background
# ==========================================
Write-Host "[4/23] Listing all currently running Windows services..." -ForegroundColor Yellow
$step4File = Join-Path $TMP_DIR "step4.txt"
Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" } | ForEach-Object {
    "<tr><td>$(Escape-Html $_.Name)</td><td>Running</td><td>$(Escape-Html $_.DisplayName)</td></tr>" | Out-File $step4File -Append -Encoding UTF8
}

# ==========================================
# STEP 5 - AppInit_DLLs Registry (Global DLL Injection)
# DLLs listed here are loaded into EVERY process on the system - classic cheat injection
# ==========================================
Write-Host "[5/23] Checking AppInit_DLLs registry for global DLL injection..." -ForegroundColor Yellow
$step5File = Join-Path $TMP_DIR "step5.txt"
$regPaths = @(
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
)
foreach ($reg in $regPaths) {
    if (Test-Path $reg) {
        $appInit = (Get-ItemProperty -Path $reg -Name "AppInit_DLLs" -ErrorAction SilentlyContinue).AppInit_DLLs
        if (-not [string]::IsNullOrEmpty($appInit)) {
            "<tr><td>$reg</td><td>$(Escape-Html $appInit)</td></tr>" | Out-File $step5File -Append -Encoding UTF8
        }
    }
}

# ==========================================
# STEP 6 - USB & Input Device Inventory
# Looks for unusual input hardware: Teensy, Arduino (hardware cheat devices)
# ==========================================
Write-Host "[6/23] Checking connected USB and input devices..." -ForegroundColor Yellow
$step6File = Join-Path $TMP_DIR "step6.txt"
Get-PnpDevice -Class "Mouse","Keyboard","HIDClass" -ErrorAction SilentlyContinue | ForEach-Object {
    "<tr><td>$($_.Class)</td><td>$(Escape-Html $_.FriendlyName)</td><td>$($_.Status)</td></tr>" | Out-File $step6File -Append -Encoding UTF8
}

# ==========================================
# STEP 7 - GPU / Display Adapter Information
# ==========================================
Write-Host "[7/23] Checking display adapter configuration..." -ForegroundColor Yellow
$step7File = Join-Path $TMP_DIR "step7.txt"
Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue | ForEach-Object {
    "<tr><td>$(Escape-Html $_.Name)</td><td>$($_.CurrentHorizontalResolution)x$($_.CurrentVerticalResolution)</td><td>$(Escape-Html $_.DriverVersion)</td></tr>" | Out-File $step7File -Append -Encoding UTF8
}

# ==========================================
# STEP 8 - Scheduled Tasks
# Cheat loaders sometimes install scheduled tasks to auto-start on login
# ==========================================
Write-Host "[8/23] Scanning scheduled tasks for suspicious entries..." -ForegroundColor Yellow
$step8File = Join-Path $TMP_DIR "step8.txt"
Get-ScheduledTask -ErrorAction SilentlyContinue |
Where-Object { $_.State -eq "Ready" -or $_.State -eq "Running" } |
Select-Object -First 50 | ForEach-Object {
    "<tr><td>$(Escape-Html $_.TaskName)</td><td>$(Escape-Html $_.TaskPath)</td><td>$($_.State)</td></tr>" | Out-File $step8File -Append -Encoding UTF8
}

# ==========================================
# STEP 9 - Top Running Processes (by memory usage)
# ==========================================
Write-Host "[9/23] Listing top running processes by memory usage..." -ForegroundColor Yellow
$step9File = Join-Path $TMP_DIR "step9.txt"
Get-Process -ErrorAction SilentlyContinue | Sort-Object -Property WS -Descending | Select-Object -First 30 | ForEach-Object {
    $memMB = [Math]::Round($_.WS / 1MB, 1)
    "<tr><td>$($_.Id)</td><td>$(Escape-Html $_.ProcessName)</td><td>$memMB MB</td></tr>" | Out-File $step9File -Append -Encoding UTF8
}

# ==========================================
# STEP 10 - Hidden Files in System Root
# Files hidden at C:\ root are unusual and worth flagging
# ==========================================
Write-Host "[10/23] Looking for hidden files in the system root (C:\)..." -ForegroundColor Yellow
$step10File = Join-Path $TMP_DIR "step10.txt"
Get-ChildItem -Path "C:\" -Hidden -File -ErrorAction SilentlyContinue | ForEach-Object {
    "<tr><td>$(Escape-Html $_.FullName)</td><td>Hidden file at system root</td></tr>" | Out-File $step10File -Append -Encoding UTF8
}

# ==========================================
# STEP 11 - FULL MEMORY MAP + RWX DETECTION
# ==========================================

Write-Host "[11/23] Full memory map scan (all regions + RWX detection)..." -ForegroundColor Yellow

$step11File = Join-Path $TMP_DIR "step11.txt"
if (-not (Test-Path $step11File)) {
    New-Item -ItemType File -Path $step11File -Force | Out-Null
}

if (-not $RWX_ANOM_COUNT) { $RWX_ANOM_COUNT = 0 }

$MemApiDef = @"
using System;
using System.Runtime.InteropServices;

public class MemoryScanner {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int access, bool inheritHandle, int pid);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    public static extern int VirtualQueryEx(
        IntPtr hProcess,
        IntPtr address,
        out MEMORY_BASIC_INFORMATION mbi,
        int size
    );

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
}
"@

Add-Type -TypeDefinition $MemApiDef -ErrorAction SilentlyContinue

# safer process list
$processes = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Id -gt 4 -and $_.Path
}

foreach ($p in $processes) {
    $hProc = [MemoryScanner]::OpenProcess(0x0418, $false, $p.Id)
    if ($hProc -eq [IntPtr]::Zero) { continue }
    try {
        $address = [IntPtr]::Zero
        $mbi = New-Object MemoryScanner+MEMORY_BASIC_INFORMATION
        $mbiSize = [System.Runtime.InteropServices.Marshal]::SizeOf($mbi)
        while ([MemoryScanner]::VirtualQueryEx($hProc, $address, [ref]$mbi, $mbiSize) -ne 0) {
            $addrHex = "0x" + $mbi.BaseAddress.ToString("X")
            $sizeMB = [math]::Round($mbi.RegionSize.ToUInt64() / 1MB, 2)
            $prot = $mbi.Protect
            $perm =
                switch ($prot) {
                    0x10 { "R" }
                    0x20 { "RX" }
                    0x04 { "RW" }
                    0x40 { "RWX" }
                    default { "OTHER" }
                }
            $procPath = $p.Path
            $signerName = "Unknown"
            try {
                if ($procPath -and (Test-Path $procPath)) {
                    $sig = Get-AuthenticodeSignature -FilePath $procPath -ErrorAction SilentlyContinue
                    if ($sig -and $sig.Status -eq "Valid" -and $sig.SignerCertificate) {
                        $signerName = $sig.SignerCertificate.GetNameInfo("SimpleName", $false)
                    }
                }
            } catch { }
            $isTrusted = $false
            if ($procPath -and $TrustedApps) {
                foreach ($app in $TrustedApps) {
                    foreach ($path in $app.Paths) {
                        if ($procPath -ieq $path) {
                            $isTrusted = $true
                            break
                        }
                    }
                    if ($isTrusted) { break }
                }
            }
            $status = ""
            if ($perm -eq "RWX" -and $mbi.State -eq 0x1000 -and $mbi.Type -eq 0x20000) {
                if (-not $isTrusted) {
                    $status = "<span style='color:#ef4444;font-weight:bold;'>SUSPICIOUS RWX</span>"
                    $RWX_ANOM_COUNT++
                } else {
                    $status = "<span style='color:#f59e0b;font-weight:bold;'>RWX (Trusted Process)</span>"
                }
            }
            else {
                $status = "<span style='color:#9ca3af;'>OK</span>"
            }
            "<tr>
                <td>PID $($p.Id) ($($p.ProcessName))</td>
                <td>$procPath</td>
                <td>$signerName</td>
                <td>$addrHex</td>
                <td>$perm</td>
                <td>$sizeMB MB</td>
                <td>$status</td>
            </tr>" | Out-File $step11File -Append -Encoding UTF8
            try {
                $next = $mbi.BaseAddress.ToInt64() + $mbi.RegionSize.ToUInt64()
                $address = [IntPtr]::new($next)
            }
            catch {
                break
            }
        }
    }
    finally {
        [MemoryScanner]::CloseHandle($hProc) | Out-Null
    }
}

# ==========================================
# STEP 12 - Hidden / Ghost Processes (Cross-view mismatch check)
# Compares WMI process list vs Get-Process snapshot
# ==========================================
Write-Host "[12/23] Checking for hidden processes..." -ForegroundColor Yellow
$step12File = Join-Path $TMP_DIR "step12.txt"
$wmiPIDs = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessId)
$psPIDs  = @(Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
$missingFromPS = Compare-Object -ReferenceObject $wmiPIDs -DifferenceObject $psPIDs -PassThru | Where-Object { $_ }
foreach ($processId in $missingFromPS) {
    if ($processId) {
        "<tr><td>PID $processId</td><td>Cross-view mismatch (WMI vs Get-Process snapshot)</td></tr>" | Out-File $step12File -Append -Encoding UTF8
        $UNLINKED_COUNT++
    }
}

# ==========================================
# STEP 13 - Environment Variable Hooks
# __COMPAT_LAYER and similar env vars can alter how executables are loaded
# ==========================================
Write-Host "[13/23] Checking for suspicious environment variable overrides..." -ForegroundColor Yellow
$step13File = Join-Path $TMP_DIR "step13.txt"
if ($env:__COMPAT_LAYER) {
    "<tr><td>__COMPAT_LAYER (global hook)</td><td>$(Escape-Html $env:__COMPAT_LAYER)</td></tr>" | Out-File $step13File -Append -Encoding UTF8
}
if ($env:COR_ENABLE_PROFILING -eq "1") {
    "<tr><td>COR_ENABLE_PROFILING (CLR profiler active)</td><td>CLSID: $(Escape-Html $env:COR_PROFILER)</td></tr>" | Out-File $step13File -Append -Encoding UTF8
}

# ==========================================
# STEP 14 - Virtual Input Device Drivers
# vJoy, Interception, reWASD, Cronus = hardware spoofing for cheats
# ==========================================
Write-Host "[14/23] Checking for virtual/spoofed input device drivers..." -ForegroundColor Yellow
$step14File = Join-Path $TMP_DIR "step14.txt"
$targetInputDevices = "vjoy|interception|rewasd|titanone|cronus|vgamepad|xoutput|hidguardian"
Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
Where-Object { $_.DeviceName -match $targetInputDevices -or $_.Manufacturer -match $targetInputDevices } |
ForEach-Object {
    "<tr><td>$(Escape-Html $_.DeviceName)</td><td>$(Escape-Html $_.Manufacturer)</td><td>$(Escape-Html $_.InfName)</td></tr>" |
        Out-File $step14File -Append -Encoding UTF8
    $INPUT_SPOOFS++
}

# ==========================================
# STEP 15 - Cheat Overlay / HUD Processes
# Cheat overlays (ESP boxes, aimbot HUD) often run as visible window processes
# ==========================================
Write-Host "[15/23] Scanning for cheat overlay or HUD processes..." -ForegroundColor Yellow
$step15File = Join-Path $TMP_DIR "step15.txt"
Get-Process -ErrorAction SilentlyContinue |
Where-Object { $_.MainWindowTitle -match "overlay|hud|canvas|cheat|menu|hack|esp|aimbot" -and
               $_.ProcessName -notmatch "steam|discord|obs|nvidia|amd|geforce" } |
ForEach-Object {
    "<tr><td>PID $($_.Id)</td><td>$(Escape-Html $_.ProcessName)</td><td>$(Escape-Html $_.MainWindowTitle)</td></tr>" |
        Out-File $step15File -Append -Encoding UTF8
    $OVERLAYS_COUNT++
}

# ==========================================
# STEP 16 - Core System File Integrity (SHA256)
# Verifies key Windows system files haven't been tampered with
# ==========================================
Write-Host "[16/23] Computing SHA256 hashes of critical Windows system files..." -ForegroundColor Yellow
$step16File = Join-Path $TMP_DIR "step16.txt"
$coreBinaries = @(
    "$env:windir\System32\ntoskrnl.exe",
    "$env:windir\System32\drivers\etc\hosts",
    "$env:windir\System32\winlogon.exe",
    "$env:windir\System32\lsass.exe"
)
foreach ($bin in $coreBinaries) {
    if (Test-Path $bin) {
        $hash = (Get-FileHash -Path $bin -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        "<tr><td>$(Escape-Html $bin)</td><td style='font-family:monospace;font-size:11px'>$hash</td><td>Computed OK</td></tr>" |
            Out-File $step16File -Append -Encoding UTF8
    }
}

# ==========================================
# STEP 17 - Test-Signing / Kernel Code Integrity (KEY CHECK)
# testsigning ON = Windows loads unsigned kernel drivers
# ==========================================
Write-Host "[17/23] Checking Windows kernel code integrity / test-signing mode..." -ForegroundColor Yellow
$step17File = Join-Path $TMP_DIR "step17.txt"

$bcEdit = (bcdedit /enum "{current}" 2>$null) | Out-String
if ($bcEdit -match "testsigning\s+[Yy]es" -or $bcEdit -match "nointegritychecks\s+[Yy]es") {
    $TEST_SIGN_STATUS = 1
    "<tr><td>Kernel Code Integrity</td><td><strong style='color:#f87171'>TEST-SIGNING or NOINTEGRITYCHECKS is ON - Windows will load unsigned kernel drivers. This is required by most cheat driver loaders.</strong></td></tr>" |
        Out-File $step17File -Append -Encoding UTF8
} else {
    "<tr><td>Kernel Code Integrity</td><td><span style='color:#10b981'>Enforced - Windows only loads digitally signed kernel drivers (normal/safe state)</span></td></tr>" |
        Out-File $step17File -Append -Encoding UTF8
}

# ==========================================
# STEP 18 - Unsigned Kernel Drivers (KEY CHECK)
# ==========================================
Write-Host "[18/23] Scanning for unsigned kernel drivers..." -ForegroundColor Yellow
$step18File = Join-Path $TMP_DIR "step18.txt"
Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
Where-Object { $_.IsSigned -eq $false -and $null -ne $_.DeviceName } |
ForEach-Object {
    "<tr><td>$(Escape-Html $_.DeviceName)</td><td>$(Escape-Html $_.InfName)</td><td>Not signed</td></tr>" |
        Out-File $step18File -Append -Encoding UTF8
    $DRV_OVERRIDES++
}

# ==========================================
# STEP 19 - Image File Execution Options (IFEO) Debugger Hooks
# ==========================================
Write-Host "[19/23] Checking IFEO (Image File Execution Options) for process hijacks..." -ForegroundColor Yellow
$step19File = Join-Path $TMP_DIR "step19.txt"
$ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
if (Test-Path $ifeoPath) {
    Get-ChildItem -Path $ifeoPath -ErrorAction SilentlyContinue | ForEach-Object {
        $item = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
        $dbg = $item.Debugger
        if ($dbg) {
            "<tr><td>$(Escape-Html $_.PSChildName)</td><td>Redirected to: $(Escape-Html $dbg)</td></tr>" |
                Out-File $step19File -Append -Encoding UTF8
        }
    }
}

# ==========================================
# STEP 20 - Suspicious Named Pipes
# ==========================================
Write-Host "[20/23] Scanning named pipes for cheat-related communication channels..." -ForegroundColor Yellow
$step20File = Join-Path $TMP_DIR "step20.txt"
try {
    [System.IO.Directory]::GetFiles("\\.\pipe\") |
    Where-Object { $_ -match "cheat|hack|inject|menu|hook|aimbot|esp" } |
    ForEach-Object {
        "<tr><td>Suspicious named pipe</td><td>$(Escape-Html $_)</td></tr>" |
            Out-File $step20File -Append -Encoding UTF8
        $PIPE_COUNT++
    }
} catch { }

# ==========================================
# STEP 21 - Firewall Rules & Network Routes
# ==========================================
Write-Host "[21/23] Checking firewall rules and network routes..." -ForegroundColor Yellow
$step21File = Join-Path $TMP_DIR "step21.txt"
Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Select-Object -First 15 | ForEach-Object {
    "<tr><td>Firewall Rule</td><td>$(Escape-Html $_.DisplayName)</td><td>$($_.Action)</td></tr>" |
        Out-File $step21File -Append -Encoding UTF8
}
Get-NetRoute -ErrorAction SilentlyContinue | Select-Object -First 15 | ForEach-Object {
    "<tr><td>Network Route</td><td>$($_.DestinationPrefix)</td><td>Next Hop: $($_.NextHop)</td></tr>" |
        Out-File $step21File -Append -Encoding UTF8
}

# ==========================================
# STEP 22 - Macro / Input Automation Tools (KEY CHECK)
# ==========================================
Write-Host "[22/23] Checking for running macro and input automation tools..." -ForegroundColor Yellow
$step22File = Join-Path $TMP_DIR "step22.txt"
$macroPatterns = "autohotkey|ahk|macro|recomp|autoclicker|mousemanager|keystroke|inputbot|rapidfire"
Get-Process -ErrorAction SilentlyContinue |
Where-Object { $_.ProcessName -match $macroPatterns } |
ForEach-Object {
    "<tr><td>PID $($_.Id)</td><td>$(Escape-Html $_.ProcessName)</td><td>Input automation tool detected</td></tr>" |
        Out-File $step22File -Append -Encoding UTF8
    $SYNTH_COUNT++
}

# ==========================================
# STEP 23 - AMSI Provider Validation
# ==========================================
Write-Host "[23/23] Checking Windows AMSI provider registrations..." -ForegroundColor Yellow
$step23File = Join-Path $TMP_DIR "step23.txt"
$amsiProviders = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"
if (Test-Path $amsiProviders) {
    Get-ChildItem -Path $amsiProviders -ErrorAction SilentlyContinue | ForEach-Object {
        $guid = $_.PSChildName
        $name = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\$guid" -ErrorAction SilentlyContinue).'(default)'
        "<tr><td>$(Escape-Html $(if ($name) { $name } else { 'Unknown' }))</td><td>GUID: $guid</td></tr>" |
            Out-File $step23File -Append -Encoding UTF8
    }
}

# ==========================================
# ADDENDUM - DNS Cache & hosts file
# ==========================================
Write-Host "[+] Checking DNS cache..." -ForegroundColor Cyan
$dnsFile = Join-Path $TMP_DIR "dns_cache.txt"

Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 40 | ForEach-Object {
    "<tr><td>DNS Cache</td><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.Data)</td></tr>" |
        Out-File $dnsFile -Append -Encoding UTF8
}
$hostsPath = "C:\Windows\System32\drivers\etc\hosts"
if (Test-Path $hostsPath) {
    Get-Content $hostsPath | Where-Object { $_ -notmatch "^\s*#" -and $_ -match "\S" } | ForEach-Object {
        "<tr><td>hosts file entry</td><td>$(Escape-Html $_)</td><td></td></tr>" |
            Out-File $dnsFile -Append -Encoding UTF8
    }
}

# ==========================================
# SYSTEM INFORMATION COLLECTION
# ==========================================
Write-Host "[*] Collecting system hardware and OS information..." -ForegroundColor Cyan

$HOST_NODE    = $env:COMPUTERNAME
$CURRENT_USER = [Environment]::UserName
$TIMESTAMP    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

$osInfo       = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$OS_NAME      = $osInfo.Caption
$OS_BUILD     = "Build $($osInfo.BuildNumber)"
$OS_ARCH      = $osInfo.OSArchitecture
$UPTIME_VAL   = (New-TimeSpan -Start $osInfo.LastBootUpTime -End (Get-Date)).ToString("%d' days 'h' hr 'm' min'")
$LAST_BOOT    = $osInfo.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
$RAM_TOTAL    = "$([Math]::Round($osInfo.TotalVisibleMemorySize / 1MB, 2)) GB"
$RAM_AVAIL    = "$([Math]::Round($osInfo.FreePhysicalMemory / 1MB, 2)) GB"
$RAM_USED     = "$([Math]::Round(($osInfo.TotalVisibleMemorySize - $osInfo.FreePhysicalMemory) / 1MB, 2)) GB"

$cpuInfo      = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue
$CPU_MODEL    = $cpuInfo.Name
$CPU_CORES    = "$($cpuInfo.NumberOfCores) physical / $($cpuInfo.NumberOfLogicalProcessors) logical"

$gpuInfo      = Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue
$GPU_NAME     = ($gpuInfo | Select-Object -ExpandProperty Name) -join ", "
$GPU_DRIVER   = ($gpuInfo | Select-Object -First 1 -ExpandProperty DriverVersion)

$diskInfo     = Get-PSDrive C -ErrorAction SilentlyContinue
$DISK_FREE    = "$([Math]::Round($diskInfo.Free / 1GB, 1)) GB free"
$DISK_USED    = "$([Math]::Round($diskInfo.Used / 1GB, 1)) GB used"

$SECURE_BOOT  = try { Confirm-SecureBootUEFI -ErrorAction SilentlyContinue } catch { "Cannot determine" }
if ($SECURE_BOOT -eq $true)  { $SECURE_BOOT = "Enabled" }
if ($SECURE_BOOT -eq $false) { $SECURE_BOOT = "Disabled" }

# ==========================================
# BUILD SUMMARY VERDICT
# ==========================================
$CRITICAL_SUMMARY = ""
$CRITICAL_ALERTS  = 0
$WARN_ALERTS      = 0

if ($RWX_ANOM_COUNT -gt 0) {
    $CRITICAL_SUMMARY += "<li class='finding-critical'><span class='finding-icon'>[CRITICAL]</span><strong>CRITICAL - Code Injection Detected:</strong> Found $RWX_ANOM_COUNT untrusted process(es) running with anonymous read-write-execute (RWX) private memory regions. This indicates manual map injection where malicious code is executing directly from volatile memory allocations without filesystem footprints.</li>"
    $CRITICAL_ALERTS++
}
if ($UNLINKED_COUNT -gt 0) {
    $CRITICAL_SUMMARY += "<li class='finding-critical'><span class='finding-icon'>[CRITICAL]</span><strong>CRITICAL - Hidden Processes (DKOM):</strong> Found $UNLINKED_COUNT process(es) visible in WMI but hidden from the standard process list. This is a rootkit technique (Direct Kernel Object Manipulation) used to conceal cheat processes from anti-cheat software.</li>"
    $CRITICAL_ALERTS++
}
if ($TEST_SIGN_STATUS -ne 0) {
    $CRITICAL_SUMMARY += "<li class='finding-critical'><span class='finding-icon'>[CRITICAL]</span><strong>CRITICAL - Test-Signing Mode Active:</strong> Windows is configured to load unsigned kernel drivers. This is required by nearly all cheat driver loaders (kdmapper, capcom exploit, etc.) and has no legitimate gaming reason to be enabled.</li>"
    $CRITICAL_ALERTS++
}
if ($DRV_OVERRIDES -gt 0) {
    $CRITICAL_SUMMARY += "<li class='finding-high'><span class='finding-icon'>[HIGH]</span><strong>HIGH - Unsigned Drivers Loaded:</strong> Found $DRV_OVERRIDES unsigned kernel driver(s). Cheat drivers are almost always unsigned because they would be blocked by Microsoft's signing requirements.</li>"
    $WARN_ALERTS++
}
if ($INPUT_SPOOFS -gt 0) {
    $CRITICAL_SUMMARY += "<li class='finding-high'><span class='finding-icon'>[HIGH]</span><strong>HIGH - Virtual Input Device Driver:</strong> Found $INPUT_SPOOFS known input-spoofing driver(s) (vJoy, Interception, Cronus, reWASD, etc.). These are used to spoof hardware identifiers or inject fake mouse/keyboard input.</li>"
    $WARN_ALERTS++
}
if ($SYNTH_COUNT -gt 0) {
    $CRITICAL_SUMMARY += "<li class='finding-warn'><span class='finding-icon'>[WARN]</span><strong>WARNING - Macro/Automation Tool Running:</strong> Found $SYNTH_COUNT macro tool(s) active (e.g., AutoHotKey). These can simulate mouse clicks and movement for triggerbot or recoil control scripts.</li>"
    $WARN_ALERTS++
}
if ($PIPE_COUNT -gt 0) {
    $CRITICAL_SUMMARY += "<li class='finding-warn'><span class='finding-icon'>[WARN]</span><strong>WARNING - Suspicious Named Pipes:</strong> Found $PIPE_COUNT named pipe(s) with cheat-related names. Cheat modules use named pipes to communicate internally without network traffic.</li>"
    $WARN_ALERTS++
}
if ($ENV_INJECT_COUNT -gt 0) {
    $CRITICAL_SUMMARY += "<li class='finding-info'><span class='finding-icon'>[INFO]</span><strong>NOTICE - Suspicious Shell History:</strong> Found $ENV_INJECT_COUNT command(s) in PowerShell history matching cheat/injection keywords. This indicates prior cheat tool usage on this machine.</li>"
}

$OVERALL_VERDICT = ""
$VERDICT_CLASS   = ""
if ($CRITICAL_ALERTS -gt 0) {
    $OVERALL_VERDICT = "&#x26D4; SUSPICIOUS - $CRITICAL_ALERTS critical indicator(s) found. Manual review strongly recommended."
    $VERDICT_CLASS   = "verdict-critical"
} elseif ($WARN_ALERTS -gt 0) {
    $OVERALL_VERDICT = "&#x26A0;&#xFE0F; CAUTION - No critical indicators, but $WARN_ALERTS warning(s) require review."
    $VERDICT_CLASS   = "verdict-warn"
} else {
    $OVERALL_VERDICT = "&#x2705; CLEAN - No cheat indicators detected across all 23 checks."
    $VERDICT_CLASS   = "verdict-clean"
    $CRITICAL_SUMMARY = "<li class='finding-clean'><span class='finding-icon'>[OK]</span><strong>System appears clean.</strong> No RWX memory injections, hidden processes, test-signing, unsigned drivers, or active macro tools found. All critical checks passed.</li>"
}

# ==========================================
# GENERATE HTML REPORT
# ==========================================
Write-Host "[*] Writing HTML report..." -ForegroundColor Cyan

$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Anti-Cheat Forensic Report - $HOST_NODE</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #e2e8f0; font-size: 13px; line-height: 1.6; }

header { background: #161b22; border-bottom: 3px solid #ef4444; padding: 20px 32px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }
.logo { font-size: 18px; font-weight: 700; color: #ef4444; }
.logo small { font-size: 11px; color: #8b949e; font-weight: 400; display: block; margin-top: 2px; }
.scan-meta { font-size: 11px; color: #8b949e; text-align: right; }
.scan-meta span { color: #e2e8f0; font-weight: 600; }

nav { background: #161b22; border-bottom: 1px solid #21262d; padding: 0 32px; display: flex; gap: 0; flex-wrap: wrap; }
nav a { color: #8b949e; text-decoration: none; font-size: 11px; padding: 10px 12px; display: inline-block; border-bottom: 2px solid transparent; transition: all 0.15s; }
nav a:hover { color: #ef4444; border-bottom-color: #ef4444; }

.container { max-width: 1400px; margin: 0 auto; padding: 28px 32px; }

.verdict-box { border-radius: 10px; padding: 18px 24px; margin-bottom: 24px; }
.verdict-critical { background: #1a0000; border: 2px solid #ef4444; }
.verdict-warn     { background: #1a0f00; border: 2px solid #f59e0b; }
.verdict-clean    { background: #001a0a; border: 2px solid #10b981; }
.verdict-title { font-size: 16px; font-weight: 700; margin-bottom: 14px; }
.verdict-critical .verdict-title { color: #ef4444; }
.verdict-warn     .verdict-title { color: #f59e0b; }
.verdict-clean    .verdict-title { color: #10b981; }
.findings-list { list-style: none; display: flex; flex-direction: column; gap: 8px; }
.findings-list li { padding: 10px 14px; border-radius: 7px; font-size: 12.5px; line-height: 1.5; display: flex; gap: 10px; align-items: flex-start; }
.finding-icon { font-size: 14px; flex-shrink: 0; margin-top: 1px; }
.finding-critical { background: #2d0000; border-left: 3px solid #ef4444; color: #fca5a5; }
.finding-high     { background: #2d1500; border-left: 3px solid #f97316; color: #fdba74; }
.finding-warn     { background: #2d2200; border-left: 3px solid #f59e0b; color: #fcd34d; }
.finding-info     { background: #001a2d; border-left: 3px solid #3b82f6; color: #93c5fd; }
.finding-clean    { background: #002d16; border-left: 3px solid #10b981; color: #6ee7b7; }

.dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 28px; }
.stat-card { background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 16px 12px; text-align: center; transition: border-color 0.15s; }
.stat-card:hover { border-color: #373e47; }
.stat-card .num { font-size: 28px; font-weight: 700; color: #10b981; line-height: 1; }
.stat-card .num.danger { color: #ef4444; }
.stat-card .num.warn   { color: #f59e0b; }
.stat-card .label { font-size: 10px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.6px; margin-top: 6px; }
.stat-card .sub { font-size: 9px; color: #4b5563; margin-top: 3px; }

.hw-section { margin-bottom: 28px; }
.hw-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; }
.hw-card { background: #161b22; border: 1px solid #21262d; border-radius: 10px; overflow: hidden; }
.hw-card-title { background: #0d1117; padding: 9px 14px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; color: #60a5fa; border-bottom: 1px solid #21262d; }
.hw-card table { width: 100%; border-collapse: collapse; }
.hw-card td { padding: 8px 14px; border-bottom: 1px solid #0d1117; font-size: 12px; }
.hw-card td:first-child { color: #8b949e; width: 45%; white-space: nowrap; }
.hw-card td:last-child  { color: #e2e8f0; word-break: break-word; }

.section { margin-bottom: 24px; scroll-margin-top: 20px; }
.section-header { display: flex; align-items: flex-start; gap: 10px; margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid #21262d; flex-wrap: wrap; }
.section-title-group { flex: 1; }
.section-header h2 { font-size: 14px; font-weight: 600; color: #e2e2e2; }
.section-header .explain { font-size: 11px; color: #6b7280; margin-top: 2px; font-style: italic; }
.badge { font-size: 10px; padding: 3px 9px; border-radius: 20px; font-weight: 700; white-space: nowrap; }
.b-red    { background: #3d0000; color: #f87171; border: 1px solid #7f1d1d; }
.b-orange { background: #431407; color: #fb923c; border: 1px solid #7c2d12; }
.b-yellow { background: #2d1a00; color: #fbbf24; border: 1px solid #78350f; }
.b-blue   { background: #0c1a3a; color: #60a5fa; border: 1px solid #1e3a8a; }
.b-green  { background: #052e16; color: #34d399; border: 1px solid #065f46; }
.b-gray   { background: #1e293b; color: #94a3b8; border: 1px solid #334155; }

.table-wrap { overflow-x: auto; border-radius: 8px; border: 1px solid #21262d; max-height: 380px; overflow-y: auto; }
table.data-table { width: 100%; border-collapse: collapse; }
table.data-table thead { background: #0d1117; position: sticky; top: 0; z-index: 1; }
table.data-table th { padding: 9px 12px; text-align: left; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: #8b949e; font-weight: 700; border-bottom: 1px solid #21262d; white-space: nowrap; }
table.data-table td { padding: 8px 12px; border-bottom: 1px solid #161b22; color: #c9d1d9; word-break: break-word; font-size: 12px; }
table.data-table td span { white-space: nowrap; display: inline-block; }
table.data-table tr:hover td { background: #161b22; }

.empty-ok  { color: #10b981; font-size: 12px; padding: 12px 16px; background: #052e16; border-radius: 8px; border: 1px solid #166534; }
.empty-ok::before { content: "[OK]"; font-weight: 700; }

footer { text-align: center; padding: 24px; color: #374151; font-size: 11px; border-top: 1px solid #21262d; margin-top: 32px; }
footer strong { color: #4b5563; }
</style>
</head>
<body>

<header>
  <div>
    <div class="logo">Forensic Scanner - Windows
      <small>23-step system audit for in-game cheat detection</small>
    </div>
  </div>
  <div class="scan-meta">
    Host: <span>$HOST_NODE</span><br>
    User: <span>$CURRENT_USER</span><br>
    Scanned: <span>$TIMESTAMP</span>
  </div>
</header>

<nav>
  <a href="#verdict">Verdict</a>
  <a href="#dashboard">Dashboard</a>
  <a href="#sysinfo">System Info</a>
  <a href="#memanom">[!] Memory Injection</a>
  <a href="#memunlink">[!] Hidden Processes</a>
  <a href="#taint">[!] Test-Signing</a>
  <a href="#drvunsigned">Unsigned Drivers</a>
  <a href="#inputvirtual">Virtual Inputs</a>
  <a href="#synth">Macro Tools</a>
  <a href="#pipes">Named Pipes</a>
  <a href="#ifeo">IFEO Hooks</a>
  <a href="#history">Shell History</a>
  <a href="#dns">DNS / Hosts</a>
  <a href="#services">Services</a>
  <a href="#amsi">AMSI</a>
</nav>

<div class="container">

<div id="verdict" class="verdict-box $VERDICT_CLASS">
  <div class="verdict-title">Scan Verdict: $OVERALL_VERDICT</div>
  <ul class="findings-list">
    $CRITICAL_SUMMARY
  </ul>
</div>

<div class="dashboard" id="dashboard">
  <div class="stat-card">
    <div class="num $(if ($RWX_ANOM_COUNT -gt 0) { 'danger' })">$RWX_ANOM_COUNT</div>
    <div class="label">Memory Injections</div>
    <div class="sub">Anonymous RWX regions</div>
  </div>
  <div class="stat-card">
    <div class="num $(if ($UNLINKED_COUNT -gt 0) { 'danger' })">$UNLINKED_COUNT</div>
    <div class="label">Hidden Processes</div>
    <div class="sub">WMI vs GetProcess mismatch</div>
  </div>
  <div class="stat-card">
    <div class="num $(if ($TEST_SIGN_STATUS -ne 0) { 'danger' })">$TEST_SIGN_STATUS</div>
    <div class="label">Test-Signing</div>
    <div class="sub">0 = safe, 1 = risky</div>
  </div>
  <div class="stat-card">
    <div class="num $(if ($DRV_OVERRIDES -gt 0) { 'warn' })">$DRV_OVERRIDES</div>
    <div class="label">Unsigned Drivers</div>
    <div class="sub">Kernel-level risk</div>
  </div>
  <div class="stat-card">
    <div class="num $(if ($INPUT_SPOOFS -gt 0) { 'warn' })">$INPUT_SPOOFS</div>
    <div class="label">Virtual Inputs</div>
    <div class="sub">Hardware spoofing</div>
  </div>
  <div class="stat-card">
    <div class="num $(if ($SYNTH_COUNT -gt 0) { 'warn' })">$SYNTH_COUNT</div>
    <div class="label">Macro Tools</div>
    <div class="sub">Input automation</div>
  </div>
  <div class="stat-card">
    <div class="num">$OVERLAYS_COUNT</div>
    <div class="label">HUD/Overlays</div>
    <div class="sub">Suspicious windows</div>
  </div>
  <div class="stat-card">
    <div class="num $(if ($PIPE_COUNT -gt 0) { 'warn' })">$PIPE_COUNT</div>
    <div class="label">Suspicious Pipes</div>
    <div class="sub">Cheat IPC channels</div>
  </div>
  <div class="stat-card">
    <div class="num">$ENV_INJECT_COUNT</div>
    <div class="label">History Hits</div>
    <div class="sub">Shell command matches</div>
  </div>
</div>

<div class="section hw-section" id="sysinfo">
  <div class="section-header">
    <div class="section-title-group">
      <h2>System & Hardware Information</h2>
      <div class="explain">Full hardware and OS profile of the scanned machine</div>
    </div>
    <span class="badge b-gray">System Profile</span>
  </div>
  <div class="hw-grid">
    <div class="hw-card">
      <div class="hw-card-title">Operating System</div>
      <table>
        <tr><td>OS</td><td>$OS_NAME</td></tr>
        <tr><td>Build</td><td>$OS_BUILD ($OS_ARCH)</td></tr>
        <tr><td>Hostname</td><td>$HOST_NODE</td></tr>
        <tr><td>Current User</td><td>$CURRENT_USER</td></tr>
        <tr><td>System Uptime</td><td>$UPTIME_VAL</td></tr>
        <tr><td>Last Boot</td><td>$LAST_BOOT</td></tr>
        <tr><td>Secure Boot</td><td>$SECURE_BOOT</td></tr>
      </table>
    </div>
    <div class="hw-card">
      <div class="hw-card-title">⚙️ Hardware</div>
      <table>
        <tr><td>CPU</td><td>$CPU_MODEL</td></tr>
        <tr><td>CPU Cores</td><td>$CPU_CORES</td></tr>
        <tr><td>RAM Total</td><td>$RAM_TOTAL</td></tr>
        <tr><td>RAM Used</td><td>$RAM_USED</td></tr>
        <tr><td>RAM Available</td><td>$RAM_AVAIL</td></tr>
        <tr><td>Disk C: (free)</td><td>$DISK_FREE / used $DISK_USED</td></tr>
        <tr><td>GPU</td><td>$(Escape-Html $GPU_NAME)</td></tr>
        <tr><td>GPU Driver</td><td>$GPU_DRIVER</td></tr>
      </table>
    </div>
  </div>
</div>
"@

$htmlContent | Out-File $OUTPUT_FILE -Encoding UTF8

# ── STEP 11: Memory Injection ──
@"
<div class="section" id="memanom">
  <div class="section-header">
    <div class="section-title-group">
      <h2>[CRITICAL] Anonymous RWX Memory - Code Injection Check</h2>
      <div class="explain">Private memory that is readable, writable, AND executable with no file backing on disk. This is the #1 sign of manual map injection. Results are explicitly matched against paths and digital certificates to flag unverified software.</div>
    </div>
    <span class="badge b-red">CRITICAL</span>
  </div>
"@ | Out-File $OUTPUT_FILE -Append -Encoding UTF8

$d = Get-FileContent $step11File
if ($d) {
    "<div class='table-wrap'><table class='data-table'><thead><tr><th>Process (PID + Name)</th><th>Executable Path</th><th>Digital Signer</th><th>Memory Address</th><th>Status</th></tr></thead><tbody>$d</tbody></table></div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8
} else {
    "<p class='empty-ok'>No anonymous RWX memory regions found in any running process.</p>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8
}
"</div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8

# ── STEP 12: Hidden Processes ──
@"
<div class="section" id="memunlink">
  <div class="section-header">
    <div class="section-title-group">
      <h2>[CRITICAL] Hidden Processes - Rootkit Detection (DKOM)</h2>
      <div class="explain">Compares the WMI process list against PowerShell's Get-Process. Any PID that appears in WMI but is hidden from Get-Process has been concealed by a rootkit technique called Direct Kernel Object Manipulation - used by cheat drivers to hide themselves.</div>
    </div>
    <span class="badge b-red">CRITICAL</span>
  </div>
"@ | Out-File $OUTPUT_FILE -Append -Encoding UTF8

$d = Get-FileContent $step12File
if ($d) {
    "<div class='table-wrap'><table class='data-table'><thead><tr><th>PID</th><th>Status</th></tr></thead><tbody>$d</tbody></table></div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8
} else {
    "<p class='empty-ok'>No hidden processes detected - WMI and process list match completely.</p>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8
}
"</div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8

# ── STEP 17: Test-Signing ──
@"
<div class="section" id="taint">
  <div class="section-header">
    <div class="section-title-group">
      <h2>[CRITICAL] Kernel Code Integrity - Test-Signing Mode</h2>
      <div class="explain">Test-signing allows Windows to load kernel drivers that are NOT signed by Microsoft. This is required by virtually all cheat driver loaders (kdmapper, capcom exploit, etc.). There is no legitimate gaming reason to have this enabled.</div>
    </div>
    <span class="badge b-red">CRITICAL</span>
  </div>
  <div class='table-wrap'><table class='data-table'><thead><tr><th>Setting</th><th>Status</th></tr></thead><tbody>
"@ | Out-File $OUTPUT_FILE -Append -Encoding UTF8
Get-FileContent $step17File | Out-File $OUTPUT_FILE -Append -Encoding UTF8
"</tbody></table></div></div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8

# ── STEP 18: Unsigned Drivers ──
@"
<div class="section" id="drvunsigned">
  <div class="section-header">
    <div class="section-title-group">
      <h2>[HIGH] Unsigned Kernel Drivers</h2>
      <div class="explain">Drivers that are not digitally signed by Microsoft. Cheat drivers are almost always unsigned because they can't pass Microsoft's signing requirements. Any unknown unsigned driver here warrants investigation.</div>
    </div>
    <span class="badge b-orange">HIGH</span>
  </div>
"@ | Out-File $OUTPUT_FILE -Append -Encoding UTF8

$d = Get-FileContent $step18File
if ($d) {
    "<div class='table-wrap'><table class='data-table'><thead><tr><th>Driver Name</th><th>INF File</th><th>Signature Status</th></tr></thead><tbody>$d</tbody></table></div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8
} else {
    "<p class='empty-ok'>No unsigned kernel drivers found - all loaded drivers are properly signed.</p>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8
}
"</div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8

# ── STEP 14: Virtual Input Devices ──
@"
<div class="section" id="inputvirtual">
  <div class="section-header">
    <div class="section-title-group">
      <h2>[HIGH] Virtual / Spoofed Input Device Drivers</h2>
      <div class="explain">Known input-spoofing drivers: vJoy, Interception, Cronus Zen, reWASD, Titan One. These create virtual gamepads or intercept input at the driver level to simulate hardware actions for cheating - including anti-recoil and aimbot mouse movements.</div>
    </div>
    <span class="badge b-orange">HIGH</span>
  </div>
"@ | Out-File $OUTPUT_FILE -Append -Encoding UTF8

$d = Get-FileContent $step14File
if ($d) {
    "<div class='table-wrap'><table class='data-table'><thead><tr><th>Device Name</th><th>Manufacturer</th><th>INF File</th></tr></thead><tbody>$d</tbody></table></div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8
} else {
    "<p class='empty-ok'>No known virtual input device drivers detected.</p>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8
}
"</div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8

# ── STEP 22: Macro Tools ──
@"
<div class="section" id="synth">
  <div class="section-header">
    <div class="section-title-group">
      <h2>[WARN] Macro / Input Automation Tools</h2>
      <div class="explain">Programs like AutoHotKey simulate mouse clicks and keyboard presses. They are used to build triggerbot scripts, recoil control macros, and rapid-fire automations that go beyond normal controller/keyboard usage.</div>
    </div>
    <span class="badge b-yellow">WARNING</span>
  </div>
"@ | Out-File $OUTPUT_FILE -Append -Encoding UTF8

$d = Get-FileContent $step22File
if ($d) {
    "<div class='table-wrap'><table class='data-table'><thead><tr><th>PID</th><th>Process Name</th><th>Finding</th></tr></thead><tbody>$d</tbody></table></div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8
} else {
    "<p class='empty-ok'>No macro or input automation tools currently running.</p>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8
}
"</div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8

# ── STEP 20: Named Pipes ──
@"
<div class="section" id="pipes">
  <div class="section-header">
    <div class="section-title-group">
      <h2>[WARN] Suspicious Named Pipes</h2>
      <div class="explain">Named pipes are inter-process communication channels. Cheat modules use them to pass configuration and data between components (e.g., the injector talking to the cheat DLL) without generating network traffic.</div>
    </div>
    <span class="badge b-yellow">WARNING</span>
  </div>
"@ | Out-File $OUTPUT_FILE -Append -Encoding UTF8

$d = Get-FileContent $step20File
if ($d) {
    "<div class='table-wrap'><table class='data-table'><thead><tr><th>Type</th><th>Pipe Name</th></tr></thead><tbody>$d</tbody></table></div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8
} else {
    "<p class='empty-ok'>No named pipes with cheat-related names detected.</p>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8
}
"</div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8

# ── STEP 19: IFEO Hooks ──
@"
<div class="section" id="ifeo">
  <div class="section-header">
    <div class="section-title-group">
      <h2>Image File Execution Options (IFEO) - Process Redirect Hooks</h2>
      <div class="explain">IFEO allows any .exe launch to be silently redirected to a different program. Used by some cheats to intercept the game executable startup or by security tools to attach debuggers. Any unexpected entries here are suspicious.</div>
    </div>
    <span class="badge b-orange">HIGH</span>
  </div>
"@ | Out-File $OUTPUT_FILE -Append -Encoding UTF8

$d = Get-FileContent $step19File
if ($d) {
    "<div class='table-wrap'><table class='data-table'><thead><tr><th>Target Executable</th><th>Redirected To</th></tr></thead><tbody>$d</tbody></table></div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8
} else {
    "<p class='empty-ok'>No suspicious IFEO debugger redirections found.</p>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8
}
"</div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8

# ── STEP 1: Shell History ──
@"
<div class="section" id="history">
  <div class="section-header">
    <div class="section-title-group">
      <h2>PowerShell History - Suspicious Keyword Matches</h2>
      <div class="explain">Searches PowerShell command history for keywords associated with cheating tools, memory injection, and debugging game processes (inject, cheatengine, kdmapper, readprocessmemory, etc.).</div>
    </div>
    <span class="badge b-gray">Logs</span>
  </div>
  <div class='table-wrap'><table class='data-table'><thead><tr><th>User / History File</th><th>Matched Command</th></tr></thead><tbody>
"@ | Out-File $OUTPUT_FILE -Append -Encoding UTF8

$d = Get-FileContent $step1File
if ($d) { $d | Out-File $OUTPUT_FILE -Append -Encoding UTF8 }
else { "<tr><td colspan='2' style='color:#10b981'>No suspicious keywords found in any PowerShell history file.</td></tr>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8 }
"</tbody></table></div></div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8

# ── DNS / Hosts ──
@"
<div class="section" id="dns">
  <div class="section-header">
    <div class="section-title-group">
      <h2>DNS Cache & hosts File Entries</h2>
      <div class="explain">Cheats sometimes modify the Windows hosts file (C:\Windows\System32\drivers\etc\hosts) to block anti-cheat update servers or redirect them to localhost. Any unexpected entries blocking game/anti-cheat domains are red flags.</div>
    </div>
    <span class="badge b-blue">Network</span>
  </div>
  <div class='table-wrap'><table class='data-table'><thead><tr><th>Type</th><th>Domain / Name</th><th>Resolved Address</th></tr></thead><tbody>
"@ | Out-File $OUTPUT_FILE -Append -Encoding UTF8

$d = Get-FileContent $dnsFile
if ($d) { $d | Out-File $OUTPUT_FILE -Append -Encoding UTF8 }
else { "<tr><td colspan='3' style='color:#10b981'>No custom hosts entries or DNS cache data available.</td></tr>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8 }
"</tbody></table></div></div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8

# ── Services ──
@"
<div class="section" id="services">
  <div class="section-header">
    <div class="section-title-group">
      <h2>Running Windows Services</h2>
      <div class="explain">All currently active Windows services. Cheat loaders sometimes install themselves as services that auto-start on boot and survive system restarts.</div>
    </div>
    <span class="badge b-gray">Services</span>
  </div>
  <div class='table-wrap'><table class='data-table'><thead><tr><th>Service Name</th><th>Status</th><th>Display Name</th></tr></thead><tbody>
"@ | Out-File $OUTPUT_FILE -Append -Encoding UTF8
Get-FileContent $step4File | Out-File $OUTPUT_FILE -Append -Encoding UTF8
"</tbody></table></div></div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8

# ── STEP 23: AMSI ──
@"
<div class="section" id="amsi">
  <div class="section-header">
    <div class="section-title-group">
      <h2>AMSI Provider Registrations</h2>
      <div class="explain">Windows Antimalware Scan Interface (AMSI) lets security tools scan scripts and memory before execution. Cheats sometimes patch or bypass AMSI to avoid detection. This shows all registered AMSI providers - missing providers could indicate tampering.</div>
    </div>
    <span class="badge b-blue">Security</span>
  </div>
"@ | Out-File $OUTPUT_FILE -Append -Encoding UTF8

$d = Get-FileContent $step23File
if ($d) {
    "<div class='table-wrap'><table class='data-table'><thead><tr><th>Provider Name</th><th>Registration GUID</th></tr></thead><tbody>$d</tbody></table></div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8
} else {
    "<p class='empty-ok'>AMSI provider registrations appear intact.</p>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8
}
"</div>" | Out-File $OUTPUT_FILE -Append -Encoding UTF8

# ── Footer ──
@"
</div><footer>
  <strong>Anti-Cheat Forensic Scanner - Windows Edition</strong><br>
  Report generated on $TIMESTAMP &middot; Host: $HOST_NODE &middot; OS: $OS_NAME<br>
  This report is for forensic analysis purposes. All findings require human review before drawing conclusions.
</footer>

</body>
</html>
"@ | Out-File $OUTPUT_FILE -Append -Encoding UTF8

# Grant the launching user full control over the report file
try {
    $currentUserNT = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl = Get-Acl -Path $OUTPUT_FILE
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUserNT, "FullControl", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl -Path $OUTPUT_FILE -AclObject $acl
} catch {
    Write-Warning "Could not set file permissions: $_"
}

# Clean up temp files
Remove-Item -Recurse -Force $TMP_DIR -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[+] ============================================================" -ForegroundColor Green
Write-Host "[+] Scan complete!" -ForegroundColor Green
Write-Host "[+] Report saved to: $PSScriptRoot\$OUTPUT_FILE" -ForegroundColor Green
Write-Host "[+] Open it in any web browser to view the results." -ForegroundColor Green
Write-Host "[+] ============================================================" -ForegroundColor Green
Write-Host ""
