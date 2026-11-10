<#
=====================================================================
 EASY SECURITY AUDIT  (Windows 10 / 11)
 - Read-only: it only LOOKS at your system, it changes nothing.
 - Run as Administrator for full results.
 - Parameters: -JsonOut <file> -ReportOut <file> -NoOpen  (used by the ValkyrieGuard GUI).
 - Report is saved on your Desktop in plain English.
=====================================================================
#>
param([string]$JsonOut = '', [string]$ReportOut = '', [switch]$NoOpen)


$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

$Stamp      = Get-Date -Format 'yyyy-MM-dd_HH-mm'
$ReportPath = Join-Path ([Environment]::GetFolderPath('Desktop')) "Security_Audit_Report_$Stamp.txt"
if ($ReportOut) { $ReportPath = $ReportOut }
$IsAdmin    = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Findings = New-Object System.Collections.Generic.List[object]
$Body     = New-Object System.Collections.Generic.List[string]
$SigCache = @{}

# ----------------------------------------------------------------- helpers
function Add-Finding {
    param([string]$Level, [string]$Area, [string]$Title, [string]$Detail = '', [string]$Fix = '')
    $Findings.Add([pscustomobject]@{ Level = $Level; Area = $Area; Title = $Title; Detail = $Detail; Fix = $Fix })
}

function Add-Section {
    param([string]$Title, [string]$Explain)
    $Body.Add('')
    $Body.Add('=' * 78)
    $Body.Add($Title)
    $Body.Add('=' * 78)
    if ($Explain) { $Body.Add($Explain); $Body.Add('') }
}

function Add-Table {
    param($Rows)
    if ($Rows) {
        $Body.Add((($Rows | Format-Table -AutoSize -Wrap | Out-String -Width 200).TrimEnd()))
    } else {
        $Body.Add('(nothing found)')
    }
    $Body.Add('')
}

function Test-UserPath([string]$p) {
    return [bool]($p -match '(?i)\\(AppData|Temp|Users\\Public|Downloads)\\')
}

function Get-Sig([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ Status = 'NotFound'; Signer = '' }
    }
    if ($SigCache.ContainsKey($Path)) { return $SigCache[$Path] }
    $s = Get-AuthenticodeSignature -LiteralPath $Path
    $signer = ''
    if ($s.SignerCertificate) { $signer = ($s.SignerCertificate.Subject -replace '^.*?CN=([^,]+).*$', '$1') }
    $r = [pscustomobject]@{ Status = [string]$s.Status; Signer = $signer }
    $SigCache[$Path] = $r
    return $r
}

function Get-ExePath([string]$Cmd) {
    if (-not $Cmd) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Cmd.Trim())
    if ($c -match '^"([^"]+)"') { return $Matches[1] }
    if ($c -match '^(.+?\.(exe|bat|cmd|ps1|vbs|js|scr|com))(\s|$)') { return $Matches[1] }
    return $null
}

$BadPattern = '(?i)(-enc(odedcommand)?\s|frombase64string|downloadstring|invoke-webrequest|\biwr\s|\biex\b|mshta|wscript|cscript|regsvr32|bitsadmin|certutil.*-urlcache)'

function Judge-Command([string]$Cmd) {
    if ($Cmd -match $BadPattern) {
        return @{ Level = 'ALERT'; Reason = 'it uses a command style often seen in malware (hidden code or script downloads)' }
    }
    $exe = Get-ExePath $Cmd
    if ($exe -and [IO.Path]::IsPathRooted($exe)) {
        $sig = Get-Sig $exe
        if ($sig.Status -eq 'NotFound') {
            return @{ Level = 'WARNING'; Reason = 'the program file is missing (leftover or broken entry)' }
        }
        if ((Test-UserPath $exe) -and $sig.Status -ne 'Valid') {
            return @{ Level = 'WARNING'; Reason = 'it runs from a user folder and is NOT digitally signed' }
        }
    }
    return @{ Level = 'OK'; Reason = '' }
}

$PrivateRx = '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1|fe80|0\.0\.0\.0|::$)'

Write-Host ''
Write-Host '  EASY SECURITY AUDIT' -ForegroundColor Cyan
Write-Host '  Read-only scan. Nothing on your PC is changed.' -ForegroundColor DarkGray
Write-Host ''

if (-not $IsAdmin) {
    Add-Finding 'WARNING' 'Audit' 'Script was NOT run as Administrator' 'Some checks (failed logins, BitLocker, some processes) may be incomplete.' 'Close this and restart as Administrator (right-click > Run as administrator, or use the Restart as Administrator button in ValkyrieGuard).'
}

# ============================================================ 1. SYSTEM
Write-Host '[1/7] System information...' -ForegroundColor Yellow
Add-Section 'SECTION 1: ABOUT THIS COMPUTER' 'Basic facts about the PC that was scanned.'

$os   = Get-CimInstance Win32_OperatingSystem
$boot = $os.LastBootUpTime
$days = [math]::Round(((Get-Date) - $boot).TotalDays, 1)
Add-Table @(
    [pscustomobject]@{ Item = 'Computer name';     Value = $env:COMPUTERNAME },
    [pscustomobject]@{ Item = 'Logged in as';      Value = "$env:USERDOMAIN\$env:USERNAME" },
    [pscustomobject]@{ Item = 'Windows version';   Value = "$($os.Caption) (build $($os.BuildNumber))" },
    [pscustomobject]@{ Item = 'Last restart';      Value = "$boot  ($days days ago)" },
    [pscustomobject]@{ Item = 'Scan time';         Value = (Get-Date) },
    [pscustomobject]@{ Item = 'Ran as Admin';      Value = $(if ($IsAdmin) { 'Yes' } else { 'No' }) }
)
if ($days -gt 30) {
    Add-Finding 'INFO' 'System' "PC has not been restarted for $days days" 'Many security updates only finish installing after a restart.' 'Restart the computer.'
}

# ======================================================= 2. PROTECTIONS
Write-Host '[2/7] Checking security protections...' -ForegroundColor Yellow
Add-Section 'SECTION 2: SECURITY PROTECTIONS' 'These are the main shields Windows has. Each one should be ON.'

$prot = New-Object System.Collections.Generic.List[object]

# Antivirus
$mp = Get-MpComputerStatus
if ($mp) {
    if ($mp.RealTimeProtectionEnabled) {
        $prot.Add([pscustomobject]@{ Check = 'Antivirus live protection'; Result = 'ON' })
        Add-Finding 'OK' 'Protection' 'Windows Defender live protection is ON'
    } else {
        $prot.Add([pscustomobject]@{ Check = 'Antivirus live protection'; Result = 'OFF  <-- problem' })
        Add-Finding 'ALERT' 'Protection' 'Antivirus live protection is OFF' 'Nothing is watching files in real time. Malware can run freely.' 'Open Windows Security > Virus & threat protection > turn on Real-time protection.'
    }
    $age = $mp.AntivirusSignatureAge
    $prot.Add([pscustomobject]@{ Check = 'Antivirus definitions age'; Result = "$age day(s) old" })
    if ($age -gt 7) {
        Add-Finding 'WARNING' 'Protection' "Antivirus definitions are $age days old" 'Old definitions cannot recognise new malware.' 'Windows Security > Virus & threat protection > Check for updates.'
    } else {
        Add-Finding 'OK' 'Protection' 'Antivirus definitions are up to date'
    }
} else {
    $prot.Add([pscustomobject]@{ Check = 'Windows Defender'; Result = 'Could not read (another antivirus may be installed)' })
    Add-Finding 'INFO' 'Protection' 'Could not read Windows Defender status' 'A third-party antivirus may be in use.' 'Make sure some antivirus is active and up to date.'
}

# Firewall
$fw = Get-NetFirewallProfile
foreach ($p in $fw) {
    $state = if ($p.Enabled) { 'ON' } else { 'OFF  <-- problem' }
    $prot.Add([pscustomobject]@{ Check = "Firewall ($($p.Name) network)"; Result = $state })
    if (-not $p.Enabled) {
        Add-Finding 'ALERT' 'Protection' "Firewall is OFF for $($p.Name) networks" 'Anyone on that network can try to connect to your PC freely.' 'Windows Security > Firewall & network protection > turn it on.'
    }
}
if ($fw -and -not ($fw | Where-Object { -not $_.Enabled })) {
    Add-Finding 'OK' 'Protection' 'Windows Firewall is ON for all network types'
}

# UAC
$uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
if ($uac -eq 1) {
    $prot.Add([pscustomobject]@{ Check = 'UAC (admin permission pop-ups)'; Result = 'ON' })
    Add-Finding 'OK' 'Protection' 'UAC (permission pop-ups) is ON'
} else {
    $prot.Add([pscustomobject]@{ Check = 'UAC (admin permission pop-ups)'; Result = 'OFF  <-- problem' })
    Add-Finding 'ALERT' 'Protection' 'UAC is OFF' 'Programs can get admin power silently, without asking you.' 'Search "Change User Account Control settings" and move the slider up.'
}

# Secure Boot
$sb = $null
try { $sb = Confirm-SecureBootUEFI } catch { }
if ($sb -eq $true) {
    $prot.Add([pscustomobject]@{ Check = 'Secure Boot'; Result = 'ON' })
    Add-Finding 'OK' 'Protection' 'Secure Boot is ON'
} elseif ($sb -eq $false) {
    $prot.Add([pscustomobject]@{ Check = 'Secure Boot'; Result = 'OFF' })
    Add-Finding 'WARNING' 'Protection' 'Secure Boot is OFF' 'It blocks malware that tries to load before Windows starts.' 'Turn it on in BIOS/UEFI settings (only if your setup allows it).'
} else {
    $prot.Add([pscustomobject]@{ Check = 'Secure Boot'; Result = 'Not supported / could not read' })
}

# BitLocker
$bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
if ($bl) {
    if ($bl.ProtectionStatus -eq 'On' -or [int]$bl.ProtectionStatus -eq 1) {
        $prot.Add([pscustomobject]@{ Check = 'Disk encryption (BitLocker)'; Result = 'ON' })
        Add-Finding 'OK' 'Protection' 'Disk encryption (BitLocker) is ON'
    } else {
        $prot.Add([pscustomobject]@{ Check = 'Disk encryption (BitLocker)'; Result = 'OFF' })
        Add-Finding 'INFO' 'Protection' 'Disk encryption (BitLocker) is OFF' 'If the laptop is lost or stolen, someone can read your files.' 'Turn on BitLocker or "Device encryption" in Settings, if your Windows edition supports it.'
    }
} else {
    $prot.Add([pscustomobject]@{ Check = 'Disk encryption (BitLocker)'; Result = 'Could not read' })
}

# Remote Desktop
$rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
if ($rdp -eq 0) {
    $prot.Add([pscustomobject]@{ Check = 'Remote Desktop'; Result = 'ENABLED  <-- check' })
    Add-Finding 'WARNING' 'Protection' 'Remote Desktop is ENABLED' 'Others can try to log in to this PC over the network. It is a very common attack target.' 'If you do not need it: Settings > System > Remote Desktop > Off.'
} else {
    $prot.Add([pscustomobject]@{ Check = 'Remote Desktop'; Result = 'Disabled (good)' })
    Add-Finding 'OK' 'Protection' 'Remote Desktop is disabled'
}

# SMBv1
$smb = Get-SmbServerConfiguration
if ($smb) {
    if ($smb.EnableSMB1Protocol) {
        $prot.Add([pscustomobject]@{ Check = 'SMBv1 (very old file sharing)'; Result = 'ENABLED  <-- problem' })
        Add-Finding 'ALERT' 'Protection' 'Old SMBv1 protocol is ENABLED' 'This old protocol was used by the WannaCry ransomware.' 'Run in admin PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'
    } else {
        $prot.Add([pscustomobject]@{ Check = 'SMBv1 (very old file sharing)'; Result = 'Disabled (good)' })
        Add-Finding 'OK' 'Protection' 'Old SMBv1 protocol is disabled'
    }
}

# Auto-login
$auto = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').AutoAdminLogon
if ($auto -eq '1') {
    $prot.Add([pscustomobject]@{ Check = 'Automatic login (no password)'; Result = 'ENABLED  <-- check' })
    Add-Finding 'WARNING' 'Protection' 'Windows logs in automatically without a password' 'Anyone who turns on the PC gets in.' 'Run netplwiz and tick "Users must enter a user name and password".'
}

# Windows Update
$hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hf) {
    $upDays = [math]::Round(((Get-Date) - $hf.InstalledOn).TotalDays)
    $prot.Add([pscustomobject]@{ Check = 'Last Windows update installed'; Result = "$($hf.InstalledOn.ToString('yyyy-MM-dd'))  ($upDays days ago)" })
    if ($upDays -gt 45) {
        Add-Finding 'WARNING' 'Protection' "No Windows update installed for $upDays days" 'Missing updates leave known security holes open.' 'Settings > Windows Update > Check for updates.'
    } else {
        Add-Finding 'OK' 'Protection' 'Windows updates are recent'
    }
}
Add-Table $prot

# ========================================================== 3. ACCOUNTS
Write-Host '[3/7] Checking user accounts...' -ForegroundColor Yellow
Add-Section 'SECTION 3: USER ACCOUNTS' 'Who can log in to this PC, and who has full (administrator) power.'

$users = Get-LocalUser
$userRows = foreach ($u in $users) {
    [pscustomobject]@{
        Name              = $u.Name
        Enabled           = $u.Enabled
        'Password needed' = $u.PasswordRequired
        'Never expires'   = $u.PasswordExpires -eq $null
        'Last login'      = $u.LastLogon
    }
}
$Body.Add('--- All local accounts ---')
Add-Table $userRows

foreach ($u in $users | Where-Object { $_.Enabled }) {
    $sid = $u.SID.Value
    if ($sid -like '*-501') {
        Add-Finding 'ALERT' 'Accounts' 'The Guest account is enabled' 'Guest accounts let strangers use the PC.' 'Run in admin PowerShell: Disable-LocalUser -Name Guest'
    }
    if ($sid -like '*-500') {
        Add-Finding 'WARNING' 'Accounts' 'The built-in "Administrator" account is enabled' 'Attackers always try this well-known name first.' 'Use your own named admin account and disable this one if not needed.'
    }
    if (-not $u.PasswordRequired) {
        Add-Finding 'ALERT' 'Accounts' "Account '$($u.Name)' does not require a password" 'Anyone can log in to this account with an empty password.' "Set a strong password: net user $($u.Name) *"
    }
}

$admins = Get-LocalGroupMember -SID 'S-1-5-32-544'
$Body.Add('--- Members of the Administrators group (full power) ---')
Add-Table ($admins | Select-Object Name, ObjectClass, PrincipalSource)
if ($admins.Count -gt 2) {
    Add-Finding 'WARNING' 'Accounts' "$($admins.Count) accounts have administrator power" 'More admins means more ways for an attacker to get full control.' 'Remove admin rights from accounts that do not need them.'
} else {
    Add-Finding 'OK' 'Accounts' 'Only a small number of administrator accounts'
}

if ($IsAdmin) {
    $new = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720; StartTime = (Get-Date).AddDays(-14) } -MaxEvents 20
    $Body.Add('--- User accounts created in the last 14 days ---')
    if ($new) {
        Add-Table ($new | Select-Object TimeCreated, @{ n = 'Detail'; e = { ($_.Message -split "`r?`n" | Select-String 'Account Name' | Select-Object -Last 1).ToString().Trim() } })
        Add-Finding 'WARNING' 'Accounts' "$(@($new).Count) new user account(s) created in the last 14 days" 'New accounts are a common way attackers keep access.' 'Check the list in Section 3. Delete any account you do not recognise.'
    } else {
        $Body.Add('(none)'); $Body.Add('')
    }
}

# ========================================================== 4. NETWORK
Write-Host '[4/7] Checking network connections...' -ForegroundColor Yellow
Add-Section 'SECTION 4: NETWORK' 'Which programs are waiting for connections (listening) and which are talking to the internet.'

$procMap = @{}
Get-Process | ForEach-Object { $procMap[[int]$_.Id] = $_ }

$riskyPorts = @{
    21   = @('ALERT',   'FTP - sends passwords unencrypted')
    23   = @('ALERT',   'Telnet - old unencrypted remote login')
    5900 = @('ALERT',   'VNC - remote screen control')
    3389 = @('WARNING', 'Remote Desktop')
    5985 = @('WARNING', 'Windows Remote Management')
    5986 = @('WARNING', 'Windows Remote Management (secure)')
    1433 = @('WARNING', 'Microsoft SQL Server database')
    3306 = @('WARNING', 'MySQL database')
    5432 = @('WARNING', 'PostgreSQL database')
    27017 = @('WARNING', 'MongoDB database')
    135  = @('INFO',    'Windows RPC (normal on Windows)')
    139  = @('INFO',    'NetBIOS file sharing (normal on Windows)')
    445  = @('INFO',    'Windows file sharing (normal on Windows)')
}

$listenRows = New-Object System.Collections.Generic.List[object]
$seen = @{}
$listen = Get-NetTCPConnection -State Listen | Sort-Object LocalPort
foreach ($c in $listen) {
    $key = "$($c.LocalPort)-$($c.OwningProcess)"
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    $pr   = $procMap[[int]$c.OwningProcess]
    $name = if ($pr) { $pr.ProcessName } else { "PID $($c.OwningProcess)" }
    $open = $c.LocalAddress -notin @('127.0.0.1', '::1')
    $listenRows.Add([pscustomobject]@{
        Port    = $c.LocalPort
        Program = $name
        'Who can reach it' = $(if ($open) { 'Other computers on the network' } else { 'This PC only (safe)' })
        Note    = $(if ($riskyPorts.ContainsKey([int]$c.LocalPort)) { $riskyPorts[[int]$c.LocalPort][1] } else { '' })
    })
    if ($open -and $riskyPorts.ContainsKey([int]$c.LocalPort)) {
        $lvl = $riskyPorts[[int]$c.LocalPort][0]
        Add-Finding $lvl 'Network' "Port $($c.LocalPort) is open to the network ($($riskyPorts[[int]$c.LocalPort][1]))" "Program using it: $name." 'If you do not need this service, turn it off or block the port in Windows Firewall.'
    }
    if ($open -and $pr -and $pr.Path -and (Test-UserPath $pr.Path)) {
        $sg = Get-Sig $pr.Path
        if ($sg.Status -ne 'Valid') {
            Add-Finding 'ALERT' 'Network' "Unsigned program in a user folder is listening on port $($c.LocalPort)" "Program: $($pr.Path)" 'Investigate it. Search its SHA-256 on virustotal.com (see Section 6).'
        }
    }
}
$Body.Add('--- Programs waiting for connections ("listening ports") ---')
Add-Table $listenRows
Add-Finding 'INFO' 'Network' "$($listenRows.Count) listening port(s) found" 'Full list is in Section 4 of this report.' ''

$estRows = New-Object System.Collections.Generic.List[object]
$est = Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch $PrivateRx }
foreach ($c in $est) {
    $pr   = $procMap[[int]$c.OwningProcess]
    $name = if ($pr) { $pr.ProcessName } else { "PID $($c.OwningProcess)" }
    $path = if ($pr) { $pr.Path } else { '' }
    $estRows.Add([pscustomobject]@{
        Program = $name
        'Talking to' = "$($c.RemoteAddress):$($c.RemotePort)"
        Path = $path
    })
    if ($path -and (Test-UserPath $path)) {
        $sg = Get-Sig $path
        if ($sg.Status -ne 'Valid') {
            Add-Finding 'ALERT' 'Network' "Unsigned program from a user folder is talking to the internet: $name" "It is connected to $($c.RemoteAddress):$($c.RemotePort). Path: $path" 'Check the file on virustotal.com. If unknown, stop it and delete it.'
        }
    }
}
$Body.Add('--- Programs currently connected to the internet ---')
Add-Table ($estRows | Sort-Object Program)

$dns = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | Select-Object InterfaceAlias, @{ n = 'DNS servers'; e = { $_.ServerAddresses -join ', ' } }
$Body.Add('--- DNS servers in use (they translate website names; attackers sometimes change them) ---')
Add-Table $dns

$hosts = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_.Trim() -and $_.Trim() -notmatch '^#' -and $_ -notmatch '^\s*(127\.0\.0\.1|::1)\s+localhost\s*$' }
$Body.Add('--- Custom entries in the hosts file ---')
if ($hosts) {
    $hosts | ForEach-Object { $Body.Add($_) }; $Body.Add('')
    Add-Finding 'WARNING' 'Network' "The hosts file has $(@($hosts).Count) custom entr(ies)" 'Malware can use this file to redirect real websites to fake ones.' 'Open C:\Windows\System32\drivers\etc\hosts in Notepad (as admin) and remove lines you did not add.'
} else {
    $Body.Add('(none - normal)'); $Body.Add('')
}

# ====================================================== 5. PERSISTENCE
Write-Host '[5/7] Checking auto-start items...' -ForegroundColor Yellow
Add-Section 'SECTION 5: THINGS THAT START AUTOMATICALLY' 'Malware often hides here so it can start again after every reboot.'

# Run keys
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
$runRows = New-Object System.Collections.Generic.List[object]
foreach ($k in $runKeys) {
    $item = Get-Item $k
    if (-not $item) { continue }
    foreach ($n in $item.GetValueNames()) {
        if (-not $n) { continue }
        $cmd = [string]$item.GetValue($n)
        $j = Judge-Command $cmd
        $runRows.Add([pscustomobject]@{ Name = $n; Command = $cmd; Location = ($k -replace 'HKLM:|HKCU:', '' -replace '.*\\Run', 'Run'); Hive = $k.Substring(0, 4); Status = $j.Level })
        if ($j.Level -ne 'OK') {
            Add-Finding $j.Level 'Auto-start' "Startup entry '$n' looks suspicious" "Because $($j.Reason). Command: $cmd" 'If you do not recognise it, disable it in Task Manager > Startup apps or delete the registry value.'
        }
    }
}
$Body.Add('--- Programs that start when you log in (registry) ---')
Add-Table ($runRows | Select-Object Name, Hive, Status, Command)

# Startup folders
$startDirs = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
$startFiles = foreach ($d in $startDirs) { Get-ChildItem -LiteralPath $d -File -Force | Where-Object { $_.Name -ne 'desktop.ini' } | Select-Object Name, FullName, LastWriteTime }
$Body.Add('--- Files in the Startup folders ---')
Add-Table $startFiles
foreach ($f in $startFiles) {
    if ($f.Name -match '(?i)\.(bat|cmd|vbs|js|ps1|scr)$') {
        Add-Finding 'WARNING' 'Auto-start' "Script file in Startup folder: $($f.Name)" $f.FullName 'Make sure you created this. If not, delete it.'
    }
}

# Scheduled tasks
$taskRows = New-Object System.Collections.Generic.List[object]
$tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' }
foreach ($t in $tasks) {
    foreach ($a in $t.Actions) {
        if (-not $a.Execute) { continue }
        $cmd = "$($a.Execute) $($a.Arguments)".Trim()
        $j = Judge-Command $cmd
        $taskRows.Add([pscustomobject]@{ Task = $t.TaskName; Status = $j.Level; Runs = $cmd })
        if ($j.Level -ne 'OK') {
            Add-Finding $j.Level 'Auto-start' "Scheduled task '$($t.TaskName)' looks suspicious" "Because $($j.Reason). It runs: $cmd" 'If you do not recognise it, disable it in Task Scheduler.'
        }
    }
}
$Body.Add('--- Scheduled tasks that are NOT from Microsoft ---')
Add-Table $taskRows

# Services
$svcRows = New-Object System.Collections.Generic.List[object]
$svcs = Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' -and $_.PathName -and $_.PathName -notmatch '(?i)^"?[A-Z]:\\Windows\\' }
foreach ($s in $svcs) {
    $j = Judge-Command $s.PathName
    $svcRows.Add([pscustomobject]@{ Service = $s.DisplayName; Status = $j.Level; Starts = $s.StartMode; Path = $s.PathName })
    if ($j.Level -ne 'OK') {
        Add-Finding $j.Level 'Auto-start' "Service '$($s.DisplayName)' looks suspicious" "Because $($j.Reason). Path: $($s.PathName)" 'Check the program. If unknown, stop and disable the service.'
    }
    $p = $s.PathName
    if ($p -notmatch '^"' -and (($p -replace '(?i)\.exe.*$', '.exe') -match ' ')) {
        Add-Finding 'WARNING' 'Auto-start' "Service '$($s.DisplayName)' has an unquoted path with spaces" "Path: $p. This can let an attacker run their own program with high privileges." 'Put quotes around the path in the service ImagePath registry value.'
    }
}
$Body.Add('--- Running services outside the Windows folder ---')
Add-Table $svcRows

# ========================================================= 6. PROCESSES
Write-Host '[6/7] Checking running programs & hashing files...' -ForegroundColor Yellow
Add-Section 'SECTION 6: SUSPICIOUS PLACES FOR RUNNING PROGRAMS' 'Normal programs live in Program Files or Windows. Programs running from Temp, Downloads, Public or AppData deserve a second look. Signed = the publisher is verified. The SHA-256 is a file fingerprint: paste it on virustotal.com to see if it is known malware.'

$procRows = New-Object System.Collections.Generic.List[object]
$groups = Get-Process | Where-Object { $_.Path -and (Test-UserPath $_.Path) } | Group-Object Path
$unsigned = 0; $signed = 0
foreach ($g in $groups) {
    $path = $g.Name
    $sig  = Get-Sig $path
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    $verdict = if ($sig.Status -eq 'Valid') { 'Signed - normal'; $signed++ } else { 'NOT SIGNED - check'; $unsigned++ }
    $procRows.Add([pscustomobject]@{
        Program   = [IO.Path]::GetFileName($path)
        Verdict   = $verdict
        Publisher = $sig.Signer
        Path      = $path
        SHA256    = $hash
    })
    if ($sig.Status -ne 'Valid') {
        Add-Finding 'WARNING' 'Processes' "Unsigned program running from a user folder: $([IO.Path]::GetFileName($path))" "Path: $path   SHA-256: $hash" 'Paste the SHA-256 into virustotal.com. If unknown or flagged, close it and delete the file.'
    }
}
Add-Table $procRows
if ($signed -gt 0 -and $unsigned -eq 0) {
    Add-Finding 'OK' 'Processes' 'All programs running from user folders are digitally signed'
}

$Body.Add('--- Scripting / download tools currently running ---')
$watch = "Name='powershell.exe' OR Name='pwsh.exe' OR Name='cmd.exe' OR Name='wscript.exe' OR Name='cscript.exe' OR Name='mshta.exe' OR Name='certutil.exe' OR Name='bitsadmin.exe'"
$shells = Get-CimInstance Win32_Process -Filter $watch | Where-Object { $_.ProcessId -ne $PID }
$shellRows = foreach ($s in $shells) {
    [pscustomobject]@{ Program = $s.Name; PID = $s.ProcessId; 'Started with' = $s.CommandLine }
    if ($s.Name -match '(?i)^(wscript|cscript|mshta|certutil|bitsadmin)') {
        Add-Finding 'WARNING' 'Processes' "$($s.Name) is running right now" "Command: $($s.CommandLine)" 'These tools are often abused by malware. Make sure you know why it is running.'
    }
}
Add-Table $shellRows

# ============================================== 7. SHARES & LOGIN EVENTS
Write-Host '[7/7] Checking shared folders & failed logins...' -ForegroundColor Yellow
Add-Section 'SECTION 7: SHARED FOLDERS AND LOGIN ATTEMPTS' 'Folders other people on the network can open, and failed password attempts.'

$shares = Get-SmbShare | Where-Object { $_.Name -notmatch '\$$' }
$Body.Add('--- Folders shared on the network ---')
Add-Table ($shares | Select-Object Name, Path, Description)
foreach ($s in $shares) {
    Add-Finding 'WARNING' 'Sharing' "Folder is shared on the network: $($s.Name)" "Path: $($s.Path)" "If you do not need it, run in admin PowerShell: Remove-SmbShare -Name '$($s.Name)'"
}
if (-not $shares) { Add-Finding 'OK' 'Sharing' 'No custom folders are shared on the network' }

if ($IsAdmin) {
    $fails = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddDays(-1) } -MaxEvents 1000
    $cnt = @($fails).Count
    $Body.Add("--- Failed login attempts in the last 24 hours: $cnt ---")
    $Body.Add('')
    if ($cnt -gt 100) {
        Add-Finding 'ALERT' 'Logins' "$cnt failed logins in the last 24 hours" 'This looks like someone guessing passwords (brute force).' 'Check Event Viewer > Security > Event ID 4625 for the source. Make sure Remote Desktop is off or protected, and use strong passwords.'
    } elseif ($cnt -gt 20) {
        Add-Finding 'WARNING' 'Logins' "$cnt failed logins in the last 24 hours" 'More than usual. Could be you mistyping, or someone guessing passwords.' 'Check Event Viewer > Security > Event ID 4625 if you were not the one typing.'
    } else {
        Add-Finding 'OK' 'Logins' "Only $cnt failed login(s) in the last 24 hours (normal)"
    }
}

# ====================================================== BUILD THE REPORT
$alerts = @($Findings | Where-Object { $_.Level -eq 'ALERT' })
$warns  = @($Findings | Where-Object { $_.Level -eq 'WARNING' })
$infos  = @($Findings | Where-Object { $_.Level -eq 'INFO' })
$oks    = @($Findings | Where-Object { $_.Level -eq 'OK' })

if ($alerts.Count -gt 0)      { $verdict = 'ATTENTION NEEDED - serious problems were found. Fix the ALERT items first.' }
elseif ($warns.Count -gt 0)   { $verdict = 'MOSTLY OK - no serious problems, but some things need a look.' }
else                          { $verdict = 'LOOKS GOOD - no problems found.' }

$R = New-Object System.Collections.Generic.List[string]
$R.Add('=' * 78)
$R.Add('  EASY SECURITY AUDIT REPORT')
$R.Add('=' * 78)
$R.Add("  Computer : $env:COMPUTERNAME")
$R.Add("  User     : $env:USERNAME")
$R.Add("  Date     : $(Get-Date)")
$R.Add("  Admin    : $(if ($IsAdmin) { 'Yes' } else { 'No (results may be incomplete)' })")
$R.Add('')
$R.Add('  OVERALL RESULT')
$R.Add("  $verdict")
$R.Add('')
$R.Add("  [ALERT]   $($alerts.Count)   = serious. Fix as soon as possible.")
$R.Add("  [WARNING] $($warns.Count)   = suspicious or risky. Please check.")
$R.Add("  [INFO]    $($infos.Count)   = good to know.")
$R.Add("  [OK]      $($oks.Count)   = checked and fine.")
$R.Add('')
$R.Add('  Note: this scan only looks. It cannot prove a PC is clean, and some')
$R.Add('  warnings can be false alarms (for example your own scripts).')

function Add-FindingGroup($title, $items) {
    if ($items.Count -eq 0) { return }
    $R.Add('')
    $R.Add('=' * 78)
    $R.Add($title)
    $R.Add('=' * 78)
    $i = 1
    foreach ($f in $items) {
        $R.Add('')
        $R.Add("$i. [$($f.Level)] $($f.Title)")
        if ($f.Detail) { $R.Add("   What we saw : $($f.Detail)") }
        if ($f.Fix)    { $R.Add("   What to do  : $($f.Fix)") }
        $i++
    }
}

Add-FindingGroup 'FIX THESE FIRST (ALERT)' $alerts
Add-FindingGroup 'PLEASE CHECK THESE (WARNING)' $warns
Add-FindingGroup 'GOOD TO KNOW (INFO)' $infos

if ($oks.Count -gt 0) {
    $R.Add('')
    $R.Add('=' * 78)
    $R.Add('THESE LOOK GOOD (OK)')
    $R.Add('=' * 78)
    foreach ($f in $oks) { $R.Add("  [OK] $($f.Title)") }
}

$R.Add('')
$R.Add('#' * 78)
$R.Add('  DETAILED DATA (for deeper checking)')
$R.Add('#' * 78)
foreach ($l in $Body) { $R.Add($l) }
$R.Add('')
$R.Add('=' * 78)
$R.Add('  END OF REPORT')
$R.Add('=' * 78)

$R | Out-File -FilePath $ReportPath -Encoding UTF8
if ($JsonOut) {
    try {
        # Plain ordered tables (not the List[object]) so ConvertTo-Json works on PowerShell 5.1 and 7+.
        $jsonItems = @($Findings | ForEach-Object {
            [ordered]@{ Level = [string]$_.Level; Area = [string]$_.Area; Title = [string]$_.Title; Detail = [string]$_.Detail; Fix = [string]$_.Fix }
        })
        ConvertTo-Json -InputObject $jsonItems -Depth 3 | Out-File -FilePath $JsonOut -Encoding UTF8
    } catch {
        Write-Host "JSON export failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ------------------------------------------------------ console summary
Write-Host ''
Write-Host '  ================ RESULT ================' -ForegroundColor Cyan
$col = if ($alerts.Count) { 'Red' } elseif ($warns.Count) { 'Yellow' } else { 'Green' }
Write-Host "  $verdict" -ForegroundColor $col
Write-Host "  ALERT: $($alerts.Count)   WARNING: $($warns.Count)   INFO: $($infos.Count)   OK: $($oks.Count)"
Write-Host ''
Write-Host "  Report saved to: $ReportPath" -ForegroundColor Green
Write-Host ''
if (-not $NoOpen) { Start-Process notepad.exe $ReportPath }
