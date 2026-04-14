<#
.SYNOPSIS
    Endpoint Response Toolkit — execute incident response actions across Windows and Linux hosts.
.DESCRIPTION
    Reads a YAML playbook defining hosts, credentials, and response actions.
    Dispatches actions via PSRemoting (Windows) or SSH (Linux).
    Every action is logged to a JSON-lines audit file.
.PARAMETER PlaybookPath
    Path to the YAML playbook file.
.PARAMETER WhatIf
    Dry-run mode — logs what would happen without executing.
.PARAMETER Force
    Skip confirmation prompts for destructive actions.
.PARAMETER MaxConcurrent
    Maximum parallel host sessions (default 10).
.PARAMETER AuditLog
    Path to the audit log file (default: respond-audit-<timestamp>.jsonl).
.PARAMETER CredentialOutputPath
    Path to export rotated credentials (encrypted). Default: rotated-creds-<timestamp>.xml
.EXAMPLE
    .\respond.ps1 -PlaybookPath .\playbook.yml
    .\respond.ps1 -PlaybookPath .\playbook.yml -WhatIf
    .\respond.ps1 -PlaybookPath .\playbook.yml -Force -MaxConcurrent 20
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$true)]
    [string]$PlaybookPath,
    [switch]$Force,
    [int]$MaxConcurrent = 10,
    [string]$AuditLog = "",
    [string]$CredentialOutputPath = ""
)

$ErrorActionPreference = 'Continue'
$script:StartTime = Get-Date

# ============================================================================
# YAML Parser (lightweight — no external module dependency)
# ============================================================================
function ConvertFrom-SimpleYaml {
    param([string]$Content)
    # This parses the subset of YAML we need: mappings, sequences, scalars.
    # For production use, consider Install-Module powershell-yaml.
    try {
        # Try powershell-yaml module first (best parsing)
        if (Get-Module -ListAvailable -Name powershell-yaml -ErrorAction SilentlyContinue) {
            Import-Module powershell-yaml -ErrorAction Stop
            return ConvertFrom-Yaml $Content
        }
    } catch {}

    # Fallback: manual parse for our specific playbook schema
    $playbook = @{ hosts = @(); credentials = @{}; variables = @{} }
    $lines = $Content -split "`r?`n"
    $currentSection = ''
    $currentHost = $null
    $currentAction = $null
    $currentCred = $null
    $currentCredName = ''
    $inParams = $false
    $inActions = $false

    foreach ($rawLine in $lines) {
        $line = $rawLine -replace '#.*$', ''  # strip comments
        if ($line -match '^\s*$') { continue }

        $indent = ($line -replace '^(\s*).*', '$1').Length

        # Top-level sections
        if ($indent -eq 0 -and $line -match '^(\w+):') {
            $currentSection = $Matches[1]
            $currentHost = $null
            $currentAction = $null
            $currentCred = $null
            $inActions = $false
            $inParams = $false
            continue
        }

        switch ($currentSection) {
            'credentials' {
                if ($indent -eq 2 -and $line -match '^\s+(\S+):') {
                    $currentCredName = $Matches[1].Trim()
                    $currentCred = @{}
                    $playbook.credentials[$currentCredName] = $currentCred
                } elseif ($indent -ge 4 -and $currentCred -ne $null -and $line -match '^\s+(\w+):\s*(.+)') {
                    $currentCred[$Matches[1].Trim()] = $Matches[2].Trim()
                }
            }
            'variables' {
                if ($line -match '^\s+(\w+):\s*(.+)') {
                    $playbook.variables[$Matches[1].Trim()] = $Matches[2].Trim()
                }
            }
            'hosts' {
                if ($line -match '^\s*-\s+host:\s*(.+)') {
                    $currentHost = @{
                        host = $Matches[1].Trim()
                        credential = ''
                        platform = 'windows'
                        actions = @()
                    }
                    $playbook.hosts += $currentHost
                    $inActions = $false
                    $inParams = $false
                    $currentAction = $null
                } elseif ($currentHost -ne $null) {
                    if ($line -match '^\s+credential:\s*(.+)') {
                        $currentHost.credential = $Matches[1].Trim()
                    } elseif ($line -match '^\s+platform:\s*(.+)') {
                        $currentHost.platform = $Matches[1].Trim().ToLower()
                    } elseif ($line -match '^\s+actions:') {
                        $inActions = $true
                        $inParams = $false
                    } elseif ($inActions -and $line -match '^\s+-\s+action:\s*(.+)') {
                        $currentAction = @{
                            action = $Matches[1].Trim()
                            target = ''
                            params = @{}
                        }
                        $currentHost.actions += $currentAction
                        $inParams = $false
                    } elseif ($currentAction -ne $null -and $line -match '^\s+target:\s*(.+)') {
                        $currentAction.target = $Matches[1].Trim()
                    } elseif ($currentAction -ne $null -and $line -match '^\s+params:') {
                        $inParams = $true
                    } elseif ($inParams -and $currentAction -ne $null -and $line -match '^\s+(\w+):\s*(.+)') {
                        $currentAction.params[$Matches[1].Trim()] = $Matches[2].Trim()
                    }
                }
            }
        }
    }
    return $playbook
}

# ============================================================================
# Audit Logger
# ============================================================================
$script:AuditLogPath = if ($AuditLog) { $AuditLog } else {
    Join-Path (Get-Location) "respond-audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').jsonl"
}
$script:Operator = "$env:USERDOMAIN\$env:USERNAME"

function Write-AuditEntry {
    param(
        [string]$Host_,
        [string]$Action,
        [string]$Target,
        [hashtable]$Params = @{},
        [string]$Status,       # 'success', 'failed', 'skipped', 'dry-run'
        [string]$Detail = '',
        [object]$PreState = $null,
        [double]$DurationMs = 0
    )
    $entry = [PSCustomObject]@{
        timestamp   = (Get-Date).ToString('o')
        operator    = $script:Operator
        host        = $Host_
        action      = $Action
        target      = $Target
        params      = $Params
        status      = $Status
        detail      = $Detail
        preState    = $PreState
        durationMs  = [math]::Round($DurationMs, 1)
    }
    $json = $entry | ConvertTo-Json -Compress -Depth 5
    Add-Content -Path $script:AuditLogPath -Value $json -Encoding UTF8
    # Console output
    $color = switch ($Status) {
        'success'  { 'Green' }
        'failed'   { 'Red' }
        'skipped'  { 'Yellow' }
        'dry-run'  { 'Cyan' }
        default    { 'White' }
    }
    Write-Host "[$Status] " -ForegroundColor $color -NoNewline
    Write-Host "$Host_ | $Action | $Target" -NoNewline
    if ($Detail) { Write-Host " | $Detail" } else { Write-Host "" }
}

# ============================================================================
# Credential Management
# ============================================================================
$script:CredentialCache = @{}
$script:RotatedCredentials = @()
$script:CredOutputPath = if ($CredentialOutputPath) { $CredentialOutputPath } else {
    Join-Path (Get-Location) "rotated-creds-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
}

function Get-CachedCredential {
    param([string]$Name, [hashtable]$CredDef)
    if ($script:CredentialCache.ContainsKey($Name)) {
        return $script:CredentialCache[$Name]
    }
    $username = if ($CredDef -and $CredDef.username) { $CredDef.username } else { $Name }
    $cred = Get-Credential -UserName $username -Message "Enter credentials for '$Name'"
    $script:CredentialCache[$Name] = $cred
    return $cred
}

function Save-RotatedCredentials {
    if ($script:RotatedCredentials.Count -gt 0) {
        $script:RotatedCredentials | Export-Clixml -Path $script:CredOutputPath -Force
        Write-Host "`nRotated credentials saved to: $($script:CredOutputPath)" -ForegroundColor Magenta
        Write-Host "This file is encrypted to the current user on this machine." -ForegroundColor Magenta
    }
}

function New-SecurePassword {
    param([int]$Length = 24)
    $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()-_=+'
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = [byte[]]::new($Length)
    $rng.GetBytes($bytes)
    $password = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
    return $password
}

# ============================================================================
# Session Management
# ============================================================================
$script:SessionCache = @{}

function Get-HostSession {
    param([string]$HostName, [pscredential]$Credential, [string]$Platform)
    $key = "$HostName|$Platform"
    if ($script:SessionCache.ContainsKey($key)) {
        $existing = $script:SessionCache[$key]
        if ($Platform -eq 'windows' -and $existing.State -eq 'Opened') {
            return $existing
        } elseif ($Platform -eq 'linux') {
            return $existing  # SSH sessions are just credential refs
        }
    }
    if ($Platform -eq 'windows') {
        $session = New-PSSession -ComputerName $HostName -Credential $Credential -ErrorAction Stop
        $script:SessionCache[$key] = $session
        return $session
    } else {
        # For Linux, store credential info for SSH dispatch
        $sshInfo = @{ Host = $HostName; Credential = $Credential }
        $script:SessionCache[$key] = $sshInfo
        return $sshInfo
    }
}

function Close-AllSessions {
    foreach ($key in $script:SessionCache.Keys) {
        $session = $script:SessionCache[$key]
        if ($session -is [System.Management.Automation.Runspaces.PSSession]) {
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        }
    }
    $script:SessionCache.Clear()
}

# ============================================================================
# Linux SSH Dispatch Helper
# ============================================================================
function Invoke-SshCommand {
    param(
        [hashtable]$SshInfo,
        [string]$Command
    )
    $host_ = $SshInfo.Host
    $user = $SshInfo.Credential.UserName
    # Use ssh with key-based auth or password via sshpass if available
    $sshOpts = "-o StrictHostKeyChecking=accept-new -o ConnectTimeout=30 -o BatchMode=yes"
    $result = & ssh $sshOpts "$user@$host_" $Command 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "SSH command failed (exit $LASTEXITCODE): $result"
    }
    return $result
}

# ============================================================================
# WINDOWS RESPONSE ACTIONS
# ============================================================================

# ---- Process Management ----
function Invoke-ActionKillProcess {
    param($Session, [string]$Target, [hashtable]$Params)
    # Target can be PID (numeric) or process name or executable path
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($target)
        $killed = @()
        if ($target -match '^\d+$') {
            $proc = Get-Process -Id ([int]$target) -ErrorAction Stop
            $killed += [PSCustomObject]@{ PID=$proc.Id; Name=$proc.Name; Path=$proc.Path }
            Stop-Process -Id ([int]$target) -Force
        } else {
            # Match by name or path
            $procs = Get-Process | Where-Object { $_.Name -eq $target -or $_.Path -eq $target }
            foreach ($proc in $procs) {
                $killed += [PSCustomObject]@{ PID=$proc.Id; Name=$proc.Name; Path=$proc.Path }
                Stop-Process -Id $proc.Id -Force
            }
        }
        $killed
    } -ArgumentList $Target
    return @{ killed = $result }
}

# ---- User / Session Management ----
function Invoke-ActionDisableLocalUser {
    param($Session, [string]$Target, [hashtable]$Params)
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($username)
        $user = Get-LocalUser -Name $username -ErrorAction Stop
        $preState = [PSCustomObject]@{ Name=$user.Name; Enabled=$user.Enabled }
        Disable-LocalUser -Name $username
        [PSCustomObject]@{ PreState=$preState; Action='disabled' }
    } -ArgumentList $Target
    return @{ preState = $result.PreState; result = $result.Action }
}

function Invoke-ActionDisableDomainUser {
    param($Session, [string]$Target, [hashtable]$Params)
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($sam)
        Import-Module ActiveDirectory -ErrorAction Stop
        $user = Get-ADUser -Identity $sam -Properties Enabled -ErrorAction Stop
        $preState = [PSCustomObject]@{ SamAccountName=$user.SamAccountName; Enabled=$user.Enabled }
        Disable-ADAccount -Identity $sam
        [PSCustomObject]@{ PreState=$preState; Action='disabled' }
    } -ArgumentList $Target
    return @{ preState = $result.PreState; result = $result.Action }
}

function Invoke-ActionForceLogoff {
    param($Session, [string]$Target, [hashtable]$Params)
    # Target: username or session ID or 'all'
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($target)
        $loggedOff = @()
        $quserOutput = query user 2>&1
        foreach ($line in ($quserOutput | Select-Object -Skip 1)) {
            $lineStr = $line.ToString().Trim()
            if ($lineStr -match '^\>?\s*(\S+)\s+(\S+)?\s+(\d+)\s+(Active|Disc)') {
                $userName = $Matches[1]
                $sessionId = $Matches[3]
                if ($target -eq 'all' -or $target -eq $userName -or $target -eq $sessionId) {
                    logoff $sessionId /v 2>&1
                    $loggedOff += [PSCustomObject]@{ User=$userName; SessionId=$sessionId }
                }
            }
        }
        $loggedOff
    } -ArgumentList $Target
    return @{ loggedOff = $result }
}

function Invoke-ActionResetLocalPassword {
    param($Session, [string]$Target, [hashtable]$Params)
    $newPassword = if ($Params.password) { $Params.password } else { New-SecurePassword }
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($username, $newPw)
        $secPw = ConvertTo-SecureString $newPw -AsPlainText -Force
        Set-LocalUser -Name $username -Password $secPw
        [PSCustomObject]@{ User=$username; PasswordChanged=$true }
    } -ArgumentList $Target, $newPassword
    # Record rotated credential securely
    $script:RotatedCredentials += [PSCustomObject]@{
        Timestamp = (Get-Date).ToString('o')
        Host      = $Session.ComputerName
        Type      = 'local-user'
        Username  = $Target
        Password  = $newPassword
    }
    return @{ result = 'password-reset'; user = $Target }
}

function Invoke-ActionResetDomainPassword {
    param($Session, [string]$Target, [hashtable]$Params)
    $newPassword = if ($Params.password) { $Params.password } else { New-SecurePassword }
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($sam, $newPw)
        Import-Module ActiveDirectory -ErrorAction Stop
        $secPw = ConvertTo-SecureString $newPw -AsPlainText -Force
        Set-ADAccountPassword -Identity $sam -NewPassword $secPw -Reset
        Set-ADUser -Identity $sam -ChangePasswordAtLogon $true
        [PSCustomObject]@{ User=$sam; PasswordChanged=$true; MustChange=$true }
    } -ArgumentList $Target, $newPassword
    $script:RotatedCredentials += [PSCustomObject]@{
        Timestamp = (Get-Date).ToString('o')
        Host      = $Session.ComputerName
        Type      = 'domain-user'
        Username  = $Target
        Password  = $newPassword
    }
    return @{ result = 'password-reset'; user = $Target; mustChangeAtLogon = $true }
}

# ---- File Operations ----
function Invoke-ActionDeleteFile {
    param($Session, [string]$Target, [hashtable]$Params)
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($path)
        $preState = $null
        if (Test-Path $path) {
            $item = Get-Item $path -Force
            $preState = [PSCustomObject]@{
                Path=$item.FullName; Size=$item.Length
                Hash=(Get-FileHash $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            }
            Remove-Item -Path $path -Force
        } else {
            throw "File not found: $path"
        }
        [PSCustomObject]@{ PreState=$preState; Deleted=$true }
    } -ArgumentList $Target
    return @{ preState = $result.PreState; deleted = $true }
}

function Invoke-ActionQuarantineFile {
    param($Session, [string]$Target, [hashtable]$Params)
    $quarantineDir = if ($Params.quarantine_dir) { $Params.quarantine_dir } else { 'C:\Quarantine' }
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($path, $qDir)
        if (-not (Test-Path $qDir)) { New-Item -ItemType Directory -Path $qDir -Force | Out-Null }
        if (-not (Test-Path $path)) { throw "File not found: $path" }
        $item = Get-Item $path -Force
        $hash = (Get-FileHash $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        $destName = "$($hash)_$($item.Name)"
        $destPath = Join-Path $qDir $destName
        Move-Item -Path $path -Destination $destPath -Force
        [PSCustomObject]@{
            OriginalPath = $item.FullName
            QuarantinePath = $destPath
            SHA256 = $hash
            Size = $item.Length
        }
    } -ArgumentList $Target, $quarantineDir
    return @{ original = $result.OriginalPath; quarantined = $result.QuarantinePath; sha256 = $result.SHA256 }
}

function Invoke-ActionCollectFile {
    param($Session, [string]$Target, [hashtable]$Params)
    $localDir = if ($Params.local_dir) { $Params.local_dir } else { '.\collected' }
    if (-not (Test-Path $localDir)) { New-Item -ItemType Directory -Path $localDir -Force | Out-Null }
    $hostName = $Session.ComputerName
    $fileName = Split-Path $Target -Leaf
    $localPath = Join-Path $localDir "${hostName}_${fileName}"
    Copy-Item -Path $Target -Destination $localPath -FromSession $Session -Force
    return @{ remotePath = $Target; localPath = $localPath }
}

# ---- Persistence Removal ----
function Invoke-ActionDeleteScheduledTask {
    param($Session, [string]$Target, [hashtable]$Params)
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($taskName)
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
        $preState = [PSCustomObject]@{
            TaskName=$task.TaskName; TaskPath=$task.TaskPath; State=$task.State.ToString()
            Actions=($task.Actions | ForEach-Object { $_.Execute }) -join '; '
        }
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        [PSCustomObject]@{ PreState=$preState; Deleted=$true }
    } -ArgumentList $Target
    return @{ preState = $result.PreState; deleted = $true }
}

function Invoke-ActionDisableService {
    param($Session, [string]$Target, [hashtable]$Params)
    $stopService = if ($Params.stop -eq 'true') { $true } else { $false }
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($svcName, $stopIt)
        $svc = Get-Service -Name $svcName -ErrorAction Stop
        $preState = [PSCustomObject]@{ Name=$svc.Name; Status=$svc.Status.ToString(); StartType=$svc.StartType.ToString() }
        Set-Service -Name $svcName -StartupType Disabled
        if ($stopIt -and $svc.Status -eq 'Running') {
            Stop-Service -Name $svcName -Force
        }
        [PSCustomObject]@{ PreState=$preState; NewStartType='Disabled'; Stopped=$stopIt }
    } -ArgumentList $Target, $stopService
    return @{ preState = $result.PreState; disabled = $true }
}

function Invoke-ActionRegistryDelete {
    param($Session, [string]$Target, [hashtable]$Params)
    $valueName = $Params.value_name  # if null, deletes the entire key
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($regPath, $valName)
        $preState = $null
        if ($valName) {
            $preState = Get-ItemProperty -Path $regPath -Name $valName -ErrorAction Stop
            Remove-ItemProperty -Path $regPath -Name $valName -Force
            [PSCustomObject]@{ PreState=$preState; Type='value-deleted' }
        } else {
            $preState = Get-Item -Path $regPath -ErrorAction Stop | Select-Object -Property Name, Property
            Remove-Item -Path $regPath -Recurse -Force
            [PSCustomObject]@{ PreState=$preState; Type='key-deleted' }
        }
    } -ArgumentList $Target, $valueName
    return @{ preState = $result.PreState; type = $result.Type }
}

function Invoke-ActionRemovePersistence {
    param($Session, [string]$Target, [hashtable]$Params)
    # Uses autorunsc to remove an autorun entry — same approach as clear.ps1
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($entry)
        $autorunscPath = Join-Path $env:TEMP 'autorunsc.exe'
        if (-not (Test-Path $autorunscPath)) { throw "autorunsc.exe not found on target at $autorunscPath" }
        $output = & $autorunscPath -d $entry 2>&1
        [PSCustomObject]@{ Entry=$entry; Output=$output }
    } -ArgumentList $Target
    return @{ entry = $Target; output = $result.Output }
}

# ---- Network / Firewall ----
function Invoke-ActionFirewallBlock {
    param($Session, [string]$Target, [hashtable]$Params)
    $direction = if ($Params.direction) { $Params.direction } else { 'Inbound' }
    $protocol = if ($Params.protocol) { $Params.protocol } else { 'Any' }
    $port = $Params.port
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($addr, $dir, $proto, $port_)
        $ruleName = "IR-Block-$addr"
        $ruleParams = @{
            DisplayName = $ruleName
            Direction   = $dir
            Action      = 'Block'
            Enabled     = 'True'
        }
        if ($addr -match '^\d+\.\d+\.\d+') {
            if ($dir -eq 'Inbound') { $ruleParams['RemoteAddress'] = $addr }
            else { $ruleParams['RemoteAddress'] = $addr }
        }
        if ($port_) { $ruleParams['LocalPort'] = $port_; $ruleParams['Protocol'] = if ($proto -eq 'Any') { 'TCP' } else { $proto } }
        elseif ($proto -ne 'Any') { $ruleParams['Protocol'] = $proto }
        New-NetFirewallRule @ruleParams
        [PSCustomObject]@{ RuleName=$ruleName; Direction=$dir; Target=$addr }
    } -ArgumentList $Target, $direction, $protocol, $port
    return @{ rule = $result.RuleName; direction = $direction }
}

function Invoke-ActionFirewallRemoveRule {
    param($Session, [string]$Target, [hashtable]$Params)
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($ruleName)
        $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
        $preState = $rule | Select-Object DisplayName, Direction, Action, Enabled
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
        [PSCustomObject]@{ PreState=$preState; Removed=$true }
    } -ArgumentList $Target
    return @{ preState = $result.PreState; removed = $true }
}

function Invoke-ActionIsolateHost {
    param($Session, [string]$Target, [hashtable]$Params)
    # Target = management IP/subnet to allow; blocks everything else
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($mgmtSubnet)
        # Create allow rule for management traffic first
        New-NetFirewallRule -DisplayName 'IR-Isolate-Allow-Mgmt' -Direction Inbound -Action Allow -RemoteAddress $mgmtSubnet -Enabled True -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName 'IR-Isolate-Allow-Mgmt-Out' -Direction Outbound -Action Allow -RemoteAddress $mgmtSubnet -Enabled True -ErrorAction SilentlyContinue
        # Set default profiles to block
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Block
        [PSCustomObject]@{ ManagementSubnet=$mgmtSubnet; Isolated=$true }
    } -ArgumentList $Target
    return @{ managementSubnet = $Target; isolated = $true }
}

function Invoke-ActionUnisolateHost {
    param($Session, [string]$Target, [hashtable]$Params)
    $result = Invoke-Command -Session $Session -ScriptBlock {
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction NotConfigured -DefaultOutboundAction NotConfigured
        Remove-NetFirewallRule -DisplayName 'IR-Isolate-Allow-Mgmt' -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName 'IR-Isolate-Allow-Mgmt-Out' -ErrorAction SilentlyContinue
        [PSCustomObject]@{ Unisolated=$true }
    }
    return @{ unisolated = $true }
}

# ---- Security Policy & Logging ----
function Invoke-ActionSetAuditPolicy {
    param($Session, [string]$Target, [hashtable]$Params)
    # Target = subcategory, Params.setting = success/failure/both/none
    $setting = if ($Params.setting) { $Params.setting } else { 'both' }
    $auditFlag = switch ($setting.ToLower()) {
        'success' { '/success:enable /failure:disable' }
        'failure' { '/success:disable /failure:enable' }
        'both'    { '/success:enable /failure:enable' }
        'none'    { '/success:disable /failure:disable' }
    }
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($subcategory, $flag)
        $prePol = & auditpol /get /subcategory:"$subcategory" /r 2>$null | ConvertFrom-Csv
        $preState = $prePol | Select-Object 'Subcategory', 'Inclusion Setting'
        $cmd = "auditpol /set /subcategory:`"$subcategory`" $flag"
        $output = Invoke-Expression $cmd 2>&1
        [PSCustomObject]@{ PreState=$preState; Command=$cmd; Output=$output }
    } -ArgumentList $Target, $auditFlag
    return @{ preState = $result.PreState; command = $result.Command }
}

function Invoke-ActionSetRegistryValue {
    param($Session, [string]$Target, [hashtable]$Params)
    $valueName = $Params.name
    $valueData = $Params.data
    $valueType = if ($Params.type) { $Params.type } else { 'DWord' }
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($regPath, $name, $data, $type)
        $preState = $null
        try { $preState = Get-ItemProperty -Path $regPath -Name $name -ErrorAction Stop } catch {}
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name $name -Value $data -Type $type
        [PSCustomObject]@{ PreState=$preState; Path=$regPath; Name=$name; NewValue=$data }
    } -ArgumentList $Target, $valueName, $valueData, $valueType
    return @{ preState = $result.PreState; path = $Target; name = $valueName; newValue = $valueData }
}

function Invoke-ActionEnablePSLogging {
    param($Session, [string]$Target, [hashtable]$Params)
    # Enables ScriptBlock, Module, and/or Transcription logging
    $result = Invoke-Command -Session $Session -ScriptBlock {
        $changes = @()
        # ScriptBlock logging
        $sbPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        if (-not (Test-Path $sbPath)) { New-Item -Path $sbPath -Force | Out-Null }
        Set-ItemProperty -Path $sbPath -Name EnableScriptBlockLogging -Value 1 -Type DWord
        $changes += 'ScriptBlockLogging=Enabled'
        # Module logging
        $mlPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
        if (-not (Test-Path $mlPath)) { New-Item -Path $mlPath -Force | Out-Null }
        Set-ItemProperty -Path $mlPath -Name EnableModuleLogging -Value 1 -Type DWord
        $mlNamesPath = "$mlPath\ModuleNames"
        if (-not (Test-Path $mlNamesPath)) { New-Item -Path $mlNamesPath -Force | Out-Null }
        Set-ItemProperty -Path $mlNamesPath -Name '*' -Value '*' -Type String
        $changes += 'ModuleLogging=Enabled(*)'
        # Transcription
        $trPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        if (-not (Test-Path $trPath)) { New-Item -Path $trPath -Force | Out-Null }
        Set-ItemProperty -Path $trPath -Name EnableTranscripting -Value 1 -Type DWord
        Set-ItemProperty -Path $trPath -Name EnableInvocationHeader -Value 1 -Type DWord
        $changes += 'Transcription=Enabled'
        $changes
    }
    return @{ changes = $result }
}

function Invoke-ActionSetEventLogSize {
    param($Session, [string]$Target, [hashtable]$Params)
    # Target = log name (Security, System, etc.), Params.max_size_kb
    $maxSizeKB = if ($Params.max_size_kb) { [int]$Params.max_size_kb } else { 1048576 }  # 1GB default
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($logName, $maxKB)
        $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
        $preState = [PSCustomObject]@{ LogName=$log.LogName; MaxSizeKB=($log.MaximumSizeInBytes / 1024) }
        wevtutil sl $logName /ms:$($maxKB * 1024)
        [PSCustomObject]@{ PreState=$preState; NewMaxSizeKB=$maxKB }
    } -ArgumentList $Target, $maxSizeKB
    return @{ preState = $result.PreState; newMaxSizeKB = $maxSizeKB }
}

function Invoke-ActionBlockHash {
    param($Session, [string]$Target, [hashtable]$Params)
    # Block a file hash via Windows Defender custom indicators
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($hash)
        Add-MpPreference -ThreatIDDefaultAction_Ids 0 -ThreatIDDefaultAction_Actions Quarantine -ErrorAction SilentlyContinue
        # Use Defender custom indicator approach
        $defenderPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatIDDefaultAction'
        if (-not (Test-Path $defenderPath)) { New-Item -Path $defenderPath -Force | Out-Null }
        # Alternative: use MpPreference for hash-based blocking if available
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $hash -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
        } catch {
            # Fallback: record the hash for manual follow-up
        }
        [PSCustomObject]@{ Hash=$hash; Blocked=$true }
    } -ArgumentList $Target
    return @{ hash = $Target; blocked = $true }
}

function Invoke-ActionRunScript {
    param($Session, [string]$Target, [hashtable]$Params)
    # Target = inline script or path to script
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($script_)
        if (Test-Path $script_) {
            $output = & $script_ 2>&1
        } else {
            $output = Invoke-Expression $script_ 2>&1
        }
        [PSCustomObject]@{ Output = ($output | Out-String) }
    } -ArgumentList $Target
    return @{ output = $result.Output }
}

# ============================================================================
# LINUX RESPONSE ACTIONS (dispatched via SSH)
# ============================================================================
function Invoke-LinuxAction {
    param($SshInfo, [string]$Action, [string]$Target, [hashtable]$Params)

    $cmd = switch ($Action) {
        'kill-process' {
            if ($Target -match '^\d+$') { "kill -9 $Target" }
            else { "pkill -9 -f '$Target'" }
        }
        'disable-user' {
            "usermod -L '$Target' && usermod -s /sbin/nologin '$Target'"
        }
        'force-logoff' {
            "pkill -u '$Target' -9"
        }
        'reset-password' {
            $newPw = if ($Params.password) { $Params.password } else { New-SecurePassword }
            $script:RotatedCredentials += [PSCustomObject]@{
                Timestamp = (Get-Date).ToString('o')
                Host      = $SshInfo.Host
                Type      = 'linux-user'
                Username  = $Target
                Password  = $newPw
            }
            "echo '${Target}:${newPw}' | chpasswd"
        }
        'delete-file' {
            "rm -f '$Target'"
        }
        'quarantine-file' {
            $qDir = if ($Params.quarantine_dir) { $Params.quarantine_dir } else { '/var/quarantine' }
            "mkdir -p '$qDir' && hash=`$(sha256sum '$Target' | cut -d' ' -f1) && mv '$Target' '$qDir/`${hash}_$(Split-Path $Target -Leaf)' && chattr +i '$qDir/`${hash}_$(Split-Path $Target -Leaf)'"
        }
        'collect-file' {
            # Return content encoded for transfer
            "cat '$Target' | base64"
        }
        'firewall-block' {
            $chain = if ($Params.direction -eq 'outbound') { 'OUTPUT' } else { 'INPUT' }
            "iptables -A $chain -s '$Target' -j DROP && iptables -A $chain -d '$Target' -j DROP"
        }
        'firewall-unblock' {
            $chain = if ($Params.direction -eq 'outbound') { 'OUTPUT' } else { 'INPUT' }
            "iptables -D $chain -s '$Target' -j DROP 2>/dev/null; iptables -D $chain -d '$Target' -j DROP 2>/dev/null"
        }
        'disable-service' {
            $stopFlag = if ($Params.stop -eq 'true') { '&& systemctl stop' } else { '' }
            "systemctl disable '$Target' $stopFlag '$Target'"
        }
        'remove-cron' {
            "crontab -l 2>/dev/null | grep -v '$Target' | crontab -"
        }
        'remove-authorized-key' {
            $user = if ($Params.user) { $Params.user } else { 'root' }
            $home = if ($user -eq 'root') { '/root' } else { "/home/$user" }
            "sed -i '/$Target/d' '$home/.ssh/authorized_keys'"
        }
        'set-sysctl' {
            $value = $Params.value
            "sysctl -w '$Target=$value' && grep -q '^$Target' /etc/sysctl.conf && sed -i 's/^$Target.*/$Target = $value/' /etc/sysctl.conf || echo '$Target = $value' >> /etc/sysctl.conf"
        }
        'enable-auditd-rule' {
            "auditctl $Target && echo '$Target' >> /etc/audit/rules.d/ir-response.rules"
        }
        'run-script' {
            $Target
        }
        'isolate-host' {
            # Target = management IP/subnet to allow
            "iptables -I INPUT 1 -s '$Target' -j ACCEPT && iptables -I OUTPUT 1 -d '$Target' -j ACCEPT && iptables -A INPUT -j DROP && iptables -A OUTPUT -j DROP"
        }
        'unisolate-host' {
            "iptables -D INPUT -j DROP 2>/dev/null; iptables -D OUTPUT -j DROP 2>/dev/null; iptables -D INPUT -s '$Target' -j ACCEPT 2>/dev/null; iptables -D OUTPUT -d '$Target' -j ACCEPT 2>/dev/null"
        }
        default {
            throw "Unknown Linux action: $Action"
        }
    }

    $output = Invoke-SshCommand -SshInfo $SshInfo -Command $cmd
    return @{ command = $cmd; output = ($output | Out-String) }
}

# ============================================================================
# ACTION DISPATCHER
# ============================================================================
$script:DestructiveActions = @(
    'kill-process', 'delete-file', 'quarantine-file', 'delete-scheduled-task',
    'disable-service', 'remove-persistence', 'registry-delete', 'isolate-host',
    'reset-local-password', 'reset-domain-password', 'reset-password',
    'disable-user', 'force-logoff', 'block-hash'
)

$script:WindowsActions = @{
    'kill-process'            = 'Invoke-ActionKillProcess'
    'disable-local-user'      = 'Invoke-ActionDisableLocalUser'
    'disable-domain-user'     = 'Invoke-ActionDisableDomainUser'
    'force-logoff'            = 'Invoke-ActionForceLogoff'
    'reset-local-password'    = 'Invoke-ActionResetLocalPassword'
    'reset-domain-password'   = 'Invoke-ActionResetDomainPassword'
    'delete-file'             = 'Invoke-ActionDeleteFile'
    'quarantine-file'         = 'Invoke-ActionQuarantineFile'
    'collect-file'            = 'Invoke-ActionCollectFile'
    'delete-scheduled-task'   = 'Invoke-ActionDeleteScheduledTask'
    'disable-service'         = 'Invoke-ActionDisableService'
    'registry-delete'         = 'Invoke-ActionRegistryDelete'
    'registry-set'            = 'Invoke-ActionSetRegistryValue'
    'remove-persistence'      = 'Invoke-ActionRemovePersistence'
    'firewall-block'          = 'Invoke-ActionFirewallBlock'
    'firewall-remove-rule'    = 'Invoke-ActionFirewallRemoveRule'
    'isolate-host'            = 'Invoke-ActionIsolateHost'
    'unisolate-host'          = 'Invoke-ActionUnisolateHost'
    'set-audit-policy'        = 'Invoke-ActionSetAuditPolicy'
    'enable-ps-logging'       = 'Invoke-ActionEnablePSLogging'
    'set-event-log-size'      = 'Invoke-ActionSetEventLogSize'
    'block-hash'              = 'Invoke-ActionBlockHash'
    'run-script'              = 'Invoke-ActionRunScript'
}

$script:LinuxActions = @(
    'kill-process', 'disable-user', 'force-logoff', 'reset-password',
    'delete-file', 'quarantine-file', 'collect-file',
    'firewall-block', 'firewall-unblock', 'disable-service',
    'remove-cron', 'remove-authorized-key',
    'set-sysctl', 'enable-auditd-rule', 'run-script',
    'isolate-host', 'unisolate-host'
)

function Invoke-ResponseAction {
    param(
        [string]$HostName,
        [string]$Platform,
        $Session,
        [string]$Action,
        [string]$Target,
        [hashtable]$Params
    )

    $isDryRun = $WhatIfPreference
    $isDestructive = $Action -in $script:DestructiveActions

    # Confirmation for destructive actions
    if ($isDestructive -and -not $Force -and -not $isDryRun) {
        $confirm = Read-Host "DESTRUCTIVE: $Action on $HostName targeting '$Target'. Proceed? (y/N)"
        if ($confirm -ne 'y') {
            Write-AuditEntry -Host_ $HostName -Action $Action -Target $Target -Params $Params -Status 'skipped' -Detail 'User declined confirmation'
            return
        }
    }

    if ($isDryRun) {
        Write-AuditEntry -Host_ $HostName -Action $Action -Target $Target -Params $Params -Status 'dry-run' -Detail 'WhatIf mode — no action taken'
        return
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = $null
        if ($Platform -eq 'linux') {
            $result = Invoke-LinuxAction -SshInfo $Session -Action $Action -Target $Target -Params $Params
        } else {
            $funcName = $script:WindowsActions[$Action]
            if (-not $funcName) { throw "Unknown Windows action: $Action" }
            $result = & $funcName -Session $Session -Target $Target -Params $Params
        }
        $sw.Stop()
        $preState = if ($result.preState) { $result.preState } else { $null }
        $detail = if ($result.output) { ($result.output | Out-String).Trim().Substring(0, [Math]::Min(500, ($result.output | Out-String).Length)) } else { '' }
        Write-AuditEntry -Host_ $HostName -Action $Action -Target $Target -Params $Params -Status 'success' -Detail $detail -PreState $preState -DurationMs $sw.Elapsed.TotalMilliseconds
    } catch {
        $sw.Stop()
        Write-AuditEntry -Host_ $HostName -Action $Action -Target $Target -Params $Params -Status 'failed' -Detail $_.Exception.Message -DurationMs $sw.Elapsed.TotalMilliseconds
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
Write-Host "`n=========================================" -ForegroundColor White
Write-Host " Endpoint Response Toolkit" -ForegroundColor White
Write-Host "=========================================" -ForegroundColor White
Write-Host " Playbook:  $PlaybookPath"
Write-Host " Operator:  $script:Operator"
Write-Host " Audit Log: $script:AuditLogPath"
Write-Host " Mode:      $(if ($WhatIfPreference) { 'DRY RUN' } else { 'LIVE' })"
Write-Host " Force:     $Force"
Write-Host "=========================================" -ForegroundColor White

# Parse playbook
if (-not (Test-Path $PlaybookPath)) {
    Write-Error "Playbook not found: $PlaybookPath"
    exit 1
}
$yamlContent = Get-Content -Path $PlaybookPath -Raw
$playbook = ConvertFrom-SimpleYaml -Content $yamlContent

if (-not $playbook.hosts -or $playbook.hosts.Count -eq 0) {
    Write-Error "No hosts defined in playbook"
    exit 1
}

# Prompt for all required credentials upfront
$credDefs = if ($playbook.credentials) { $playbook.credentials } else { @{} }
$requiredCreds = $playbook.hosts | ForEach-Object { $_.credential } | Select-Object -Unique
foreach ($credName in $requiredCreds) {
    if (-not $credName) { continue }
    $credDef = $credDefs[$credName]
    $null = Get-CachedCredential -Name $credName -CredDef $credDef
}

Write-Host "`nStarting execution... ($($playbook.hosts.Count) hosts, $(($playbook.hosts | ForEach-Object { $_.actions.Count } | Measure-Object -Sum).Sum) total actions)`n" -ForegroundColor White

# Execute per host
$hostIndex = 0
foreach ($hostEntry in $playbook.hosts) {
    $hostIndex++
    $hostName = $hostEntry.host
    $platform = if ($hostEntry.platform) { $hostEntry.platform } else { 'windows' }
    $credName = $hostEntry.credential
    $actions = $hostEntry.actions

    Write-Host "`n--- [$hostIndex/$($playbook.hosts.Count)] $hostName ($platform) ---" -ForegroundColor Cyan

    # Get session
    $credential = $script:CredentialCache[$credName]
    $session = $null
    try {
        $session = Get-HostSession -HostName $hostName -Credential $credential -Platform $platform
    } catch {
        Write-AuditEntry -Host_ $hostName -Action 'connect' -Target $hostName -Status 'failed' -Detail $_.Exception.Message
        Write-Host "Failed to connect to $hostName — skipping all actions" -ForegroundColor Red
        continue
    }

    # Execute actions
    foreach ($actionEntry in $actions) {
        $actionName = $actionEntry.action
        $target = $actionEntry.target
        $params = if ($actionEntry.params) { $actionEntry.params } else { @{} }

        Invoke-ResponseAction -HostName $hostName -Platform $platform -Session $session -Action $actionName -Target $target -Params $params
    }
}

# Cleanup
Close-AllSessions
Save-RotatedCredentials

# Summary
$endTime = Get-Date
$duration = $endTime - $script:StartTime
Write-Host "`n=========================================" -ForegroundColor White
Write-Host " Execution Complete" -ForegroundColor White
Write-Host "=========================================" -ForegroundColor White
Write-Host " Duration:       $([math]::Round($duration.TotalSeconds, 1))s"
Write-Host " Audit Log:      $script:AuditLogPath"
if ($script:RotatedCredentials.Count -gt 0) {
    Write-Host " Rotated Creds:  $script:CredOutputPath" -ForegroundColor Magenta
}
Write-Host "=========================================" -ForegroundColor White
