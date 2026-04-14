<#
.SYNOPSIS
    Inventory module — loads hosts + credentials from inventory.yml / inventory.sops.yml / targetHosts.txt.
.DESCRIPTION
    Provides Get-Inventory which returns a list of resolved host entries, each with:
      - HostName, Platform, CredentialName, Credential (PSCredential or SSH info)
    
    Credential resolution order:
      1. Host-level credential override
      2. Group-level credential
      3. Interactive prompt (with option to save)
    
    File resolution order:
      1. inventory.sops.yml (SOPS-encrypted — requires sops + age key)
      2. inventory.yml (plaintext — warns)
      3. targetHosts.txt (legacy single-credential mode)
#>

# ============================================================================
# YAML Parser (lightweight subset for our inventory schema)
# ============================================================================
function ConvertFrom-InventoryYaml {
    param([string]$Content)
    
    # Try powershell-yaml module first
    try {
        if (Get-Module -ListAvailable -Name powershell-yaml -ErrorAction SilentlyContinue) {
            Import-Module powershell-yaml -ErrorAction Stop
            return ConvertFrom-Yaml $Content
        }
    } catch {}

    # Fallback manual parse
    $result = @{ credentials = @{}; groups = @{}; hosts = [ordered]@{} }
    $lines = $Content -split "`r?`n"
    $currentSection = ''
    $currentItem = ''
    $currentObj = $null

    foreach ($rawLine in $lines) {
        $line = $rawLine -replace '#.*$', ''
        if ($line -match '^\s*$') { continue }
        $indent = ($line -replace '^(\s*).*', '$1').Length

        # Top-level sections
        if ($indent -eq 0 -and $line -match '^(\w[\w-]*):') {
            $currentSection = $Matches[1]
            $currentItem = ''
            $currentObj = $null
            continue
        }

        switch ($currentSection) {
            'credentials' {
                if ($indent -eq 2 -and $line -match '^\s+([\w-]+):') {
                    $currentItem = $Matches[1].Trim()
                    $currentObj = @{}
                    $result.credentials[$currentItem] = $currentObj
                } elseif ($indent -ge 4 -and $null -ne $currentObj -and $line -match '^\s+([\w_]+):\s*(.+)') {
                    $currentObj[$Matches[1].Trim()] = $Matches[2].Trim()
                }
            }
            'groups' {
                if ($indent -eq 2 -and $line -match '^\s+([\w-]+):') {
                    $currentItem = $Matches[1].Trim()
                    $currentObj = @{}
                    $result.groups[$currentItem] = $currentObj
                } elseif ($indent -ge 4 -and $null -ne $currentObj -and $line -match '^\s+([\w_]+):\s*(.+)') {
                    $currentObj[$Matches[1].Trim()] = $Matches[2].Trim()
                }
            }
            'hosts' {
                if ($indent -eq 2 -and $line -match '^\s+([\w.\-]+):') {
                    $currentItem = $Matches[1].Trim()
                    $currentObj = @{}
                    $result.hosts[$currentItem] = $currentObj
                } elseif ($indent -ge 4 -and $null -ne $currentObj -and $line -match '^\s+([\w_]+):\s*(.+)') {
                    $currentObj[$Matches[1].Trim()] = $Matches[2].Trim()
                }
            }
        }
    }
    return $result
}

# ============================================================================
# SOPS Decryption
# ============================================================================
function Invoke-SopsDecrypt {
    param([string]$FilePath)
    
    $sopsCmd = Get-Command sops -ErrorAction SilentlyContinue
    if (-not $sopsCmd) {
        Write-Error "sops not found in PATH. Install from https://github.com/getsops/sops or use plaintext inventory.yml"
        return $null
    }
    
    try {
        $json = & sops --decrypt --output-type json $FilePath 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Error "sops decrypt failed: $json"
            return $null
        }
        return $json | ConvertFrom-Json -AsHashtable
    } catch {
        Write-Error "sops decrypt error: $($_.Exception.Message)"
        return $null
    }
}

# ============================================================================
# Save credentials back to inventory (SOPS or plaintext)
# ============================================================================
function Save-InventoryCredential {
    param(
        [string]$InventoryPath,
        [string]$HostName,
        [string]$CredentialName,
        [hashtable]$CredentialDef,
        [string]$GroupName = ''
    )
    
    $isSops = $InventoryPath -match '\.sops\.'
    
    if ($isSops) {
        # For SOPS files, decrypt → modify → re-encrypt
        $sopsCmd = Get-Command sops -ErrorAction SilentlyContinue
        if (-not $sopsCmd) {
            Write-Host "  Cannot auto-save: sops not available" -ForegroundColor Yellow
            return $false
        }
        try {
            # Decrypt to temp
            $tempFile = [System.IO.Path]::GetTempFileName() + ".yml"
            & sops --decrypt $InventoryPath > $tempFile 2>$null
            if ($LASTEXITCODE -ne 0) {
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                return $false
            }
            $content = Get-Content $tempFile -Raw
            
            # Add credential definition if not exists
            if ($content -notmatch "^\s+${CredentialName}:" ) {
                $credBlock = "`n  ${CredentialName}:`n"
                foreach ($k in $CredentialDef.Keys) {
                    $credBlock += "    ${k}: $($CredentialDef[$k])`n"
                }
                $content = $content -replace '(credentials:)', "`$1$credBlock"
            }
            
            # Update host to reference credential
            if ($content -match "^\s+${HostName}:" ) {
                # Host exists — add/update credential line
                $content = $content -replace "(  ${HostName}:.*?)(\n  \S)", "`$1`n    credential: ${CredentialName}`$2"
            }
            
            Set-Content $tempFile -Value $content -NoNewline
            # Re-encrypt
            $ageRecipients = $env:SOPS_AGE_RECIPIENTS
            if (-not $ageRecipients) {
                # Try to read from existing file's sops metadata
                $ageRecipients = & sops --decrypt --extract '["sops"]["age"]' $InventoryPath 2>$null
            }
            & sops --encrypt --in-place $tempFile 2>$null
            if ($LASTEXITCODE -eq 0) {
                Copy-Item $tempFile $InventoryPath -Force
            }
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            return $true
        } catch {
            return $false
        }
    } else {
        # Plaintext inventory — direct YAML append/modify
        try {
            $content = Get-Content $InventoryPath -Raw
            
            # Add credential if not exists
            if ($content -notmatch "  ${CredentialName}:") {
                $credBlock = "  ${CredentialName}:`n"
                foreach ($k in $CredentialDef.Keys) {
                    $credBlock += "    ${k}: $($CredentialDef[$k])`n"
                }
                $content = $content -replace '(credentials:\s*\n)', "`$1$credBlock"
            }
            
            # Update host's credential reference
            if ($content -match "  ${HostName}:") {
                # Check if credential line already exists under this host
                if ($content -match "  ${HostName}:\s*\n(    \w+:.*\n)*    credential:") {
                    $content = $content -replace "(  ${HostName}:.*\n(?:    \w+:.*\n)*    )credential:\s*\S+", "`${1}credential: ${CredentialName}"
                } else {
                    $content = $content -replace "(  ${HostName}:\s*\n)", "`$1    credential: ${CredentialName}`n"
                }
            } else {
                # Add host entry
                $content = $content.TrimEnd() + "`n  ${HostName}:`n    credential: ${CredentialName}`n"
            }
            
            Set-Content $InventoryPath -Value $content -NoNewline
            return $true
        } catch {
            return $false
        }
    }
}

# ============================================================================
# Interactive Credential Prompt
# ============================================================================
function Request-CredentialInteractive {
    param(
        [string[]]$UnresolvedHosts,
        [string]$InventoryPath,
        [hashtable]$Inventory
    )
    
    $results = @{}  # hostname → { CredentialName, Credential, CredDef, Platform }
    
    if ($UnresolvedHosts.Count -eq 0) { return $results }
    
    Write-Host "`n  ┌─────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "  │  Credentials needed for $($UnresolvedHosts.Count) host(s)               │" -ForegroundColor Cyan
    Write-Host "  └─────────────────────────────────────────────────┘" -ForegroundColor Cyan
    
    foreach ($h in $UnresolvedHosts) {
        Write-Host "    - $h" -ForegroundColor White
    }
    
    $applyMode = 'individual'
    if ($UnresolvedHosts.Count -gt 1) {
        Write-Host ""
        Write-Host "  Options:" -ForegroundColor Yellow
        Write-Host "    [1] Enter ONE set of credentials for ALL $($UnresolvedHosts.Count) hosts" -ForegroundColor White
        Write-Host "    [2] Enter credentials individually per host" -ForegroundColor White
        Write-Host "    [3] Skip these hosts" -ForegroundColor White
        $choice = Read-Host "  Choice (1/2/3)"
        switch ($choice) {
            '1' { $applyMode = 'shared' }
            '3' { return $results }
            default { $applyMode = 'individual' }
        }
    }
    
    $sharedCred = $null
    $sharedCredDef = $null
    $sharedCredName = $null
    $sharedPlatform = $null
    
    if ($applyMode -eq 'shared') {
        Write-Host ""
        Write-Host "  Platform for these hosts:" -ForegroundColor Yellow
        Write-Host "    [1] Windows (WinRM/PSRemoting)" -ForegroundColor White
        Write-Host "    [2] Linux (SSH with password)" -ForegroundColor White
        Write-Host "    [3] Linux (SSH with key)" -ForegroundColor White
        $platChoice = Read-Host "  Choice (1/2/3)"
        
        switch ($platChoice) {
            '1' {
                $sharedPlatform = 'windows'
                $cred = Get-Credential -Message "Enter Windows credentials for all $($UnresolvedHosts.Count) hosts"
                $sharedCred = $cred
                $sharedCredName = "auto-winrm-$($cred.UserName -replace '[\\@\.]', '-')"
                $sharedCredDef = @{
                    type = 'winrm'
                    username = $cred.UserName
                    password = $cred.GetNetworkCredential().Password
                }
            }
            '2' {
                $sharedPlatform = 'linux'
                $cred = Get-Credential -Message "Enter SSH credentials for all $($UnresolvedHosts.Count) hosts"
                $sharedCred = $cred
                $sharedCredName = "auto-ssh-$($cred.UserName -replace '[\\@\.]', '-')"
                $sharedCredDef = @{
                    type = 'ssh-password'
                    username = $cred.UserName
                    password = $cred.GetNetworkCredential().Password
                }
            }
            '3' {
                $sharedPlatform = 'linux'
                $keyPath = Read-Host "  SSH key file path"
                $username = Read-Host "  SSH username"
                $sharedCred = @{ UserName = $username; KeyFile = $keyPath }
                $sharedCredName = "auto-sshkey-$($username -replace '[\\@\.]', '-')"
                $sharedCredDef = @{
                    type = 'ssh-key'
                    username = $username
                    key_file = $keyPath
                }
            }
        }
        
        foreach ($h in $UnresolvedHosts) {
            $results[$h] = @{
                CredentialName = $sharedCredName
                Credential     = $sharedCred
                CredDef        = $sharedCredDef
                Platform       = $sharedPlatform
            }
        }
    } else {
        # Individual per host
        foreach ($h in $UnresolvedHosts) {
            Write-Host "`n  Credentials for: $h" -ForegroundColor Cyan
            Write-Host "    [1] Windows (WinRM)  [2] SSH password  [3] SSH key  [4] Skip" -ForegroundColor Yellow
            $pc = Read-Host "    Choice"
            
            switch ($pc) {
                '1' {
                    $cred = Get-Credential -Message "Windows credentials for $h"
                    $credName = "auto-winrm-$h"
                    $results[$h] = @{
                        CredentialName = $credName
                        Credential     = $cred
                        CredDef        = @{ type = 'winrm'; username = $cred.UserName; password = $cred.GetNetworkCredential().Password }
                        Platform       = 'windows'
                    }
                }
                '2' {
                    $cred = Get-Credential -Message "SSH credentials for $h"
                    $credName = "auto-ssh-$h"
                    $results[$h] = @{
                        CredentialName = $credName
                        Credential     = $cred
                        CredDef        = @{ type = 'ssh-password'; username = $cred.UserName; password = $cred.GetNetworkCredential().Password }
                        Platform       = 'linux'
                    }
                }
                '3' {
                    $keyPath = Read-Host "    SSH key file path"
                    $username = Read-Host "    SSH username"
                    $credName = "auto-sshkey-$h"
                    $results[$h] = @{
                        CredentialName = $credName
                        Credential     = @{ UserName = $username; KeyFile = $keyPath }
                        CredDef        = @{ type = 'ssh-key'; username = $username; key_file = $keyPath }
                        Platform       = 'linux'
                    }
                }
            }
        }
    }
    
    # Ask if user wants to save
    if ($results.Count -gt 0 -and $InventoryPath) {
        Write-Host ""
        $save = Read-Host "  Save these credentials for future unattended use? (y/N)"
        if ($save -eq 'y') {
            $savedCount = 0
            # Deduplicate credential definitions
            $savedCredNames = @{}
            foreach ($h in $results.Keys) {
                $r = $results[$h]
                $credName = $r.CredentialName
                if (-not $savedCredNames.ContainsKey($credName)) {
                    $savedCredNames[$credName] = $true
                }
                $ok = Save-InventoryCredential -InventoryPath $InventoryPath -HostName $h -CredentialName $credName -CredentialDef $r.CredDef
                if ($ok) { $savedCount++ }
            }
            Write-Host "  Saved credentials for $savedCount host(s) to $InventoryPath" -ForegroundColor Green
        }
    }
    
    return $results
}

# ============================================================================
# Mark credential as failed (prevent auto-save association)
# ============================================================================
$script:FailedCredentials = @{}

function Set-CredentialFailed {
    param([string]$HostName, [string]$CredentialName)
    $script:FailedCredentials[$HostName] = $CredentialName
    Write-Host "  Credential '$CredentialName' failed for $HostName — will NOT be auto-saved" -ForegroundColor Red
}

# ============================================================================
# Main: Get-Inventory
# ============================================================================
function Get-Inventory {
    <#
    .SYNOPSIS
        Load and resolve inventory from inventory.sops.yml, inventory.yml, or targetHosts.txt.
    .OUTPUTS
        Array of objects: HostName, Platform, CredentialName, Credential, AuthType
    #>
    param(
        [string]$Path = ''  # Override inventory file path
    )
    
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
    
    # ---- Locate inventory file ----
    $inventoryPath = $null
    $inventory = $null
    
    if ($Path -and (Test-Path $Path)) {
        $inventoryPath = $Path
    } else {
        # Auto-discover
        $candidates = @(
            (Join-Path $scriptDir 'inventory.sops.yml'),
            (Join-Path $scriptDir 'inventory.sops.yaml'),
            (Join-Path $scriptDir 'inventory.yml'),
            (Join-Path $scriptDir 'inventory.yaml')
        )
        foreach ($c in $candidates) {
            if (Test-Path $c) {
                $inventoryPath = $c
                break
            }
        }
    }
    
    # ---- Load inventory ----
    if ($inventoryPath -and (Test-Path $inventoryPath)) {
        $isSops = $inventoryPath -match '\.sops\.'
        
        if ($isSops) {
            Write-Host "  Loading encrypted inventory: $inventoryPath" -ForegroundColor Cyan
            $inventory = Invoke-SopsDecrypt -FilePath $inventoryPath
        } else {
            Write-Host "  Loading inventory: $inventoryPath" -ForegroundColor Cyan
            Write-Host "  WARNING: Inventory is NOT encrypted. Consider using SOPS." -ForegroundColor Yellow
            $content = Get-Content $inventoryPath -Raw
            $inventory = ConvertFrom-InventoryYaml -Content $content
        }
    }
    
    # ---- Fallback: legacy targetHosts.txt ----
    if (-not $inventory -or -not $inventory.hosts -or $inventory.hosts.Count -eq 0) {
        $legacyPath = Join-Path $scriptDir 'targetHosts.txt'
        if (Test-Path $legacyPath) {
            Write-Host "  Falling back to legacy targetHosts.txt" -ForegroundColor Yellow
            $hosts = (Get-Content $legacyPath -Raw).Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries) | Where-Object { $_ -and $_ -notmatch '^\s*#' }
            
            # All hosts are unresolved — prompt interactively
            $interactiveResults = Request-CredentialInteractive -UnresolvedHosts $hosts -InventoryPath $null -Inventory $null
            
            $entries = @()
            foreach ($h in $hosts) {
                if ($interactiveResults.ContainsKey($h)) {
                    $r = $interactiveResults[$h]
                    $entries += [PSCustomObject]@{
                        HostName       = $h
                        Platform       = $r.Platform
                        CredentialName = $r.CredentialName
                        Credential     = $r.Credential
                        AuthType       = $r.CredDef.type
                        KeyFile        = $r.CredDef.key_file
                    }
                }
            }
            return $entries
        }
        
        Write-Error "No inventory file or targetHosts.txt found"
        return @()
    }
    
    # ---- Resolve credentials for each host ----
    $credentials = if ($inventory.credentials) { $inventory.credentials } else { @{} }
    $groups = if ($inventory.groups) { $inventory.groups } else { @{} }
    $hostEntries = $inventory.hosts
    
    $resolvedEntries = @()
    $unresolvedHosts = @()
    $credentialCache = @{}  # credName → PSCredential
    
    foreach ($hostName in $hostEntries.Keys) {
        $hostDef = $hostEntries[$hostName]
        if (-not $hostDef) { $hostDef = @{} }
        
        # Resolve platform and credential name via group inheritance
        $groupName = $hostDef.group
        $groupDef = if ($groupName -and $groups.ContainsKey($groupName)) { $groups[$groupName] } else { @{} }
        
        $platform = $hostDef.platform
        if (-not $platform) { $platform = $groupDef.platform }
        if (-not $platform) { $platform = 'windows' }
        
        $credName = $hostDef.credential
        if (-not $credName) { $credName = $groupDef.credential }
        
        if ($credName -and $credentials.ContainsKey($credName)) {
            $credDef = $credentials[$credName]
            $authType = $credDef.type
            $keyFile = $credDef.key_file
            
            # Build PSCredential or SSH info
            if (-not $credentialCache.ContainsKey($credName)) {
                if ($authType -eq 'ssh-key') {
                    $credentialCache[$credName] = @{
                        UserName = $credDef.username
                        KeyFile  = $keyFile
                    }
                } else {
                    $secPw = ConvertTo-SecureString $credDef.password -AsPlainText -Force
                    $credentialCache[$credName] = [PSCredential]::new($credDef.username, $secPw)
                }
            }
            
            $resolvedEntries += [PSCustomObject]@{
                HostName       = $hostName
                Platform       = $platform.ToLower()
                CredentialName = $credName
                Credential     = $credentialCache[$credName]
                AuthType       = $authType
                KeyFile        = $keyFile
            }
        } else {
            $unresolvedHosts += $hostName
        }
    }
    
    # ---- Handle unresolved hosts ----
    if ($unresolvedHosts.Count -gt 0) {
        $interactiveResults = Request-CredentialInteractive -UnresolvedHosts $unresolvedHosts -InventoryPath $inventoryPath -Inventory $inventory
        
        foreach ($h in $unresolvedHosts) {
            if ($interactiveResults.ContainsKey($h)) {
                $r = $interactiveResults[$h]
                $resolvedEntries += [PSCustomObject]@{
                    HostName       = $h
                    Platform       = $r.Platform
                    CredentialName = $r.CredentialName
                    Credential     = $r.Credential
                    AuthType       = $r.CredDef.type
                    KeyFile        = $r.CredDef.key_file
                }
            }
        }
    }
    
    # ---- Summary ----
    $winCount = ($resolvedEntries | Where-Object { $_.Platform -eq 'windows' }).Count
    $linCount = ($resolvedEntries | Where-Object { $_.Platform -eq 'linux' }).Count
    $credNames = ($resolvedEntries | Select-Object -ExpandProperty CredentialName -Unique)
    Write-Host "`n  Inventory loaded: $($resolvedEntries.Count) hosts ($winCount Windows, $linCount Linux), $($credNames.Count) credential set(s)" -ForegroundColor Green
    
    return $resolvedEntries
}
