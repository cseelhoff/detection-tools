# trusted-host-setup.ps1
# Configures WinRM trusted hosts and tests connectivity to target hosts.
# Run this from a non-domain-joined workstation before using collect-snapshots.ps1.

#Requires -RunAsAdministrator

# Read target hosts
$targetHosts = (Get-Content -Path '.\targetHosts.txt' -Raw).Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)

if ($targetHosts.Count -eq 0) {
    Write-Error "No hosts found in targetHosts.txt"
    exit 1
}

# Build comma-separated list for TrustedHosts
$trustedHostList = $targetHosts -join ','

# Show current TrustedHosts
$currentTrustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
Write-Host "Current TrustedHosts: $currentTrustedHosts" -ForegroundColor Yellow

# Set TrustedHosts
Write-Host "Setting TrustedHosts to: $trustedHostList" -ForegroundColor Cyan
Set-Item WSMan:\localhost\Client\TrustedHosts -Value $trustedHostList -Force
Write-Host "TrustedHosts updated successfully." -ForegroundColor Green

# Prompt for credentials
$creds = Get-Credential -Message "Enter domain credentials for target hosts"

# Test connectivity to each host
Write-Host "`nTesting connectivity to target hosts..." -ForegroundColor Cyan
foreach ($host_ in $targetHosts) {
    Write-Host "`n--- $host_ ---"

    # Test network reachability
    $ping = Test-Connection -ComputerName $host_ -Count 1 -Quiet
    if ($ping) {
        Write-Host "  Ping: OK" -ForegroundColor Green
    } else {
        Write-Host "  Ping: FAILED" -ForegroundColor Red
        continue
    }

    # Test WinRM connectivity
    try {
        $session = New-PSSession -ComputerName $host_ -Credential $creds -ErrorAction Stop
        Write-Host "  PSRemoting: OK" -ForegroundColor Green
        Remove-PSSession $session
    } catch {
        Write-Host "  PSRemoting: FAILED - $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`nSetup complete." -ForegroundColor Green
