# ================================================
# Tanium Password Reset Deploy Script
# Package: "Reset Local User Password (Simple)"
# ================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetHost,
    [Parameter(Mandatory=$true)]
    [string]$TargetUser,
    [Parameter(Mandatory=$true)]
    [string]$NewPassword
)
$SecretKeyRaw = "$TargetHost" + "Team10"
$bytes = [System.Text.Encoding]::UTF8.GetBytes($SecretKeyRaw)
$sha = [System.Security.Cryptography.SHA256]::Create()
$SecretKey = $sha.ComputeHash($bytes)

$ActionName = "API Reset - $TargetUser on $TargetHost"

$ActionGroupId   = 4             # Usually 4 for "All Computers" or default action group
$body = @{
    name         = $ActionName
    comment      = ""
    action_group = @{ id = $ActionGroupId }

    package_spec = @{
        source_id             = 4904
        parameters            = @(
            @{ key = '$1'; value = $SecretKey;   type = 1 }
            @{ key = '$2'; value = $ExcludeUsers -join ",";  type = 1 }
        )
    }
    target_group = @{
        and_flag = $true
        filters  = @(
            @{
                sensor = @{
                    hash = "3409330187" # Computer Name sensor
                }
                operator         = "Equal"
                value            = "$TargetHost"
                value_type       = "String"
                ignore_case_flag = 1
            }
        )
    }
} | ConvertTo-Json -Depth 10
# Build headers
$headers = @{
    "Content-Type" = "application/json"
    "session" = "token-67cdbb3c0a233b733c60f6c2aeac9b8a6b9bee83dc4bfbd3adfcae774f"
}

# API endpoint (Tanium REST API v2)
$uri = "https://ls26bt10-api.cloud.tanium.com/api/v2/actions"

Write-Host "Deploying action to $TargetHost..." -ForegroundColor Cyan

$response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body

try {
    $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body
    # $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body

    Write-Host "SUCCESS!" -ForegroundColor Green
    Write-Host "Action ID: $($response.id)" -ForegroundColor Green
    Write-Host "Action Name: $($response.name)" -ForegroundColor Green
    Write-Host "View progress in Tanium Console → Action History" -ForegroundColor Green
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.ErrorDetails.Message) {
        Write-Host "Response: $($_.ErrorDetails.Message)" -ForegroundColor Red
    }
}