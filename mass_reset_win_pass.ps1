# ================================================
# Tanium Password Reset Deploy Script
# Package: "Reset Local User Password (Simple)"
# ================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetHost,
    [Parameter(Mandatory=$true)]
    [string]$MagicWord,
    $ExcludeUsers = @()
)

$ExcludeUsers = @("DefaultAccount", "Guest")
$TargetHost = "DESKTOP-CNOSR7O"
$TargetHost = $TargetHost.ToUpper()
$SecretKeyRaw = "$TargetHost$MagicWord"
$bytes = [System.Text.Encoding]::UTF8.GetBytes($SecretKeyRaw)
$sha = [System.Security.Cryptography.SHA256]::Create()
$hash = $sha.ComputeHash($bytes)
$SecretKey = -join ($hash | ForEach-Object { $_.ToString("x2") })

$ActionName = "Mass Windows Reset - $TargetHost"
$CommaUsers = $ExcludeUsers -join ","
# $CommaUsers = '@("' + ($ExcludeUsers -join '","') + '")'

$ActionGroupId   = 4             # Usually 4 for "All Computers" or default action group
$body = @{
    name         = $ActionName
    comment      = ""
    action_group = @{ id = $ActionGroupId }

    package_spec = @{
        source_id             = 4904
        parameters            = @(
            @{ key = '$1'; value = $SecretKey;   type = 1 }
            @{ key = '$2'; value = $CommaUsers;  type = 1 }
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
$actionId = $response.data.id

Write-Host "Action deployed with ID: $actionId" -ForegroundColor Green
# Parameters for the log retrieval
Start-Sleep -Seconds 5

$LinesToReturn = 100
$QuestionText = "Get Computer Name and Tanium Action Log[$actionId,$LinesToReturn] from all machines with Computer Name equals $TargetHost"

# 1. Create the ad-hoc question
$questionBody = @{
    query_text = $QuestionText
} | ConvertTo-Json

$questionUri = "https://ls26bt10-api.cloud.tanium.com/api/v2/questions"
$questionResponse = Invoke-RestMethod -Uri $questionUri -Method Post -Headers $headers -Body $questionBody
$newQuestionId = $questionResponse.data.id

Write-Host "Question issued (ID: $newQuestionId). Waiting for logs..." -ForegroundColor Cyan

# 2. Poll for results (Wait a few seconds for endpoints to respond)
Start-Sleep -Seconds 5
$resultsUri = "https://ls26bt10-api.cloud.tanium.com/api/v2/result_data/question/$newQuestionId"
$resultsResponse = Invoke-RestMethod -Uri $resultsUri -Method Get -Headers $headers
# $resultsResponse.data.result_sets.rows.data
$logText = $resultsResponse.data.result_sets.rows.data.text | Where-Object { $_ -match '^\d{3}\|' }
$users = $logText |
    ForEach-Object { ($_ -split '\|', 2)[1] } |
    Where-Object { $_ -notmatch '^\d{4}-\d{2}-\d{2}T' -and $_ -notmatch '^(Action |Package |Downloading|Running|Process Group|Command Line|Completed)' }

foreach ($u in $users) {
    $u = $u.ToUpper()
    $raw = "$u$SecretKey"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($raw)
    $hash = $sha.ComputeHash($bytes)
    $hashHex = -join ($hash | ForEach-Object { $_.ToString("x2") })
    $password = $hashHex.Substring(0, 16)
    Write-Host "Password for $TargetHost \ ${u}: $password"
}
