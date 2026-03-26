$targetHost = 'mda-s6-4.mda.mil'
$session = New-PSSession -ComputerName $targetHost -Credential $creds
if (!$session) {
    Write-Error "Failed to create a session to $targetHost`n"
    exit
}
$snapshotResults = Invoke-Command -Session $session -ScriptBlock {
    $processInfos = Get-Process -IncludeUserName
    Write-Host ($processInfos[0] | ConvertTo-Json -Depth 1)
}
$snapshotResults
