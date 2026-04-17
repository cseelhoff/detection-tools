param(
    [Parameter(Mandatory)]
    [string]$SecretKey,
    [string]$ExcludeUsers
)
$ExcludeUsers = if ($ExcludeUsers) {
    [System.Net.WebUtility]::UrlDecode($ExcludeUsers) -split ","
} else { @() }
$localUsers = Get-LocalUser | Where-Object { $_.Name -notin $ExcludeUsers }
$sha = [System.Security.Cryptography.SHA256]::Create()

foreach ($user in $localUsers) {
    $raw = "$($user.Name.ToUpper())$SecretKey"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($raw)
    $hash = $sha.ComputeHash($bytes)
    $hashHex = -join ($hash | ForEach-Object { $_.ToString("x2") })
    $password = $hashHex.Substring(0, 16)

    $secure = ConvertTo-SecureString $password -AsPlainText -Force
    Set-LocalUser -Name $user.Name -Password $secure
    Write-Host "$($user.Name)"
}
