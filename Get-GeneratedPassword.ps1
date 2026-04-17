param(
    [Parameter(Mandatory)]
    [string]$Username,
    [Parameter(Mandatory)]
    [string]$SecretKey
)
$raw = $Username.ToUpper() + $SecretKey
$bytes = [System.Text.Encoding]::UTF8.GetBytes($raw)
$sha = [System.Security.Cryptography.SHA256]::Create()
$hash = $sha.ComputeHash($bytes)
$hashHex = -join ($hash | ForEach-Object { $_.ToString("x2") })
$password = $hashHex.Substring(0, 16)
Write-Host "Password for ${Username}: $password"
