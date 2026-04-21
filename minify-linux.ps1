param(
    [string]$InputFile  = '.\Reset-LocalLinuxPasswords.sh',
    [string]$OutputFile = '.\tanium-mini-linux.sh'
)

# Normalize line endings to LF so the decoded payload runs cleanly on Linux
# regardless of how git/editors saved the source file.
$text  = [IO.File]::ReadAllText((Resolve-Path $InputFile)) -replace "`r`n", "`n" -replace "`r", "`n"
$bytes = [Text.Encoding]::UTF8.GetBytes($text)
$b64   = [Convert]::ToBase64String($bytes)

$line = "/bin/bash -c `"echo $b64 | base64 -d | /bin/bash -s '`$1' '`$2'`""

Set-Content -Path $OutputFile -Value $line -Encoding ascii -NoNewline
Write-Host "Wrote $OutputFile ($($line.Length) chars, payload $($bytes.Length) bytes)"
