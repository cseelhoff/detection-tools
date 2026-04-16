$ErrorActionPreference = 'Continue'
Set-Location 'c:\Users\caleb\Source\Repos\detection-tools'
try {
    & '.\windows-collector.ps1' -OutputDir 'c:\Users\caleb\Source\Repos\detection-tools' 2>&1 | Out-File '.\collector-test.log' -Encoding utf8
} catch {
    $_ | Out-File '.\collector-test.log' -Encoding utf8 -Append
}
