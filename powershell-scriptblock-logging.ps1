$basePath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 
if (-not (Test-Path $basePath)) {     
  $null = New-Item $basePath -Force
  New-ItemProperty $basePath -Name "EnableScriptBlockLogging" -PropertyType Dword 
}
Set-ItemProperty $basePath -Name "EnableScriptBlockLogging" -Value "1"
