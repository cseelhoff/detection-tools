<#
.SYNOPSIS
    Local-only test — runs the snapshot collection logic directly on this machine
    without PSRemoting. Outputs system-info_localhost.json.
.DESCRIPTION
    Extracts and executes the same data collection code from collect-snapshots.ps1
    but runs it locally. Useful for testing/development.
.EXAMPLE
    .\test-local-collection.ps1
#>

Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host " Local Snapshot Collection Test" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Host: $env:COMPUTERNAME (localhost)" -ForegroundColor White
Write-Host " Time: $(Get-Date)" -ForegroundColor White
Write-Host "=========================================" -ForegroundColor Cyan

$sw = [System.Diagnostics.Stopwatch]::StartNew()

# ---- Collection (same code as the remote scriptblock) ----
Write-Host "`n[1/3] Collecting system data..." -ForegroundColor Yellow

$systemUUID = Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
$computerInfo = Get-ComputerInfo | Select-Object -Property CsName, CsDNSHostName, CsDomain, CsManufacturer, CsModel, CsPartOfDomain, @{Name='CsPCSystemType'; Expression={$_.CsPCSystemType.ToString()}}, OsName, @{Name='OsType'; Expression={$_.OsType.ToString()}}, OsVersion, OsSystemDrive, OsLastBootUpTime

Write-Host "  ComputerInfo: $($computerInfo.CsName) / $($computerInfo.OsName)" -ForegroundColor Gray
$diskVolumes = Get-Volume | Select-Object -Property UniqueId, DriveLetter, DriveType, Size, FileSystemLabel, FileSystem
Write-Host "  DiskVolumes: $($diskVolumes.Count)" -ForegroundColor Gray
$netAdapters1 = Get-NetAdapter -IncludeHidden | Select-Object -Property MacAddress, Status, PhysicalMediaType, InterfaceIndex, Name, InterfaceDescription
$dnsSettings = Get-DnsClient | Select-Object -Property InterfaceIndex, ConnectionSpecificSuffix, ConnectionSpecificSuffixSearchList, RegisterThisConnectionsAddress
$netAdapters = New-Object System.Collections.ArrayList
foreach($netAdapter in $netAdapters1) {
    $connectionSpecificSuffix = $dnsSettings | Where-Object {$_.InterfaceIndex -eq $netAdapter.InterfaceIndex} | Select-Object -ExpandProperty ConnectionSpecificSuffix
    if ($null -eq $connectionSpecificSuffix) { $connectionSpecificSuffix = "" } else { $connectionSpecificSuffix = $connectionSpecificSuffix.ToString() }
    $registerThisConnectionsAddress = $dnsSettings | Where-Object {$_.InterfaceIndex -eq $netAdapter.InterfaceIndex} | Select-Object -ExpandProperty RegisterThisConnectionsAddress | Where-Object {$_ -eq $true}
    if ($null -eq $registerThisConnectionsAddress -or "" -eq $registerThisConnectionsAddress) { $registerThisConnectionsAddress = $false } else { $registerThisConnectionsAddress = [System.Convert]::ToBoolean($registerThisConnectionsAddress) }
    $null = $netAdapters.Add([PSCustomObject]@{ MacAddress = $netAdapter.MacAddress; Status = $netAdapter.Status; PhysicalMediaType = $netAdapter.PhysicalMediaType; InterfaceIndex = $netAdapter.InterfaceIndex; Name = $netAdapter.Name; InterfaceDescription = $netAdapter.InterfaceDescription; ConnectionSpecificSuffix = $connectionSpecificSuffix; RegisterThisConnectionsAddress = $registerThisConnectionsAddress })
}
Write-Host "  NetAdapters: $($netAdapters.Count)" -ForegroundColor Gray

$ipAddresses = Get-NetIPAddress | Select-Object -Property InterfaceIndex, IPAddress, PrefixLength, @{Name='AddressFamily'; Expression={$_.AddressFamily.ToString()}}, @{Name='Type'; Expression={$_.Type.ToString()}}, SkipAsSource, @{Name='ValidLifetimeTicks'; Expression={$_.ValidLifetime.Ticks}}
$dnsServers1 = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -Property InterfaceIndex, ServerAddresses
$dnsServers = New-Object System.Collections.ArrayList
foreach ($dnsServer in $dnsServers1) {
    foreach ($serverAddress in $dnsServer.ServerAddresses) {
        $null = $dnsServers.Add([PSCustomObject]@{ InterfaceIndex = $dnsServer.InterfaceIndex; ServerAddress = $serverAddress })
    }
}
$arpCache = Get-NetNeighbor | Select-Object -Property InterfaceIndex, IPAddress, LinkLayerAddress, @{Name='State'; Expression={$_.State.ToString()}}
$routes = Get-NetRoute | Select-Object -Property InterfaceIndex, @{Name='Protocol'; Expression={$_.Protocol.ToString()}}, @{Name='AddressFamily'; Expression={$_.AddressFamily.Value}}, DestinationPrefix, NextHop, RouteMetric
$tcpConnections = Get-NetTCPConnection | Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, CreationTime, @{Name='State'; Expression={$_.State.ToString()}}
$udpConnections = Get-NetUDPEndpoint | Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, CreationTime

Write-Host "  Network data collected" -ForegroundColor Gray

$processInfos = Get-Process -IncludeUserName
$parentProcesses = Get-WmiObject -Class Win32_Process | Select-Object ProcessId, ParentProcessId, CommandLine
$processes = New-Object System.Collections.ArrayList
foreach ($process in $processInfos) {
    $processInfo = [PSCustomObject]@{
        ProcessName = $process.Name; UserName = $process.UserName; CreationDate = $process.StartTime; ProcessId = $process.Id
        ParentProcessId = ($parentProcesses | Where-Object { $_.ProcessId -eq $process.Id }).ParentProcessId
        CommandLine = ($parentProcesses | Where-Object { $_.ProcessId -eq $process.Id }).CommandLine
        ExecutablePath = $process.Path
    }
    $processes.Add($processInfo) | Out-Null
}
Write-Host "  Processes: $($processes.Count)" -ForegroundColor Gray

$users = Get-LocalUser | Select-Object -Property Name, Enabled, LastLogon, PasswordLastSet, @{Name='PrincipalSource'; Expression={$_.PrincipalSource.Value}}, @{Name='SID'; Expression={$_.SID.Value}}
$groups = Get-LocalGroup | Select-Object -Property Name, @{Name='SID'; Expression={$_.SID.Value}}
$members = New-Object System.Collections.ArrayList
foreach ($group in $groups) {
    try {
        $membersInGroup = $group | Get-LocalGroupMember -ErrorAction SilentlyContinue | Select-Object -Property @{Name='SID'; Expression={$_.SID.Value}}
        foreach ($member in $membersInGroup) {
            $null = $members.Add([PSCustomObject]@{ UserSID = $member.SID; GroupSID = $group.SID })
        }
    } catch {}
}
Write-Host "  Users: $($users.Count), Groups: $($groups.Count)" -ForegroundColor Gray

$shares = Get-SmbShare | Select-Object -Property Name, Path, ScopeName

# ---- Security Products ----
Write-Host "  Collecting security products..." -ForegroundColor Gray
$securityProducts = New-Object System.Collections.ArrayList
try {
    $avProducts = Get-WmiObject -Namespace 'root\SecurityCenter2' -Class AntiVirusProduct -ErrorAction Stop
    foreach ($av in $avProducts) {
        $stateHex = '{0:X6}' -f $av.productState
        $enabledByte = [int]"0x$($stateHex.Substring(2,2))"
        $defsByte = [int]"0x$($stateHex.Substring(4,2))"
        $null = $securityProducts.Add([PSCustomObject]@{ Type='AntiVirus'; DisplayName=$av.displayName; Enabled=($enabledByte -band 0x10) -ne 0; DefinitionsUpToDate=($defsByte -eq 0x00) })
    }
} catch {}
$defenderStatus = $null
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    $defenderStatus = [PSCustomObject]@{
        AMServiceEnabled=$mpStatus.AMServiceEnabled; AntivirusEnabled=$mpStatus.AntivirusEnabled
        RealTimeProtectionEnabled=$mpStatus.RealTimeProtectionEnabled; BehaviorMonitorEnabled=$mpStatus.BehaviorMonitorEnabled
        OnAccessProtectionEnabled=$mpStatus.OnAccessProtectionEnabled; AntivirusSignatureVersion=$mpStatus.AntivirusSignatureVersion
        AMRunningMode=$(try { $mpStatus.AMRunningMode } catch { $null })
    }
} catch {}

# ---- Audit Policies ----
Write-Host "  Collecting audit policies..." -ForegroundColor Gray
$auditPolicies = $null
try {
    $auditPolOutput = & auditpol /get /category:* /r 2>$null
    if ($auditPolOutput) { $auditPolicies = $auditPolOutput | ConvertFrom-Csv | Select-Object -Property 'Subcategory', 'Subcategory GUID', 'Inclusion Setting' }
} catch {}

# ---- Installed Apps ----
Write-Host "  Collecting installed apps..." -ForegroundColor Gray
$installedApps = $null
try {
    $installedApps = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } | Select-Object -Property DisplayName, DisplayVersion, Publisher, InstallDate
} catch {}

# ---- Hotfixes ----
$installedHotfixes = $null
try { $installedHotfixes = Get-HotFix -ErrorAction SilentlyContinue | Select-Object HotFixID, Description, InstalledOn } catch {}

# ---- Token Privileges ----
$tokenPrivileges = $null
try { $tokenPrivileges = & whoami /priv /fo csv 2>$null | ConvertFrom-Csv } catch {}

# ---- Named Pipes ----
Write-Host "  Collecting named pipes..." -ForegroundColor Gray
$namedPipes = $null
try {
    $namedPipes = [System.IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object {
        [PSCustomObject]@{ Name = ($_ -replace '^\\\\.\\pipe\\','') }
    }
} catch {}

# ---- Environment Variables ----
$environmentVariables = Get-ChildItem Env: | Select-Object -Property Name, Value

# ---- Firewall ----
Write-Host "  Collecting firewall..." -ForegroundColor Gray
$firewallProfiles = $null
try { $firewallProfiles = Get-NetFirewallProfile | Select-Object -Property Name, Enabled, DefaultInboundAction, DefaultOutboundAction } catch {}

# ---- Logged On Users ----
$loggedOnUsers = New-Object System.Collections.ArrayList
try {
    $quserOutput = query user 2>&1
    foreach ($line in ($quserOutput | Select-Object -Skip 1)) {
        $lineStr = $line.ToString()
        if ($lineStr -match '^\s*>?\s*(\S+)\s+(\S+)?\s+(\d+)\s+(Active|Disc)') {
            $null = $loggedOnUsers.Add([PSCustomObject]@{ UserName=$Matches[1]; SessionName=$Matches[2]; State=$Matches[4] })
        }
    }
} catch {}

# Skip autorunsc (requires separate exe), MFT scan, registry watchlist, ACLs, etc. for speed
# These are tested via the full remote collection path

Write-Host "`n[2/3] Building snapshot object..." -ForegroundColor Yellow

$dateTimeFinished = Get-Date
$snapshot = [PSCustomObject]@{
    SystemUUID = $systemUUID
    SnapshotTime = $dateTimeFinished
    ComputerInfo = $computerInfo
    DiskVolumes = $diskVolumes
    NetAdapters = $netAdapters
    DnsServers = $dnsServers
    IpAddresses = $ipAddresses
    ArpCache = $arpCache
    Routes = $routes
    TcpConnections = $tcpConnections
    UdpConnections = $udpConnections
    Processes = $processes
    Users = $users
    Groups = $groups
    Members = $members
    Shares = $shares
    SecurityProducts = $securityProducts
    DefenderStatus = $defenderStatus
    AuditPolicies = $auditPolicies
    InstalledApps = $installedApps
    InstalledHotfixes = $installedHotfixes
    TokenPrivileges = $tokenPrivileges
    NamedPipes = $namedPipes
    EnvironmentVariables = $environmentVariables
    FirewallProfiles = $firewallProfiles
    LoggedOnUsers = $loggedOnUsers
}

$outputFile = ".\system-info_localhost.json"
Write-Host "`n[3/3] Saving to $outputFile..." -ForegroundColor Yellow
$snapshot | ConvertTo-Json -Depth 9 | Out-File -FilePath $outputFile -Encoding utf8

$sw.Stop()
$fileSize = [math]::Round((Get-Item $outputFile).Length / 1KB, 1)

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host " Collection Complete!" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host " Duration:  $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" -ForegroundColor White
Write-Host " Output:    $outputFile ($fileSize KB)" -ForegroundColor White
Write-Host " Fields:    $($snapshot.PSObject.Properties.Count)" -ForegroundColor White
Write-Host "=========================================" -ForegroundColor Green
Write-Host ""
Write-Host "To analyze: python analyze-snapshots.py $outputFile" -ForegroundColor Cyan
Write-Host ""
