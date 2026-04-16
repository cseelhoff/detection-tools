<#
.SYNOPSIS
    Windows Collector - Standalone endpoint data collection script.
.DESCRIPTION
    Collects comprehensive Windows system state and saves as JSON.
    Can be run directly, deployed via PSRemoting, or uploaded via SSH+SFTP.
.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File windows-collector.ps1
    powershell.exe -ExecutionPolicy Bypass -File windows-collector.ps1 -OutputDir C:\Temp
#>
param(
    [string]$OutputDir = $env:TEMP
)
$ErrorActionPreference = 'Continue'
Write-Host "Windows Collector starting on $($env:COMPUTERNAME)..."
Write-Host "Output directory: $OutputDir"
$snapshot = & {
$systemUUID = Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
#write-host 'compinfo'
$computerInfo = Get-ComputerInfo | Select-Object -Property CsName, CsDNSHostName, CsDomain, CsManufacturer, CsModel, CsPartOfDomain, @{Name='CsPCSystemType'; Expression={$_.CsPCSystemType.ToString()}}, OsName, @{Name='OsType'; Expression={$_.OsType.ToString()}}, OsVersion, OsSystemDrive, OsLastBootUpTime
#write-host $computerInfo
$diskVolumes = Get-Volume | Select-Object -Property UniqueId, DriveLetter, DriveType, Size, FileSystemLabel, FileSystem
$netAdapters1 = Get-NetAdapter -IncludeHidden | Select-Object -Property MacAddress, Status, PhysicalMediaType, InterfaceIndex, Name, InterfaceDescription
$dnsSettings = Get-DnsClient | Select-Object -Property InterfaceIndex, ConnectionSpecificSuffix, ConnectionSpecificSuffixSearchList, RegisterThisConnectionsAddress
$netAdapters = New-Object System.Collections.ArrayList
foreach($netAdapter in $netAdapters1) {
    $connectionSpecificSuffix = $dnsSettings | Where-Object {$_.InterfaceIndex -eq $netAdapter.InterfaceIndex} | Select-Object -ExpandProperty ConnectionSpecificSuffix
    if ($null -eq $connectionSpecificSuffix)
    {
        $connectionSpecificSuffix = ""
    } else {
        $connectionSpecificSuffix = $connectionSpecificSuffix.ToString()
    }
    $registerThisConnectionsAddress = $dnsSettings | Where-Object {$_.InterfaceIndex -eq $netAdapter.InterfaceIndex} | Select-Object -ExpandProperty RegisterThisConnectionsAddress | Where-Object {$_ -eq $true}
    if ($null -eq $registerThisConnectionsAddress -or "" -eq $registerThisConnectionsAddress) {
        $registerThisConnectionsAddress = $false
    } else {
        $registerThisConnectionsAddress = [System.Convert]::ToBoolean($registerThisConnectionsAddress)
    }
    $null = $netAdapters.Add(
        [PSCustomObject]@{
            MacAddress = $netAdapter.MacAddress
            Status = $netAdapter.Status
            PhysicalMediaType = $netAdapter.PhysicalMediaType
            InterfaceIndex = $netAdapter.InterfaceIndex
            Name = $netAdapter.Name
            InterfaceDescription = $netAdapter.InterfaceDescription
            ConnectionSpecificSuffix = $connectionSpecificSuffix
            RegisterThisConnectionsAddress = $registerThisConnectionsAddress
        }
    )
}
$dnsSearchSuffixes = New-Object System.Collections.ArrayList
foreach ($dnsSetting in $dnsSettings) {
    foreach ($SuffixSearch in $dnsSetting.ConnectionSpecificSuffixSearchList) {
        $null = $dnsSearchSuffixes.Add(
            [PSCustomObject]@{
                InterfaceIndex = $dnsSetting.InterfaceIndex
                SuffixSearch = $cSuffixSearch
            }
        )
    }
}
$dnsServers1 = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -Property InterfaceIndex, ServerAddresses
$dnsServers = New-Object System.Collections.ArrayList
foreach ($dnsServer in $dnsServers1) {
    foreach ($serverAddress in $dnsServer.ServerAddresses) {
        $null = $dnsServers.Add(
            [PSCustomObject]@{
                InterfaceIndex = $dnsServer.InterfaceIndex
                ServerAddress = $serverAddress
            }
        )
    }
}
$ipAddresses = Get-NetIPAddress | Select-Object -Property InterfaceIndex, IPAddress, PrefixLength, @{Name='AddressFamily'; Expression={$_.AddressFamily.ToString()}},  @{Name='Type'; Expression={$_.Type.ToString()}}, SkipAsSource, @{Name='ValidLifetimeTicks'; Expression={$_.ValidLifetime.Ticks}}
$arpCache = Get-NetNeighbor | Select-Object -Property InterfaceIndex, IPAddress, LinkLayerAddress, @{Name='State'; Expression={$_.State.ToString()}}
$routes = Get-NetRoute | Select-Object -Property InterfaceIndex, @{Name='Protocol'; Expression={$_.Protocol.ToString()}}, @{Name='AddressFamily'; Expression={$_.AddressFamily.Value}}, DestinationPrefix, NextHop, RouteMetric
$tcpConnections = Get-NetTCPConnection | Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, CreationTime, @{Name='State'; Expression={$_.State.ToString()}}
$udpConnections = Get-NetUDPEndpoint | Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, CreationTime
$processInfos = Get-Process -IncludeUserName
$parentProcesses = Get-WmiObject -Class Win32_Process | Select-Object ProcessId, ParentProcessId, CommandLine
$processes = New-Object System.Collections.ArrayList
foreach ($process in $processInfos) {
    #write-host ($process | ConvertTo-Json -Depth 2)
    $processInfo = [PSCustomObject]@{
        ProcessName = $process.Name
        UserName = $process.UserName
        CreationDate = $process.StartTime
        #ParentProcessId = $process.Parent.Id
        ProcessId = $process.Id
        ParentProcessId = ($parentProcesses | Where-Object { $_.ProcessId -eq $process.Id }).ParentProcessId
        CommandLine = ($parentProcesses | Where-Object { $_.ProcessId -eq $process.Id }).CommandLine
        ExecutablePath = $process.Path
    }
    $processes.Add($processInfo) | Out-Null
}

$users = Get-LocalUser | Select-Object -Property Name, Enabled, LastLogon, PasswordLastSet, @{Name='PrincipalSource'; Expression={$_.PrincipalSource.Value}}, @{Name='SID'; Expression={$_.SID.Value}}
$groups = Get-LocalGroup | Select-Object -Property Name, @{Name='SID'; Expression={$_.SID.Value}}
$members = New-Object System.Collections.ArrayList
foreach ($group in $groups) {
    $membersInGroup = $group | Get-LocalGroupMember | Select-Object -Property @{Name='SID'; Expression={$_.SID.Value}}
    foreach ($member in $membersInGroup) {
        $null = $members.Add(
            [PSCustomObject]@{
                UserSID = $member.SID
                GroupSID = $group.SID
            }
        )
    }
}
$shares = Get-SmbShare | Select-Object -Property Name, Path, ScopeName

# ---- AV / EDR / Security Product Status ----
$securityProducts = New-Object System.Collections.ArrayList
# Windows Security Center (WMI) - works on workstations; may not exist on Server Core
try {
    $avProducts = Get-WmiObject -Namespace 'root\SecurityCenter2' -Class AntiVirusProduct -ErrorAction Stop
    foreach ($av in $avProducts) {
        $stateHex = '{0:X6}' -f $av.productState
        # Byte 1 (bits 12-15): product type; Byte 2 (bits 8-11): enabled/disabled; Byte 3 (bits 4-7): definitions status
        $enabledByte = [int]"0x$($stateHex.Substring(2,2))"
        $defsByte    = [int]"0x$($stateHex.Substring(4,2))"
        $null = $securityProducts.Add([PSCustomObject]@{
            Type            = 'AntiVirus'
            DisplayName     = $av.displayName
            InstanceGuid    = $av.instanceGuid
            PathToSignedProductExe = $av.pathToSignedProductExe
            ProductState    = $av.productState
            Enabled         = ($enabledByte -band 0x10) -ne 0
            DefinitionsUpToDate = ($defsByte -eq 0x00)
        })
    }
} catch {}
try {
    $fwProducts = Get-WmiObject -Namespace 'root\SecurityCenter2' -Class FirewallProduct -ErrorAction Stop
    foreach ($fw in $fwProducts) {
        $null = $securityProducts.Add([PSCustomObject]@{
            Type         = 'Firewall'
            DisplayName  = $fw.displayName
            InstanceGuid = $fw.instanceGuid
            PathToSignedProductExe = $fw.pathToSignedProductExe
            ProductState = $fw.productState
        })
    }
} catch {}
try {
    $asProducts = Get-WmiObject -Namespace 'root\SecurityCenter2' -Class AntiSpywareProduct -ErrorAction Stop
    foreach ($as in $asProducts) {
        $null = $securityProducts.Add([PSCustomObject]@{
            Type         = 'AntiSpyware'
            DisplayName  = $as.displayName
            InstanceGuid = $as.instanceGuid
            PathToSignedProductExe = $as.pathToSignedProductExe
            ProductState = $as.productState
        })
    }
} catch {}
# Windows Defender status (works on both workstation and server)
$defenderStatus = $null
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    $defenderStatus = [PSCustomObject]@{
        AMServiceEnabled              = $mpStatus.AMServiceEnabled
        AntispywareEnabled            = $mpStatus.AntispywareEnabled
        AntivirusEnabled              = $mpStatus.AntivirusEnabled
        BehaviorMonitorEnabled        = $mpStatus.BehaviorMonitorEnabled
        IoavProtectionEnabled         = $mpStatus.IoavProtectionEnabled
        NISEnabled                    = $mpStatus.NISEnabled
        OnAccessProtectionEnabled     = $mpStatus.OnAccessProtectionEnabled
        RealTimeProtectionEnabled     = $mpStatus.RealTimeProtectionEnabled
        AntivirusSignatureLastUpdated = $mpStatus.AntivirusSignatureLastUpdated
        AntivirusSignatureVersion     = $mpStatus.AntivirusSignatureVersion
        FullScanAge                   = $mpStatus.FullScanAge
        QuickScanAge                  = $mpStatus.QuickScanAge
        TamperProtectionSource        = $(try { $mpStatus.TamperProtectionSource } catch { $null })
        AMRunningMode                 = $(try { $mpStatus.AMRunningMode } catch { $null })
    }
} catch {}
# Detect common EDR services
$edrServiceNames = @(
    'CrowdStrike*', 'CSFalcon*',           # CrowdStrike
    'CarbonBlack*', 'CbDefense*', 'cb',    # Carbon Black
    'SentinelAgent*', 'SentinelOne*',       # SentinelOne
    'Tanium*',                              # Tanium
    'Cylance*',                             # Cylance
    'McAfee*', 'masvc', 'macmnsvc',         # McAfee
    'Symantec*', 'SepMaster*', 'ccSvcHst',  # Symantec/Broadcom
    'YOURSERVICENAME'                       # Placeholder
)
$edrServices = New-Object System.Collections.ArrayList
foreach ($pattern in $edrServiceNames) {
    try {
        $svcs = Get-Service -Name $pattern -ErrorAction SilentlyContinue
        foreach ($svc in $svcs) {
            $null = $edrServices.Add([PSCustomObject]@{
                ServiceName = $svc.Name
                DisplayName = $svc.DisplayName
                Status      = $svc.Status.ToString()
                StartType   = $svc.StartType.ToString()
            })
        }
    } catch {}
}

# ---- Firewall Rules ----
$firewallProfiles = $null
try {
    $firewallProfiles = Get-NetFirewallProfile | Select-Object -Property Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogFileName, LogMaxSizeKilobytes, LogAllowed, LogBlocked
} catch {}
$firewallRules = $null
try {
    $firewallRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | Select-Object -Property Name, DisplayName, @{Name='Direction'; Expression={$_.Direction.ToString()}}, @{Name='Action'; Expression={$_.Action.ToString()}}, @{Name='Profile'; Expression={$_.Profile.ToString()}}, Enabled, Description
} catch {}

# ---- Logged-in Users / Active Sessions ----
$loggedOnUsers = New-Object System.Collections.ArrayList
# query user / quser gives console, RDP, and other sessions
try {
    $quserOutput = query user 2>&1
    foreach ($line in ($quserOutput | Select-Object -Skip 1)) {
        $lineStr = $line.ToString()
        if ($lineStr -match '^\s*>?\s*(\S+)\s+(\S+)?\s+(\d+)\s+(Active|Disc)\s+([\d+:\.]+)?\s*(.*)$') {
            $null = $loggedOnUsers.Add([PSCustomObject]@{
                UserName    = $Matches[1]
                SessionName = $Matches[2]
                SessionId   = $Matches[3]
                State       = $Matches[4]
                IdleTime    = $Matches[5]
                LogonTime   = $Matches[6].Trim()
            })
        }
    }
} catch {}
# WinRM / PSRemoting sessions
$winrmSessions = $null
try {
    $winrmSessions = Get-WSManInstance -ResourceURI shell -Enumerate -ErrorAction Stop | Select-Object -Property Owner, ClientIP, ShellId, State, ShellRunTime, ShellInactivity
} catch {}
# OpenSSH sessions (sshd processes with connected clients)
$sshSessions = New-Object System.Collections.ArrayList
try {
    $sshdProcesses = $processInfos | Where-Object { $_.Name -eq 'sshd' }
    foreach ($sshd in $sshdProcesses) {
        $sshConn = $tcpConnections | Where-Object { $_.OwningProcess -eq $sshd.Id -and $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' }
        foreach ($conn in $sshConn) {
            $null = $sshSessions.Add([PSCustomObject]@{
                ProcessId     = $sshd.Id
                UserName      = $sshd.UserName
                RemoteAddress = $conn.RemoteAddress
                RemotePort    = $conn.RemotePort
                State         = $conn.State
            })
        }
    }
} catch {}

# ---- Local Security Policy: Security Options + Audit Policies ----
$securityOptions = $null
$auditPolicies = $null
try {
    $seceditPath = Join-Path $env:TEMP 'secedit_export.inf'
    $seceditDb = Join-Path $env:TEMP 'secedit_export.sdb'
    & secedit /export /cfg $seceditPath /quiet 2>$null
    if (Test-Path $seceditPath) {
        $secPolicy = Get-Content $seceditPath -Raw
        # Parse security options from [Registry Values] and [System Access] and [Privilege Rights]
        $securityOptions = [PSCustomObject]@{
            SystemAccess   = @{}
            RegistryValues = @{}
            PrivilegeRights = @{}
        }
        $currentSection = ''
        foreach ($policyLine in $secPolicy -split "`r?`n") {
            if ($policyLine -match '^\[(.+)\]$') {
                $currentSection = $Matches[1]
                continue
            }
            if ($policyLine -match '^\s*$' -or $policyLine -match '^\s*;') { continue }
            $eqIdx = $policyLine.IndexOf('=')
            if ($eqIdx -gt 0) {
                $key = $policyLine.Substring(0, $eqIdx).Trim()
                $val = $policyLine.Substring($eqIdx + 1).Trim()
                switch ($currentSection) {
                    'System Access'    { $securityOptions.SystemAccess[$key] = $val }
                    'Registry Values'  { $securityOptions.RegistryValues[$key] = $val }
                    'Privilege Rights' { $securityOptions.PrivilegeRights[$key] = $val }
                }
            }
        }
        Remove-Item $seceditPath -Force -ErrorAction SilentlyContinue
        Remove-Item $seceditDb -Force -ErrorAction SilentlyContinue
    }
} catch {}
# Advanced Audit Policies (auditpol)
try {
    $auditPolOutput = & auditpol /get /category:* /r 2>$null
    if ($auditPolOutput) {
        $auditPolicies = $auditPolOutput | ConvertFrom-Csv | Select-Object -Property 'Subcategory', 'Subcategory GUID', 'Inclusion Setting'
    }
} catch {}

# ---- Domain Controller Detection + AD Queries ----
$isDomainController = $false
$domainUsers = $null
$domainServiceAccounts = $null
$domainGroups = $null
$domainComputers = $null
$domainGroupMemberships = $null
$gpos = $null
try {
    $dcCheck = Get-WmiObject -Class Win32_ComputerSystem -Property DomainRole
    # DomainRole: 4 = Backup DC, 5 = Primary DC
    if ($dcCheck.DomainRole -ge 4) {
        $isDomainController = $true
    }
} catch {}
if ($isDomainController) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        # Domain Users
        $domainUsers = Get-ADUser -Filter * -Properties Name, SamAccountName, UserPrincipalName, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, PasswordExpired, LockedOut, WhenCreated, WhenChanged, MemberOf, Description, DistinguishedName |
            Select-Object -Property Name, SamAccountName, UserPrincipalName, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, PasswordExpired, LockedOut, WhenCreated, WhenChanged, Description, DistinguishedName, @{Name='MemberOf'; Expression={ $_.MemberOf -join ';' }}, @{Name='SID'; Expression={$_.SID.Value}}

        # Managed Service Accounts + Group Managed Service Accounts
        $domainServiceAccounts = New-Object System.Collections.ArrayList
        try {
            $msas = Get-ADServiceAccount -Filter * -Properties Name, SamAccountName, Enabled, WhenCreated, DistinguishedName, @{Name='SID'; Expression={$_.SID.Value}} -ErrorAction SilentlyContinue
            foreach ($msa in $msas) {
                $null = $domainServiceAccounts.Add([PSCustomObject]@{
                    Name              = $msa.Name
                    SamAccountName    = $msa.SamAccountName
                    Enabled           = $msa.Enabled
                    WhenCreated       = $msa.WhenCreated
                    DistinguishedName = $msa.DistinguishedName
                    SID               = $msa.SID.Value
                })
            }
        } catch {}

        # Domain Groups
        $domainGroups = Get-ADGroup -Filter * -Properties Name, SamAccountName, @{Name='GroupScope'; Expression={$_.GroupScope.ToString()}}, @{Name='GroupCategory'; Expression={$_.GroupCategory.ToString()}}, WhenCreated, Description, DistinguishedName, @{Name='SID'; Expression={$_.SID.Value}} |
            Select-Object -Property Name, SamAccountName, GroupScope, GroupCategory, WhenCreated, Description, DistinguishedName, SID

        # Domain Computers
        $domainComputers = Get-ADComputer -Filter * -Properties Name, DNSHostName, Enabled, OperatingSystem, OperatingSystemVersion, LastLogonDate, WhenCreated, IPv4Address, DistinguishedName, @{Name='SID'; Expression={$_.SID.Value}} |
            Select-Object -Property Name, DNSHostName, Enabled, OperatingSystem, OperatingSystemVersion, LastLogonDate, WhenCreated, IPv4Address, DistinguishedName, SID

        # Group Memberships (all groups -> members)
        $domainGroupMemberships = New-Object System.Collections.ArrayList
        $allGroups = Get-ADGroup -Filter * -Properties SamAccountName
        foreach ($adGroup in $allGroups) {
            try {
                $groupMembers = Get-ADGroupMember -Identity $adGroup -ErrorAction SilentlyContinue
                foreach ($gm in $groupMembers) {
                    $null = $domainGroupMemberships.Add([PSCustomObject]@{
                        GroupName          = $adGroup.SamAccountName
                        GroupDN            = $adGroup.DistinguishedName
                        MemberName         = $gm.SamAccountName
                        MemberDN           = $gm.DistinguishedName
                        MemberObjectClass  = $gm.objectClass
                        MemberSID          = $gm.SID.Value
                    })
                }
            } catch {}
        }

        # GPOs
        $gpos = New-Object System.Collections.ArrayList
        try {
            $allGPOs = Get-GPO -All -ErrorAction Stop
            foreach ($gpo in $allGPOs) {
                $gpoReport = $null
                try {
                    $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction Stop
                } catch {}
                $null = $gpos.Add([PSCustomObject]@{
                    DisplayName    = $gpo.DisplayName
                    Id             = $gpo.Id.ToString()
                    GpoStatus      = $gpo.GpoStatus.ToString()
                    CreationTime   = $gpo.CreationTime
                    ModificationTime = $gpo.ModificationTime
                    WmiFilter      = $gpo.WmiFilter
                    Description    = $gpo.Description
                    XmlReport      = $gpoReport
                })
            }
        } catch {}
    } catch {}
}

$autorunscPath = Join-Path -Path $env:TEMP -ChildPath '\autorunsc.exe'
$pinfo = New-Object System.Diagnostics.ProcessStartInfo
$pinfo.FileName = $autorunscPath
$pinfo.RedirectStandardError = $true
$pinfo.RedirectStandardOutput = $true
$pinfo.UseShellExecute = $false
$pinfo.Arguments = '-accepteula -a * -ct -s -h -nobanner *'
$pinfo.Verb = "runas"
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $pinfo
$autorunsc_stdout = ""
try {
    $p.Start() | Out-Null
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    $autorunsc_stdout = $stdout | ConvertFrom-Csv -Delimiter "`t" | Where-Object { $_.MD5 -ne '' }
    $autorunsc_stderr = $stderr
} catch {
    $autorunsc_stderr = $_.Exception.Message
    Write-Error $_
}
$usersDirectory = Split-Path $env:USERPROFILE -Parent
try {
$extensions = @('.exe', '.bat', '.cmd', '.ps1', '.msi', '.jar', '.py', '.sh')
$userExecutables = New-Object System.Collections.ArrayList
$dirStack = New-Object System.Collections.Stack
$dirStack.Push($usersDirectory)
while ($dirStack.Count -gt 0) {
    $dir = $dirStack.Pop()
    try {
        foreach ($item in [System.IO.DirectoryInfo]::new($dir).GetFileSystemInfos()) {
            if ($item -is [System.IO.DirectoryInfo]) {
                # Skip junctions and symlinks to avoid infinite recursion
                if (-not ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                    $dirStack.Push($item.FullName)
                }
            } elseif ($item.Extension -in $extensions) {
                $null = $userExecutables.Add([PSCustomObject]@{ FullName = $item.FullName; Length = $item.Length })
            }
        }
    } catch {}
}
} catch {
    #Write-Host "Error getting files"
}

# ---- NTFS MFT File Inventory (WizTree-style fast scan) ----
# Reads the Master File Table directly via FSCTL_ENUM_USN_DATA.
# This enumerates every file record on the volume in seconds rather
# than minutes, because it sequentially scans the MFT instead of
# recursively walking directories through the filesystem API.
#
# The inventory is written directly to a CSV file (not returned in the
# snapshot object) because millions of records would exhaust memory
# during JSON serialization. The CSV is saved alongside the JSON snapshot.
$fileInventoryCount = 0
$fileInventoryErrors = ""
try {
    $mftSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

public class MftScanner
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr CreateFile(
string lpFileName, uint dwDesiredAccess, uint dwShareMode,
IntPtr lpSecurityAttributes, uint dwCreationDisposition,
uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
IntPtr hDevice, uint dwIoControlCode,
ref MFT_ENUM_DATA_V0 lpInBuffer, int nInBufferSize,
IntPtr lpOutBuffer, int nOutBufferSize,
out int lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x01;
    private const uint FILE_SHARE_WRITE = 0x02;
    private const uint OPEN_EXISTING = 3;
    private const uint FSCTL_ENUM_USN_DATA = 0x000900B3;
    // Mask to extract 48-bit file number from File Reference Number (strip 16-bit sequence)
    private const long FRN_MASK = 0x0000FFFFFFFFFFFF;

    [StructLayout(LayoutKind.Sequential)]
    private struct MFT_ENUM_DATA_V0
    {
public long StartFileReferenceNumber;
public long LowUsn;
public long HighUsn;
    }

    public static int EnumerateVolumeToCsv(string volumeLetter, string csvPath)
    {
// Phase 1: Scan MFT and collect all directory names + file entries
var dirNames = new Dictionary<long, string>();     // masked FRN -> dir name
var dirParents = new Dictionary<long, long>();      // masked FRN -> masked parent FRN
var fileEntries = new List<long[]>();               // [maskedParentFRN, attrs, fnameIdx]
var fileNames = new List<string>();
string volumePath = "\\\\.\\" + volumeLetter + ":";
int fileCount = 0;

// Pre-seed FRN 5 = NTFS root directory (not returned by USN enumeration)
dirNames[5] = volumeLetter + ":";
dirParents[5] = 5; // self-referencing root

IntPtr hVolume = CreateFile(volumePath,
    GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
    IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
if (hVolume == new IntPtr(-1))
    throw new Win32Exception(Marshal.GetLastWin32Error(),
        "Failed to open volume " + volumePath);

try
{
    int bufferSize = 2 * 1024 * 1024; // 2 MB buffer for speed
    IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
    try
    {
        var mftData = new MFT_ENUM_DATA_V0();
        mftData.StartFileReferenceNumber = 0;
        mftData.LowUsn = 0;
        mftData.HighUsn = long.MaxValue;
        int bytesReturned;

        while (DeviceIoControl(hVolume, FSCTL_ENUM_USN_DATA,
            ref mftData, Marshal.SizeOf(mftData),
            buffer, bufferSize, out bytesReturned, IntPtr.Zero))
        {
            int offset = 8; // skip next-USN at start of buffer
            while (offset < bytesReturned)
            {
                int recordLen = Marshal.ReadInt32(buffer, offset);
                if (recordLen == 0) break;

                // USN_RECORD_V2 fields
                long frn = Marshal.ReadInt64(buffer, offset + 8) & FRN_MASK;
                long parentFrn = Marshal.ReadInt64(buffer, offset + 16) & FRN_MASK;
                // USN_RECORD_V2 layout:
                //   +0  RecordLength (4)  +4 MajorVersion (2)  +6 MinorVersion (2)
                //   +8  FileReferenceNumber (8)  +16 ParentFileReferenceNumber (8)
                //  +24  Usn (8)  +32 TimeStamp (8)  +40 Reason (4)  +44 SourceInfo (4)
                //  +48  SecurityId (4)  +52 FileAttributes (4)
                //  +56  FileNameLength (2)  +58 FileNameOffset (2)  +60 FileName (var)
                int attrs = Marshal.ReadInt32(buffer, offset + 52);
                int fnLength = Marshal.ReadInt16(buffer, offset + 56);
                int fnOffset = Marshal.ReadInt16(buffer, offset + 58);
                string fn = Marshal.PtrToStringUni(
                    new IntPtr(buffer.ToInt64() + offset + fnOffset), fnLength / 2);

                if ((attrs & 0x10) != 0) // FILE_ATTRIBUTE_DIRECTORY
                {
                    dirNames[frn] = fn;
                    dirParents[frn] = parentFrn;
                }
                else
                {
                    fileNames.Add(fn);
                    fileEntries.Add(new long[] { parentFrn, attrs, fileNames.Count - 1 });
                }
                offset += recordLen;
            }
            mftData.StartFileReferenceNumber = Marshal.ReadInt64(buffer, 0);
        }
    }
    finally
    {
        Marshal.FreeHGlobal(buffer);
    }
}
finally
{
    CloseHandle(hVolume);
}

// Phase 2: Resolve directory paths and write CSV
// Allowlist: only security-relevant extensions
var allowedExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".scr", ".cpl", ".com", ".pif",
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsh", ".wsf", ".hta", ".sct", ".py", ".sh", ".rb", ".pl",
    ".xml", ".json", ".yml", ".yaml", ".conf", ".cfg", ".ini", ".inf", ".reg",
    ".toml", ".env",
    ".msi", ".msp", ".mst", ".cab",
    ".log", ".evtx", ".etl",
    ".lnk", ".url",
    ".jar", ".class", ".war",
    ".task", ".job",
};
// Directories to skip entirely
var excludedDirNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
    "WinSxS", "servicing", "Installer", "SoftwareDistribution",
    "assembly", "catroot", "catroot2",
};

var pathCache = new Dictionary<long, string>();
string rootPath = volumeLetter + ":";

using (var writer = new StreamWriter(csvPath, false, System.Text.Encoding.UTF8))
{
    writer.WriteLine("FullPath,FileName,FileAttributes,FileSize");
    foreach (var entry in fileEntries)
    {
        long parentFrn = entry[0];
        int attrs = (int)entry[1];
        string fileName = fileNames[(int)entry[2]];

        // Extension allowlist filter
        int dotIdx = fileName.LastIndexOf('.');
        if (dotIdx < 0) continue;
        string ext = fileName.Substring(dotIdx);
        if (!allowedExtensions.Contains(ext)) continue;

        // Resolve full directory path
        string dirPath = ResolveDirPath(parentFrn, dirNames, dirParents, pathCache, rootPath);

        // Exclude known Windows system directories
        bool skip = false;
        foreach (var exDir in excludedDirNames)
        {
            if (dirPath.IndexOf("\\" + exDir + "\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                dirPath.EndsWith("\\" + exDir, StringComparison.OrdinalIgnoreCase))
            {
                skip = true;
                break;
            }
        }
        if (skip) continue;

        string fullPath = dirPath + "\\" + fileName;

        // Get file size via FileInfo (fast for individual lookups, OS caches metadata)
        long fileSize = 0;
        try { fileSize = new FileInfo(fullPath).Length; } catch { }

        // CSV escape
        string csvPath1 = fullPath;
        string csvName = fileName;
        if (csvPath1.Contains(",") || csvPath1.Contains("\"") || csvPath1.Contains("\n"))
            csvPath1 = "\"" + csvPath1.Replace("\"", "\"\"") + "\"";
        if (csvName.Contains(",") || csvName.Contains("\""))
            csvName = "\"" + csvName.Replace("\"", "\"\"") + "\"";

        writer.Write(csvPath1);
        writer.Write(',');
        writer.Write(csvName);
        writer.Write(',');
        writer.Write(attrs);
        writer.Write(',');
        writer.WriteLine(fileSize);
        fileCount++;
    }
}
return fileCount;
    }

    private static string ResolveDirPath(long frn,
Dictionary<long, string> dirNames, Dictionary<long, long> dirParents,
Dictionary<long, string> cache, string rootPath)
    {
if (cache.ContainsKey(frn))
    return cache[frn];

// FRN 5 = NTFS root directory
if (frn == 5)
{
    cache[frn] = rootPath;
    return rootPath;
}

// Walk the parent chain, collecting directory names
var parts = new List<string>();
long current = frn;
int depth = 0;
while (depth < 512)
{
    // Check cache first
    if (cache.ContainsKey(current))
    {
        parts.Add(cache[current]);
        break;
    }
    // Root directory
    if (current == 5)
    {
        parts.Add(rootPath);
        break;
    }
    // Look up this directory's name
    string name;
    if (!dirNames.TryGetValue(current, out name))
    {
        // Unknown FRN — probably orphaned or system metadata; use root
        parts.Add(rootPath);
        break;
    }
    parts.Add(name);
    // Move to parent
    long parent;
    if (!dirParents.TryGetValue(current, out parent) || parent == current)
    {
        parts.Add(rootPath);
        break;
    }
    current = parent;
    depth++;
}

// parts is [child, ..., parent, root] — reverse to get path order
parts.Reverse();
string path = string.Join("\\", parts);
cache[frn] = path;
return path;
    }
}
'@
    if (-not ([System.Management.Automation.PSTypeName]'MftScanner').Type) {
        Add-Type -TypeDefinition $mftSource -Language CSharp
    }
    $systemDriveLetter = $env:SystemDrive.TrimEnd(':')
    $mftCsvPath = Join-Path $env:TEMP "file-inventory_$($env:COMPUTERNAME).csv"
    $fileInventoryCount = [MftScanner]::EnumerateVolumeToCsv($systemDriveLetter, $mftCsvPath)
    $fileInventoryErrors = ""
} catch {
    $fileInventoryErrors = $_.Exception.Message
}

# ---- Security-Critical Registry Watchlist ----
# Autorunsc already covers persistence (Run, RunOnce, Services, IFEO, AppInit,
# Winlogon, Shell extensions, COM/CLSID, LSA, SSP, Print Monitors, Winsock,
# WMI subscriptions, Netsh, Boot Execute, Known DLLs, Time Providers, etc.)
# This watchlist targets what autorunsc does NOT cover: defense evasion,
# credential theft config, remote access settings, and audit/logging tampering.
$registryWatchlist = @(
    # ===== DEFENSE EVASION / SECURITY WEAKENING =====
    # Windows Defender config + exclusions (attackers add exclusion paths)
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions'
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes'
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\IpAddresses'
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection'
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\SpyNet'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet'
    # UAC settings (EnableLUA, ConsentPromptBehavior, etc.)
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    # LSASS protection (RunAsPPL) - prevents credential dumping
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL'
    # Credential Guard / Device Guard
    'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags'
    # AMSI providers (removing/replacing disables script scanning)
    'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
    # Firewall policy via GPO
    'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
    'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile'
    'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
    'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'
    'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'
    'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'
    # Windows Update (disabling patches)
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    # Certificate trust stores (rogue root CAs for MITM)
    'HKLM:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates'
    'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates'
    'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates'
    'HKLM:\SOFTWARE\Microsoft\SystemCertificates\CA\Certificates'
    'HKLM:\SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates'

    # ===== CREDENTIAL THEFT / AUTHENTICATION =====
    # WDigest plaintext credential caching (UseLogonCredential = 1)
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    # CredSSP / credential delegation settings
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
    # Kerberos parameters
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
    # NTLM settings (downgrade, restrict, audit)
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    # AutoLogon credentials (stored in cleartext in Winlogon)
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

    # ===== REMOTE ACCESS SETTINGS =====
    # RDP (fDenyTSConnections, NLA, security layer)
    'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    # WinRM (AllowUnencrypted, TrustedHosts, etc.)
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
    # OpenSSH Server config
    'HKLM:\SOFTWARE\OpenSSH'
    # SMB settings (signing disabled = relay attacks)
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'

    # ===== LOGGING / AUDIT TAMPERING =====
    # Event log config (shrinking max size, changing retention = hiding tracks)
    'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'
    'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System'
    'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application'
    'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Windows PowerShell'
    'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Sysmon/Operational'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
    # PowerShell logging (disabling ScriptBlock/Module/Transcription logging)
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    # Audit policy via registry
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\AuditPolicy'
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    # Sysmon service (deleting/disabling = blind spot)
    'HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64'
    'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv'

    # ===== NETWORK =====
    # DNS client (poisoning via policy)
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    # Proxy settings (redirecting traffic)
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
    # TCP/IP parameters (hosts file path, IP forwarding)
    'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
)

$registrySnapshot = New-Object System.Collections.ArrayList
$registryErrors = New-Object System.Collections.ArrayList
foreach ($regPath in $registryWatchlist) {
    try {
        if (-not (Test-Path $regPath)) { continue }
        $item = Get-Item -Path $regPath -ErrorAction SilentlyContinue
        if ($null -eq $item) { continue }
        $values = @{}
        foreach ($valName in $item.GetValueNames()) {
            $valData = $item.GetValue($valName)
            $valKind = $item.GetValueKind($valName).ToString()
            if ($valData -is [byte[]] -and $valData.Length -gt 512) {
                $valData = [Convert]::ToBase64String($valData, 0, 512) + "...(truncated)"
            } elseif ($valData -is [byte[]]) {
                $valData = [Convert]::ToBase64String($valData)
            }
            $values[$valName] = [PSCustomObject]@{
                Value = $valData
                Kind  = $valKind
            }
        }
        $subkeys = @()
        try { $subkeys = @($item.GetSubKeyNames()) } catch {}
        $null = $registrySnapshot.Add([PSCustomObject]@{
            Path        = $regPath
            Values      = $values
            SubkeyCount = $subkeys.Count
            Subkeys     = $(if ($subkeys.Count -le 200) { $subkeys } else { $subkeys[0..199] })
        })
    } catch {
        $null = $registryErrors.Add([PSCustomObject]@{
            Path  = $regPath
            Error = $_.Exception.Message
        })
    }
}
# For keys where each subkey is an individual entry, recurse one level
$recurseOneLevel = @(
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions'
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes'
    'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    'HKLM:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates'
)
foreach ($parentPath in $recurseOneLevel) {
    try {
        if (-not (Test-Path $parentPath)) { continue }
        $childKeys = Get-ChildItem -Path $parentPath -ErrorAction SilentlyContinue
        foreach ($childKey in $childKeys) {
            $childValues = @{}
            foreach ($valName in $childKey.GetValueNames()) {
                $valData = $childKey.GetValue($valName)
                $valKind = $childKey.GetValueKind($valName).ToString()
                if ($valData -is [byte[]] -and $valData.Length -gt 512) {
                    $valData = [Convert]::ToBase64String($valData, 0, 512) + "...(truncated)"
                } elseif ($valData -is [byte[]]) {
                    $valData = [Convert]::ToBase64String($valData)
                }
                $childValues[$valName] = [PSCustomObject]@{
                    Value = $valData
                    Kind  = $valKind
                }
            }
            if ($childValues.Count -gt 0) {
                $cleanPath = $childKey.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
                $null = $registrySnapshot.Add([PSCustomObject]@{
                    Path        = $cleanPath
                    Values      = $childValues
                    SubkeyCount = 0
                    Subkeys     = @()
                })
            }
        }
    } catch {}
}

# ---- Environment Variables ----
$environmentVariables = Get-ChildItem Env: | Select-Object -Property Name, Value

# ---- Installed Applications ----
$installedApps = $null
try {
    $installedApps = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object -Property DisplayName, DisplayVersion, Publisher, InstallLocation, InstallDate
} catch {}

# ---- Scheduled Tasks (non-Microsoft) ----
$scheduledTasks = $null
try {
    $scheduledTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.Author -and $_.Author -notmatch 'Microsoft' -and $_.State -ne 'Disabled' } |
        Select-Object -Property TaskName, TaskPath, Author, State,
            @{N='Actions'; E={($_.Actions | ForEach-Object { $_.Execute }) -join '; '}},
            @{N='RunAs'; E={$_.Principal.UserId}}
} catch {}

# ---- Non-Microsoft Services ----
$thirdPartyServices = $null
try {
    $thirdPartyServices = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
        $svcPath = $_.PathName -replace '"',''
        $company = ''
        try {
            $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($svcPath)
            $company = $vi.CompanyName
        } catch {}
        if ($company -and $company -notmatch '^Microsoft') {
            [PSCustomObject]@{
                Name        = $_.Name
                DisplayName = $_.DisplayName
                State       = $_.State
                StartMode   = $_.StartMode
                PathName    = $_.PathName
                StartName   = $_.StartName
                Company     = $company
            }
        }
    }
} catch {}

# ---- Non-Microsoft Kernel Drivers ----
$thirdPartyDrivers = $null
try {
    $thirdPartyDrivers = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.PathName } | ForEach-Object {
        $drvPath = $_.PathName -replace '\\SystemRoot',"$env:SystemRoot" -replace '^\\\?\?\\',''
        try {
            $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($drvPath)
            if ($vi.CompanyName -and $vi.CompanyName -notmatch '^Microsoft') {
                [PSCustomObject]@{
                    Name    = $_.Name
                    Path    = $drvPath
                    Company = $vi.CompanyName
                    Product = $vi.ProductName
                    Version = $vi.ProductVersion
                }
            }
        } catch {}
    }
} catch {}

# ---- Named Pipes ----
$namedPipes = $null
try {
    $namedPipes = [System.IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object {
        $pipeName = $_ -replace '^\\\\.\\pipe\\',''
        [PSCustomObject]@{ Name = $pipeName }
    }
} catch {}

# ---- Credential Guard / VBS Status (WMI) ----
$credentialGuardStatus = $null
try {
    $credentialGuardStatus = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop |
        Select-Object -Property VirtualizationBasedSecurityStatus, SecurityServicesConfigured, SecurityServicesRunning
} catch {}

# ---- ASR Rules ----
$asrRules = $null
try {
    $asrPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
    $asrEnabled = Get-ItemProperty $asrPath -Name ExploitGuard_ASR_Rules -ErrorAction SilentlyContinue
    $asrRuleValues = Get-ItemProperty "$asrPath\Rules" -ErrorAction SilentlyContinue
    $asrExclusions = Get-ItemProperty "$asrPath\ASROnlyExclusions" -ErrorAction SilentlyContinue
    $asrRules = [PSCustomObject]@{
        Enabled    = $asrEnabled.ExploitGuard_ASR_Rules
        Rules      = $asrRuleValues
        Exclusions = $asrExclusions
    }
} catch {}

# ---- LAPS Detection ----
$lapsInstalled = $null
try {
    $lapsInstalled = [PSCustomObject]@{
        DllExists    = Test-Path 'C:\Program Files\LAPS\CSE\AdmPwd.dll'
        PolicyConfig = $(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -ErrorAction SilentlyContinue)
    }
} catch {}

# ---- AppLocker Effective Policy ----
$appLockerPolicy = $null
try {
    $appLockerPolicy = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
} catch {}

# ---- WEF (Windows Event Forwarding) ----
$wefConfig = $null
try {
    $wefConfig = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' -ErrorAction SilentlyContinue
} catch {}

# ---- PowerShell Remoting Session Configs ----
$psSessionConfigs = $null
try {
    $psSessionConfigs = @('Microsoft.PowerShell','Microsoft.PowerShell.Workflow','Microsoft.PowerShell32') | ForEach-Object {
        $cfg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Plugin\$_" -Name ConfigXML -ErrorAction SilentlyContinue
        if ($cfg) { [PSCustomObject]@{ Plugin = $_; ConfigXML = $cfg.ConfigXML } }
    }
} catch {}

# ---- AMSI Providers (resolved DLL paths) ----
$amsiProviders = $null
try {
    $amsiProviders = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue | ForEach-Object {
        $clsid = $_.PSChildName
        $dllPath = ''
        try { $dllPath = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -ErrorAction Stop).'(Default)' } catch {}
        [PSCustomObject]@{ CLSID = $clsid; DllPath = $dllPath }
    }
} catch {}

# ---- Certificates with Private Keys ----
$certificates = $null
try {
    $certificates = Get-ChildItem Cert:\LocalMachine\My, Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
        Select-Object -Property Subject, Issuer, NotAfter, HasPrivateKey, Thumbprint,
            @{N='EKU'; E={($_.EnhancedKeyUsageList.FriendlyName) -join ', '}},
            @{N='Template'; E={($_.Extensions | Where-Object {$_.Oid.FriendlyName -match 'Template'} | ForEach-Object { $_.Format($false) }) -join ''}}
} catch {}

# ---- Cloud Environment Detection ----
$cloudEnvironment = $null
try {
    $cloudEnvironment = [PSCustomObject]@{
        AWS   = Test-Path 'C:\Program Files\Amazon'
        Azure = Test-Path 'C:\WindowsAzure'
        GCP   = Test-Path 'C:\Program Files\Google\Compute Engine'
    }
} catch {}

# ---- Cached Credentials (cmdkey) ----
$cachedCredentials = $null
try {
    $cachedCredentials = & cmdkey /list 2>$null
} catch {}

# ---- AutoLogon Credentials ----
$autoLogon = $null
try {
    $autoLogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName, DefaultPassword, DefaultDomainName, AutoAdminLogon, AltDefaultUserName, AltDefaultDomainName -ErrorAction SilentlyContinue
} catch {}

# ---- AlwaysInstallElevated ----
$alwaysInstallElevated = $null
try {
    $hklmVal = (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $hkcuVal = (Get-ItemProperty 'HKCU:\Software\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $alwaysInstallElevated = [PSCustomObject]@{ HKLM = $hklmVal; HKCU = $hkcuVal }
} catch {}

# ---- PrintNightmare Point-and-Print ----
$pointAndPrint = $null
try {
    $pointAndPrint = Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name RestrictDriverInstallationToAdministrators, NoWarningNoElevationOnInstall, UpdatePromptSettings -ErrorAction SilentlyContinue
} catch {}

# ---- .NET Versions ----
$dotNetVersions = $null
try {
    $dotNetVersions = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse -ErrorAction SilentlyContinue |
        Get-ItemProperty -Name Version -ErrorAction SilentlyContinue |
        Where-Object { $_.Version } |
        Select-Object -Property PSChildName, Version -Unique
} catch {}

# ---- Sysmon Configuration Details ----
$sysmonConfig = $null
try {
    $sysmonConfig = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters' -Name HashingAlgorithm, Options -ErrorAction SilentlyContinue
} catch {}

# ---- WSL Distributions ----
$wslDistributions = $null
try {
    $wslDistributions = Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss' -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue | Select-Object -Property DistributionName, BasePath, State, DefaultUid
    }
} catch {}

# ---- Container Detection ----
$insideContainer = $null
try {
    $insideContainer = (Test-Path "$env:SystemRoot\System32\cexecsvc.exe") -or
        ($null -ne (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Services\cexecsvc' -ErrorAction SilentlyContinue))
} catch {}

# ---- SAM/SYSTEM Backup Files ----
$samBackups = $null
try {
    $samPaths = @(
        "$env:SystemRoot\repair\SAM","$env:SystemRoot\System32\config\RegBack\SAM",
        "$env:SystemRoot\repair\SYSTEM","$env:SystemRoot\System32\config\RegBack\SYSTEM"
    )
    $samBackups = $samPaths | Where-Object { Test-Path $_ } | ForEach-Object {
        $f = Get-Item $_
        [PSCustomObject]@{ Path = $_; Size = $f.Length; LastWriteTime = $f.LastWriteTime }
    }
} catch {}

# ---- Unattend/GPP Credential Files ----
$unattendFiles = $null
try {
    $uaPaths = @(
        "$env:WINDIR\sysprep\sysprep.xml","$env:WINDIR\Panther\Unattend.xml",
        "$env:WINDIR\Panther\Unattended.xml","$env:WINDIR\System32\Sysprep\unattend.xml"
    )
    $unattendFiles = $uaPaths | Where-Object { Test-Path $_ }
} catch {}

# ---- Printers ----
$printers = $null
try {
    $printers = Get-CimInstance Win32_Printer -ErrorAction SilentlyContinue |
        Select-Object -Property Name, DriverName, PortName, Shared, Published, Network
} catch {}

# ---- Token Privileges ----
$tokenPrivileges = $null
try {
    $tokenPrivileges = & whoami /priv /fo csv 2>$null | ConvertFrom-Csv
} catch {}

# ---- Installed Hotfixes ----
$installedHotfixes = $null
try {
    $installedHotfixes = Get-HotFix -ErrorAction SilentlyContinue |
        Select-Object -Property HotFixID, Description, InstalledOn, InstalledBy
} catch {}

# ---- DNS Cache ----
$dnsCache = $null
try {
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue |
        Select-Object -Property Entry, RecordName, RecordType, Status, Data, TimeToLive
} catch {}

# ---- Saved RDP Connections ----
$savedRdpConnections = $null
try {
    $savedRdpConnections = Get-ChildItem 'HKCU:\Software\Microsoft\Terminal Server Client\Servers' -ErrorAction SilentlyContinue | ForEach-Object {
        $server = $_.PSChildName
        $hint = (Get-ItemProperty $_.PSPath -Name UsernameHint -ErrorAction SilentlyContinue).UsernameHint
        [PSCustomObject]@{ Server = $server; UsernameHint = $hint }
    }
} catch {}

# ---- PuTTY Saved Sessions ----
$puttySessions = $null
try {
    $puttySessions = Get-ChildItem 'HKCU:\Software\SimonTatham\PuTTY\Sessions' -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            SessionName = $_.PSChildName
            HostName    = $props.HostName
            UserName    = $props.UserName
            PortNumber  = $props.PortNumber
            Protocol    = $props.Protocol
            ProxyHost   = $props.ProxyHost
        }
    }
} catch {}

# ---- PowerShell Console History ----
$psHistory = $null
try {
    $usersDir = Split-Path $env:USERPROFILE -Parent
    $psHistory = New-Object System.Collections.ArrayList
    foreach ($userDir in (Get-ChildItem $usersDir -Directory -ErrorAction SilentlyContinue)) {
        $histPath = Join-Path $userDir.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (Test-Path $histPath) {
            $size = (Get-Item $histPath).Length
            # Collect last 200 lines only to avoid bloat
            $lines = Get-Content $histPath -Tail 200 -ErrorAction SilentlyContinue
            $null = $psHistory.Add([PSCustomObject]@{
                User  = $userDir.Name
                Path  = $histPath
                Size  = $size
                Lines = $lines
            })
        }
    }
} catch {}

# ---- Recent Security Events (logon, process creation, PS scriptblock) ----
$recentEvents = $null
try {
    $recentEvents = @{}
    # Last 100 logon events (4624)
    try {
        $recentEvents['Logon4624'] = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 100 -ErrorAction SilentlyContinue |
            Select-Object -Property TimeCreated, Id, @{N='Message'; E={$_.Message.Substring(0, [Math]::Min(500, $_.Message.Length))}}
    } catch {}
    # Last 50 failed logons (4625)
    try {
        $recentEvents['FailedLogon4625'] = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 -ErrorAction SilentlyContinue |
            Select-Object -Property TimeCreated, Id, @{N='Message'; E={$_.Message.Substring(0, [Math]::Min(500, $_.Message.Length))}}
    } catch {}
    # Last 50 process creation events (4688)
    try {
        $recentEvents['ProcessCreation4688'] = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 50 -ErrorAction SilentlyContinue |
            Select-Object -Property TimeCreated, Id, @{N='Message'; E={$_.Message.Substring(0, [Math]::Min(500, $_.Message.Length))}}
    } catch {}
    # Last 50 PowerShell ScriptBlock events (4104)
    try {
        $recentEvents['ScriptBlock4104'] = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 50 -ErrorAction SilentlyContinue |
            Select-Object -Property TimeCreated, Id, @{N='Message'; E={$_.Message.Substring(0, [Math]::Min(1000, $_.Message.Length))}}
    } catch {}
} catch {}

# ---- DPAPI Master Key Inventory ----
$dpapiKeys = $null
try {
    $dpapiKeys = New-Object System.Collections.ArrayList
    $protectDirs = @("$env:APPDATA\Microsoft\Protect", "$env:LOCALAPPDATA\Microsoft\Protect")
    foreach ($dir in $protectDirs) {
        if (Test-Path $dir) {
            Get-ChildItem $dir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                $null = $dpapiKeys.Add([PSCustomObject]@{
                    Path = $_.FullName
                    Name = $_.Name
                    LastWriteTime = $_.LastWriteTime
                    Length = $_.Length
                })
            }
        }
    }
    # Credential files
    $credDirs = @("$env:APPDATA\Microsoft\Credentials", "$env:LOCALAPPDATA\Microsoft\Credentials")
    foreach ($dir in $credDirs) {
        if (Test-Path $dir) {
            Get-ChildItem $dir -Force -ErrorAction SilentlyContinue | ForEach-Object {
                $null = $dpapiKeys.Add([PSCustomObject]@{
                    Path = $_.FullName
                    Name = $_.Name
                    LastWriteTime = $_.LastWriteTime
                    Length = $_.Length
                })
            }
        }
    }
} catch {}

# ---- WiFi Profiles ----
$wifiProfiles = $null
try {
    $wifiOutput = & netsh wlan show profiles 2>$null
    if ($wifiOutput) {
        $wifiProfiles = $wifiOutput | Select-String 'All User Profile' | ForEach-Object {
            $name = ($_ -split ':')[1].Trim()
            [PSCustomObject]@{ SSID = $name }
        }
    }
} catch {}

# ---- Mapped Drives ----
$mappedDrives = $null
try {
    $mappedDrives = Get-CimInstance Win32_MappedLogicalDisk -ErrorAction SilentlyContinue |
        Select-Object -Property Name, ProviderName, SessionID, Size, FreeSpace
} catch {}

# ---- Hosts File ----
$hostsFileContent = $null
try {
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsFileContent = (Get-Content $hostsPath -ErrorAction SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' }) -join "`n"
} catch {}

# ---- Service Binary ACLs (for offline priv-esc analysis) ----
$serviceBinaryAcls = $null
try {
    $serviceBinaryAcls = New-Object System.Collections.ArrayList
    $allServices = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName }
    foreach ($svc in $allServices) {
        $binPath = $svc.PathName -replace '"','' -replace '\s+-.*$','' -replace '\s+/.*$',''
        if (-not (Test-Path $binPath -ErrorAction SilentlyContinue)) { continue }
        try {
            $acl = Get-Acl $binPath -ErrorAction Stop
            $null = $serviceBinaryAcls.Add([PSCustomObject]@{
                ServiceName = $svc.Name
                BinaryPath  = $binPath
                Owner       = $acl.Owner
                SDDL        = $acl.Sddl
            })
        } catch {}
    }
} catch {}

# ---- Scheduled Task Binary ACLs ----
$taskBinaryAcls = $null
try {
    $taskBinaryAcls = New-Object System.Collections.ArrayList
    $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($task in $allTasks) {
        foreach ($action in $task.Actions) {
            if (-not $action.Execute) { continue }
            $exePath = $action.Execute -replace '"',''
            if (-not (Test-Path $exePath -ErrorAction SilentlyContinue)) { continue }
            try {
                $acl = Get-Acl $exePath -ErrorAction Stop
                $null = $taskBinaryAcls.Add([PSCustomObject]@{
                    TaskName   = $task.TaskName
                    TaskPath   = $task.TaskPath
                    BinaryPath = $exePath
                    RunAs      = $task.Principal.UserId
                    Owner      = $acl.Owner
                    SDDL       = $acl.Sddl
                })
            } catch {}
        }
    }
} catch {}

# ---- PATH Directory ACLs ----
$pathDirAcls = $null
try {
    $pathDirAcls = ($env:PATH -split ';') | Where-Object { $_ -and (Test-Path $_) } | ForEach-Object {
        try {
            $acl = Get-Acl $_ -ErrorAction Stop
            [PSCustomObject]@{ Path = $_; Owner = $acl.Owner; SDDL = $acl.Sddl }
        } catch {}
    }
} catch {}

# ---- Named Pipe SDDLs (top 200 for size control) ----
$namedPipeAcls = $null
try {
    $pipeNames = [System.IO.Directory]::GetFiles('\\.\pipe\') | Select-Object -First 200
    $namedPipeAcls = New-Object System.Collections.ArrayList
    foreach ($pipe in $pipeNames) {
        $pipeName = $pipe -replace '^\\\\.\\pipe\\',''
        try {
            $acl = Get-Acl "\\.\pipe\$pipeName" -ErrorAction Stop
            $null = $namedPipeAcls.Add([PSCustomObject]@{ Name = $pipeName; SDDL = $acl.Sddl })
        } catch {
            $null = $namedPipeAcls.Add([PSCustomObject]@{ Name = $pipeName; SDDL = 'ACCESS_DENIED' })
        }
    }
} catch {}

# ---- SMB Share ACLs ----
$shareAcls = $null
try {
    $shareAcls = Get-SmbShare -ErrorAction SilentlyContinue | ForEach-Object {
        $shareAccess = Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue |
            Select-Object -Property AccountName, AccessControlType, AccessRight
        [PSCustomObject]@{
            ShareName   = $_.Name
            Path        = $_.Path
            Permissions = $shareAccess
        }
    }
} catch {}

# ---- Home Directory ACLs ----
$homeDirAcls = $null
try {
    $usersDir2 = Split-Path $env:USERPROFILE -Parent
    $homeDirAcls = Get-ChildItem $usersDir2 -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $acl = Get-Acl $_.FullName -ErrorAction Stop
            [PSCustomObject]@{ Path = $_.FullName; Owner = $acl.Owner; SDDL = $acl.Sddl }
        } catch {}
    }
} catch {}

$dateTimeFinished = (Get-Date).ToString('o')
[PSCustomObject]@{
    SystemUUID = $systemUUID
    SnapshotTime = $dateTimeFinished
    ComputerInfo = $computerInfo
    DiskVolumes = $diskVolumes
    NetAdapters = $netAdapters
    DnsSearchSuffixes = $dnsSearchSuffixes
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
    EDRServices = $edrServices
    FirewallProfiles = $firewallProfiles
    FirewallRules = $firewallRules
    LoggedOnUsers = $loggedOnUsers
    WinRMSessions = $winrmSessions
    SSHSessions = $sshSessions
    SecurityOptions = $securityOptions
    AuditPolicies = $auditPolicies
    IsDomainController = $isDomainController
    DomainUsers = $domainUsers
    DomainServiceAccounts = $domainServiceAccounts
    DomainGroups = $domainGroups
    DomainComputers = $domainComputers
    DomainGroupMemberships = $domainGroupMemberships
    GPOs = $gpos
    Autorunsc = $autorunsc_stdout
    AutorunscErrors = $autorunsc_stderr
    UserExecutables = $userExecutables
    FileInventoryCount = $fileInventoryCount
    FileInventoryCsvPath = $mftCsvPath
    FileInventoryErrors = $fileInventoryErrors
    RegistrySnapshot = $registrySnapshot
    RegistryErrors = $registryErrors
    EnvironmentVariables = $environmentVariables
    InstalledApps = $installedApps
    ScheduledTasks = $scheduledTasks
    ThirdPartyServices = $thirdPartyServices
    ThirdPartyDrivers = $thirdPartyDrivers
    NamedPipes = $namedPipes
    CredentialGuardStatus = $credentialGuardStatus
    ASRRules = $asrRules
    LAPSInstalled = $lapsInstalled
    AppLockerPolicy = $appLockerPolicy
    WEFConfig = $wefConfig
    PSSessionConfigs = $psSessionConfigs
    AMSIProviders = $amsiProviders
    Certificates = $certificates
    CloudEnvironment = $cloudEnvironment
    CachedCredentials = $cachedCredentials
    AutoLogon = $autoLogon
    AlwaysInstallElevated = $alwaysInstallElevated
    PointAndPrint = $pointAndPrint
    DotNetVersions = $dotNetVersions
    SysmonConfig = $sysmonConfig
    WSLDistributions = $wslDistributions
    InsideContainer = $insideContainer
    SAMBackups = $samBackups
    UnattendFiles = $unattendFiles
    Printers = $printers
    TokenPrivileges = $tokenPrivileges
    InstalledHotfixes = $installedHotfixes
    DnsCache = $dnsCache
    SavedRdpConnections = $savedRdpConnections
    PuttySessions = $puttySessions
    PSHistory = $psHistory
    RecentEvents = $recentEvents
    DPAPIKeys = $dpapiKeys
    WifiProfiles = $wifiProfiles
    MappedDrives = $mappedDrives
    HostsFileContent = $hostsFileContent
    ServiceBinaryAcls = $serviceBinaryAcls
    TaskBinaryAcls = $taskBinaryAcls
    PathDirAcls = $pathDirAcls
    NamedPipeAcls = $namedPipeAcls
    ShareAcls = $shareAcls
    HomeDirAcls = $homeDirAcls
}
}

# ---- Save JSON output ----
Write-Host "Saving JSON..."
$outPath = Join-Path $OutputDir "system-info.json"

function Save-SnapshotJson {
    param($Result, [string]$FilePath)
    $sb = [System.Text.StringBuilder]::new(2 * 1024 * 1024)
    $null = $sb.Append('{')
    $first = $true
    foreach ($prop in $Result.PSObject.Properties) {
        if (-not $first) { $null = $sb.Append(',') }
        $first = $false
        $propName = $prop.Name -replace '"', '\"'
        $null = $sb.Append("`
`"$propName`": ")
        try {
            $json = $prop.Value | ConvertTo-Json -Depth 5 -Compress -WarningAction SilentlyContinue
            if ($null -eq $json) { $json = 'null' }
            $null = $sb.Append($json)
        } catch {
            $null = $sb.Append('null')
        }
    }
    $null = $sb.Append("`
}")
    [System.IO.File]::WriteAllText($FilePath, $sb.ToString(), [System.Text.Encoding]::UTF8)
}

Save-SnapshotJson -Result $snapshot -FilePath $outPath
$sizeMB = [math]::Round((Get-Item $outPath).Length / 1MB, 1)
Write-Host "Collection complete: $outPath ($sizeMB MB)"
Write-Host "Fields: $($snapshot.PSObject.Properties.Count)"
