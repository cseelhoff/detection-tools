# check if $creds is defined
if (-not $creds) {
    $creds = Get-Credential -UserName 'username@domain.com' -Message "Enter domain credentials (DOMAIN\Username)"
}
$targetHosts = (Get-Content -Path '.\targetHosts.txt' -Raw).Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)

# Ensure autorunsc.exe is present locally; attempt download if missing
if (-not (Test-Path '.\autorunsc.exe')) {
    Write-Host "autorunsc.exe not found locally. Attempting to download from Sysinternals..." -ForegroundColor Yellow
    try {
        $zipPath = Join-Path $env:TEMP 'autoruns.zip'
        $extractPath = Join-Path $env:TEMP 'autoruns_extract'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Autoruns.zip' -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
        Copy-Item -Path (Join-Path $extractPath 'autorunsc.exe') -Destination '.\autorunsc.exe' -Force
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "autorunsc.exe downloaded successfully." -ForegroundColor Green
    } catch {
        Write-Error "Failed to download autorunsc.exe: $($_.Exception.Message)"
        Write-Error "Please manually place autorunsc.exe in the working directory and re-run the script."
        exit 1
    }
}

$autorunscScriptBlock = {
    param($targetHost, [pscredential]$creds)
    write-host "targethost: $targetHost"
    $autoRunscPath = '.\autorunsc.exe'
    $session = New-PSSession -ComputerName $targetHost -Credential $creds
    # if the session is not created, exit the script
    if (!$session) {
        Write-Error "Failed to create a session to $targetHost`n"
        exit
    }
    $installResults = Invoke-Command -Session $session -ScriptBlock {
        # Define the path to autorunsc.exe in the Downloads directory
        $autorunscPath = Join-Path -Path $env:TEMP -ChildPath '\autorunsc.exe'
        #$autorunscPath | Out-File -FilePath '.\autorunscPath.txt'

        # Check if autorunsc.exe exists
        $autorunscExists = Test-Path $autorunscPath
        [PSCustomObject]@{
            AutorunscExists = $autorunscExists
            DownloadPath = $autorunscPath
        }
    }
    if (!$installResults.AutorunscExists) {
        Copy-Item -Path $autoRunscPath -Destination $installResults.DownloadPath -ToSession $session
    }
    $snapshotResults = Invoke-Command -Session $session -ScriptBlock {
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
        $dateTimeFinished = Get-Date
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
        }
    }
    $snapshotResults
}
$maxConcurrentJobs = 10

# Create an array to hold the job objects
$jobs = @()

$ReadFromFileScriptBlock = {
    param($targetHost)
    $json = Get-Content ".\system-info_$($targetHost).json" | ConvertFrom-Json
    $json
}

# Start a job for each target host
$targetHostsCount = $targetHosts.Count
for ($i = 0; $i -lt $targetHostsCount; $i++) {
    $targetHost = $targetHosts[$i]
    write-host "running script on host: $targetHost"
    # If there are 10 or more running jobs, wait for one to finish
    while (($jobs | Where-Object { $_.State -eq 'Running' }).Count -ge $maxConcurrentJobs) {
        # Wait for any job to finish
        $finishedJob = Get-Job | Wait-Job -Any
        # Remove the finished job from the jobs array
        $jobs = $jobs | Where-Object { $_.Id -ne $finishedJob.Id }
    }
    # Start a new job
    $jobs += Start-Job -ScriptBlock $autorunscScriptBlock -ArgumentList @($targetHost, $creds)
    #$jobs += Start-Job -ScriptBlock $ReadFromFileScriptBlock -ArgumentList @($targetHost)

    # Update the progress bar
    Write-Progress -Activity "Processing target hosts" -Status "$i of $targetHostsCount completed" -PercentComplete (($i / $targetHostsCount) * 100)
}
$jobs | Wait-Job
$results = $null
$results = $jobs | Receive-Job
$resultIndex = 0
foreach ($result in $results) {
    
    $result | ConvertTo-Json -Depth 9 | Out-File -FilePath ".\system-info_$($targetHosts[$resultIndex]).json"
    $resultIndex += 1
}