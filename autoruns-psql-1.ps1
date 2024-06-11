# check if $creds is defined
if (-not $creds) {
    $creds = Get-Credential -UserName 'luke.verlooy@pao.mil'
}
$targetHosts = (Get-Content -Path '.\targetHosts.txt' -Raw).Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)
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
        $userExecutables = Get-ChildItem $usersDirectory -Recurse -Force | Where-Object { $_.Extension -in @('.exe', '.bat', '.cmd', '.ps1', '.msi', '.jar', '.py', '.sh') } | Select-Object FullName, Length
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

<#


CREATE TABLE unique_autorunsc_signer_path_cmdline (
    id SERIAL PRIMARY KEY,
    signer VARCHAR(255),
    imagepath VARCHAR(255),
    launchstring VARCHAR(2048),
    short_launchstring VARCHAR(255)
);

INSERT INTO unique_autorunsc_signer_path_cmdline (signer, imagepath, launchstring, short_launchstring)
SELECT
    signer,
    imagepath,
    launchstring,
    SUBSTRING(launchstring FROM 1 FOR 255)::character varying(255) AS short_launchstring
FROM autorunsc
GROUP BY 
    autorunsc.signer, 
    autorunsc.imagepath, 
    autorunsc.launchstring;



ALTER TABLE autorunsc ADD COLUMN unique_autorunsc_id INT;

UPDATE autorunsc 
SET unique_autorunsc_id = unique_autorunsc_signer_path_cmdline.id
FROM unique_autorunsc_signer_path_cmdline
WHERE 
    unique_autorunsc_signer_path_cmdline.signer = autorunsc.signer
    AND unique_autorunsc_signer_path_cmdline.imagepath = autorunsc.imagepath
    AND unique_autorunsc_signer_path_cmdline.launchstring = autorunsc.launchstring;


SELECT public_autorunsc.unique_autorunsc_id, Count(public_autorunsc.id) AS CountOfid
FROM public_autorunsc
GROUP BY public_autorunsc.unique_autorunsc_id;


BEGIN;

DO $$ 
BEGIN
    CREATE TEMP TABLE old_snapshots AS
    SELECT snapshotid FROM public.systemsnapshots WHERE snapshottime < CURRENT_DATE + INTERVAL '12 hours';

    DELETE FROM public.arpcache WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.autorunsc WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.computerinfo WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.diskvolumes WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.dnssearchsuffixes WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.dnsservers WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.groups WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.ipaddresses WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.members WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.netadapters WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.processes WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.routes WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.shares WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.tcpconnections WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.udpconnections WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.userexecutables WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.users WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);

    DELETE FROM public.systemsnapshots WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM unique_autorunsc_signer_path_cmdline;
        
    INSERT INTO unique_autorunsc_signer_path_cmdline (signer, imagepath, launchstring, short_launchstring)
    SELECT
        signer,
        imagepath,
        launchstring,
        SUBSTRING(launchstring FROM 1 FOR 255)::character varying(255) AS short_launchstring
    FROM autorunsc
    GROUP BY 
        autorunsc.signer, 
        autorunsc.imagepath, 
        autorunsc.launchstring;

    UPDATE autorunsc 
    SET unique_autorunsc_id = unique_autorunsc_signer_path_cmdline.id
    FROM unique_autorunsc_signer_path_cmdline
    WHERE 
        unique_autorunsc_signer_path_cmdline.signer = autorunsc.signer
        AND unique_autorunsc_signer_path_cmdline.imagepath = autorunsc.imagepath
        AND unique_autorunsc_signer_path_cmdline.launchstring = autorunsc.launchstring;

EXCEPTION WHEN OTHERS THEN
    -- In case of error, rollback the transaction
    ROLLBACK;
    RAISE;
END $$;

COMMIT;

#>