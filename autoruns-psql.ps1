# check if $creds is defined
if (-not $creds) {
    $creds = Get-Credential -UserName 'localadmin'
}
$targetHosts = (Get-Content -Path '.\targetHosts.txt' -Raw).Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)
$autorunscScriptBlock = {
    param($targetHost, [pscredential]$creds)
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
        $autorunscPath | Out-File -FilePath '.\autorunscPath.txt'

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
    $systemUUID = Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
    $computerInfo = Get-ComputerInfo | Select-Object -Property CsName, CsDNSHostName, CsDomain, CsManufacturer, CsModel, CsPartOfDomain, @{Name='CsPCSystemType'; Expression={$_.CsPCSystemType.ToString()}}, OsName, @{Name='OsType'; Expression={$_.OsType.ToString()}}, OsVersion, OsSystemDrive, OsLastBootUpTime
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
    $processes = New-Object System.Collections.ArrayList
    foreach ($process in $processInfos) {
        $processInfo = [PSCustomObject]@{
            ProcessName = $process.Name
            UserName = $process.UserName
            CreationDate = $process.StartTime
            ParentProcessId = $process.Parent.Id
            ProcessId = $process.Id
            CommandLine = $process.StartInfo.Arguments
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
    $dateTimeFinished = Get-Date
    [PSCustomObject]@{
        SystemUUID = $systemUUID
        Time = $dateTimeFinished
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
    }
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
$results = $jobs | Receive-Job

$config = Get-Content .\config.json | ConvertFrom-Json
$npgsqlPath = $config.npgsqlPath
if (Test-Path $npgsqlPath) {
    Add-Type -Path $npgsqlPath
} else {
    Write-Host "Npgsql.dll not found at the specified path: $npgsqlPath"
    exit
}
$connectionString = $config.connectionString
$connection = New-Object Npgsql.NpgsqlConnection($connectionString)
$connection.Open()

if($connection.State -ne 'Open') {
    Write-Host "Connection failed"
    exit
}

function TableDefinitionToSql($tableName, $columns, $primaryKeys = $null, $foreignKeys = $null) {
    $sql = "CREATE TABLE public.$tableName ("
    $sql += "`n    SystemUUID VARCHAR(255),"
    $sql += "`n    Time TIMESTAMP,"
    $sql += ($columns | ForEach-Object { "`n    $($_.name -replace '[^a-zA-Z0-9]', '') $($_.type)" }) -join ","
    if ($null -ne $primaryKeys -and $primaryKeys.Count -gt 0) {
        $sql += ","
        $sql += "`n    PRIMARY KEY (" + ($primaryKeys -join ", ") + ")"
    }
    if ($null -ne $foreignKeys -and $foreignKeys.Count -gt 0) {
        $sql += ","
        foreach ($foreignKey in $foreignKeys) {
            $columns = [string]::Join(", ", $foreignKey["ForeignKeys"])
            $refTable = $foreignKey["Table"]
            $refColumns = [string]::Join(", ", $foreignKey["References"])
            $sql += "`n    FOREIGN KEY ($columns) REFERENCES $refTable($refColumns),"
        }
        $sql = $sql.TrimEnd(",")
    }
    $sql += "`n);"
    return $sql
}
function CheckAndCreateTable($tableName, $tableColumns, $primaryKeys = $null, $foreignKeys = $null) {
    $command = $connection.CreateCommand()
    try {
        $command.CommandText = "SELECT to_regclass('public.$tableName')::text"
        $exists = $command.ExecuteScalar()
        if ($null -eq $exists -or $exists -eq "" -or $exists.GetType().Name -eq "DBNull") {
            $command.CommandText = (TableDefinitionToSql $tableName $tableColumns $primaryKeys $foreignKeys)
            $null = $command.ExecuteNonQuery()
        }
    } catch {
        Write-Host "Error executing command: $_"
    } finally {
        $command.Dispose()
    }
}

function InsertDataIntoTable($tableName, $tableColumns, $tableData, $systemUUID, $time) {
    # $tableColumns is an array of objects with properties 'name' and 'type'
    $columnNames = ($tableColumns | ForEach-Object { $_.name -replace "[^a-zA-Z0-9]", "" }) -join ","
    $columnParameterNames = ($tableColumns | ForEach-Object { '@' + ($_.name -replace "[^a-zA-Z0-9]", "")}) -join ","
    $command = $connection.CreateCommand()
    try {
        $command.CommandText = "INSERT INTO public.$tableName (SystemUUID, Time, $columnNames) VALUES (@SystemUUID, @Time, $columnParameterNames)"
        foreach($row in $tableData) {
            $command.Parameters.Clear()
            foreach($column in $tableColumns) {
                $columnName = $column.name
                $value = $row.$($columnName)
                $sanitizedColumnName = $columnName -replace "[^a-zA-Z0-9]", ""
                if ($null -eq $value) {
                    $null = $command.Parameters.AddWithValue("@$($sanitizedColumnName)", [System.DBNull]::Value)
                } else {
                    if ($value -is [System.UInt16]) {
                        $value = [System.Int32]::Parse($value.ToString())
                    }
                    elseif ($value -is [System.UInt32]) {
                        $value = [System.Int32]::Parse($value.ToString())
                    }
                    elseif ($value -is [System.UInt64]) {
                        $value = [System.Int64]::Parse($value.ToString())
                    }
                    $null = $command.Parameters.AddWithValue("@$($sanitizedColumnName)", $value)
                }
            }
            $null = $command.Parameters.AddWithValue("@SystemUUID", $systemUUID)
            $null = $command.Parameters.AddWithValue("@Time", $time)
            $null = $command.ExecuteNonQuery()
        }
    } catch {
        Write-Host "Error executing command: $_"
    } finally {
        $command.Dispose()
    }
}

$systemSnapshotPrimaryKeys = @('SystemUUID', 'Time')
$systemSnapshotColumn = @(
    [PSCustomObject]@{name='Unused';type='VARCHAR(255)'}
)
CheckAndCreateTable 'SystemSnapshots' $systemSnapshotColumn $systemSnapshotPrimaryKeys
$jsonTables = Get-Content .\table_definitions.json | ConvertFrom-Json
foreach ($table in $jsonTables) {
    $tableName = $table.name
    $tableColumns = $table.columns
    $foreignKeys = @(
        @{
            "ForeignKeys" = @("SystemUUID","Time"); 
            "Table" = "SystemSnapshots"; 
            "References" = @("SystemUUID","Time")
        };
    )
    CheckAndCreateTable $tableName $tableColumns $null $foreignKeys
}

$resultIndex = 0
foreach ($result in $results) {
    $result | ConvertTo-Json -Depth 9 | Out-File -FilePath ".\system-info_$($targetHosts[$resultIndex]).json"
    $systemUUID = $result.SystemUUID
    $time = $result.Time
    InsertDataIntoTable 'SystemSnapshots' $systemSnapshotColumn @('') $systemUUID $time
    foreach ($table in $jsonTables) {
        $tableName = $table.name
        $tableColumns = $table.columns
        $tableData = $results.$($tableName)
        if ($null -ne $tableData -and $tableData.Count -gt 0) {
            InsertDataIntoTable $tableName $tableColumns $tableData $systemUUID $time
        }
    }
    $resultIndex++
}

$connection.Close()
Write-Host "Data inserted into database"
