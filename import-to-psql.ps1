# import-to-psql.ps1 — Import JSON snapshots into PostgreSQL
$targetHosts = (Get-Content -Path '.\targetHosts.txt' -Raw).Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries) | Where-Object { $_ -and $_ -notmatch '^\s*#' }

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
    $sql += "`n    id SERIAL PRIMARY KEY,"
    $sql += "`n    SnapshotID INTEGER,"
    $sql += ($columns | ForEach-Object { "`n    $($_.name -replace '[^a-zA-Z0-9_]', '') $($_.type)" }) -join ","
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

function CheckAndCreateSnapshotTable($tableName, $tableColumns, $primaryKeys = $null, $foreignKeys = $null) {
    $command = $connection.CreateCommand()
    $tableName = 'SystemSnapshots'
    try {
        $command.CommandText = "SELECT to_regclass('public.$tableName')::text"
        $exists = $command.ExecuteScalar()
        if ($null -eq $exists -or $exists -eq "" -or $exists.GetType().Name -eq "DBNull") {
            $sql = "CREATE TABLE public.$tableName ("
            $sql += "`n    SnapshotID SERIAL PRIMARY KEY,"
            $sql += "`n    SystemUUID VARCHAR(255),"
            $sql += "`n    SnapshotTime TIMESTAMP"
            $sql += "`n);"
            $command.CommandText = $sql
            $null = $command.ExecuteNonQuery()
        }
        # Ensure a unique index exists on (SystemUUID, SnapshotTime)
        $command.CommandText = "CREATE UNIQUE INDEX IF NOT EXISTS idx_systemsnapshots_uuid_time ON public.SystemSnapshots(SystemUUID, SnapshotTime)"
        $null = $command.ExecuteNonQuery()
    } catch {
        Write-Host "Error executing command: $_"
    } finally {
        $command.Dispose()
    }
}

function InsertDataIntoSnapshotsTable($systemUUID, $snapshotTime) {
    $command = $connection.CreateCommand()
    $SnapshotIDResult = -1
    $isExisting = $false
    try {
        # Check if a snapshot already exists for this SystemUUID and SnapshotTime
        $command.CommandText = "SELECT SnapshotID FROM public.SystemSnapshots WHERE SystemUUID = @SystemUUID AND SnapshotTime = @SnapshotTime LIMIT 1"
        $null = $command.Parameters.AddWithValue("@SystemUUID", $systemUUID)
        $null = $command.Parameters.AddWithValue("@SnapshotTime", $snapshotTime)
        $existingID = $command.ExecuteScalar()
        if ($null -ne $existingID -and $existingID.GetType().Name -ne "DBNull") {
            $SnapshotIDResult = $existingID
            $isExisting = $true
        } else {
            # No existing snapshot found, insert a new one
            $command.CommandText = "INSERT INTO public.SystemSnapshots (SystemUUID, SnapshotTime) VALUES (@SystemUUID, @SnapshotTime) RETURNING SnapshotID"
            $SnapshotIDResult = $command.ExecuteScalar()
        }
    } catch {
        Write-Host "Error executing command: $_"
    } finally {
        $command.Dispose()
    }
    return @{ SnapshotID = $SnapshotIDResult; IsExisting = $isExisting }
}

function InsertDataIntoTable($tableName, $tableColumns, $tableData, $snapshotID) {
    # $tableColumns is an array of objects with properties 'name' and 'type'
    $columnNames = ($tableColumns | ForEach-Object { $_.name -replace "[^a-zA-Z0-9]", "" }) -join ","
    $columnParameterNames = ($tableColumns | ForEach-Object { '@' + ($_.name -replace "[^a-zA-Z0-9]", "")}) -join ","
    # Delete existing rows for this snapshot before reinserting
    $deleteCmd = $connection.CreateCommand()
    try {
        $deleteCmd.CommandText = "DELETE FROM public.$tableName WHERE SnapshotID = @SnapshotID"
        $null = $deleteCmd.Parameters.AddWithValue("@SnapshotID", $snapshotID)
        $deletedCount = $deleteCmd.ExecuteNonQuery()
        if ($deletedCount -gt 0) {
            Write-Host "  cleared $deletedCount existing rows from $tableName for SnapshotID=$snapshotID"
        }
    } catch {
        Write-Host "Error clearing existing data from ${tableName}: $_"
    } finally {
        $deleteCmd.Dispose()
    }
    $command = $connection.CreateCommand()
    try {
        $command.CommandText = "INSERT INTO public.$tableName (SnapshotID, $columnNames) VALUES (@SnapshotID, $columnParameterNames)"
        foreach($row in $tableData) {
            $command.Parameters.Clear()
            foreach($column in $tableColumns) {
                $columnName = $column.name
                $colType = $column.type.ToUpper()
                $value = $row.$($columnName)
                $sanitizedColumnName = $columnName -replace "[^a-zA-Z0-9]", ""
                if ($null -eq $value) {
                    $null = $command.Parameters.AddWithValue("@$($sanitizedColumnName)", [System.DBNull]::Value)
                } else {
                    # Type coercion for cross-platform compatibility
                    # Arrays/objects -> JSON string
                    if ($value -is [System.Array] -or $value -is [PSCustomObject] -or $value -is [System.Collections.IDictionary]) {
                        $value = ($value | ConvertTo-Json -Compress -Depth 3 -WarningAction SilentlyContinue)
                    }
                    # Numeric type coercion
                    if ($value -is [System.UInt16]) { $value = [System.Int32]::Parse($value.ToString()) }
                    elseif ($value -is [System.UInt32]) { $value = [System.Int32]::Parse($value.ToString()) }
                    elseif ($value -is [System.UInt64]) { $value = [System.Int64]::Parse($value.ToString()) }
                    # String-to-int coercion for INTEGER/BIGINT columns
                    if (($colType -match 'INTEGER|BIGINT') -and $value -is [string]) {
                        $intVal = 0
                        if ([int64]::TryParse($value, [ref]$intVal)) { $value = $intVal }
                        else { $value = [System.DBNull]::Value }
                    }
                    # String-to-bool coercion for BOOLEAN columns
                    elseif ($colType -eq 'BOOLEAN' -and $value -is [string]) {
                        $value = $value -in @('true', 'True', '1', 'yes', 'enabled')
                    }
                    # Non-parseable timestamp -> NULL
                    elseif ($colType -eq 'TIMESTAMP' -and $value -is [string]) {
                        $dt = [datetime]::MinValue
                        if (-not [datetime]::TryParse($value, [ref]$dt)) {
                            $value = [System.DBNull]::Value
                        }
                    }
                    $null = $command.Parameters.AddWithValue("@$($sanitizedColumnName)", $value)
                }
            }
            $null = $command.Parameters.AddWithValue("@SnapshotID", $snapshotID)
            try {
                $null = $command.ExecuteNonQuery()
            } catch {
                # Skip individual row errors, log first occurrence
                if (-not $script:rowErrorLogged) {
                    Write-Host "  Row insert error in ${tableName}: $($_.Exception.Message)" -ForegroundColor Yellow
                    $script:rowErrorLogged = $true
                }
            }
        }
        $script:rowErrorLogged = $false
    } catch {
        Write-Host "Error executing command: $_"
    } finally {
        $command.Dispose()
    }
}

CheckAndCreateSnapshotTable

$jsonTables = Get-Content .\table_definitions.json | ConvertFrom-Json
foreach ($table in $jsonTables) {
    $tableName = $table.name
    $tableColumns = $table.columns
    $foreignKeys = @(
        @{
            "ForeignKeys" = @("SnapshotID"); 
            "Table" = "SystemSnapshots"; 
            "References" = @("SnapshotID")
        };
    )
    CheckAndCreateTable $tableName $tableColumns $null $foreignKeys
}

$resultIndex = 0
foreach ($targetHost in $targetHosts) {
    write-host "importing host data: $targetHost"
    $result = Get-Content ".\system-info_$($targetHost).json" -Raw -Encoding UTF8 | ConvertFrom-Json
    $systemUUID = $result.SystemUUID
    $snapshotTime = $result.SnapshotTime
    $snapshotResult = InsertDataIntoSnapshotsTable $systemUUID $snapshotTime
    $snapshotID = $snapshotResult.SnapshotID
    if ($snapshotResult.IsExisting) {
        Write-Host "  reusing existing snapshot (SnapshotID=$snapshotID) for $targetHost"
    } else {
        Write-Host "  created new snapshot (SnapshotID=$snapshotID) for $targetHost"
    }
    foreach ($table in $jsonTables) {
        $tableName = $table.name
        write-host "importing host data: $targetHost for table name: $tableName"
        $tableColumns = $table.columns
        $tableData = $result.$($tableName)

        # ---- Normalize Linux ComputerInfo to match Windows column names ----
        if ($tableName -eq 'ComputerInfo' -and $null -ne $tableData) {
            # If it has 'Hostname' but not 'CsName', it's Linux format — remap
            if ($null -ne $tableData.Hostname -and $null -eq $tableData.CsName) {
                $tableData = @([PSCustomObject]@{
                    CsName           = $tableData.Hostname
                    CsDNSHostName    = $tableData.FQDN
                    CsDomain         = $tableData.Domain
                    CsManufacturer   = $tableData.Manufacturer
                    CsModel          = $tableData.Model
                    CsPartOfDomain   = [bool]$tableData.Domain
                    CsPCSystemType   = $tableData.Architecture
                    OsName           = $tableData.OsName
                    OsType           = $tableData.OsId
                    OsVersion        = $tableData.OsVersion
                    OsSystemDrive    = '/'
                    OsLastBootUpTime = if ($tableData.LastBootTime) { try { [datetime]::Parse($tableData.LastBootTime) } catch { $null } } else { $null }
                })
            }
        }

        # ---- Normalize Linux Users to match Windows column names + add Linux fields ----
        if ($tableName -eq 'Users' -and $null -ne $tableData -and @($tableData).Count -gt 0) {
            $first = @($tableData)[0]
            if ($null -ne $first.UID -and $null -eq $first.SID) {
                $flatRows = New-Object System.Collections.ArrayList
                foreach ($u in $tableData) {
                    $null = $flatRows.Add([PSCustomObject]@{
                        Name                = $u.Name
                        Enabled             = if ($null -ne $u.InteractiveLogin) { $u.InteractiveLogin } else { $true }
                        LastLogon           = $null
                        PasswordLastSet     = $null
                        PrincipalSource     = 'Linux'
                        SID                 = "$($u.UID)"
                        UID                 = $u.UID
                        GID                 = $u.GID
                        HomeDirectory       = $u.HomeDirectory
                        Shell               = $u.Shell
                        PasswordStatus      = $u.PasswordStatus
                        PasswordFingerprint = $u.PasswordFingerprint
                        PasswordLocked      = $u.PasswordLocked
                    })
                }
                $tableData = $flatRows
            }
        }

        # ---- Normalize Linux EnvironmentVariables (dict -> array of Name,Value) ----
        if ($tableName -eq 'EnvironmentVariables' -and $null -ne $tableData -and $tableData -is [PSCustomObject]) {
            # Check if it's a dict (Linux) vs array (Windows)
            $props = @($tableData.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' })
            if ($props.Count -gt 0 -and $null -eq $tableData.Name) {
                $flatRows = New-Object System.Collections.ArrayList
                foreach ($prop in $props) {
                    $null = $flatRows.Add([PSCustomObject]@{
                        Name  = $prop.Name
                        Value = if ($prop.Value -is [string]) { $prop.Value } else { ($prop.Value | ConvertTo-Json -Compress -Depth 2) }
                    })
                }
                $tableData = $flatRows
            }
        }

        # ---- Normalize Linux DiskVolumes to match Windows column names ----
        if ($tableName -eq 'DiskVolumes' -and $null -ne $tableData -and @($tableData).Count -gt 0) {
            $first = @($tableData)[0]
            if ($null -ne $first.name -and $null -eq $first.UniqueId) {
                $flatRows = New-Object System.Collections.ArrayList
                foreach ($vol in $tableData) {
                    $null = $flatRows.Add([PSCustomObject]@{
                        UniqueId        = $vol.uuid
                        DriveLetter     = $vol.mountpoint
                        DriveType       = $vol.type
                        Size            = $vol.size
                        FileSystemLabel = $vol.name
                        FileSystem      = $vol.fstype
                    })
                }
                $tableData = $flatRows
            }
        }

        # ---- Normalize Linux Members to match Windows column names ----
        if ($tableName -eq 'Members' -and $null -ne $tableData -and @($tableData).Count -gt 0) {
            $first = @($tableData)[0]
            if ($null -ne $first.UserName -and $null -eq $first.UserSID) {
                $flatRows = New-Object System.Collections.ArrayList
                foreach ($m in $tableData) {
                    $null = $flatRows.Add([PSCustomObject]@{
                        UserSID  = $m.UserName
                        GroupSID = $m.GroupName
                    })
                }
                $tableData = $flatRows
            }
        }

        # ---- Normalize Linux Routes to match Windows column names ----
        if ($tableName -eq 'Routes' -and $null -ne $tableData -and @($tableData).Count -gt 0) {
            $first = @($tableData)[0]
            if ($null -ne $first.Destination -and $null -eq $first.DestinationPrefix) {
                $flatRows = New-Object System.Collections.ArrayList
                foreach ($r in $tableData) {
                    $null = $flatRows.Add([PSCustomObject]@{
                        InterfaceIndex    = 0
                        DestinationPrefix = $r.Destination
                        NextHop           = $r.Gateway
                        RouteMetric       = $r.Metric
                    })
                }
                $tableData = $flatRows
            }
        }

        # ---- Normalize Linux SecurityProducts to match Windows column names ----
        if ($tableName -eq 'SecurityProducts' -and $null -ne $tableData -and @($tableData).Count -gt 0) {
            $first = @($tableData)[0]
            if ($null -ne $first.Name -and $null -eq $first.DisplayName) {
                $flatRows = New-Object System.Collections.ArrayList
                foreach ($p in $tableData) {
                    $enabled = $false
                    if ($p.ServiceStatus -eq 'active' -or $p.ServiceStatus -eq 'running') { $enabled = $true }
                    $null = $flatRows.Add([PSCustomObject]@{
                        Type                   = $p.Type
                        DisplayName            = $p.Name
                        InstanceGuid           = $p.ServiceName
                        PathToSignedProductExe = $p.Version
                        ProductState           = $null
                        Enabled                = $enabled
                        DefinitionsUpToDate    = $null
                    })
                }
                $tableData = $flatRows
            }
        }

        # ---- Flatten nested structures into row arrays ----
        if ($tableName -eq 'SecurityOptions' -and $null -ne $tableData) {
            # SecurityOptions is { SystemAccess:{k:v}, RegistryValues:{k:v}, PrivilegeRights:{k:v} }
            $flatRows = New-Object System.Collections.ArrayList
            foreach ($section in @('SystemAccess', 'RegistryValues', 'PrivilegeRights')) {
                $dict = $tableData.$section
                if ($null -ne $dict) {
                    foreach ($prop in $dict.PSObject.Properties) {
                        $null = $flatRows.Add([PSCustomObject]@{
                            Section      = $section
                            SettingName  = $prop.Name
                            SettingValue = if ($prop.Value -is [string]) { $prop.Value } else { ($prop.Value | ConvertTo-Json -Compress -Depth 3) }
                        })
                    }
                }
            }
            $tableData = $flatRows
        }
        elseif ($tableName -eq 'RegistryValues' -and $null -ne $result.RegistrySnapshot) {
            # RegistrySnapshot is array of { Path, Values:{name:{Value,Kind}}, SubkeyCount, Subkeys }
            $flatRows = New-Object System.Collections.ArrayList
            foreach ($entry in $result.RegistrySnapshot) {
                if ($null -eq $entry.Values) { continue }
                foreach ($prop in $entry.Values.PSObject.Properties) {
                    $valObj = $prop.Value
                    $valData = if ($valObj -is [PSCustomObject] -and $null -ne $valObj.Value) {
                        if ($valObj.Value -is [string]) { $valObj.Value -replace "`0", '' } else { ($valObj.Value | ConvertTo-Json -Compress -Depth 3) -replace "`0", '' }
                    } else { '' }
                    $valKind = if ($valObj -is [PSCustomObject] -and $valObj.Kind) { $valObj.Kind } else { '' }
                    $null = $flatRows.Add([PSCustomObject]@{
                        Path      = $entry.Path
                        ValueName = $prop.Name
                        ValueData = $valData
                        ValueKind = $valKind
                    })
                }
            }
            $tableData = $flatRows
        }
        elseif ($tableName -eq 'RecentEvents' -and $null -ne $tableData) {
            # RecentEvents is { Logon4624:[{TimeCreated,Id,Message}], FailedLogon4625:[...], ... }
            $flatRows = New-Object System.Collections.ArrayList
            foreach ($prop in $tableData.PSObject.Properties) {
                $category = $prop.Name
                if ($null -eq $prop.Value) { continue }
                foreach ($evt in $prop.Value) {
                    $null = $flatRows.Add([PSCustomObject]@{
                        Category    = $category
                        TimeCreated = if ($evt.TimeCreated) { $evt.TimeCreated.ToString() } else { '' }
                        EventId     = $evt.Id
                        Message     = $evt.Message
                    })
                }
            }
            $tableData = $flatRows
        }
        elseif ($tableName -eq 'PSHistory' -and $null -ne $tableData) {
            # PSHistory is [{ User, Path, Size, Lines:[] }] — join Lines into text
            $flatRows = New-Object System.Collections.ArrayList
            foreach ($entry in $tableData) {
                $lines = if ($entry.Lines -is [array]) { $entry.Lines -join "`n" } else { $entry.Lines }
                $null = $flatRows.Add([PSCustomObject]@{
                    UserName = $entry.User
                    Path     = $entry.Path
                    Size     = $entry.Size
                    Lines    = $lines
                })
            }
            $tableData = $flatRows
        }
        elseif ($tableName -eq 'ASRRules' -and $null -ne $tableData) {
            # ASRRules is { Enabled:int, Rules:{guid:mode,...}, Exclusions:{path:val,...} }
            $flatRows = New-Object System.Collections.ArrayList
            $enabled = $tableData.Enabled
            if ($null -ne $tableData.Rules) {
                foreach ($prop in $tableData.Rules.PSObject.Properties) {
                    if ($prop.Name -match '^PS') { continue }
                    $null = $flatRows.Add([PSCustomObject]@{
                        Enabled      = $enabled
                        EntryType    = 'Rule'
                        SettingKey   = $prop.Name
                        SettingValue = $prop.Value
                    })
                }
            }
            if ($null -ne $tableData.Exclusions) {
                foreach ($prop in $tableData.Exclusions.PSObject.Properties) {
                    if ($prop.Name -match '^PS') { continue }
                    $null = $flatRows.Add([PSCustomObject]@{
                        Enabled      = $enabled
                        EntryType    = 'Exclusion'
                        SettingKey   = $prop.Name
                        SettingValue = $prop.Value
                    })
                }
            }
            $tableData = $flatRows
        }
        elseif ($tableName -eq 'LAPSInstalled' -and $null -ne $tableData) {
            # LAPSInstalled is { DllExists:bool, PolicyConfig:{AdmPwdEnabled:int,...} }
            $pc = $tableData.PolicyConfig
            $tableData = @([PSCustomObject]@{
                DllExists          = $tableData.DllExists
                AdmPwdEnabled      = if ($pc) { $pc.AdmPwdEnabled } else { $null }
                PasswordComplexity = if ($pc) { $pc.PasswordComplexity } else { $null }
                PasswordLength     = if ($pc) { $pc.PasswordLength } else { $null }
                PasswordAgeDays    = if ($pc) { $pc.PasswordAgeDays } else { $null }
            })
        }
        elseif ($tableName -eq 'AppLockerPolicy' -and $null -ne $result.AppLockerPolicy) {
            # AppLockerPolicy is a raw XML string — wrap in a single-row object
            $tableData = @([PSCustomObject]@{
                PolicyXml = $result.AppLockerPolicy
            })
        }
        elseif ($tableName -eq 'WEFConfig' -and $null -ne $result.WEFConfig) {
            $tableData = @([PSCustomObject]@{
                ConfigData = ($result.WEFConfig | ConvertTo-Json -Compress -Depth 3)
            })
        }
        elseif ($tableName -eq 'CachedCredentials' -and $null -ne $result.CachedCredentials) {
            $text = if ($result.CachedCredentials -is [array]) { $result.CachedCredentials -join "`n" } else { $result.CachedCredentials.ToString() }
            $tableData = @([PSCustomObject]@{ Output = $text })
        }
        elseif ($tableName -eq 'SysmonConfig' -and $null -ne $result.SysmonConfig) {
            $tableData = @([PSCustomObject]@{
                HashingAlgorithm = $result.SysmonConfig.HashingAlgorithm
                Options          = $result.SysmonConfig.Options
            })
        }
        elseif ($tableName -eq 'SnapshotMetadata') {
            # Collect remaining scalar/blob fields into key-value rows
            $flatRows = New-Object System.Collections.ArrayList
            # IsDomainController
            if ($null -ne $result.IsDomainController) {
                $null = $flatRows.Add([PSCustomObject]@{ Key = 'IsDomainController'; Value = $result.IsDomainController.ToString() })
            }
            # InsideContainer
            if ($null -ne $result.InsideContainer) {
                $null = $flatRows.Add([PSCustomObject]@{ Key = 'InsideContainer'; Value = $result.InsideContainer.ToString() })
            }
            # HostsFileContent
            if ($result.HostsFileContent) {
                $null = $flatRows.Add([PSCustomObject]@{ Key = 'HostsFileContent'; Value = $result.HostsFileContent })
            }
            # UnattendFiles
            if ($null -ne $result.UnattendFiles) {
                $uf = if ($result.UnattendFiles -is [array]) { $result.UnattendFiles -join ';' } else { $result.UnattendFiles.ToString() }
                $null = $flatRows.Add([PSCustomObject]@{ Key = 'UnattendFiles'; Value = $uf })
            }
            # AutorunscErrors
            if ($result.AutorunscErrors) {
                $null = $flatRows.Add([PSCustomObject]@{ Key = 'AutorunscErrors'; Value = $result.AutorunscErrors.ToString() })
            }
            # FileInventoryCount
            if ($null -ne $result.FileInventoryCount) {
                $null = $flatRows.Add([PSCustomObject]@{ Key = 'FileInventoryCount'; Value = $result.FileInventoryCount.ToString() })
            }
            # FileInventoryErrors
            if ($result.FileInventoryErrors) {
                $null = $flatRows.Add([PSCustomObject]@{ Key = 'FileInventoryErrors'; Value = $result.FileInventoryErrors })
            }
            # RegistryErrors
            if ($null -ne $result.RegistryErrors -and @($result.RegistryErrors).Count -gt 0) {
                $null = $flatRows.Add([PSCustomObject]@{ Key = 'RegistryErrors'; Value = ($result.RegistryErrors | ConvertTo-Json -Compress -Depth 3) })
            }
            # SudoVersion (Linux)
            if ($result.SudoVersion) {
                $null = $flatRows.Add([PSCustomObject]@{ Key = 'SudoVersion'; Value = $result.SudoVersion })
            }
            $tableData = $flatRows
        }
        # ---- Linux nested structure flattening ----
        elseif ($tableName -eq 'LoggedInUsers' -and $null -ne $tableData) {
            $flatRows = New-Object System.Collections.ArrayList
            if ($tableData.ActiveSessions) {
                foreach ($s in $tableData.ActiveSessions) {
                    $null = $flatRows.Add([PSCustomObject]@{
                        SessionType = 'Active'; UserName = $s.UserName; Terminal = $s.Terminal
                        LoginTime = $s.LoginTime; Source = $s.Source; RemoteAddress = ''
                        SessionId = ''; State = ''; Service = ''
                    })
                }
            }
            if ($tableData.SSHConnections) {
                foreach ($s in $tableData.SSHConnections) {
                    $null = $flatRows.Add([PSCustomObject]@{
                        SessionType = 'SSH'; UserName = ''; Terminal = ''
                        LoginTime = ''; Source = ''; RemoteAddress = $s.RemoteAddress
                        SessionId = ''; State = ''; Service = ''
                    })
                }
            }
            if ($tableData.LogindSessions) {
                foreach ($s in $tableData.LogindSessions) {
                    $null = $flatRows.Add([PSCustomObject]@{
                        SessionType = 'Logind'; UserName = $s.Name; Terminal = $s.TTY
                        LoginTime = ''; Source = $s.RemoteHost; RemoteAddress = $s.RemoteHost
                        SessionId = $s.SessionId; State = $s.State; Service = $s.Service
                    })
                }
            }
            $tableData = $flatRows
        }
        elseif ($tableName -eq 'HostsFile' -and $null -ne $tableData) {
            $flatRows = New-Object System.Collections.ArrayList
            foreach ($entry in $tableData) {
                $hostnames = if ($entry.Hostnames -is [array]) { $entry.Hostnames -join ' ' } else { $entry.Hostnames }
                $null = $flatRows.Add([PSCustomObject]@{ IPAddress = $entry.IPAddress; Hostnames = $hostnames })
            }
            $tableData = $flatRows
        }
        elseif ($tableName -eq 'KernelHardening' -and $null -ne $tableData) {
            $flatRows = New-Object System.Collections.ArrayList
            foreach ($prop in $tableData.PSObject.Properties) {
                $null = $flatRows.Add([PSCustomObject]@{ Setting = $prop.Name; SettingValue = $prop.Value.ToString() })
            }
            $tableData = $flatRows
        }
        elseif ($tableName -eq 'SecurityModules' -and $null -ne $tableData) {
            $flatRows = New-Object System.Collections.ArrayList
            foreach ($prop in $tableData.PSObject.Properties) {
                $val = if ($prop.Value -is [string]) { $prop.Value } else { ($prop.Value | ConvertTo-Json -Compress -Depth 3) }
                $null = $flatRows.Add([PSCustomObject]@{ Module = $prop.Name; Status = $val })
            }
            $tableData = $flatRows
        }
        elseif ($tableName -eq 'ContainerInfo' -and $null -ne $tableData) {
            $tools = if ($tableData.container_tools -is [array]) { $tableData.container_tools -join ',' } else { '' }
            $sockets = if ($tableData.docker_sockets) { ($tableData.docker_sockets | ConvertTo-Json -Compress -Depth 3) } else { '' }
            $tableData = @([PSCustomObject]@{
                InsideContainer = $tableData.inside_container
                ContainerType = $tableData.container_type
                ContainerTools = $tools
                DockerSockets = $sockets
                K8sServiceAccount = $tableData.k8s_service_account
            })
        }
        elseif ($tableName -eq 'SshConfig' -and $null -ne $tableData) {
            $flatRows = New-Object System.Collections.ArrayList
            if ($tableData.SshdSettings) {
                foreach ($prop in $tableData.SshdSettings.PSObject.Properties) {
                    $null = $flatRows.Add([PSCustomObject]@{ Section = 'SshdSettings'; SettingKey = $prop.Name; SettingValue = $prop.Value })
                }
            }
            if ($tableData.HostKeys) {
                foreach ($hk in $tableData.HostKeys) {
                    $null = $flatRows.Add([PSCustomObject]@{ Section = 'HostKey'; SettingKey = $hk.File; SettingValue = $hk.Key })
                }
            }
            if ($tableData.AgentSockets) {
                foreach ($as in $tableData.AgentSockets) {
                    $null = $flatRows.Add([PSCustomObject]@{ Section = 'AgentSocket'; SettingKey = $as.Path; SettingValue = $as.UID.ToString() })
                }
            }
            if ($tableData.HostsAllow) { $null = $flatRows.Add([PSCustomObject]@{ Section = 'TCPWrappers'; SettingKey = 'hosts.allow'; SettingValue = $tableData.HostsAllow }) }
            if ($tableData.HostsDeny) { $null = $flatRows.Add([PSCustomObject]@{ Section = 'TCPWrappers'; SettingKey = 'hosts.deny'; SettingValue = $tableData.HostsDeny }) }
            $tableData = $flatRows
        }
        elseif ($tableName -eq 'PrivilegedGroups' -and $null -ne $tableData) {
            $flatRows = New-Object System.Collections.ArrayList
            foreach ($prop in $tableData.PSObject.Properties) {
                $members = if ($prop.Value -is [array]) { $prop.Value -join ',' } else { $prop.Value.ToString() }
                $null = $flatRows.Add([PSCustomObject]@{ GroupName = $prop.Name; Members = $members })
            }
            $tableData = $flatRows
        }
        elseif ($tableName -eq 'KerberosConfig' -and $null -ne $tableData) {
            $flatRows = New-Object System.Collections.ArrayList
            foreach ($prop in $tableData.PSObject.Properties) {
                $val = if ($prop.Value -is [string]) { $prop.Value } elseif ($prop.Value -is [array]) { ($prop.Value | ConvertTo-Json -Compress -Depth 3) } else { $prop.Value.ToString() }
                $null = $flatRows.Add([PSCustomObject]@{ SettingKey = $prop.Name; SettingValue = $val })
            }
            $tableData = $flatRows
        }
        elseif ($tableName -eq 'RcommandsTrust' -and $null -ne $tableData) {
            $flatRows = New-Object System.Collections.ArrayList
            foreach ($prop in $tableData.PSObject.Properties) {
                $null = $flatRows.Add([PSCustomObject]@{ FilePath = $prop.Name; Content = $prop.Value })
            }
            $tableData = $flatRows
        }
        elseif ($tableName -eq 'ShellHistory' -and $null -ne $tableData) {
            $flatRows = New-Object System.Collections.ArrayList
            foreach ($entry in $tableData) {
                $lines = if ($entry.Last200 -is [array]) { $entry.Last200 -join "`n" } else { $entry.Last200 }
                $null = $flatRows.Add([PSCustomObject]@{
                    UserName = $entry.User; File = $entry.File; TotalLines = $entry.TotalLines; Lines = $lines
                })
            }
            $tableData = $flatRows
        }
        elseif ($tableName -eq 'AuditConfig' -and $null -ne $tableData) {
            $flatRows = New-Object System.Collections.ArrayList
            if ($tableData.AuditdStatus) { $null = $flatRows.Add([PSCustomObject]@{ SettingKey = 'AuditdStatus'; SettingValue = $tableData.AuditdStatus }) }
            if ($tableData.AuditRules) { $null = $flatRows.Add([PSCustomObject]@{ SettingKey = 'AuditRules'; SettingValue = ($tableData.AuditRules -join "`n") }) }
            if ($tableData.AuditdConfig) {
                foreach ($prop in $tableData.AuditdConfig.PSObject.Properties) {
                    $null = $flatRows.Add([PSCustomObject]@{ SettingKey = "AuditdConfig.$($prop.Name)"; SettingValue = $prop.Value })
                }
            }
            $tableData = $flatRows
        }
        elseif ($tableName -eq 'PamConfig' -and $null -ne $tableData) {
            $flatRows = New-Object System.Collections.ArrayList
            if ($tableData.PamFiles) {
                foreach ($prop in $tableData.PamFiles.PSObject.Properties) {
                    $val = if ($prop.Value -is [array]) { $prop.Value -join "`n" } else { $prop.Value.ToString() }
                    $null = $flatRows.Add([PSCustomObject]@{ Section = 'PamFile'; SettingKey = $prop.Name; SettingValue = $val })
                }
            }
            if ($tableData.LoginDefs) {
                foreach ($prop in $tableData.LoginDefs.PSObject.Properties) {
                    $null = $flatRows.Add([PSCustomObject]@{ Section = 'LoginDefs'; SettingKey = $prop.Name; SettingValue = $prop.Value })
                }
            }
            $tableData = $flatRows
        }
        elseif ($tableName -eq 'CollectionErrors' -and $null -ne $tableData) {
            if ($tableData -is [string]) {
                $tableData = @([PSCustomObject]@{ Error = $tableData })
            } elseif ($tableData -is [array]) {
                $flatRows = New-Object System.Collections.ArrayList
                foreach ($err in $tableData) { $null = $flatRows.Add([PSCustomObject]@{ Error = $err.ToString() }) }
                $tableData = $flatRows
            }
        }
        elseif ($tableName -eq 'FirewallRules' -and $null -ne $tableData -and $tableData -is [PSCustomObject] -and -not ($tableData | Get-Member -Name 'Name' -MemberType NoteProperty)) {
            # Linux FirewallRules is {iptables:str, nftables:str, ...} — flatten to SnapshotMetadata-style rows
            # Skip — the Windows array format is handled by the generic path; store Linux as metadata
            $flatRows = New-Object System.Collections.ArrayList
            foreach ($prop in $tableData.PSObject.Properties) {
                $null = $flatRows.Add([PSCustomObject]@{
                    Name = $prop.Name; DisplayName = $prop.Name; Direction = ''; Action = ''
                    Profile = ''; Enabled = ''; Description = $prop.Value
                })
            }
            $tableData = $flatRows
        }

        if ($null -ne $tableData -and @($tableData).Count -gt 0) {
            InsertDataIntoTable $tableName $tableColumns $tableData $snapshotID
        }
    }

    # ---- Import MFT File Inventory CSV via COPY (bulk load) ----
    # Resolve hostname for CSV filename (. / localhost -> COMPUTERNAME)
    $csvHostName = if ($targetHost -in @('.', 'localhost', '127.0.0.1')) { $env:COMPUTERNAME } else { $targetHost }
    $csvPath = ".\file-inventory_$($csvHostName).csv"
    if (Test-Path $csvPath) {
        Write-Host "importing MFT file inventory: $csvPath"
        # Create table if not exists
        $createCmd = $connection.CreateCommand()
        try {
            $createCmd.CommandText = @"
CREATE TABLE IF NOT EXISTS public.fileinventory (
    id BIGSERIAL PRIMARY KEY,
    snapshotid INTEGER REFERENCES public.systemsnapshots(snapshotid),
    fullpath TEXT,
    filename VARCHAR(512),
    fileattributes INTEGER,
    filesize BIGINT DEFAULT 0
)
"@
            $null = $createCmd.ExecuteNonQuery()
            # Create index for path lookups
            $createCmd.CommandText = "CREATE INDEX IF NOT EXISTS idx_fileinventory_snap ON public.fileinventory(snapshotid)"
            $null = $createCmd.ExecuteNonQuery()
            $createCmd.CommandText = "CREATE INDEX IF NOT EXISTS idx_fileinventory_name ON public.fileinventory(filename)"
            $null = $createCmd.ExecuteNonQuery()
        } catch {
            Write-Host "  Error creating fileinventory table: $_" -ForegroundColor Red
        } finally {
            $createCmd.Dispose()
        }

        # Delete existing rows for this snapshot
        $delCmd = $connection.CreateCommand()
        try {
            $delCmd.CommandText = "DELETE FROM public.fileinventory WHERE snapshotid = @sid"
            $null = $delCmd.Parameters.AddWithValue("@sid", $snapshotID)
            $deleted = $delCmd.ExecuteNonQuery()
            if ($deleted -gt 0) { Write-Host "  cleared $deleted existing file inventory rows" }
        } catch {} finally { $delCmd.Dispose() }

        # Bulk load via COPY FROM STDIN
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $rowCount = 0
        $errorCount = 0
        try {
            $copyCmd = "COPY public.fileinventory (snapshotid, fullpath, filename, fileattributes, filesize) FROM STDIN WITH (FORMAT csv, HEADER false)"
            $writer = $connection.BeginTextImport($copyCmd)
            # Read raw bytes; decode each line as UTF-8 with replacement to guarantee clean output
            $utf8Replace = [System.Text.Encoding]::GetEncoding('utf-8', [System.Text.EncoderReplacementFallback]::new('_'), [System.Text.DecoderReplacementFallback]::new('_'))
            $allBytes = [System.IO.File]::ReadAllBytes($csvPath)
            $allText = $utf8Replace.GetString($allBytes)
            $allBytes = $null  # free memory
            $lines = $allText.Split([string[]]@("`r`n", "`n"), [StringSplitOptions]::None)
            $allText = $null  # free memory
            $isHeader = $true

            foreach ($line in $lines) {
                if ($isHeader) { $isHeader = $false; continue }
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                try {
                    # Strip control chars except comma and quote (CSV delimiters)
                    $safeLine = $line -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
                    $writer.WriteLine("$snapshotID,$safeLine")
                    $rowCount++
                    if ($rowCount % 500000 -eq 0) {
                        Write-Host "  loaded $rowCount rows..." -ForegroundColor Gray
                    }
                } catch {
                    $errorCount++
                }
            }
            $lines = $null
            $writer.Dispose()
            $sw.Stop()
            Write-Host "  MFT import complete: $rowCount rows in $([math]::Round($sw.Elapsed.TotalSeconds, 1))s ($errorCount parse errors)" -ForegroundColor Green
        } catch {
            Write-Host "  MFT bulk import error: $_" -ForegroundColor Red
            Write-Host "  ($rowCount rows were loaded before the error)" -ForegroundColor Yellow
        }
    }

    # ---- Import Linux FileInventory from JSON (if no CSV but JSON has data) ----
    if (-not (Test-Path $csvPath) -and $null -ne $result.FileInventory -and @($result.FileInventory).Count -gt 0) {
        Write-Host "importing Linux file inventory from JSON: $(@($result.FileInventory).Count) entries"
        # Ensure table exists
        $createCmd = $connection.CreateCommand()
        try {
            $createCmd.CommandText = @"
CREATE TABLE IF NOT EXISTS public.fileinventory (
    id BIGSERIAL PRIMARY KEY,
    snapshotid INTEGER REFERENCES public.systemsnapshots(snapshotid),
    fullpath TEXT,
    filename VARCHAR(512),
    fileattributes INTEGER,
    filesize BIGINT DEFAULT 0
)
"@
            $null = $createCmd.ExecuteNonQuery()
            $createCmd.CommandText = "CREATE INDEX IF NOT EXISTS idx_fileinventory_snap ON public.fileinventory(snapshotid)"
            $null = $createCmd.ExecuteNonQuery()
            $createCmd.CommandText = "CREATE INDEX IF NOT EXISTS idx_fileinventory_name ON public.fileinventory(filename)"
            $null = $createCmd.ExecuteNonQuery()
        } catch {} finally { $createCmd.Dispose() }

        # Delete existing
        $delCmd = $connection.CreateCommand()
        try {
            $delCmd.CommandText = "DELETE FROM public.fileinventory WHERE snapshotid = @sid"
            $null = $delCmd.Parameters.AddWithValue("@sid", $snapshotID)
            $deleted = $delCmd.ExecuteNonQuery()
            if ($deleted -gt 0) { Write-Host "  cleared $deleted existing file inventory rows" }
        } catch {} finally { $delCmd.Dispose() }

        # Bulk load via COPY
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $rowCount = 0
        try {
            $copyCmd = "COPY public.fileinventory (snapshotid, fullpath, filename, fileattributes, filesize) FROM STDIN WITH (FORMAT csv, HEADER false)"
            $writer = $connection.BeginTextImport($copyCmd)
            foreach ($fi in $result.FileInventory) {
                $path = ($fi.Path -replace '"', '""')
                $fname = [System.IO.Path]::GetFileName($fi.Path) -replace '"', '""'
                $attrs = 0  # Linux doesn't have Windows file attributes; store permissions as text isn't compatible
                $size = if ($fi.Size) { $fi.Size } else { 0 }
                $writer.WriteLine("$snapshotID,`"$path`",`"$fname`",$attrs,$size")
                $rowCount++
                if ($rowCount % 50000 -eq 0) {
                    Write-Host "  loaded $rowCount rows..." -ForegroundColor Gray
                }
            }
            $writer.Dispose()
            $sw.Stop()
            Write-Host "  Linux file inventory import complete: $rowCount rows in $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" -ForegroundColor Green
        } catch {
            Write-Host "  Linux file inventory bulk import error: $_" -ForegroundColor Red
            Write-Host "  ($rowCount rows were loaded before the error)" -ForegroundColor Yellow
        }
    }

    $resultIndex++
}

$connection.Close()
Write-Host "Data inserted into database"