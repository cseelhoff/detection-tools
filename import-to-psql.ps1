# check if $creds is defined
if (-not $creds) {
    $creds = Get-Credential -UserName 'luke.verlooy@mda.mil'
}
$targetHosts = (Get-Content -Path '.\targetHosts.txt' -Raw).Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)

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
            $null = $command.Parameters.AddWithValue("@SnapshotID", $snapshotID)
            $null = $command.ExecuteNonQuery()
        }
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
    $result = Get-Content ".\system-info_$($targetHost).json" | ConvertFrom-Json
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
        if ($null -ne $tableData -and $tableData.Count -gt 0) {
            InsertDataIntoTable $tableName $tableColumns $tableData $snapshotID
        }
    }
    $resultIndex++
}

$connection.Close()
Write-Host "Data inserted into database"