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
    } catch {
        Write-Host "Error executing command: $_"
    } finally {
        $command.Dispose()
    }
}

function InsertDataIntoSnapshotsTable($systemUUID, $snapshotTime) {
    $command = $connection.CreateCommand()
    $SnapshotIDResult = -1
    try {
        $command.CommandText = "INSERT INTO public.SystemSnapshots (SystemUUID, SnapshotTime) VALUES (@SystemUUID, @SnapshotTime) RETURNING SnapshotID"
        $command.Parameters.Clear()
        $null = $command.Parameters.AddWithValue("@SystemUUID", $systemUUID)
        $null = $command.Parameters.AddWithValue("@SnapshotTime", $snapshotTime)
        $SnapshotIDResult = $command.ExecuteScalar()
    } catch {
        Write-Host "Error executing command: $_"
    } finally {
        $command.Dispose()
    }
    return $SnapshotIDResult
}

function InsertDataIntoTable($tableName, $tableColumns, $tableData, $snapshotID) {
    # $tableColumns is an array of objects with properties 'name' and 'type'
    $columnNames = ($tableColumns | ForEach-Object { $_.name -replace "[^a-zA-Z0-9]", "" }) -join ","
    $columnParameterNames = ($tableColumns | ForEach-Object { '@' + ($_.name -replace "[^a-zA-Z0-9]", "")}) -join ","
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
    $snapshotID = InsertDataIntoSnapshotsTable $systemUUID $snapshotTime
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

<#
CREATE OR REPLACE VIEW public.latest_snapshots
AS SELECT systemuuid,
    max(snapshottime) AS snapshottime,
    max(snapshotid) AS snapshotid
   FROM systemsnapshots
  GROUP BY systemuuid;
#>


<#
WITH 
latest_timestamps AS (
    SELECT systemuuid, MAX(SnapshotTime) AS max_SnapshotTime
    FROM systemsnapshots
    GROUP BY systemuuid
),
oldest_timestamps AS (
    SELECT systemuuid, MIN(SnapshotTime) AS min_SnapshotTime
    FROM systemsnapshots
    WHERE (systemuuid, SnapshotTime) NOT IN (SELECT systemuuid, max_SnapshotTime FROM latest_timestamps)
    GROUP BY systemuuid
),
latest_entries AS (
    SELECT *
    FROM autorunsc
    WHERE (systemuuid, SnapshotTime) IN (SELECT systemuuid, max_SnapshotTime FROM latest_timestamps)
),
oldest_entries AS (
    SELECT *
    FROM autorunsc
    WHERE (systemuuid, SnapshotTime) IN (SELECT systemuuid, min_SnapshotTime FROM oldest_timestamps)
)
SELECT latest_entries.*
FROM latest_entries
LEFT JOIN oldest_entries
ON latest_entries.launchstring = oldest_entries.launchstring AND latest_entries.md5 = oldest_entries.md5 AND latest_entries.systemuuid = oldest_entries.systemuuid
WHERE oldest_entries.systemuuid IS NULL
UNION
SELECT oldest_entries.*
FROM oldest_entries
LEFT JOIN latest_entries
ON latest_entries.launchstring = oldest_entries.launchstring AND latest_entries.md5 = oldest_entries.md5 AND latest_entries.systemuuid = oldest_entries.systemuuid
WHERE latest_entries.systemuuid IS NULL;
#>