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
        if ($null -ne $tableData -and $tableData.Count -gt 0) {
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

    $resultIndex++
}

$connection.Close()
Write-Host "Data inserted into database"