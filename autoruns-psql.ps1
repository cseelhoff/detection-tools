# check if $creds is defined
if (-not $creds) {
    $creds = Get-Credential -UserName 'localadmin'
}
$targetHosts = Get-Content -Path '.\targetHosts.txt'
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
    $autorunscResults = Invoke-Command -Session $session -ScriptBlock {
        # Define the path to autorunsc.exe in the Downloads directory
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
        $p.Start() | Out-Null
        $stdout = $p.StandardOutput.ReadToEnd()
        $stderr = $p.StandardError.ReadToEnd()
        $p.WaitForExit()

        return ($stdout + $stderr)
    }
    $autorunscResults
}
$maxConcurrentJobs = 10

# Create an array to hold the job objects
$jobs = @()

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

    # Update the progress bar
    Write-Progress -Activity "Processing target hosts" -Status "$i of $targetHostsCount completed" -PercentComplete (($i / $targetHostsCount) * 100)
}

# Wait for all jobs to complete
$jobs | Wait-Job

# Collect the results
$results = $jobs | Receive-Job
$resultIndex = 0
foreach ($result in $results) {
    #output the results
    $json = $result | ConvertFrom-Csv -Delimiter "`t" | ConvertTo-Json -Depth 9
    $json | Out-File -FilePath ".\autorunscResults_$($targetHosts[$resultIndex]).json"
    $resultIndex++
}

# Load the Npgsql .NET data provider for PostgreSQL
Add-Type -Path "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Npgsql\v4.0_4.1.14.0__5d8b90d52f46fda7\Npgsql.dll"

# Read the JSON file
#$json = Get-Content -Path '.\autoruns.json' | ConvertFrom-Json

# Define the connection string
$connectionString = "Host=localhost;Username=postgres;Password=password;Database=postgres"

# Create a new connection
$connection = New-Object Npgsql.NpgsqlConnection($connectionString)
$connection.Open()

$scanRun = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

foreach($targetHost in $targetHosts) {
    $json = Get-Content -Path ".\autorunscResults_$targetHost.json" | ConvertFrom-Json


    # Loop through each object in the JSON array
    foreach ($item in $json) {
        # Create a new command
        if($null -eq $item.Entry -or $item.Entry -eq "") {
            continue
        }
        $command = $connection.CreateCommand()

        # Define the parameters and escape any single quotes
        #$time = "'" + ($item.Time -replace "'", "''") + "'"
        #if ($time -eq "''") {
        #    $time = "NULL"
        #}
        $entryLocation = $item.'Entry Location' -replace "'", "''"
        $entry = $item.Entry -replace "'", "''"
        $enabled = $item.Enabled -replace "'", "''"
        $category = $item.Category -replace "'", "''"
        $item_profile = $item.Profile -replace "'", "''"
        $description = $item.Description -replace "'", "''"
        $signer = $item.Signer -replace "'", "''"
        $company = $item.Company -replace "'", "''"
        $imagePath = $item.'Image Path' -replace "'", "''"
        $version = $item.Version -replace "'", "''"
        $launchString = $item.'Launch String' -replace "'", "''"
        $md5 = $item.MD5 -replace "'", "''"
        $sha1 = $item.'SHA-1' -replace "'", "''"
        $pesha1 = $item.'PESHA-1' -replace "'", "''"
        $pesha256 = $item.'PESHA-256' -replace "'", "''"
        $sha256 = $item.'SHA-256' -replace "'", "''"
        $imp = $item.IMP -replace "'", "''"
        
        $command.CommandText = @"
INSERT INTO autoruns (
    Time, Target_Host, Entry_Location, Entry, Enabled, Category, Profile, Description, Signer, Company, Image_Path, Version, Launch_String, MD5, SHA_1, PESHA_1, PESHA_256, SHA_256, IMP
) VALUES (
    '$scanRun', '$targetHost', '$entryLocation', '$entry', '$enabled', '$category', '$item_profile', '$description', '$signer', '$company', '$imagePath', '$version', '$launchString', '$md5', '$sha1', '$pesha1', '$pesha256', '$sha256', '$imp'
)
"@
        # Execute the command with a try/catch block and print any errors
        try {
            $null = $command.ExecuteNonQuery()
        } catch {
            Write-Host $_.Exception.Message
            Write-Host ($item | ConvertTo-Json)
            Write-Host ($command.CommandText)
            Read-Host -Prompt "Press Enter to continue"
        }
    }
}

$command = $connection.CreateCommand()
$command.CommandText = @"
WITH 
latest_timestamps AS (
    SELECT Target_Host, MAX(time) AS run_time
    FROM autoruns
    GROUP BY Target_Host
),
oldest_timestamps AS (
    SELECT Target_Host, MIN(time) AS run_time
    FROM autoruns
    GROUP BY Target_Host
),
latest_entries AS (
    SELECT *
    FROM autoruns
    WHERE (Target_Host, time) IN (SELECT Target_Host, run_time FROM latest_timestamps)
),
oldest_entries AS (
    SELECT *
    FROM autoruns
    WHERE (Target_Host, time) IN (SELECT Target_Host, run_time FROM oldest_timestamps)
)
SELECT latest_entries.*
FROM latest_entries
LEFT JOIN oldest_entries
ON latest_entries.launch_string = oldest_entries.launch_string AND latest_entries.md5 = oldest_entries.md5 AND latest_entries.Target_Host = oldest_entries.Target_Host
WHERE oldest_entries.Target_Host IS NULL
UNION
SELECT oldest_entries.*
FROM oldest_entries
LEFT JOIN latest_entries
ON latest_entries.launch_string = oldest_entries.launch_string AND latest_entries.md5 = oldest_entries.md5 AND latest_entries.Target_Host = oldest_entries.Target_Host
WHERE latest_entries.Target_Host IS NULL;
"@

try {
    $results = $command.ExecuteReader()
    $data = New-Object System.Data.DataTable
    $data.Load($results)
    $results.close()
    $scanRun = $scanRun -replace ":", "-"
    $data | Select-Object -ExcludeProperty RowError, RowState, Table, ItemArray, HasErrors | ConvertTo-Json -Depth 9 | Out-File -FilePath ".\autoruns_deltas_$scanRun.json"
} catch {
    Write-Host $_.Exception.Message
    Write-Host ($command.CommandText)
    Read-Host -Prompt "Press Enter to continue"
}

# Close the connection
$connection.Close()

