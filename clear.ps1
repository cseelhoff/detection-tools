# Define a function to kill a process
function Stop-ProcessForce {
    param (
        [Parameter(Mandatory=$true)]
        [string]$process_id
    )
    Process {
        Stop-Process -Id $process_id -Force
    }
}
# Define a function to delete a file
function Remove-File {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    Process {
        # Use Sysinternals' handle program to find and close any handles to the file
        #$handleOutput = & 'handle.exe' $FilePath
        #$handleOutput -match 'pid: (\d+).*?type: File.*?(\d+):' | ForEach-Object {
        #    $process_id = $Matches[1]
        #    $handle = $Matches[2]
        #    & 'handle.exe' -p $process_id -c $handle -y
        #}

        # Remove the file
        Remove-Item -Path $FilePath -Force
    }
}

# Define a function to remove persistence entries
function Remove-Persistence {
    param (
        [Parameter(Mandatory=$true)]
        [string]$autoruns_entry,
        [Parameter(Mandatory=$true)]
        [string]$autorunsc_path
    )
    Process {
        # Assuming Autorunsc is in the PATH
        & $autorunsc_path -d $autoruns_entry
    }
}
# Define a function to disable a local user account
function Disable-LocalUser {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Username
    )
    Process {
        $user = [ADSI]"WinNT://$env:COMPUTERNAME/$Username,user"
        $user.UserFlags.value = $user.UserFlags.value -bor 0x2
        $user.SetInfo()
    }
}

# Define a function to disable a domain user account
function Disable-DomainUser {
    param (
        [Parameter(Mandatory=$true)]
        [string]$samAccountName
    )
    Process {
        # Import the Active Directory module
        Import-Module ActiveDirectory

        # Disable the user
        Disable-ADAccount -Identity $samAccountName
    }
}

# Read JSON file
$jsonData = Get-Content -Path 'input.json' | ConvertFrom-Json

$credsHashTable = @{}
# Loop through each endpoint in the JSON data
foreach ($endpoint in $jsonData.endpoints) {
    # Prompt for credentials
    if ($credsHashTable.ContainsKey($endpoint.credentials)) {
        continue
    }
    $credential = Get-Credential -Message "Enter credentials for $($endpoint.credentials)"
    $credsHashTable[$endpoint.credentials] = $credential
}

$autoRunscPath = '.\autorunsc.exe'
# Loop through each endpoint in the JSON data
foreach ($endpoint in $jsonData.endpoints) {
    # Prompt for credentials
    $credential = $credsHashTable[$endpoint.credentials]
    $session = New-PSSession -ComputerName $endpoint.name -Credential $credential 

    #check if $endpoint.actions contains any actions named remove-persistence
    $removePersistenceExist = $endpoint.actions | Where-Object { $_.type -eq 'remove-persistence' }
    if ($removePersistenceExist) {
        $installResults = Invoke-Command -Session $session -ScriptBlock {
            $autorunscPath = Join-Path -Path $env:TEMP -ChildPath '\autorunsc.exe'
            [PSCustomObject]@{
                AutorunscExists = Test-Path $autorunscPath
                DownloadPath = $autorunscPath
            }
        }
        if (!$installResults.AutorunscExists) {
            Copy-Item -Path $autoRunscPath -Destination $installResults.DownloadPath -ToSession $session
        }
    }

    # Perform actions based on the JSON data
    foreach ($action in $endpoint.actions) {
        switch ($action.type) {
            'kill-process' {
                Invoke-Command -Session $session -ScriptBlock ${function:Stop-ProcessForce} -ArgumentList $action.process_id
            }
            'delete-file' {
                Invoke-Command -Session $session -ScriptBlock ${function:Remove-File} -ArgumentList $action.path
            }
            'remove-persistence' {
                Invoke-Command -Session $session -ScriptBlock ${function:Remove-Persistence} -ArgumentList $action.autoruns_entry $installResults.DownloadPath
            }
            'disable-localuser' {
                Invoke-Command -Session $session -ScriptBlock ${function:Disable-LocalUser} -ArgumentList $action.username
            }
            'disable-domainuser' {
                Invoke-Command -Session $session -ScriptBlock ${function:Disable-DomainUser} -ArgumentList $action.samAccountName
            }
        }
    }

    # Close the PSRemote session
    Remove-PSSession -Session $session
}
