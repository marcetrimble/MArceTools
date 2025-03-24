# Work Tools PowerShell Script Module
# Author: Martin Arce martin_arce@trimble.com

<#
.SYNOPSIS
Verifies if the current user has administrator permissions.

.DESCRIPTION
This function returns True when the current user is a member of the built-on Administrators group, and False 
otherwise.
#>
function Test-IsAdministrator {
    try {
        $AdminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
        $Identity =  [Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentSecId = New-Object Security.Principal.WindowsPrincipal($Identity)
        $CurrentSecId.IsInRole($AdminRole)
    }
    catch {
        Write-Warning "Error checking administrator privileges: $($_.Exception.Message)"
        return $false
    }
}

<#
.SYNOPSIS
Copies to system clipboard a location. By default uses the current location.

.DESCRIPTION
Retrieves the current location and saves it to the local clipboard as plain text.

.PARAMETER Path
Defines a custom path to a directory to be copied to the system clipboard.

.PARAMETER Verbose
Switches on or off the information messages of the script.
#>
function Copy-Location {
    [CmdletBinding()]
    param(
        [string] $Path = (Get-Location | Select-Object -ExpandProperty Path)
    )

    try{
        $ResolvedPath = Resolve-Path -Path $Path -ErrorAction Stop | Select-Object -ExpandProperty Path
        $ResolvedPath | Set-Clipboard
        Write-Verbose "`"$ResolvedPath`" copied to clipboard"
    }
    catch {
        Write-Error "Failed to copy path to clipboard: $_"
    }
}

<#
.SYNOPSIS
Finds and returns a copy of a SketchUp license for internal testing.

.DESCRIPTION
Given the SketchUp version, this cmdlet finds a local copy of a license for internal testing, copies the contents
to the local clipboard

.PARAMETER Year
Specifies the year version of the required license.
#>
function Copy-SULicence {
    [CmdletBinding()]
    param(
        [string] $Year
    )
    try {
        $secret = Get-Secret -Name "SU_LIC_$Year" -AsPlainText -ErrorAction Stop
        $secret | Set-Clipboard
    }
    catch {
        Write-Error "A licence for the provided version '$Year' is not available"
    }
}

<#
.SYNOPSIS
Shows the currently free system memory

.DESCRIPTION
This function retrieves the amount of available physical memory (RAM) on a Windows system and returns the value in
megabytes (MB)
#>
function Get-FreeMemoryGB {
    try {
        $FreeMemoryMB = Get-CimInstance -ClassName Win32_OperatingSystem |
            Select-Object -ExpandProperty FreePhysicalMemory
        $FreeMemoryGB = $FreeMemoryMB / 1MB
        return $FreeMemoryGB
    }
    catch {
        Write-Error "Failed to retrieve free physical memory: `n`t$_"
    }
}

<#
.SYNOPSIS
Shows the size in memory occupied by a folder

.DESCRIPTION
This function calculates and displays the size of a specified folder in various units (bytes, kibibytes, mebibytes,
and gibibytes)

.PARAMETER Folder
Specifies the system directory to be measured
#>
function Get-FolderSize {
    [CmdletBinding()]
    param(
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [string] $Folder = (Get-Location | Select-Object -ExpandProperty Path)
    )

    $size = Get-ChildItem -Recurse -File -Path $Folder |
        Measure-Object -Property Length -Sum |
        Select-Object -ExpandProperty Sum

    $fileSize = New-Object -TypeName psobject -Property @{
        Name     = Resolve-Path $Folder
        size_B   = $size
        size_KiB = $size/1Kb
        size_MiB = $size/1Mb
        size_GiB = $size/1Gb
    }

    # Not using Format-List because the output object don't allow for member selection
    return $fileSize
}

<#
.SYNOPSIS
Shows information about a Jira issue

.DESCRIPTION
This function uses the Jira API to query for general information about a specified Jira issue.

.PARAMETER IssueId
Specifies the issue ID of the issue to be queried

.PARAMETER Board
Specifies Jira board ID of the issue to be queried
#>
function Get-JiraIssue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [int] $IssueId,
        [string] $Board = "SUDO",
        [string] $VaultEntry = "Jira PAT pdOas913 (marce)"
    )
    try {
        # Retrieve token securely
        $Token = Get-Secret -Name $VaultEntry
        if (-not $Token) {
            throw "Failed to retrieve Jira Personal Access Token"
        }

        $Headers = @{ Accept = "application/json" }
        $Url = "https://jira.trimble.tools/rest/api/latest/issue/$Board-$IssueId"

        try {
            $Res = Invoke-RestMethod -Uri $Url -Headers $Headers -Authentication Bearer -Token $Token
            $Data = $Res.fields
        }
        catch {
            throw "Failed to retrieve Jira issue details: $_"
        }

        # Create the issue information object
        $IssueInfo = New-Object -TypeName psobject -Property @{
            IssueID      = "$board-$issueid"
            Summary      = $data.summary
            Status       = $data.status.name
            Assignee     = "$($data.assignee.displayName) - $($data.assignee.emailAddress)"
            Verifier     = "$($data.customfield_15511.displayName) - $($data.customfield_15511.emailAddress)"
            Reporter     = "$($data.reporter.displayName) - $($data.reporter.emailAddress)"
            WhatToTest   = $data.customfield_15509
            Description  = $data.description
            Created      = $data.created
            Updated      = $data.updated
            DueDate      = $data.duedate
            JiraIssueURL = "https://jira.trimble.tools/browse/$board-$issueId"
        }

        return $IssueInfo | Select-Object IssueID, Summary,  Status,  Assignee,  Verifier,  Reporter,  WhatToTest, 
            Description,  Created,  Updated,  DueDate,  JiraIssueURL
    }
    catch {
        Write-Error "An error ocurred: $_"
    }
}

<#
.SYNOPSIS
Returns a list of user defined variables

.DESCRIPTION
The Get-UDVariable PowerShell function retrieves a list of variables available in the current session,
excluding specific system variables and special variables used internally by PowerShell. This ensures that it only
returns user-defined variables from the current session.
#>
function Get-UDVariable {
    $excludedVariables = @("FormatEnumerationLimit", "MaximumAliasCount", "MaximumDriveCount",
        "MaximumErrorCount", "MaximumFunctionCount", "MaximumVariableCount", "PGHome", "PGSE", "PGUICulture",
        "PGVersionTable", "PROFILE", "PSSessionOption")
    $specialVariables = [psobject].Assembly.GetType('System.Management.Automation.SpecialVariables').
        GetFields('NonPublic,Static') | Where-Object { $_.FieldType -eq [string] } |
        ForEach-Object {$_.GetValue($null)}
    Get-Variable | Where-Object {$excludedVariables + $specialVariables -notcontains $_.Name}
}

<#
.SYNOPSIS
Generate a random username

.DESCRIPTION
This function returns a randomized string with the format 5 letters + 3 numbers
#>
function Get-Username {
    $Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()
    $Username = -join (Get-Random -InputObject $Chars[0..51] -Count 5)
    $Numbers = -join (Get-Random -InputObject $Chars[-10..-1] -Count 3)
    return $Username + $Numbers
}

<#
.SYNOPSIS
Recreates the functionality of UNIX systems utlity which

.DESCRIPTION
Shows the pathnames of the files which would be executed in the current environment, had its argument been given as
a command. This is done by searching using Get-Commands cmdlet and extracting the Path attribute with Select-Object
cmdlet

.PARAMETER FileName
Specifies the filename to look up for the current environment.
#>
function Get-CommandPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [string] $FileName
    )
    Get-Command -Name $FileName -ErrorAction SilentlyContinue | 
        Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue
}

<#
.SYNOPSIS
Copies a file from the host machine to a specified Hyper-V virtual machine.

.DESCRIPTION
This function copies a single file from the local machine to the Downloads folder of a specified Hyper-V virtual 
machine. It utilizes the `Copy-VMFile` cmdlet to perform the file transfer.

.PARAMETER VM
Specifies the target Hyper-V virtual machine. This parameter is mandatory.

.PARAMETER File
Specifies the path to the file on the host machine that will be copied. This parameter is mandatory. The path must 
point to an existing file.

.EXAMPLE
Copy-ToVM -VM "MyVM" -File "C:\Temp\MyFile.txt"
Copies the file "C:\Temp\MyFile.txt" to the "Downloads" folder of the virtual machine named "MyVM".

.NOTES
Requires the Hyper-V module to be installed. The destination path on the virtual machine is fixed to 
"C:\users\user\Downloads\". The destination filename will be the same as the source filename. Error handling is 
included to catch and display any exceptions during the file transfer.

.INPUTS
Microsoft.HyperV.PowerShell.VirtualMachineBase, String

.OUTPUTS
None or ErrorRecord

.FUNCTIONALITY
Copies a file to a Hyper-V VM.
#>
function Copy-ToVM {
    [CmdletBinding()]
	param(
	    [Parameter(Mandatory=$True)][Microsoft.HyperV.PowerShell.VirtualMachineBase] $VM,
	    [Parameter(Mandatory=$True)][ValidateScript({Test-Path -Path $_ -PathType Leaf})][string] $File
	)
    try {
        $FileFullName = Resolve-Path -Path $File | Select-Object -ExpandProperty Path
        $CopyParams = @{
            VM = $VM
            SourcePath = $FileFullName
            DestinationPath = "C:\users\user\Downloads\$(Split-Path $FileFullName -leaf)"
            FileSource = "Host"
        }
        Copy-VmFile @CopyParams
    }
    catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Displays the latest SU installers found in the user's Downloads\SU_INSTALLERS directory.

.DESCRIPTION
This function searches recursively within the user's Downloads\SU_INSTALLERS directory for files, sorts them by 
creation time, and returns the specified number of the most recent installers.

.PARAMETER last
Specifies the number of latest installers to display. Defaults to 1.

.EXAMPLE
Show-LatestSUInstallers
Displays the latest SU installer.

.EXAMPLE
Show-LatestSUInstallers -last 5
Displays the 5 latest SU installers.

.NOTES
Requires that the directory '$Env:USERPROFILE\Downloads\SU_INSTALLERS' exists.
The output includes the CreationTime and FullName of each installer file.
#>
function Show-LatestSUInstallers {
    [CmdletBinding()]
    param(
        [int] $Last = 1
    )
    return Get-ChildItem -Path $Env:USERPROFILE\Downloads\SU_INSTALLERS -Filter "*.exe" -Recurse |
        Sort-Object -Property Creationtime |
        Select-Object CreationTime, Fullname -Last $last
}

<#
.SYNOPSIS
Show the latest plan run results from a specified bamboo plan

.DESCRIPTION
This function uses the Bamboo API to query for information on the latest run from a specified Bamboo project and
plan.

.PARAMETER ProjectKey
Specifies the Bamboo project key that contains the plan to be queried

.PARAMETER BuildKey
Specifies the Build key that identifies the plan to be queried

.PARAMETER BuildState
Filter queried plan results by their final state: "Successful" or "Failed". Empty string acts as placeholder for no
filtering.

.PARAMETER maxResults
#>
function Get-BambooResult {
    [CmdletBinding()]
    param(
        [string] $ProjectKey = "SU",
        [string] $BuildKey = "SMI",
        [ValidateSet("Successful", "Failed", "")][string] $BuildState,
        [int] $MaxResults = 5,
        [string] $VaultEntry = "Bamboo PAT (marce)"
    )
    $Token = (Get-Secret -Name $VaultEntry).Password
    $Url = "https://bamboo.trimble.tools/rest/api/latest/result/$ProjectKey-$BuildKey"
    $Headers  = @{ Accept = "application/json" }
    $Body = @{ "max-results" = $MaxResults; buildstate = $BuildState }
    $Response =  Invoke-RestMethod -Uri $Url -Headers $Headers -Body $Body -Authentication Bearer -Token $Token
    return $Response.Results.Result | Format-Table key, buildstate
}

<#
.SYNOPSIS
Pushes latest changes of local Obsidian vault to the remote repository

.DESCRIPTION
This function executes git add -A, git commit, and git push origin main  in a quick succession to push the latest
changes of the local copy of an Obisdian vault to the remote repository
#>
function Push-ObsidianVault {
    Push-Location "$Env:USERPROFILE\Documents\Obsidian\MARCE-TR-VAULT"
    git add -A
    git commit -m "Push-Vault at $(Get-Date)"
    git push origin main
    Pop-Location
}

<#
.SYNOPSIS
Stops vivaldi.exe forcefully

.DESCRIPTION
This function is a shorthand for Stop-Process -Name vivaldi -Force
#>
function Stop-Vivaldi {
    try{
        Stop-Process -Name vivaldi -Force -ErrorAction Stop
    }
    catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Connects to a remote host using TightVNC.

.DESCRIPTION
The `Connect-TVNC` function checks if TightVNC is installed on the local machine. If it is installed, it retrieves the TightVNC password from a secret store and uses it to connect to the specified remote host using TightVNC.

.PARAMETER Host
The IP address of the remote host to connect to. This parameter is mandatory and must be in the format of an IPv4 address.

.EXAMPLE
Connect-TVNC -Host "192.168.1.100"
This command connects to the TightVNC server running on the remote host with IP address 192.168.1.100.

.NOTES
- The function assumes that the TightVNC password is stored in a secret named "TightVNC_win".
- The function uses the TightVNC viewer executable located in the Program Files directory.
#>
function Connect-TVNC {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`$"})]
        [string] $Host,
        [string] $VaultEntry = "TightVNC_win"
    )

    $InstalledSoftwareKeys = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\
    if( $InstalledSoftwareKeys | Where-Object -FilterScript {($_.GetValue("DisplayName") -eq "TightVNC") } ) {
        $password = Get-Secret -Name $VaultEntry | ConvertFrom-SecureString -AsPlainText
        & $ENV:ProgramFiles\TightVNC\tvnviewer.exe -host="$Host" -port="5900" -password="$password"
    }
    else {
        Write-Error "TightVNC is not installed."
    }

}

<#
.SYNOPSIS
Counts and sums the lengths of items by their file extensions in a specified directory.

.DESCRIPTION
This function recursively searches through a specified directory and its subdirectories to find all unique file extensions. 
It then counts the number of files and sums their lengths for each file extension.

.PARAMETER Path
The path to the directory to search. If not specified, the current directory is used.

.EXAMPLE
CountByExtension-Items -Path "C:\MyFolder"
This command will count and sum the lengths of items by their file extensions in the "C:\MyFolder" directory.

.NOTES
The function uses the `Get-ChildItem` cmdlet to retrieve files and their properties.
The `Measure-Object` cmdlet is used to count the files and sum their lengths.
The output is sorted by file extension.
#>
function Get-FileExtensionStatistics {
    [CmdletBinding()]
    param(
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string] $Path = (Get-Location).Path
    )
    $Extensions = Get-ChildItem -File -Recurse -Path $Path | Select-Object -Unique -ExpandProperty Extension 
    $Output = @()
    foreach($Extension in $Extensions) {
        $Measure = Get-ChildItem -Path $Path -Recurse -Filter "*$Extension" | Measure-Object -Property Length -Sum
        $Output += [pscustomobject] @{
            Extension = $Extension
            Count = $Measure.Count
            TotalLength = [int] $Measure.Sum
        }
    }
    return $Output | Sort-Object -Property Extension
}

<#
.SYNOPSIS
Retrieves the local IPv4/6 addresses and associated interface names of active network adapters.

.DESCRIPTION
This function gets all network adapters that are currently in an "Up" state, then retrieves their IPv4 addresses.
It returns a custom object for each IPv4 address, containing the interface name (alias) and the IP address itself.

.EXAMPLE
Get-LocalIP

Description:
Returns a list of custom objects, each representing an IPv4 address and its corresponding interface name.

.EXAMPLE
Get-LocalIP | Format-Table

Description:
Formats the output of Get-LocalIP into a table for easier reading.

.OUTPUTS
System.Management.Automation.PSCustomObject[]

.NOTES
This function relies on the Get-NetAdapter and Get-NetIpAddress cmdlets, which are available on Windows systems.

.LINK
https://docs.microsoft.com/en-us/powershell/module/netadapter/get-netadapter?view=windowsserver2022-ps
https://docs.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress?view=windowsserver2022-ps
#>
function Get-LocalIP {
    $NetAdapter = Get-NetAdapter | Where-Object -Property Status -eq UP
    return $NetAdapter | Get-NetIpAddress -AddressFamily IPv4, IPv6 | ForEach-Object {
        [pscustomobject] @{ NetAdapter = $_.InterfaceAlias; IPAddress = $_.IPAddress }
    }
}

Set-Alias -Name ct    -Value Connect-TVNC
Set-Alias -Name cl    -Value Copy-Location
Set-Alias -Name gbr   -Value Get-BambooResult
Set-Alias -Name which -Value Get-CommandPath
Set-Alias -Name du    -Value Get-FolderSize
Set-Alias -Name gj    -Value Get-JiraIssue
Set-Alias -Name kv    -Value Stop-Vivaldi

Export-ModuleMember -Alias * -Function *
