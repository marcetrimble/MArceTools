# Work Tools PowerShell Script Module
# Author: Martin Arce martin_arce@trimble.com

<#
.SYNOPSIS
Verifies if the current user has administrator permissions.
.DESCRIPTION
This command returns True when the current user is a member of the built-on Administrators group, and False otherwise.
#>
function Check-Admin {
    $current_sec_id = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()))
    return $current_sec_id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

<#
.SYNOPSIS
Copies to clipboard the current location.
.DESCRIPTION
Retrieves the current location and saves it to the local clipboard as plain text.
#>
function Copy-Location {
    $location = Get-Location | Select-Object -Expand Path
    $location | Set-Clipboard
    Write-Output "`"$location`" copied to clipboard"
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
    param(
        [ValidateSet("2023", "2024", "2025")][string] $Year
    )
    Get-Secret -Name "SU_LIC_$Year" -AsPlainText | Set-Clipboard
}

<#
.SYNOPSIS
Shows the currently free system memory
.DESCRIPTION
This function retrieves the amount of available physical memory (RAM) on a Windows system and returns the value in
megabytes (MB)
#>
function Get-AvailableRam {
    $freeMem = Get-CimInstance -ClassName Win32_OperatingSystem `
        | Select-Object FreePhysicalMemory `
        | Select-Object -ExpandProperty FreePhysicalMemory
    return $freeMem/1Mb
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
    param(
      [string] $Folder = '.'
    )

    if (Test-Path $Folder) {
        $size = Get-ChildItem -Recurse -Path $folder `
            | Measure-Object -Property Length -Sum `
            | Select-Object -ExpandProperty Sum

        $fileSize = New-Object -TypeName psobject -Property @{
            Name     = Resolve-Path $Folder
            size_B   = $size
            size_KiB = $size/1Kb
            size_MiB = $size/1Mb
            size_GiB = $size/1Gb
        }

        return $fileSize | Format-List Name, size_B, size_KiB, size_MiB, size_GiB
    }
    else {
        Write-Error "Directory not found."
    }
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
    param (
        [Parameter(Mandatory=$true)] [string] $IssueId,
        [string] $Board = "SUDO"
    )

    $token = Get-Secret -Name "Jira PAT pdOas913 (marce)"
    $headers = @{ Accept = "application/json" }
    $url = "https://jira.trimble.tools/rest/api/latest/issue/$board-$issueId"
    $res = Invoke-RestMethod -Uri $url -Headers $headers -Authentication Bearer -Token $token

    $issueInfo = New-Object -TypeName psobject -Property @{
        IssueID      = "$board-$issueid"
        Summary      = $res.fields.summary
        Status       = $res.fields.status.name
        Assignee     = "$($res.fields.assignee.displayName) - $($res.fields.assignee.emailAddress)"
        Verifier     = "$($res.fields.customfield_15511.displayName) - $($res.fields.customfield_15511.emailAddress)"
        Reporter     = "$($res.fields.reporter.displayName) - $($res.fields.reporter.emailAddress)"
        WhatToTest   = $res.fields.customfield_15509
        Description  = $res.fields.description
        Created      = $res.fields.created
        Updated      = $res.fields.updated
        DueDate      = $res.fields.duedate
        JiraIssueURL = "https://jira.trimble.tools/browse/$board-$issueId"
    }

    return $issueInfo | Select-Object IssueID, Summary,  Status,  Assignee,  Verifier,  Reporter,  WhatToTest,  `
    Description,  Created,  Updated,  DueDate,  JiraIssueURL
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
    Get-Variable | Where-Object {
        (
            @(
                "FormatEnumerationLimit",
                "MaximumAliasCount",
                "MaximumDriveCount",
                "MaximumErrorCount",
                "MaximumFunctionCount",
                "MaximumVariableCount",
                "PGHome",
                "PGSE",
                "PGUICulture",
                "PGVersionTable",
                "PROFILE",
                "PSSessionOption"
            ) -notcontains $_.name
        ) -and ` (
            ([psobject].Assembly.GetType('System.Management.Automation.SpecialVariables').GetFields('NonPublic,Static') | Where-Object FieldType -eq ([string]) | ForEach-Object GetValue $null)
        ) -notcontains $_.name
    }
}

<#
.SYNOPSIS
Generate a random username
.DESCRIPTION
This function returns a randomized string with the format 5 letters + 3 numbers
#>
function Get-Username {
    $abc1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray()
    $abc2 = "abcdefghijklmnopqrstuvwxyz".toCharArray()
    $num = "0123456789".toCharArray()

    $x = $abc1+$abc2 | Get-Random -Count 5
    $x = [System.String]::Join("", $x)

    $y = $num | Get-Random -Count 3
    $y = [System.String]::Join("", $y)

    return $x+$y
}

<#
.SYNOPSIS
Recreates the functionality of UNIX systems utlity which
.DESCRIPTION
Shows the pathnames of the files which would be executed in the current environment, had its argument been given as
a command. This is done by searching using Get-Commands cmdlet and extracting the Path attribute with Select-Object
cmdlet
.PARAMETER FileName
Specifies the filename to look for
#>
function which {
    param(
        [Parameter(Mandatory=$true)] [string] $FileName
    )
    Get-Command -Name $FileName -ErrorAction SilentlyContinue `
    | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue
}

# WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP 

<#
.SYNOPSIS
Show the latest plan run results from a specified bamboo plan
.DESCRIPTION
This function uses the Bamboo API to query for information on the latest run from a specified Bamboo project and plan.
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
    param(
        [string] $ProjectKey = "SU",
        [string] $BuildKey = "SMI",
        [ValidateSet("Successful", "Failed", "")][string] $BuildState,
        [int] $maxResults = 5
    )
    $token = (Get-Secret -Name "Bamboo PAT (marce)").Password
    $url = "https://bamboo.trimble.tools/rest/api/latest/result/$ProjectKey-$BuildKey"
    $headers  = @{ Accept = "application/json" }
    $body = @{ "max-results" = $maxResults; buildstate = $BuildState }
    $response =  Invoke-RestMethod -Uri $url -Headers $headers -Body $body -Authentication Bearer -Token $token
    return $response.results.result | Format-Table key, buildstate
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
Search the web using a predefined list of search engines.
.DESCRIPTION
This function builds an appropriate URL given a query and a selected search engine and calls vivaldi browser to
open it.
.PARAMETER SearchEngine
The nickname of the search engine to be used in the search
.PARAMETER q
The query string to search for
.PARAMETER csvFile
The path to a csv file that describes the URL templates to be used for each search engine
#>
function Search-Web {
    param(
        [Parameter(Mandatory=$True)][string] $SearchEngine,
        [Parameter(Mandatory=$True)][string] $q,
        [string] $csvFile = "C:\Users\marce\code\PowerShell\searchengines.csv"
    )

    if(-not (Test-Path $csvFile)) {
        Write-Output "$csvFile does not describe a file..."
        return
    }
    $searchEngines = ConvertFrom-Csv -InputObject (Get-Content -Path $csvFile -Raw)
    if ($SearchEngine -notin ($searchengines.nickname)) {
        write-Output "$searchEngine not recognized as a search engine..."
        return
    }

    $url = ($searchEngines | ? nickname -eq $SearchEngine).url -replace "%s", $q
    $engine = ($searchEngines | ? nickname -eq $SearchEngine).Name -replace "%s", $q

    Write-Output "`$Engine: $searchEngine"
    Write-Output "`$Query: $q"
    & vivaldi $url --parent-window
}

<#function Run-BambooPlan {
    $VaultEntry = "Bamboo PASS (svcacct_sketchup_devops)"
    $user = (Get-Secret -Name $VaultEntry).UserName
    $pass = ConvertFrom-SecureString -SecureString (Get-Secret -Name $VaultEntry).Password -AsPlainText
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $User,$Pass)))

    $projectKey = "SKDEVOPS"
    $buildKey = "MCT"
    $baseurl = "bamboo.trimble.tools"

    $url = "https://$baseurl/rest/api/latest/queue/$projectKey-$buildKey"
    $headers = @{Accept = "application/json"; Authorization = ("Basic {0}" -f $base64AuthInfo)}

    echo "`$url: $url"

    return (Invoke-RestMethod -uri $url -Headers $headers)
}#>

<#function Lookup-CrowdinString {
    param(
        [string] $id
    )

    $token = (Get-Secret -Name 'Crowdin User Token (marce)').Password
    $projectId = 305435 # Trimble/SketchUp Client
    $fileId = 1392 # /develop/client.xliff
    $url =   "https://crowdin.com/api/v2/projects/$projectId/strings"
    $body = @{
        fileId = $fileId
        limit = 500
    }

    return Invoke-RestMethod -Uri $url -Body $body -Authentication Bearer -Token $token
}#>

<#function Get-Time {
    param(
        [string] $Location = "Mexicali"
    )
    $locationEndpoints = @{
        PST="America/Tijuana"
        MST="America/Denver"
        CST="America/Belize"
        EST="America/New_York"
        Mexicali = "America/Tijuana"
        Boulder = "America/Denver"
        Tokyo = "Asia/Tokyo"
        Vancouver = "America/Vancouver"
        Toronto = "America/Toronto"
        Guadalajara = "America/Mexico_City"
        Redmond =  "America/Vancouver"
    }
    $url = "http://worldtimeapi.org/api/timezone/$($locationEndpoints[$Location])"
    $response = Invoke-RestMethod -Uri $url
    $date = Get-Date -Date $response.datetime
    $output = New-Object -TypeName psobject -Property @{
        Name = $Location
        TimeZone = $response.abbreviation
        DateTime = $date.DateTime
        Time = $date.TimeOfDay.toString()
    }
    return $output
}#>


<#function Update-Commands {
    param(
        [Parameter(Mandatory=$true)][string] $id
    )

    if ((Get-Location).Path -ne (Resolve-Path "~\src\common_application")) {
        Write-Output "This function needs to run from ~\src\common_application..."
        return
    }

    $objList = @()

    $langs = Get-ChildItem -Directory -Path .\commandhelpers `
        | Where-Object -FilterScript {($_.Name).Length -lt 6} `
        | Select-Object -ExpandProperty Name

    $langs | %{
        $lang = $_;
        $dir = ".\commandhelpers\$lang\commands.json";
        Write-Output "DIR $dir`a: $(test-path $dir)";
        $objList += New-Object -TypeName psobject -Property @{
            lang = $lang
            jsonObj = (ConvertFrom-Json -InputObject (Get-Content -Path $dir -raw) -depth 10)}
    }

    # debuging debuging debuging debuging
    # ($objList | ? lang -eq "cs").jsonObj.list | ? skoreid -eq $id
    # $objList.jsonObj.list | ? skoreid -eq $id
    # debuging debuging debuging debuging

    $objList.jsonobj.list | ? skoreid -eq $id | ft skoreid, key, title, menu
    # $objList | ForEach-Object -Process {
        # ($_.jsonObj.list) | Where-Object -Property skoreId -eq $id | ft key, title, menu
        # $entry = ($_.jsonObj.list) | Where-Object -Property skoreId -eq $id
        # New-Object psobject -property @{lang = $_.lang; title = $entry.title; menu = $entry.menu}
    # }
}#>


# WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP - WIP 

Export-ModuleMember -Function *
