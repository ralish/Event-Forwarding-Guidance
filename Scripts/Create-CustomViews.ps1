<#
    .SYNOPSIS
    Creates Custom Views for Event Viewer from WEC Subscriptions

    .DESCRIPTION
    This script automates the process of creating Custom Views for associated Windows Event Collector subscriptions by parsing the associated XML subscription files.

    To successfully parse the subscription files the script expects each Select element within the XPath query to have an XML comment immediately prior to the element.

    This comment should provide a short description of the query and will be used in naming of the created Custom View. Consult the sample subscriptions as a reference.

    .PARAMETER WECSubscriptionsPath
    Specifies the directory containing Windows Event Collector subscriptions to parse.

    .PARAMETER CustomViewsPath
    Specifies the directory where generated Custom Views will be saved.

    .PARAMETER TimeFilter
    A TimeSpan object provided by Get-TimeSpan used to filter custom views.

    .LINK
    https://www.nsa.gov/ia/_files/app/Spotting_the_Adversary_with_Windows_Event_Log_Monitoring.pdf
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$WECSubscriptionsPath,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$CustomViewsPath,

    [Parameter(Mandatory=$false)]
    [TimeSpan]$TimeFilter
)

# Ensure that any errors we receive are considered fatal
$ErrorActionPreference = 'Stop'

# Constants of Custom View XML data used during assembly
Set-Variable -Name CvFileStart -Option Constant -Scope Script -Value "<ViewerConfig>`n`t<QueryConfig>`n`t`t<QueryParams>`n`t`t`t<UserQuery/>`n`t`t</QueryParams>`n`t`t<QueryNode>"
Set-Variable -Name CvFileEnd -Option Constant -Scope Script -Value "`n`t`t</QueryNode>`n`t</QueryConfig>`n</ViewerConfig>"
Set-Variable -Name CvNameStart -Option Constant -Scope Script -Value "`n`t`t`t<Name>"
Set-Variable -Name CvNameEnd -Option Constant -Scope Script -Value "</Name>"
Set-Variable -Name CvQueryStart -Option Constant -Scope Script -Value "`n`t`t`t<QueryList>`n`t`t`t`t<Query Id=`"0`">"
Set-Variable -Name CvQueryEnd -Option Constant -Scope Script -Value "`n`t`t`t`t</Query>`n`t`t`t</QueryList>"
Set-Variable -Name CvFwdEvtStart -Option Constant -Scope Script -Value "`n    <Select Path=`"ForwardedEvents`">"
Set-Variable -Name CvFwdEvtEnd -Option Constant -Scope Script -Value "`n    </Select>"

Function Validate-Input () {
    if (Test-Path -Path $WECSubscriptionsPath -PathType Container) {
        $script:WECSubscriptionsPath = Resolve-Path $WECSubscriptionsPath
    } else {
        Write-Error "The provided WEC subscriptions path does not exist: $WECSubscriptionsPath"
    }

    $script:Subscriptions = Get-ChildItem -Path $WECSubscriptionsPath -Recurse -File -Include "*.xml"
    if (!($Subscriptions)) {
        Write-Error "No WEC subscriptions found in the given path: $WECSubscriptionsPath"
    }

    if ($TimeFilter) {
        if ($TimeFilter.TotalSeconds -lt 60) {
            Write-Error "The provided time filter must be at least 60 seconds."
        }
        $script:CustomViewsPath = Join-Path $CustomViewsPath (Get-TimeSpanDescription $TimeFilter)
    }

    if (Test-Path -Path $CustomViewsPath -PathType Container -IsValid) {
        if (!(Test-Path -Path $CustomViewsPath -PathType Container)) {
            Write-Verbose "Creating the specified directory to store Custom Views: $CustomViewsPath"
            $null = New-Item -Path $CustomViewsPath -ItemType Directory
        }
        $script:CustomViewsPath = Resolve-Path $CustomViewsPath
    } else {
        Write-Error "The provided Custom Views path is invalid: $CustomViewsPath"
    }
}

Function Get-TimeSpanDescription ([TimeSpan] $TimeSpan) {
    if ($TimeSpan.Days -gt 0 ) {
        if ($TimeSpan.Days -eq 1) {
            return "Last Day"
        } else {
            return "Last " + $TimeSpan.Days + " Days"
        }
    } elseif ($TimeSpan.Hours -gt 0) {
        if ($TimeSpan.Hours -eq 1) {
            return "Last Hour"
        } else {
            return "Last " + $TimeSpan.Hours + " Hours"
        }
    } else {
        if ($TimeSpan.Minutes -eq 1) {
            return "Last Minute"
        } else {
            return "Last " + $TimeSpan.Minutes + " Minutes"
        }
    }
}

Function Parse-Subscription ([IO.FileInfo] $Subscription) {
    $Xml = [xml] (Get-Content $Subscription.FullName)
    $Query = [xml] $Xml.Subscription.Query.InnerText
    $QueryIds = $Query.Querylist.ChildNodes

    foreach ($QueryId in $QueryIds) {
        $SelectElements = $QueryId.Select
        if (!($SelectElements)) {
            Write-Warning ("No Select elements in Query Id " + $QueryId.Id + 
                           " for subscription: " + $Subscription.Name)
        } else {
            foreach ($SelectElement in $SelectElements) {
                $CustomView = New-CustomView $SelectElement
                if ($CustomView) {
                    $CvCategory = [IO.Path]::GetFileNameWithoutExtension($Subscription.FullName)
                    $CvName = $CustomView[0]
                    $CvData = $CustomView[1]
                    $CvFile = "$CvCategory - $CvName.xml"
                    Export-CustomView $CvData $CvFile
                }
            }
        }
    }
}

Function New-CustomView ([Xml.XmlElement] $SelectElement) {
    # Attempt to extract the Custom View name
    $CvName = Extract-SelectComment $SelectElement
    if (!($CvName)) {
        Write-Warning ("Couldn't find the identifying comment for Select element:`n" + $SelectElement.OuterXML)
        return
    }

    # Extract the XPath query from the element
    $CvXpath = $SelectElement.InnerText

    # If we've provided a time filter we need to add it
    if ($TimeFilter) {
        $TimeDiff = $TimeFilter.TotalMilliseconds
        $CvXpath += "  and`n      *[System[TimeCreated[timediff(@SystemTime) &lt;= $TimeDiff]]]"
    }

    # The extracted query is for selecting events on remote systems, but
    # we'll be creating the Custom View on the Event Collector. As such,
    # we must adjust the provided query to use the Forwarded Events log.
    $CvQuery = $CvFwdEvtStart + $CvXpath + $CvFwdEvtEnd

    # Construct the Custom View
    $CvData = $CvFileStart
    $CvData += $CvNameStart + $CvName + $CvNameEnd
    $CvData += $CvQueryStart + $CvQuery + $CvQueryEnd
    $CvData += $CvFileEnd

    # Return the generated XML as well as the extracted name
    return [String[]] $CustomView = $CvName, $CvData
}

Function Export-CustomView ([String] $CvData, [String] $CvFile) {
    $CvPath = Join-Path $CustomViewsPath $CvFile
    Out-File -FilePath $CvPath -Encoding UTF8 -InputObject $CvData -Force
}

Function Extract-SelectComment ([Xml.XmlElement] $SelectElement) {
    if (!($SelectElement.PreviousSibling)) {
        return
    }

    if ($SelectElement.PreviousSibling.GetType().Name -ne "XmlComment") {
        return
    }

    $SelectComment = $SelectElement.PreviousSibling.Innertext.Trim()
    Write-Debug "Found comment of Select element: $SelectComment"
    return $SelectComment
}

# Additional sanity checking
Validate-Input

# Create Custom View for each subscription
foreach ($Subscription in $Subscriptions) {
    Write-Verbose ("Processing WEC subscription: " + $Subscription.Name)
    Parse-Subscription $Subscription
}
