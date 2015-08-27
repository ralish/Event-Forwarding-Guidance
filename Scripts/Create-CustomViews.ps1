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

    .PARAMETER PerSubscriptionFolders
    Place generated Custom Views into folders per subscription.

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
    [switch]$PerSubscriptionFolders,

    [Parameter(Mandatory=$false)]
    [TimeSpan]$TimeFilter
)

# Ensure that any errors we receive are considered fatal
$ErrorActionPreference = 'Stop'

# Constants of Custom View XML data used during assembly
Set-Variable -Name CvFileViewerConfigStart -Option Constant -Scope Script -Value "<ViewerConfig>"
Set-Variable -Name CvFileQueryConfigStart -Option Constant -Scope Script -Value "`n`t<QueryConfig>"
Set-Variable -Name CvFileQueryParamsStart -Option Constant -Scope Script -Value "`n`t`t<QueryParams>"
Set-Variable -Name CvFileUserQuery -Option Constant -Scope Script -Value "`n`t`t`t<UserQuery />"
Set-Variable -Name CvFileQueryParamsEnd -Option Constant -Scope Script -Value "`n`t`t</QueryParams>"
Set-Variable -Name CvFileQueryNodeStart -Option Constant -Scope Script -Value "`n`t`t<QueryNode>"
Set-Variable -Name CvFileNameStart -Option Constant -Scope Script -Value "`n`t`t`t<Name>"
Set-Variable -Name CvFileNameEnd -Option Constant -Scope Script -Value "</Name>"
Set-Variable -Name CvFileSortConfig -Option Constant -Scope Script -Value "`n`t`t`t<SortConfig Asc=`"0`">`n`t`t`t`t<Column Name=`"Date and Time`" Type=`"System.DateTime`" Path=`"Event/System/TimeCreated/@SystemTime`" Visible=`"`">150</Column>`n`t`t`t</SortConfig>"
Set-Variable -Name CvFileQueryListStart -Option Constant -Scope Script -Value "`n`t`t`t<QueryList>"
Set-Variable -Name CvFileQueryIdStart -Option Constant -Scope Script -Value "`n`t`t`t`t<Query Id=`"0`">"
Set-Variable -Name CvFileSelectPathStart -Option Constant -Scope Script -Value "`n    <Select Path=`"ForwardedEvents`">"
Set-Variable -Name CvFileSelectPathEnd -Option Constant -Scope Script -Value "</Select>"
Set-Variable -Name CvFileQueryIdEnd -Option Constant -Scope Script -Value "`n`t`t`t`t</Query>"
Set-Variable -Name CvFileQueryListEnd -Option Constant -Scope Script -Value "`n`t`t`t</QueryList>"
Set-Variable -Name CvFileQueryNodeEnd -Option Constant -Scope Script -Value "`n`t`t</QueryNode>"
Set-Variable -Name CvFileQueryConfigEnd -Option Constant -Scope Script -Value "`n`t</QueryConfig>"
Set-Variable -Name CvFileResultsConfig -Option Constant -Scope Script -Value "`n`t<ResultsConfig>`n`t`t<Columns>`n`t`t`t<Column Name=`"Level`" Type=`"System.String`" Path=`"Event/System/Level`" Visible=`"`">100</Column>`n`t`t`t<Column Name=`"Date and Time`" Type=`"System.DateTime`" Path=`"Event/System/TimeCreated/@SystemTime`" Visible=`"`">150</Column>`n`t`t`t<Column Name=`"Source`" Type=`"System.String`" Path=`"Event/System/Provider/@Name`" Visible=`"`">200</Column>`n`t`t`t<Column Name=`"Event ID`" Type=`"System.UInt32`" Path=`"Event/System/EventID`" Visible=`"`">75</Column>`n`t`t`t<Column Name=`"Task Category`" Type=`"System.String`" Path=`"Event/System/Task`" Visible=`"`">100</Column>`n`t`t`t<Column Name=`"Computer`" Type=`"System.String`" Path=`"Event/System/Computer`" Visible=`"`">250</Column>`n`t`t</Columns>`n`t</ResultsConfig>"
Set-Variable -Name CvFileViewerConfigEnd -Option Constant -Scope Script -Value "`n</ViewerConfig>"

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
                    Export-CustomView $CvCategory $CvName $CvData
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
    $CvData = $CvFileViewerConfigStart
    $CvData += $CvFileQueryConfigStart
    $CvData += $CvFileQueryParamsStart + $CvFileUserQuery + $CvFileQueryParamsEnd
    $CvData += $CvFileQueryNodeStart
    $CvData += $CvFileNameStart + $CvName + $CvFileNameEnd
    $CvData += $CvFileSortConfig
    $CvData += $CvFileQueryListStart
    $CvData += $CvFileQueryIdStart
    $CvData += $CvFileSelectPathStart + $CvQuery + $CvFileSelectPathEnd
    $CvData += $CvFileQueryIdEnd
    $CvData += $CvFileQueryListEnd
    $CvData += $CvFileQueryNodeEnd
    $CvData += $CvFileQueryConfigEnd
    $CvData += $CvFileResultsConfig
    $CvData += $CvFileViewerConfigEnd
    
    # Return the generated XML as well as the extracted name
    return [String[]] $CustomView = $CvName, $CvData
}

Function Export-CustomView ([String] $CvCategory, [String] $CvName, [String] $CvData) {
    if ($PerSubscriptionFolders) {
        $CvFile = "$CvName.xml"
        $CvCategoryPath = Join-Path $CustomViewsPath $CvCategory
        if (Test-Path -Path $CvCategoryPath -PathType Container -IsValid) {
            if (!(Test-Path -Path $CvCategoryPath -PathType Container)) {
                $null = New-Item -Path $CvCategoryPath -ItemType Directory
            }
            $CustomViewsPath = Resolve-Path $CvCategoryPath
        } else {
            Write-Error "A Custom Views category path is invalid: $CvCategoryPath"
        }
    } else {
        $CvFile = "$CvCategory - $CvName.xml"
    }

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
