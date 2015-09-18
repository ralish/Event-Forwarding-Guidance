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
    Specifies the directory where generated Custom Views will be saved. Defaults to "Custom Views" in the current working directory if not specified.

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

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [String]$CustomViewsPath='Custom Views',

    [Parameter(Mandatory=$false)]
    [switch]$PerSubscriptionFolders,

    [Parameter(Mandatory=$false)]
    [TimeSpan]$TimeFilter
)

# Ensure that any errors we receive are considered fatal
$ErrorActionPreference = 'Stop'

Function Get-SelectComment ([Xml.XmlElement] $SelectElement) {
    if (!($SelectElement.PreviousSibling)) {
        return
    }

    if ($SelectElement.PreviousSibling.GetType().Name -ne "XmlComment") {
        return
    }

    $SelectComment = $SelectElement.PreviousSibling.Innertext.Trim()
    return $SelectComment
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

Function New-CustomView ([Xml.XmlElement] $SelectElement, [String] $CvPath) {
    # Extract the XPath query from the element
    $CvXpath = $SelectElement.InnerText

    # If we've provided a time filter we need to add it
    if ($TimeFilter) {
        $TimeDiff = $TimeFilter.TotalMilliseconds
        $CvXpath += "  and`n      *[System[TimeCreated[timediff(@SystemTime) <= $TimeDiff]]]"
    }

    # Construct the Custom View
    $CvXmlDoc = New-Object Xml.XmlDocument

    $CvXmlViewerConfig = $CvXmlDoc.CreateElement("ViewerConfig")
    $CvXmlDoc.AppendChild($CvXmlViewerConfig) | Out-Null

    $CvXmlQueryConfig = $CvXmlDoc.CreateElement("QueryConfig")
    $CvXmlViewerConfig.AppendChild($CvXmlQueryConfig) | Out-Null

    $CvXmlQueryParams = $CvXmlDoc.CreateElement("QueryParams")
    $CvXmlQueryConfig.AppendChild($CvXmlQueryParams) | Out-Null

    $CvXmlUserQuery = $CvXmlDoc.CreateElement("UserQuery")
    $CvXmlQueryParams.AppendChild($CvXmlUserQuery) | Out-Null

    $CvXmlQueryNode = $CvXmlDoc.CreateElement("QueryNode")
    $CvXmlQueryConfig.AppendChild($CvXmlQueryNode) | Out-Null

    $CvXmlQueryName = $CvXmlDoc.CreateElement("Name")
    $CvXmlQueryName.InnerText = $CvName
    $CvXmlQueryNode.AppendChild($CvXmlQueryName) | Out-Null

    $CvXmlSortConfig = $CvXmlDoc.CreateElement("SortConfig")
    $CvXmlSortConfig.SetAttribute("Asc", "0")
    $CvXmlQueryNode.AppendChild($CvXmlSortConfig) | Out-Null

    $CvXmlSortColumn = $CvXmlDoc.CreateElement("Column")
    $CvXmlSortColumn.SetAttribute("Name", "Date and Time")
    $CvXmlSortColumn.SetAttribute("Type", "System.DateTime")
    $CvXmlSortColumn.SetAttribute("Path", "Event/System/TimeCreated/@SystemTime")
    $CvXmlSortColumn.SetAttribute("Visible", "")
    $CvXmlSortColumn.InnerText = "150"
    $CvXmlSortConfig.AppendChild($CvXmlSortColumn) | Out-Null

    $CvXmlQueryList = $CvXmlDoc.CreateElement("QueryList")
    $CvXmlQueryNode.AppendChild($CvXmlQueryList) | Out-Null

    $CvXmlQuery = $CvXmlDoc.CreateElement("Query")
    $CvXmlQuery.SetAttribute("Id", "0")
    $CvXmlQuery.SetAttribute("Path", "ForwardedEvents")
    $CvXmlQueryList.AppendChild($CvXmlQuery) | Out-Null

    $CvXmlSelect = $CvXmlDoc.CreateElement("Select")
    $CvXmlSelect.SetAttribute("Path", "ForwardedEvents")
    $CvXmlSelect.InnerText = $CvXpath
    $CvXmlQuery.AppendChild($CvXmlSelect) | Out-Null

    $CvXmlResultsConfig = $CvXmlDoc.CreateElement("ResultsConfig")
    $CvXmlViewerConfig.AppendChild($CvXmlResultsConfig) | Out-Null

    $CvXmlColumns = $CvXmlDoc.CreateElement("Columns")
    $CvXmlResultsConfig.AppendChild($CvXmlColumns) | Out-Null

    $CvXmlColumnLevel = $CvXmlDoc.CreateElement("Column")
    $CvXmlColumnLevel.SetAttribute("Name", "Level")
    $CvXmlColumnLevel.SetAttribute("Type", "System.String")
    $CvXmlColumnLevel.SetAttribute("Path", "Event/System/Level")
    $CvXmlColumnLevel.SetAttribute("Visible", "")
    $CvXmlColumnLevel.InnerText = "100"
    $CvXmlColumns.AppendChild($CvXmlColumnLevel) | Out-Null

    $CvXmlColumnDateAndTime = $CvXmlDoc.CreateElement("Column")
    $CvXmlColumnDateAndTime.SetAttribute("Name", "Date and Time")
    $CvXmlColumnDateAndTime.SetAttribute("Type", "System.DateTime")
    $CvXmlColumnDateAndTime.SetAttribute("Path", "Event/System/TimeCreated/@SystemTime")
    $CvXmlColumnDateAndTime.SetAttribute("Visible", "")
    $CvXmlColumnDateAndTime.InnerText = "150"
    $CvXmlColumns.AppendChild($CvXmlColumnDateAndTime) | Out-Null

    $CvXmlColumnSource = $CvXmlDoc.CreateElement("Column")
    $CvXmlColumnSource.SetAttribute("Name", "Source")
    $CvXmlColumnSource.SetAttribute("Type", "System.String")
    $CvXmlColumnSource.SetAttribute("Path", "Event/System/Provider/@Name")
    $CvXmlColumnSource.SetAttribute("Visible", "")
    $CvXmlColumnSource.InnerText = "200"
    $CvXmlColumns.AppendChild($CvXmlColumnSource) | Out-Null

    $CvXmlColumnEventId = $CvXmlDoc.CreateElement("Column")
    $CvXmlColumnEventId.SetAttribute("Name", "Event ID")
    $CvXmlColumnEventId.SetAttribute("Type", "System.UInt32")
    $CvXmlColumnEventId.SetAttribute("Path", "Event/System/EventID")
    $CvXmlColumnEventId.SetAttribute("Visible", "")
    $CvXmlColumnEventId.InnerText = "75"
    $CvXmlColumns.AppendChild($CvXmlColumnEventId) | Out-Null

    $CvXmlColumnTaskCategory = $CvXmlDoc.CreateElement("Column")
    $CvXmlColumnTaskCategory.SetAttribute("Name", "Task Category")
    $CvXmlColumnTaskCategory.SetAttribute("Type", "System.String")
    $CvXmlColumnTaskCategory.SetAttribute("Path", "Event/System/Task")
    $CvXmlColumnTaskCategory.SetAttribute("Visible", "")
    $CvXmlColumnTaskCategory.InnerText = "100"
    $CvXmlColumns.AppendChild($CvXmlColumnTaskCategory) | Out-Null

    $CvXmlColumnComputer = $CvXmlDoc.CreateElement("Column")
    $CvXmlColumnComputer.SetAttribute("Name", "Computer")
    $CvXmlColumnComputer.SetAttribute("Type", "System.String")
    $CvXmlColumnComputer.SetAttribute("Path", "Event/System/Computer")
    $CvXmlColumnComputer.SetAttribute("Visible", "")
    $CvXmlColumnComputer.InnerText = "250"
    $CvXmlColumns.AppendChild($CvXmlColumnComputer) | Out-Null

    # Save the generated Custom View
    $CvXmlDoc.Save($CvPath)
}

Function Parse-Subscription ([IO.FileInfo] $Subscription) {
    $Xml = [xml] (Get-Content $Subscription.FullName)
    $Query = [xml] $Xml.Subscription.Query.InnerText
    $QueryIds = $Query.Querylist.ChildNodes

    $CvCategory = [IO.Path]::GetFileNameWithoutExtension($Subscription.FullName)
    if ($PerSubscriptionFolders) {
        $CvCategoryPath = Join-Path $CustomViewsPath $CvCategory
        if (Test-Path -Path $CvCategoryPath -PathType Container -IsValid) {
            if (!(Test-Path -Path $CvCategoryPath -PathType Container)) {
                New-Item -Path $CvCategoryPath -ItemType Directory | Out-Null
            }
            $CustomViewsPath = Resolve-Path $CvCategoryPath
        } else {
            throw "A Custom Views category path is invalid: $CvCategoryPath"
        }
    }

    foreach ($QueryId in $QueryIds) {
        $SelectElements = $QueryId.Select
        if (!($SelectElements)) {
            Write-Warning ("No Select elements in Query Id " + $QueryId.Id +
                           " for subscription: " + $Subscription.Name)
        } else {
            foreach ($SelectElement in $SelectElements) {
                $CvName = Get-SelectComment $SelectElement
                if (!($CvName)) {
                    Write-Warning ("Couldn't find the identifying comment for Select element:`n" + $SelectElement.OuterXML)
                    break
                }

                if ($PerSubscriptionFolders) {
                    $CvFile = "$CvName.xml"
                } else {
                    $CvFile = "$CvCategory - $CvName.xml"
                }
                $CvPath = Join-Path $CustomViewsPath $CvFile

                New-CustomView $SelectElement $CvPath
            }
        }
    }
}

Function Validate-Input () {
    if (Test-Path -Path $WECSubscriptionsPath -PathType Container) {
        $script:WECSubscriptionsPath = Resolve-Path $WECSubscriptionsPath
    } else {
        throw "The provided WEC subscriptions path does not exist: $WECSubscriptionsPath"
    }

    $script:Subscriptions = Get-ChildItem -Path $WECSubscriptionsPath -Recurse -File -Include "*.xml"
    if (!($Subscriptions)) {
        throw "No WEC subscriptions found in the given path: $WECSubscriptionsPath"
    }

    if ($TimeFilter) {
        if ($TimeFilter.TotalSeconds -lt 60) {
            throw "The provided time filter must be at least 60 seconds."
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
        throw "The provided Custom Views path is invalid: $CustomViewsPath"
    }
}

# Additional sanity checking
Validate-Input

# Create Custom View for each subscription
foreach ($Subscription in $Subscriptions) {
    Write-Verbose ("Processing WEC subscription: " + $Subscription.Name)
    Parse-Subscription $Subscription
}
