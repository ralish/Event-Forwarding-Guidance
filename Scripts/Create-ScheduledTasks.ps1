<#
    .SYNOPSIS
    Creates Scheduled Tasks with event triggers from WEC Subscriptions

    .DESCRIPTION
    This script automates the process of creating Scheduled Tasks with event triggers for associated Windows Event Collector subscriptions by parsing the associated XML subscription files.

    To successfully parse the subscription files the script expects each Select element within the XPath query to have an XML comment immediately prior to the element.

    This comment should provide a short description of the query and will be used in naming of the created Scheduled Task. Consult the sample subscriptions as a reference.

    .PARAMETER WECSubscriptionsPath
    Specifies the directory containing Windows Event Collector subscriptions to parse.

    .PARAMETER ScheduledTasksPath
    Specifies the directory where generated Scheduled Tasks will be saved. Defaults to "Scheduled Tasks" in the current working directory if not specified.

    .PARAMETER EnableTask
    Specifies that the generated Scheduled Task should be set as enabled by default. On importing into a system the task will be immediately active.

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
    [String]$ScheduledTasksPath='Scheduled Tasks',

    [Parameter(Mandatory=$false)]
    [switch]$EnableTask
)

# Ensure that any errors we receive are considered fatal
$ErrorActionPreference = 'Stop'

# Constants of XPath Query XML data used during assembly
Set-Variable -Name XpQueryListStart -Option Constant -Scope Script -Value "`n`t`t`t`t<QueryList>"
Set-Variable -Name XpQueryIdStart -Option Constant -Scope Script -Value "`n`t`t`t`t`t<Query Id=`"0`">"
Set-Variable -Name XpSelectPathStart -Option Constant -Scope Script -Value "`n    <Select Path=`"ForwardedEvents`">"
Set-Variable -Name XpSelectPathEnd -Option Constant -Scope Script -Value "</Select>"
Set-Variable -Name XpQueryIdEnd -Option Constant -Scope Script -Value "`n`t`t`t`t`t</Query>"
Set-Variable -Name XpQueryListEnd -Option Constant -Scope Script -Value "`n`t`t`t`t</QueryList>"

# Constants of Scheduled Task XML data used during assembly
Set-Variable -Name StFileXmlDeclaration -Option Constant -Scope Script -Value "<?xml version=`"1.0`" encoding=`"UTF-16`"?>"
Set-Variable -Name StFileTaskStart -Option Constant -Scope Script -Value "`n<Task version=`"1.2`" xmlns=`"http://schemas.microsoft.com/windows/2004/02/mit/task`">"
Set-Variable -Name StFileRegistrationInfoStart -Option Constant -Scope Script -Value "`n`t<RegistrationInfo>"
Set-Variable -Name StFileDateStart -Option Constant -Scope Script -Value "`n`t`t<Date>"
Set-Variable -Name StFileDateEnd -Option Constant -Scope Script -Value "`</Date>"
Set-Variable -Name StFileAuthorStart -Option Constant -Scope Script -Value "`n`t`t<Author>"
Set-Variable -Name StFileAuthorEnd -Option Constant -Scope Script -Value "`</Author>"
Set-Variable -Name StFileRegistrationInfoEnd -Option Constant -Scope Script -Value "`n`t</RegistrationInfo>"
Set-Variable -Name StFileTriggersStart -Option Constant -Scope Script -Value "`n`t<Triggers>"
Set-Variable -Name StFileEventTriggerStart -Option Constant -Scope Script -Value "`n`t`t<EventTrigger>"
Set-Variable -Name StFileEnabledStart -Option Constant -Scope Script -Value "`n`t`t`t<Enabled>"
Set-Variable -Name StFileEnabledEnd -Option Constant -Scope Script -Value "</Enabled>"
Set-Variable -Name StFileSubscriptionStart -Option Constant -Scope Script -Value "`n`t`t`t<Subscription>"
Set-Variable -Name StFileSubscriptionEnd -Option Constant -Scope Script -Value "`n`t`t`t</Subscription>"
Set-Variable -Name StFileEventTriggerEnd -Option Constant -Scope Script -Value "`n`t`t</EventTrigger>"
Set-Variable -Name StFileTriggersEnd -Option Constant -Scope Script -Value "`n`t</Triggers>"
Set-Variable -Name StFilePrincipalsStart -Option Constant -Scope Script -Value "`n`t<Principals>"
Set-Variable -Name StFilePrincipalStart -Option Constant -Scope Script -Value "`n`t`t<Principal id=`"Author`">"
Set-Variable -Name StFileUserIdStart -Option Constant -Scope Script -Value "`n`t`t`t<UserId>"
Set-Variable -Name StFileLogonType -Option Constant -Scope Script -Value "`n`t`t`t<LogonType>InteractiveToken</LogonType>"
Set-Variable -Name StFileRunLevel -Option Constant -Scope Script -Value "`n`t`t`t<RunLevel>LeastPrivilege</RunLevel>"
Set-Variable -Name StFileUserIdEnd -Option Constant -Scope Script -Value "</UserId>"
Set-Variable -Name StFilePrincipalEnd -Option Constant -Scope Script -Value "`n`t`t</Principal>"
Set-Variable -Name StFilePrincipalsEnd -Option Constant -Scope Script -Value "`n`t</Principals>"
Set-Variable -Name StFileSettingsBlob -Option Constant -Scope Script -Value "`n`t<Settings>`n`t`t<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>`n`t`t<DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>`n`t`t<StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>`n`t`t<AllowHardTerminate>true</AllowHardTerminate>`n`t`t<StartWhenAvailable>false</StartWhenAvailable>`n`t`t<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>`n`t`t<IdleSettings>`n`t`t`t<StopOnIdleEnd>true</StopOnIdleEnd>`n`t`t`t<RestartOnIdle>false</RestartOnIdle>`n`t`t</IdleSettings>`n`t`t<AllowStartOnDemand>true</AllowStartOnDemand>`n`t`t<Enabled>false</Enabled>`n`t`t<Hidden>false</Hidden>`n`t`t<RunOnlyIfIdle>false</RunOnlyIfIdle>`n`t`t<WakeToRun>false</WakeToRun>`n`t`t<ExecutionTimeLimit>P3D</ExecutionTimeLimit>`n`t`t<Priority>7</Priority>`n`t</Settings>"
Set-Variable -Name StFileActionsStart -Option Constant -Scope Script -Value "`n`t<Actions Context=`"Author`">"
Set-Variable -Name StFileExecStart -Option Constant -Scope Script -Value "`n`t`t<Exec>"
Set-Variable -Name StFileCommandStart -Option Constant -Scope Script -Value "`n`t`t`t<Command>"
Set-Variable -Name StFileCommandEnd -Option Constant -Scope Script -Value "</Command>"
Set-Variable -Name StFileExecEnd -Option Constant -Scope Script -Value "`n`t`t</Exec>"
Set-Variable -Name StFileActionsEnd -Option Constant -Scope Script -Value "`n`t</Actions>"
Set-Variable -Name StFileTaskEnd -Option Constant -Scope Script -Value "`n</Task>"

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

    if (Test-Path -Path $ScheduledTasksPath -PathType Container -IsValid) {
        if (!(Test-Path -Path $ScheduledTasksPath -PathType Container)) {
            Write-Verbose "Creating the specified directory to store Scheduled Tasks: $ScheduledTasksPath"
            $null = New-Item -Path $ScheduledTasksPath -ItemType Directory
        }
        $script:ScheduledTasksPath = Resolve-Path $ScheduledTasksPath
    } else {
        Write-Error "The provided Scheduled Tasks path is invalid: $ScheduledTasksPath"
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
                $ScheduledTask = New-ScheduledTask $SelectElement
                if ($ScheduledTask) {
                    $StCategory = [IO.Path]::GetFileNameWithoutExtension($Subscription.FullName)
                    $StName = $ScheduledTask[0]
                    $StData = $ScheduledTask[1]
                    Export-ScheduledTask $StCategory $StName $StData
                }
            }
        }
    }
}

Function New-ScheduledTask ([Xml.XmlElement] $SelectElement) {
    # Attempt to extract the Scheduled Task name
    $StName = Extract-SelectComment $SelectElement
    if (!($StName)) {
        Write-Warning ("Couldn't find the identifying comment for Select element:`n" + $SelectElement.OuterXML)
        return
    }

    # Extract the XPath query from the element
    $StXpath = $SelectElement.InnerText

    # Get the current date & time in round-trip format for timestamp
    $StDate = Get-Date -Format o

    # Get the current domain & logged-in user for authorship
    $StAuthor = [Environment]::UserDomainName + '\' + [Environment]::UserName

    # Configure the generated Scheduled Task's default state
    if ($EnableTask) {
        $StEnabled = "true"
    } else {
        $StEnabled = "false"
    }

    # The extracted query is for selecting events on remote systems, but
    # we'll be creating the Scheduled Task on the Event Collector. So we
    # must adjust the provided query to use the Forwarded Events log.
    $StSelectQuery += $XpSelectPathStart + $StXpath + $XpSelectPathEnd

    # Build the inner Subscription query used as the event trigger
    $StSubscription = $XpQueryListStart
    $StSubscription += $XpQueryIdStart
    $StSubscription += $StSelectQuery
    $StSubscription += $XpQueryIdEnd
    $StSubscription += $XpQueryListEnd

    # Properly escape the final query for inclusion
    $StSubscription = [Security.SecurityElement]::Escape($StSubscription)

    # Construct the Scheduled Task
    $StData = $StFileXmlDeclaration
    $StData += $StFileTaskStart
    $StData += $StFileRegistrationInfoStart
    $StData += $StFileDateStart + $StDate + $StFileDateEnd
    $StData += $StFileAuthorStart + $StAuthor + $StFileAuthorEnd
    $StData += $StFileRegistrationInfoEnd
    $StData += $StFileTriggersStart
    $StData += $StFileEventTriggerStart
    $StData += $StFileEnabledStart + $StEnabled + $StFileEnabledEnd
    $StData += $StFileSubscriptionStart + $StSubscription + $StFileSubscriptionEnd
    $StData += $StFileEventTriggerEnd
    $StData += $StFileTriggersEnd
    $StData += $StFilePrincipalsStart
    $StData += $StFilePrincipalStart
    $StData += $StFileUserIdStart + $StAuthor + $StFileUserIdEnd
    $StData += $StFileLogonType
    $StData += $StFileRunLevel
    $StData += $StFilePrincipalEnd
    $StData += $StFilePrincipalsEnd
    $StData += $StFileSettingsBlob
    $StData += $StFileActionsStart
    $StData += $StFileExecStart
    $StData += $StFileCommandStart + "TODO" + $StFileCommandEnd
    $StData += $StFileExecEnd
    $StData += $StFileActionsEnd
    $StData += $StFileTaskEnd
    
    # Return the generated XML as well as the extracted name
    return [String[]] $ScheduledTask = $StName, $StData
}

Function Export-ScheduledTask ([String] $StCategory, [String] $StName, [String] $StData) {
    $StFile = "$StCategory - $StName.xml"

    $StPath = Join-Path $ScheduledTasksPath $StFile
    Out-File -FilePath $StPath -Encoding UTF8 -InputObject $StData -Force
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

# Create Scheduled Task for each subscription
foreach ($Subscription in $Subscriptions) {
    Write-Verbose ("Processing WEC subscription: " + $Subscription.Name)
    Parse-Subscription $Subscription
}
