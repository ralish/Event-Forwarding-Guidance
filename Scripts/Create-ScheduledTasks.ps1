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

    .PARAMETER ExecutedCommand
    Specifies the command to be executed on triggering of the generated Scheduled Task.

    .PARAMETER CommandArguments
    Specifies any arguments to be passed to the command to be executed by the Scheduled Task.

    .PARAMETER EnableTask
    Specifies that the generated Scheduled Task should be set as enabled by default. On importing into a system the task will be immediately active.

    .NOTES
    While this script will automatically XML escape the provided command and any arguments, this will only ensure the Scheduled Task XML definition is valid. It does not guarantee the command and any provided arguments are correctly escaped for invocation by the Task Scheduler!

    For example, if providing a PowerShell command, it's recommended to Base 64 encode its arguments and provide them to PowerShell via the "-EncodedCommand" parameter. This ensures there's no unintended interpretation of the arguments by the Windows API during parsing prior to invocation (i.e. before PowerShell is actually launched to execute the supplied script).

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

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$ExecutedCommand,

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [String]$CommandArguments,

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

Function Get-SelectComment ([Xml.XmlElement] $SelectElement) {
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

Function New-ScheduledTask ([Xml.XmlElement] $SelectElement, [String] $StPath) {
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

    # XML escape the subscription query, command & any arguments
    $StSubscription = [Security.SecurityElement]::Escape($StSubscription)
    $ExecutedCommand = [Security.SecurityElement]::Escape($ExecutedCommand)
    $CommandArguments = [Security.SecurityElement]::Escape($CommandArguments)

    # Construct the Scheduled Task
    $XmlDoc = New-Object Xml.XmlDocument
    $XmlDeclaration = $XmlDoc.CreateXmlDeclaration("1.0", "UTF-16", $null)
    $XmlDoc.AppendChild($XmlDeclaration) | Out-Null

    $XmlTask = $XmlDoc.CreateElement("Task")
    $XmlTask.SetAttribute("version", "1.2")
    $XmlTask.SetAttribute("xmlns", "http://schemas.microsoft.com/windows/2004/02/mit/task")
    $XmlDoc.AppendChild($XmlTask) | Out-Null

    $XmlRegistrationInfo = $XmlDoc.CreateElement("RegistrationInfo")
    $XmlTask.AppendChild($XmlRegistrationInfo) | Out-Null

    $XmlDate = $XmlDoc.CreateElement("Date")
    $XmlDate.InnerText = $StDate
    $XmlRegistrationInfo.AppendChild($XmlDate) | Out-Null

    $XmlAuthor = $XmlDoc.CreateElement("Author")
    $XmlAuthor.InnerText = $StAuthor
    $XmlRegistrationInfo.AppendChild($XmlAuthor) | Out-Null

    $XmlTriggers = $XmlDoc.CreateElement("Triggers")
    $XmlTask.AppendChild($XmlTriggers) | Out-Null

    $XmlEventTrigger = $XmlDoc.CreateElement("EventTrigger")
    $XmlTriggers.AppendChild($XmlEventTrigger) | Out-Null

    $XmlEnabled = $XmlDoc.CreateElement("Enabled")
    $XmlEnabled.InnerText = $StEnabled
    $XmlEventTrigger.AppendChild($XmlEnabled) | Out-Null

    $XmlSubscription = $XmlDoc.CreateElement("Subscription")
    $XmlSubscription.InnerText = $StSubscription
    $XmlEventTrigger.AppendChild($XmlSubscription) | Out-Null

    $XmlPrincipals = $XmlDoc.CreateElement("Principals")
    $XmlTask.AppendChild($XmlPrincipals) | Out-Null

    $XmlPrincipal = $XmlDoc.CreateElement("Principal")
    $XmlPrincipal.SetAttribute("id", "Author")
    $XmlPrincipals.AppendChild($XmlPrincipal) | Out-Null

    $XmlUserId = $XmlDoc.CreateElement("UserId")
    $XmlUserId.InnerText = "S-1-5-19" # LOCAL SERVICE
    $XmlPrincipal.AppendChild($XmlUserId) | Out-Null

    $XmlLogonType = $XmlDoc.CreateElement("LogonType")
    $XmlLogonType.InnerText = "InteractiveToken"
    $XmlPrincipal.AppendChild($XmlLogonType) | Out-Null

    $XmlSettings = $XmlDoc.CreateElement("Settings")
    $XmlTask.AppendChild($XmlSettings) | Out-Null

    $XmlMultipleInstancesPolicy = $XmlDoc.CreateElement("MultipleInstancesPolicy")
    $XmlMultipleInstancesPolicy.InnerText = "IgnoreNew"
    $XmlSettings.AppendChild($XmlMultipleInstancesPolicy) | Out-Null

    $XmlDisallowStartIfOnBatteries = $XmlDoc.CreateElement("DisallowStartIfOnBatteries")
    $XmlDisallowStartIfOnBatteries.InnerText = "false"
    $XmlSettings.AppendChild($XmlDisallowStartIfOnBatteries) | Out-Null

    $XmlStopIfGoingOnBatteries = $XmlDoc.CreateElement("StopIfGoingOnBatteries")
    $XmlStopIfGoingOnBatteries.InnerText = "false"
    $XmlSettings.AppendChild($XmlStopIfGoingOnBatteries) | Out-Null

    $XmlAllowHardTerminate = $XmlDoc.CreateElement("AllowHardTerminate")
    $XmlAllowHardTerminate.InnerText = "true"
    $XmlSettings.AppendChild($XmlAllowHardTerminate) | Out-Null

    $XmlStartWhenAvailable = $XmlDoc.CreateElement("StartWhenAvailable")
    $XmlStartWhenAvailable.InnerText = "false"
    $XmlSettings.AppendChild($XmlStartWhenAvailable) | Out-Null

    $XmlRunOnlyIfNetworkAvailable = $XmlDoc.CreateElement("RunOnlyIfNetworkAvailable")
    $XmlRunOnlyIfNetworkAvailable.InnerText = "true"
    $XmlSettings.AppendChild($XmlRunOnlyIfNetworkAvailable) | Out-Null

    $XmlIdleSettings = $XmlDoc.CreateElement("IdleSettings")
    $XmlSettings.AppendChild($XmlIdleSettings) | Out-Null

    $XmlStopOnIdleEnd = $XmlDoc.CreateElement("StopOnIdleEnd")
    $XmlStopOnIdleEnd.InnerText = "false"
    $XmlIdleSettings.AppendChild($XmlStopOnIdleEnd) | Out-Null

    $XmlRestartOnIdle = $XmlDoc.CreateElement("RestartOnIdle")
    $XmlRestartOnIdle.InnerText = "false"
    $XmlIdleSettings.AppendChild($XmlRestartOnIdle) | Out-Null

    $XmlAllowStartOnDemand = $XmlDoc.CreateElement("AllowStartOnDemand")
    $XmlAllowStartOnDemand.InnerText = "true"
    $XmlSettings.AppendChild($XmlAllowStartOnDemand) | Out-Null

    $XmlSettings.AppendChild($XmlEnabled) | Out-Null # Reuse earlier element

    $XmlHidden = $XmlDoc.CreateElement("Hidden")
    $XmlHidden.InnerText = "false"
    $XmlSettings.AppendChild($XmlHidden) | Out-Null

    $XmlRunOnlyIfIdle = $XmlDoc.CreateElement("RunOnlyIfIdle")
    $XmlRunOnlyIfIdle.InnerText = "false"
    $XmlSettings.AppendChild($XmlRunOnlyIfIdle) | Out-Null

    $XmlWakeToRun = $XmlDoc.CreateElement("WakeToRun")
    $XmlWakeToRun.InnerText = "false"
    $XmlSettings.AppendChild($XmlWakeToRun) | Out-Null

    $XmlExecutionTimeLimit = $XmlDoc.CreateElement("ExecutionTimeLimit")
    $XmlExecutionTimeLimit.InnerText = "P3D"
    $XmlSettings.AppendChild($XmlExecutionTimeLimit) | Out-Null

    $XmlPriority = $XmlDoc.CreateElement("Priority")
    $XmlPriority.InnerText = "7"
    $XmlSettings.AppendChild($XmlPriority) | Out-Null

    $XmlActions = $XmlDoc.CreateElement("Actions")
    $XmlActions.SetAttribute("Context", "Author")
    $XmlTask.AppendChild($XmlActions) | Out-Null

    $XmlExec = $XmlDoc.CreateElement("Exec")
    $XmlActions.AppendChild($XmlExec) | Out-Null

    $XmlCommand = $XmlDoc.CreateElement("Command")
    $XmlCommand.InnerText = $ExecutedCommand
    $XmlExec.AppendChild($XmlCommand) | Out-Null

    if ($CommandArguments) {
        $XmlArguments = $XmlDoc.CreateElement("Arguments")
        $XmlArguments.InnerText = $CommandArguments
        $XmlExec.AppendChild($XmlArguments) | Out-Null
    }

    # Save the generated Scheduled Task
    $XmlDoc.Save($StPath)
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
                $StName = Get-SelectComment $SelectElement
                if (!($StName)) {
                    Write-Warning ("Couldn't find the identifying comment for Select element:`n" + $SelectElement.OuterXML)
                    break
                }

                $StCategory = [IO.Path]::GetFileNameWithoutExtension($Subscription.FullName)
                $StFile = "$StCategory - $StName.xml"
                $StPath = Join-Path $ScheduledTasksPath $StFile

                New-ScheduledTask $SelectElement $StPath
            }
        }
    }
}

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

# Additional sanity checking
Validate-Input

# Create Scheduled Task for each subscription
foreach ($Subscription in $Subscriptions) {
    Write-Verbose ("Processing WEC subscription: " + $Subscription.Name)
    Parse-Subscription $Subscription
}
