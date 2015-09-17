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

    .PARAMETER AlertsEmailSmtpServer
    Specifies the SMTP server to be used for email delivery.

    .PARAMETER AlertsSenderEmailAddress
    Specifies the sender email address for event alerts.

    .PARAMETER AlertsRecipientEmailAddress
    Specifies the recipient email address for event alerts.

    .PARAMETER EnableTask
    Specifies that the generated Scheduled Task should be set as enabled by default. On importing into a system the task will be immediately active.

    .NOTES
    While this script will automatically XML escape the provided command and any arguments, this will only ensure the Scheduled Task XML definition is valid. It does not guarantee the command and any provided arguments are correctly escaped for invocation by the Task Scheduler!

    For example, if providing a PowerShell command, it's recommended to Base64 encode its arguments and provide them to PowerShell via the "-EncodedCommand" parameter. This ensures there's no unintended interpretation of the arguments by the Windows API during parsing prior to invocation (i.e. before PowerShell is actually launched to execute the supplied script).

    .LINK
    https://www.nsa.gov/ia/_files/app/Spotting_the_Adversary_with_Windows_Event_Log_Monitoring.pdf
#>

[CmdletBinding(DefaultParameterSetName='CustomCommand')]
Param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$WECSubscriptionsPath,

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [String]$ScheduledTasksPath='Scheduled Tasks',

    [Parameter(Mandatory=$true,ParameterSetName='CustomCommand')]
    [ValidateNotNullOrEmpty()]
    [String]$ExecutedCommand,

    [Parameter(Mandatory=$false,ParameterSetName='CustomCommand')]
    [ValidateNotNullOrEmpty()]
    [String]$CommandArguments,

    [Parameter(Mandatory=$true,ParameterSetName='EmailAlerts')]
    [ValidateNotNullOrEmpty()]
    [String]$AlertsEmailSmtpServer,

    [Parameter(Mandatory=$true,ParameterSetName='EmailAlerts')]
    [ValidateNotNullOrEmpty()]
    [String]$AlertsSenderEmailAddress,

    [Parameter(Mandatory=$true,ParameterSetName='EmailAlerts')]
    [ValidateNotNullOrEmpty()]
    [String]$AlertsRecipientEmailAddress,

    [Parameter(Mandatory=$false)]
    [switch]$EnableTask
)

# Ensure that any errors we receive are considered fatal
$ErrorActionPreference = 'Stop'

Function Get-EmailAlertsScript ([String] $FilterXml) {
    $AlertCommand =
@"
`$Event = Get-WinEvent -MaxEvents 1 -FilterXml $FilterXml -ErrorAction SilentlyContinue
if (`$Event) {
    `$EventHtml = ConvertTo-Html -InputObject `$Event -As List -Property *
    Send-MailMessage -SmtpServer "$AlertsEmailSmtpServer" -From "$AlertsSenderEmailAddress" -To "$AlertsRecipientEmailAddress" -Subject "Event Alert!" -Body (`$EventHtml | Out-String) -BodyAsHtml
}
"@

    # Ensure the command is Base64 encoded
    return [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("$AlertCommand"))
}

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

    # XML escape the command & any arguments
    $ExecutedCommand = [Security.SecurityElement]::Escape($ExecutedCommand)
    if ($CommandArguments) {
        $CommandArguments = [Security.SecurityElement]::Escape($CommandArguments)
    }

    # Construct the Subscription Query used as the Event Trigger
    $EtXmlDoc = New-Object Xml.XmlDocument

    $EtXmlQueryList = $EtXmlDoc.CreateElement("QueryList")
    $EtXmlDoc.AppendChild($EtXmlQueryList) | Out-Null

    $EtXmlQuery = $EtXmlDoc.CreateElement("Query")
    $EtXmlQuery.SetAttribute("Id", "0")
    $EtXmlQueryList.AppendChild($EtXmlQuery) | Out-Null

    $EtXmlSelect = $EtXmlDoc.CreateElement("Select")
    $EtXmlSelect.SetAttribute("Path", "ForwardedEvents")
    $EtXmlSelect.InnerText = $SelectElement.InnerText
    $EtXmlQuery.AppendChild($EtXmlSelect) | Out-Null

    # Escape the subscription query as we need to embed it in more XML!
    $StSubscription = [Security.SecurityElement]::Escape($EtXmlDoc.OuterXml)

    # Configure command & arguments if we're setting up email alerts
    if ($AlertsEmailSmtpServer) {
        $ExecutedCommand = "powershell"
        $EmailAlertsScript = Get-EmailAlertsScript $EtXmlDoc.OuterXml
        $CommandArguments = "-NoProfile -EncodedCommand `"$EmailAlertsScript`""
    }

    # Construct the Scheduled Task
    $StXmlDoc = New-Object Xml.XmlDocument
    $StXmlDeclaration = $StXmlDoc.CreateXmlDeclaration("1.0", "UTF-16", $null)
    $StXmlDoc.AppendChild($StXmlDeclaration) | Out-Null

    $StXmlTask = $StXmlDoc.CreateElement("Task")
    $StXmlTask.SetAttribute("version", "1.2")
    $StXmlTask.SetAttribute("xmlns", "http://schemas.microsoft.com/windows/2004/02/mit/task")
    $StXmlDoc.AppendChild($StXmlTask) | Out-Null

    $StXmlRegistrationInfo = $StXmlDoc.CreateElement("RegistrationInfo")
    $StXmlTask.AppendChild($StXmlRegistrationInfo) | Out-Null

    $StXmlDate = $StXmlDoc.CreateElement("Date")
    $StXmlDate.InnerText = $StDate
    $StXmlRegistrationInfo.AppendChild($StXmlDate) | Out-Null

    $StXmlAuthor = $StXmlDoc.CreateElement("Author")
    $StXmlAuthor.InnerText = $StAuthor
    $StXmlRegistrationInfo.AppendChild($StXmlAuthor) | Out-Null

    $StXmlTriggers = $StXmlDoc.CreateElement("Triggers")
    $StXmlTask.AppendChild($StXmlTriggers) | Out-Null

    $StXmlEventTrigger = $StXmlDoc.CreateElement("EventTrigger")
    $StXmlTriggers.AppendChild($StXmlEventTrigger) | Out-Null

    $StXmlEnabled = $StXmlDoc.CreateElement("Enabled")
    $StXmlEnabled.InnerText = $StEnabled
    $StXmlEventTrigger.AppendChild($StXmlEnabled) | Out-Null

    $StXmlSubscription = $StXmlDoc.CreateElement("Subscription")
    $StXmlSubscription.InnerText = $StSubscription
    $StXmlEventTrigger.AppendChild($StXmlSubscription) | Out-Null

    $StXmlPrincipals = $StXmlDoc.CreateElement("Principals")
    $StXmlTask.AppendChild($StXmlPrincipals) | Out-Null

    $StXmlPrincipal = $StXmlDoc.CreateElement("Principal")
    $StXmlPrincipal.SetAttribute("id", "Author")
    $StXmlPrincipals.AppendChild($StXmlPrincipal) | Out-Null

    $StXmlUserId = $StXmlDoc.CreateElement("UserId")
    $StXmlUserId.InnerText = "S-1-5-19" # LOCAL SERVICE
    $StXmlPrincipal.AppendChild($StXmlUserId) | Out-Null

    $StXmlRunLevel = $StXmlDoc.CreateElement("RunLevel")
    $StXmlRunLevel.InnerText = "LeastPrivilege"
    $StXmlPrincipal.AppendChild($StXmlRunLevel) | Out-Null

    $StXmlSettings = $StXmlDoc.CreateElement("Settings")
    $StXmlTask.AppendChild($StXmlSettings) | Out-Null

    $StXmlMultipleInstancesPolicy = $StXmlDoc.CreateElement("MultipleInstancesPolicy")
    $StXmlMultipleInstancesPolicy.InnerText = "Parallel"
    $StXmlSettings.AppendChild($StXmlMultipleInstancesPolicy) | Out-Null

    $StXmlDisallowStartIfOnBatteries = $StXmlDoc.CreateElement("DisallowStartIfOnBatteries")
    $StXmlDisallowStartIfOnBatteries.InnerText = "false"
    $StXmlSettings.AppendChild($StXmlDisallowStartIfOnBatteries) | Out-Null

    $StXmlStopIfGoingOnBatteries = $StXmlDoc.CreateElement("StopIfGoingOnBatteries")
    $StXmlStopIfGoingOnBatteries.InnerText = "false"
    $StXmlSettings.AppendChild($StXmlStopIfGoingOnBatteries) | Out-Null

    $StXmlAllowHardTerminate = $StXmlDoc.CreateElement("AllowHardTerminate")
    $StXmlAllowHardTerminate.InnerText = "true"
    $StXmlSettings.AppendChild($StXmlAllowHardTerminate) | Out-Null

    $StXmlStartWhenAvailable = $StXmlDoc.CreateElement("StartWhenAvailable")
    $StXmlStartWhenAvailable.InnerText = "false"
    $StXmlSettings.AppendChild($StXmlStartWhenAvailable) | Out-Null

    $StXmlRunOnlyIfNetworkAvailable = $StXmlDoc.CreateElement("RunOnlyIfNetworkAvailable")
    $StXmlRunOnlyIfNetworkAvailable.InnerText = "false"
    $StXmlSettings.AppendChild($StXmlRunOnlyIfNetworkAvailable) | Out-Null

    $StXmlIdleSettings = $StXmlDoc.CreateElement("IdleSettings")
    $StXmlSettings.AppendChild($StXmlIdleSettings) | Out-Null

    $StXmlStopOnIdleEnd = $StXmlDoc.CreateElement("StopOnIdleEnd")
    $StXmlStopOnIdleEnd.InnerText = "false"
    $StXmlIdleSettings.AppendChild($StXmlStopOnIdleEnd) | Out-Null

    $StXmlRestartOnIdle = $StXmlDoc.CreateElement("RestartOnIdle")
    $StXmlRestartOnIdle.InnerText = "false"
    $StXmlIdleSettings.AppendChild($StXmlRestartOnIdle) | Out-Null

    $StXmlAllowStartOnDemand = $StXmlDoc.CreateElement("AllowStartOnDemand")
    $StXmlAllowStartOnDemand.InnerText = "true"
    $StXmlSettings.AppendChild($StXmlAllowStartOnDemand) | Out-Null

    $StXmlSettings.AppendChild($StXmlEnabled.Clone()) | Out-Null # Reuse earlier element

    $StXmlHidden = $StXmlDoc.CreateElement("Hidden")
    $StXmlHidden.InnerText = "false"
    $StXmlSettings.AppendChild($StXmlHidden) | Out-Null

    $StXmlRunOnlyIfIdle = $StXmlDoc.CreateElement("RunOnlyIfIdle")
    $StXmlRunOnlyIfIdle.InnerText = "false"
    $StXmlSettings.AppendChild($StXmlRunOnlyIfIdle) | Out-Null

    $StXmlWakeToRun = $StXmlDoc.CreateElement("WakeToRun")
    $StXmlWakeToRun.InnerText = "false"
    $StXmlSettings.AppendChild($StXmlWakeToRun) | Out-Null

    $StXmlExecutionTimeLimit = $StXmlDoc.CreateElement("ExecutionTimeLimit")
    $StXmlExecutionTimeLimit.InnerText = "PT1H" # 1 hour
    $StXmlSettings.AppendChild($StXmlExecutionTimeLimit) | Out-Null

    $StXmlPriority = $StXmlDoc.CreateElement("Priority")
    $StXmlPriority.InnerText = "7"
    $StXmlSettings.AppendChild($StXmlPriority) | Out-Null

    $StXmlActions = $StXmlDoc.CreateElement("Actions")
    $StXmlActions.SetAttribute("Context", "Author")
    $StXmlTask.AppendChild($StXmlActions) | Out-Null

    $StXmlExec = $StXmlDoc.CreateElement("Exec")
    $StXmlActions.AppendChild($StXmlExec) | Out-Null

    $StXmlCommand = $StXmlDoc.CreateElement("Command")
    $StXmlCommand.InnerText = $ExecutedCommand
    $StXmlExec.AppendChild($StXmlCommand) | Out-Null

    if ($CommandArguments) {
        $StXmlArguments = $StXmlDoc.CreateElement("Arguments")
        $StXmlArguments.InnerText = $CommandArguments
        $StXmlExec.AppendChild($StXmlArguments) | Out-Null
    }

    # Save the generated Scheduled Task
    $StXmlDoc.Save($StPath)
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
