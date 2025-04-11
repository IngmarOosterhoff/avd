[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]
    $ResourceGroupName,
    [Parameter(Mandatory)]
    [string]
    $hostPoolName,
    [Parameter(Mandatory)]
    [string]
    $Location
)

# Setting ErrorActionPreference to stop script execution when error occurs
$ErrorActionPreference = 'Stop'

#Get required automation variables
$desiredHostCount = Get-AutomationVariable -Name "desiredHostCount_$($HostPoolName)" -ErrorAction Stop
$DevOpsPAT = Get-AutomationVariable -Name "PAT" -ErrorAction Stop
$MaintenanceTagName = Get-AutomationVariable -Name "maintenanceTagName" -ErrorAction Stop

#Functions based on basicScale.ps1 from Microsoft https://github.com/Azure/RDS-Templates/tree/master/wvd-templates/wvd-scaling-script

[string[]]$DesiredRunningStates = @('Available', 'NeedsAssistance')

function Get-PSObjectPropVal {
    param (
        $Obj,
        [string]$Key,
        $Default = $null
    )
    $Prop = $Obj.PSObject.Properties[$Key]
    if ($Prop) {
        return $Prop.Value
    }
    return $Default
}

# Function to return local time converted from UTC
function Get-UTCDateTime {
    return (Get-Date).ToUniversalTime()
}

function Write-Log {
    # Note: this is required to support param such as ErrorAction
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [switch]$Err,

        [switch]$Warn
    )

    [string]$MessageTimeStamp = (Get-UTCDateTime).ToString('yyyy-MM-dd HH:mm:ss')
    $Message = "[$($MyInvocation.ScriptLineNumber)] $Message"
    [string]$WriteMessage = "$MessageTimeStamp $Message"

    if ($Err) {
        Write-Error $WriteMessage
        $Message = "ERROR: $Message"
    }
    elseif ($Warn) {
        Write-Warning $WriteMessage
        $Message = "WARN: $Message"
    }
    else {
        Write-Output $WriteMessage
    }

}

function Get-SessionHostName {
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $SessionHost
    )
    return $SessionHost.Name.Split('/')[-1]
}

function TryUpdateSessionHostDrainMode {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [hashtable]$VM,

        [switch]$AllowNewSession
    )
    Begin { }
    Process {
        $SessionHost = $VM.SessionHost
        if ($SessionHost.AllowNewSession -eq $AllowNewSession) {
            return
        }

        [string]$SessionHostName = $VM.SessionHostName
        Write-Log "Update session host '$SessionHostName'$AllowNewSession"
        if ($PSCmdlet.ShouldProcess($SessionHostName, "Update session host to set allow new sessions to $AllowNewSession")) {
            try {
                $SessionHost = $VM.SessionHost = Update-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -Name $SessionHostName -AllowNewSession:$AllowNewSession
                if ($SessionHost.AllowNewSession -ne $AllowNewSession) {
                    throw $SessionHost
                }
            }
            catch {
                Write-Log -Warn "Failed to update the session host '$SessionHostName'$($AllowNewSession)$($PSItem | Format-List -Force | Out-String)"
            }
        }
    }
    End { }
}

# Collect the credentials from Azure Automation Account Assets
Write-Log "Get auto connection from asset: AzureRunAsConnection"
try {
    "Logging in to Azure..."
    Connect-AzAccount -Identity
}
catch {
    Write-Error -Message $_.Exception
    throw $_.Exception
}

#region validate pipeline exists and that it isn't currently running
$EncodedAuth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$DevOpsPAT"))
$Headers = @{
    Authorization = "Basic $EncodedAuth"
}
$Pipelines = Invoke-RestMethod -Method Get -Uri "https://dev.azure.com/ingmar0/InfraAsCode/_apis/pipelines" -Headers $Headers

#Pipeline name must include the HostPool Name (may include spaces) and the region location (may include spaces)
$Pipeline = $Pipelines.value | Where-Object -Property folder -EQ "\AVD\$hostPoolName" |
Where-Object -FilterScript { $_.name.replace(' ', '') -like "*$hostPoolName*" } |
Where-Object -FilterScript { $_.name.replace(' ', '') -like "*2*" }

if ($null -eq $Pipeline) {
    if ($Pipelines -like "*Sign In*") {
        Write-Log "Azure DevOps Authentication failed, please update the PAT Token" -Err
    }
    else {
        Write-Log "Unable to locate pipeline for $hostPoolName" -Err
    }
    exit
}

$Runs = Invoke-RestMethod -Method Get -Uri ($Pipeline.url.Split('?')[0] + "/runs") -ContentType "application/json" -Headers $Headers
$RunningJobs = $Runs.value | Where-Object -Property state -NE "completed"
if ($null -ne $RunningJobs) {
    Write-Log "Pipeline currently running, stopping to avoid unexpected results"
    Write-Log "Pipeline currently running, stopping" -Warn
    exit
}
#endregion

#region validate host pool, ensure there is at least 1 session host, get num of user sessions

# Validate and get HostPool info
$HostPool = $null
try {
    Write-Log "Get information of Hostpool '$HostPoolName' in resource group '$ResourceGroupName'"
    $HostPool = Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName -Name $HostPoolName
    if (!$HostPool) {
        throw $HostPool
    }
}
catch {
    throw [System.Exception]::new("Failed to get information of Hostpool '$HostPoolName' in resource group '$ResourceGroupName'. Ensure that you have entered the correct values", $PSItem.Exception)
}

# Ensure HostPool load balancer type is not persistent
if ($HostPool.LoadBalancerType -ieq 'Persistent') {
    throw "HostPool '$HostPoolName' is configured with 'Persistent' load balancer type. Scaling tool only supports these load balancer types: BreadthFirst, DepthFirst"
}

Write-Log 'Get all session hosts'
$SessionHosts = @(Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName)
if (!$SessionHosts) {
    Write-Log "There are no session hosts in the Hostpool '$HostPoolName'. Ensure that hostpool has session hosts"
    Write-Log 'End'
    return
}

Write-Log "HostPool info: $($HostPool | Format-List -Force | Out-String)"
Write-Log "Number of session hosts in the HostPool (Including $MaintenanceTagName Tag): $($SessionHosts.Count)"

#endregion

#region get all session hosts, VMs & user sessions info and compute workload

# Note: session host is considered "running" if its running AND is in desired states AND allowing new sessions
# Object that contains all session host objects, VM instance objects except the ones that are under maintenance
$VMs = @{ }

# Populate all session hosts objects
foreach ($SessionHost in $SessionHosts) {
    [string]$SessionHostName = Get-SessionHostName -SessionHost $SessionHost
    $VMs.Add($SessionHostName.Split('.')[0].ToLower(), @{
            SessionHostName = $SessionHostName
            SessionHost     = $SessionHost
            Instance        = $null
            Maintenance     = $false
        }
    )
}

Write-Log 'Get all VMs, check session host status and get usage info'
foreach ($VMInstance in (Get-AzVM -Status)) {
    if (!$VMs.ContainsKey($VMInstance.Name.ToLower())) {
        # This VM is not a WVD session host
        continue
    }

    [string]$VMName = $VMInstance.Name.ToLower()

    $VM = $VMs[$VMName]

    if ($VMInstance.Tags.Keys -contains $MaintenanceTagName) {
        Write-Log "VM '$VMName' is in maintenance and will be ignored"
        $VM.Maintenance = $true
    }

    $SessionHost = $VM.SessionHost
    if ((Get-PSObjectPropVal -Obj $SessionHost -Key 'VirtualMachineId') -and $VMInstance.VmId -ine $SessionHost.VirtualMachineId) {
        # This VM is not a WVD session host
        continue
    }
    if ($VM.Instance) {
        throw "More than 1 VM found in Azure with same session host name '$($VM.SessionHostName)' (This is not supported): $($VMInstance | Format-List -Force | Out-String)$($VM.Instance | Format-List -Force | Out-String)"
    }

    $VM.Instance = $VMInstance

    Write-Log "Session host: '$($VM.SessionHostName)$($VMInstance.PowerState)$($SessionHost.Status)$($SessionHost.UpdateState)$($SessionHost.Session)$($SessionHost.AllowNewSession)"

    if ($VMInstance.PowerState -ieq 'VM running') {
        if ($SessionHost.Status -notin $DesiredRunningStates) {
            Write-Log -Warn 'VM is in running state but session host is not and so it will be ignored (this could be because the VM was just started and has not connected to broker yet)'
        }
    }
    else {
        if ($SessionHost.Status -in $DesiredRunningStates) {
            Write-Log -Warn "VM is not in running state but session host is (this could be because the VM was just stopped and broker doesn't know that yet)"
        }
    }
}

$inValidVMNames = $VMs.Keys | Where-Object -FilterScript { $null -eq $VMs[$_].Instance }
foreach ($VMName in $inValidVMNames) {
    Write-Log "VM '$VMName' could not be matched and will be ignored"
    $VMs.Remove($VMName)
}

$ValidVMs = @{}
$MaintenanceVMs = @{}

$VMs.GetEnumerator() | Where-Object -FilterScript { $_.Value.Maintenance -eq $false } | ForEach-Object -Process { $ValidVMs.Add($_.Key, $_.Value) }
$VMs.GetEnumerator() | Where-Object -FilterScript { $_.Value.Maintenance -eq $true } | ForEach-Object -Process { $MaintenanceVMs.Add($_.Key, $_.Value) }

$ValidVMCount = $ValidVMs.Count
$MaintenanceVMCount = $MaintenanceVMs.count

$ValidVMCount = [int]$ValidVMCount
$MaintenanceVMCount = [int]$MaintenanceVMCount

#endregion

if ($ValidVMCount -lt $desiredHostCount) {
    Write-Log "Found $($ValidVMCount) total VMs but requested $desiredHostCount"
    $NewPoolCount = $desiredHostCount + $MaintenanceVMCount

    Write-Log "Running DevOps Pipeline to request $NewPoolCount hosts (Including $MaintenanceTagName tagged hosts)"
    Invoke-RestMethod -Method Post -Uri ($Pipeline.url.Split('?')[0] + "/runs?api-version=6.0-preview.1") -ContentType "application/json" -Headers $Headers -Body (@{
            templateParameters = @{
                InstanceCount = $NewPoolCount
            }
        } | ConvertTo-Json)
}
elseif ($ValidVMCount -gt $desiredHostCount) {
    Write-Log "Found $($VMs.Count) total VMs but requested $desiredHostCount"
    $RemoveCount = $ValidVMCount - $desiredHostCount
    Write-Log "Removing $RemoveCount Hosts"

    #Take copy of validVMs Hashtable
    $RemoveVMs = $ValidVMs.Clone()

    if ($RemoveVMs.Count -gt $RemoveCount) {
        #remove any hosts with existing sessions first
        $RemoveHostsWithSessions = @{}
        foreach ($VMName in $RemoveVMs.Keys) {
            if ($RemoveVMs[$VMName].SessionHost.Session -gt 0) {
                Write-Log "$VMName has $($RemoveVMs[$VMName].SessionHost.Session) Sessions"
                $RemoveHostsWithSessions.Add($VMName, $RemoveVMs[$VMName])
            }
        }

        if (($RemoveVMs.Count - $RemoveHostsWithSessions.Count) -eq $RemoveCount) {
            #Removing session hosts with sessions matches the number of session hosts to rebuild exactly
            foreach ($VMName in $RemoveHostsWithSessions.Keys) {
                $RemoveVMs.Remove($VMName)
            }
        }
        elseif (($RemoveVMs.Count - $RemoveHostsWithSessions.Count) -lt $RemoveCount) {
            #Remove all session hosts which have sessions would take the number to rebuild under the correct amount
            $NumberToRemove = $RemoveVMs.Count - $RemoveCount
            #Identify the required number of hosts with the highest number of sessions and exclude them
            $TrimmedRemoveHostsWithSessions = @{}
            $RemoveHostsWithSessions.GetEnumerator() |
            Sort-Object -Property @{e = { $_.Value.SessionHost.Session } } -Descending |
            Select-Object -First $NumberToRemove |
            ForEach-Object -Process { $TrimmedRemoveHostsWithSessions.Add($_.Key, $_.Value) }

            foreach ($VMName in $TrimmedRemoveHostsWithSessions.Keys) {
                $RemoveVMs.Remove($VMName)
            }
        }
        else {
            #Removing all the session hosts with sessions isn't enough
            #Remove session hosts with active sessions
            foreach ($VMName in $RemoveHostsWithSessions.Keys) {
                $RemoveVMs.Remove($VMName)
            }

            #Identify how many more to remove
            #priorotise VMs which are already off
            $PriorityVMs = @{}
            $RemoveVMs.GetEnumerator() |
            Sort-Object -Property @{e = { $_.Value.Instance.PowerState } }, @{e = { $_.Value.SessionHost.AllowNewSession } } |
            Select-Object -First $RemoveCount |
            ForEach-Object -Process { $PriorityVMs.Add($_.Key, $_.Value) }

            #Only remove the priority VMs
            $RemoveVMs = $PriorityVMs.Clone()
        }
    }
    Write-Log "Final Number of session hosts identified to rebuild: $($RemoveVMs.Count)"

    #endregion

    #region Mark VMs for Decomm via tag to exclude from Sheduling solution and disable new connections
    foreach ($VMName in $RemoveVMs.Keys) {
        $VM = $RemoveVMs[$VMName]
        Write-Log "Host $($VMName) identified to be removed, currently hosting $($VM.SessionHost.Session) sessions"
        $tags = $VM.Instance.Tags
        if (-NOT $tags.Keys.Contains($MaintenanceTagName)) {
            $tags.Add($MaintenanceTagName, "true")
            Set-AzResource -ResourceGroupName $VM.Instance.ResourceGroupName -ResourceName $VMName -ResourceType "Microsoft.Compute/VirtualMachines" -Tag $tags -Force
        }

        TryUpdateSessionHostDrainMode -VM $VM
    }
    #endregion
}
else {
    Write-Log "Nothing to do"
}
