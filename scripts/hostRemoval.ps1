[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]
    $ResourceGroupName,
    [Parameter(Mandatory)]
    [string]
    $ResourceGroupNameAvdMetadata,
    [Parameter(Mandatory)]
    [string]
    $hostPoolName,
    [Parameter(Mandatory)]
    [string]
    $Location,
    [Parameter()]
    [switch]
    $ForceDestroy
)

$ErrorActionPreference = 'Stop'

$desiredHostCount = Get-AutomationVariable -Name "desiredHostCount_$($HostPoolName)" -ErrorAction Stop
$devOpsPAT = Get-AutomationVariable -Name "PAT" -ErrorAction Stop
$maintenanceTagName = Get-AutomationVariable -Name "maintenanceTagName" -ErrorAction Stop
$resourceGroupNameVMs = "$ResourceGroupName-vms"

[string[]]$desiredRunningStates = @('Available', 'NeedsAssistance')

#region functions
#Functions based on basicScale.ps1 from Microsoft https://github.com/Azure/RDS-Templates/tree/master/wvd-templates/wvd-scaling-script
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

function TryForceLogOffUser {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $Session
    )
    Begin { }
    Process {
        [string[]]$Toks = $Session.Name.Split('/')
        [string]$SessionHostName = $Toks[1]
        [string]$SessionID = $Toks[-1]
        try {
            Write-Log "Force log off user: '$($Session.ActiveDirectoryUserName)', session ID: $SessionID"
            if ($PSCmdlet.ShouldProcess($SessionID, 'Force log off user with session ID')) {
                # Note: -SessionHostName param is case sensitive, so the command will fail if it's case is modified
                Remove-AzWvdUserSession -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -SessionHostName $SessionHostName -Id $SessionID -Force
            }
        }
        catch {
            Write-Log -Warn "Failed to force log off user: '$($Session.ActiveDirectoryUserName)', session ID: $SessionID $($PSItem | Format-List -Force | Out-String)"
        }
    }
    End { }
}
#endregion functions

###     Connect to Azure
Write-Log "Establish connection to Azure"
try {
    Write-Log "Logging in to Azure..."
    Connect-AzAccount -Identity
}
catch {
    Write-Error -Message $_.Exception
    throw $_.Exception
}

#region validate host pool, ensure there is at least 1 session host, get num of user sessions
# Validate and get HostPool info
$HostPool = $null
try {
    Write-Log "Collect host pool info of '$HostPoolName' in resource group '$ResourceGroupName'"
    $HostPool = Get-AzWvdHostPool -ResourceGroupName $ResourceGroupNameAvdMetadata -Name $HostPoolName
    if (!$HostPool) {
        throw $HostPool
    }
}
catch {
    throw [System.Exception]::new("Failed to get host pool info of '$HostPoolName' in resource group '$ResourceGroupName'. Ensure that you have entered the correct values", $PSItem.Exception)
}

# Ensure HostPool load balancer type is not persistent
if ($HostPool.LoadBalancerType -ieq 'Persistent') {
    throw "Host pool '$HostPoolName' is configured with a 'Persistent' load balancer type. Scaling tool only supports these load balancer types: BreadthFirst, DepthFirst"
}

Write-Log 'Get all session hosts'
$SessionHosts = @(Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupNameAvdMetadata -HostPoolName $HostPoolName)
if (!$SessionHosts) {
    Write-Log "There are no session hosts in the Host pool '$HostPoolName'. Ensure that host pool has session hosts"
    Write-Log 'End'
    return
}

#Write-Log "Host pool info: $($HostPool | Format-List -Force | Out-String)"
Write-Log " Number of session hosts in the host pool: $($SessionHosts.Count)"
#endregion

#region get all session hosts, VMs & user sessions info and compute workload

# Session host is considered "running" if its running AND is in desired states AND allowing new sessions
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
    if ($VMInstance.Tags.Keys -contains $maintenanceTagName) {
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
        if ($SessionHost.Status -notin $desiredRunningStates) {
            Write-Log -Warn 'VM is in running state but session host is not and so it will be ignored (this could be because the VM was just started and has not connected to broker yet)'
        }
    }
    else {
        if ($SessionHost.Status -in $desiredRunningStates) {
            Write-Log -Warn "VM is not in running state but session host is (this could be because the VM was just stopped and broker doesn't know that yet)"
        }
    }
}

$inValidVMNames = $VMs.Keys | Where-Object -FilterScript { $null -eq $VMs[$_].Instance }
foreach ($VMName in $inValidVMNames) {
    Write-Log "VM '$VMName' could not be matched and will be ignored"
    $VMs.Remove($VMName)
}
Write-Output "VMs type is $($VMs.GetType())"

$ValidVMs = @{}
$MaintenanceVMs = @{}

$VMs.GetEnumerator() | Where-Object -FilterScript { $_.Value.Maintenance -eq $false } | ForEach-Object -Process { $ValidVMs.Add($_.Key, $_.Value) }
$VMs.GetEnumerator() | Where-Object -FilterScript { $_.Value.Maintenance -eq $true } | ForEach-Object -Process { $MaintenanceVMs.Add($_.Key, $_.Value) }

#endregion

#region Check that new VMs are sufficient to take load before killing VMs
if ($desiredHostCount -gt $ValidVMs.Count) {
    Write-Log "Only $($ValidVMs.Count) valid Hosts found while $desiredHostCount was desired, exiting"
    Write-Log -Warn "Only $($ValidVMs.Count) valid Hosts found while $desiredHostCount was desired, exiting"
    return
}
#endregion

if ($MaintenanceVMs.Count -le 0) {
    Write-Output "No VMs to remove, finishing"
    return
}

#region validate pipeline exists and that it isn't currently running
#This pipeline turns on all VMs temporarily to ensure that it can update hosts, as this would conflict with this runbook check to make
#sure that this pipeline isn't running before attempting to turn off VMs
$EncodedAuth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$devOpsPAT"))
$Headers = @{
    Authorization = "Basic $EncodedAuth"
}
$Pipelines = Invoke-RestMethod -Method Get -Uri "https://dev.azure.com/ingmar0/InfraAsCode/_apis/pipelines" -Headers $Headers

#Pipeline name must include the HostPool Name (may include spaces) and the region location (may include spaces)
$Pipeline = $Pipelines.value | Where-Object -Property folder -EQ "\AVD\$hostPoolName" |
Where-Object -FilterScript { $_.name.replace(' ', '') -like "2*$hostPoolName*" }

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

#region remove hosts

foreach ($VMName in $MaintenanceVMs.Keys) {
    $VM = $MaintenanceVMs[$VMName]
    if ($VM.SessionHost.Session -gt 0) {
        if (-NOT $ForceDestroy) {
            Write-Log -Warn "$($VM.SessionHost.Name) still has active sessions, skipping"
            continue
        }
        else {
            Write-Log -Warn "$($VM.SessionHost.Name) still has active sessions, kicking active users"
            [array]$UserSessions = @()
            Write-Log "Get all user sessions from session host '$($VM.SessionHostName)'"
            try {
                $UserSessions = @(Get-AzWvdUserSession -ResourceGroupName $ResourceGroupNameAvdMetadata -HostPoolName $HostPoolName -SessionHostName $VM.SessionHostName)
            }
            catch {
                Write-Log -Warn "Failed to retrieve user sessions of session host '$($VM.SessionHostName)': $($PSItem | Format-List -Force | Out-String)"
                return
            }

            Write-Log "Force log off $($UserSessions.Count) users on session host: '$($VM.SessionHostName)'"
            $UserSessions | TryForceLogOffUser
        }
    }

    $updatevm = Get-AzVM -Name $VMName
    Get-AzVM -Name $VMName | Start-AzVM
    $machinename = $updatevm.Name
    Write-Log "- VM name: $VMName"

    $SessionHost = Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupNameAvdMetadata -HostPoolName "$hostPoolName" | Where-Object -property Name -like *$machineName* | select-object -ExpandProperty Name
    $SessionHost = $SessionHost.Split('/')[-1]
    Write-Log "- Session host name: $SessionHost"

    try {
        Remove-AzWvdSessionHost -HostPoolName "$hostPoolName" -Name $SessionHost -ResourceGroupName $ResourceGroupNameAvdMetadata -Force
        Write-Log "  Removal from host pool successful"
    }
    catch {
        Write-Log "!!!   Removal of AVD Session Host failed"
    }

    # Remove Entra ID
    Write-Log "Removing Entra Id $machinename"
    try {
        Get-AzVMExtension -ResourceGroupName $resourceGroupNameVMs -VMName $machinename | Where-Object Name -like *AADLoginForWindows* | Remove-AzVMExtension -Force | Out-Null
        Write-Log "  Removal of extensions successful"
    }
    catch {
        Write-Log "!!!   Removal of the device from Entra failed"
    }

    Write-Log "Removing VM $machinename"
    try {

        Remove-AzVM -Name $machinename -ResourceGroupName "$resourceGroupNameVMs" -Force

        #   Remove the NICs
        foreach ($nicUri in $updatevm.NetworkProfile.NetworkInterfaces.Id) {
            Write-Log "Removing NIC $($nicUri.Split('/')[-1])"
            $nic = $($nicUri.Split('/')[-1])
            try {
                Get-AzResource -ResourceType Microsoft.Network/networkInterfaces -Name $nic | Remove-AzResource -Force  
            }
            catch {
                Write-Log "Deletion of NIC failed"
            }
        }

        #   Remove the Disk
        Write-Log "Removing Disk $($updatevm.Instance.StorageProfile.OsDisk.Name)"
        try {
            Remove-AzDisk -ResourceGroupName $resourceGroupNameVMs -DiskName $updatevm.StorageProfile.OsDisk.Name -Force
        }
        catch {
            Write-Log "removal of disk failed"
        }         
    }
    catch {
        Write-Log "!!! Removal of the VM failed"
    }

}

#endregion
