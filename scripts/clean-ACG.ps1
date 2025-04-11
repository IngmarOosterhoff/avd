################################################################################
##  File:  Clean-ACG.ps1
##  Desc:  Removes old image versions from the Azure Compute Gallery (ACG)
################################################################################

[CmdletBinding()]
Param(
    [Parameter(Mandatory)]
    [String]
    $ResourceGroupName,
    [Parameter(Mandatory)]
    [String]
    $computeGalleryName,
    [Parameter(Mandatory)]
    [String]
    $ImageTemplateName,
    [Parameter()]
    [int]
    $VersionCount = 3 # Keep 3 versions by default
)

$subscriptionId = Get-AutomationVariable -Name "subscriptionId" -ErrorAction Stop

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



try {
    Write-Log "Logging in to Azure..."
    Connect-AzAccount -Identity

    $context = Set-AzContext -SubscriptionId $subscriptionId | out-null

    $AllImageVersions = Get-AzGalleryImageVersion -ResourceGroupName $ResourceGroupName -GalleryName $computeGalleryName -GalleryImageDefinitionName $ImageTemplateName
    $RemoveVersions = @()
    $RemoveVersions += $AllImageVersions | Sort-Object -Property Name -Descending | Select-Object -Skip $VersionCount

    if ($RemoveVersions.Count -gt 0) {
        Write-Output "Removing $($RemoveVersions.Count) Old Versions"
        foreach ($version in $RemoveVersions) {
            Write-Output "Removing version: $($Version.Name)"
            Remove-AzGalleryImageVersion -InputObject $version -Force
        }
    }
    else {
        Write-Output "No old image versions to remove from the gallery."
    }
}
catch {
    Write-Error -Message $_.Exception
    throw $_.Exception
}