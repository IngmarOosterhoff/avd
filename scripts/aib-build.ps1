[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$Location,

    [Parameter(Mandatory)]
    [string]$TemplateName,

    [Parameter(Mandatory)]
    [string]$TemplateResourceGroupName


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

$ErrorActionPreference = 'Stop'

# Collect the credentials from Azure Automation Account Assets
Write-Log "Get auto connection from asset: AzureRunAsConnection"

try {
    Write-Log "Logging in to Azure..."
    Connect-AzAccount -Identity

    $context = Set-AzContext -SubscriptionId $subscriptionId | out-null

    # Import Modules
    Install-Module -Name Az.Accounts -RequiredVersion 2.15.0
    install-module Az.ImageBuilder -AllowClobber -Force
    Import-Module -Name 'Az.Accounts', 'Az.Compute', 'Az.ImageBuilder'
    Write-Output "$TemplateName | $TemplateResourceGroupName | Imported the required modules."

    # Connect to Azure using the Managed Identity
    # Connect-AzAccount -Environment $EnvironmentName -Subscription $SubscriptionId -Tenant $TenantId -Identity -AccountId $ClientId | Out-Null
    # Write-Output "$TemplateName | $TemplateResourceGroupName | Connected to Azure."

    # Get the date / time and status of the last AIB Image Template build
    $ImageBuild = Get-AzImageBuilderTemplate -ResourceGroupName $TemplateResourceGroupName -Name $TemplateName
    $ImageBuildDate = $ImageBuild.LastRunStatusStartTime
    if (!$ImageBuildDate) {
        Write-Output "$TemplateName | $TemplateResourceGroupName | Last Build Start Time: None."
    }
    else {
        Write-Output "$TemplateName | $TemplateResourceGroupName | Last Build Start Time: $ImageBuildDate."
    }
    $ImageBuildStatus = $ImageBuild.LastRunStatusRunState
    if (!$ImageBuildStatus) {
        Write-Output "$TemplateName | $TemplateResourceGroupName | Last Build Run State: None."
    }
    else {
        Write-Output "$TemplateName | $TemplateResourceGroupName | Last Build Run State: $ImageBuildStatus."
    }


    # # Get the date of the latest marketplace image version
    # $ImageVersionDateRaw = (Get-AzVMImage -Location $Location -PublisherName $ImagePublisher -Offer $ImageOffer -Skus $ImageSku | Sort-Object -Property 'Version' -Descending | Select-Object -First 1).Version.Split('.')[-1]
    # $Year = '20' + $ImageVersionDateRaw.Substring(0, 2)
    # $Month = $ImageVersionDateRaw.Substring(2, 2)
    # $Day = $ImageVersionDateRaw.Substring(4, 2)
    # $ImageVersionDate = Get-Date -Year $Year -Month $Month -Day $Day -Hour 00 -Minute 00 -Second 00
    # Write-Output "$TemplateName | $TemplateResourceGroupName | Marketplace Image, Latest Version Date: $ImageVersionDate."

    # # If the latest Image Template build is in a failed state, output a message and throw an error
    # if ($ImageBuildStatus -eq 'Failed') {
    #     Write-Output "$TemplateName | $TemplateResourceGroupName | Latest Image Template build failed. Review the build log and correct the issue."
    #     throw
    # }
    # If the latest Marketplace Image Version was released after the last AIB Image Template build then trigger a new AIB Image Template build
    # elseif ($ImageVersionDate -gt $ImageBuildDate) {   
    Write-Output "$TemplateName | $TemplateResourceGroupName | Image Template build initiated with new Marketplace Image Version."
    Start-AzImageBuilderTemplate -ResourceGroupName $TemplateResourceGroupName -Name $TemplateName
    Write-Output "$TemplateName | $TemplateResourceGroupName | Image Template build succeeded. New Image Version available in Compute Gallery."
    # }
    # else {
    #     Write-Output "$TemplateName | $TemplateResourceGroupName | Image Template build not required. Marketplace Image Version is older than the latest Image Template build."
    # }
}
catch {
    Write-Error -Message $_.Exception
    throw $_.Exception
}