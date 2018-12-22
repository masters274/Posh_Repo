#requires -Version 3.0 -Modules core

<#PSScriptInfo

        .VERSION 0.3

        .GUID 516711c1-bcf1-4e8a-ac7e-4cf33f16ff4b

        .AUTHOR Chris Masters

        .COMPANYNAME Chris Masters

        .COPYRIGHT (c) 2016 Chris Masters. All rights reserved.

        .TAGS system warranty dell support techdirect servicetag expressservicecode

        .LICENSEURI 

        .PROJECTURI https://www.powershellgallery.com/profiles/masters274/

        .ICONURI 

        .EXTERNALMODULEDEPENDENCIES core

        .REQUIREDSCRIPTS 

        .EXTERNALSCRIPTDEPENDENCIES 

        .RELEASENOTES
        11/14/2016:        
                0.2 -   Fixed mapping issues for LOB & Description
                    -   Added a switch param to use the sandbox environment. Default is production
                    -   Reversed if statement
                0.3 -   Added link to get your TechDirect account setup, and request a key

        .PRIVATEDATA 
        Setup your TechDirect account, and request your API key from 
        https://techdirect.dell.com/portal/AboutAPIs.aspx
#> 

<#
        .SYNOPSIS
        Get warranty and support information about Dell systems.

        .DESCRIPTION
        Allows you to take the service tag information from all of your Dell assets, and get the support 
        information for each. This save many hours when you have hundreds or thousands of Dell devices.

        .EXAMPLE
        ./GetDellSupportInfo.ps1 -ApiKey '1234567890' -ServiceTag ('abc1234',def5678')
        This will return the support information about both service tags provided. 

        .NOTES
        Requires that you have a valid API key from TechDirect for warranty lookup.

        .LINK
        https://github.com/masters274/
        https://techdirect.dell.com/portal/AboutAPIs.aspx

        .INPUTS
        Accepts a string value for API key and a string or array of strings for the ServiceTag parameter

        .OUTPUTS
        Provides PSObject with system information for each service tag. 
#>


[CmdletBinding()]
Param 
(
    [Parameter(Mandatory=$true,ValueFromPipeline=$true,
            HelpMessage='ServiceTag of Dell device',
        Position=0)]
    [Alias('st')]
    [String[]]$ServiceTag,
    	
    [Parameter(Mandatory=$true,
            HelpMessage='API key from Dell TechDirect',
        Position=1)]
    [Alias('ak','api')]
    [String]$ApiKey,

    [Parameter(HelpMessage='Use Dell sandbox?', Position=2)]
    [Switch]$Dev
  
)

Begin 
{
    $scriptVersion = 'Dell Support Info Grabber version 0.2'
    
    Write-Output -InputObject $scriptVersion
	# Check for requirements
	Try 
	{
		Write-Debug -Message 'Checking for prerequisites'
		Test-ModuleLoaded -RequiredModules ('core') -Quiet | Out-Null
	}
	Catch 
	{
		Write-Debug -Message 'If you made it here, you do not have the Core module available to check requirements'
		Write-Error -Message 'Core module not loaded! Failed to test requirements.'
	}
}

Process 
{

    # Get a baseline snapshot
    Write-Debug -Message 'Creating a variable snapshot'
    
    Write-Debug -Message 'Processing the script...'
    # Variables
    if ($Dev) 
    {
        $strDomainName = 'sandbox.api.dell.com'
    }
    
    Else 
    {
        $strDomainName = 'api.dell.com'
    }
    
    $strBaseUri = ('https://{0}/support/assetinfo/v4/' -f $strDomainName)
    $arrayMethods = ('GetAssetHeader','GetAssetWarranty','GetAssetSummary','GetCodeMapping')
    $strContentType = 'Application/xml'
    $objReportData = @()

    Foreach ($system in $ServiceTag) {
        
        # Verify that we have a valid service tag
        if ($system.Length -ne 7) 
        {
            Write-Error -Message ('Service Tag {0} is invalid!' -f $system)
        }
    
        $strUri = ('{0}/{1}/{2}?apikey={3}' -f $strBaseUri,$arrayMethods[2],$system,$ApiKey)
        Write-Debug -Message ('URI: {0}' -f $strUri)
        
        Try 
        {
            $rawRequest = Invoke-WebRequest -Uri $strUri -ContentType $strContentType -Method Get `
            -ErrorVariable $wrev
        }
    
        Catch
        {
            Write-Error -Message ('Something went wrong connecting to {0}' -f $strBaseUri)
        }
    
        If (!($wrev.Count -gt 0)) 
        {
            [xml]$xmlContent = $rawRequest.Content 
        
        
            $objBuilder = New-Object -TypeName PSObject 
            
            $objBuilder |
             Add-Member -MemberType NoteProperty -Name 'ServiceTag' -Value (
                '{0}' -f $xmlContent.AssetSummaryDTO.AssetSummaryResponse.AssetHeaderData.ServiceTag
            )
             
            $objBuilder |
             Add-Member -MemberType NoteProperty -Name 'CustomerNumber' -Value (
                '{0}' -f $xmlContent.AssetSummaryDTO.AssetSummaryResponse.AssetHeaderData.CustomerNumber
            )
             
            $objBuilder |
             Add-Member -MemberType NoteProperty -Name 'OrderNumber' -Value (
                '{0}' -f $xmlContent.AssetSummaryDTO.AssetSummaryResponse.AssetHeaderData.OrderNumber
            )
             
            $objBuilder |
             Add-Member -MemberType NoteProperty -Name 'LOB' -Value (
                '{0}' -f $xmlContent.AssetSummaryDTO.AssetSummaryResponse.ProductHeaderData.LOB
            )
             
            $objBuilder |
             Add-Member -MemberType NoteProperty -Name 'ModelDescription' -Value (
                '{0}' -f $xmlContent.AssetSummaryDTO.AssetSummaryResponse.ProductHeaderData.SystemDescription
             )
                          
            $objBuilder |
             Add-Member -MemberType NoteProperty -Name 'ShipDate' -Value (
                '{0}' -f $(
                    Get-Date -Date $xmlContent.AssetSummaryDTO.AssetSummaryResponse.AssetHeaderData.ShipDate `
                    -UFormat '%Y-%m-%d'
                )
            )             
            
            # Check if system has extended or initial warranty
            If (
                $xmlContent.AssetSummaryDTO.AssetSummaryResponse.AssetEntitlementData.AssetEntitlement.EntitlementType -contains 'EXTENDED'
            ) 
            
            {
                $strWarrantyType = 'Extended'
                [datetime]$dtSupportEndDate = $xmlContent.AssetSummaryDTO.AssetSummaryResponse.AssetEntitlementData.AssetEntitlement | 
                Where-Object {$_.EntitlementType -match 'EXTENDED'} | 
                ForEach-Object {$_.EndDate} | 
                Sort-Object -Descending | 
                Select-Object -First 1
            }
            
            Else 
            {
                $strWarrantyType = 'Initial'
                [datetime]$dtSupportEndDate = $xmlContent.AssetSummaryDTO.AssetSummaryResponse.AssetEntitlementData.AssetEntitlement | 
                Where-Object {$_.EntitlementType -match 'INITIAL'} | 
                ForEach-Object {$_.EndDate} | 
                Sort-Object -Descending | 
                Select-Object -First 1
            }
            
            $objBuilder |
             Add-Member -MemberType NoteProperty -Name 'WarrantyType' -Value (
                '{0}' -f $strWarrantyType
            )
            
            $objBuilder |
             Add-Member -MemberType NoteProperty -Name 'SupportEndDate' -Value (
                '{0}' -f $(Get-Date -Date ($dtSupportEndDate) -UFormat '%Y-%m-%d')
            )
            
            [int] $intDaysRemaining = $((New-TimeSpan -Start $(Get-Date) -End $dtSupportEndDate).Days)
            $objBuilder |
             Add-Member -MemberType NoteProperty -Name 'DaysRemaining' -Value $intDaysRemaining
            
            If ( $(New-TimeSpan -Start $(Get-Date) -End $dtSupportEndDate).Days -lt 1 ) 
            {
                $strWarrantyStatus = 'Expired'
            }
            
            Else 
            {
                $strWarrantyStatus = 'Active'
            }
            
            $objBuilder |
             Add-Member -MemberType NoteProperty -Name 'WarrantyStatus' -Value (
                '{0}' -f $strWarrantyStatus
            )
            
            $objReportData += $objBuilder
        }
    
    }
    
    $objReportData
    
    # Clean up the environment 
    Write-Debug -Message 'Reverting local variables to snapshot'
}

End 
{
    
}