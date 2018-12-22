#requires -Version 1.0
#requires -PSSnapin VMware.VimAutomation.Core

<#PSScriptInfo

        .VERSION 0.1

        .GUID 58a4280b-fcf2-43bc-9dc9-b1da178da404

        .AUTHOR Chris Masters

        .COMPANYNAME Chris Masters

        .COPYRIGHT (c) 2018 Chris Masters. All rights reserved.

        .TAGS network vmware vsphere ping vmkping virtual

        .LICENSEURI 

        .PROJECTURI https://www.powershellgallery.com/profiles/masters274/

        .ICONURI 

        .EXTERNALMODULEDEPENDENCIES VMware.VimAutomation.Core

        .REQUIREDSCRIPTS 

        .EXTERNALSCRIPTDEPENDENCIES 

        .RELEASENOTES
        12/22/2018:        
                0.1 -   Day one release. 

        .PRIVATEDATA 
        
#> 

<#
        .SYNOPSIS
        VMK Ping from PowerCli

        .DESCRIPTION
        This script allows you to test the connectivity of your virtual nics in vSphere. You no longer need to 
        enable SSH to perform these tests. This script works great in an automated deployment strategy. 

        .EXAMPLE
        Invoke-VmkPing -VMHost myHost.domain.local -Credential root -IPAddress 192.168.200.10
        This will perform a VMK ping to 192.168.200.10 from host myHost.domain.local, results will look similar to
        the following.

        Duplicated     : 0
        HostAddr       : 192.168.200.10
        PacketLost     : 0
        Recieved       : 3
        RoundtripAvgMS : 192
        RoundtripMaxMS : 221
        RoundtripMinMS : 168
        Transmitted    : 3

        .EXAMPLE
        Invoke-VmkPing -VMHost myHost.domain.local -Credential root -IPAddress 192.168.200.10 -DFBit -Size 8972
        This will perform a VMK ping to 192.168.200.10 from host myHost.domain.local with the DF (don't fragment)
        bit set, and test that jumbo frames are configured properly, end to end. Don't forget about packet headers.
        We set the size to 8972, to test that our jumbo configuration of 9000 is working propery. Don't forget the
        -DFBit setting, otherwise it will always work no matter the size if connectivity is true. 

        .NOTES
        Requires that you have VMware.VimAutomation.Core PSSnapin loaded.

        .LINK
        https://github.com/masters274/
        https://www.powershellgallery.com/profiles/masters274/

        .INPUTS
        Accepts a string value for API key and a string or array of strings for the ServiceTag parameter

        .OUTPUTS
        Provides PSObject with network stats, based on the results
        
        Duplicated     : 0
        HostAddr       : 192.168.200.10
        PacketLost     : 0
        Recieved       : 3
        RoundtripAvgMS : 192
        RoundtripMaxMS : 221
        RoundtripMinMS : 168
        Transmitted    : 3 
#>


Param
(
    [Parameter(Mandatory=$true, HelpMessage = 'VMHost you want to ping from')]
    [String] $VMHost, 
        
    [Parameter(Mandatory=$true, HelpMessage='Credentials for administering VMHost')]
    [System.Management.Automation.Credential()]
    [PSCredential] $Credential,
        
    [int] $Count = 3,
        
    [Switch] $DFBit, # set this when testing jumbo frames, or > 1500 packet size
        
    [Parameter(Mandatory = $true, HelpMessage = 'IP you want to ping for testing')]
    [IPAddress] $IPAddress,
        
    [ValidatePattern('^vmk*')]
    [String] $Interface = $null, # $null will pick the nic based on routing table, or interface subnet
        
    [int] $Size = 1500, # set to 8972 to test jumbo frames
        
    [Long] $TTL = $null
)
    
Begin
{
    
}
    
Process
{
    # Variables 
    $strStopAction = 'Stop'
    
    # Connect to the VMHost
    Try
    {
        Connect-VIServer -Server $VMHost -Credential $Credential -WarningAction SilentlyContinue -ErrorAction $strStopAction | Out-Null
        $cmdESXcli = Get-EsxCli -VMHost $VMHost -ErrorAction $strStopAction
    }
    Catch
    {
        Write-Error -Message ('Failed to connect to VMHost {0}' -f $VMHost)
        return
    }
        
    #ping(long count, boolean debug, boolean df, string host, string interface, string interval, boolean ipv4, boolean ipv6, string netstack, string nexthop, long size, long ttl, string wait
    [Bool] $isIPv4 = $false
    [Bool] $isIPv6 = $false
     
    If ($IPAddress.AddressFamily -eq 'InterNetworkV6')
    {
        $isIPv6 = $true
    }
    Else
    {
        $isIPv4 = $true
    }
        
    $ret = $cmdESXcli.network.diag.ping(
        $Count,
        $false, # debugging
        $(If (!$DFBit) {$null} Else {$DFBit}), # Don't fragment bit
        $IPAddress,
        $null,
        $null, # String Interval
        $isIPv4,
        $isIPv6,
        $null, # [string] netstack
        $null, # [string] nexthop
        $Size, # Set to 8972 to test jumbo frames, also need DF bit set
        $(If (!$TTL) {$null} Else {$TTL}),
        $null # [String] wait
    )
        
    If ($ret.summary.PacketLost -gt 0)
    {
        Write-Warning -Message ('IP {0} not reachable, or missing packets!' -f $IPAddress)
    }
    
    $ret.summary
}
    
End
{
    Disconnect-VIServer -Server $VMHost -Force -Confirm:$false | Out-Null
}
