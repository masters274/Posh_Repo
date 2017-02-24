<#
        .Synopsis
        Module with various network functions

        .DESCRIPTION
        Module with various network functions
        
        .NOTES
        N/A
        
        .COMPONENT
        The component this cmdlet belongs to
        
        .ROLE
        The role this cmdlet belongs to
        
        .FUNCTIONALITY
        The functionality that best describes this cmdlet
#>


#region Verion Info

<#
        Version 0.1
        - Day one
#>

#endregion


#region Prerequisites

# All modules require the core
[scriptblock] $__init = {
    Try
    {
        Import-Module -Name 'core'
    }

    Catch
    {
        Try
        {
            $uriCoreModule = 'https://raw.githubusercontent.com/masters274/Powershell_Stuff/master/Modules/Core/core.psm1'
    
            $moduleCode = (Invoke-WebRequest -Uri $uriCoreModule).Content
            
            Invoke-Expression -Command $moduleCode
        }
    
        Catch
        {
            Write-Error -Message ('Failed to load {0}, due to missing core module' -f $PSScriptRoot)
        }
    }
}

& $__init

#endregion


#region Functions


### DNS Functions ###


Function Get-DnsAddressList 
{
    param(
        [parameter(Mandatory=$true)][Alias("Host")]
        [string]$HostName
    )

    Try 
    {
        return [System.Net.Dns]::GetHostEntry($HostName).AddressList
    }
    
    Catch [System.Net.Sockets.SocketException] 
    {
        IF ($_.Exception.ErrorCode -ne 11001) 
        {
            throw $_
        }
        
        return = @()
    }
}


Function Get-DNSDebugLog 
{ # Parses the DNS debug log
    <#
            .SYNOPSIS
            Reads the specified DNS debug log.

            .DESCRIPTION
            Retrives all entries in the DNS debug log for further processing using powershell or exporting to Excel.

            .PARAMETER Path
            Specifies the path to the DNS debug logfile.

            .PARAMETER Ignore
            Specifies which IPs to ignore.

            .INPUTS
            Takes the filepath of the DNS servers debug log.
            And an Ignore parameter to ignore certain ips.

            .OUTPUTS
            Array of PSCustomObject

            \windows\system32\dns\dns.log

            .EXAMPLE
            Get-DNSDebugLog -Path "$($env:SystemRoot)\system32\dns\dns.log" -Verbose |? {$_.QR -eq "Query"-and $_.Way -eq 'RCV'} |group-Object "Client IP"| Sort-Object -Descending Count| Select -First 10 Name, Count

            Name            Count
            ----            -----
            192.168.66.103     21
            192.168.66.37      11
            192.168.66.22       4
            192.168.66.117      1


            .EXAMPLE
            C:\PS> Import-Module ActiveDirectory
            C:\PS> $ignore =  Get-ADDomainController -Filter * | Select-Object -ExpandProperty Hostname |ForEach-Object {[System.Net.Dns]::GetHostAddresses($_)|select -ExpandProperty IPAddressToString}
            C:\PS> Get-DNSDebugLog -Ignore:$Ignore -Path '\\dc01.domain.tld\c$\dns.log'

            .LINK
            Script center: http://gallery.technet.microsoft.com/scriptcenter/Get-DNSDebugLog-Easy-ef048bdf
            My Blog: http://virot.eu
            Blog Entry: http://virot.eu/wordpress/easy-handling-before-removing-dns/

            .NOTES
            Author:	Oscar Virot - virot@virot.com
            Filename: Get-DNSDebugLog.ps1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        [ValidateScript({Test-Path($_)})]
        $Path,
        
        [Parameter(Mandatory=$False)]
        [string[]]
        $Ignore
    )
    
    Begin
    {
        Write-Verbose "Storing DNS logfile format"
        $dnspattern = "^([0-9]{1,2}\/[0-9]{2}\/[0-9]{2,4}|[0-9]{2,4}-[0-9]{2}-[0-9]{2}) ([0-9: ]{7,8}\s?P?A?M?) ([0-9A-Z]{3,4} PACKET\s*[0-9A-Za-z]{8,16}) (UDP|TCP) (Snd|Rcv) ([0-9 .]{7,15}) ([0-9a-z]{4}) (.) (.) \[.*\] (.*) (\(.*)"
        Write-Verbose "Storing storing returning customobject format"
        $returnselect = @{label="Client IP";expression={[ipaddress] ($temp[6]).trim()}},
        @{label="DateTime";expression={[DateTime] (Get-Date("$($temp[1]) $($temp[2])"))}},
        @{label="QR";expression={switch($temp[8]){" " {'Query'};"R" {'Response'}}}},
        @{label="OpCode";expression={switch($temp[9]){'Q' {'Standard Query'};'N' {'Notify'};'U' {'Update'};'?' {'Unknown'}}}},
        @{label="Way";expression={$temp[5]}},
        @{label="QueryType";expression={($temp[10]).Trim()}},
        @{label="Query";expression={$temp[11] -replace "(`\(.*)","`$1" -replace "`\(.*?`\)","." -replace "^.",""}}
    }
    
    Process
    {
        Write-Verbose "Getting the contents of $Path, and matching for correct rows."
        $rows = (Get-Content $Path) -match $dnspattern -notmatch 'ERROR offset' -notmatch 'NOTIMP'
        # $file = ls $Path;
        # $objFile = [System.IO.File]::ReadAllText($file.FullName);
        # $rows = $objFile.split("\n") -match $dnspattern -notmatch 'ERROR offset' -notmatch 'NOTIMP'
        Write-Verbose "Found $($rows.count) in debuglog, processing 1 at a time."
        ForEach ($row in $rows)
        {
            Try
            {
                $temp = $Null
                $temp = [regex]::split($row,$dnspattern)
                if ($Ignore -notcontains ([ipaddress] ($temp[6]).trim()))
                {
                    $true | Select-Object $returnselect
                }
            }
            Catch
            {
                Write-Verbose 'Failed to interpet row.'
                Write-Debug 'Failed to interpet row.'
                Write-Debug $row
            }
        }
    }
    
    End
    {
    
    }
}


Function Get-DnsMXQuery 
{
    param(
        [parameter(Mandatory=$true)]
    [string]$DomainName)

    if (-not $Script:global_dnsquery) {
        $Private:SourceCS = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace PM.Dns {
  public class MXQuery {
    [DllImport("dnsapi", EntryPoint="DnsQuery_W", CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
    private static extern int DnsQuery(
        [MarshalAs(UnmanagedType.VBByRefStr)]
        ref string pszName, 
        ushort     wType, 
        uint       options, 
        IntPtr     aipServers, 
        ref IntPtr ppQueryResults, 
        IntPtr pReserved);

    [DllImport("dnsapi", CharSet=CharSet.Auto, SetLastError=true)]
    private static extern void DnsRecordListFree(IntPtr pRecordList, int FreeType);

    public static string[] Resolve(string domain)
    {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            throw new NotSupportedException();

        List<string> list = new List<string>();

        IntPtr ptr1 = IntPtr.Zero;
        IntPtr ptr2 = IntPtr.Zero;
        int num1 = DnsQuery(ref domain, 15, 0, IntPtr.Zero, ref ptr1, IntPtr.Zero);
        if (num1 != 0)
            throw new Win32Exception(num1);
        try {
            MXRecord recMx;
            for (ptr2 = ptr1; !ptr2.Equals(IntPtr.Zero); ptr2 = recMx.pNext) {
                recMx = (MXRecord)Marshal.PtrToStructure(ptr2, typeof(MXRecord));
                if (recMx.wType == 15)
                    list.Add(Marshal.PtrToStringAuto(recMx.pNameExchange));
            }
        }
        finally {
            DnsRecordListFree(ptr1, 0);
        }

        return list.ToArray();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MXRecord
    {
        public IntPtr pNext;
        public string pName;
        public short  wType;
        public short  wDataLength;
        public int    flags;
        public int    dwTtl;
        public int    dwReserved;
        public IntPtr pNameExchange;
        public short  wPreference;
        public short  Pad;
    }
  }
}
'@

        Add-Type -TypeDefinition $Private:SourceCS -ErrorAction Stop
        $Script:global_dnsquery = $true
    }

    [PM.Dns.MXQuery]::Resolve($DomainName) | % {
        $rec = New-Object PSObject
        Add-Member -InputObject $rec -MemberType NoteProperty -Name "Host"        -Value $_
        Add-Member -InputObject $rec -MemberType NoteProperty -Name "AddressList" -Value $(Get-DnsAddressList $_)
        $rec
    }
}


Function Get-DnsCache 
{

    [CmdLetBinding()]
    PARAM 
    (
        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
        [String] $InputFile,
        
        [String] $ComputerName,
        
        [PSCredential] $Credential
    )
    
    $Props = [Ordered] @{
        RecordName = ""
        RecordType = ""
        Section    = ""
        TimeToLive = 0
        DataLength = 0
        Data       = ""
    }

    $Records = @()

    IF ($InputFile) 
    { # Allow for the use of offline cache file
        $Cache = gc $InputFile
    } 
    
    ElseIF ($ComputerName)
    {
        [String] $sb = '{ ipconfig /displaydns }'
        [String] $Command = (
            'Invoke-Command -Command {0} -ComputerName {2}{1}{2} -Authentication Kerberos' -f $sb,$ComputerName,"'"
        )
        
        IF ($Credential) { $Command = $Command + ' -Credential $Credential' }
        
        $Cache = Invoke-Expression -Command $Command 
    }
    
    Else
    {
        $Cache = ipconfig /displaydns
    }
	
    For 
    (
        $i=0
        $i -le ($Cache.Count -1)
        $i++
    ) 
    
    {
        IF ($Cache[$i] -like '*Record Name*')
        {
            $Record = New-Object -TypeName psobject -Property $Props
            $Record.RecordName = ($Cache[$i] -split -split ": ")[1]
            $Record.Section = ($Cache[$i+4] -split -split ": ")[1]
            $Record.TimeToLive = ($Cache[$i+2] -split -split ": ")[1]
            $Record.DataLength = ($Cache[$i+3] -split -split ": ")[1]

            $iRecord = ($Cache[$i+5] -split ": ")
            $Record.RecordType = ($iRecord[0].TrimStart() -split ' ')[0]
            $Record.Data = $iRecord[1]

            $Records += $Record
        } 
        
        Else 
        {
            Continue
        }
    }

    $Records 
}


Function Clear-DnsCache
{
    [CmdLetBinding()]
    PARAM 
    (        
        [String] $ComputerName,
        
        [PSCredential] $Credential
    )

    IF ($ComputerName)
    {
        [String] $sb = '{ ipconfig /flushdns }'
        [String] $Command = (
            'Invoke-Command -Command {0} -ComputerName {2}{1}{2} -Authentication Kerberos' -f $sb,$ComputerName,"'"
        )
        
        IF ($Credential) { $Command = $Command + ' -Credential $Credential' }
        
        Invoke-Expression -Command $Command 
    }
    
    Else
    {
        ipconfig /flushdns
    }
}


### IP Address Functions ####


Function ConvertTo-DottedDecimalIP ( [String]$IP ) 
{

    Switch -RegEx ($IP) {
        "([01]{8}\.){3}[01]{8}" {

            Return [String]::Join('.', $( $IP.Split('.') | ForEach-Object {[Convert]::ToInt32($_, 2) } ))}
        "\d" {

            $IP = [UInt32]$IP
            $DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
                    $Remainder = $IP % [Math]::Pow(256, $i)
                    ($IP - $Remainder) / [Math]::Pow(256, $i)
                    $IP = $Remainder
            } )

            Return [String]::Join('.', $DottedIP)
        }
        
        Default {
            Write-Error "Cannot convert this format"
        }
    }
}


Function ConvertTo-DecimalIP ( [String]$IP ) 
{

    $IPAddress = [Net.IPAddress]::Parse($IP)
    $i = 3
    $IPAddress.GetAddressBytes() | %{
    $DecimalIP += $_ * [Math]::Pow(256, $i); $i-- }

    Return [UInt32]$DecimalIP
}


Function ifconfig 
{
	
    $arrayInterfaces = @()


    Foreach ($adapter in $(Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Sort-Object -Property Name)) {
                $strName = $adapter.Name
                $strMac = $adapter.MacAddress
                $strIP = $adapter | Get-NetIpAddress | ForEach-Object {$_.IPAddress
        }
		
        $objBuilder = New-Object -TypeName PSObject
        $objBuilder | Add-Member -Type NoteProperty -Name "Iface" -Value "$strName"
        $objBuilder | Add-Member -Type NoteProperty -Name "MacAddress" -Value "$strMac"
        $objBuilder | Add-Member -Type NoteProperty -Name "IP Address" -Value "$strIP"
		
        $arrayInterfaces += $objBuilder
		
    }

    $arrayInterfaces 
}


Function Get-MyIpAddress
{
    <#
            .Synopsis
            Get's your public IP address. 

            .DESCRIPTION
            Uses https://api.ipify.org API to return your IP address. 

            .EXAMPLE
            $ip = Get-MyIpAddress
    #>

    <#
            Version 0.1
            - Day one
    #>

    Try
    {
        $uri = 'https://api.ipify.org'
    
        $ip = Invoke-WebRequest -Uri $uri
    
        Return $ip.Content
    }
    
    Catch
    {
        Write-Error -Message 'Failed to get IP address'
    }
}


#endregion
