#requires -Version 5.0
#requires -Modules @{ModuleName='core'; ModuleVersion='1.4'}

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
        
        return
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
        #$rows = (Get-Content $Path) -match $dnspattern -notmatch 'ERROR offset' -notmatch 'NOTIMP'
        $file = ls $Path;
        $objFile = [System.IO.File]::ReadAllText($file.FullName);
        $rows = $objFile.split("`n") -match $dnspattern -notmatch 'ERROR offset' -notmatch 'NOTIMP'
        Write-Verbose "Found $($rows.count) rows in debuglog, processing 1 at a time."
        
        [int]$intTracker = 0
                
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
                $strFailedRow = 'Failed to interpet row.'
                Write-Verbose $strFailedRow
                Write-Debug $strFailedRow
                Write-Debug $row
            }

            $perc = ($intTracker/$($rows.Count) * 100)
            Write-Progress -PercentComplete $perc -Activity "Processing $intTracker of $($rows.Count)" `
            -Status 'File analysis progress'
            $intTracker++
        }
    }
    
    End
    {
    
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


Function Get-HostsFile
{
    $strHostsFile = '{0}\System32\Drivers\etc\hosts' -f $env:SystemRoot
    Get-Content -Path $strHostsFile -Encoding Ascii
}


Function Add-HostsFileEntry
{
    Param
    (
        [Parameter(Mandatory = $true, Position = 0,
        HelpMessage = 'Name of the system to add')]
        [Alias('System')]
        [String] $HostName,
        
        [Parameter(Mandatory = $true, Position = 1,
        HelpMessage = 'IP of the hostname to add')]
        [ipaddress] $IP
    )
    
    $boolIsAdmin = (Test-AdminRights)
    $strHostsFile = '{0}\System32\Drivers\etc\hosts' -f $env:SystemRoot
    
    If (!$boolIsAdmin)
    {
        '{0} This command requires admin rights {0}' -f "`n"
        
        [String] $cmd = $MyInvocation.Line
        
        If ($cmd -clike ('* {0}*' -f '$'))
        {
            $msg = @'
            {0}Unable to elevate when using variables as parameters!{0}
Try again without variables, or use this function from and elevated prompt
'@ -f "`n"

            Write-Host -ForegroundColor Yellow $msg
            Return
        }
        Else
        {
            $input = $(
                Add-Type -AssemblyName Microsoft.VisualBasic
                [Microsoft.VisualBasic.Interaction]::MsgBox("Do you want to run this command elevated?", "YesNo", "Elevate?")
            )
            $answer = $input
            
            If ($answer -eq 'Yes')
            {
                Invoke-Elevate -Command $cmd
            }
        }
        Return
    }
    
    $objFile = Get-Content -Path $strHostsFile -Encoding Ascii
    [int] $intLineCount = $objFile.Count -1
    
    # Check if the last line in the file is a blank line
    [bool] $boolIsBlankLine = ($objFile[$intLineCount] -eq '')
    
    If (!$boolIsBlankLine)
    {
        "`n" | Out-File -Append -Encoding ascii -FilePath $strHostsFile
    }
    
    "$IP`t$HostName" | Out-File -Append -Encoding ascii -FilePath $strHostsFile
    
    $?
}


Function Remove-HostsFileEntry
{
    Param
    (
        [Parameter(Mandatory = $true, Position = 1,
        HelpMessage = 'IP of the hostname to remove')]
        [ipaddress] $IP
    )
    
    $boolIsAdmin = (Test-AdminRights)
    $strHostsFile = '{0}\System32\Drivers\etc\hosts' -f $env:SystemRoot
    
    If (!$boolIsAdmin)
    {
        '{0} This command requires admin rights {0}' -f "`n"
        
        [String] $cmd = $MyInvocation.Line
        
        If ($cmd -clike ('* {0}*' -f '$'))
        {
            $msg = @'
            {0}Unable to elevate when using variables as parameters!{0}
Try again without variables, or use this function from and elevated prompt
'@ -f "`n"

            Write-Host -ForegroundColor Yellow $msg
            Return
        }
        Else
        {
            $input = $(
                Add-Type -AssemblyName Microsoft.VisualBasic
                [Microsoft.VisualBasic.Interaction]::MsgBox("Do you want to run this command elevated?", "YesNo", "Elevate?")
            )
            $answer = $input
            
            If ($answer -eq 'Yes')
            {
                Invoke-Elevate -Command $cmd
            }
        }
        Return
    }
    
    # Remove the entry
    $objFile = Get-Content -Path $strHostsFile -Encoding Ascii | 
    Where-Object {$_ -notmatch $IP.ToString()} 
    
    # Can't do a one-liner cause the file would be busy still
    $objFile | Set-Content -Path $strHostsFile -Encoding Ascii -Force
    
    $?
}


Function Get-DNSScavengeRecord
{
    <#
            .SYNOPSIS
            This will search the supplied DNS zone, and display records that will be scavenged

            .DESCRIPTION
            This script can help you visualize which records will be scavenged if you enable scavenging on the DNS 
            server. Reminder: you must enable scavenging on the zone, and the server before it will start cleaning 
            your DNS. This script helps you to turn it on... many times admins don't turn this on till there's an 
            obvious problem. Turning this on could delete important records that are not static. 

            .PARAMETER ComputerName
            This should be the Windows DNS server that you plan to query

            .PARAMETER Domain
            This will be the zone name you wish to query. This will accept an array of zones. 

            .PARAMETER Age
            Sets the age in the filter query. You'll only want to see records that would be considered expired.

            .PARAMETER Credential
            Credentials that will allow you to query WMI on the DNS server

            .EXAMPLE
            Get-DNSScavengeRecord -ComputerName dc01 -Domain contoso.com -Age 20 -Credential $myCred
            Will return expired records from dc01 in the contoso.com DNS zone

            .EXAMPLE
            Get-DNSScavengeRecord -ComputerName dc01 -Domain contoso.com -Age 20 -Credential $myCred | FL *
            Will return expired records from dc01 in the contoso.com DNS zone, and show all properties

            .NOTES
            This command limits the properties returned to keep it clean. To see all properties available, you can 
            pipe to Format-List -Properties *, or to Get-Member

            .LINK
            https://www.powershellgallery.com/packages/Network

            .INPUTS
            You can pipe an array of strings to this function

            .OUTPUTS
            Array of objects returned. Default property display is limited. 
    #>


    Param
    (
        [Parameter(Mandatory=$true, HelpMessage='DNS server to connect to')]
        [String] $ComputerName,
        
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage='DNS zone to search')]
        [String[]] $Domain,
        
        [Int] $Age = 14, # Default config: refresh=7 & no-refresh=7
        
        [Parameter(Mandatory=$true, HelpMessage='Credentials for administering the DNS server')]
        [System.Management.Automation.Credential()]
        [PSCredential] $Credential
    )
    
    Begin
    {
        # Constants
        $dtExpireAge = $Age
        $dtBeginTime = [Int] (New-TimeSpan `
            -Start $(Get-Date -Date ('01/01/1601 00:00')) `
        -End $((Get-Date).AddDays(-$dtExpireAge))).TotalHours  
        
        # Pretty messy if we display everything... will keep it simple
        [String[]] $defaultDisplaySet = 'OwnerName','IPAddress', 'Date'
        $defaultDisplayPropertySet = New-Object -TypeName System.Management.Automation.PSPropertySet -ArgumentList (
            'DefaultDisplayPropertySet',[string[]] $defaultDisplaySet
        )
        $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
    }
    
    Process
    {
        # Variables 
        $objRecords = @()
        
        Foreach ($zone in $Domain)
        {
            $objRecords += Get-WmiObject -Credential $Credential -ComputerName $ComputerName `
            -Namespace 'root\MicrosoftDNS' `
            -Query ("select * from MicrosoftDNS_AType where Containername='{0}' AND TimeStamp<{1} AND TimeStamp<>0 " -f $zone, $dtBeginTime)  
        }
   
        # Adding a readable date to each record for ease of use  
        $objRecords | Foreach-Object { 
            
            Add-Member -InputObject $_ -MemberType NoteProperty -Name 'Date' `
            -Value $(([DateTime]'1.1.1601').AddHours($_.Timestamp)) 
            
            Add-Member -InputObject $_ -MemberType MemberSet -Name PSStandardMembers -Value $PSStandardMembers
        } 
        
        $objRecords
    }
    
    End
    {}
}


Function Invoke-DNSManualCleanUp
{
    <#
            .SYNOPSIS
            Clean up a scope when waiting for scavenging takes too long!

            .DESCRIPTION
            Scavenging is not aggressive, and takes forever to get things done... This does not.

            .PARAMETER ComputerName
            DNS server with the zone in it

            .PARAMETER ZoneName
            Domain/Zone name to be cleaned up

            .PARAMETER Age
            How many days since the last timestamp. If older than that, DELETE!

            .PARAMETER Credential
            Credentials for connecting and managing DNS, on the DNS server

            .PARAMETER Force
            You'll be asked to confirm each record deletion. If you don't want to be bothered with checking, use 
            this parameter

            .EXAMPLE
            Invoke-DNSManualCleanUp -ComputerName dc01 -ZoneName contoso.com -Age 90 -Credential $MyCreds -Force
            This will connect to dc01, query the contoso.com DNS zone for records that have not been updated 
            within the last 90 days, and it will delete all returned values without prompting

            .NOTES
            Be careful with this one... DNS is the life blood of your domain/network. This function can ruin your
            day

            .LINK
            https://www.powershellgallery.com/packages/Network

            .INPUTS
            Accepts an array of strings from the pipeline

            .OUTPUTS
            Nothing if all goes well, errors if not...
    #>


    Param
    (
        [Parameter(Mandatory=$true, HelpMessage='Name of computer to manage')]
        [String] $ComputerName,
        
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage='DNS zone to search')]
        [String[]] $ZoneName,
        
        [ValidateSet('HInfo','Afsdb','Atma','Isdn','Key','Mb','Md','Mf','Mg','MInfo','Mr','Mx','NsNxt','Rp','Rt',
                'Wks','X25','A','AAAA','CName','Ptr','Srv','Txt','Wins','WinsR','Ns','Soa','NasP','NasPtr','DName',
                'Gpos','Loc','DhcId','Naptr','RRSig','DnsKey','DS','NSec','NSec3','NSec3Param'
        )]
        [String] $RRType = 'A',
        
        [Int] $Age = 90,
        
        [Parameter(Mandatory=$true, HelpMessage='Credentials for administering DNS')]
        [System.Management.Automation.Credential()]
        [PSCredential] $Credential,
        
        [Switch] $Force
    )
    
    Begin
    {
        # Functions
        Function Script:Where-NotSystem
        {
            Param
            (
                [Object]
                [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Data to filter")]
                $InputObject
            )
            process
            {
                if ($InputObject.TimeStamp -lt $t -And $InputObject.HostName -NotMatch '^gc.|dnszone|\@' -And $InputObject.TimeStamp -ne $null)
                {
                    $InputObject
                }
            }
        }

        # Constants
        $t = ([DateTime]::Now).AddDays(-$Age) 
        $s = New-CimSession -ComputerName $ComputerName -Credential $Credential
        
        If ($Force)
        {
            # We'll need to set the back to the original settings in case the clean up is ran again
            $PSDefaultParameterValuesOrig = $PSDefaultParameterValues
            
            $PSDefaultParameterValues += @{
                'Remove-DnsServerResourceRecord:Force' = $True
            }
        }
    }
    
    Process
    {
        # Variables 
        $records = @()
        
        Foreach ($Zone in $ZoneName)
        {
            $records += Get-DnsServerResourceRecord -ZoneName $Zone -RRType $RRType -CimSession $s | 
            Where-NotSystem
            
            $records | Remove-DnsServerResourceRecord -ZoneName $Zone
        }
    }
    
    End
    {
        Remove-CimSession -CimSession $s -ErrorAction SilentlyContinue 
        
        If ($Force)
        {
            $PSDefaultParameterValues = $PSDefaultParameterValuesOrig
        }
    }
}



### IP Address Functions ####


Function ConvertTo-DottedDecimalIP ( [String] $IP ) 
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


Function Convert-SubnetMaskToCidr
{
    Param
    (
        [IPAddress] $SubnetMask
    )
    
    $retVal = 0
    
    $octets = $SubnetMask.IPAddressToString.Split('.')
    
    foreach($octet in $octets)
    {
        while(0 -ne $octet) 
        {
            $octet = ($octet -shl 1) -band [byte]::MaxValue
            $retVal++
        }
    }
    
    $retVal
}


Function Convert-CidrToDottedSubnetMask
{
    Param
    (
        $CIDR
    )
    
    [IPAddress] $Mask = 0
    
    $Mask.Address = ([UInt32]::MaxValue -1) -shl (32 - $CIDR) -shr (32 - $CIDR)
    
    $Mask
}


Function ConvertTo-DecimalIP ( [String]$IP ) 
{

    $IPAddress = [Net.IPAddress]::Parse($IP)
    $i = 3
    $IPAddress.GetAddressBytes() | %{
    $DecimalIP += $_ * [Math]::Pow(256, $i); $i-- }

    Return [UInt32]$DecimalIP
}


If (Get-Module -ListAvailable -Name NetAdapter, NetTCPIP) 
{
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


### Web Functions ###


Function Get-WebCertificate
{
    <#

            .Synopsis
            Retrieve the details of a website's TLS certificate

            .DESCRIPTION
            Long description

            .EXAMPLE
            Example of how to use this cmdlet

            .EXAMPLE
            Another example of how to use this cmdlet
    #>

    <#
            Version 0.?
            - ???
    #>

    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true,
        Position = 0, HelpMessage = 'Name or IP of system')]
        [String[]] $System,
        
        [int] $Port = 443
    )
    
    Begin
    {
        # Baseline our environment 
        #Invoke-VariableBaseLine

        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
    }
    
    Process
    {
        # Variables
        [int] $intTimeOutMilliseconds = 2500
        $objCerts = @()
        
        
        Foreach ($objSystem in $System) 
        {
            # ensure that workin variables are clean. 
            <#
                    $request = $null 
                    $cert = $null
                    $dtExpiration = $null
                    $certName = $null
                    $intDaysRemaining = $null
            #>
            
            # Must be working with a string name
            If ($objSystem -notmatch 'https://')
            {
                [URI] $objSystem = 'https://{0}' -f $objSystem
            }
                
            Else
            {
                
            }
            
            # attempt to retrieve the server certificate
            $request = $null
            Remove-Variable -Name request -ErrorAction SilentlyContinue
            $request = [Net.HttpWebRequest]::Create($objSystem)
            $request.TimeOut = $intTimeOutMilliseconds
            
            Try
            {
                $request.GetResponse()
            }

            Catch 
            {
                Write-Debug -Message ('Unable to find {0}' -f $objSystem)
            }
            
            If ($request.ServicePoint.Certificate.Subject -ne $null)
            {
                $strCertName = $request.ServicePoint.Certificate.GetName()
                $strCommonName = $strCertName.Split(' ') -Match 'CN=' -replace 'CN='
                [DateTime]$dtExpiration = $request.ServicePoint.Certificate.GetExpirationDateString()
                [int]$intDaysRemaining = ($dtExpiration - $(get-date)).Days
            
                $objBuilder = New-Object -TypeName PSObject 
                $objBuilder | Add-Member -MemberType NoteProperty -Name 'URI' -Value $objSystem
                $objBuilder | Add-Member -MemberType NoteProperty -Name 'Name' -Value $strCertName
                $objBuilder | Add-Member -MemberType NoteProperty -Name 'CommonName' -Value $strCommonName
                $objBuilder | Add-Member -MemberType NoteProperty -Name 'EffectiveDate' -Value $request.ServicePoint.Certificate.GetEffectiveDateString()
                $objBuilder | Add-Member -MemberType NoteProperty -Name 'EndDate' -Value $request.ServicePoint.Certificate.GetExpirationDateString()
                $objBuilder | Add-Member -MemberType NoteProperty -Name 'RemainingDays' -Value $intDaysRemaining
                $objBuilder | Add-Member -MemberType NoteProperty -Name 'SHA1' -Value $request.ServicePoint.Certificate.GetSerialNumberString()
                $objBuilder | Add-Member -MemberType NoteProperty -Name 'KeyAlgorithm' -Value $request.ServicePoint.Certificate.GetKeyAlgorithm()
                $objBuilder | Add-Member -MemberType NoteProperty -Name 'SerialNumber' -Value $request.ServicePoint.Certificate.GetSerialNumberString()
                $objBuilder | Add-Member -MemberType NoteProperty -Name 'Subject' -Value $request.ServicePoint.Certificate.Subject
                $objBuilder | Add-Member -MemberType NoteProperty -Name 'Issuer' -Value $request.ServicePoint.Certificate.GetIssuerName()
                $objBuilder | Add-Member -MemberType NoteProperty -Name 'Handle' -Value $request.ServicePoint.Certificate.Handle
                $objBuilder | Add-Member -MemberType NoteProperty -Name 'Format' -Value $request.ServicePoint.Certificate.GetFormat()
            
                # Append our cert object
                $objCerts += $objBuilder
            }
        }

        # Return the object of certs
        $objCerts
    }
    
    End
    {
        # Clean up the environment
        #Invoke-VariableBaseLine -Clean
    }
}


Function Get-WebSecurityProtocol
{
    [Net.ServicePointManager]::SecurityProtocol
}


Function Set-WebSecurityProtocol
{
    Param
    (
        [Parameter(Mandatory=$true, Position=0, HelpMessage='Select protocols to be enabled')]
        [ValidateSet('SSLv3', 'TLS1.0', 'TLS1.1', 'TLS1.2')]
        [String[]] $Protocols,
        
        [Switch] $Append,
        
        [Switch] $Quiet
    )
    
    # Variables
    $intCounter = 0
    $dictProtocols = @{
        'SSLv3' = 'Ssl3'
        'TLS1.0' = 'Tls'
        'TLS1.1' = 'Tls11'
        'TLS1.2' = 'Tls12'
    }
    
    $currentProtocols = Get-WebSecurityProtocol
    
    Foreach ($protocol in $Protocols)
    {
        If ((!$Append) -and $intCounter -eq 0)
        { 
            $strOperator = '=' 
            $boolSkip = $false
        } 
        
        Else 
        { 
            $strOperator = '+=' 
            
            If ($currentProtocols.ToString().Split(',').Trim() -contains $dictProtocols[$protocol]) 
            { $boolSkip = $true } Else { $boolSkip = $false }
        }
        
        $strCommand = ('[Net.ServicePointManager]::SecurityProtocol {0} [Net.SecurityProtocolType]::{1}' `
        -f $strOperator, $($dictProtocols["$protocol"]))

        If (!$boolSkip)
        {
            Invoke-Expression -Command $strCommand | Out-Null
        }
        
        $intCounter++
    }
    
    If (!$Quiet)
    {
        Get-WebSecurityProtocol
    }
}


Function Import-509Certificate 
{    
    Param
    (
        [Parameter(Mandatory=$true, Position=0, HelpMessage='Full path to certificate file')]
        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
        [ValidateNotNullOrEmpty()]
        [Alias('Path')]
        [String] $FilePath,
        
        # Object type: System.Security.Cryptography.X509Certificates.StoreLocation
        [Parameter(Mandatory=$true, Position=1, HelpMessage='System or user?')]
        [ValidateSet('LocalMachine','CurrentUser')]
        [String] $StoreLocation = 'CurrentUser',
        
        # Object type: System.Security.Cryptography.X509Certificates.StoreName
        [Parameter(Position=2, HelpMessage='Where should we store the certificate')]
        [ValidateSet(
                'AddressBook', 'AuthRoot', 'CertificateAuthority', 'Disallowed', 
        'My', 'Root', 'TrustedPeople', 'TrustedPublisher')]
        [String] $StoreName = 'My',
        
        [Parameter(Mandatory=$false, Position=3, HelpMessage='Password for certificate file')]
        [Alias('Password')]
        [String] $CertificatePassword = $null
    )
    
    # Check if we can continue
    [bool] $isAdmin = Test-AdminRights
    
    If ($isAdmin -eq $false -and $StoreLocation -eq 'LocalMachine')
    {
        # TODO: Use Invoke-Elevate to continue with the import
        Write-Output "`nLocalMachine requires elevation!`n"
        Return
    }
    
    # Variables
    $objFile = Get-Item -Path $FilePath
    [String] $strFileName = $objFile.FullName
    $pfx = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
    $store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store($StoreName,$StoreLocation)
    
    # Import the certificate
    If ($CertificatePassword)
    {
        # Using default flags for now
        $Flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
        
        $pfx.Import($strFileName,$CertificatePassword,$Flags)
    }
    Else
    {
        $pfx.import($strFileName)
    }
    
    # Open the certificate store, add the cert to the store, and close it
    $store.Open("MaxAllowed")
    $store.Add($pfx)
    $store.Close()
}


Function Expand-Uri
{
    Param
    (
        [Parameter(Mandatory=$true, Position=0,
        HelpMessage='Short URL to be expanded')]
        [Alias('URL')]
        [uri] $URI
    )
    
    $retVal = Invoke-WebRequest -UseBasicParsing -Uri $URI -MaximumRedirection 0 -ErrorAction Ignore |
    ForEach-Object {$_.Headers} | ForEach-Object {$_.Location}
    
    $retVal
}


Function Get-Proxy
{
    $ProxySettings = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' `
    -Name DefaultConnectionSettings).DefaultConnectionSettings
        
    If ($ProxySettings[8] -eq 0x01)
    {
        $false
    }
    Else
    {
        $true
    }
}


Function Enable-Proxy
{    
    $ProxySettings = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' `
    -Name DefaultConnectionSettings).DefaultConnectionSettings
    
    If ($ProxySettings[16] -ne '0x00')
    {
        # Appears there may be an auto-config URL
        $ProxySettings[8] = 15 # = 0x0F
    }
    ElseIF ($ProxySettings[24] -ne '0x00')
    {
        # Looks like a manual proxy is set
        $ProxySettings[8] = 13 # = 0x0D
    }
    Else
    {
        # Just enable auto-detect settings (a.k.a WPAD)
        $ProxySettings[8] = 9 # = 0x09
    }
    
    #$regVal = Convert-ByteArrayToHex -ByteArray $ProxySettings
    $regVal = [Byte[]] $ProxySettings
    
    # Enable the proxy setting
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' `
    -Name ProxyEnable -Value 1
    
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' `
    -Name DefaultConnectionSettings -Value ([Byte[]]($regVal))
}


Function Disable-Proxy
{
    Param
    (
        [Switch] $ClearSettings
    )
    
    If ($ClearSettings)
    {
        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' `
        -Name DefaultConnectionSettings `
        -Value (
            [byte[]](
                0x46,0x00,0x00,0x00,0x2E,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x1C,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            )
        )
    }
    Else
    {
        $ProxySettings = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' `
        -Name DefaultConnectionSettings).DefaultConnectionSettings
    
        $ProxySettings[8] = 1
    
        #$regVal = Convert-ByteArrayToHex -ByteArray $ProxySettings
        $regVal = [Byte[]] $ProxySettings
        
        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' `
        -Name DefaultConnectionSettings -Value ([Byte[]]($regVal))
    }
    
    # Disable the proxy setting
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' `
    -Name ProxyEnable -Value 0
}


Function Set-WebCertificatePolicy
{
    Param
    (
        [Switch] $IgnoreInvalidCertificate
    )
    
    Try
    {
        Add-Type -TypeDefinition @'
using System.Net;
using System.Security.Cryptography.X509Certificates;

public class InSecureWebPolicy : ICertificatePolicy 
{
    public bool CheckValidationResult(ServicePoint sPoint, X509Certificate cert,WebRequest wRequest, int certProb)
    {
        return true;
    }
}
'@
    }
    Catch
    {
        Write-Error -Message 'Failed to load the insecure policy'
    }
    
    
    $pol = [System.Net.ServicePointManager]::CertificatePolicy
    
    # Policy reverts after closing your shell, so only process is needed. 
    Invoke-EnvironmentalVariable -Name pol -Scope Process -Value $pol 
    
    If ($IgnoreInvalidCertificate)
    {
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName InSecureWebPolicy
    }
    ElseIf ($pol)
    {
        [System.Net.ServicePointManager]::CertificatePolicy = $pol
    }
    Else
    {
        'You do not seem to have a policy to revert to. Please close, and launch a new shell'
    }
}


Function Test-CertificateAuthorityPlacement
{
    Param
    (
        [Parameter(Position = 0)]
        [ValidateSet('CurrentUser','LocalMachine')]
        [String] $Scope = 'CurrentUser',
        
        [Switch] $Quiet
    )
    
    $badCerts = Get-Childitem Cert:\$Scope\root -Recurse | Where-Object {$_.Issuer -ne $_.Subject}
    
    If ($badCerts)
    {
        'You have miss-placed CAs.'
        
        $badCerts
    }
    Else
    {
        If (!$Quiet)
        {
            Invoke-DebugIt -Console -Force -Message '[INFO]' -Value 'All appears well' -Color 'Green'
        }
    }
}


New-Alias -Name Expand-Url -Value Expand-Uri -ErrorAction SilentlyContinue
New-Alias -Name Add-WebSecurityProtocol -Value Set-WebSecurityProtocol -ErrorAction SilentlyContinue


### Network Functions ###


Function Get-Netstat
{
    # TODO: Needs to be more efficient. Makes a call to get-process for each item. 
    # TODO: Get netstat info from remote computers. Parameter -ComputerName as [String[]]
    # Variables
    $nets = $(netstat -aon).Trim() | 
    Select-Object -Skip 4 | 
    ConvertFrom-String -PropertyNames Protocol,LocalAddress,RemoteAddress,State,PID
        
    $nets = $nets | Where-Object { $_.State -match "ESTABLISHED|LISTENING"} |
    Select-Object -Property Protocol,`
    
    @{ 
        Name = 'LocalAddress' 
        Expression = { 
            if ($_.LocalAddress -notmatch ']') 
            {
                $_.LocalAddress.Split(':')[0] 
            } 
            Else 
            {
                $_.LocalAddress.Split(']')[0].Trim('[')
            }
        }
    }, `
    @{ 
        Name = 'LocalPort' 
        Expression = { 
            if ($_.LocalAddress -match ']') 
            { 
                $_.LocalAddress.Split(']')[1].Trim(':') 
            } 
            Else 
            { 
                $_.LocalAddress.Split(':')[1] 
            }
        }
    }, `
    @{ 
        Name = 'RemoteAddress' 
        Expression = { 
            if ($_.RemoteAddress -notmatch ']') 
            {
                $_.RemoteAddress.Split(':')[0] 
            } 
            Else 
            {
                $_.RemoteAddress.Split(']')[0].Trim('[')
            }
        }
    }, `
    @{ 
        Name = 'RemotePort' 
        Expression = { 
            if ($_.RemoteAddress -match ']') 
            { 
                $_.RemoteAddress.Split(']')[1].Trim(':') 
            } 
            Else 
            { 
                $_.RemoteAddress.Split(':')[1] 
            }
        }
    },`
    State,`
    PID,
    @{ 
        Name = 'Process' 
        Expression = { 
            Get-Process -ID $($_.PID ) | % ProcessName
        }
    }
    
    $nets
}


Function Send-WakeOnLan
{
    <#
            .SYNOPSIS
            Function for waking up computers on the network

            .DESCRIPTION
            This function sends magic packets to wake up a shutdown computer, that has Wake On LAN configured. 

            .PARAMETER broadcastAddress
            The broadcast address is the top IP address in a subnet. e.x. if the IP of the computer you want to wake
            up is 192.168.1.100 with a subnet mask of 255.255.255.0, the broadcast address would be 192.168.1.255

            This parameter is not the IP of the destination computer. 

            .PARAMETER macAddress
            This would be the physical address of the computer you wish to wake up. e.x. 00-01-de-ad-b3-ef

            .PARAMETER JumpServer
            If you need to wake a computer on a network other than your own, and the network does not allow directed-
            broadcast, you can wake up a computer on the routed network, via another computer on that same network. 

            .PARAMETER Credential
            This would be the credential uses to connect/execute commands on the jump server. 

            .EXAMPLE
            Send-WakeOnLan -BroadcastAddress 192.168.1.255 -MacAddress 00-01-de-ad-b3-ef -JumpServer Computer01 -Credential $creds
            This will connect to Computer02, and run the wake on LAN command from there. It will attempt to wake
            up the system with MAC address 00-01-de-ad-b3-ef on the same network


            .EXAMPLE
            Get-Content -Path .\list_of_macs.txt | Send-WakeOnLan -BroadcastAddress 192.168.1.255
            This will process each mac, and attempt to wake them all up. 

            .EXAMPLE
            Send-WakeOnLan -BroadcastAddress 192.168.1.255 -MacAddress 00-01-de-ad-b3-ef
            This will attempt to wake up a system with MAC address 00-01-de-ad-b3-ef

            .EXAMPLE
            '00-01-de-ad-b3-ef' | Send-WakeOnLan -BroadcastAddress 192.168.1.255
            Wake up a single machine. Pipeline the MAC address only. 

            .EXAMPLE
            # Build a holder for hosts
            $objOfHolding = @()

            $objBuilder = New-Object PSObject
            $objBuilder | Add-Member -MemberType NoteProperty -Name 'BroadcastAddress' -Value '192.168.1.255'
            $objBuilder | Add-Member -MemberType NoteProperty -Name 'MacAddress' -Value '00-01-de-ad-b3-ef'
            $objBuilder | Add-Member -MemberType NoteProperty -Name 'JumpServer' -Value 'Server01'

            # Place in the holding object
            $objOfHolding += $objBuilder

            # Adding the next host
            rv objBuilder
            $objBuilder = New-Object psobject
            $objBuilder | Add-Member -MemberType NoteProperty -Name 'BroadcastAddress' -Value '172.30.1.255'
            $objBuilder | Add-Member -MemberType NoteProperty -Name 'MacAddress' -Value 'be-3f-02-03-de-ad'

            # This object is on my local network, so I don't need a jump server. We will set this to null
            $objBuilder | Add-Member -MemberType NoteProperty -Name 'JumpServer' -Value $null


            # Place in the holding object
            $objOfHolding += $objBuilder

            # We now have a CSV that we'll maintain will all systems, from all locations. 
            $objOfHolding | Export-Csv -Path '.\All_My_Systems.csv'  -NoTypeInformation -Encoding ASCII

            # When all systems need to be woke up...

            # Import our list of maintained systems. 
            $csvFile = Import-Csv -Path '.\All_My_Systems.csv' -Encoding ASCII

            # Now pipe the object to the wake up function
            $csvFile | Send-WakeOnLan -Credential


            This will wake multiple machines defined in a CSV file. 


            .NOTES
            Scalable WOL, without needing to make changes to your network. No "ip directed-broadcast" necessary :)

            .LINK
            N/A

            .INPUTS
            Accepts string input of MAC address from the pipeline. Will also accept an array object with MAC 
            address, broadcast address, and jump server defined. 

            .OUTPUTS
            Void
    #>


    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, 
        ValueFromPipelineByPropertyName = $true)] 
        [ValidateNotNullorEmpty()] 
        [ValidateScript({$_ -like '*-*-*-*-*-*'})] 
        [Alias('ma')]
        [String] $MacAddress,
        
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)] 
        [ValidateNotNullorEmpty()]
        [Alias('bc')]
        [IPAddress] $BroadcastAddress,
        
        [Parameter(Position = 2, ValueFromPipelineByPropertyName = $true)] 
        [Alias('js')]
        [String] $JumpServer,
            
        [System.Management.Automation.Credential()]
        [PSCredential] $Credential
    )
    
    Process
    {
        Write-Verbose -Message $BroadCastAddress
        Write-Verbose -Message $MacAddress
        
        [ScriptBlock] $sbShaker = {
            
            Param
            (
                $BroadCastAddress,
                $MacAddress
            )

            Try 
            {
                [void][System.Reflection.Assembly]::LoadWithPartialName('System.Net')
                
                [void][System.Reflection.Assembly]::LoadWithPartialName('System.Net.Sockets')

                $NetUdpClient = New-Object System.Net.Sockets.UdpClient
                $NetIpEndPoint = New-Object System.Net.IPEndPoint $([IPAddress]::Parse($BroadCastAddress)),10000
            } 
            Catch 
            { 
                Throw
            }
           

            If ($NetUdpClient -and $NetIpEndPoint) 
            {
                Try
                {
                    [byte[]]$macBytes = $MacAddress.Split('-') | ForEach-Object { [byte]('0x{0}' -f $_) }
                    [byte[]]$bytes = New-Object -TypeName 'byte[]' -ArgumentList $(6 + 16 * $($macBytes.length))

                    for ($i = 0; $i -lt 6; $i++) 
                    { 
                        $bytes[$i] = [byte] 0xff 
                    }

                    for ($i = 6; $i -lt $bytes.length; $i += $macBytes.length) 
                    {
                        for($j = 0; $j -lt $macBytes.length; $j++) 
                        { 
                            $bytes[$i + $j] = $macBytes[$j] 
                        } 
                    }

                    $NetUdpClient.Connect($NetIpEndPoint)

                    [void]$NetUdpClient.Send($bytes, $bytes.length)

                    $NetUdpClient.Close()
                } 
                Catch 
                { 
                    Throw 
                }
            }
        }
    
        
        If ($JumpServer)
        {
            If ($Credential)
            {
                Invoke-Command -ComputerName $JumpServer -Credential $Credential -Authentication Kerberos `
                -ScriptBlock $sbShaker -ArgumentList $broadcastAddress,$macAddress -AsJob | Out-Null
            }
            Else
            {
                Invoke-Command -ComputerName $JumpServer -ScriptBlock $sbShaker `
                -ArgumentList $broadcastAddress,$macAddress -AsJob | Out-Null
            }
        }        
        Else
        {
            $sbShaker.Invoke( $broadcastAddress, $macAddress )
        }
    }
}


#endregion
