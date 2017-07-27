#requires -Version 3.0

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

        Version 0.2
        - Function (WEB) Added : Get-WebCertificate
        - Function (DNS) Changed : Added progress to the Get-DnsDebugLog 

        Version 0.3
        - Function (WEB) added : Get-WebSecurityProtocol
        - Function (WEB) added : Set-WebSecurityProtocol 
        - Function (WEB) added : Import-509Certificate

        Version 0.4
        - Function (DNS) added : Get-HostsFile : Pretty self explainatory
        - Function (DNS) added : Add-HostsFileEntry : Offers elevation if not running as admin
        - Function (DNS) added : Remove-HostsFileEntry : Elevation offered. Only IP arg for now. 
#>

#endregion


#region Prerequisites

# All modules require the core
If (!(Get-Module -Name core))
{
    Try
    {
        Import-Module -Name 'core' -ErrorAction Stop
    }

    Catch
    {
        Try
        {
            $uriCoreModule = 'https://raw.githubusercontent.com/masters274/Posh_Repo/master/Modules/Core/core.psm1'
    
            $moduleCode = (Invoke-WebRequest -Uri $uriCoreModule -UseBasicParsing).Content
            
            Invoke-Expression -Command $moduleCode
        }
    
        Catch
        {
            Write-Error -Message ('Failed to load {0}, due to missing core module' -f $PSScriptRoot)
        }
    }
}

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
        Invoke-VariableBaseLine

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
        Invoke-VariableBaseLine -Clean
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
            
            If ($currentProtocols -match $dictProtocols[$protocol]) 
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


#endregion
