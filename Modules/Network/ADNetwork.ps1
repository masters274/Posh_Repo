<#
        .Synopsis
        Various functions for getting network info from AD

        .DESCRIPTION
        Various functions for getting network info from AD
        
        .NOTES
        Not much to say here... pretty straight forward. Just filling the gaps
        
        .COMPONENT
        Acitve Directory Network management
        
        .ROLE
        Acitve Directory Specific Network management
        
        .FUNCTIONALITY
        Not much to say here... pretty straight forward. Just filling the gaps
#>


#region Functions



Function Get-AdAuthorizedDhcpServer
{
    <#
            .Synopsis
            Get a list of authorized DHCP servers from Active Directory

            .DESCRIPTION
            Lists authorized DHCP servers, and is also helpful with finding remnants of old servers still 
            authorized, but do not exist via the "Warning" output.

            .EXAMPLE
            Get-AdAuthorizedDhcpServer
            This uses your default name, and returns a list of AD objects

            .EXAMPLE
            Get-AdAuthorizedDhcpServer -Domain child.domain.local
            Gets the DHCP servers from the child domain
    #>



    [CmdLetBinding()]
    Param
    (
        [Parameter(ValueFromPipeline = $true, Position = 0)] 
        [ValidateScript({$_ -like '*.*'})]
        [Alias('DNSRoot')]
        [String] $Domain
    )
    
    Begin
    {
        If (!$Domain)
        {
            Try
            {
                $Domain = (Get-ADDomain).DNSRoot
            }
            Catch
            {
                Throw
            }
        }
        
        Write-Verbose -Message $Domain
    }
    
    Process
    {
        # Variables
        [String] $strFilter = "objectclass -eq 'dhcpclass' -AND Name -ne 'dhcproot'"
        [String] $strSearchBase = 'cn=configuration'
        $goodServers = @() # Servers in config, that no longer exist
        
        
        Foreach ($dc in $Domain.Split('.'))
        {
            $strSearchBase += ',dc={0}' -f $dc 
        }
        
        Write-Verbose -Message $strSearchBase
        
        $objDhcpServers = Get-ADObject -SearchBase $strSearchBase -Filter "$strFilter" -Properties * -Server $Domain
        
        Foreach ($server in $objDhcpServers)
        {
            Write-Verbose -Message $server.Name 
            
            Try
            {
                [String] $id = $server.Name.Replace(".$Domain",'')
                $null = Get-ADComputer -Identity $id
                $goodServers += $server
            }
            Catch
            {
                #$objDhcpServers.Remove(($objDhcpServers | ? {$_.Name -eq $server.Name}))
                
                Write-Warning -Message ('{0} exists in config, but not an AD computer' -f $server.Name) 
                
                Continue
            }
        }
        
        $goodServers
    }
    
    End
    {
    
    }
}


#endregion