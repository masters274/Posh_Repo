<#
        .Synopsis
        Short description

        .DESCRIPTION
        Long description
        
        .NOTES
        General notes
        
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


Function Get-InstalledSoftware
{
    <#
            .Synopsis
            Get installed software on the local or remote computer, safely. 

            .DESCRIPTION
            Uses the uninstall path to capture installed software. This is safer than using the WMI query, which
            checks the integrity upon query, and can often reconfigure, or reset application defaults. 

            .EXAMPLE
            $progs = Get-InstalledPrograms

            .EXAMPLE
            Get-InstalledPrograms |Select-Object -Property DisplayName, Publisher, InstallDate, Version |FT -Auto
    #>

    <#
            Version 0.1
            - Day one
    #>

    [CmdLetBinding()]
    Param
    (
        [ValidateScript({ Test-Connection -ComputerName $_ -Quiet -Count 4 }) ]
        [String] $ComputerName,
        
        [PSCredential] $Credential
    )
    
    Begin
    {
        # Baseline our environment 
        Invoke-VariableBaseLine

        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
        
        # List of required modules for this function
        $arrayModulesNeeded = (
            'Core'
        )
        
        # Verify and load required modules
        Test-ModuleLoaded -RequiredModules $arrayModulesNeeded -Quiet
    }
    
    Process
    {
        # Variables
        [String] $strScriptBlock = 'Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
        Invoke-DebugIt -Console -Message 'ScriptBlock' -Value $strScriptBlock
    
        IF ($ComputerName)
        {
            Invoke-DebugIt -Console -Message 'Computer name is present' -Value $ComputerName
            
            $strScriptBlock = '{' + $strScriptBlock + '}'
            Invoke-DebugIt -Console -Message 'Scriptblock modified' -Value $strScriptBlock
            
            [String] $strCommand = 'Invoke-Command -ComputerName {0} -Command {1} -Authentication Kerberos' -f $ComputerName,$strScriptBlock
            Invoke-DebugIt -Console -Message 'String command' -Value $strCommand
        
            IF ($Credential) 
            { 
                Invoke-DebugIt -Console -Message 'Credential is present' -Value $($Credential.UserName)
                
                $strCommand = $strCommand + ' -Credential $Credential' 
                Invoke-DebugIt -Console -Message 'String command' -Value $strCommand
            }
        }
    
        Else
        {
            Invoke-DebugIt -Console -Value 'Local machine query' -Color 'Blue'
            
            $strCommand = $strScriptBlock
            Invoke-DebugIt -Console -Message 'String command' -Value $strCommand
        }
    
        $arrayPrograms = Invoke-Expression -Command $strCommand
    
        $arrayPrograms
    }
    
    End
    {
        # Clean up the environment
        Invoke-VariableBaseLine -Clean
    }
}


#endregion