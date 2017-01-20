# Advanced function with example parameters.

Function Verb-Noun
{
    <#
            .Synopsis
            Short description
	   
            .DESCRIPTION
            Long description
	   
            .EXAMPLE
            Example of how to use this function
	   
            .EXAMPLE
            Another example of how to use this function
    #>

    <#
            Version 0.?
            - ? MACD. Move, add, change, or delete details go here. ?
    #>

    [CmdLetBinding()]
    [CmdletBinding(DefaultParameterSetName='Command')]
    Param
    (
        [ValidateScript({ Test-Connection -ComputerName $_ -Quiet -Count 4 }) ]
        [String] $ComputerName,
        
        [ValidateScript({ Split-Path $_ -Parent | Test-Path })]
        [String] $Path,
        
        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
        [ValidatePattern('\.txt$')]
        [ValidateNotNullOrEmpty()]
        [String] $txtFilePath,
        
        # ScriptBlock: Negates the need for Command
        [Parameter(Mandatory=$false,ParameterSetName="Command")]
        [Parameter(Mandatory=$true, Position=0,ParameterSetName='ScriptBlock',                
                HelpMessage='Scriptblock of commands to be executed')]
        [Alias('sb')]
        [ScriptBlock] $ScriptBlock,
        
        # Command: Negates the need for ScriptBlock
        [Parameter(Mandatory=$false, ParameterSetName='ScriptBlock')]
        [Parameter(Mandatory=$true, Position=0, ParameterSetName='Command',
                HelpMessage='Commands to be executed')]
        [Alias('cmd')]
        [String] $Command,
        
        [ValidatePattern('\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b')]
        [Parameter(Mandatory=$true)]
        
        [Parameter(Mandatory=$true, Position=1,
            HelpMessage='Select the type of output you require.')]
        [ValidateSet('Excel','CSV','Screen','GridView')]
        [String] $OutputType 
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

    }
    
    End
    {
        # Clean up the environment
        Invoke-VariableBaseLine -Clean
    }
}
