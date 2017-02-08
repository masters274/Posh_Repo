<#
        .Synopsis
        Module that extends core functionality in powershell. 

        .DESCRIPTION
        Module with various generic functions that could be used in any script
        
        .NOTES
        Code reuse saves time!
        
        .COMPONENT
        Core
        
        .ROLE
        Fill gaps in general use
        
        .FUNCTIONALITY
        General Powershell functionality extension

        .AUTHOR
        Chris Masters - https://github.com/masters274
#>

<#
        Version 0.3
        - Code folding regions added for better navigation and visibility
        - Function (SECURITY) added : Test-AdminRights
        - Function (SECURITY) added : Start-ImpersonateUser
        - Function (SECURITY) added : Get-LoggedOnUser
        - Function (SECURITY) added : Invoke-Elevate
        - Function (FILESYSTEM) added : Open-Notepad++
        - Multiple aliases added for functions
        - EventLogging added to Invoke-DebugIt function

        Version 0.4
        - Function (SECURITY) updated : Invoke-Elevate, "sudo $$" or "sudo $^" now works, similar to "sudo !!"
        - Function (DEVELOPMENT) updated : Fixed scope issues with Invoke-VariableBaseLine
        - Function (DEVELOPMENT) updated : $boolDebug must be set for -Debug to be recognized in other functions.

        Version 0.5
        - Function (FILESYSTEM) updated : As cool as it was, renamed Open-Notepad++ to Open-NotepadPlusPlus :(
        - Function (FILESYSTEM) added : New alias created for Invoke-Touch = touch
        - Function (SECURITY) added : Invoke-CredentailManager, with aliases
        - Function (LOG/ALERT) updated : Removed the $boolDebug declaration from this function. This will be
        set by the calling function, when -Debug is used. 
        - Function (DEVELOPMENT) updated : Now allows you to add the file path to a module not in the default path.
        
        Version 0.6
        - Function (DEVELOPMENT) added : Invoke-EnvrionmentalVariable
        - Function (DEVELOPMENT) added : Invoke-Alert with alias (alert). Audible tone for when you want to
        monitor the availability of something while doing some other work. 
        - Function (SECURITY) updated : Parameter alias on Invoke-CredentialManager for backward compatibility
        - Function (DEVELOPMENT) added : ConvertTo-Hexadecimal
        - Function (DEVELOPMENT) added : ConvertFrom-HexToFile. Great way for working with binary files.
        - Function (DEVELOPMENT) added : ConvertTo-Base36
        - Function (DEVELOPMENT) added : ConvertFrom-Base36
        - Function (DEVELOPMENT) added : ConvertTo-Base64
        - Function (DEVELOPMENT) added : ConvertFrom-Base64

        Version 0.7
        - Function (FILESYSTEM) added : New-SymLink
        - Function (FILESYSTEM) added : Remove-SymLink
        - Function (DEVELOPMENT) updated : Add-Signature. Removed aliases used inside the function.
        - Module header information added. 
        - Function (LOG/ALERT) moved : Moved Invoke-Alert to Log/Alert region.
        - Custom Type : added : MkLink type added. This is needed by several functions.
        - Function (SECURITY) : updated : Invoke-Elevate : Removed variable baseline function call. This function 
        is typically used in conjunction with other functions, which may be using the baseline functionality. 
#>


#region Custom Shared Types 

$sbMkLinkType = {
    <#
            lpSymlinkFileName = [String] Path/name where you wan the link to be placed
            lpTargetFileName = [String] File or folder path you want linked to
            dwFlags = [int] 0 for file, and 1 for directory. Use logic to figure this out instead of asking
    #>
    
    $typDef = @'
        using System;
        using System.Runtime.InteropServices;
  
        namespace mklink
        {
            public class symlink
            {
                [DllImport("kernel32.dll", EntryPoint="CreateSymbolicLink")]
                public static extern bool CreateSymbolicLink(string lpSymlinkFileName, string lpTargetFileName, int dwFlags);
                
                [DllImport("kernel32.dll", EntryPoint="CreateHardLink")]
                public static extern bool CreateHardLink(string lpSymlinkFileName, string lpTargetFileName, IntPtr lpSecurityAttributes);
            }
        }
'@
    Try 
    {
        $null = [mklink.symlink]
    } 
        
    Catch 
    {
        Add-Type -TypeDefinition $typDef
    }
}


& $sbMkLinkType

#endregion


#region : DEVELOPMENT FUNCTIONS 


Function Test-ModuleLoaded 
{
    <#
            .SYNOPSIS
            Checks that all required modules are loaded.

            .DESCRIPTION
            Receives an array of strings, which should be the module names. 
            The function then checks that these are loaded. If the required
            modules are not loaded, the function will try to load them by name
            via the default module path. Function returns a failure if it's
            unable to load any of the required modules.

            .PARAMETER RequiredModules
            Parameter should be a string or array of strings.

            .PARAMETER Quiet
            Avoids output to the screen.

            .EXAMPLE
            Test-ModuleLoaded -RequiredModules "ActiveDirectory"
            Verifies that the ActiveDirectory module is loaded. If not, it will attempt to load it.
            if this fails, a $false will be returned, otherwise, a $true will be returned. 
            
            $arrayModules = ('ActiveDirectory','MyCustomModule')
            $result = Test-ModuleLoaded -RequiredModules $arrayModules

            Checks if the two modules are loaded, or loadable, if so, $result will contain a value of
            $true, otherwise it will contain the value of $false.

            .NOTES
            None yet.

            .LINK
            https://github.com/masters274/

            .INPUTS
            Requires at the very least, a string name of a module.

            .OUTPUTS
            Returns success or failure code ($true | $false), depending on if required modules are loaded.
    #>
    [CmdletBinding()]
    Param 
    (
        [Parameter(Mandatory=$true,HelpMessage='String array of module names')]
        [String[]]$RequiredModules,
        [Switch]$Quiet
    ) 

    
    Process 
    {
        # Variables
        $boolDebug = $PSBoundParameters.Debug.IsPresent
        $loadedModules = Get-Module
        $availableModules = Get-Module -ListAvailable
        [int]$failedModules = 0
        [System.Collections.ArrayList]$missingModules = @()
        $arraryRequiredModules = $RequiredModules
        
        # Loop thru all module requirements
        Foreach ($module in $arraryRequiredModules) 
        {
            Invoke-DebugIt -Message 'Module' -Value $module -Console
            
            IF ($loadedModules.Name -contains $module) 
            {
                $true | Out-Null 
            } 
            
            ElseIF (($availableModules.Name -ccontains $module) -or ($null = Test-Path -Path $module)) 
            {
                Import-Module -Name $module
            }
            
            Else 
            {
                Invoke-DebugIt -Message 'Missing module' -Value $module -Console
                
                $missingModules.Add($module)
                $failedModules++
            }
        }
        
        # Return the boolean value for success for failure
        if ($failedModules -gt 0) 
        {
            Write-Error -Message 'Failed to load required modules'
        } 
        
        else 
        {
            IF (!($Quiet))
            {
                return $true
            }
        }
    }
}


Function Invoke-VariableBaseLine 
{
    <#
            .SYNOPSIS
            A function used to keep your environment clean.

            .DESCRIPTION
            This function, when used at the beginning of a script or major setup of functions, will snapshot
            the variables within the local scope. when ran for the second time with the -Clean parameter, usually
            at the end of a script, will remove all the variables created during the script run. This is helpful
            when working in ISE and you need to run your script multiple times while building. You don't want 
            prexisting data to end up in the second run. Also when you have an infinite loop script that you need
            the environment clean after each call to something. 

            .PARAMETER Clean
            The name says it all...

            .EXAMPLE
            Invoke-VarBaseLine -Clean
            This will clean up all the variables created between the start and finish callse of this function

            .NOTES
            This ain't rocket surgery :-\

            .LINK
            https://github.com/masters274/

            .INPUTS
            N/A.

            .OUTPUTS
            Void.
    #>


    
    [CmdletBinding()]
    Param 
    (
        [Switch]$Clean
    )
    
    Begin 
    {
        if ($Clean -and -not $baselineLocalVariables) 
        {
            Write-Error -Message 'No baseline variable is set to revert to.'
        }
    }
    
    Process 
    {
        # logger -Console -Force -Value $(($MyInvocation.Line).split(' ')[1]).Trim() 
        
        if ($Clean) 
        {
            Compare-Object -ReferenceObject $($baselineLocalVariables.Name) -DifferenceObject `
            $((Get-Variable -Scope 0).Name) |
            Where-Object { $_.SideIndicator -eq '=>'} |
            ForEach-Object { 
                Remove-Variable -Name ('{0}' -f $_.InputObject) -ErrorAction SilentlyContinue
            }
        }
        
        else 
        {
            $Global:baselineLocalVariables = Get-Variable -Scope Local
        }
    }
    
    End 
    {
        if ($Clean) 
        {
            Remove-Variable -Name baselineLocalVariables -Scope Global -ErrorAction SilentlyContinue
        }
    }
}


Function Add-Signature 
{
    # Signs a file using the first code signing cert in your personal store
    # ./makecert -n "PowerShell Local CertificateRoot" -a sha1 -eku 1.3.6.1.5.5.7.3.3 -r -sv root.pvk root.cer -ss Root -sr localMachine 
    # ./makecert -n "PowerShell tux" -ss MY -a sha1 -eku 1.3.6.1.5.5.7.3.3 -iv root.pvk -ic root.cer
    
    Param
    (
        [string] $File=$(throw "Please specify a filename.")
    )
    
    # $cert = @(Get-ChildItem cert:\CurrentUser\My | where-object { $_.FriendlyName -eq "MyCodeSigningCert" }) #[0] #-codesigning)[0]
    $cert=(Get-ChildItem Cert:currentuser\my\ -CodeSigningCert |
    Select-Object -First 1)

    # check if the file is a PowerShell file, if not, fix it... 
    $srtExt = ( Get-ChildItem -Path $File | 
    ForEach-Object { $_.Extension } )

    IF ($srtExt -ne '.ps1') 
    {   # we want to be able to sign any file that we can write to... 

        # rename the file
        Get-ChildItem -Path $File | Rename-Item -NewName { $_.Name -replace "$srtExt$" ,".ps1" }
        
        # get the temporary file name
        $strTempName = [io.path]::ChangeExtension($File,"ps1")
        
        # sign the file with the new name
        Set-AuthenticodeSignature $strTempName $cert
        
        # change the file name back to the original
        Get-ChildItem -Path $strTempName | Rename-Item -NewName { $_.Name -replace ".ps1$" ,"$srtExt" }
    } 
    
    Else 
    {
        # just sign the file... 
        Set-AuthenticodeSignature $File $cert
    }
}


Function Invoke-EnvironmentalVariable
{
    <#
            .Synopsis
            Short description

            .DESCRIPTION
            Long description

            .EXAMPLE
            Example of how to use this cmdlet

            .EXAMPLE
            Another example of how to use this cmdlet
    #>

    <#
            Version 0.1
            - Day one, it's my berphday!
    #>

    [CmdLetBinding()]
    [CmdletBinding(DefaultParameterSetName='Get')]
    Param
    (
        [Parameter(Mandatory=$true, Position=0,                
        HelpMessage='Name of the variable')]
        [String] $Name,
        
        [Parameter(Position=1,
        HelpMessage='Value of the variable')]
        $Value,
        
        [Parameter(Mandatory=$false, Position=2,
        HelpMessage='Select the scope you require.')]
        [ValidateSet('Machine','User','Process')]
        [String]$Scope = 'User',
        
        [ValidateSet('Get','Set','Remove')]
        [String]$Action = 'Get'
    )
    
    Begin
    {
        # Baseline our environment 
        Invoke-VariableBaseLine

        # Debugging for scripts
        [Bool] $boolDebug = $PSBoundParameters.Debug.IsPresent
    }
    
    Process
    {
        # Variables
        [String] $strCommand = '[Environment]::GetEnvironmentVariable($Name,$Scope)'
        [String] $strFunctionCalledName = $MyInvocation.InvocationName
        [Bool] $boolIsAdmin = Test-AdminRights
    
        Invoke-DebugIt -Message 'Command text' -Value $strCommand -Console
        Invoke-DebugIt -Message 'Function called name' -Value $strFunctionCalledName -Console
        Invoke-DebugIt -Message 'Admin?' -Value $boolIsAdmin -Console
        Invoke-DebugIt -Message 'first item in command pipe' -Value $MyInvocation.InvocationName -Console
        
        IF ($Action -eq 'Set' -or `
            $strFunctionCalledName -eq 'Set-EnvVar' -or `
        $strFunctionCalledName -eq 'Set-EnvironmentalVariable')
        {
            IF ($Value)
            {
                [String] $strCommand = '[Environment]::SetEnvironmentVariable($Name,$Value,$Scope)'
            }
            
            Else
            {
                Write-Error -Message '{0} : Value is required when using "Set"' -f $strFunctionCalledName
                Return
            }
        }
        
        ElseIF ($Action -eq 'Remove' -or $strFunctionCalledName -match 'Remove-Env')
        {
            [String] $strCommand = ''
        }
        
        IF ($boolIsAdmin -or ($Scope -eq 'User' -or $Scope -eq 'Process' -or $Action -eq 'Get'))
        {
            Invoke-Expression -Command $strCommand
        }
            
        Else
        {
            Invoke-Elevate -Command $strCommand
        }
    }
    
    End
    {
        # Clean up the environment
        Invoke-VariableBaseLine -Clean
    }
}


Function ConvertTo-Hexadecimal 
{ 
    Param
    (
        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
        [String] $FilePath
    )
    
    # Converts a file to hexadecimal string. 
    
    [byte[]] $hex = Get-Content -Encoding byte -Path $FilePath # C:\path\to\file.exe
    # [System.IO.File]::WriteAllLines(".\hexdump.txt", ([string]$hex)) # Ouput HEX to file
	
    [String] $hex
}


Function ConvertFrom-HexToFile 
{ # Converts hexadecimal string to file. 
    # PS > [byte[]] $hex = gc -encoding byte -path C:\path\to\file.exe
    # PS > [System.IO.File]::WriteAllLines(".\hexdump.txt", ([string]$hex))
    
    Param
    (
        [String]$HexString, 
        
        [ValidateScript({ Split-Path $_ -Parent | Test-Path })]
        [String] $FilePath
    )
    
    # Variables
    $strfilename = $FilePath | Split-Path -Leaf
    
    Try 
    {
        $objDirectory = gci ($FilePath | Split-Path -Parent)
    
        $strDirectory = $objDirectory[0].Parent.FullName
    }
    
    Catch
    {
        $strDirectory = $pwd.Path 
    } 
    
    $file = "$strDirectory\$strfilename"

    [Byte[]] $strTemp = $HexString -Split ' '
    
    [System.IO.File]::WriteAllBytes($file, $strTemp) # NOTE: MUST BE FULL FILE PATH!
}


Function ConvertFrom-Base36 
{
    Param 
    (
        [Parameter(valuefrompipeline=$true, 
        HelpMessage='Alphadecimal string to convert')]
        [string] $Base36Num = ''
    )
    
    $alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    $inputarray = $base36Num.tolower().tochararray()
    [array]::reverse($inputarray)
    [long]$decNum=0
    $pos=0

    foreach ($c in $inputarray) {
        $decNum += $alphabet.IndexOf($c) * [long][Math]::Pow(36, $pos)
        $pos++
    }
    $decNum
}


Function ConvertTo-Base36 
{
    Param 
    (
        [Parameter(valuefrompipeline=$true, 
        HelpMessage='Integer number to convert')]
        [int] $DecNum = ''
    )
    
    $alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    Do {
        $remainder = ($DecNum % 36)
        $char = $alphabet.substring($remainder,1)
        $base36Num = "$char$base36Num"
        $DecNum = ($DecNum - $remainder) / 36
    }
    
    While ($DecNum -gt 0)

    $base36Num
}


Function ConvertFrom-Base64 
{
    Param
    (
        [String] $InputString
    )
    
    $bytes  = [System.Convert]::FromBase64String($InputString)
    $decoded = [System.Text.Encoding]::UTF8.GetString($bytes)

    $decoded
}


Function ConvertTo-Base64 
{
    Param
    (
        [String] $InputString
    )
    $bytes  = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    $encoded = [System.Convert]::ToBase64String($bytes)

    $encoded
}


New-Alias -Name Add-Sig -Value Add-Signature -ErrorAction SilentlyContinue
New-Alias -Name sign -Value Add-Signature -ErrorAction SilentlyContinue
New-Alias -Name Set-EnvVar -Value Invoke-EnvironmentalVariable -ErrorAction SilentlyContinue
New-Alias -Name Get-EnvVar -Value Invoke-EnvironmentalVariable -ErrorAction SilentlyContinue
New-Alias -Name Set-EnvironmentalVariable -Value Invoke-EnvironmentalVariable -ErrorAction SilentlyContinue
New-Alias -Name Get-EnvironmentalVariable -Value Invoke-EnvironmentalVariable -ErrorAction SilentlyContinue

#endregion


#region : FILE SYSTEM FUNCTIONS 


Function Invoke-Touch
{
    Param
    (
        [Parameter(Mandatory=$true,Position=1,HelpMessage='File path')]
        [String]$Path,
        
        [Switch]$Quiet
    )
    
    Begin
    {

    }
	
    Process
    {
        $strPath = $Path

        # See if we can figure out if asking for file or directory
        if ("$($strPath -replace '^\.')" -like '*.*') 
        { 
            $strType = 'File'
        } 
        
        Else 
        { 
            $strType = 'Directory'
        }

        if ((Test-Path "$strPath") -eq $true) 
        {
            If ("$strType" -match 'File') 
            {
                (Get-ChildItem $strPath).LastWriteTime = Get-Date
            } 
        }
    
        Else 
        {
            If ($Quiet)
            {
                $null = New-Item -Force -ItemType $strType -Path "$strPath"
            }
            
            Else 
            {
                New-Item -Force -ItemType $strType -Path "$strPath"
            }
        }
        
    }
    
    End
    {
        
    }
}


Function Open-NotepadPlusPlus
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [Alias('Path','FN')]
        [String[]]$FileName
    )
    
    Process
    {
        [String] $strProgramPath = "${env:ProgramFiles(x86)}\Notepad++\notepad++.exe"
        IF (Test-Path -Path $strProgramPath)
        {
            & $strProgramPath $FileName
        }
        
        Else
        {
            Write-Error -Message 'It appears that you do not have Notepad++ installed on this machine'
        }
    }
}


Function New-SymLink
{
    <#
            .Synopsis
            Creates symbolic links

            .DESCRIPTION
            This provides similar functionality to *nix ln command

            .EXAMPLE
            New-SymLnk -Link .\MyNewShortCut -Target '\\DataShareServer\MyShare'

            .EXAMPLE
            ln .\shortcut ..\FileIcantLiveWithOut.txt

            .NOTES
            This function requires elevation
    #>

    <#
            Version 0.2
            - Using DLL Import instead of calls to mklink.exe
    #>

    [CmdLetBinding()]
    Param
    (
        [Parameter(Position = 0)]
        [ValidateScript({ Split-Path $_ -Parent | Test-Path })]
        [String] $Link,
        
        [Parameter(Position = 1)]
        [ValidateScript({ Test-Path $_ })]
        [String] $Target
    )
    
    Begin
    {
        # Baseline our environment 
        Invoke-VariableBaseLine
        
        # Stop on error action
        $ErrorActionPreference = 'Stop'

        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
        
        # Check if this is an elevated prompt
        [bool] $boolIsAdmin = $(Test-AdminRights)
        
        # Check that our DLL import exists
        Try
        {
            $null = [mklink.symlink]
        }
        
        Catch
        {
            Write-Error -Message '[mklink.symlink] type not loaded' 
        }
        
        # Check if the link/file already exists.
        IF (Test-Path -Path $Link)
        {
            Write-Error -Message ('{0} already exists!' -f $Link)
        }
    }
    
    Process
    {
    
        <# 
                If (Test-Path -PathType Container $Target)
                {
                $strCommand = "cmd /c mklink /d"
                }
    
                Else
                {
                $strCommand = "cmd /c mklink"
                }
                Invoke-Expression -Command ('{0} {1} {2}' -f $strCommand, $Link, $Target)
        #>
        
        # Variables 
        $boolResult = $null
        
        $linkPath = Get-item -Path $(Split-Path -Path "$Link" -Parent)
        IF ($linkPath -eq $null) { $linkPath = $PWD.Path + '\' + ($Link |Split-Path -Leaf) } 
        Else {$linkPath = $linkPath.FullName + '\' + $($link | Split-Path -Leaf) }
        
        $TargetPath = "$((Get-Item -Path $Target).FullName)"
        
        If (Test-Path -PathType Container $Target)
        {
            [int] $dwFlag = 1
            
            [String] $dwType = 'Directory'
        }
    
        Else
        {
            [int] $dwFlag = 0
            
            [String] $dwType = 'File'
        }
        
        Invoke-DebugIt -Console -Message 'DW Type' -Value "$dwType"
        
        $strCommand = '$boolResult = [mklink.symlink]::CreateSymbolicLink("{0}","{1}",{2})' -f $linkPath,$TargetPath,$dwFlag
        
        IF ($boolIsAdmin)
        {
            Invoke-Expression -Command $strCommand
        }
        
        Else 
        {
            # Ask if we should elevate...
            Invoke-DebugIt -Console -Value 'This command requires elevation. Press "Y" to attempt elevation.' -Force
            
            $response = Read-Host -Prompt 'Continue (Y/N)?'
            
            IF ($response -eq 'Y')
            {
                $strRemoteCommand = @"
Import-Module -name Core; 

$($strCommand);

IF (!`$boolResult)
{
    Invoke-DebugIt -Console -Message 'Status' -Value 'Failed to create link!' -Color 'Red' -Force
}

Else
{
    Invoke-DebugIt -Console -Message 'Success' -Value 'Link created successfully' -Color 'Green' -Force
}
"@
                Invoke-Elevate -Command $strRemoteCommand -Persist
            }
            
            Else
            {
                Invoke-DebugIt -Console -Value "Couldn't get it done, huh?" -Color 'Yellow' -Force 
            }
        }
        
    
        
        
        IF ($boolResult = $false) 
        {
            Invoke-DebugIt -Console -Force -Message 'Failed' -Value 'Unable to create link!' -Color 'red'
        }
        
        Else
        {
            Invoke-DebugIt -Console -Message 'Success' -Value $boolResult -Color 'Green'
        }
    }
    
    End
    {
        # Clean up the environment
        Invoke-VariableBaseLine -Clean
    }
}


Function Remove-SymLink
{
    Param
    (
        [String] $Link
    )
    
    If (Test-Path -PathType Leaf $Link)
    {
        $strCommand = "Remove-Item -Path $Link -Force"
    }
    
    Else
    {
        $dir = Get-Item -Path $Link
        $strCommand = '[System.IO.Directory]::Delete("{0}")' -f $dir
        # Making a system.io call due to junction handling in < POSH 6
    }

    Invoke-Expression -Command ('{0}' -f $strCommand)
}


New-Alias -Name npp -Value Open-NotepadPlusPlus -ErrorAction SilentlyContinue
New-Alias -Name touch -Value Invoke-Touch -ErrorAction SilentlyContinue
New-Alias -Name ln -Value New-SymLink -ErrorAction SilentlyContinue 

#endregion


#region : LOG/ALERT FUNCTIONS 


Function Invoke-Snitch 
{
    <#
            .SYNOPSIS
            Describe purpose of "Invoke-Snitch" in 1-2 sentences.

            .DESCRIPTION
            Add a more complete description of what the function does.

            .PARAMETER strMessage
            This is a required variable. Message that is sent.

            .EXAMPLE
            Invoke-Snitch -strMessage Value
            Describe what this call does

            .NOTES
            Requires that you set, somewhere in your environment: smtphost, emailto, emailfrom, and emailsubject

            .LINK
            URLs to related sites
            The first link is opened by Get-Help -Online Invoke-Snitch

            .INPUTS
            Requires a string message.

            .OUTPUTS
            Void.
    #>

    # Function to send an email alert to distro-list
	
    [CmdletBinding()]
    param 
    (
        [Parameter(Mandatory=$true)]
        [string]$strMessage
    )
    

    # Check that the required variables are set in the environment
    if ($smtphost -and $emailto -and $emailfrom -and $emailsubject -and $strMessage) 
    {
        Send-MailMessage -SmtpServer $smtphost -To $emailto -From $emailfrom -Subject $emailsubject `
        -BodyasHTML ('{0}' -f $strMessage)
        
    } 
    
    else 
    {
    
        Write-Error -Message 'Not all required variables are set to invoke the snitch!'
    }
}
    
Function Invoke-DebugIt 
{
    <#
            .SYNOPSIS
            A more visually dynamic option for printing debug information.

            .DESCRIPTION
            Quick function to print custom debug information with complex formatting.

            .PARAMETER msg
            Descripter for the value to be printed. Color is gray.

            .PARAMETER val
            Emphasized "value" output for quick visibility when debugging. Default
            color of value is Cyan. Intentionally left as undefined variable type to
            avoid errors when presenting various types of data, possibly forgetting to
            add ToString() to the end of someting like an integer. 

            .PARAMETER Color
            Used when you need to categorize/differentiate, visually, types of values.
            Default color is Cyan.

            .PARAMETER Console
            Used when you want to log to the console. Can be used when logging to file as well. 

            .PARAMETER Logfile
            Used to log output to file. Logged as CSV

            .EXAMPLE
            Invoke-DebugIt -msg "Count of returned records" -val "({0} -f $($records.count)) -color Green
            Assuming that the number of records returned would be five, the following would be printed to
            the screen. Count of returned records : 5

            The message would be gray, and the number 5 would be Cyan, providing contrasting emphasis.

            .NOTES
            Pretty easy to understand. Just give it a try :)

    #>
    <#    
            CHANGELOG:
    
            ver 0.2
            - Changed parameters to full name
            - Added aliases to the parameters so older scripts would continue to function
            - Added the ability to log to file
            - Added -Console switch parameter for specifying output type
            - Added logic for older scripts that are not console switch aware

            ver 0.3
            - Takes value from pipeline
            - Added positional values to parameters
            - Changed type accelerator from .NET [Boolean] to PowerShell [Bool]
            - Added application event log, logging.

    #>
	
    [CmdletBinding()]
    Param
    (
        [Parameter(
        Position=0)]
        [Alias('msg','m')]
        [String] $Message,
        
        [Parameter(
                ValueFromPipeline=$true,
                Mandatory=$false,
        Position=1)]
        [Alias('val','v')]
        $Value,
        
        [Alias('c')]
        [String] $Color,
        
        [Alias('f')]
        [Switch] $Force, # Log even if the Debug parameter is not set
        
        [Alias('con')]
        [Switch] $Console, # Should we log to the console
        
        [Switch] $EvetLog, # Add an entry to the Application Event log
        
        [int] $EventId = 60001, # Default event log ID
        
        [ValidateScript({ Test-Path -Path ($_ | Split-Path -Parent) -PathType Container })]
        [Alias('log','l')]
        [String] $Logfile
    )
    
    $ScriptVersion = '0.'
    #[Bool] $boolDebug = $PSBoundParameters.Debug.IsPresent
    
    If (!($Console -and $Logfile))
    { # Backward compatible logic
        $Console = $true
    }
    
    IF ($Console)
    {
        If ($Color) 
        {
            $strColor = $Color
        } 
        
        Else 
        {
            $strColor = 'Cyan'
        }
    
        If ($boolDebug -or $Force) 
        {
            Write-Host -NoNewLine -f Gray ('{0}{1} : ' -f (Get-Date).ToString('yyyyMMdd_HHmmss : '), ($Message)) 
            Write-Host -f $($strColor) ('{0}' -f ($Value))
        }
    }
    
    If ($Logfile.Length -gt 0)
    {
        $strSender = ('{0},{1},{2}' -f (Get-Date).ToString('yyyyMMdd_HHmmss'),$Message,$Value)
        $strSender | Out-File -FilePath $Logfile -Encoding ascii -Append
    }
    
    IF ($EvetLog) 
    {
        [String] $strSource = 'PoshLogger'
        [String] $strEventLogName = 'Application'
        
        # Check if the source exists
        IF (!(Get-EventLog -Source $strSource -LogName $strEventLogName -Newest 1))
        {
            # Check if running as Administrator
            $boolAdmin = Test-AdminRights
            IF ($boolAdmin) 
            {
                New-EventLog -LogName $strEventLogName -Source $strSource
            }
            
            Else
            {
                Invoke-Elevate -ScriptBlock { New-EventLog -LogName $strEventLogName -Source $strSource }
            }
        }
        
        Write-EventLog -LogName $strEventLogName -Source $strSource -EventId $EventId -Message ($Message + $Value)
    }
}


Function Invoke-Alert
{
    <#
            .Synopsis
            Audible tone that can be easily called when some event is triggered. 

            .DESCRIPTION
            Great for monitoring things in the background, when you need to be working on something else. 

            .PARAMETER Duration
            This is the count or duration in seconds that the tone will be generated. A value of zero will
            beep until interrupted. Negative integers will beep only once. 

            .EXAMPLE
            The following will beep 3 times when the listed IP is reachable
            While (!(Test-Connection 8.8.8.8 -Q -C 1)) { sleep -s 1 }; Alert

            .EXAMPLE
            The following will beep once the IP is reachable, until you close the window, or Ctrl+C
            While (!(Test-Connection 8.8.8.8 -Q -C 1)) { sleep -s 1 }; Alert -c 0
    #>

    <#
            Version 0.1
            - Day one
    #>

    Param
    (
        [Parameter(Position=0)]
        [Alias('Count','c','Number', 'n')]
        [Int]$Duration = 3
    )
    
    Process
    {
        # Variables
        $i = 0
    
        Do
        {
            [console]::Beep(1000,700)
            Start-Sleep -Seconds 1
            
            If ($Duration -gt 0) { $i++ }
        }
        While ($i -lt $Duration) 
    }
}


New-Alias -Name logger -Value Invoke-DebugIt -ErrorAction SilentlyContinue
New-Alias -Name Invoke-Logger -Value Invoke-DebugIt -ErrorAction SilentlyContinue
New-Alias -Name Alert -Value Invoke-Alert -ErrorAction SilentlyContinue

#endregion


#region : SECURITY FUNCTIONS 


Function Test-AdminRights
{
    ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] 'Administrator')
}


Function Start-ImpersonateUser
{
    Param
    (
        [Parameter(Mandatory=$true,HelpMessage='Scriptblock to be ran')]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory=$true,HelpMessage='User to impersonate')]
        [String]$Username,
        
        [ValidateScript({ Test-Connection -ComputerName $_ -Quiet -Count 4 })]
        [String]$ComputerName,
        
        [PSCredential]$Credential
    )
    
    Begin
    {
        # List of required modules for this function
        $arrayModulesNeeded = (
            'core'
        )
        
        # Verify and load required modules
        Test-ModuleLoaded -RequiredModules $arrayModulesNeeded -Quiet
    }
    
    Process
    {
    
        # Variables 
        [boolean] $boolHidden = $true
        [String] $strCommandExec = 'powershell'
        [String] $strCommand = "& { $ScriptBlock }"
        [String] $strEncodedCommand = [Convert]::ToBase64String($([System.Text.Encoding]::Unicode.GetBytes($strCommand)))
        [String] $strArguments = "-Nop -W Hidden -Exec ByPass -EncodedCommand $strEncodedCommand"
        [String] $strJobName = ('ImpersonationJob{0}' -f (Get-Random))
        [String] $strTempFileName = [Guid]::NewGuid().ToString('d')
        [String] $strTempFilePath = ('{0}\{1}' -f $env:TEMP,$strTempFileName)
        [String] $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo />
  <Triggers />
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings />
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>$($boolHidden.ToString().ToLower())</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$strCommandExec</Command>
      <Arguments>$strArguments</Arguments>
    </Exec>
  </Actions>
  <Principals>
    <Principal id="Author">
      <UserId>$Username</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
</Task>
"@

        Try
        {
            $xml | Set-Content -Encoding Ascii -Path $strTempFilePath -Force
            $ErrorActionPreference = 'Stop'
            
            $strCommandBaseCreate = 'SCHTASKS.exe /Create /TN $strJobName /XML $strTempFilePath /S $ComputerName'
            $strCommandBaseRun = 'SCHTASKS.exe /Run /TN $strJobName /S $ComputerName'
            $strCommandBaseDelete = 'SCHTASKS.exe /Delete /TN $strJobName /S $ComputerName /F'
            
            $strCommandCredential = (
                '/U {0} /P {1}' -f $Credential.UserName, $Credential.GetNetworkCredential().Password
            )
            
            If ($Credential) 
            {
                Invoke-Expression -Command ('{0} {1}' -f $strCommandBaseCreate,$strCommandCredential)
                Invoke-Expression -Command ('{0} {1}' -f $strCommandBaseRun,$strCommandCredential)
                Invoke-Expression -Command ('{0} {1}' -f $strCommandBaseDelete,$strCommandCredential)
            }
            
            Else
            {
                Invoke-Expression -Command ('{0}' -f $strCommandBaseCreate)
                Invoke-Expression -Command ('{0}' -f $strCommandBaseRun)
                Invoke-Expression -Command ('{0}' -f $strCommandBaseDelete)
            }
             
        }
        
        Catch
        {
            Write-Error -Message ('Failed to run scheduled task on computer: {0}' -f $ComputerName)
        }

        Finally
        {
            Remove-Item -Path $strTempFilePath -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            
        }
    }
    
    End
    {
        
    }
}


Function Get-LoggedOnUser 
{
    [CmdletBinding()]             
    Param              
    (                        
        [Parameter(Mandatory=$true,
                Position=0,                           
                ValueFromPipeline=$true,             
                ValueFromPipelineByPropertyName=$true
        )]
        [String[]]$ComputerName,
        
        [PSCredential]$Credential
    )
 
    Begin             
    {             

    }
           
    Process             
    { 
        $ComputerName | ForEach-Object { 
            $Computer = $_ 
            
            Try 
            {
                If ($Credential)
                {
                    Try
                    {
                        $processinfo = @(Get-WmiObject -Credential $Credential -Class Win32_Process -ComputerName $Computer -Filter "Name='explorer.exe'" -EA 'Stop')
                    }
                    
                    Catch 
                    {
                        Write-Error -Message 'Get-LoggedOnUser: Failed to connect to remote system'
                    }
                }
                    
                Else
                {
                    Try
                    {
                        $processinfo = @(Get-WmiObject -Class Win32_Process -ComputerName $Computer -Filter "Name='explorer.exe'" -EA 'Stop') 
                    }
                    
                    Catch 
                    {
                        Write-Error -Message 'Get-LoggedOnUser: Failed to connect to remote system'
                    }
                }
                
                If ($processinfo) 
                {     
                    $processinfo | Foreach-Object {$_.GetOwner()} |  
                    Where-Object { $_ -notcontains 'NETWORK SERVICE' -and $_ -notcontains 'LOCAL SERVICE' -and $_ -notcontains 'SYSTEM' } | 
                    Sort-Object -Unique -Property User | 
                    ForEach-Object { New-Object psobject -Property @{ Computer=$Computer; Domain=$_.Domain; User=$_.User } } |  
                    Select-Object Computer,Domain,User 
                }
            }
            
            Catch 
            {
                "Cannot find any processes running on $Computer" | Out-Host 
            }
        }
    }
    
    End 
    { 
 
    }
}


Function Invoke-Elevate
{
    [CmdLetBinding()]
    [CmdletBinding(DefaultParameterSetName='Command')]
    Param
    (
        # ScriptBlock: Negates the need for Command
        [Parameter(Mandatory=$false,ParameterSetName="Command")]
        [Parameter(Mandatory=$true, Position=0,ParameterSetName='ScriptBlock',                
        HelpMessage='Scriptblock of commands to be executed')]
        [ScriptBlock] $ScriptBlock,
        
        # Command: Negates the need for ScriptBlock
        [Parameter(Mandatory=$false, ParameterSetName='ScriptBlock')]
        [Parameter(Mandatory=$true, Position=0, ParameterSetName='Command',
        HelpMessage='Commands to be executed')]
        [String] $Command,
        
        [Switch] $Persist
    )
    
    Begin
    {
        # Invoke-VariableBaseLine
        
        [Bool] $boolDebug = $PSBoundParameters.Debug.IsPresent
    }
    
    Process 
    {
    
        [String] $strCommand = "& { $ScriptBlock }"
 
        IF ($Command)
        {
            [String] $strCommand = $Command
        }
        
        [String] $strEncodedCommand = [Convert]::ToBase64String($([System.Text.Encoding]::Unicode.GetBytes($strCommand)))
        [String] $strArguments = "-Nop -Exec ByPass -EncodedCommand $strEncodedCommand"
        
        IF ($Persist)
        {
            $strArguments += ' -NoExit'
        }
    
        Start-Process PowerShell -Verb runas -ArgumentList $strArguments
    }
    
    End
    {
        # Invoke-VariableBaseLine -Clean
    }
}


Function Invoke-CredentialManager
{
    <#
            .Synopsis
            Function for managing credentials for storage

            .DESCRIPTION
            Used to both store, and retreive a password from 

            .EXAMPLE
            Invoke-CredentailManager -FilePath .\MySshPassord.auth

            .EXAMPLE
            Invoke-CredentailManager -FilePath .\MySshPassord.auth -Credentail $creds
    #>

    <#
            Version 0.?
            - ? MACD. Move, add, change, or delete details go here. ?
    #>
    
    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory=$true, Position=0,
        HelpMessage='Path to where the credentials files is stored')]
        [Alias('CredentialsFile')]
        [string]$FilePath,
        
        [Parameter(Position=1)]
        [PSCredential]$Credential
    )
    
    Begin
    {
        # Baseline our environment 
        Invoke-VariableBaseLine

        # Global debugging for scripts
        $boolDebug = $PSBoundParameters.Debug.IsPresent
    }
    
    Process
    {
        # Variables
        $CredentialsFile = $FilePath
        
        # Check to see if the file exists 
        IF (-not (Test-Path $credentialsfile))
        { 
            # If not, then prompt user for the credential 
            IF ($Credential) 
            {
                $creds = $Credential
            }
        
            Else
            {
                $creds = Get-Credential 
            }
        
            # Get the password part 
            $encpassword = $creds.password 
        
            # Convert it from secure string and save it to the specified file 
            $encpassword | ConvertFrom-SecureString | Set-Content $CredentialsFile
        } 
    
        Else 
        { 
            # If the file exists, get the content and convert it back to secure string 
            $encpassword = Get-Content -Path $credentialsfile | ConvertTo-SecureString 
        }
     
        # Use the Marshal classes to create a pointer to the secure string in memory 
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($encpassword) 
    
        # Change the value at the pointer back to unicode (i.e. plaintext) 
        $pass = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)  
    
        # Return the decrypted password 
        $pass 
    }
    
    End
    {
        # Clean up the environment
        Invoke-VariableBaseLine -Clean
    }
}


New-Alias -Name elevate -Value Invoke-Elevate -ErrorAction SilentlyContinue
New-Alias -Name sudo -Value Invoke-Elevate -ErrorAction SilentlyContinue
New-Alias -Name Store-Credentials -Value Invoke-CredentialManager -ErrorAction SilentlyContinue
New-Alias -Name Get-Password -Value Invoke-CredentialManager -ErrorAction SilentlyContinue

#endregion