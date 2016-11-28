Function Invoke-DebugIt {
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

    #>
	
    [CmdletBinding()]
    Param
    (
        [Alias('msg','m')]
        [String] $Message,
        
        [Alias('val','v')]$Value,
        
        [Alias('c')]
        [String] $Color,
        
        [Alias('f')]
        [Switch] $Force, # Log even if the Debug parameter is not set
        
        [Alias('con')]
        [Switch] $Console, # Should we log to the console
        
        [ValidateScript({ Test-Path -Path ($_ | Split-Path -Parent) -PathType Container })]
        [Alias('log','l')]
        [String] $Logfile
    )
    
    [boolean] $Debug = $PSBoundParameters.Debug.IsPresent
    
    If (!($Console -and $Logfile))
    { # Backware compatible logic
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
    
        If ($Debug -or $Force) 
        {
            Write-Host -NoNewLine -f Gray ('{0}{1} : ' -f (Get-Date -UFormat '%Y%m%d-%H%M%S : '), ($Message)) 
            Write-Host -f $($strColor) ('{0}' -f ($Value))
        }
    }
    
    If ($Logfile.Length -gt 0)
    {
        $strSender = ('{0},{1},{2}' -f (Get-Date -UFormat '%Y%m%d-%H%M%S'),$Message,$Value)
        $strSender | Out-File -FilePath $Logfile -Encoding ascii -Append
    }
}

New-Alias -Name logger -Value Invoke-DebugIt
New-Alias -Name Invoke-Logger -Value Invoke-DebugIt


Function Test-ModuleLoaded {
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
    
    Param (
        [Parameter(Mandatory=$true,HelpMessage='String array of module names')]
        [String[]]$RequiredModules,
        [Switch]$Quiet
    ) 

    
    Process {
        # Variables
        $loadedModules = Get-Module
        $availableModules = Get-Module -ListAvailable
        [int]$failedModules = 0
        [System.Collections.ArrayList]$missingModules = @()
        $arraryRequiredModules = $RequiredModules
        
        # Loop thru all module requirements
        foreach ($module in $arraryRequiredModules) {
        
            if ($loadedModules.Name -contains $module) {
                $true | Out-Null 
        
            } elseif ($availableModules.Name -ccontains $module) {
                Import-Module -Name $module
        
            } else {
                if (!$Quiet) {
                    Write-Output -InputObject ('{0} module is missing.' -f $module)
                }
                
                $missingModules.Add($module)
                $failedModules++
            }
        }
        
        # Return the boolean value for success for failure
        if ($failedModules -gt 0) {
            $false
        } else {
            $true
        }
    }
}


Function Invoke-VariableBaseLine {
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
    Param (
        [Switch]$Clean
    )
    
    Begin {
        if ($Clean -and -not $baselineLocalVariables) {
            Write-Error -Message 'No baseline variable is set to revert to.'
        }
    }
    
    Process {
        if ($Clean) {
            Compare-Object -ReferenceObject $($baselineLocalVariables.Name) -DifferenceObject `
            $((Get-Variable -Scope 0).Name) |
            Where-Object { $_.SideIndicator -eq '=>'} |
            ForEach-Object { 
                Remove-Variable -Name ('{0}' -f $_.InputObject) -ErrorAction SilentlyContinue
            }
        }
        else {
            $baselineLocalVariables = Get-Variable -Scope Local
        }
    }
    
    End {
        if ($Clean) {
            Remove-Variable -Name baselineLocalVariables -ErrorAction SilentlyContinue
        }
    }
}


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
    if ($smtphost -and $emailto -and $emailfrom -and $emailsubject -and $strMessage) {
        Send-MailMessage -SmtpServer $smtphost -To $emailto -From $emailfrom -Subject $emailsubject `
        -BodyasHTML ('{0}' -f $strMessage)
        
    } else {
    
        Write-Error -Message 'Not all required variables are set to invoke the snitch!'
    }
}


Function Invoke-Touch # Mimics Linux touch command
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
        if ("$($strPath -replace "^\.")" -like "*.*") 
        { 
            $strType = "File"
        } 
        
        Else 
        { 
            $strType = "Directory"
        }

        if ((Test-Path "$strPath") -eq $true) 
        {
            If ("$strType" -match "File") 
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
    
