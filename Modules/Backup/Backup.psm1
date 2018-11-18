<<<<<<< HEAD
#requires -Version 3.0 -Modules CimCmdlets, core


<#
                                README!!!

    Other requiremens:
        Sync functions require that you have Microsoft's Sync Framework 2.0 & SDK installed
#> 

=======
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
>>>>>>> origin/master

#region Volume Shadow Services


<<<<<<< HEAD
Function Mount-VSSAllShadow 
{
    Param
    (
        [Parameter(Mandatory=$true, HelpMessage='Destination directory')]
        [ValidateScript({
                    Test-Path -Path $_ -PathType Container
                }
        )]
        [String]$Path
    )

    Get-CimInstance -ClassName Win32_ShadowCopy | 
    Mount-VolumeShadowCopy -Path $Path -Verbose
}


Function Get-VSSShadow {
=======
Function Mount-VSSAllShadows {

    Get-CimInstance -ClassName Win32_ShadowCopy | 
    Mount-VolumeShadowCopy -Destination C:\VSS -Verbose
}


Function Get-VSSShadows {
>>>>>>> origin/master
    vssadmin list shadows | 
    Select-String -Pattern 'shadow copies at creation time' -Context 0,3 |
    ForEach-Object {
        [pscustomobject]@{
            Path = (($_.Context.PostContext -split "\r\n")[2] -split ':')[1].Trim();
            InstallDate = ($_.Line -split ':\s',2)[1];
        }
    }
}


Function Mount-VolumeShadowCopy {
    <#
            .SYNOPSIS
            Mount a volume shadow copy.
     
            .DESCRIPTION
            Mount a volume shadow copy.
      
            .PARAMETER ShadowPath
            Path of volume shadow copies submitted as an array of strings
      
            .PARAMETER Destination
            Target folder that will contain mounted volume shadow copies
              
            .EXAMPLE
            Get-CimInstance -ClassName Win32_ShadowCopy | 
<<<<<<< HEAD
            Mount-VolumeShadowCopy -Path C:\VSS -Verbose
=======
            Mount-VolumeShadowCopy -Destination C:\VSS -Verbose
>>>>>>> origin/master
 
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidatePattern('\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d{1,}')]
        [Alias('DeviceObject')]
        [String[]]$ShadowPath,
 
<<<<<<< HEAD
        [Parameter(Mandatory=$true, HelpMessage='Destination directory')]
=======
        [Parameter(Mandatory)]
>>>>>>> origin/master
        [ValidateScript({
                    Test-Path -Path $_ -PathType Container
                }
        )]
<<<<<<< HEAD
        [String]$Path
=======
        [String]$Destination
>>>>>>> origin/master
    )
    Begin {
    
        $typDef = @'
        using System;
        using System.Runtime.InteropServices;
  
        namespace mklink
        {
            public class symlink
            {
                [DllImport("kernel32.dll")]
                public static extern bool CreateSymbolicLink(string lpSymlinkFileName, string lpTargetFileName, int dwFlags);
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
    Process {
 
        $ShadowPath | ForEach-Object -Process {
 
            if ($($_).EndsWith('\')) {
                $sPath = $_
            } else {
                $sPath = ('{0}\' -f ($_))
            }
        
<<<<<<< HEAD
            $tPath = Join-Path -Path $Path -ChildPath (
=======
            $tPath = Join-Path -Path $Destination -ChildPath (
>>>>>>> origin/master
                '{0}-{1}' -f (Split-Path -Path $sPath -Leaf),[GUID]::NewGuid().Guid
            )
         
            try {
                if (
                    [mklink.symlink]::CreateSymbolicLink($tPath,$sPath,1)
                ) {
                    Write-Verbose -Message ('Successfully mounted {0} to {1}' -f $sPath, $tPath)
                } else  {
                    Write-Warning -Message ('Failed to mount {0}' -f $sPath)
                }
            } catch {
                Write-Warning -Message ('Failed to mount {0} because {1}' -f $sPath, $_.Exception.Message)
            }
        }
 
    }
    End {}
}

 
Function Dismount-VolumeShadowCopy {
    <#
            .SYNOPSIS
            Dismount a volume shadow copy.
     
            .DESCRIPTION
            Dismount a volume shadow copy.
      
            .PARAMETER Path
            Path of volume shadow copies mount points submitted as an array of strings
      
            .EXAMPLE
            Get-ChildItem -Path C:\VSS | Dismount-VolumeShadowCopy -Verbose
         
 
    #>
 
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [string[]]$Path
    )
    Begin {
    }
    Process {
        $Path | ForEach-Object -Process {
            $sPath =  $_
            if (Test-Path -Path $sPath -PathType Container) {
                if ((Get-Item -Path $sPath).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                    try {
                        [System.IO.Directory]::Delete($sPath,$false) | Out-Null
                        Write-Verbose -Message ('Successfully dismounted {0}' -f $sPath)
                    } catch {
                        Write-Warning -Message ('Failed to dismount {0} because {1}' -f $sPath, $_.Exception.Message)
                    }
                } else {
                    Write-Warning -Message ("The path {0} isn't a reparsepoint" -f $sPath)
                }
            } else {
                Write-Warning -Message ("The path {0} isn't a directory" -f $sPath)
            }
        }
    }
    End {}
}


#endregion

#region Synchronization Tools


Function Sync-Directory
{
<<<<<<< HEAD
    <#
            .SYNOPSIS
            Keep two directories synchronized

            .DESCRIPTION
            Built using the Microsoft Sync Framework 2.1. This function keeps two directories in sync with each
            other. Multiple clients can sync to the same shared directory. 

            .EXAMPLE
            Sync-Directory -SourcePath 'C:\sourceDir' -DestinationPath 'C:\destinationDirectory'

            .EXAMPLE
            Sync-Directory '.\myImportantStuff' '\\ShareServer\myShare\importantStuff' -SyncHiddenFiles

            .REQUIREMENTS
            Microsoft Sync Framework 2.1 - https://www.microsoft.com/en-us/download/details.aspx?id=19502
    #>

    <#
            Version 0.1
            - Day one
    #>

    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [String] $SourcePath,
        
        [ValidateScript({
                    try {
                        [System.Guid]::Parse($_) | Out-Null
                        $true
                    } catch {
                        $false
                    }
        })]
        [String] $sGuid,
        
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [String] $DestinationPath,
        
        [ValidateScript({
                    try {
                        [System.Guid]::Parse($_) | Out-Null
                        $true
                    } catch {
                        $false
                    }
        })]
        [String] $dGuid,
        
        [String[]] $FileNameFilter = ('~*.tmp','*.dat','Desktop.ini','*.lnk','Thumbs.db','*.metadata'),
        
        [Switch] $SyncHiddenFiles,
        
        [Switch] $SyncSystemFiles,
        
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [String] $ArchivePath
    )
    
    Begin
    {
        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
        
        # Includes
        $Libraries = (
            'Microsoft.Synchronization',
            'Microsoft.Synchronization.Files',
            'Microsoft.Synchronization.MetadataStorage'
        )
        
        # Error action preference
        $ErrorActionPreference = 'Stop'
        
        Try
        {
            Foreach ($Library in $Libraries)
            {
                $null = [System.Reflection.Assembly]::LoadWithPartialName($Library)
            }
        }
        
        Catch 
        {
            Write-Error -Message 'Failed to load Sync Framework libraries. Microsoft Sync Framework 2.1 required'
        }
    }
    
    Process
    {
        Function Script:Get-Match
        {
            <#
                    .DESCRIPTION
                    Matches an environmental variable used to store sync jobs.

                    .PARAMETER InputObject
                    Array of variables to filter.
            #>


            Param 
            (
                [Parameter(Mandatory=$true, 
                        ValueFromPipeline=$true, 
                HelpMessage='Data to filter')]
                $InputObject
            )
            Process
            {
                IF ($InputObject -match 'SyncDir_')
                {
                    $InputObject
                }
            }
        }
        
        
        Function Script:Sync-File
        {
            Param
            (
                [String] $Source,
                
                [GUID] $sGuid,
                
                [String] $Destination,
                
                [GUID] $dGuid,
                
                [Microsoft.Synchronization.Files.FileSyncScopeFilter] $Filter,
                
                [Microsoft.Synchronization.Files.FileSyncOptions] $Options
            )
            
            $sourceProvider = $null
            $destinationProvider = $null
            
            Try
            {
                $sourceProvider = New-Object Microsoft.Synchronization.Files.FileSyncProvider `
                -ArgumentList $sGuid, $Source, $Filter, $Options
                
                $destinationProvider = New-Object Microsoft.Synchronization.Files.FileSyncProvider `
                -ArgumentList $dGuid, $Destination, $Filter, $Options
                
                # Agent and sync action
                $synDirection = [Microsoft.Synchronization.SyncDirectionOrder]::UploadAndDownload

                $syncAgent = [Microsoft.Synchronization.SyncOrchestrator]::new()

                [Microsoft.Synchronization.SyncProvider] $srcProv = $sourceProvider
                [Microsoft.Synchronization.SyncProvider] $dstProv = $destinationProvider

                $syncAgent.LocalProvider = $srcProv
                $syncAgent.RemoteProvider = $dstProv
                $syncAgent.Direction = $synDirection
    
                $results = $syncAgent.Synchronize()
        
                $results
            }
            
            Finally
            {
                If ($sourceProvider)
                {
                    $sourceProvider.Dispose()
                }
                
                If ($destinationProvider)
                {
                    $destinationProvider.Dispose()
                }
            }
        }
        
      
        Function Script:Get-Change
        {
            Param
            (
                [String] $RootPath,
                
                [Guid] $Guid,
                
                [Microsoft.Synchronization.Files.FileSyncScopeFilter] $Filter,
                
                [Microsoft.Synchronization.Files.FileSyncOptions] $Options
            )
            
            $Provider = $null
            
            Try
            {
                $Provider =  New-Object Microsoft.Synchronization.Files.FileSyncProvider `
                -ArgumentList $Guid, $RootPath, $Filter, $Options
                
                $Provider.DetectChanges()
				
                If ($boolDebug) 
                {
                    $Provider.GetChangeBatch()
                }
            }
            
            Finally
            {
                If ($Provider)
                {
                    $Provider.Dispose()
                }
            }
        }
        
        
        # Guids  #TODO: Need to get this from the MetaData file
        If ($sGuid) { $srcGuid = $sGuid } Else { $srcGuid = [guid]::NewGuid().guid }
        If ($dGuid) { $dstGuid = $dGuid } Else { $dstGuid = [guid]::NewGuid().guid }
        
        # Sync directories
        $strSourceDirectory = (Get-Item -Path $SourcePath).FullName -replace "\\$"
        $strDestinationDirectory = (Get-Item -Path $DestinationPath).FullName -replace "\\$"
        
        # Filter
        $scopeFilter = [Microsoft.Synchronization.Files.FileSyncScopeFilter]::new()
        
        # File attribute objects for the scope filter. We don't want hidden or system files
        $attribHidden = [System.IO.FileAttributes]::Hidden
        $attribSystem = [System.IO.FileAttributes]::System

        # Array needed cause there is no Add() method, only get or set;
        $arrayAttrib = ($attribHidden,$attribSystem)
        $scopeFilter.AttributeExcludeMask = $arrayAttrib
        $arrayNameFilters = $FileNameFilter

        Foreach ($nameFilter in $arrayNameFilters)
        {
            $scopeFilter.FileNameExcludes.Add("$nameFilter")
        }
        
        # Options object
        $syncOptions = ( 
            [Microsoft.Synchronization.Files.FileSyncOptions]::RecycleConflictLoserFiles, 
            [Microsoft.Synchronization.Files.FileSyncOptions]::RecycleDeletedFiles,
            [Microsoft.Synchronization.Files.FileSyncOptions]::RecyclePreviousFileOnUpdates
        )

        # Detect all changes 
        <#
                Get-Change -RootPath $strSourceDirectory -Filter $scopeFilter -Options $syncOptions -Guid $srcGuid
                Get-Change -RootPath $strDestinationDirectory -Filter $scopeFilter -Options $syncOptions -Guid $dstGuid
        #>

        # Sync files both directions
        Try
        {
            Sync-File -Source $strSourceDirectory -sGuid $srcGuid -Destination $strDestinationDirectory `
            -dGuid $dstGuid -Filter $scopeFilter -Options $syncOptions 
        }
        Catch
        {
            [String] $errorMessage = @'
{0}, FAILURE!!, Something went wrong during the Sync-Files function
Source directory: {1}
Destination directory : {2}
{3}

'@ -f (Get-Date).ToString(), $strSourceDirectory, $strDestinationDirectory, "`n"
            $errorMessage | Out-File -FilePath "$PSScriptRoot\.Syncronization_error.log" -Encoding ascii -Append 
        }
    }
    
    End
    {

    }
=======
	<#
			.SYNOPSIS
			Keep two directories synchronized

			.DESCRIPTION
			Built using the Microsoft Sync Framework 2.1. This function keeps two directories in sync with each
			other. Multiple clients can sync to the same shared directory. 

			.EXAMPLE
			Sync-Directory -SourcePath 'C:\sourceDir' -DestinationPath 'C:\destinationDirectory'

			.EXAMPLE
			Sync-Directory '.\myImportantStuff' '\\ShareServer\myShare\importantStuff' -SyncHiddenFiles

			.REQUIREMENTS
			Microsoft Sync Framework 2.1 - https://www.microsoft.com/en-us/download/details.aspx?id=19502
	#>

	<#
			Version 0.1
			- Day one
	#>

	[CmdLetBinding()]
	Param
	(
		[Parameter(Mandatory = $true, Position = 0)]
		[ValidateScript({ Test-Path $_ -PathType Container })]
		[String] $SourcePath,
        
		[ValidateScript({
					try {
						[System.Guid]::Parse($_) | Out-Null
						$true
					} catch {
						$false
					}
		})]
		[String] $sGuid,
        
		[Parameter(Mandatory = $true, Position = 1)]
		[ValidateScript({ Test-Path $_ -PathType Container })]
		[String] $DestinationPath,
        
		[ValidateScript({
					try {
						[System.Guid]::Parse($_) | Out-Null
						$true
					} catch {
						$false
					}
		})]
		[String] $dGuid,
        
		[String[]] $FileNameFilter = ('~*.tmp','*.dat','Desktop.ini','*.lnk','Thumbs.db'),
        
		[Switch] $SyncHiddenFiles,
        
		[Switch] $SyncSystemFiles,
        
		[ValidateScript({ Test-Path $_ -PathType Container })]
		[String] $ArchivePath
	)
    
	Begin
	{
		# Baseline our environment 
		Invoke-VariableBaseLine

		# Debugging for scripts
		$Script:boolDebug = $PSBoundParameters.Debug.IsPresent
        
		# Includes
		$Libraries = (
			'Microsoft.Synchronization',
			'Microsoft.Synchronization.Files',
			'Microsoft.Synchronization.MetadataStorage'
		)
        
		# Error action preference
		$ErrorActionPreference = 'Stop'
        
		Try
		{
			Foreach ($Library in $Libraries)
			{
				$null = [System.Reflection.Assembly]::LoadWithPartialName($Library)
			}
		}
        
		Catch 
		{
			Write-Error -Message 'Failed to load Sync Framework libraries. Microsoft Sync Framework 2.1 required'
		}
	}
    
	Process
	{
		Function Script:Where-Matches
		{
			<#
					.DESCRIPTION
					Matches an environmental variable used to store sync jobs.

					.PARAMETER InputObject
					Array of variables to filter.
			#>


			Param 
			(
				[Parameter(Mandatory=$true, 
						ValueFromPipeline=$true, 
				HelpMessage='Data to filter')]
				$InputObject
			)
			Process
			{
            
				IF (
					$InputObject -match 'SyncDir_'
				)
        
				{
					$InputObject
				}
			}
		}
        
		# Check if GUID is stored for the source and destination, if not, create it. 
		#$envVars = [System.Environment]::GetEnvironmentVariables('User').Keys.Split("`n") | Where-Matches
        

        
		# Sync directories
		$strSourceDirectory = (Get-Item -Path $SourcePath).FullName -replace "\\$"
		$strDestinationDirectory = (Get-Item -Path $DestinationPath).FullName -replace "\\$"
		
				# Guids  
		#TODO: Need to get this from the MetaData file
		If ($sGuid) { $srcGuid = $sGuid } Else { $srcGuid = [guid]::NewGuid().guid }
		If ($dGuid) { $dstGuid = $dGuid } Else { $dstGuid = [guid]::NewGuid().guid }
        
		# Filter
		$scopeFilter = [Microsoft.Synchronization.Files.FileSyncScopeFilter]::new()
		# File attribute objects for the scope filter. We don't want hidden or system files
		$attribHidden = [System.IO.FileAttributes]::Hidden
		$attribSystem = [System.IO.FileAttributes]::System

		# Array needed cause there is no Add() method, only get or set;
		$arrayAttrib = ($attribHidden,$attribSystem)
		$scopeFilter.AttributeExcludeMask = $arrayAttrib
		$arrayNameFilters = $FileNameFilter

		Foreach ($nameFilter in $arrayNameFilters)
		{
			$scopeFilter.FileNameExcludes.Add("$nameFilter")
		}
        
		# Options object
		$syncOptions = ( 
			[Microsoft.Synchronization.Files.FileSyncOptions]::RecycleConflictLoserFiles, 
			[Microsoft.Synchronization.Files.FileSyncOptions]::RecycleDeletedFiles,
			[Microsoft.Synchronization.Files.FileSyncOptions]::RecyclePreviousFileOnUpdates
		)
        
		# Providers
		$sourceProvider = New-Object Microsoft.Synchronization.Files.FileSyncProvider `
		-ArgumentList $srcGuid, $strSourceDirectory, $scopeFilter, $syncOptions
    
		$destinationProvider =  New-Object Microsoft.Synchronization.Files.FileSyncProvider `
		-ArgumentList $dstGuid, $strDestinationDirectory, $scopeFilter, $syncOptions
    
		#$sourceProvider.DetectChanges()
		#$destinationProvider.DetectChanges()
        
		# Display detected changes
		#$sourceProvider.DetectedChanges += [System.EventHandler] $srcAppliedChangeEventArgs
		#$destinationProvider.DetectedChanges


		# Agent and sync action
		$synDirection = [Microsoft.Synchronization.SyncDirectionOrder]::UploadAndDownload

		$syncAgent = [Microsoft.Synchronization.SyncOrchestrator]::new()

		[Microsoft.Synchronization.SyncProvider] $srcProv = $sourceProvider
		[Microsoft.Synchronization.SyncProvider] $dstProv = $destinationProvider

		$syncAgent.LocalProvider = $srcProv
		$syncAgent.RemoteProvider = $dstProv
		$syncAgent.Direction = $synDirection
    
		$results = $syncAgent.Synchronize()
        
		$results
	}
    
	End
	{
		# Clean up the environment
		Invoke-VariableBaseLine -Clean
	}
>>>>>>> origin/master
}


#endregion
