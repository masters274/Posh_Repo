# Different functions for connecting to various types of databases

<#
        Version 0.2
        - Function : Submit-PSobjectToDatabase : Updated : Now identifies if field is [int], and submits as such

        Version 0.3
        - Function : Submit-PSobjectToDatabase : Updated : Column names now enclosed in sqare brakets []. Spaces... Bah!
        - Function : New-TableFromPSObject : Added : Produces a table script (MS SQL), based on PSObject
#>

function Connect-MsSqlDatabase 
{ # Connects to a Microsoft SQL Server, and executes a query. 
    PARAM 
    (
        [String] $Server,
        
        [Parameter(Mandatory=$true, ValueFromPipeLine=$true,
            HelpMessage='Database Name')]
        [String] $Database,
        
        [String] $Username,
        
        [String] $Password,
        
        [String] $Query = $(Throw 'How are you gonna run a SQL query, without the query..!'),
        
        [Switch] $Kerberos
    )
    
    # Variables:
    $dtStartTime = Get-Date # Start the clock.
    
    if ($Kerberos) 
    {
        $strSqlConnectionString = "DataSource=$Server; Database=$Database; Integrated Security=SSPI"
    } 
    
    else 
    {
        if ($Username -eq $Null -or $Password -eq $Null) 
        {
            Write-Host "Username and Password must be set when not performing a Trusted (Kerberos) connection" -ForegroundColor Red
        } 
        
        else 
        { 
            $strSqlConnectionString = "Data Source=$Server; Database=$Database; User=$Username; Password=$Password"
        }
    }
    
    $strCommand = "$Query"
    $objConnection = New-Object System.Data.SqlClient.SQLConnection($strSqlConnectionString)
    $constructorSqlCommand = New-Object System.Data.SqlClient.SqlCommand($strCommand, $objConnection)
	
	
    # Actions:
    Try 
    {
        $objConnection.Open() # Open the connection to the database 
		
        if ($strCommand -match "Select") 
        { # Select query, return a table object  
            $constructorDataAdapter = New-Object -TypeName System.Data.SqlClient.SqlDataAdapter($constructorSqlCommand)
            $objDataSet = New-Object -TypeName System.Data.DataSet
            $constructorDataAdapter.Fill($objDataSet) |Out-Null
            $retValue = $objDataSet.Tables
        } 
        
        else 
        {
            $retValue = $constructorSqlCommand.ExecuteNonQuery() # Execute the query and return the number of rows affected. 
        }
    } 
    
    Catch 
    {
        Write-Error -Message "Something went wrong while connecting to the database. Check your work!"
    }
	
    # Clean up:
    $objConnection.Close()
    $constructorSqlCommand.Dispose()
    Remove-Variable Password -ErrorAction SilentlyContinue
    Remove-Variable Username -ErrorAction SilentlyContinue
    Remove-Variable objConnection -ErrorAction SilentlyContinue
    Remove-Variable Query -ErrorAction SilentlyContinue
    Remove-Variable strCommand -ErrorAction SilentlyContinue
	
    if ($Debug)
    { # How long did it take to execute this function? 
        $dtElapsedTime = New-TimeSpan $dtStartTime $(Get-Date)
        $dtElapsedTime |
        ForEach-Object {
            Write-Host "Elapsed Time in minutes: $($_.Minutes).$($_.Seconds).$($_.Milliseconds)"
        }
    }
	
    $retValue # Return the value from the query executed 
}


function Connect-MySqlDatabase 
{
    
}


function Connect-AccessDataBase 
{ # Opens a Microsoft Access Database file, and executes a query. 
    # TODO: 
    # error checking on file path
    # - Get list of driver providers already installed, pick the best one. If none installed, have Jet DB driver and install it.
	
    PARAM 
    (
        [String]$MDBFile,
        [String]$Statement
    )
	
    # DB providers:
    $objDbProviders = (New-Object system.data.oledb.oledbenumerator).GetElements()
	
    # Connect to the database
    $objConnection = New-Object -com ADODB.Connection
    $objRecordset = New-Object -com ADODB.Recordset
    $objConnection.open("Provider = Microsoft.ACE.OLEDB.15.0;Data Source=""$MDBFile""")
	
    # SQL statement to get the record(s)
    $objRecordset.open("$Statement",$objConnection)
	
    if ("$($Statement)" -match 'select') 
    { # Only return a value, if there is a value to return... :)  SELECT statements only.
        $2dArrayRecord = $objRecordset.GetRows() # Caution, returns a two dimensional array!
		
        # Give'em something they can use...
        Return $2dArrayRecord # PowerShell strips the 2 dimensional array[0,0], and turns it into a 1 dimensional array[0]. YAY!!
		
        # Clean up time, we're done here...
        # Close the Recordset
        $objRecordset.close()
    }
	
    # Close the connection
    $objConnection.close()

}


Function Submit-PSobjectToDatabase 
{
    param 
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage='Data to filter')]
        $InputObject,
        
        [Parameter(Mandatory=$true, HelpMessage='Database Server Name')]
        [String]$Server,
        
        [Parameter(Mandatory=$true, HelpMessage='Database Name')]
        [String]$Database,
        
        [Parameter(Mandatory=$true, HelpMessage='Database Table Name')]
        [String]$Table,
        
        [PSCredential]$Credential
    )
    
    Begin
    {
        Try
        {
            Test-ModuleLoaded -RequiredModules 'core','Database'
        }
        
        Catch
        {
            Write-Error -Message 'Failed to load required modules!'
        }
        
        Invoke-VariableBaseLine
    }
    
    Process 
    {
        # Get the column information 
        #$strColumnNames = ($InputObject | Get-Member -MemberType NoteProperty).Name
        
        $strColumnNames = $InputObject | 
        Get-Member -MemberType NoteProperty |
        Select-Object -Property Name,@{ Name='Type'; Expression={ $_.Definition.Split(' ')[0] }}
            
        $objFailedItems = @()
        
        Foreach ($record in $InputObject) 
        {            
            # Get the global Scan/Report date that should be set from the object created. 
            #if (!$Global:dtScanDate) 
            #{
            $dtScanDate = (Get-Date -Year (Get-Date).Year -Month (Get-Date).Month -Day 1)
            #}
            
            # Variables : Temp
            $strBuilder = @()
            $strValues = @()
            
            
            Foreach ($column in $strColumnNames) 
            {
                $strBuilder += '[' + $column.Name + ']'
                
                IF ($column.Type -match 'int')
                {
                    $strValues += ($record.$($column.Name) -replace ("'",''))
                }
                
                Else
                {
                    $strValues += "'" + ($record.$($column.Name) -replace ("'",'')) + "'"
                }
                
                
                $newVals = $strValues -join "," 
                #$newVals = $newVals -replace ("^|$","'")
            }
        
            $strQuery = ('INSERT INTO {0}.{1} ({2}) VALUES ({3})' -f $Database, $Table,($strBuilder -join ','), $newVals)
            
            
            Try 
            {
                Connect-MsSqlDatabase -Server $Server -Database $Database -Username $($Credential.UserName) `
                -Password $($Credential.GetNetworkCredential().Password) -Query $strQuery | 
                Out-Null
            }
            
            Catch 
            {
                $objFailedItems += $record
                
                Write-Host $strQuery
            }
            
            # Clean up the temp variables
            Remove-Variable strBuilder -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
            Remove-Variable strValues -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
            Remove-Variable newVals -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }
        
        # $objFailedItems.Count
    }
    
    End 
    {
        Invoke-VariableBaseLine -Clean
    }
}


Function  New-TableFromPSObject
{
    <#
            .Synopsis
            Creates a script, that creates a table in MS SQL

            .DESCRIPTION
            Takes a PSObject, checks for the types of properties, then creates a script, which can then be ran on 
            and MS SQL Server, as a query, that will in turn create a table based on the object.  

            .EXAMPLE
            New-TableFromPSObject -InputObject $sender -Database 'MyDB' -Table 'NewTableName' -AllowNulls

            .EXAMPLE
            $queryScript = New-TableFromPSObject -InputObject $sender -Database 'MyDB' -Table 'NewTableName'
            Connect-MsSqlDatabase -Server 'DBServer' -Database 'MyDB' -Kerberos -Query $queryScript

            .EXAMPLE
            Add some easy date information to our $sender 
            
            $senderWithDateKeys = $sender | Select-Object -Property Entity,Profile,Status,Date,`
                @{Name='YearID'; Expression={ (Get-Date).Year }},`
                @{Name='MonthID'; Expression={ (Get-Date).Month }},`
                @{Name='DayID'; Expression={ 1 }}
    #>
    
    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, 
        HelpMessage='Data to filter')]
        [Alias('io')]
        [PSObject] $InputObject,
        
        [Parameter(Mandatory=$true, ValueFromPipeLine=$true,
            HelpMessage='Database Name')]
        [String] $Database,
        
        [Parameter(Mandatory=$true, HelpMessage='Database Table Name')]
        [String] $Table,
        
        [Switch] $AllowNulls
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
        $strColumnNames = $InputObject | 
        Get-Member -MemberType Properties |
        Select-Object -Property Name,@{ 
            Name='Type'
            Expression={ $_.Definition.Split(' ')[0] }
        }
        
        IF ($AllowNulls)
        {
            $strNullable = 'NULL'
        }
        
        Else
        {
            $strNullable = 'NOT NULL'
        }
            
        $strDatabaseName = '[' + $($Database.Trim()) + ']'
        $strTableName = '[' + $($Table.Trim()) + ']'
        $strSchemaBuilder = @()
        $arrayScript = @()
        
        $strBeginScript = @"
USE $strDatabaseName
GO

SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

SET ANSI_PADDING ON
GO 

"@

        $strEndScript = @"

GO

SET ANSI_PADDING OFF
GO

"@
    
        Foreach ($Column in $strColumnNames) 
        {
            IF ($Column.Type -match 'int') 
            {
                $accelSqlType = 'int'
            }
                    
            ElseIF ($_.Type -match 'Date')
            {
                $accelSqlType = 'datetime'
            }
                    
            Else
            {
                # Quotes around the column name in case of space in the name
                [int] $intColumnMaxLength = ($InputObject."$($Column.Name)".GetEnumerator().Length | 
                Measure-Object -Maximum).Maximum | Out-Null
            
                IF ($intColumnMaxLength -le 50)
                {
                    $intColumnMaxLength = 50
                }
        
                Else
                {
                    $intColumnMaxLength = $intColumnMaxLength + 10
                }

                $accelSqlType = 'varchar ({0})' -f $intColumnMaxLength 
            }

            $strSchemaBuilder += '[{0}] [{1}] {2}' -f $Column.Name, $accelSqlType, $strNullable
        }
    
        $arrayScript = $strBeginScript + ('CREATE TABLE {0} (' -f $strTableName) + 
            ($($strSchemaBuilder -join ',') -replace (',',",`n")) + ') ON [PRIMARY]' + $strEndScript
        
        $arrayScript
    }
    
    End
    {
        # Clean up the environment
        Invoke-VariableBaseLine -Clean
    }
}