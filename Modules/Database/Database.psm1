# Different functions for connecting to various types of databases

<#
    Version 0.2
    - Function : Submit-PSobjectToDatabase : Updated : Now identifies if field is [int], and submits as such
#>

function Connect-MsSqlDatabase 
{ # Connects to a Microsoft SQL Server, and executes a query. 
    PARAM 
    (
        [String]$Server,
        [String]$Database = "Master",
        [String]$Username,
        [String]$Password,
        [String]$Query = $(Throw "How are you gonna run a SQL query, without the query..!"),
        [Switch]$Kerberos,
        [Switch]$Debug
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
            Write-Host -ForegroundColor Red "Username and Password must be set when not performing a Trusted (Kerberos) connection"
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
        Write-Error -Message -ForegroundColor Red "Something went wrong while connecting to the database. Check your work!"
    }
	
    # Clean up:
    $objConnection.Close()
    $constructorSqlCommand.Dispose()
    rv Password -ErrorAction SilentlyContinue
    rv Username -ErrorAction SilentlyContinue
    rv objConnection -ErrorAction SilentlyContinue
    rv Query -ErrorAction SilentlyContinue
    rv strCommand -ErrorAction SilentlyContinue
	
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
                $strBuilder += $column.Name
                
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