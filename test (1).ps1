param(
    [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$false)]
    [System.String]
    $spath,

    [Parameter(Mandatory=$True, Position=1, ValueFromPipeline=$false)]
    [System.String]
    $odays,
	
	[parameter(Mandatory=$false,Position=2)]
    [ValidateSet('Report','Delete')]
    [String] $Action = 'Delete',
	
    [parameter(Mandatory=$false,Position=3)]
    [String] $DriveName = "z",
	
    [parameter(Mandatory=$false,Position=4)]
    $AuditLogFolderName = 'Auditlog',
	
	[parameter(Mandatory=$false,Position=5)]
    [String] $UserName='.\accountname',
	
    [parameter(Mandatory=$false,Position=6)]
    [String] $Password='mypass'
	
)

$sharepath = $spath
$days = $odays
$NumberofOldDays = $days

$app1 = "application1"
$app2 = "application2"
$app3 = "application3"
$app4 = "application4"
$app5 = "application5"
$app6 = "application6"

if($sharepath -eq $app1){
    $NetworkSharePath = '\\192.168.4.5\MyShare1'
}
elseif ($sharepath -eq $app2) {
    $NetworkSharePath = '\\192.168.4.5\MyShare2'
}
elseif ($sharepath -eq $app3) {
    $NetworkSharePath = '\\192.168.4.5\MyShare3'
}
elseif ($sharepath -eq $app4) {
    $NetworkSharePath = '\\192.168.4.5\MyShare4'
}
elseif ($sharepath -eq $app5) {
    $NetworkSharePath = '\\192.168.4.5\MyShare5'
}
elseif ($sharepath -eq $app6) {
    $NetworkSharePath = '\\192.168.4.5\MyShare6'
}
else{
    write-output "sharepath is not defined properly"
}



Try
{
   $OldErrorActionPreference= $ErrorActionPreference; 
   $OldErrorActionPreference= "SilentlyContinue"; 
   $OverallExecutionStatus = 0;
   $NetworkCredential = $null;
   $SecurePass = ConvertTo-SecureString -String $Password -AsPlainText -Force;
   $NetworkCredential = New-Object -TypeName System.Management.Automation.PSCredential($UserName,$SecurePass);
   Try
   {        
        New-PSDrive -Name $DriveName -PSProvider FileSystem -Root $NetworkSharePath -Credential $NetworkCredential -Persist -Scope global -Confirm:$false|Out-Null;
        $InternalSharePath = $DriveName +":";
        
        if(Test-Path -Path $InternalSharePath )
        {
            $TempAuditLogLocation = '';
            
            $TempAuditLogLocation = $($InternalSharePath + '\'+ $AuditLogFolderName);
            $FullAuditLogLocation = '';
            $FullAuditLogLocation = $($NetworkSharePath + '\'+ $AuditLogFolderName);
            $AuditLog = "$TempAuditLogLocation\AuditLog_"  +$(get-date -format dd-MM-yyyy-HH-mm-ss)+ "_AuditLog.csv";
            $ErrorLog = "$TempAuditLogLocation\ErrorLog_"  +$(get-date -format dd-MM-yyyy-HH-mm-ss)+ "_ErrorLog.txt";
            if(!(Test-Path -Path $TempAuditLogLocation))
            {
                New-Item -Path $TempAuditLogLocation -ItemType Directory  -Force -Confirm:$false|Out-Null;
            }
        }
        else
        {
           Write-Error "Unable to access the Network share : $NetworkSharePath so script will exit now. Please fix the error & re-run the script. ";
           $OverallExecutionStatus = 1;
           Throw "Unable to access the Network share : $NetworkSharePath so script will exit now. Please fix the error & re-run the script. ";
           Exit 1; 
        }
   }
   Catch [System.Exception]
   {
        Write-Error "There is an Error : $($_.Exception.Message) . script will exit now. Please fix the error & re-run the script. ";
        $OverallExecutionStatus = 1;
        Throw "There is an Error : $($_.Exception.Message) . ";
        Exit 1;
   }

   $DateToRefer = [DateTime] $((Get-Date).AddDays(-$NumberofOldDays));
   if($Action -eq 'Report')
   {
        Get-ChildItem -Path $InternalSharePath -Recurse -Exclude "$FullAuditLogLocation*"  | ? {($_.FullName -notlike "$TempAuditLogLocation*") -and  ($_.LastWriteTime -lt ($DateToRefer)) } |Select-Object @{Name='FullPath';Expression = { $($NetworkSharePath +'\' +$_.Name)}},@{Name='LastModified';Expression = {$_.LastWriteTime}}|Export-Csv $AuditLog -Append -NoTypeInformation -Force -Confirm:$false;
   }
   elseif($Action -eq 'Delete')
   {
        Get-ChildItem -Path $InternalSharePath -Recurse -Exclude "$FullAuditLogLocation*"  | ? { ($_.FullName -notlike "$TempAuditLogLocation*") -and  ($_.LastWriteTime -lt ($DateToRefer)) } |  
        ForEach-Object{
        
            $DeleteStatus = '';
            $FullPath = '';
            $FullPath = $($NetworkSharePath +'\' +$_.Name);
            $LastModified = $($_.LastWriteTime);
            $DeletedOn = '';
            $ErrMessage = '';

            Try
            {
                $DeletedOn = [String] $(Get-Date -Format dd-MM-yyyy-hh-mm-ss);
                Remove-Item -Path $($_.FullName) -Force -Confirm:$false -ErrorAction SilentlyContinue;
                $DeleteStatus = 'Success';
                $ErrMessage = '';

            }
            Catch [System.Exception]
            {
                $ErrMessage = [String] $($_.Exception.Message);
                $DeleteStatus = 'Failed';
            }
            finally
            {
                $CustomObject = [psCustomObject] @{
                                                    FullPath = $FullPath;
                                                    LastModified = $LastModified;
                                                    DeletedOn = $DeletedOn;
                                                    DeleteStatus = $DeleteStatus;
                                                    Error= $ErrMessage;
                                              };

                $CustomObject|Export-Csv $AuditLog -Append -NoTypeInformation -Force -Confirm:$false;

            }
        }        
   }
}
Catch [System.Exception]
{
    Write-Error "There is an Error : $($_.Exception.Message) ";
    $OverallExecutionStatus = 1;
    $ErrorMessageForDisplay = [string] "$(Get-Date -Format dd-MM-yyyy-hh-mm-ss) There is an Error : $($_.Exception.Message) ";
}
Finally
{
    if($OverallExecutionStatus -eq 0)
    {
        Write-Output "Script Execution is successsful.";
    }
    else
    {
        Write-Output "Script Execution completed with some errors. `n*********************************************************`n$ErrorMessageForDisplay`n*********************************************************";
    }
    Remove-PSDrive -Name $DriveName -Scope global -Force -Confirm:$false ;
    $ErrorActionPreference =$OldErrorActionPreference; 
}