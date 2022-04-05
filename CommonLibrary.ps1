####################################### GENERAL FUNCTIONS###################################################
# This file has all necessary defintions and functions for create web site configuration
# Authour : Navaneethan Jayapal
# Created Date: 10/01/2018
function Set-LogFileName
{
	[CmdletBinding()]
	Param (
		$Value
	)
	
	$script:var = $Value
}

function Get-LogFileName
{
	[CmdletBinding()]
	Param (
	
	)
	
	$script:var
}


# Usage:  Get the Current Time stamp to log the timestamp
# Syntax: Get-TimeStamp
function Get-TimeStamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}

# Usage:  Log the content to the appropriate  log file
# Syntax: LogWrite -logstring "log messages" -LogFile "logFileName"

function LogWrite([string]$logstring) {
    $LogFile= Get-LogFileName  
    if($LogFile -eq "") 
    {  Write-Debug "FilePath is empty"
        $LogFile=.\Output.txt
        Set-LogFileName .\Output.txt
    }
	$finalText = "{0} {1}" -f $(Get-TimeStamp),$logstring
	Write-Output "$finalText" | Tee-Object $LogFile -append
}

####################################### GENERAL FUNCTIONS###################################################
####################################### FOLDER CREATION FUNCTIONS ###################################################
# CreateApplicationFolder

# Usage  :  Create a folder based on the parameter, If the folder is not exits, will create one, if it's exists it won't create
# Syntax :  CreateApplicationFolder -folderName "D:\UserDocuments";

function CreateApplicationFolder{
[cmdletbinding()]
param(
[Parameter(Mandatory=$true)]
[string]$folderName
)
    if(!(Test-Path -Path $folderName))
    {
        New-Item -ItemType directory -Path $folderName
        LogWrite -logstring "Folder Name $folderName is created." 
    }
    else
    {
        LogWrite -logstring "Folder Name $folderName already exists." 
    }
}

####################################### FOLDER CREATION FUNCTIONS ###################################################


####################################### Files and FOLDER PERMISSIONS GRANT###################################################

# Usage  : Grant the permissions for particular user for list of files.
# Syntax : Grant-FilesFullRights - Files d:\temp\test1.txt -UserName ikasystems\njayapal

function Grant-FilesFullRights {
 [cmdletbinding()]
 param( 
 [Parameter(Mandatory=$true)]
 [string[]]$Files, 
 [Parameter(Mandatory=$true)]
 [string]$UserName 
 )
 
 $rule=new-object System.Security.AccessControl.FileSystemAccessRule ($UserName,"FullControl","Allow")

 foreach($File in $Files) {
  if(Test-Path $File) 
  {
       try 
       {
            LogWrite -logstring "Setting the File permission"
            $acl = Get-ACL -Path $File -ErrorAction stop
            $acl.SetAccessRule($rule)
            Set-ACL -Path $File -ACLObject $acl -ErrorAction stop
            LogWrite -logstring "Successfully set permissions on $File"
       } 
       catch 
       {
            LogWrite -logstring  "$File : Failed to set perms. Details : $_"
            Continue
       }
  } 
  else 
  {
        LogWrite -logstring  "$File : No such file found"
        Continue
  }
 }

}
# Usage  : Check the permissions for particular user to the particular folder or not
# Syntax : checkFolderRights -FolderName d:\temp  -UserName ikasystems\njayapal
function checkFolderRights{
 [cmdletbinding()]
 param( 
 [Parameter(Mandatory=$true)]
 [string[]]$FolderName,
 [Parameter(Mandatory=$true)]
  [string]$UserName
 )
 
    $hasRighstforUser="true"
    $perm=(Get-Acl $FolderName).Access | where {$_.IdentityReference -eq $UserName}|select FileSystemRights
     
    if(!$perm)
    {
      LogWrite -logstring "$UserName doesn't have rights for this folder $FolderName"
       $hasRighstforUser= "false"
    }
    else
    {
        $permrights=($perm).FileSystemRights
        LogWrite -logstring "$UserName has $permrights rights for this folder $FolderName"
        $hasRighstforUser="true"
    }
    return $hasRighstforUser
 }

 

# Usage  : Grant the permissions for particular user to the particular folders including  subfolders
# Syntax : Grant-FolderFullRights - FolderName d:\temp  -UserName ikasystems\njayapal
function Grant-FolderFullRights{
 [cmdletbinding()]
 param( 
 [Parameter(Mandatory=$true)]
 [string[]]$FolderName,
 [Parameter(Mandatory=$true)]
 [string]$UserName
 )
    $hasRighstforUser="true"
    
    $hasRighstforUser= checkFolderRights  -FolderName $FolderName  -UserName $UserName
    Write-Host  $hasRighstforUser
    if($hasRighstforUser -eq "false")
    {
        $Right="FullControl"
        LogWrite -logstring "UserName :$UserName"
        try
        {

            $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($UserName,$Right, "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl = Get-Acl $FolderName    
            $acl.SetAccessRule($rule)
            Set-Acl $FolderName $acl

            foreach ($Folder in $(Get-ChildItem -Directory $FolderName -Recurse))
            {   
                #Write-Host  $Folder.FullName
                $acl = Get-Acl $Folder.FullName   
                $acl.SetAccessRule($rule)
                Set-Acl $Folder.FullName $acl
            }
            LogWrite -logstring "Folder Permission setting for the the $FolderName"
        }
        catch
        {
            LogWrite -logstring ("ERROR:  Unable to set folder Rights $($FolderName).  Exception:  " + $_.Exception) -    LogFile $LogFile
            if ($pauseAtEnd -eq $True) 
            {
                read-host "Press ENTER to continue..."
            }
		    Exit 3
            #LogWrite -logstring "ERROR:  Unable to set folder Rights"          
        }
    }
    else
    {
      LogWrite -logstring "UserName :$UserName already exisits"
    }
  }
####################################### Files and FOLDER PERMISSIONS GRANT###################################################

#############ADAM INSTANCESSS
Function Get-ADAMInstancesList {
    Param(
    [string]$file
    )
    Process
    {
        $read = New-Object System.IO.StreamReader($file)
        $serverarray = @()

        while (($line = $read.ReadLine()) -ne $null)
        {
            $serverarray += $line
        }

        $read.Dispose()
        return $serverarray
    }
}

function CreateAdamInstance{
 [cmdletbinding()]
    param(
    [Parameter(Mandatory=$true)]
    [string]$clientName,
    [Parameter(Mandatory=$true)]
    [string]$environmentName,
    [Parameter(Mandatory=$true)]
    [string]$dcname,
    [Parameter(Mandatory=$true)]
    [string]$adamPort,  
    [Parameter(Mandatory=$true)]
    [string]$adamSSLPort
    )
    
    $adamName = "{0}-{1}" -f $clientName,$environmentName
    $adamDesc = "{0} AD LDS instance" -f $clientName
    $adamPart = "O={0},DC={1},DC=COM"  -f $adamName ,$dcname
    $adamPort = $adamPort
    $adamSSLPort =  $adamSSLPort
    $adamPath = "C:\Program Files\ADAM\"


#
#    Create answer file for ADAM installation
#
    Set-Content -Path ADAM.txt "[ADAMInstall]
    InstanceName=""$adamName""
    InstanceDescription=""$adamDesc""
    LocalLDAPPortToListenOn=$adamPort
    LocalSSLPortToListenOn=$adamSSLPort
    NewApplicationPartitionToCreate=""$adamPart""
    DataFilesPath=""$adamPath$adamName""
    LogFilesPath=""$adamPath$adamName""
    ImportLDIFFiles=""ms-inetorgperson.ldf"" ""ms-user.ldf"" ""ms-userproxy.ldf"" ""ms-azman.ldf"""
     LogWrite -logstring  "Installing ADAM instances"
    Start-Process "C:\Windows\ADAM\adaminstall.exe" -ArgumentList "/answer:ADAM.txt" -Wait
 
    Set-Content -Path ADAMSTR.ldf "dn: CN=ApplicationData,$adamPart
changetype: add
objectClass: top
objectClass: container
cn: ApplicationData

dn: CN=Users,CN=ApplicationData,$adamPart
changetype: add
objectClass: top
objectClass: container
cn: Users

dn: CN=Administrators,CN=Users,CN=ApplicationData,$adamPart
changetype: add
objectClass: top
objectClass: container
cn: Administrators

dn: CN=Debuggers,CN=Users,CN=ApplicationData,$adamPart
changetype: add
objectClass: top
objectClass: container
cn: Debuggers

dn: CN=PortalUsers,CN=Users,CN=ApplicationData,$adamPart
changetype: add
objectClass: top
objectClass: container
cn: PortalUsers"

LogWrite -logstring  "Validating ADAM instances"
#
#Enable password transmission over unsecured connection
#
    dsmgmt.exe "ds b" connections "connect to server localhost:$adamPort" quit "allow passwd op on unsecured connection" quit quit quit
LogWrite -logstring  "validated"
#
#Import additional attributes from ikaSchemaExtension.ldf file
#
    ldifde -i -u -f ikaSchemaExtension.ldf -s localhost:$adamPort -c "cn=Configuration,dc=X" "#configurationNamingContext"
LogWrite -logstring  "Schema Extensions were loaded."
#
#Import ADAM Structure and users from ADAMSTR.ldf file
#
    ldifde -i -f ADAMSTR.ldf -s localhost:$adamPort  
     LogWrite -logstring "Imported ADAM Structure and users from ADAMSTR.ldf"
    Start-Sleep -s 14
    LogWrite -logstring  "Creating the users"
    New-ADUser -name "ikaAdminuser"  -UserPrincipalName "ikaAdminuser" -server  "localhost:$adamPort"  -path "CN=Administrators,CN=Users,CN=ApplicationData,$adamPart"
    New-ADUser -name "setupuser"     -UserPrincipalName "setupuser"    -server  "localhost:$adamPort"  -path "CN=PortalUsers,CN=Users,CN=ApplicationData,$adamPart"
    LogWrite -logstring  "Created the users"
    LogWrite -logstring  "Adding the adminuser into Admin role"
    $User = Get-ADUser -Identity "CN=ikaAdminuser,CN=Administrators,CN=Users,CN=ApplicationData,$adamPart" -Server "localhost:$adamPort"
    $Group = Get-ADGroup -Identity "CN=Administrators,CN=Roles,$adamPart" -Server "localhost:$adamPort"
    Add-ADGroupMember -Identity $Group -Members $User -Server "localhost:$adamPort"
    LogWrite -logstring  "Administrator role was assigned for the ikaAdminUser"
}

###########################