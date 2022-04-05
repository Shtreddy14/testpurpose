.".\CommonLibrary.ps1"
# Usage:  Get the Current Time stamp to log the timestamp
# Syntax: Get-TimeStamp
function Get-TimeStamp_test{
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}
function Get-CertificateThumbprint {
    # 
    # This will return a certificate thumbprint, null if the file isn't found or throw an exception.
    #
    [cmdletbinding()]
    param 
    (
        [parameter(Mandatory = $true)][string] $CertPath,
        [parameter(Mandatory = $false)][string] $Certpwd
    )

    try 
    {
        if (!(Test-Path $CertPath)) {
            return $null;
        }

        if ($Certpwd) {
            $sSecStrPassword = ConvertTo-SecureString -String $Certpwd -Force –AsPlainText
        }
        
        $certificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $certificateObject.Import($CertPath, $sSecStrPassword,'DefaultKeySet');

        return $certificateObject.Thumbprint.ToLower()
    } 
    catch [Exception] {
        # 
        # Catch accounts already added.
        throw $_;
    }
}

function ValidateCerts{
  # 
    # This will return a certificate installed or not.
    #
    [cmdletbinding()]
    param 
    (
       [parameter(Mandatory = $true)][string] $certThumbprint
    )
    
   # $certThumbprint="TST"+$certThumbprint
    LogWrite -logstring "Vaidating Cert .."
   # Write-Host $certThumbprint
     
    $isAlreadyInstalled=$false
    
    if(Get-ChildItem -Path Cert:\LocalMachine\my | Where-Object {$_.Thumbprint -eq $certThumbprint})
    {
         LogWrite -logstring "found .."
        $isAlreadyInstalled=$true
    }
    
    return $isAlreadyInstalled
}

function Install_Certificate {
[cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)] 
        $certPath,
        [Parameter(Mandatory=$true)]  
        $Certpwd = $null       
    )
        $certRootStore = “localMachine”
        $certStore = “My”
    LogWrite -logstring "Cert installing.."
  
    if ($Certpwd -eq $null) {
    
      LogWrite -logstring "Cert Password is missing. Getting the password"
      $Certpwd = read-host “Enter the pfx password” -assecurestring
    }
     
    $certThumbprint= Get-CertificateThumbprint -CertPath $CertPath -Certpwd $Certpwd
    LogWrite -logstring 'Thumbprint: $certThumbprint'
    if((ValidateCerts -certThumbprint $certThumbprint) -eq "true")
    {    LogWrite -logstring "Cert already installed"
  
    }
    else
    {
        $pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $pfx.import($certPath,$Certpwd,“Exportable,PersistKeySet”)       
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($certStore,$certRootStore)
        $store.open(“MaxAllowed”)
        $store.add($pfx)
        $store.close();
        LogWrite -logstring "Cert  installed" 
    }
 }

function Install_ADFS_ServiceCommCertifcate{
[cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)] 
        $certPath,
        [Parameter(Mandatory=$true)]  
        $Certpwd = $null)
        LogWrite -logstring 'Installing Service communication certificates'
        Install_Certificate -certPath $certPath -Certpwd $Certpwd
        
         
        $NewThumbprint= Get-CertificateThumbprint -CertPath $CertPath -Certpwd $Certpwd   
        
        if((ValidateCerts -certThumbprint $NewThumbprint) -eq "true")
        {
            #Setting the ADFS ADFS Certificate
            #Set-AdfsCertificate -IsPrimary -CertificateType "Service-Communications" -Thumbprint ‎$NewThumbprint
        }
}

function Install_SSOCertificate {
[cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)] 
        $certPath,
        [Parameter(Mandatory=$true)]  
        $Certpwd = $null,
        [Parameter(Mandatory=$true)]  
        $CertUser,
        [Parameter(Mandatory=$true)]  
        $ADFS_URL,
        [Parameter(Mandatory=$true)]  
        $RootFolderPath
    )
        LogWrite -logstring 'Installing SSO certificates'
        Install_Certificate -certPath $certPath -Certpwd $Certpwd
        
        $NewThumbprint= Get-CertificateThumbprint -CertPath $CertPath -Certpwd $Certpwd   
        
        if((ValidateCerts -certThumbprint $NewThumbprint) -eq "true")
        {
            #Set-AdfsCertificate -IsPrimary -CertificateType "Token-Signing" -Thumbprint ‎$NewThumbprint
            #Set-AdfsCertificate -IsPrimary -CertificateType "Token-Decrypting" -Thumbprint ‎$NewThumbprint

            LogWrite -logstring "Granting the Access to IIS_Isers"
            Grant_User_Access  -userName IIS_IUSRS -permission FullControl -certStoreLocation \LocalMachine\My -certThumbprint $NewThumbprint
            LogWrite -logstring "Granting the Access to Application accounts"
            Grant_User_Access  -userName $CertUser -permission FullControl -certStoreLocation \LocalMachine\My -certThumbprint $NewThumbprint
        
            LogWrite -logstring "Updating the thumbprint in all the Relying party applications with $NewThumbprint"
            $ADFS_URL=$ADFS_URL+'/adfs/services/trust'
            Write-Host $ADFS_URL
            LogWrite -logstring "Searching Thumbprint for the ADFS URL $ADFS_URL"
            UpdateAllRP_ThumbPrint_webconfigs -ADFSURL $ADFS_URL -newThumbprintValue $NewThumbprint -RootFolderPath $RootFolderPath
        }
        else{
             LogWrite -logstring 'Cert not installed'
             Write-Host 'Cert not installed ' -ForegroundColor Red
        }
}
 
function Grant_User_Access {
param(
    [string]$userName,
    [string]$permission,
    [string]$certStoreLocation,
    [string]$certThumbprint
);
# check if certificate is already installed
$certificateInstalled = Get-ChildItem cert:$certStoreLocation | Where thumbprint -eq $certThumbprint

# download & install only if certificate is not already installed on machine
if ($certificateInstalled -eq $null)
{
     LogWrite -logstring 'Certificate with thumbprint:$certThumbprint+" does not exist at $certStoreLocation'
     Write-Host 'Certificate not exist' -ForegroundColor Red
     return
}
else
{
    try
    {
        $rule = new-object security.accesscontrol.filesystemaccessrule $userName, $permission, allow
        $root = "c:\programdata\microsoft\crypto\rsa\machinekeys"
        $l = ls Cert:$certStoreLocation
        $l = $l |? {$_.thumbprint -like $certThumbprint}
        $l |%{
            $keyname = $_.privatekey.cspkeycontainerinfo.uniquekeycontainername
            $p = [io.path]::combine($root, $keyname)
            if ([io.file]::exists($p))
            {
                $acl = get-acl -path $p
                $acl.addaccessrule($rule)
                echo $p
                set-acl $p $acl
            }
        }
    }
    catch 
    {
         LogWrite -logstring  "Caught an exception:"
         LogWrite -logstring  "$($_.Exception)"
        exit 1;
    }    
}} 

function UpdateAllRP_ThumbPrint_webconfigs{
[CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ADFSURL,
        [Parameter(Mandatory)]
        [string]$newThumbprintValue,
        [Parameter(Mandatory)]
        [string] $RootFolderPath
    )
    $AdministrationPath=$RootFolderPath+'\Administration'
    $ClaimsPath=$RootFolderPath+'\Claims'
    $EnrollmentPath=$RootFolderPath+'\Enrollment'
    $OldEnrollmentPath=$RootFolderPath+'\MedicareGW'

    if (Test-Path $AdministrationPath){
        LogWrite -logstring "Updating the Administration Thumbprint value"
        UpdateThumbPrint_webconfig -URL $ADFSURL -newThumbprintValue $newThumbprintValue -AppFolderName_path $AdministrationPath
    }
    if (Test-Path $ClaimsPath){
        LogWrite -logstring "Updating the Claims Thumbprint value"
        UpdateThumbPrint_webconfig -URL $ADFSURL -newThumbprintValue $newThumbprintValue -AppFolderName_path $ClaimsPath
    }
    if (Test-Path $EnrollmentPath){ 
        LogWrite -logstring "Updating the Enrollment Thumbprint value"
        UpdateThumbPrint_webconfig -URL $ADFSURL -newThumbprintValue $newThumbprintValue -AppFolderName_path $EnrollmentPath
    }
    if (Test-Path $OldEnrollmentPath) {
    LogWrite -logstring "Updating the MedicareGW Thumbprint value"
        UpdateThumbPrint_webconfig -URL $ADFSURL -newThumbprintValue $newThumbprintValue -AppFolderName_path $OldEnrollmentPath
    }


}
function UpdateThumbPrint_webconfig{
[CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$URL,
        [Parameter(Mandatory)]
        [string]$newThumbprintValue,
        [Parameter(Mandatory)]
        [string] $AppFolderName_path
    )
    

$CONFIG_PATH=$AppFolderName_path+"\web.config"
if (!(Test-Path $CONFIG_PATH)){ return;   }
$timestamp = (Get-Date -Format yyyyMMddHHmmss)
$target_filename= "{0}\Web_{1}.config" -f $AppFolderName_path, $timestamp

Copy-Item $CONFIG_PATH -Destination $target_filename

$FileContent = Get-Content $CONFIG_PATH
$search="<trustedIssuers>"
$foundMatch= 0
ForEach($line in $FileContent){
    $line1= $line | Select-String $URL | Select-Object -ExcludeProperty Line
    if( $line1 -ne $null){
        if($line1.ToString() -clike "*thumbprint*" -and $line1.ToString().Replace(" ","").EndsWith('/>') -and $line1.ToString().Replace(" ","").StartsWith('<add')){ 
            $line2= $line1 | Select-String $newThumbprintValue | Select-Object -ExcludeProperty Line
            if($line2 -ne $null){
                $msg= "name and thumbprint already exists"
                Write-Host $msg
                $foundMatch= 1
            }
            else{
                $textToAdd= '<add thumbprint="' +$newThumbprintValue + '"' + ' name="'+$URL+'" />'
                $FileContent -replace $line1, $textToAdd | Set-Content $CONFIG_PATH
                $FileContent = Get-Content $CONFIG_PATH
                $foundMatch= 1
            }
        }
    }
}

    if ($foundMatch -eq 0){
        $NewthumbPrintLine="`n" + '<add thumbprint="' +$newThumbprintValue + '"' + ' name="'+$URL+'" />'
        $linenumber= Get-Content $CONFIG_PATH | select-string $search
        $lineNo= $linenumber.LineNumber
        $FileContent[$lineNo-1] += $NewthumbPrintLine
        $FileContent | Set-Content $CONFIG_PATH
    }
}
 
#update_THPRINT -URL 'http://bcbsksg-adfs.test.advantasure.com/adfs/services/trust' -Thumb '0976123456789012345678980'