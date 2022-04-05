#$CONFIG_PATH="C:\Test"

<#
 Validate the ADFS Certificate same or not between Sigining and Decryption.
#>

function Validate_ADFS_SIGNING_DECRYPT_CERT {
    $thumbprint_sign=(Get-ADFSCertificate -CertificateType "Token-Signing" | Out-String -Stream | select-string "Thumbprint      :").tostring().Split(':')[1].trim()
    $thumbprint_decr=(Get-ADFSCertificate -CertificateType "Token-Decrypting" | Out-String -Stream | select-string "Thumbprint      :").tostring().Split(':')[1].trim()


    #$CONFIG_THUMB=(select-string "thumbprint=" $CONFIG_PATH\Administration\web.config).tostring().split('=')[1].split(' ')[0].replace('"','')

    if ($thumbprint_sign -eq $thumbprint_decr)
     # -and ($thumbprint_sign -eq $CONFIG_THUMB)) 
     {
        write-host "PASS: Both Certs are same"
    } else {
        write-host "FAIL: Certificates are different. Please CHECK" -ForegroundColor Red
    }
}

<#
 Validate the ADFS Certificate Expiry dates
#>

function ADFS_CERT_EXIPRYDATE{
    $after_date_sign=(Get-ADFSCertificate -CertificateType "Token-Signing" | Out-String -Stream | select-string "After" -Context 0,1 | out-String -stream | select-string "PM","AM").tostring().trim()
    $today_date_sign=date
    if((get-date $after_date_sign) -lt (get-date $today_date_sign)) {
        write-host "FAIL: Certificate is expiry" -ForegroundColor Red
    } else {
        write-host "PASS: Certificate still Valid."
    }

    $after_date_decr=(Get-ADFSCertificate -CertificateType "Token-Decrypting" | Out-String -Stream | select-string "After" -Context 0,1 | out-String -stream | select-string "PM","AM").tostring().trim()
    $today_date_decr=date
    if((get-date $after_date_decr) -lt (get-date $today_date_decr)) {
        write-host "FAIL: Certificate is expiry" -ForegroundColor Red
    } else {
        write-host "PASS: Certificate still Valid."
    }
}

<#
 Validate the ADFS Service running in the server
#>

function Validate_ADFS_SERVICE_Status {
    $ADFSSRV_STATUS=(Get-Service adfssrv | out-string -stream | select-string "Running").tostring().split(' ')[0].trim()
    if($ADFSSRV_STATUS -ne "Running") {
        Write-Host "FAILE: ADFS Service is not running. Please check" -ForegroundColor Red
    } else {
        Write-Host "PASS: ADFS Service is running."
    }
}

<#
 Validate the Federated Meta data URL for every folder
#>

function Validate_FederatedURL
{
[cmdletbinding()]
 param( 
 [Parameter(Mandatory=$true)]
 [string]$FolderPath
 )
  
  
  if(test-path $Administration_ConfigPath)
  {
    $COUNT=(select-string "FederationMetadataLocation" $FolderPath+"\ClientSettings\ClientAppSettings.xml" | out-string -stream | select-string "/>").Matches.count
    Write-Host $COUNT entries found in Client Appsettings.xml file -ForegroundColor Green
    if ($COUNT -gt 1)
    {
        Write-Host 'There are multiple FederationMetadataLocation entries in '+ $FolderName+'. Please check the site Config'   -ForegroundColor Green
     }
  }
  
  $COUNTWEBCONFIG=(select-string "FederationMetadataLocation" $FolderPath\web.config | out-string -stream | select-string "/>").Matches.count
  Write-Host $COUNTWEBCONFIG entries found in web config file -ForegroundColor Green
  
  if ($COUNTWEBCONFIG -gt 1)
  {
        Write-Host 'There are multiple FederationMetadataLocation entries in '+ $FolderName+'. Please check the site Config'   -ForegroundColor Green
  }

  If ($COUNT -eq 0 -and $COUNTWEBCONFIG -eq 0)
  {
    Write-Host "ERROR: FederationMetadataLocation string is not found in either of the config files. Please check it" -ForegroundColor Red
  }
  If ($COUNT -eq 1)  {
    $FEDERATION_URL=(select-string "FederationMetadataLocation" $FolderPath\ClientSettings\ClientAppSettings.xml | out-string -stream | select-string "/>").tostring().split('=')[1].split(' ')[0].replace('"','').trim()
  }
  If ($COUNTWEBCONFIG -eq 1)  {
    $FEDERATION_URL=(select-string "FederationMetadataLocation" $FolderPath\web.config | out-string -stream | select-string "/>").tostring().split('=')[1].split(' ')[0].replace('"','').trim()
  }
  if ($FEDERATION_URL -ne $null)
  {
    $STATUS_CODE=(Invoke-WebRequest -Uri $FEDERATION_URL).StatusCode
    Write-Host $FEDERATION_URL
    if($STATUS_CODE -ne 200) 
    {Write-Host "FAIL: Federation url response is not 200. Please check" -ForegroundColor Red} 
     else {Write-Host "PASS: Federation url response is 200"}
   }
 }

 <#
 Validate the Federated Meta data URL for every folder
#>

function Get_ThumbPrintFromConfig
{
[cmdletbinding()]
 param( 
 [Parameter(Mandatory=$true)]
 [string]$FolderPath
 )
 return (select-string "thumbprint=" $FolderPath\web.config).tostring().split('=')[1].split(' ')[0].replace('"','')
 }
 <#
 Validate the Certificate Name with Accounts web config
#>

function Validate_Certificate_Name{
[CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CONFIG_PATH)
    
    $sign_cert_value=(Get-ADFSCertificate -CertificateType "Token-Signing" | Out-String -Stream | select-string "Subject" -Context 0,1 | Out-String -Stream | Select-String "CN").tostring().Split(',')[0].Trim().Split('=')[1]
    if( (test-path $CONFIG_PATH\Accounts\Clientsettings\ClientAppSettings.xml) -and ((select-string "SigningCertificateName" $CONFIG_PATH\Accounts\Clientsettings\ClientAppSettings.xml) -ne $null) )
    {
       $AppCertNameValue=(select-string "SigningCertificateName" $CONFIG_PATH\Accounts\Clientsettings\ClientAppSettings.xml).toString().trim().split('=')[3].split(',')[0].trim()
    }
    else
    { 
     if ( (select-string "SigningCertificateName" $CONFIG_PATH\Accounts\web.config) -ne $null) 
     {
        $AppCertNameValue=(select-string "SigningCertificateName" $CONFIG_PATH\Accounts\web.config).toString().trim().split('=')[3].split(',')[0].trim()
     }
    }

    If (($AppCertNameValue -ne $null) -and ($AppCertNameValue -ne ""))
    {
       if($sign_cert_value -eq $AppCertNameValue) {
            Write-Host  "PASS: Certificate Name match with IDP"
        } else {
            Write-Host  "FAIL: Certificates Name not matched betweeb ADFS Cert and IDP configuration. Please check" -ForegroundColor Red
        }
    }
}

<#
 Validate the Thumbpring and Federated meta data location for all the relying party
#>
function Validate_Relying_Party_Values {
[CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CONFIG_PATH)

    $thumbprint_sign=(Get-ADFSCertificate -CertificateType "Token-Signing" | Out-String -Stream | select-string "Thumbprint      :").tostring().Split(':')[1].trim()
    $Administration_ConfigPath= $CONFIG_PATH+"\Administration"
    $Claims_ConfigPath= $CONFIG_PATH+"\Claims"
    $Enrollment_ConfigPath= $CONFIG_PATH+"\Enrollment"
    $MedicareGW_ConfigPath= $CONFIG_PATH+"\MedicareGW"

    if(test-path $Administration_ConfigPath)
    {
        Validate_FederatedURL -FolderPath $Administration_ConfigPath 
        $Admin_THUMB=Get_ThumbPrintFromConfig -FolderPath $Administration_ConfigPath
        
        if($thumbprint_sign -eq $Admin_THUMB)
        {
          Write-Host  "PASS: Certificate ThuumbPrint match with Adminsitration config file"
        }
        else
        {
            Write-Host  "FAIL: Certificate ThuumbPrint NOT match with Adminsitration config file" -ForegroundColor Red
        }
        
    }
    if(test-path $Claims_ConfigPath)
    {
        Validate_FederatedURL -FolderPath $Claims_ConfigPath
        $claim_THUMB=Get_ThumbPrintFromConfig -FolderPath $Claims_ConfigPath
        if($thumbprint_sign -eq $claim_THUMB)
        {
          Write-Host  "PASS: Certificate ThuumbPrint match with Claims config file"
        }
        else
        {
            Write-Host  "FAIL: Certificate ThuumbPrint NOT match with Claims config file" -ForegroundColor Red
        }         
    }
    
    if(test-path $Enrollment_ConfigPath)
    {
        Validate_FederatedURL -FolderPath $Enrollment_ConfigPath
        $ENRL_THUMB=Get_ThumbPrintFromConfig  -FolderPath $Enrollment_ConfigPath
        if($thumbprint_sign -eq $ENRL_THUMB)
        {
          Write-Host  "PASS: Certificate ThuumbPrint match with Enrollment config file"
        }
        else
        {
            Write-Host  "FAIL: Certificate ThuumbPrint NOT match with Enrollment config file" -ForegroundColor Red
        }
        
    }
    else
    {
        if(test-path $MedicareGW_ConfigPath)
        {
            Validate_FederatedURL -FolderPath $MedicareGW_ConfigPath
            $ENRL_THUMB=Get_ThumbPrintFromConfig -FolderPath $MedicareGW_ConfigPath
            if($thumbprint_sign -eq $ENRL_THUMB)
            {
              Write-Host  "PASS: Certificate ThuumbPrint match with Enrollment config file"
            }
            else
            {
                Write-Host  "FAIL: Certificate ThuumbPrint NOT match with Enrollment config file" -ForegroundColor Red
            }
            
        }
    }
     
}


 <#
function signing_certificate_validation() {
    # Checking for Certification value.
    $sign_cert_value=(Get-ADFSCertificate -CertificateType "Token-Signing" | Out-String -Stream | select-string "Subject" -Context 0,1 | Out-String -Stream | Select-String "CN").tostring().Split(',')[0].Trim().Split('=')[1]
    if ( (select-string "SigningCertificateName" $CONFIG_PATH\Accounts\web.config) -ne $null) {
        $file1_sign_cert=(select-string "SigningCertificateName" $CONFIG_PATH\Accounts\web.config).toString().trim().split('=')[3].split(',')[0].trim()
        if($sign_cert_value -eq $file1_sign_cert) {
            echo "SUCCESS: Both the certs are equal"
        } else {
            echo "ERROR: Certificates are not same. Please check"
        }
    } else {
        if( (test-path $CONFIG_PATH\Accounts\Clientsettings\ClientAppSettings.xml) -and ((select-string "SigningCertificateName" $CONFIG_PATH\Accounts\Clientsettings\ClientAppSettings.xml) -ne $null) ){
            $file2_sign_cert=(select-string "SigningCertificateName" $CONFIG_PATH\Accounts\Clientsettings\ClientAppSettings.xml).toString().trim().split('=')[3].split(',')[0].trim()
            if($sign_cert_value -eq $file2_sign_cert) {
                echo "SUCCESS: Both the certs are equal"
            } else {
                    echo "ERROR: Certificates are not same. Please check"
            }
        }else {
            echo "ERROR: SigningCertificateName is not found in any of the file. Please check"
        }
    }
}

function federation_url_validation() {
    # Checking the no.of occurences of "FederationMetadataLocation" string
    $COUNT=(select-string "FederationMetadataLocation" $CONFIG_PATH\Administration\web.config | out-string -stream | select-string "/>").Matches.count
    if($COUNT -eq 0) {
        $COUNT1=(select-string "FederationMetadataLocation" $CONFIG_PATH\Administration\Clientsettings\ClientAppSettings.xml | out-string -stream | select-string "/>").Matches.count
        if($COUNT1 -eq 0) {
            echo "ERROR: FederationMetadataLocation string is not found in either of the config files. Please check it"
        } else {
            if($COUNT1 -gt 1) {
                echo "ERROR: The website will be failed as there are multiple occurences of FederationMetadataLocation"
            } else {
                $FEDERATION_URL=(select-string "FederationMetadataLocation" $CONFIG_PATH\Administration\Clientsettings\ClientAppSettings.xml | out-string -stream | select-string "/>").tostring().split('=')[1].split(' ')[0].replace('"','').trim()
                $STATUS_CODE=(Invoke-WebRequest -Uri $FEDERATION_URL).StatusCode

                if($STATUS_CODE -ne 200) {
                    echo "ERROR: Federation url response is not 200. Please check"
                } else {
                    echo "SUCCESS: Federation url response is 200"
                }
            }
        }
    }
    elseif($count -gt 1 ){
        echo "ERROR: The website will be failed as there are multiple occurences of FederationMetadataLocation"
    } else {
        $FEDERATION_URL=(select-string "FederationMetadataLocation" $CONFIG_PATH\Administration\web.config | out-string -stream | select-string "/>").tostring().split('=')[1].split(' ')[0].replace('"','').trim()
        $STATUS_CODE=(Invoke-WebRequest -Uri $FEDERATION_URL).StatusCode

        if($STATUS_CODE -ne 200) {
            echo "ERROR: Federation url response is not 200. Please check"
        } else {
            echo "SUCCESS: Federation url response is 200"
        }
    }
}
#>
function Validate_ADFS_ConfigSettings{[CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Web_CONFIG_PATH)

    #Checking the ADFS cert settings
    Validate_ADFS_SIGNING_DECRYPT_CERT
    #Checking the ADFS cert exipiry dates
    ADFS_CERT_EXIPRYDATE
    #Checking the ADFS Server running status
    Validate_ADFS_SERVICE_Status 
    #Validating the ADFS Sigining certificate name with Accounts
    Validate_Certificate_Name -CONFIG_PATH $Web_CONFIG_PATH
    #Validating the ADFS Relying party Thumbprint values with Certificate
    Validate_Relying_Party_Values -CONFIG_PATH $Web_CONFIG_PATH
 }

 Validate_ADFS_ConfigSettings -Web_CONFIG_PATH "c:\test\" # Root folder of the Accounts,Administration,Claims and Enrollment folder