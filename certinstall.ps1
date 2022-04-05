 .".\CommonLibrary.ps1"
.".\certInstalLib.ps1"
 Set-LogFileName ".\certInstall.txt"
$certPath= "C:\ADFStest\New folder\dev\star__dev_advantasure.com.pfx"
$thumb=$args[0]
#Install_Certificate -certPath  $certPath -Certpwd 'D3v!_@dvant'
$config_PAth='C:\ADFStest\New folder\Configs'
$ADFSURL='https://bcbsksc-adfs.test.advantasure.com'
 $uName= 'entcorecloud\njayapal'
 $environmentName="dev"
 $certpassword="No_certs"
 $certpassword= Switch ($environmentName)
 {
       "dev" { "D3v!_@dvant";break }
       "STAGE" { "St@g3!2019@dvanT";break }
       "prod" { "Pr0d!2019@dvanT";break }
        default {"No_certs"; break}
      }
    if (!($certpassword -eq "No_certs"))
    {
       #$certPath= "C:\ADFStest\New folder\dev\star__dev.advantasure.com.pfx"     
       #$certThumbprint= Get-CertificateThumbprint  -certPath $certPath -Certpwd $certpassword
       #Write-Host 'test' $certThumbprint
       #$certThumbprint= Install_Certificate  -certPath $certPath -Certpwd $certpassword
       #Write-Host 'test' $certThumbprint
       Install_Certificate -certPath  $certPath -Certpwd $certpassword -CertUser $uName -ADFS_URL $ADFSURL -RootFolderPath $config_PAth

    }
$certs_move = Get-ChildItem -Path Cert:\CurrentUser\My\ | Where-Object {$_.Thumbprint -eq $thumb}
$certs_move | Move-Item -Destination cert:\CurrentUser\Root\
