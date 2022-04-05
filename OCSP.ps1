#get a list of certs
#Get-ChildItem -Path Cert:\localmachine\my



#install certificate lo machine
function Install-PfxCertificate ($certPath, [string]$storeLocation = "ZDWDVQAUTL03C", [string]$storeName = "ADFStest")
{
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath, "C:\ADFStest\wc_dev_advantasure.pfx", "MachineKeySet,PersistKeySet")
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
    $store.Open("ReadWrite")
    $store.Add($cert)
    $store.Close()
    "Thumbprint: $($cert.Thumbprint)"
}

Install-PfxCertificate "C:\ADFStest\wc_dev_advantasure.pfx"


#check expired certificate and delete them
function Remove-ExpiredCertificates {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ZDWDVQAUTL03C.entcorecloud.com','CurrentUser')]
        [string]$CertificateStore
    )
    process{
        $today = Get-Date
        $path = "Cert:\$CertificateStore\ADFStest"
        $expiredCertList = Get-ChildItem -Path $path | Where-Object -Property NotAfter -lt $today

        foreach ($certificate in $expiredCertList){
            if ($PSCmdlet.ShouldProcess("certificate $($certificate.Subject) that expired $($certificate.NotAfter)",'Remove')){
                Remove-Item -Path $certificate.PSPath -Force
            }
        }
    }
} 


#grant permissions
Import-Module webadministration
#
# $certCN is the identifiying CN for the certificate you wish to work with
# The selection also sorts on Expiration date, just in case there are old expired certs still in the certificate store.
#  Make sure we work with the most recent cert 
$certCN = "mycert"
Try
{
$WorkingCert = Get-ChildItem CERT:\ZDWDVQAUTL03C.entcorecloud.com\ADFStest |where {$_.Subject -match $certCN} | sort $_.NotAfter -Descending | select -first 1 -erroraction STOP
    $TPrint = $WorkingCert.Thumbprint
    $rsaFile = $WorkingCert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
}
Catch
{
    "        Error: unable to locate certificate for $($CertCN)"
    Exit
}
$keyPath = "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\"
$fullPath=$keyPath+$rsaFile
$acl=Get-Acl -Path $fullPath
$permission="Authenticated Users","Read","Allow"
$accessRule=new-object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.AddAccessRule($accessRule)
Try
{
    Set-Acl $fullPath $acl
    "        Success: ACL set on certificate"
}
Catch
{
    "        Error: unable to set ACL on certificate"
    Exit
}
