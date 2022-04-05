$cert_path= "C:\ADFStest\wc_dev_advantasure.pfx"
$cert= Get-ChildItem $cert_path
$msg= "certificate already installed"
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store "My", "LocalMachine"
$pfx= New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$pfx.Import($cert_path)
$store.Open("ReadWrite")
$store.Add($pfx)
$store.Close()

$newthumb= $pfx.Thumbprint
Write-Host $newthumb
$Config_Path= "Cert:\localmachine\My"
$certs= Get-ChildItem $Config_Path -Recurse
$count= 0
ForEach($Cert in $certs){
    if($Cert.NotAfter -lt(Get-Date))
    {
        $Cert | Remove-Item
    }
    elseIf($Cert.Thumbprint -eq $newthumb)
    {
        Write-Host $msg
        $count=1
    }
}