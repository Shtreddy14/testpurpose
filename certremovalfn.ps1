function Remove-ExpiredCertificates {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ZDWDVQAUTL03C.entcorecloud.com','CurrentUser')]
        [string]$CertificateStore
    )
    process{
        $today = Get-Date
        $path = "Cert:\LocalMachine\My"
        $sample_cert = "*.dev.advantasure.com"
        $expiredCertList = Get-ChildItem -Path $path | Where-Object -Property NotAfter -lt $today

        foreach ($sample_cert in $expiredCertList){
            if ($PSCmdlet.ShouldProcess("certificate $($sample_cert.Subject) that expired $($sample_cert.NotAfter)",'Remove')){
                Remove-Item -Path $sample_cert.PSPath -Force
            }
        }
    }
} 

Remove-ExpiredCertificates