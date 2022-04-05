 cd cert:
 $Certs = Get-ChildItem -path Cert:\LocalMachine\My\5158E42D43B56CC348696C2DBE26574765CC1DA6
 Write-host "$Certs"

 cd cert:
 $cert_path = "Cert:\LocalMachine\My\5158E42D43B56CC348696C2DBE26574765CC1DA6"
 $Certs = (Get-ChildItem -path $cert_path | select-string "After" -Context 0,1 | out-String -stream | select-string "AM").tostring().trim()
 Write-host "$Certs"
 $today = date
 $today
 if((get-date $Certs) -lt (get-date $today)) {
        write-host "FAIL: Certificate is expiry" -ForegroundColor Red
        Remove-Item "5158E42D43B56CC348696C2DBE26574765CC1DA6" -Force
    }

