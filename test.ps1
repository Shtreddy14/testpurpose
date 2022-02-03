param(
    [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$false)]
    [System.String]
    $spath,

    [Parameter(Mandatory=$True, Position=1, ValueFromPipeline=$false)]
    [System.String]
    $odays
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


write-output "NetworkSharePath = "$NetworkSharePath
write-output "Number of old days = "$NumberofOldDays