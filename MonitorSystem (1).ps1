function clean_logs($path) {
	Get-ChildItem $path -Recurse | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-14) } | Remove-Item
}

function check_cpu {
    param (
        $location,
        $servername
    )

    $todaylog = "$location/cpu_logs/" + (get-date -f "yyyyMMdd") + ".csv"
    $yesterdaylog = "$location/cpu_logs/" + (Get-Date (Get-Date).AddDays(-1) -Format "yyyyMMdd") + ".csv"

    # Check if today log file exist.  Create if does not exist
    if (Test-Path $todaylog) {
        # Remove previous log files
        Get-ChildItem "$location\cpu_logs\*.csv" | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-14) } | Remove-Item
        # Get the last counter value
        [int]$counter = (Get-Content $todaylog | Select-Object -Last 1).split(", ")[-1]
    }
    else {
        # Create log file
        New-Item -ItemType File $todaylog -Force -Value "Time, CPU Percent, Counter`n"
        # Get counter value from yesterday log file
        if (Test-Path $yesterdaylog) {
            [int]$counter = (Get-Content $yesterdaylog | Select-Object -Last 1).split(", ")[-1]
        }
        else {
            [int]$counter = 0
        }
    }
    # Get CPU usage
    $processMemoryUsage=Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average | Select Average
    [int]$cpupercent = $processMemoryUsage.Average.ToString("#,0")

    # If CPU usage is above 80%, increment counter, send email at 10 minutes, 1 hour, and 8 hours
    if ($cpupercent -gt 80) {
        $counter++
        #$counter
        if ($counter -eq 2) {
            $body = "CPU usage has been above 80% for 10 minutes"
        }
        if ($counter -eq 12) {
            $body = "CPU usage has been above 80% for an hour"
        }
        if ($counter -eq 96) {
            $body = "CPU usage has been above 80% for 8 hours"
        }
    }
    # Reset counter to 0 when CPU usage drops below 60%
    else { 
        $counter = 0
    }
    $value = (get-date -f "yyyy/MM/dd HH:mm:ss") + ", " + $cpupercent + ", " + $counter
    Add-Content $todaylog -Value $value

    $email = @{
        From = "ProductionCheck@advantasure.com"
        To = "devops@advantasure.com"
        Subject = "CPU usage high on $servername"
        SMTPServer = "10.10.3.25"
        Priority = "Normal"
        Body = "$body"
    }
    if ($body){
        send-mailmessage @email
        Start-Sleep -s 15
    }

}

function check_disk {
    param (
        $location,
        $servername
    )

    $todaylog = "$location/disk_logs/" + (get-date -f "yyyyMMdd") + ".csv"
    $yesterdaylog = "$location/disk_logs/" + (Get-Date (Get-Date).AddDays(-1) -Format "yyyyMMdd") + ".csv"

    # Check if today log file exist.  Create if does not exist
    if (Test-Path $todaylog) {
        # Remove previous log files
        Get-ChildItem "$location\disk_logs\*.csv" | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-14) } | Remove-Item
    }
    else {
        # Create log file
        New-Item -ItemType File $todaylog -Force -Value "Time,Drive,Space,Free Space,Space Remaining`n"
    }

    clean_logs "$location/disk_logs"
    $script:notifyEmail = $false
    $drives =  Get-WmiObject Win32_LogicalDisk -Filter {Size != null and ProviderName = null}
    $drives | ForEach-Object -Process {
        $drivename = $_.DeviceID[0]
        $freespace = $_.freespace / 1gb
        $size = $_.size/1gb
        $drivepercent = $_.freespace / $_.size * 100
        write-host "size: $size"
        write-host "freespace: $freespace"
        write-host "percent left: $drivepercent"
        if ($drivepercent -lt 20) {
                $script:notifyEmail = $true
        }
        $freespace = [math]::Round($_.freespace / 1gb,2)
        $size = [math]::Round($_.size/1gb,2)
        $drivepercent = [math]::Round($_.freespace / $_.size * 100,0)
        $value = (get-date -f "yyyy/MM/dd HH:mm:ss") + ",$drivename`:,$size GB,$freespace GB,$drivepercent%"
        Add-Content $todaylog -Value $value
        $body += "Drive $drivename`: Status:`nDisk size: $size GB`nFree space remaining: $freespace GB`nFree remaining percentage: $drivepercent%`n`n"
    }

    $email = @{
            From = "ProductionCheck@advantasure.com"	
            To = "devops@advantasure.com"
            Subject = "Diskspace usage high on $servername"
            SMTPServer = "10.10.3.25"
            Priority = "Normal"
            Body = "$body"
        }

    if ($script:notifyEmail){
        $body = @()
        $body = $body | out-string
        send-mailmessage @email
        Start-Sleep -s 15
    }

}
function check_mem {
    param (
        $location,
        $servername
    )

    $todaylog = "$location/mem_logs/" + (get-date -f "yyyyMMdd") + ".csv"
    $yesterdaylog = "$location/mem_logs/" + (Get-Date (Get-Date).AddDays(-1) -Format "yyyyMMdd") + ".csv"

    # Check if today log file exist.  Create if does not exist
    if (Test-Path $todaylog) {
        # Remove previous log files
        Get-ChildItem "$location\cpu_logs\*.csv" | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-14) } | Remove-Item
        # Get the last counter value
        [int]$counter = (Get-Content $todaylog | Select-Object -Last 1).split(", ")[-1]
    }
    else {
        # Create log file
        New-Item -ItemType File $todaylog -Force -Value "Time, CPU Percent, Counter`n"
        # Get counter value from yesterday log file
        if (Test-Path $yesterdaylog) {
            [int]$counter = (Get-Content $yesterdaylog | Select-Object -Last 1).split(", ")[-1]
        }
        else {
            [int]$counter = 0
        }
    }
	$email = @{
        From = "ProductionCheck@advantasure.com"
        To = "devops@advantasure.com"
        Subject = "Memory usage high on $servername"
        SMTPServer = "10.10.3.25"
        Priority = "Normal"
        Body = "$body"
    }
	$CompObject =  Get-WmiObject -Class WIN32_OperatingSystem
	$timeout = 0
	$thersholdtime = 5
	$memorythreshold = 80
	while($timeout -lt $thersholdtime){
	# Memory Check
	$Memory = ((($CompObject.TotalVisibleMemorySize - $CompObject.FreePhysicalMemory)*100)/ $CompObject.TotalVisibleMemorySize)
	$value = (get-date -f "yyyy/MM/dd HH:mm:ss") + ",$Memory%"
    Add-Content $todaylog -Value $value
	if ("$Memory" -gt $memorythreshold){
		   $value = (get-date -f "yyyy/MM/dd HH:mm:ss") + ",$Memory%"
           Add-Content $todaylog -Value $value
		   start-sleep -seconds 60
		   $timeout++
		   if ($timeout -eq 5){
			 $body = "Memory usage has been above 80% for 5 minutes"
		     send-mailmessage @email
			 Start-Sleep -s 15
		   }
		   else{
			Write-Host "Waiting for $timeout minutes"
		   }  
	}
	else {
      $value = (get-date -f "yyyy/MM/dd HH:mm:ss") + ",$Memory%"
      Add-Content $todaylog -Value $value
	  Write-Host "$Memory is not greater than 80"
	exit
	}
	}
}

$location = Get-Location
$domain =  (Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem).domain
$servername = "$env:computername.$domain"

check_cpu -location $location -servername $servername
check_disk -location $location -servername $servername
check_mem -location $location -servername $servername