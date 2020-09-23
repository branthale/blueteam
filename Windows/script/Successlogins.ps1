$pattern = '[^a-zA-Z0-9@.]',''
$continue = "1"
Do {
$results = $results | Where-object {$_."Account Name" -notlike "*Crabology*" -and $_."account name" -notlike "*health*" -and $_."Account name" -notlike "*system*" }
$results = $results | sort-object timegenerated
cls
$results
start-sleep 60
$data = Get-eventlog -logname security -newest 5000 -instanceid 4624
$A = ""
$results =
Foreach ($temp in $data) {
$1 = $temp.message
$1 = $1.split("`n")
Foreach ($line in $1) {
If ($line -like "*Workstation Name:*") {$line2 = $line.split(":");$WSname = $line2[1];If ($wsname -ne $null) {$wsname = $wsname -replace $pattern}}
If ($line -like "*Account Name:*") {$line3 = $line.split(":");$ACCname = $line3[1];If ($ACCname -ne $null) {$ACCname = $ACCname -replace $pattern}}
}
$Temp | Select Timegenerated,@{l="Account Name";e={$ACCname}},@{l="Computername";e={$wsname}}
#If ($wsname -ne $null) {clear-variable wsname}
#If ($ACCname -ne $null) {clear-variable ACCname}

}

}
While ($continue -eq "1")