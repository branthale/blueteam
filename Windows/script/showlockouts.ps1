$pattern = '[^a-zA-Z0-9@.]',''
$continue = "1"
Do {
$results = $results | sort-object timegenerated
cls
$results
start-sleep 15
$data = Get-eventlog -logname security -newest 200 -instanceid 4740
$A = ""
$results =
Foreach ($temp in $data) {
$1 = $temp.message
$1 = $1.split("`n")
Foreach ($line in $1) {
If ($line -like "*Caller Computer Name:*") {$line2 = $line.split(":");$WSname = $line2[1];If ($wsname -ne $null) {$wsname = $wsname -replace $pattern}}
If ($line -like "*Account Name:*") {$line3 = $line.split(":");$ACCname = $line3[1];If ($ACCname -ne $null) {$ACCname = $ACCname -replace $pattern}}
}
$Temp | Select Timegenerated,@{l="Account Name";e={$ACCname}},@{l="Computername";e={$wsname}}
}
}
While ($continue -eq "1")