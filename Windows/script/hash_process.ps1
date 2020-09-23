Hash processes

$bobbob = get_process;$($bobbob).path | foreach { If ($_ -ne "" ) {Get-FileHash $_ }}

$remaining = "1”
Do {
$basehash = import-csv c:\basehash.csv
$runproc = get-process
$runhash = ;$($runproc).path | foreach { If ($_ -ne "" ) {Get-FileHash $_ }}
$comphash = compare-object $basehash $runhash –property hash
$comphash
$runhash | export-csv c:\bashhash.csv -NoTypeInformation
Start-sleep 10
 
}
While ($remaining –eq “1” ) 
 



