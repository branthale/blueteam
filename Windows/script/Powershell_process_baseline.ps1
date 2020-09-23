$before = get-process
$before | export-csv c:\before.csv –NoTypeInformation
$remaining = ‘1”
Do {
$before = import-csv c:\before.csv
$after – get-process
$stuff = compare-object $before $after –property processname
If ($stuff –ne $null ) { $stuff | stop-process –force;$stuff}
Start-sleep 1
Clear-variable stuff
}
While ($reamaining –eq “1” )
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
