Show new process from baseline and kill them.  Run before is the baseline.  Mr Crabb has the credit on this one.

Run before 
$before = get-process
$before | export-csv c:\before.csv –NoTypeInformation
$remaining = ‘1”
Do {
$before = import-csv c:\before.csv
$after = get-process
$stuff = compare-object $before $after –property processname
If ($stuff –ne $null ) { $stuff | stop-process –force;$stuff}
Start-sleep 1
Clear-variable stuff
}
While ($reamaining –eq “1” )
