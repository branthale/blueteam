$Baseline = Get-service | Where-object {$_.status -like "*running*" } 
$baseline | export-csv c:\temp\baseline.csv -NoTypeInformation


$continue = "1"

Do {

$current = get-service | Where-object {$_.status -like "*running*" }

$compare = compare-object $baseline $current -Property name
$compare
start-sleep 10
cls
}
while ($continue -eq "1")
