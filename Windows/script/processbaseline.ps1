### Baseline needs C:\Temp Folder or error



$Baseline = Get-process | Select-object name -Unique
$baseline | export-csv c:\temp\processbaseline.csv -NoTypeInformation


$continue = "1"

Do {

$current = get-process | select name -Unique

$compare = compare-object $baseline $current -Property name
$new = $compare | where-object {$_.sideindicator -eq "=>" }
$override = import-csv c:\temp\override.txt
If ($new -ne $null) { $new = compare-object $new $override -Property name | Where-object {$_.sideindicator -eq "<=" } | Select-object name }
If ($new -ne $null) { 
$date = get-date 
$new | stop-process -force ; $new | Foreach {$temp = $_.name;write-host "$temp has been killed $date" }
clear-variable new
}



start-sleep 5




}
while ($continue -eq "1")