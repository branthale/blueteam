$continue = "1"
$date = Get-Date
$query = $date.Addhours(-2)

Do{
cls
$results = $results | sort-object timestamp
$results | Select-object -last 100
Start-sleep 15
$results = Get-messagetrackinglog -start $query -resultsize unlimited | Where-object {$_.recipients -notlike "*healthmailbox*" -and $_.sender -notlike "*healthmailbox*" } | Select timestamp,sender,recipients,originalclientip

}


While ($continue -eq "1")