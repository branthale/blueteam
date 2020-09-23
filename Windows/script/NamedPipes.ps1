Finding APT that uses named pipes 

List Named Pipes on windows with Powershell

$pipeName = "testpipe"
$delPipe = [System.IO.Directory]::GetFiles("\\.\pipe\") | where { $_ -match $pipeName }

[System.IO.Directory]::GetFiles("\\.\pipe\") 
get-childitem \\.\pipe\



