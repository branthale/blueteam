https://blueteamblog.com/threat-hunting-with-windows-security-event-logs

EVENT ID 4625 / 529-539 – FAILED LOGINS
Lets start off with looking at failed logins. These can be a little difficult to look at due to their sheer number, especially on a large environment. However, we can look for a few things which stand out.Large numbers of failed logins on a single source within a small number of time. This can indicate attackers attempting to brute force using credentials they have already found.

You can also look for hosts with the highest numbers of failed logins within a period of time, but sorted by username. Is there a personal laptop within the organisation with failed logins from 10 different users. If so, why?


 
Failed logins outside office hours. Does your business only work Mon-Fri 8-6 but you see a bunch of failed logins on Saturday night? Figure out why.

Look at https://www.ultimatewindowssecurity.com/ for Event ID 4625 and check against your logs. It shows you all the failure reasons for logins. This can help a lot, for example – is the account being logged into expired? Is it disabled? These codes will tell you.

As I just mentioned, look for failure reasons. Code 0XC000072 means an account is currently disabled. Why is there disabled accounts attempting to log in?

For all of these searches, you will need to rule out ‘legitimate behaviour’. This can take some time, but it is worth it. Examples – Do you have shared workstations, or admins who work outside of office hours? If so, then you will need to add those as exceptions to your searches.

Event ID 4771 – FAILED KERBEROS PRE AUTHENTICATION
This relates a bit to the previous EventID as it happens when someone first logs on for the day. As I mentioned at the start, I’m not going to dig into Kerberos too much in this article but there is something simple you can look for.

Event ID 4771 along with code 0x18. This means ‘pre authentication information was invalid’ or put simply, bad password. Look for large numbers of these coming from a single host. This sort of behaviour usually highlights brute force attempts.

EVENTID 4765 / 4766 – SID HISTORY ADDED TO AN ACCOUNT / FAILED
SID History (Security Identifier) being changed on an account should only happen when users are being migrated between domains. Look for these Event IDs and check if they appear on your network. If you don’t have any migrations going on, I highly recommend you look into the activity on these accounts more. This is because malicious actors commonly alter SID-HISTORY to escalate privileges and impersonate users.

EVENTID 4794 – ATTEMPT MADE TO SET DSRM PASSWORD
Event ID 4794 looks at any attempts made to change the password of the Directory Services Restore Mode admin password. This is vitally important – if someone is able to enter DSRM they can edit and access the Active Directory database. Tune out legitimate uses of this and look into any attempts made outside this.

EVENT ID’S 4793/643, 4713/617, 4719/612 – POLICY CHANGES
These EventIDs look at Domain, Kerberos and System Audit Policies being changed. These policies should only be changed by approved users and even then, the changes should happen within change windows or approved times. Look for accounts changing audit policies outside this as this is a common action taken by attackers.

EVENT ID’s 4735/639, 4737/641, 4755/659 – SECURITY ENABLED GROUPS CHANGED
Look for changes being made to any groups you consider ‘Critical’. This could be Domain Admins, SQL Admins, financial users or anything else your business deems important. The main thing here is to look for changes being made to any critical groups and ask why. Any modifcations being made to important groups should have relevant documentation saying why – if they don’t, this is a massive red flag.

EVENT ID’S 4728/632, 4732/636, 4756/660 – USERS BEING ADDED TO SECURITY ENABLED GROUPS
Very similar to above, but this time we are looking for users being added to the same ‘Critical’ groups. If a user is being added to an important group that gives them privileges or access; there should be documentation saying why (Usually for job role) If this doesn’t exist – why? Attackers will commonly get accounts added to groups to escalate privileges.

EVENT ID 1102 / 517 – AUDIT LOG CLEARED
After performing attacks, threat actors will usually clear the audit logs to make it more difficult to find out what was done and who did it. Any audit logs being cleared should be investigated to confirm they are valid actions.

EVENT ID 4648 / 552 – LOGON ATTEMPTED USING EXPLICIT CREDENTIALS
This Event ID triggers when a user connects to a server or runs a program locally using alternate credentials. It will also trigger when a user sets up a scheduled tasks with different credentials. Searching for this event ID will show a lot of noise, but it is worth spending some time to look through this.

Look for a user’s using other peoples credentials to access resources, this will stand out and is a common action performed by threat actors.

EVENT ID 4697 / 601 – SERVICE INSTALLED
As part of attacks, threat actors install new services.

Create a whitelist of common services (Such as common programs, Microsoft services etc) and then look at anything not matching them. This can highlight services which have potentially been installed maliciously.

EVENT ID 4688 / 592 – PROCESS CREATED
Similar to above, but this time looking at new processes being created.

We can use this Event ID to look for commands which are commonly used by attackers during campaigns, lets split these into 3 groups.


 
When attackers initially gain access to a machine, they are known to run the following commands in a short period of time :

tasklist
ver
ipconfig
systeminfo
net time
netstat
whoami
net start
qprocess
query
After doing this, attackers then perform Recon on the wider environment using these commands :

dir
net view
ping
net use
type
net user
net localgroup
net group
net config
net share
After they have gained a foothold in a network and want to spread, they commonly use these commands :

at
reg
wmic
wusa
netsh advfirewall
sc
rundll32
Use the above lists and look for lots of these commands having been run by the same user. If the user is not an admin or involved in networking or security, why are they doing this? It is strange if a HR employee starts running a lot of these commands when they have never used them before.

EVENT ID 4672 / 576 – SPECIAL PRIVILEGES ASSIGNED TO NEW LOGON
This event monitors when an account with admin level privileges logs on. This can include normal logons, scheduled tasks or service logins. Rule out the normal, legitimate behaviour and look at the other logins, does anything stand out?

EVENT ID’S 4698 / 4702 / 602 – SCHEDULED TASK CREATED / UPDATED
Threat actors will commonly schedule new tasks or update existing ones to perform malicious actions on a network. Look through the new tasks being created, or updated tasks for anything that stands out.

EVENT ID 4720 / 624 – A LOCAL USER ACCOUNT WAS CREATED
When a local SAM or Domain account is created, this event is logged. Many times to get around restrictions, attackers will create local accounts and then elevate them to local admins. To look for this, look for EventID 4720 / 624 and then EventID 4732 / 636 happening within a short space of time. This could indicate an attacker creating a local admin account to aid in their attacks.


