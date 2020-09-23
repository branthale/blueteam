# blueteam
Blue Teams tools and tactics from the Purple Team


This repo is to share ideas, tools, and tactics for cyber blue teams.  

One of the challenges in cyber defense is understanding the attacker and knowing how to detect them.

Specific Technologies that are used in exercises are mentioned with some samples and code to help identify them.

## Hunting the Red Team 

  Red Team tools such as Cobalt Strike can provide a safe way to test your skills at detection.  I have included some packet captures and powershell to investigate.
  
  Be careful not to focus on specific Cobalt Strike detections, but instead look at how malware works
    
      Beaconing - almost everything calls out from the inside to the internet over some interval.  Main protocols are the ones allowed through firewalls - http,https,dns,ssh
      
        Look for communications to weird DNS names, http with really long cookies or short responses every X minutes - You need the domain names - IPs are easy to change
        
      Staging - most malware stages - a small program pulls down a bigger one
      
         Why are you downloading EXE?

## Microsoft 

Microsoft doc on how to run powershell on a remote machine - useful if you don't have console access

  [Windows/RemoteCommandLine](Windows/RemoteCommandLine)  

  [Windows/PowerShellRemotingSSH](Windows/PowerShellRemotingSSH)
  
  https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7
  
  
## Linux  how to do things in Linux

  [Linux/ReadMe.md](Linux/ReadMe.md)
