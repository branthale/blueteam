# blueteam
Blue Teams tools and tactics from the Purple Team (several contributers to this and some stuff straight from the internet)


This repo is to share ideas, tools, and tactics for cyber blue teams.  

One of the challenges in cyber defense is understanding the attacker and knowing how to detect them.

Specific Technologies that are used in exercises are mentioned with some samples and code to help identify them.

## Hunting the Red Team 

  Red Team tools such as Cobalt Strike can provide a safe way to test your skills at detection.  I have included some packet captures and powershell to investigate.
  
  Be careful not to focus on specific Cobalt Strike detections, but instead look at how malware works. Note the other malware Covenant, DNSCAT2, etc lots of stuff for RED to use.
    
      Beaconing - almost everything calls out from the inside to the internet over some interval.  Main protocols are the ones allowed through firewalls - http,https,dns,ssh
      
        Look for communications to weird DNS names, http with really long cookies or short responses every X minutes - You need the domain names - IPs are easy to change
        
      Staging - most malware stages - a small program pulls down a bigger one
      
         Why are you downloading EXE?
      
      On the box you think has malware 
      
        Sysinternals - tcpdump, process viewer, netstat, taskman (enable command line tab), powershell (view proccesses, named pipes, etc)
        
        Get a PCAP - wireshark, tcpdump
        
        Get a memdump of the system or process and put it into a SIFT workstation and run volitility (vol.py)
     
     If you are hunting on individual boxes you are doing it wrong - centralize your logs 
       
       But my tool is broke?  Figure something out - export pcaps, forward logs, something - you can't win monitoring indvidual machines
       
     Build a story with your dections 
     
       Found a beacon?  Cool! How did it get there?  Who is it talking to?  Any other systems doing a simlar thing? 

       Check for persistance - it might show you how all this happened.  File in a user download or temp folder ?  They clicked a link somewhere.

## Microsoft 

Microsoft doc on how to run powershell on a remote machine - useful if you don't have console access

  [Windows/RemoteCommandLine](Windows/RemoteCommandLine)  

  [Windows/PowerShellRemotingSSH](Windows/PowerShellRemotingSSH)
  
  https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7
  
  
## Linux  how to do things in Linux

  [Linux/ReadMe.md](Linux/ReadMe.md)
  
 ![RedTeam](https://github.com/branthale/blueteam/blob/master/RedTeamIsReady_small.jpg)
