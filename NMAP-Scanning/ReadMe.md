# Detecting NMAP or other port scans 

Your SIEM should get your firewall and system logs.  IDS on firewall should fire alerts on port scans, but say that isnt working?

## Use Security Onion to detect NMAP

You can look at the Zeek/Bro logs on the Security Onion box  (sensor specifically) or use the Kibana interface

  NIDS is the obvious starting place and you should see SNORT/SURRICATA Alert
  
  Conn logs can let you see weird ports that are scanned or top talkers

  Firewall Logs - you may see your FW IDS alerts here
  
## What if your span/sensing/packet capture is broken and you aren't getting traffic?
 Use Wireshark or TCPDUMP on the affected system and copy the pcaps to the security onion box and use so-pcap commands to import
 
 https://github.com/Security-Onion-Solutions/security-onion/wiki/so-import-pcap
 
 so-import-pcap 
 
## Red Team is mean and broke Security Onion

  Netstat is your friend
  Firewall logs are your friend
  
  
