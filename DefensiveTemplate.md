# Blue Team: Summary of Operations

## Table of Contents
- Network Topology
- Description of Targets
- Monitoring the Targets
- Patterns of Traffic & Behavior
- Suggestions for Going Further

### Network Topology

The following machines were identified on the network:
- Kali
  - **Operating System**: Linux 
  - **Purpose**: Penetration testing suite
  - **IP Address**: 192.168.1.90
- Target 1
  - **Operating System**: Linux
  - **Purpose**: Company Website/ Wordpress Blog
  - **IP Address**: 192.168.1.110
- Target 2
  - **Operating System**: Linux
  - **Purpose**: Company Website/ Wordpress Blog
  - **IP Address**: 192.168.1.115
- Capstone
  - **Operating System**: Linux
  - **Purpose**: Employee File-Sharing
  - **IP Address**: 192.168.1.105
- ELK
  - **Operating System**: Linux
  - **Purpose**: ELK-stack system and network monitoring
  - **IP Address**: 192.168.1.100

### Description of Targets

The target of this attack was: `Target 1` 192.168.1.110

Target 1 is an Apache web server and has SSH enabled, so ports 80 and 22 are possible ports of entry for attackers. As such, the following alerts have been implemented:

### Monitoring the Targets

Traffic to these services should be carefully monitored. To this end, we have implemented the alerts below:

#### Excessive HTTP Errors
'Excessive HTTP Errors' is implemented as follows:
  - **Metric**: HTTP Response Codes
  - **Threshold**: When HTTP response codes over 400 are the most common for 5 consecutive minutes
  - **Vulnerability Mitigated**: Brute-force attacks
  - **Reliability**: For this machine, this alert could be reliable in the right circumstances, however, it would not track any stealthy (slow) brute-force attacks and if the attack lasted less than 5 minutes, then an alert would not trigger. Medium reliability.

#### HTTP Request Size
'HTTP Request Size' is implemented as follows:
  - **Metric**: HTTP Request Bytes
  - **Threshold**: When the sum of all the HTTP requests is over 3500 bytes for 1 minute
  - **Vulnerability Mitigated**: DDOS
  - **Reliability**: High reliability

#### High CPU Usage
'High CPU Usage' is implemented as follows:
  - **Metric**: CPU Usage (%)
  - **Threshold**: When CPU Usage is over 50% for  5 minutes
  - **Vulnerability Mitigated**: Unauthorized access, DDOS, and Cryptojacking
  - **Reliability**: High reliablitiy


