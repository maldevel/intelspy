![Alt text](logo.png?raw=true "IntelSpy")

Perform automated network reconnaissance scans to gather network intelligence.

IntelSpy is a multi-threaded network intelligence tool which performs automated network services enumeration. It performs live hosts detection scans, port scans, services enumeration scans, web content scans, brute-forcing, detailed off-line exploits searches and more. 

The tool will also launch further enumeration scans for each detected service using a number of different tools.

---

### Features

* Scans multiple targets in the form of IP addresses, IP ranges (CIDR notation) and resolvable hostnames.
* Scans targets concurrently.
* Detects live hosts in an IP range (CIDR) network.
* Customizable port scanning profiles and service enumeration commands.
* Creates a directory structure for results gathering and reporting.
* Logs every command that was executed.
* Generates shell scripts containing commands to be run manually.
* Extracts important information in txt and markdown format for further inspection.
* Stores data to an SQLite database.
* Generates an HTML report.

---

### Requirements

* Python 3 (``` sudo apt install python3 ```)
* Linux (preferably Kali Linux or any other hacking distribution containing the tools below.)
  * https://www.kali.org/downloads/
* toml (https://github.com/toml-lang/toml)
* seclists (https://github.com/danielmiessler/SecLists)
* curl (*prerequisite*) (``` sudo apt install curl ```)
* enum4linux (*prerequisite*) (``` sudo apt install enum4linux ```)
* gobuster (*prerequisite*) (``` sudo apt install gobuster ```)
* hydra (*optional*) (``` sudo apt install hydra ```)
* ldapsearch (*optional*) (``` sudo apt install ldap-utils ```)
* medusa (*optional*) (``` sudo apt install medusa ```)
* nbtscan (*prerequisite*) (``` sudo apt install nbtscan ```)
* nikto (*prerequisite*) (``` sudo apt install nikto ```)
* nmap (*prerequisite*) (``` sudo apt install nmap ```)
* onesixtyone (*prerequisite*) (``` sudo apt install onesixtyone ```)
* oscanner (*optional*) (``` sudo apt install oscanner ```)
* pandoc (*prerequisite*) (``` sudo apt install pandoc ```)
* patator (*optional*) (``` sudo apt install patator ```)
* showmount (*prerequisite*) (``` sudo apt install nfs-common ```)
* smbclient (*prerequisite*) (``` sudo apt install smbclient ```)
* smbmap (*prerequisite*) (``` sudo apt install smbmap ```)
* smtp-user-enum (*prerequisite*) (``` sudo apt install smtp-user-enum ```)
* snmpwalk (*prerequisite*) (``` sudo apt install snmp ```)
* sslscan (*prerequisite*) (``` sudo apt install sslscan ```)
* svwar (*prerequisite*) (``` sudo apt install sipvicious ```)
* tnscmd10g (*prerequisite*) (``` sudo apt install tnscmd10g ```)
* whatweb (*prerequisite*) (``` sudo apt install whatweb ```)
* wkhtmltoimage (*prerequisite*) (``` sudo apt install wkhtmltopdf ```)
* wpscan (*optional*) (``` sudo apt install wpscan ```)


```
pip3 install -r requirements.txt
```

---

### Usage

```
$ python3 intelspy.py -h

 ___               __        
  |  ._ _|_  _  | (_  ._     
 _|_ | | |_ (/_ | __) |_) \/ 
                      |   /  
                                
IntelSpy v2.0 - Perform automated network reconnaissance scans to gather network intelligence.
IntelSpy is an open source tool licensed under GPLv3.
Written by: @maldevel | Logisek ICT
Web: https://logisek.com | https://pentest-labs.com
Project: https://github.com/maldevel/intelspy


usage: intelspy.py [-h] [-ts TARGET_FILE] -p PROJECT_NAME -w WORKING_DIR
                   [--exclude <host1[,host2][,host3],...>] [-s SPEED]
                   [-ct <number>] [-cs <number>] [--profile PROFILE_NAME]
                   [--livehost-profile LIVEHOST_PROFILE_NAME]
                   [--heartbeat HEARTBEAT] [-v]
                   [targets [targets ...]]

positional arguments:
  targets               IP addresses (e.g. 10.0.0.1), CIDR notation (e.g.
                        10.0.0.1/24), or resolvable hostnames (e.g.
                        example.com) to scan.

optional arguments:
  -h, --help            show this help message and exit
  -ts TARGET_FILE, --targets TARGET_FILE
                        Read targets from file.
  -p PROJECT_NAME, --project-name PROJECT_NAME
                        project name
  -w WORKING_DIR, --working-dir WORKING_DIR
                        working directory
  --exclude <host1[,host2][,host3],...>
                        exclude hosts/networks
  -s SPEED, --speed SPEED
                        0-5, set timing template (higher is faster) (default:
                        4)
  -ct <number>, --concurrent-targets <number>
                        The maximum number of target hosts to scan
                        concurrently. Default: 5
  -cs <number>, --concurrent-scans <number>
                        The maximum number of scans to perform per target
                        host. Default: 10
  --profile PROFILE_NAME
                        The port scanning profile to use (defined in port-
                        scan-profiles.toml). Default: default
  --livehost-profile LIVEHOST_PROFILE_NAME
                        The live host scanning profile to use (defined in
                        live-host-scan-profiles.toml). Default: default
  --heartbeat HEARTBEAT
                        Specifies the heartbeat interval (in seconds) for task
                        status messages. Default: 60
  -v, --verbose         Enable verbose output. Repeat for more verbosity (-v,
                        -vv, -vvv).
```

---

### Usage Examples

Scanning single target

```
sudo python3 intelspy.py -p MyProjectName -w /home/user/pt/projects/ 192.168.10.15
sudo python3 intelspy.py -p MyProjectName -w /home/user/pt/projects/ 192.168.10.15 -v
sudo python3 intelspy.py -p MyProjectName -w /home/user/pt/projects/ 192.168.10.15 -vv
sudo python3 intelspy.py -p MyProjectName -w /home/user/pt/projects/ 192.168.10.15 -vvv
```

Scanning a hostname

```
sudo python3 intelspy.py -p MyProjectName -w /home/user/pt/projects/ example.com
```

Scanning a network range(CIDR)

```
sudo python3 intelspy.py -p MyProjectName -w /home/user/pt/projects/ 192.168.10.0/24
```

Scanning multiple targets (comma separated)

```
sudo python3 intelspy.py -p MyProjectName -w /home/user/pt/projects/ 192.168.10.15 192.168.10.0/24 example.com
```

Scanning targets from file

```
sudo python3 intelspy.py -p MyProjectName -w /home/user/pt/projects/ -ts /home/user/targets.txt
```

Excluding one host

```
sudo python3 intelspy.py -p MyProjectName -w /home/user/pt/projects/ --exclude 192.168.10.9 192.168.10.0/24
```

Excluding many hosts

```
sudo python3 intelspy.py -p MyProjectName -w /home/user/pt/projects/ --exclude 192.168.10.9,192.168.10.24 192.168.10.0/24
```

---

### Credits

I started working on IntelSpy when I discovered [AutoRecon](https://github.com/Tib3rius/AutoRecon). Instead of reinventing the wheel, IntelSpy is the result of merging IntelSpy with the best features of the AutoRecon to create a network reconnaissance tool suitable for Penetration Testing engagements.

---
