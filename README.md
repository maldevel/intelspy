![Alt text](logo.png?raw=true "Title")

## [Under Development]

Perform automated network reconnaissance scans to gather network intelligence.

IntelSpy is a multi-threaded network intelligence spy tool which performs automated enumeration of network services. It performs live hosts detection scans, port scans, services enumeration scans, web content scans, brute-force, detailed off-line exploits searches and more. 

The tool will also launch further enumeration scans for each detected service using a number of different tools.

---

### Credits

I had started working on IntelSpy when one day I discovered [AutoRecon](https://github.com/Tib3rius/AutoRecon). Instead of reinventing the wheel, IntelSpy is the result of combining/merging IntelSpy with the best features of the AutoRecon to create a network reconnaissance tool suitable for Penetration Testing engagements.

---

### Features

* Scans multiple targets in the form of IP addresses, IP ranges (CIDR notation) and resolvable hostnames.
* Can scan targets concurrently.
* Customizable port scanning profiles and service enumeration commands.
* Creates a directory structure for results gathering.
* Logs commands that were run.
* Extracts important information in txt and markdown format.
* Stores data to an SQLite database.
* Generates HTML report.

---

### Requirements

* Python 3
* colorama
* toml (https://github.com/toml-lang/toml)
* seclists

```
pip3 install -r requirements.txt
sudo apt install seclists
```

---

### Additional Tools

* curl
* enum4linux
* gobuster
* nbtscan
* nikto
* nmap
* onesixtyone
* oscanner
* smbclient
* smbmap
* smtp-user-enum
* snmpwalk
* sslscan
* svwar
* tnscmd10g
* whatweb
* wkhtmltoimage
* pandoc

---

### Usage

```
 ___               __        
  |  ._ _|_  _  | (_  ._     
 _|_ | | |_ (/_ | __) |_) \/ 
                      |   /  
                                
IntelSpy v1.0 - Perform automated network reconnaissance scans to gather network intelligence.
IntelSpy is an open source tool licensed under GPLv3.
Written by: @maldevel | Logisek
https://pentest-labs.com/
https://github.com/maldevel/intelspy


usage: intelspy.py [-h] [-ts TARGET_FILE] -p PROJECT_NAME -w WORKING_DIR
                   [--analyze <datetime>]
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
  --analyze <datetime>  analyze results, no scan (e.g. 2020-03-14_18-07-32)
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
  -v, --verbose         Enable verbose output. Repeat for more verbosity.
```

---

### Usage Examples

Scanning single target

```
sudo python3 intelspy.py -p MyProjectName -w /home/user/pt/projects/ 192.168.10.15
```

Scanning a hostname

```
sudo python3 intelspy.py -p MyProjectName -w /home/user/pt/projects/ example.com
```

Scanning a network range(CIDR)

```
sudo python3 intelspy.py -p MyProjectName -w /home/user/pt/projects/ 192.168.10.0/24
```

Scanning multiple targets

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

Analyze previous results (Do not scan).

```
sudo python3 intelspy.py -p MyProjectName -w /home/user/pt/projects/ --analyze 2020-03-14_18-07-32 192.168.10.0/24
```

---
