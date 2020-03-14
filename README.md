![Alt text](logo.png?raw=true "Title")

## [Under Development]

Perform automated network reconnaissance scans to gather network intelligence.

IntelSpy is a network intelligence spy tool which performs automated enumeration of network services. It performs live hosts detection scans, port scans, services enumeration scans, web content scans, brute-force, detailed off-line exploits searches and more. The tool will also launch further enumeration scans for each detected service using a number of different tools.

---

### Features

* Scans IP addresses and IP ranges (CIDR notation).
* Creates a directory structure for results gathering.
* Logs commands that were run.
* Extracts important information in txt and markdown format.
* Stores data to an SQLite database.
* Generates HTML report.

---

### Requirements

* Python 3
* colorama
* nmap
* pandoc

```
pip3 install -r requirements.txt
sudo apt install nmap pandoc
```

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


usage: intelspy.py [-h] -t <host or IP range> -p PROJECT_NAME -w WORKING_DIR
                   [--analyze <datetime>]
                   [--exclude <host1[,host2][,host3],...>]
                   [--top-tcp-ports <number>] [--top-udp-ports <number>]

optional arguments:
  -h, --help            show this help message and exit
  -t <host or IP range>, --target <host or IP range>
                        target IP or IP range
  -p PROJECT_NAME, --project-name PROJECT_NAME
                        project name
  -w WORKING_DIR, --working-dir WORKING_DIR
                        working directory
  --analyze <datetime>  analyze results, no scan (e.g. 2020-03-14_18-07-32)
  --exclude <host1[,host2][,host3],...>
                        exclude hosts/networks
  --top-tcp-ports <number>
                        scan <number> most common TCP ports
  --top-udp-ports <number>
                        scan <number> most common UDP ports
```

---

### Usage Examples

Simple scan

```
sudo python3 intelspy.py -t 192.168.10.0/24 -p MyProjectName -w /home/user/pt/projects/
```

Exclude one host

```
sudo python3 intelspy.py -t 192.168.10.0/24 -p MyProjectName -w /home/user/pt/projects/ --exclude 192.168.10.9
```

Exclude many hosts

```
sudo python3 intelspy.py -t 192.168.10.0/24 -p MyProjectName -w /home/user/pt/projects/ --exclude 192.168.10.9,192.168.10.254
```

Select the number of the Top TCP and Top UDP ports to scan

```
sudo python3 intelspy.py -t 192.168.10.0/24 -p MyProjectName -w /home/user/pt/projects/ --top-tcp-ports 2000 --top-udp-ports 500
```

Analyze previous results (Do not scan).

```
sudo python3 intelspy.py -t 192.168.1.0/24 -p home-network -w /media/data/Tools/Testing --top-tcp-ports 10 --top-udp-ports 10 --analyze 2020-03-14_18-07-32
```

---
