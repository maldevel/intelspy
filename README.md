# AutoScan

Perform automated network reconnaissance scans.

AutoScan is a network reconnaissance tool which performs automated enumeration of network services.

AutoScan performs live hosts detection scans, port scans and services enumeration and detection scans. 

The tool will also launch further enumeration scans of those services using a number of different tools.

---

## Features

* Scans IP addresses and IP ranges (CIDR notation).
* Creates a directory structure for results gathering.
* Logs commands that were run.
* Extracts important information in txt and markdown format.

---

## Requirements

* Python 3
* colorama

```
pip3 install -r requirements.txt
```

---

## Usage

```
usage: scan.py [-h] -t TARGET -st SCAN_TYPE -p PROJECT_NAME -w WORKING_DIR

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        target IP or IP range
  -st SCAN_TYPE, --scan-type SCAN_TYPE
                        network scan type (internal or external)
  -p PROJECT_NAME, --project-name PROJECT_NAME
                        project name
  -w WORKING_DIR, --working-dir WORKING_DIR
                        working directory
```

---

## Usage Examples

```
sudo python3 scan.py -t 192.168.10.0/24 -st external -p MyProjectName -w /home/user/pt/projects/
```

---
