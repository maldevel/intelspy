#!/usr/bin/python3

#    This file is part of IntelSpy
#    Copyright (C) 2020 @maldevel
#    https://github.com/maldevel/intelspy
#
#    IntelSpy - Perform automated network reconnaissance scans.
#	 Gather network intelligence.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    For more see the file 'LICENSE' for copying permission.


# Created by @maldevel
# Logisek
# https://pentest-labs.com
# scan.py Version 1.0
# Released under GPL Version 3 License
# March 2020


import subprocess
from subprocess import Popen, PIPE, STDOUT
from datetime import datetime
import argparse
import os
from datetime import timezone
import socket
import sys
import shlex
from pathlib import Path
import colorama
from colorama import Fore, Style
import time
import ipaddress
import sqlite3
from sqlite3 import Error



#####################################################################################################################
__version__ = 1.0

EventID = 0
ProjectDir = ''
LiveHostsDir = ''
LogsDir = ''
LogsFile = ''
ReportDir = ''
LiveHostsListFile = ''
InternalPTMode = False
LiveHostsList = []
LiveHostsMDFile = ''
DatabaseDir = ''
DatabaseFile = ''
DbConnection = None
CommandsDir = ''
CommandsFile = ''
TopTcpPortsDir = ''
TopTcpPortsFile = ''
TopTcpPortsMatrixFile = ''
TopTcpPortsList = []
TopTcpPortsMDFile = ''


#####################################################################################################################
message = """
 ___               __        
  |  ._ _|_  _  | (_  ._     
 _|_ | | |_ (/_ | __) |_) \/ 
                      |   /  
                                
IntelSpy v{} - Perform automated network reconnaissance scans to gather network intelligence.
IntelSpy is an open source tool licensed under GPLv3.
Written by: @maldevel | Logisek
https://pentest-labs.com/
https://github.com/maldevel/intelspy

""".format(__version__)



#####################################################################################################################
class db:
	@classmethod
	def connect(self):
		global DatabaseFile, DbConnection

		try:
			DbConnection = sqlite3.connect(DatabaseFile)
			db.createLiveHostsTbl()

			log.info('Database file {0}.'.format(DatabaseFile))
		except Exception as e:
			log.error("An error occured during sqlite3 database connection: {0}.".format(str(e)))
			if DbConnection:
				DbConnection.close()
			exit(1)

	@classmethod
	def disconnect(self):
		global DbConnection

		try:
			if DbConnection:
				DbConnection.close()
		except Exception as e:
			log.error("An error occured during sqlite3 database connection: {0}.".format(str(e)))
			exit(1)
	
	@classmethod
	def addLiveHost(self, liveHost):
		global DbConnection

		c = DbConnection.cursor()
		c.execute('''REPLACE INTO live_hosts(Ipaddr) 
			VALUES(?);''', [liveHost])
		DbConnection.commit()
		id = c.lastrowid
		c.close()
		return id

	@classmethod
	def getLiveHosts(self):
		global DbConnection

		c = DbConnection.cursor()
		c.execute('''SELECT Ipaddr from live_hosts;''')
		DbConnection.commit()
		rows = c.fetchall()
		c.close()
		return rows

	@classmethod
	def createLiveHostsTbl(self):
		global DbConnection

		DbConnection.execute('''CREATE TABLE live_hosts
         (ID INTEGER PRIMARY KEY AUTOINCREMENT,
         Ipaddr CHAR(50) UNIQUE NOT NULL);''')



#####################################################################################################################
class md:
	@classmethod
	def genLiveHosts(self, live_hosts):
		data = "## Live Hosts\n\n"
		for val in live_hosts:
			if val != "":
				data += "* " + val + "\n"
		data += "\n---\n"
		return data

	@classmethod
	def genTopPorts(self, topPorts, topNum):
		data = "## Top {0} TCP Ports\n\n".format(topNum)
		for key, value in topPorts.items():
			data += "### {0}\n\n".format(key)
			if value != "":
				for port in value:
					data += "* " + port + "\n"
				data += "\n"
			data += "---\n\n"
		return data



#####################################################################################################################
class pt:
	@classmethod
	def setMode(self, target):
		ipv4 = ipaddress.IPv4Network(target)
		InternalPTMode = ipv4.is_private
		return InternalPTMode



#####################################################################################################################
class exec:
	@classmethod
	def run(self, command, shell):
		print(Fore.MAGENTA + Style.BRIGHT)
		subprocess.run(command, shell=shell)
		print(Style.NORMAL + Fore.RESET)

	@classmethod
	def pipe(self, command):
		print(Fore.MAGENTA + Style.BRIGHT)
		p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out, err = p.communicate()
		print(out)
		print(Style.NORMAL + Fore.RESET)
		return out



#####################################################################################################################
class help:

	@classmethod
	def writeMD(self, data, filePath):
		with open(filePath, 'w') as file:
				file.write(data)

	@classmethod
	def elapsedTime(self, start):
	    sec = round(time.time() - start)

	    m, s = divmod(sec, 60)
	    h, m = divmod(m, 60)

	    tt = []
	    if h == 1:
	        tt.append(str(h) + ' hour')
	    elif h > 1:
	        tt.append(str(h) + ' hours')

	    if m == 1:
	        tt.append(str(m) + ' minute')
	    elif m > 1:
	        tt.append(str(m) + ' minutes')

	    if s == 1:
	        tt.append(str(s) + ' second')
	    elif s > 1:
	        tt.append(str(s) + ' seconds')
	    else:
	        tt.append('less than a second')

	    return ', '.join(tt)



#####################################################################################################################
class grep:

	@classmethod
	def openPorts(self, target, numOfPorts):
		global TopTcpPortsDir, TopTcpPortsFile, TopTcpPortsList, LogsFile, TopTcpPortsMDFile
		
		cmdOutput = ''

		try:

			gnmapFilesDir = os.path.join(TopTcpPortsDir, '*.gnmap')
			command = "egrep -v \"^#|Status: Up\" {0}|cut -d' ' -f2,4-| sed 's/Ignored.*//g' | awk '{{printf \"Host: \" $1 \"\\nOpen ports: \" NF-1 \"\\n\"; $1=\"\"; for(i=2; i<=NF; i++) {{ a=a\"\"$i; }}; split(a,s,\",\"); for(e in s) {{ split(s[e],v,\"/\"); printf \"%s\\t%s\\n\", v[1], v[5]}}; a=\"\"; printf \"\\n\"; }}'| tee {1}".format(gnmapFilesDir, TopTcpPortsFile)
			commandMatrix = "egrep -v \"^#|Status: Up\" {0}|cut -d' ' -f2,4-| sed 's/Ignored.*//g' | awk '{{printf $1 \";\" NF-1 \";\"; $1=\"\"; for(i=2; i<=NF; i++) {{ a=a\"\"$i; }}; split(a,s,\",\"); for(e in s) {{ split(s[e],v,\"/\"); printf \"%s(%s),\", v[1], v[5]}}; a=\"\"; printf \"\\n\"; }}'> {1}".format(gnmapFilesDir, TopTcpPortsMatrixFile)
			
			log.info('Hosts with opened ports of target {0}.'.format(target))
			log.debug('Command: {0}'.format(command))
			log.info('Output')

			start = time.time()
			exec.run(command, True)
			log.writeCmdLog(command)

			exec.run(commandMatrix, True)
			log.writeCmdLog(commandMatrix)

		except Exception as e:
			log.error("An error occured during nmap scan results grep: {0}.".format(str(e)))

		try:
			with open(TopTcpPortsFile, 'r') as file:
				cmdOutput = file.read()

			with open(LogsFile, 'a') as file:
				file.write(cmdOutput)

			with open(TopTcpPortsMatrixFile, 'r') as file:
				cmdOutput2 = file.read()

			with open(LogsFile, 'a') as file:
				file.write(cmdOutput2)

		except Exception as e:
			log.error("An error occured while trying to append grep result to log file '{0}': {1}.".format(LogsFile, e))

		
		message = "Task completed in {0}.".format(help.elapsedTime(start))
		log.infoPickC(message, Fore.CYAN)

		TopTcpPortsList = list(filter(bool, cmdOutput2.split('\n')))
		portsCounter = 0
		openPortsDict = {}
		for line in TopTcpPortsList:
			data = list(filter(bool, line.split(';')))
			host = data[0]
			ports = list(filter(bool, data[2].split(',')))
			portsCounter += len(ports)
			openPortsDict[host] = ports
			#print(host)
			#print(numOfPorts)
			#for port in ports:
				#print(port)
			#	portsCounter += 1
			#hostsCounter += 1

		log.info("{0} open TCP ports detected on {1} hosts.".format(portsCounter, len(TopTcpPortsList)))
		help.writeMD(md.genTopPorts(openPortsDict, numOfPorts), TopTcpPortsMDFile)

		#for host in LiveHostsList:
		#	db.addLiveHost(host)

		return cmdOutput

	@classmethod
	def liveHosts(self, target):
		global LiveHostsDir, LiveHostsListFile, LogsFile, LiveHostsMDFile
		
		cmdOutput = ''

		try:

			gnmapFilesDir = os.path.join(LiveHostsDir, '*.gnmap')
			command = "cat {0} | grep 'Status: Up' | cut -d ' ' -f2 | sort -V | uniq | tee {1}".format(gnmapFilesDir, LiveHostsListFile)
			
			log.info('Live hosts of target {0}.'.format(target))
			log.debug('Command: {0}'.format(command))
			log.info('Output')

			start = time.time()
			exec.run(command, True)
			log.writeCmdLog(command)

		except Exception as e:
			log.error("An error occured during nmap scan results grep: {0}.".format(str(e)))

		try:
			with open(LiveHostsListFile, 'r') as file:
				cmdOutput = file.read()

			with open(LogsFile, 'a') as file:
				file.write(cmdOutput)

		except Exception as e:
			log.error("An error occured while trying to append grep result to log file '{0}': {1}.".format(LogsFile, e))

		
		message = "Task completed in {0}.".format(help.elapsedTime(start))
		log.infoPickC(message, Fore.CYAN)

		LiveHostsList = list(filter(bool, cmdOutput.split('\n')))
		log.info("{0} live hosts detected.".format(len(LiveHostsList)))

		help.writeMD(md.genLiveHosts(LiveHostsList), LiveHostsMDFile)

		for host in LiveHostsList:
			db.addLiveHost(host)

		return cmdOutput



#####################################################################################################################
class fm:

	@classmethod
	def createProjectDirStructure(self, target, projName, workingDir, defaultTopTcpPorts):
		global ProjectDir, LiveHostsDir, LogsDir, LogsFile, ReportDir, LiveHostsListFile, LiveHostsMDFile, DatabaseDir, DatabaseFile, CommandsDir, CommandsFile, TopTcpPortsDir, TopTcpPortsFile, TopTcpPortsMatrixFile, TopTcpPortsMDFile

		ProjectDir = os.path.join(workingDir, projName)
		ScansDir = os.path.join(ProjectDir, 'scans')
		DatabaseDir = os.path.join(ProjectDir, 'db')
		DatabaseFile = os.path.join(DatabaseDir, "{0}-{1}.db".format(projName, datetime.now().strftime("%Y-%m-%d_%H-%M-%S")))
		CommandsDir = os.path.join(ProjectDir, 'commands')
		CommandsFile = os.path.join(CommandsDir, "{0}-{1}-commands-log.txt".format(projName, datetime.now().strftime("%Y-%m-%d_%H-%M-%S")))

		LiveHostsDir = os.path.join(ScansDir, 'live-hosts', target.replace('/', '_'), datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
		TopTcpPortsDir = os.path.join(ScansDir, 'tcp', 'ports', "top-{0}".format(defaultTopTcpPorts), target.replace('/', '_'), datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))

		LogsDir = os.path.join(ProjectDir, 'logs', target.replace('/', '_'))
		LogsFile = os.path.join(LogsDir, "{0}-log-{1}-{2}.txt".format(projName, target.replace('/', '_'), datetime.now().strftime("%Y-%m-%d_%H-%M-%S")))
		
		ReportDir = os.path.join(ProjectDir, 'report', target.replace('/', '_'), datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))

		LiveHostsListFile = os.path.join(ReportDir, "{0}-live-hosts-list-{1}-{2}.txt".format(projName, target.replace('/', '_'), datetime.now().strftime("%Y-%m-%d_%H-%M-%S")))
		LiveHostsMDFile = LiveHostsListFile.replace('.txt', '.md')

		TopTcpPortsFile = os.path.join(ReportDir, "{0}-top-{1}-{2}-{3}.txt".format(projName, defaultTopTcpPorts, target.replace('/', '_'), datetime.now().strftime("%Y-%m-%d_%H-%M-%S")))
		TopTcpPortsMatrixFile = os.path.join(ReportDir, "{0}-top-{1}-{2}-{3}-matrix.txt".format(projName, defaultTopTcpPorts, target.replace('/', '_'), datetime.now().strftime("%Y-%m-%d_%H-%M-%S")))
		TopTcpPortsMDFile = TopTcpPortsFile.replace('.txt', '.md')

		Path(LiveHostsDir).mkdir(parents=True, exist_ok=True)
		Path(TopTcpPortsDir).mkdir(parents=True, exist_ok=True)
		Path(LogsDir).mkdir(parents=True, exist_ok=True)
		Path(ReportDir).mkdir(parents=True, exist_ok=True)
		Path(DatabaseDir).mkdir(parents=True, exist_ok=True)
		Path(CommandsDir).mkdir(parents=True, exist_ok=True)

		log.info("Creating project directory structure '{0}'.".format(ProjectDir))		



#####################################################################################################################
class log:

	@classmethod
	def nextEventID(self):
		global EventID
		EventID += 1
		return EventID

	@classmethod
	def infoPickC(self, logStr, color):
		log.write('Info', logStr, color)

	@classmethod
	def info(self, logStr):
		log.write('Info', logStr, Fore.GREEN)

	@classmethod
	def error(self, logStr):
		log.write('Error', logStr, Fore.RED)

	@classmethod
	def debug(self, logStr):
		log.write('Error', logStr, Fore.BLUE)

	@classmethod
	def write(self, logType, logStr, color):
		global LogsFile

		eventID = str(log.nextEventID())

		print("[{0} {1}] ".format(datetime.now().strftime("%d/%b/%Y:%H:%M:%S"), 
			datetime.now(timezone.utc).astimezone().strftime('%z')) + color + logStr + Fore.RESET )

		try:
			with open(LogsFile, "a") as logFile:
				logFile.write("[{0} {1}] {2} EventID={3} Type={4} Log=\"{5}\"\n".format(datetime.now().strftime("%d/%b/%Y:%H:%M:%S"), 
					datetime.now(timezone.utc).astimezone().strftime('%z'), socket.gethostname(), eventID, logType, logStr))
		except Exception as e:
			print("[{0} {1}] {2} '{3}': {4}\n".format(datetime.now().strftime("%d/%b/%Y:%H:%M:%S"), 
				datetime.now(timezone.utc).astimezone().strftime('%z'), "There is a problem writing to the log file", LogsFile, str(e)))
			sys.exit()

		return

	@classmethod
	def writeCmdLog(self, cmd):
		global CommandsFile

		try:
			with open(CommandsFile, "a") as logFile:
				logFile.write("[{0} {1}] {2} Log=\"{3}\"\n".format(datetime.now().strftime("%d/%b/%Y:%H:%M:%S"), 
					datetime.now(timezone.utc).astimezone().strftime('%z'), socket.gethostname(), cmd))
		except Exception as e:
			print("[{0} {1}] {2} '{3}': {4}\n".format(datetime.now().strftime("%d/%b/%Y:%H:%M:%S"), 
				datetime.now(timezone.utc).astimezone().strftime('%z'), "There is a problem writing to the log file", LogsFile, str(e)))
			sys.exit()

		return

#####################################################################################################################
class user:

	@classmethod
	def isRoot(self):
		if os.geteuid() != 0:
			log.error("You need root permissions.")
			return False
		return True



#####################################################################################################################
class scanner:

	@classmethod
	def topTcpPorts(self, projName, topports):
		global TopTcpPortsDir

		ips = db.getLiveHosts()
		for host in ips:
			log.info('Scanning target {0} for open Top {1} TCP ports.'.format(host[0], topports))
			scanner.topPorts(projName, TopTcpPortsDir, host[0], topports)

	@classmethod
	def livehosts(self, projName, target, exclude):
		global LiveHostsDir

		log.info('Scanning target {0} for live hosts.'.format(target))
		scanner.liveHostsIcmpEcho(projName, LiveHostsDir, target, exclude)

		log.info('Scanning target {0} for live hosts.'.format(target))
		scanner.liveHostsTcpAck(projName, LiveHostsDir, target, exclude)

		log.info('Scanning target {0} for live hosts.'.format(target))
		scanner.liveHostsTcpSyn(projName, LiveHostsDir, target, exclude)

		log.info('Scanning target {0} for live hosts.'.format(target))
		scanner.liveHostsSctp(projName, LiveHostsDir, target, exclude)

		log.info('Scanning target {0} for live hosts.'.format(target))
		scanner.liveHostsUdp(projName, LiveHostsDir, target, exclude)

		log.info('Scanning target {0} for live hosts.'.format(target))
		scanner.liveHostsProtocolPing(projName, LiveHostsDir, target, exclude)

		log.info('Scanning target {0} for live hosts.'.format(target))
		scanner.liveHostsTimestamp(projName, LiveHostsDir, target, exclude)

		log.info('Scanning target {0} for live hosts.'.format(target))
		scanner.liveHostsNetmask(projName, LiveHostsDir, target, exclude)

		log.info('Scanning target {0} for live hosts.'.format(target))
		scanner.liveHostsTopTcp100(projName, LiveHostsDir, target, exclude)


	@classmethod
	def generateNmapLogPrefix(self, projName, prefix, outputDir, target):
		nmapLogFilePrefix = "{0}-{1}-{2}-{3}".format(projName, prefix, target, 
			datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))

		return os.path.join(outputDir, nmapLogFilePrefix)

	@classmethod
	def topPorts(self, projName, outputDir, target, topports):
		outputDir = scanner.generateNmapLogPrefix(projName, "top-tcp-ports-{0}-scan".format(topports), outputDir, target)
		command = "nmap -sS -n -Pn -vv --top-ports {0} --reason --open -T4 -oA {1} {2}".format(topports, outputDir, target)
		scanner.scan("Top {0} TCP Ports".format(topports), outputDir, command, target)

	@classmethod
	def liveHostsIcmpEcho(self, projName, outputDir, target, exclude):

		outputDir = scanner.generateNmapLogPrefix(projName, 'live-hosts-icmp-echo-scan', outputDir, target.replace('/', '_'))
		if exclude:
			command = "nmap -vv -n -sn -PE -oA {0} --exclude {1} {2}".format(outputDir, exclude, target)
		else:
			command = "nmap -vv -n -sn -PE -oA {0} {1}".format(outputDir, target)
		scanner.scan('ICMP echo', outputDir, command, target)


	@classmethod
	def liveHostsTcpAck(self, projName, outputDir, target, exclude):

		outputDir = scanner.generateNmapLogPrefix(projName, 'live-hosts-tcp-ack-scan', outputDir, target.replace('/', '_'))
		if exclude:
			command = "nmap -vv -n -sn -PA21,22,23,25,53,80,88,110,111,135,139,143,199,443,445,465,587,993,995,1025,1433,1720,1723,3306,3389,5900,8080,8443 -oA {0} --exclude {1} {2}".format(outputDir, exclude, target)
		else:
			command = "nmap -vv -n -sn -PA21,22,23,25,53,80,88,110,111,135,139,143,199,443,445,465,587,993,995,1025,1433,1720,1723,3306,3389,5900,8080,8443 -oA {0} {1}".format(outputDir, target)
		scanner.scan('TCP ACK', outputDir, command, target)


	@classmethod
	def liveHostsTcpSyn(self, projName, outputDir, target, exclude):

		outputDir = scanner.generateNmapLogPrefix(projName, 'live-hosts-tcp-syn-scan', outputDir, target.replace('/', '_'))
		if exclude:
			command = "nmap -vv -n -sn -PS21,22,23,25,53,80,88,110,111,135,139,143,199,443,445,465,587,993,995,1025,1433,1720,1723,3306,3389,5900,8080,8443 -oA {0} --exclude {1} {2}".format(outputDir, exclude, target)
		else:
			command = "nmap -vv -n -sn -PS21,22,23,25,53,80,88,110,111,135,139,143,199,443,445,465,587,993,995,1025,1433,1720,1723,3306,3389,5900,8080,8443 -oA {0} {1}".format(outputDir, target)
		scanner.scan('TCP SYN', outputDir, command, target)


	@classmethod
	def liveHostsSctp(self, projName, outputDir, target, exclude):

		outputDir = scanner.generateNmapLogPrefix(projName, 'live-hosts-sctp-scan', outputDir, target.replace('/', '_'))
		if exclude:
			command = "nmap -vv -n -sn -PY132,2905 -oA {0} --exclude {1} {2}".format(outputDir, exclude, target)
		else:
			command = "nmap -vv -n -sn -PY132,2905 -oA {0} {1}".format(outputDir, target)
		scanner.scan('SCTP', outputDir, command, target)


	@classmethod
	def liveHostsUdp(self, projName, outputDir, target, exclude):

		outputDir = scanner.generateNmapLogPrefix(projName, 'live-hosts-udp-scan', outputDir, target.replace('/', '_'))
		if exclude:
			command = "nmap -vv -n -sn -PU53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,1434,1600,4500,49152 -oA {0} --exclude {1} {2}".format(outputDir, exclude, target)
		else:
			command = "nmap -vv -n -sn -PU53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,1434,1600,4500,49152 -oA {0} {1}".format(outputDir, target)
		scanner.scan('UDP', outputDir, command, target)


	@classmethod
	def liveHostsProtocolPing(self, projName, outputDir, target, exclude):

		outputDir = scanner.generateNmapLogPrefix(projName, 'live-hosts-protocol-ping-scan', outputDir, target.replace('/', '_'))
		if exclude:
			command = "nmap -vv -n -sn -PO -oA {0} --exclude {1} {2}".format(outputDir, exclude, target)
		else:
			command = "nmap -vv -n -sn -PO -oA {0} {1}".format(outputDir, target)
		scanner.scan('Protocol Ping', outputDir, command, target)


	@classmethod
	def liveHostsTimestamp(self, projName, outputDir, target, exclude):

		outputDir = scanner.generateNmapLogPrefix(projName, 'live-hosts-timestamp-scan', outputDir, target.replace('/', '_'))
		if exclude:
			command = "nmap -vv -n -sn -PP -oA {0} --exclude {1} {2}".format(outputDir, exclude, target)
		else:
			command = "nmap -vv -n -sn -PP -oA {0} {1}".format(outputDir, target)
		scanner.scan('Timestamp', outputDir, command, target)


	@classmethod
	def liveHostsNetmask(self, projName, outputDir, target, exclude):

		outputDir = scanner.generateNmapLogPrefix(projName, 'live-hosts-netmask-scan', outputDir, target.replace('/', '_'))
		if exclude:
			command = "nmap -vv -n -sn -PM -oA {0} --exclude {1} {2}".format(outputDir, exclude, target)
		else:
			command = "nmap -vv -n -sn -PM -oA {0} {1}".format(outputDir, target)
		scanner.scan('Netmask', outputDir, command, target)


	@classmethod
	def liveHostsTopTcp100(self, projName, outputDir, target, exclude):

		outputDir = scanner.generateNmapLogPrefix(projName, 'live-hosts-top-tcp-100-scan', outputDir, target.replace('/', '_'))
		if exclude:
			command = "nmap -vv -sS -n -Pn --top-ports 100 --reason --open -T4 -oA {0} --exclude {1} {2}".format(outputDir, exclude, target)
		else:
			command = "nmap -vv -sS -n -Pn --top-ports 100 --reason --open -T4 -oA {0} {1}".format(outputDir, target)
		scanner.scan('Top 100 TCP Ports', outputDir, command, target)


	@classmethod
	def scan(self, type, nmapLogFilePrefix, command, target):
		global LogsFile

		nmapOutput = ''

		log.info('Scan Type: {1}'.format(target, type))
		log.debug('Command: {0}'.format(command))
		log.info('Nmap Output')

		start = time.time()

		try:
			exec.run(shlex.split(command), False)
			log.writeCmdLog(command)

		except Exception as e:
			log.error("An error occured during nmap scan ({0}): {1}.".format(type, e))

		try:
			
			with open(nmapLogFilePrefix + ".nmap", 'r') as file:
				nmapOutput = file.read()

			with open(LogsFile, 'a') as file:
				file.write(nmapOutput)

		except Exception as e:
			log.error("An error occured while trying to append nmap scan output to log file '{0}': {1}.".format(LogsFile, str(e)))


		message = "Task completed in {0}.".format(help.elapsedTime(start))
		log.infoPickC(message, Fore.CYAN)

		return nmapOutput



#####################################################################################################################
def main(args,extra):
	global LiveHostsList

	defaultTopTcpPorts = 1000

	fm.createProjectDirStructure(args.target, args.project_name, args.working_dir, defaultTopTcpPorts)
	db.connect()

	if not user.isRoot():
		exit(1)

	if pt.setMode(args.target) == True:
		log.info('Penetration Test Type: Internal.')
	else:
		log.info('Penetration Test Type: External.')

	if args.exclude:
		log.info("Excluding: {0}.".format(args.exclude))

	scanner.livehosts(args.project_name, args.target, args.exclude)

	grep.liveHosts(args.target)

	scanner.topTcpPorts(args.project_name, defaultTopTcpPorts)

	grep.openPorts(args.target, defaultTopTcpPorts)

	db.disconnect()



#####################################################################################################################
if __name__ == '__main__':

	print(message)

	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--target', metavar='<host or IP range>', help='target IP or IP range', required=True)
	parser.add_argument('-p', '--project-name', help='project name', required=True)
	parser.add_argument('-w', '--working-dir', help='working directory', required=True)
	parser.add_argument('--exclude', metavar='<host1[,host2][,host3],...>', help='exclude hosts/networks', required=False)

	args,extra = parser.parse_known_args()
	main(args,extra)
