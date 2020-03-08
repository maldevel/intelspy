#!/usr/bin/python3

#    This file is part of AutoScan
#    Copyright (C) 2020 @maldevel
#    https://github.com/maldevel/autoscan
#
#    AutoScan - Perform automated reconnaissance scans 
#    against provided IPs or IP ranges.
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
# scan.py Version 1.0
# Released under GPL Version 3 License.
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

EventID = 0
ProjectDir = ''
LiveHostsDir = ''
LogsDir = ''
LogsFile = ''
ReportDir = ''
LiveHostsListFile = ''

#####################################################################################################################
class grep:

	@classmethod
	def liveHosts(self, target):
		global LiveHostsDir, LiveHostsListFile, LogsFile
		
		try:

			gnmapFilesDir = os.path.join(LiveHostsDir, '*.gnmap')

			command = "cat {0} | grep 'Status: Up' | cut -d ' ' -f2 | sort -V | uniq | tee {1}".format(gnmapFilesDir, LiveHostsListFile)
			
			log.info('Live hosts of target {0}.'.format(target))
			log.info('Command: {0}'.format(command))
			log.info('Output:')
			log.info('********************************* START *********************************')
			subprocess.run(command, shell=True)

		except:
			e = sys.exc_info()[0]
			log.error("An error occured during nmap scan results grep: {0}.".format(e))


		try:
			cmdOutput = ''
			with open(LiveHostsListFile, 'r') as file:
				cmdOutput = file.read()

			with open(LogsFile, 'a') as file:
				file.write(cmdOutput)

		except:
			e = sys.exc_info()[0]
			log.error("An error occured while trying to append grep result to log file '{0}': {1}.".format(LogsFile, e))

		log.info('********************************* END *********************************')


#####################################################################################################################
class fm:

	@classmethod
	def createProjectDirStructure(self, target, projName, workingDir):
		global ProjectDir, LiveHostsDir, LogsDir, LogsFile, ReportDir, LiveHostsListFile

		ProjectDir = os.path.join(workingDir, projName)
		LiveHostsDir = os.path.join(ProjectDir, 'live-hosts', target.replace('/', '_'), datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
		LogsDir = os.path.join(ProjectDir, 'logs', target.replace('/', '_'))
		LogsFile = os.path.join(LogsDir, "{0}-log-{1}-{2}.txt".format(projName, target.replace('/', '_'), datetime.now().strftime("%Y-%m-%d_%H-%M-%S")))
		ReportDir = os.path.join(ProjectDir, 'report', target.replace('/', '_'))
		LiveHostsListFile = os.path.join(ReportDir, "{0}-live-hosts-list-{1}-{2}.txt".format(projName, target.replace('/', '_'), datetime.now().strftime("%Y-%m-%d_%H-%M-%S")))

		Path(LiveHostsDir).mkdir(parents=True, exist_ok=True)
		Path(LogsDir).mkdir(parents=True, exist_ok=True)
		Path(ReportDir).mkdir(parents=True, exist_ok=True)

		log.info("Creating project directory structure '{0}'.".format(ProjectDir))		



#####################################################################################################################
class log:

	@classmethod
	def nextEventID(self):
		global EventID
		EventID += 1
		return EventID

	@classmethod
	def info(self, logStr):
		log.write('Info', logStr)

	@classmethod
	def error(self, logStr):
		log.write('Error', logStr)

	@classmethod
	def write(self, logType, logStr):
		global LogsFile
		eventID = str(log.nextEventID())

		print("[{0} {1}] {2}".format(datetime.now().strftime("%d/%b/%Y:%H:%M:%S"), 
			datetime.now(timezone.utc).astimezone().strftime('%z'), logStr))

		try:
			with open(LogsFile, "a") as logFile:
				logFile.write("[{0} {1}] {2} EventID={3} Type={4} Log=\"{5}\"\n".format(datetime.now().strftime("%d/%b/%Y:%H:%M:%S"), 
					datetime.now(timezone.utc).astimezone().strftime('%z'), socket.gethostname(), eventID, logType, logStr))
		except:
			e = sys.exc_info()[0]
			print("[{0} {1}] {2} '{3}': {4}\n".format(datetime.now().strftime("%d/%b/%Y:%H:%M:%S"), 
				datetime.now(timezone.utc).astimezone().strftime('%z'), "There is a problem writing to the log file", LogsFile, e))
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
	def livehosts(self, projName, target):
		global LiveHostsDir

		log.info('Scanning target {0} for live hosts.'.format(target))

		scanner.liveHostsIcmpEcho(projName, LiveHostsDir, target)

		scanner.liveHostsTcpAck(projName, LiveHostsDir, target)

		scanner.liveHostsTcpSyn(projName, LiveHostsDir, target)

		scanner.liveHostsSctp(projName, LiveHostsDir, target)

		scanner.liveHostsUdp(projName, LiveHostsDir, target)

		scanner.liveHostsProtocolPing(projName, LiveHostsDir, target)

		scanner.liveHostsTimestamp(projName, LiveHostsDir, target)

		scanner.liveHostsNetmask(projName, LiveHostsDir, target)

		scanner.liveHostsTopTcp100(projName, LiveHostsDir, target)

		log.info('Scanning target {0} for live hosts completed.'.format(target))


	@classmethod
	def liveHostsIcmpEcho(self, projName, outputDir, target):

		prefix = 'live-hosts-icmp-echo-scan'

		nmapLogFilePrefix = "{0}-{1}-{2}-{3}".format(projName, prefix, args.target.replace('/', '_'), 
			datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))

		outputDir = os.path.join(outputDir, nmapLogFilePrefix)

		command = "nmap -vv -n -sn -PE -oA {0} {1}".format(outputDir, args.target)

		scanner.scan('ICMP echo', outputDir, command, target)

	@classmethod
	def liveHostsTcpAck(self, projName, outputDir, target):

		prefix = 'live-hosts-tcp-ack-scan'

		nmapLogFilePrefix = "{0}-{1}-{2}-{3}".format(projName, prefix, args.target.replace('/', '_'), 
			datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))

		outputDir = os.path.join(outputDir, nmapLogFilePrefix)

		command = "nmap -vv -n -sn -PA21,22,23,25,53,80,88,110,111,135,139,143,199,443,445,465,587,993,995,1025,1433,1720,1723,3306,3389,5900,8080,8443 -oA {0} {1}".format(outputDir, args.target)

		scanner.scan('TCP ACK', outputDir, command, target)

	@classmethod
	def liveHostsTcpSyn(self, projName, outputDir, target):

		prefix = 'live-hosts-tcp-syn-scan'

		nmapLogFilePrefix = "{0}-{1}-{2}-{3}".format(projName, prefix, args.target.replace('/', '_'), 
			datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))

		outputDir = os.path.join(outputDir, nmapLogFilePrefix)

		command = "nmap -vv -n -sn -PS21,22,23,25,53,80,88,110,111,135,139,143,199,443,445,465,587,993,995,1025,1433,1720,1723,3306,3389,5900,8080,8443 -oA {0} {1}".format(outputDir, args.target)

		scanner.scan('TCP SYN', outputDir, command, target)


	@classmethod
	def liveHostsSctp(self, projName, outputDir, target):

		prefix = 'live-hosts-sctp-scan'

		nmapLogFilePrefix = "{0}-{1}-{2}-{3}".format(projName, prefix, args.target.replace('/', '_'), 
			datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))

		outputDir = os.path.join(outputDir, nmapLogFilePrefix)

		command = "nmap -vv -n -sn -PY132,2905 -oA {0} {1}".format(outputDir, args.target)

		scanner.scan('SCTP', outputDir, command, target)

	@classmethod
	def liveHostsUdp(self, projName, outputDir, target):

		prefix = 'live-hosts-udp-scan'

		nmapLogFilePrefix = "{0}-{1}-{2}-{3}".format(projName, prefix, args.target.replace('/', '_'), 
			datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))

		outputDir = os.path.join(outputDir, nmapLogFilePrefix)

		command = "nmap -vv -n -sn -PU53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,1434,1600,4500,49152 -oA {0} {1}".format(outputDir, args.target)

		scanner.scan('UDP', outputDir, command, target)

	@classmethod
	def liveHostsProtocolPing(self, projName, outputDir, target):

		prefix = 'live-hosts-protocol-ping-scan'

		nmapLogFilePrefix = "{0}-{1}-{2}-{3}".format(projName, prefix, args.target.replace('/', '_'), 
			datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))

		outputDir = os.path.join(outputDir, nmapLogFilePrefix)

		command = "nmap -vv -n -sn -PO -oA {0} {1}".format(outputDir, args.target)

		scanner.scan('Protocol Ping', outputDir, command, target)

	@classmethod
	def liveHostsTimestamp(self, projName, outputDir, target):

		prefix = 'live-hosts-timestamp-scan'

		nmapLogFilePrefix = "{0}-{1}-{2}-{3}".format(projName, prefix, args.target.replace('/', '_'),  
			datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))

		outputDir = os.path.join(outputDir, nmapLogFilePrefix)

		command = "nmap -vv -n -sn -PP -oA {0} {1}".format(outputDir, args.target)

		scanner.scan('Timestamp', outputDir, command, target)

	@classmethod
	def liveHostsNetmask(self, projName, outputDir, target):

		prefix = 'live-hosts-netmask-scan'

		nmapLogFilePrefix = "{0}-{1}-{2}-{3}".format(projName, prefix, args.target.replace('/', '_'), 
			datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))

		outputDir = os.path.join(outputDir, nmapLogFilePrefix)

		command = "nmap -vv -n -sn -PM -oA {0} {1}".format(outputDir, args.target)

		scanner.scan('Netmask', outputDir, command, target)

	@classmethod
	def liveHostsTopTcp100(self, projName, outputDir, target):

		prefix = 'live-hosts-top-tcp-100-scan'

		nmapLogFilePrefix = "{0}-{1}-{2}-{3}".format(projName, prefix, args.target.replace('/', '_'), 
			datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))

		outputDir = os.path.join(outputDir, nmapLogFilePrefix)

		command = "nmap -vv -sS -n -Pn --top-ports 100 --reason --open -T4 -oA {0} {1}".format(outputDir, args.target)

		scanner.scan('Top TCP 100', outputDir, command, target)


	@classmethod
	def scan(self, type, nmapLogFilePrefix, command, target):
		global LogsFile

		log.info('Target: {0} Scan Type: {1}'.format(args.target, type))
		log.info('Command: {0}'.format(command))
		log.info('Nmap Output:')
		log.info('********************************* START *********************************')

		try:

			subprocess.run(shlex.split(command))

		except:
			e = sys.exc_info()[0]
			log.error("An error occured during nmap scan ({0}): {1}.".format(type, e))

		try:
			nmapOutput = ''
			with open(nmapLogFilePrefix + ".nmap", 'r') as file:
				nmapOutput = file.read()

			with open(LogsFile, 'a') as file:
				file.write(nmapOutput)
		except:
			e = sys.exc_info()[0]
			log.error("An error occured while trying to append nmap scan output to log file '{0}': {1}.".format(LogsFile, e))

		log.info('********************************* END *********************************')



#####################################################################################################################
def main(args,extra):

	fm.createProjectDirStructure(args.target, args.project_name, args.working_dir)

	if not user.isRoot():
		exit(1)

	scanner.livehosts(args.project_name, args.target)

	grep.liveHosts(args.target)


#####################################################################################################################
if __name__ == '__main__':

	parser = argparse.ArgumentParser()

	parser.add_argument('-t', '--target', help='target IP or IP range', required=True)
	parser.add_argument('-st', '--scan-type', help='network scan type (internal or external)', required=True)
	parser.add_argument('-p', '--project-name', help='project name', required=True)
	parser.add_argument('-w', '--working-dir', help='working directory', required=True)

	args,extra = parser.parse_known_args()
	main(args,extra)
