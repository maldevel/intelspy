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

EventID = 0


#####################################################################################################################
class log:

	@classmethod
	def nextEventID(self):
		global EventID
		EventID += 1
		return EventID

	@classmethod
	def info(self, logfile, logStr):
		log.write(logfile, 'Info', logStr)

	@classmethod
	def error(self, logfile, logStr):
		log.write(logfile, 'Error', logStr)

	@classmethod
	def write(self, logfile, logType, logStr):
		eventID = str(log.nextEventID())

		print("[{0} {1}] {2}".format(datetime.now().strftime("%d/%b/%Y:%H:%M:%S"), 
			datetime.now(timezone.utc).astimezone().strftime('%z'), logStr))

		try:
			with open(logfile, "a") as logFile:
				logFile.write("[{0} {1}] {2} EventID={3} Type={4} Log=\"{5}\"\n".format(datetime.now().strftime("%d/%b/%Y:%H:%M:%S"), 
					datetime.now(timezone.utc).astimezone().strftime('%z'), socket.gethostname(), eventID, logType, logStr))
		except:
			e = sys.exc_info()[0]
			print("[{0} {1}] {2} '{3}': {4}\n".format(datetime.now().strftime("%d/%b/%Y:%H:%M:%S"), 
				datetime.now(timezone.utc).astimezone().strftime('%z'), "There is a problem writing to the log file", logfile, e))
			sys.exit()

		return



#####################################################################################################################
class user:

	@classmethod
	def isRoot(self, logfile):
		if os.geteuid() != 0:
			log.error(logfile, "You need root permissions.")
			return False
		return True



#####################################################################################################################
class scanner:

	@classmethod
	def liveHosts(self, logfile, target):

		log.info(logfile, 'Target: {0} Scan Type: ICMP echo.'.format(args.target))
		
		nmapLogFilePrefix = "live-hosts-icmp-echo-scan-{0}-{1}".format(datetime.now().strftime("%Y-%m-%d_%H-%M-%S"), args.target.replace('/', '_'))
		command = "nmap -vv -n -sn -PE -oA {0} {1}".format(nmapLogFilePrefix, args.target)

		log.info(logfile, 'Command: {0}'.format(command))
		log.info(logfile, 'Nmap Output:')
		log.info(logfile, '****************************************************************************')

		try:

			subprocess.run(shlex.split(command))

		except:
			e = sys.exc_info()[0]
			log.error(logfile, "An error occured during nmap scan (Live Hosts, ICMP echo): {0}.".format(e))

		try:
			nmapOutput = ''
			with open(nmapLogFilePrefix + ".nmap", 'r') as file:
				nmapOutput = file.read()

			with open(logfile, 'a') as file:
				file.write(nmapOutput)
		except:
			e = sys.exc_info()[0]
			log.error(logfile, "An error occured while trying to append nmap scan output to log file '{0}': {1}.".format(logfile, e))

		log.info(logfile, '****************************************************************************')



#####################################################################################################################
def main(args,extra,logfile):

	log.info(logfile, 'Scanning target {0} for live hosts.'.format(args.target))
	scanner.liveHosts(logfile, args.target)



#####################################################################################################################
if __name__ == '__main__':

	logfile = 'logs.txt'

	if not user.isRoot(logfile):
		exit(1)

	parser = argparse.ArgumentParser()

	parser.add_argument('-t', '--target', help='target IP or IP range', required=True)
	parser.add_argument('-st', '--scan-type', help='network scan type (internal or external)', required=True)
	parser.add_argument('-p', '--project', help='project name', required=True)
	args,extra = parser.parse_known_args()
	main(args,extra,logfile)
