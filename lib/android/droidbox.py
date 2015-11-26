################################################################################
# (c) 2011, The Honeynet Project
# Author: Patrik Lantz patrik@pjlantz.com and Laurent Delosieres ldelosieres@hispasec.com
#
# This program is free software you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
################################################################################

"""Analyze dynamically Android applications

This script allows you to analyze dynamically Android applications. It installs, runs, and analyzes Android applications.
At the end of each analysis, it outputs the Android application's characteristics in JSON.
Please keep in mind that all data received/sent, read/written are shown in hexadecimal since the handled data can contain binary data.
"""

import sys, json, time, curses, signal, os, inspect
import zipfile, StringIO
import tempfile, shutil
import operator
import subprocess
import thread, threading
import re
import logging

from threading import Thread
from xml.dom import minidom
from subprocess import call, PIPE, Popen
from lib.android.utils import AXMLPrinter
import hashlib
# from pylab import *
# import matplotlib
# import matplotlib.pyplot as plt
# from matplotlib.patches import Rectangle
# from matplotlib.font_manager import FontProperties

from collections import OrderedDict
log = logging.getLogger(__name__)

sendsms = {}
phonecalls = {}
cryptousage = {}
dexclass = {}
dataleaks = {}
opennet = {}
sendnet = {}
recvnet = {}
closenet = {}
fdaccess = {}
servicestart = {}
accessedfiles = {}

tags = { 0x1 :   "TAINT_LOCATION",      0x2: "TAINT_CONTACTS",        0x4: "TAINT_MIC",            0x8: "TAINT_PHONE_NUMBER",
         0x10:   "TAINT_LOCATION_GPS",  0x20: "TAINT_LOCATION_NET",   0x40: "TAINT_LOCATION_LAST", 0x80: "TAINT_CAMERA",
         0x100:  "TAINT_ACCELEROMETER", 0x200: "TAINT_SMS",           0x400: "TAINT_IMEI",         0x800: "TAINT_IMSI",
         0x1000: "TAINT_ICCID",         0x2000: "TAINT_DEVICE_SN",    0x4000: "TAINT_ACCOUNT",     0x8000: "TAINT_BROWSER",
         0x10000: "TAINT_OTHERDB",      0x20000: "TAINT_FILECONTENT", 0x40000: "TAINT_PACKAGE",    0x80000: "TAINT_CALL_LOG",
         0x100000: "TAINT_EMAIL",       0x200000: "TAINT_CALENDAR",   0x400000: "TAINT_SETTINGS" }

class Application:
     """
     Used for extracting information of an Android APK
     """
     def __init__(self, filename):
	self.filename = filename
	self.packageNames = []
	self.enfperm = []
	self.permissions = []
	self.recvs = []
	self.activities = {}
	self.recvsaction = {}

	self.mainActivity = None

     def processAPK(self):
	 xml = {}
	 error = True
	 try:
		 zip = zipfile.ZipFile(self.filename)

		 for i in zip.namelist() :
			if i == "AndroidManifest.xml" :
				try :
					xml[i] = minidom.parseString( zip.read( i ) )
				except :
					xml[i] = minidom.parseString( AXMLPrinter( zip.read( i ) ).getBuff() )

				for item in xml[i].getElementsByTagName('manifest'):
					self.packageNames.append( str( item.getAttribute("package") ) )

				for item in xml[i].getElementsByTagName('permission'):
					self.enfperm.append( str( item.getAttribute("android:name") ) )

				for item in xml[i].getElementsByTagName('uses-permission'):
					self.permissions.append( str( item.getAttribute("android:name") ) )

				for item in xml[i].getElementsByTagName('receiver'):
					self.recvs.append( str( item.getAttribute("android:name") ) )
					for child in item.getElementsByTagName('action'):
						self.recvsaction[str( item.getAttribute("android:name") )] = (str( child.getAttribute("android:name") ))

				for item in xml[i].getElementsByTagName('activity'):
					activity = str( item.getAttribute("android:name") )
					self.activities[activity] = {}
					self.activities[activity]["actions"] = list()
			
					for child in item.getElementsByTagName('action'):
						self.activities[activity]["actions"].append(str(child.getAttribute("android:name")))

				for activity in self.activities:
					for action in self.activities[activity]["actions"]:
						if action == 'android.intent.action.MAIN':
							self.mainActivity = activity
				error = False

				break

		 if (error == False):
			return 1
		 else:
			return 0

	 except:
		 return 0

     def getEnfperm(self):
	return self.enfperm
	
     def getRecvsaction(self):
	return self.recvsaction

     def getMainActivity(self):
	return self.mainActivity

     def getActivities(self):
	return self.activities

     def getRecvActions(self):
	return self.recvsaction

     def getPackage(self):
	#One application has only one package name
	return self.packageNames[0]
 
     def getHashes(self, block_size=2**8):
	"""
	Calculate MD5,SHA-1, SHA-256
	hashes of APK input file
	"""

	md5 = hashlib.md5()
	sha1 = hashlib.sha1()
	sha256 = hashlib.sha256()
	f = open(self.filename, 'rb')
	while True:
		data = f.read(block_size)
		if not data:
		    break

		md5.update(data)
		sha1.update(data)
		sha256.update(data)
	return [md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()]
 
def decode(s, encodings=('ascii', 'utf8', 'latin1')):
    for encoding in encodings:
	try:
	    return s.decode(encoding)
	except UnicodeDecodeError:
	    pass
    return s.decode('ascii', 'ignore')

def getTags(tagParam):
    """
    Retrieve the tag names
    """

    tagsFound = []
    for tag in tags.keys():
        if tagParam & tag != 0:
            tagsFound.append(tags[tag])
    return tagsFound

def hexToStr(hexStr):
    """
    Convert a string hex byte values into a byte string
    """

    bytes = []
    hexStr = ''.join(hexStr.split(" "))
    for i in range(0, len(hexStr), 2):
	bytes.append(chr(int(hexStr[i:i+2], 16)))
    return unicode(''.join( bytes ), errors='replace')


def interruptHandler(signum, frame):
    """ 
	Raise interrupt for the blocking call 'logcatInput = sys.stdin.readline()'
	
	"""
    raise KeyboardInterrupt	

































class Droidbox():
	def __init__ (self, apkName, ip, port="5555"):
		self.ip = ip
		self.port = port
		self.duration = 20
		self.apkName = apkName
		self.adb = None


		print " ____                        __  ____   "
		print "/\  _`\                     /\ \/\  _`\\   [Cuckoo Integrated] "
		print "\ \ \/\ \  _ __  ___ /\_\   \_\ \ \ \L\ \   ___   __  _"  
		print " \ \ \ \ \/\`'__\ __`\/\ \  /'_` \ \  _ <' / __`\/\ \/'\\" 
		print "  \ \ \_\ \ \ \/\ \L\ \ \ \/\ \L\ \ \ \L\ \\ \L\ \/>  </"
		print "   \ \____/\ \_\ \____/\ \_\ \___,_\ \____/ \____//\_/\_\\"
		print "    \/___/  \/_/\/___/  \/_/\/__,_ /\/___/ \/___/ \//\/_/"


		#APK existing?
		if os.path.isfile(self.apkName) == False:
		    raise Exception("File %s not found" % self.apkName)

		application = Application(self.apkName)
		ret = application.processAPK()
		guest_check = os.system("ping -c 1 " + self.ip);
		
		#Error during the APK processing?
		if (ret == 0):
			raise Exception("Failed to analyze the APK. Terminate the analysis.")

		if (guest_check != 0):
			raise Exception("Guest is down!")

		activities = application.getActivities()
		self.mainActivity = application.getMainActivity()
		self.packageName = application.getPackage()

		self.recvsaction = application.getRecvsaction()
		self.enfperm = application.getEnfperm()

		#Get the hashes
		self.hashes = application.getHashes()
		log.warning("=====> connecting to adb (ip: {0})".format(self.ip))
		call(['adb', 'connect', self.ip])
		call(['adb', '-s', "{0}:{1}".format(self.ip, self.port), 'logcat', '-c'])

	def wait_for_completion(self):
		#No Main acitvity found? Return an error
		if self.mainActivity == None:
			raise Exception("No activity to start. Terminate the analysis.")

		#No packages identified? Return an error
		if self.packageName == None:
			raise Exception("No package found. Terminate the analysis.")

		log.warning("mainActivity: {0}".format(self.mainActivity))
		log.warning("self.packageName: {0}".format(self.packageName))

		#Execute the application
		#stderr=PIPE,
		ret = call(['monkeyrunner', 'monkeyrunner.py', "{0}:{1}".format(self.ip, self.port), self.apkName, self.packageName, self.mainActivity], cwd=os.path.dirname(os.path.realpath(__file__)))

		if (ret == 1):
			raise Exception("Failed to execute the application.")

		log.warning("Starting the activity %s..." % self.mainActivity)

		#By default the application has not started
		applicationStarted = 0
		stringApplicationStarted = "Start proc %s" % self.packageName
		#Open the adb logcat
		#'-s', "{0}:{1}".format(ip, port),
		self.adb = Popen(["adb", "logcat", "DroidBox:W", "dalvikvm:W", "ActivityManager:I"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

		#Wait for the application to start
		while 1:
			try:
				logcatInput = self.adb.stdout.readline()
				if not logcatInput:
	                    		raise Exception("We have lost the connection with ADB.")

				#Application started?
				if (stringApplicationStarted in logcatInput):
					applicationStarted = 1
					break;
			except:
				break

		if (applicationStarted == 0):
			#Kill ADB, otherwise it will never terminate
		        #os.kill(self.adb.pid, signal.SIGTERM)
		        raise Exception("Analysis has not been done.")

		print("Application started")
		#self.wait_for_completion()


		print("Analyzing the application during %s seconds..." % (self.duration if (self.duration !=0) else "infinite time"))

		timeStamp = time.time()
		#if self.duration:
		#    signal.signal(signal.SIGALRM, interruptHandler)
		#    signal.alarm(self.duration)

		all_output = []
		#Collect DroidBox logs
		while 1:
			try:
				logcatInput = self.adb.stdout.readline() 
				if not logcatInput:
					print log.error("We have lost the connection with ADB.")
					raise Exception("We have lost the connection with ADB.")
				
				all_output.append(logcatInput)
				if( round(time.time() - timeStamp) > self.duration ):
					print log.error("=========>Stop collectiong / timeout hits")
					raise Exception("=========>Stop collectiong")
				else:
					time.sleep(1)

			except:
				log.warning("==>try: stopCounting, join <=========")
				all_output = ",,,".join(all_output)
				log.warning("+++++++++++++++++++>   %s", all_output)
				break;
		    
		#Kill ADB, otherwise it will never terminate
		#os.kill(self.adb.pid, signal.SIGTERM)

		#Done? Store the objects in a dictionary, transform it in a JSON object and return it
		#output = dict()

		#Sort the items by their key
		# output["dexclass"] = dexclass
		# output["servicestart"] = servicestart

		# output["recvnet"] = recvnet
		# output["opennet"] = opennet
		# output["sendnet"] = sendnet
		# output["closenet"] = closenet

		# output["accessedfiles"] = accessedfiles
		# output["dataleaks"] = dataleaks

		# output["fdaccess"] = fdaccess
		# output["sendsms"] = sendsms
		# output["phonecalls"] = phonecalls
		# output["cryptousage"] = cryptousage

		# output["recvsaction"] = self.recvsaction
		# output["enfperm"] = self.enfperm

		# output["hashes"] = self.hashes
		# output["apkName"] = self.apkName
		
		log.warning("=======================>end, dump and return droidbox")
		return True
