from asatoafm_config import *

#Good for large files, after line is read, the line is taken out of memory
import fileinput
import re
import sys
from pprint import pprint

#Global variables
portMappingHash = {}

#                         1                  2			3					4		
aclRegex = 'access-list ([0-9a-zA-Z\_\-]+)\s*(extended)*\s*(permit|deny) (ip|tcp|udp|icmp|[0-9]+|gre|)'

#                         5                                      6
noPortRegex = ' (\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|any|host \d+\.\d+\.\d+\.\d+)+ (\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|any|host \d+\.\d+\.\d+\.\d+)+'
tcpUdpRegex = ' (\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|any|host \d+\.\d+\.\d+\.\d+)+'
justAccessListRegex = 'access-list'
portMappingFileRegex = '([A-Za-z0-9\-]+)\s+([0-9]+[0,5])\/((tcp|udp)+)'
objectGroupDescriptionRegex = '\s+description\s+(.*)'

createRuleListString = 'create /security firewall rule-list '
modifyRuleListString = 'modify /security firewall rule-list '

ipAndNetmaskRegex = '(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)'
hostAndIpRegex = '(host)\s+(\d+\.\d+\.\d+\.\d+)'

inServiceObjectGroupRegex ='^object\-group\s+service\s+([A-Za-z0-9\-]+)\s+(tcp|udp)'
portRangeObjectRegex = '\s+port\-object\s+range\s+([a-z0-9]+)\s+([a-z0-9]+)'
portObjectRegex = '\s+port\-object\s+(eq|gt|lt|range)\s+([a-z0-9]+)\s*([a-z0-9]*)'
portSingleObjectRegex =  '(eq|gt|lt)\s+([a-z0-9]+)'

ciscoPortMapFileRegex = '\s*([A-Za-z0-9\-]+)\s+(\d+)'

inNetworkObjectGroupRegex ='^object\-group\s+network\s+([A-Za-z0-9\-]+)'



###Pre execution
if sys.argv[1]:
	ciscoAclFile=sys.argv[1]
	
else:
	sys.exit([arg])

if DEBUG == 1:
	DEBUGFILEHANDLE = open(DEBUGFILE,'w')
###End of pre execution

def readPortMappingFile():

	for line in fileinput.input([portMappingFile]):
		matchObject = re.match(portMappingFileRegex,line)

		if matchObject:
			portMappingHash[matchObject.group(1)]=matchObject.group(2)

		elif DEBUG == 1:
			DEBUGFILEHANDLE.write("PortMappingsFile, line is not a defined service " + line)
	
#list is nice because it correlates directly to line numbers
def readFirewallFileToList():

	noPortAclList = []
	tcpUdpList = []
	icmpList = []
	
	for line in fileinput.input([ciscoAclFile]):
	
		matchAcl = re.match(aclRegex,line)
		matchAclFallback = re.match(justAccessListRegex,line)
		
		if matchAcl:
		
			if matchAcl.group(4) == "tcp" or matchAcl.group(4) == "udp":
				tcpUdpList.append(line)	
		
			elif matchAcl.group(4) == "icmp":
				icmpList.append(line)
		
			#We assume anything that is not tcp or udp does not have a port and therefore, looks like an ip acl
			else:
				noPortAclList.append(line)	
		
		#If the line has access-list in it, but was not caught, we want to log this
		elif matchAclFallback:
			DEBUGFILEHANDLE.write("Line is acl, but not caught in regex:\n" + line)

	return noPortAclList,tcpUdpList,icmpList	
	
def readCisoPortMapFileToDictionary():

	ciscoPortMapDictionary = {}

	for line in fileinput.input([ciscoPortMapFile]):
	
		matchPortMapLine = re.match(ciscoPortMapFileRegex,line)
		
		if matchPortMapLine:
		
			ciscoPortMapDictionary[matchPortMapLine.group(1)]=matchPortMapLine.group(2)
			
		elif DEBUG == 1:
			DEBUGFILEHANDLE.write("CiscoPortMapFile, line not caught " + line)
			
	return ciscoPortMapDictionary
	
def readFirewallFileToObjectList(ciscoPortMapDictionary):

	print "In firewall to object list\n"

	serviceObjectList = []
	
	#Holder for whether we are in an object
	inServiceObject = 0
	inNetworkObject = 0

	for line in fileinput.input([ciscoAclFile]):
	
		print "In for: " + line + "\n"
		
		matchStartOfServiceObject = re.match(inServiceObjectGroupRegex,line)
		matchStartOfNetworkObject = re.match(inNetworkObjectGroupRegex,line)
		matchDescription = re.match(objectGroupDescriptionRegex,line)
		matchPortObject = re.match(portObjectRegex,line)

		if matchStartOfServiceObject:
		
			print "in match start of service object"
		
			inServiceObject = 1
			
			serviceObject = serviceGroupObject(matchStartOfServiceObject.group(1))
			serviceObject.setProtocol(matchStartOfServiceObject.group(2))
			serviceObjectList.append(serviceObject)		
			
		elif (inServiceObject == 1) and matchDescription:
		
			print "in match 1 of service object"

		
			serviceObject = serviceObjectList[len(serviceObjectList)-1]
			serviceObject.setDescription(matchDescription.group(1))
			
		elif (inServiceObject == 1) and matchPortObject:
		
			print "in match 2 of service object"

		
			serviceObject.appendPortObject(line,ciscoPortMapDictionary)		
				
		elif matchStartOfNetworkObject:
		
			print "in match 3 of service object"

		
			inNetworkObject = 1
			
	print "Return"
		
	return serviceObjectList


def convertNoPortAclListToObjects(noPortAclList,noPortAclObjectList,aclNameDict):

	fullNoPortRegex = aclRegex + noPortRegex
	
	print fullNoPortRegex

	for line in noPortAclList:
	
		matchAcl = re.match(fullNoPortRegex,line)
		
		if matchAcl:
			
			aclName = matchAcl.group(1)
			
			#Add the acl name if its unique
			if not aclName in aclNameDict:
							
				aclNameDict.update({ aclName: 1 })
				
			#If the acl name (ruleset already exists, we need to count how many rules are in the ruleset, to give unique names
			else:
			
				aclNameDict[aclName] += 1		
			
			aclAction = matchAcl.group(3)
			aclProtocol = matchAcl.group(4)
			aclSource = matchAcl.group(5)
			aclDestination = matchAcl.group(6)
			aclLine = line
			
			
			newObject = noPortAcl(aclName,aclAction,aclProtocol,aclSource,aclDestination,aclLine)
			noPortAclObjectList.append(newObject)	
			
def convertTcpUdpAclListToObjects(tcpUdpAclList,tcpUdpAclObjectList,aclNameDict):

	fullTcpUdpRegec = aclRegex + tcpUdpRegex


#Takes ios netmask and flips it to read correctly
#Not used in PIX/ASA			
def flipNetmask(mask):

	flipDictionary = {"1":"0","0":"1",".":"."}
	flippedMaskBin = ""

	binaryRepresentation =  '.'.join([bin(int(x)+256)[3:] for x in mask.split('.')])
	
	for bit in binaryRepresentation:
		
		flippedMaskBin = flippedMaskBin + flipDictionary[bit] 
		
	flippedMaskDec = '.'.join([str((int(y,2))) for y in flippedMaskBin.split('.')])
	
	return flippedMaskDec
		
def writeCreateRulesets (aclNameDict,TMSHAFMFILEHANDLE):

	for aclName in aclNameDict:

		TMSHAFMFILEHANDLE.write(createRuleListString + aclName + "\n")
		
	return
	
def writeNoPortAclListRules(noPortAclObjectList,TMSHAFMFILEHANDLE):

	aclNameDictCount = {}
	aclObjectsWrittenCount = 0

	for object in noPortAclObjectList:
	
		aclName = object.ciscoName
		
		#Add the acl name if its unique
		if not aclName in aclNameDictCount:
							
			aclNameDictCount.update({ aclName: 1 })
				
		#If the acl name (ruleset already exists, we need to count how many rules are in the ruleset, to give unique names
		else:
			
			aclNameDictCount[aclName] += 1
		
		aclAction = object.afmAction
		aclProtocol = object.afmProtocol
		aclSource = object.afmSource
		aclDestination = object.afmDestination
	
		#create /security firewall rule-list testrulelist rules add { rulelist_4  { place-after last action accept }}
		TMSHAFMFILEHANDLE.write(modifyRuleListString + " " + aclName + " rules add { " + aclName + str(aclNameDictCount[aclName]) + " { destination { addresses add { " + aclDestination + " }} " + "ip-protocol " + aclProtocol + " source { addresses add { " +  aclSource + " {} }}  place-after last action " + aclAction + "}}\n" )	
		aclObjectsWrittenCount += 1
		
	return aclObjectsWrittenCount

#def convertTcpUdpAclListToObjects(list):

#def convertIcmpAclListToObjects(list):
		
class noPortAcl():
	
	def __init__(self,name):
		self.name = name
			
	def __init__(self,name,action,protocol,source,destination,line):
		
		self.ciscoName = name
		self.afmName = name
		self.ciscoProtocol = protocol
		self.afmProtocol = protocol
		self.ciscoLine = line
		
		self.ciscoAction = action
		
		
		if self.ciscoAction == "deny":
			
				self.afmAction = "drop"
				
		elif self.ciscoAction == "permit":
		
				self.afmAction = "accept"
				
		else:
		
			self.afmAction = "UNDEFINEDACTION"
				
		self.ciscoSource = source
		matchObjectSourceIpNetmask = re.match(ipAndNetmaskRegex,self.ciscoSource)
		matchObjectSourceHost= re.match(hostAndIpRegex,self.ciscoSource)

		
		if self.ciscoSource == "any":
		
			self.afmSource = "any"
			
		elif matchObjectSourceIpNetmask:
		
			self.afmSource = matchObjectSourceIpNetmask.group(1) + '/' + matchObjectSourceIpNetmask.group(2)
			
		elif matchObjectSourceHost:
		
			self.afmSource = matchObjectSourceHost.group(2) + '/' + '32'
			
		else:
		
			self.afmSource = "UNDEFINEDDESTINATION"
		
		self.ciscoDestination = destination
		matchObjectDestination = re.match(ipAndNetmaskRegex,self.ciscoDestination)
		
		if self.ciscoDestination == "any":
		
			self.afmDestination = "any"
			
	#	elif matchObjectDestination:
		
	#		self.afmDestination = matchObjectDestination.group(1) + '/' + matchObjectDestination.group(2)
			
	#	elif matchObjectDestinationHost:
		
	#		self.afmDestination = matchObjectDestinationHost.group(2) + '/' + '32'
			
		else:
		
			self.afmDestination = "UNDEFINEDDESTINATION"

#Class to hold cisco service object to afm		
class serviceGroupObject():

	def __init__(self,name):
	
		self.ciscoName = name
		self.portObjectList = []
			
	def setDescription(self,description):
	
		self.description = description
		
	def setProtocol(self,protocol):
	
		self.protocol = protocol
		
	def appendPortObject(self,portObjectString,ciscoPortMapDictionary):
	
		portObject1 = portObject(portObjectString,ciscoPortMapDictionary)	
		self.portObjectList.append(portObject1)
			
#Class to hold and convert port-object lines to afm
class portObject():

	def __init__(self,ciscoPortString,ciscoPortMapDictionary):
	
		self.ciscoPortString = ciscoPortString
		
		print "CiscoPortString: " + ciscoPortString + "\n"
		
		portSingleObjectRegexMatch = re.match(portSingleObjectRegex,ciscoPortString)
		portRangeObjectRegexMatch = re.match(portRangeObjectRegex,ciscoPortString)

		
		if portSingleObjectRegexMatch:
		
			justDigitsInPort = re.match('^\d+$',portSingleObjectRegexMatch.group(2))
		
			if justDigitsInPort:
			
				self.afmPortString = justDigitsInPort.group(0)
			
			else:
			
				ciscoPort = portSingleObjectRegexMatch.group(2)
				#NEEDS to be changed
				self.afmPortString = ciscoPortMapDictionary[ciscoPort]
				print "afmPortString: " + self.afmPortString + "\n"
	
		elif portRangeObjectRegexMatch:
		
			print "In range regex match " + portRangeObjectRegexMatch.group(2) + "\n"
		
			justDigitsInPort1 = re.match('^\d+$',portRangeObjectRegexMatch.group(1))
			justDigitsInPort2 = re.match('^\d+$',portRangeObjectRegexMatch.group(2))
			
			afmPort1 = ""
			afmPort2 = ""

			if justDigitsInPort1:
			
				afmPort1 = portRangeObjectRegexMatch.group(1)

			else:
			
				afmPort1 = ciscoPortMapDictionary[portRangeObjectRegexMatch.group(1)]

			if justDigitsInPort2:
			
				afmPort2 = portRangeObjectRegexMatch.group(2)

			else:
			
				afmPort2 = ciscoPortMapDictionary[portRangeObjectRegexMatch.group(2)]
				
			self.afmPortString = afmPort1 + "\-" + afmPort2
			
			print "AFM port range string: " + self.afmPortString + "\n"
			
			
		else:
		
			self.afmPortString = "UNDEFINED"
		

	
		
		
class networkGroupObject():

	def __init__(self,name):
	
		self.ciscoName = name
		
		
		
                        
def main():
	
	noPortAclObjectList = []
	tcpUdpAclObjectList = []

	#Hash to keep all acl names
	aclNameDict = {}
	
	readPortMappingFile()
	
	ciscoPortMapDictionary = readCisoPortMapFileToDictionary()
	pprint(ciscoPortMapDictionary)
		
	TMSHAFMFILEHANDLE = open(TMSHAFMFILE,'w')
	
	#Read all cisco objects and convert them to python objects
	serviceObjectList = readFirewallFileToObjectList(ciscoPortMapDictionary)

	noPortAclList,tcpUdpAclList,icmpAclList = readFirewallFileToList()
	
	#If list is not empty, create a list of cisco no port objects, then a list of am no port objects
	if noPortAclList:
	
		convertNoPortAclListToObjects(noPortAclList,noPortAclObjectList,aclNameDict)
		
	if tcpUdpAclList:
	
		convertTcpUdpAclListToObjects(tcpUdpAclList,tcpUdpAclObjectList,aclNameDict)	
		
	#Write afm tmsh to file
	writeCreateRulesets(aclNameDict,TMSHAFMFILEHANDLE)
	noPortObjectsWrittenCount = writeNoPortAclListRules(noPortAclObjectList,TMSHAFMFILEHANDLE)
			
	#if tcpUdpAclList:
	#	convertTcpUdpAclListToObjects(tcpUdpAclList)
		
	#if icmpAclList:
	#	convertIcmpAclListToObjects(icmpAclList)

	#Close any open files
	if DEBUG == 1:
		DEBUGFILEHANDLE.closed
				
	TMSHAFMFILEHANDLE.closed
	
	for object in serviceObjectList:
	
		print "Object name: " + object.ciscoName + "\n"
		print "Protocol: " + object.protocol + "\n"
		print "Description: " + object.description + "\n"
		
		for portObject in object.portObjectList:
		
			print "Cisco Port String: " + portObject.ciscoPortString + " AfmPortString: " + portObject.afmPortString + "\n"

	print "Number of acls without ports converted to tmsh: " + str(noPortObjectsWrittenCount) + "\n"
	
	return


main()


