from command import Command
import os
import json
from colorama import Fore


class Impersonate(Command):
				 		  
	
	def printHelp(self):

		helpstr = """\n Impersonate other user's security context by duplicating a process token.
	\n ** USAGE **: impersonate <PID> 
		"""

		print(helpstr)

	def parseArgs(self, path, cmdSpl, ind):

		if isinstance(cmdSpl[0], int):
			return cmdSpl

		return None

	def writeCommandInFile(self, command, prevId, nextId, filePath):
		if len(command) == 0:
			content = {}
			content['NextId'] = nextId
			content['NextAuth'] = ""
			content['Commands'] = command
			with open(filePath, 'w') as f:
				json.dump(content, f)
			return

		command.insert(0,"impersonate")
		content = {}
		content['NextId'] = nextId
		content['NextAuth'] = ""
		content['Commands'] = command
		with open(filePath, 'w') as f:
			json.dump(content, f)
		
	def executeCommand(self, cmdSpl, prevId, nextId, filePath):
		if cmdSpl[0] == 'help':
			self.printHelp()
		else:
			command = cmdSpl

			if command == None:
				print(Fore.RED + "PID must be a number.")
				self.writeCommandInFile([], prevId, nextId, filePath)
				return False
				
			self.writeCommandInFile(command, prevId, nextId, filePath)
			return True

