from command import Command
import os
import json

class Powershell(Command):
				 		  
	
	def printHelp(self):

		helpstr = """\n Generate a remote Powershell version 2 connection.
	\n ** USAGE **: psh <remote ip> <remote port> 
	\n [+] The connection should be handled with some external software like netcat.
		"""

		print(helpstr)

	def writeCommandInFile(self, command, prevId, nextId, filePath):

		command.insert(0,"powershell")
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
			#os.system(command)
			self.writeCommandInFile(command, prevId, nextId, filePath)
			return True

