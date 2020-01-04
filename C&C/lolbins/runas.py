from command import Command
import os
import json

class Runas(Command):
				 		  
	
	def printHelp(self):

		helpstr = """\n Log in as other local or domain user using a valid password.
	\n ** USAGE **: runas <[domain\]username> <password> 
	\n [+] Unlike the original windows runas, this command modifies your local security context.
	\n [+] Use rev2self to get back to the original security context.
		"""

		print(helpstr)

	def writeCommandInFile(self, command, prevId, nextId, filePath):

		command.insert(0,"runas")
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

