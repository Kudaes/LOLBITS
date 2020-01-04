import pathlib
import os
from colorama import Fore
import json


class Command():

	__options = []
	__execution = []
	
	def __init__(self, options = None, execution = None):

		self.exists = {}
		self.next = 0 
		self.__options = options
		self.__execution = execution

	def parseArgs(self, path, cmdSpl, ind):

		finalCom = self.__execution[ind].replace("?p", path)
		finalCom = finalCom.replace("?i",cmdSpl[0])
		finalCom = finalCom.replace("?o",cmdSpl[1])
		return finalCom

	def printMessage(self):

		pass

	def printHelp(self):

		pass

	def checkCompatibility(self, ind, cmdSpl):

		return True

	def selectWithCompatibility(self,cmdSpl):

		for e in self.exists:
			if self.checkCompatibility(e,cmdSpl):
				return True, self.exists.get(e)

		return False, None

	def writeCommandInFile(self, command, prevId, nextId, filePath):
		content = {}
		content['NextId'] = nextId
		content['NextAuth'] = ""
		content['Commands'] = [command]
		with open(filePath, 'w') as f:
			json.dump(content, f)


	def executeCommand(self, cmdSpl, prevId, nextId, filePath):

		if cmdSpl[0] == 'help':
			self.printHelp()
		else:
			exit = False
			new = ""
			while (self.next < len(self.__options)) and not exit:
				if  not self.__options[self.next].lower().startswith('c:\\'):
					path1 = "c:\windows\system32\\" + self.__options[self.next]
					path2 = "c:\windows\syswow64\\" + self.__options[self.next]
					if pathlib.Path(path1).exists():
						self.exists[self.next] = path1
						if self.checkCompatibility(self.next, cmdSpl):
							exit = True
							new = path1
					elif pathlib.Path(path2).exists():
						self.exists[self.next] = path2
						if self.checkCompatibility(self.next,cmdSpl):
							exit = True
							new = path2
					
				else:
					path = self.__options[self.next]
					if pathlib.Path(path).exists():
						self.exists[self.next] = path
						if self.checkCompatibility(self.next,cmdSpl):
							exit = True
							new = path

				self.next += 1
			if new == "":
				if len(self.exists) > 0:
					a, new = self.selectWithCompatibility(cmdSpl)
					if not a:
						print(Fore.RED + "This command can't be executed. Try using OS shell commands.")
						return False
				
				else:
					print(Fore.RED + "This command can't be executed. Try using OS shell commands.")
					return False
			self.printMessage()
			command = self.parseArgs(new, cmdSpl,self.next-1)
			self.writeCommandInFile(command, prevId, nextId, filePath)
			return True
