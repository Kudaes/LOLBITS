from command import Command
import pathlib

class Move(Command): # copy command

	__options = [	
					"print.exe",
					"replace.exe", 
					"bitsadmin.exe", 
					"esentutl.exe", 
					"findstr.exe",
					"expand.exe"
				] 
	__execution = [	
					"?p /D:?o ?i",
					"?p ?i ?o /A",
					"?p /create 1 & ?p /addfile 1 ?i ?o & ?p /RESUME 1 & ?p /complete 1 & ?p /Reset",
					"?p /y ?i /d ?o /o",
					"?p /V /L Th1SsTR1NGD03SNT3X1ST ?i > ?o",
					"?p ?i ?o"
				  ] 


	def __init__(self):

		super().__init__(self.__options, self.__execution)

	def printHelp(self):

		helpstr = """\n Copy a file from one local path to another local path. 
	\n ** USAGE **: copy <source path> <destination path>
		"""

		print(helpstr)

	def checkCompatibility(self, ind, cmdSpl):


		if ind == 1:
			if pathlib.Path(cmdSpl[1]).is_dir():
				return True  
		else:
			return True

		return False
	
	def printMessage(self):

		print("Copying file...")