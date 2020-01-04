from command import Command

class Compile(Command):

	__options = [
					 "C:\Windows\Microsoft.NET\Framework\\v4.0.30319\Csc.exe"
				 ] 
	__execution = [
				  	 "?p -out:?o ?i", "?p -target:library -out:?o ?i"
				  ] 
	__fileType = [
				 	 ["cs->exe"], ["cs->dll"]
				 ]

	def __init__(self):

		super().__init__(self.__options, self.__execution)


	def printHelp(self):

		helpstr = """\n Compile a .cs file into dll or exe.
	\n ** USAGE **: compile <file to compile> <destination path> 
		"""

		print(helpstr)

	def checkCompatibility(self, ind, cmdSpl):

		for s in self.__fileType[ind]:
			s2 = s.split("->")
			c1 = cmdSpl[0].split(".")[-1] 
			c2 = cmdSpl[1].split(".")[-1] 
			if (s2[0].lower() == c1.lower()) and (s2[1].lower() == c2.lower()):
				return True  

		return False

	def printMessage(self):

		print("Compiling...")


