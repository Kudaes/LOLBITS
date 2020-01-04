from command import Command

class Base64decode(Command):

	__options = [
					"certutil.exe"
				] 
	__execution = [
					"?p -decode ?i ?o"
				  ] 

	def __init__(self):

		super().__init__(self.__options, self.__execution)

	def printHelp(self):

		helpstr = """\n Decode a file with base64 encoded content.
	\n ** USAGE **: base64decode <file to decode> <destination path> 
		"""

		print(helpstr)

	def printMessage(self):

		print("Decoding...")