from command import Command

class Base64encode(Command):

	__options = [
					"certutil.exe"
				] 
	__execution = [
					"?p -encode ?i ?o"
				  ] 

	def __init__(self):

		super().__init__(self.__options, self.__execution)

	def printHelp(self):

		helpstr = """\n Encode the content of a file using base64 encoding.
	\n ** USAGE **: base64encode <file to encode> <destination path> 
		"""

		print(helpstr)
	
	def printMessage(self):

		print("Encoding...")