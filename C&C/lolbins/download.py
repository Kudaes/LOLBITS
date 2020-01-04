from command import Command
import pathlib

class Download(Command):

	__options = [	
					"expand.exe",
					"replace.exe", 
					"extrac32.exe",
					"findstr.exe",
					"makecab.exe",
				]

	__execution = [	
					"?p ?i ?o",
					"?p ?i ?o /A", 
					"?p /Y /C ?i ?o",
					"?p /V /L Th1SSTR1NGD03SNT3X1ST ?i > ?o",
					"?p ?i ?o",
				  ] 

	__protocol = [	
					["webdav"],
					["webdav"],
					["webdav"],
					["webdav"],
					["webdav"],
				 ]

	def __init__(self):

		super().__init__(self.__options, self.__execution)

	def printHelp(self):

		helpstr = """\n Download a file from remote host.
	\n ** USAGE **: download <download path> <destination path> 
	\n [+] Protocols allowed: Webdav.
		"""

		print(helpstr)

	def checkCompatibility(self, ind, cmdSpl):

		for s in self.__protocol[ind]:
			c = cmdSpl[0].split("\\\\") 
			if (s == "webdav" and c[0] == '') or (s == "http" and c[0].startswith('http')):
				if ind == 1:
					if pathlib.Path(cmdSpl[1]).is_dir():
						return True  
				else:
					return True

		return False

	def printMessage(self):

		print("Downloading...") 