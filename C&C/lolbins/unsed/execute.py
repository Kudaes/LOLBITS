from command import Command
import pathlib
import os


class Execute(Command):

	__options = [	
					 "C:\Windows\Microsoft.NET\Framework\\v4.0.30319\Msbuild.exe",
					 "bash.exe",
					 "sc.exe",
					 "wscript.exe",
					 "Scrptrunner.exe",
					 "pcalua.exe",
					 "mshta.exe",
					 "ftp.exe",
					 "Presentationhost.exe",
					 "rundll32.exe",
					 "rundll32.exe",
					 "rundll32.exe"
				 ] 
	__execution = [	
					 "?p ?f",
				  	 "?p -c ?f",
				  	 "?p create defServ binPath=\"?f\" DisplayName= \"defServ\" start= auto\\ & ?p start defServ",
				  	 "?p ?f",
				  	 "?p -appvscript ?f",
				  	 "?p -a ?f",
				  	 "?p ?f",
				  	 "echo !?f > file.txt && ?p -s:file.txt",
				  	 "?p ?f",
				  	 "?p pcwutl.dll,LaunchApplication ?f",
				  	 "?p url.dll,OpenURL ?f",
				  	 "?p zipfldr.dll,RouteTheCall ?f"
				  ] 
	__fileType = [
					 ["xml","csproj"],
				 	 ["exe"],
				 	 ["exe","bat"],
				 	 ["exe","bat"],
				 	 ["vbs"],
				 	 ["exe","bat"],
				 	 ["exe","bat"],
				 	 ["hta"],
				 	 ["exe","bat"],
				 	 ["xbap"],
				 	 ["exe","bat"],
				 	 ["hta"],
				 	 ["exe","bat","hta", "vbs"]
				 ]

	def __init__(self):

		super().__init__(self.__options, self.__execution)

	def parseArgs(self, path, cmdSpl, ind):
		finalCom = self.__execution[ind].replace("?p", path)
		finalCom = finalCom.replace("?f",cmdSpl[0])
		return finalCom

	def printHelp(self):

		helpstr = """\n Execute a file. 
	\n ** USAGE **: execute <path to file>
	\n [+] Extensions allowed: Exe, bat, xml, vbs, csproj, hta, xbap.
		"""

		print(helpstr)

	def checkCompatibility(self, ind, cmdSpl):

		for s in self.__fileType[ind]:
			c1 = cmdSpl[0].split(".")[-1] 
			if (s.lower() == c1.lower()):
				return True  

		return False

	def printMessage(self):

		print("Executing...")



