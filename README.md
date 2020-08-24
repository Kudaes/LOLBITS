![License](https://img.shields.io/badge/license-GNU-green.svg?style=flat-square)

```
			 ██╗      ██████╗ ██╗     ██████╗ ██╗████████╗███████╗
			 ██║     ██╔═══██╗██║     ██╔══██╗██║╚══██╔══╝██╔════╝
			 ██║     ██║   ██║██║     ██████╔╝██║   ██║   ███████╗
			 ██║     ██║   ██║██║     ██╔══██╗██║   ██║   ╚════██║
			 ███████╗╚██████╔╝███████╗██████╔╝██║   ██║   ███████║
			 ╚══════╝ ╚═════╝ ╚══════╝╚═════╝ ╚═╝   ╚═╝   ╚══════╝
```


<!-- TABLE OF CONTENTS -->
## Table of Contents

* [About the Project](#about-the-project)
  * [Acknowledgements](#acknowledgements)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Setup](#setup)
* [Usage](#usage)
* [Contributing](#contributing)
* [License](#license)
* [Contact](#contact)



<!-- ABOUT THE PROJECT -->
## About The Project

LOLBITS is a C2 framework that uses Microsoft's [Background Intelligent Transfer Service (BITS)](https://docs.microsoft.com/en-us/windows/win32/bits/background-intelligent-transfer-service-portal) to establish the communication channel between the compromised host and the backend. The C2 backend is hidden behind an apparently harmless flask web application and it's only accesible when the HTTP requests received by the app contain a valid authentication header. Since this tool is meant to be used in highly monitored environments, the following features have implemented in order to avoid EDR and AV detection:

* Patch of ETW and AMSI.
* Use of direct syscalls to avoid EDR usermode API hooking.
* Manual mapping of kernel32.dll and advapi32.dll in combination with DInvoke.
* Basic Sandbox detection before establishing the communication channel with the C2 backend.
* Use of BITS in background mode to generate the communication channel without disturbing the user experience.

Regarding the architecture, **LOLBITS** is composed of 3 main elements: 

* The C# agent that is in charge of executing the commands in the compromised host, sending back the output to the C2 server once the task is completed.
* The flask web application that acts as a dispatcher. This element is the one that allows to hide the C2 infrastructure behind a harmless website at the same time that supplies the new commands to the agent when an authenticated request is received. 
* The C2 console, used to control the agent.

In order to deny proxies content inspection, all the relevant content sent between the agent and the C2 server is encrypted using RC4 with a preshared secret key randomly generated. A high level diagram of the infrastructure behaviour would be as it's shown in the following image:

[![High level diagram][high-level-diagram]]()

To avoid that the Blue Team could reproduce some of the old requests and discover the C2 backend infrastructure, each authentication header is randomly generated and is valid only for one single cycle (a cycle is composed of a POST request followed by a GET request, in that order). Old authentication headers will be ignored and the harmless website will be displayed for those requests.

## Acknowledgements
Some of this tool features have being implemented either reusing code from other projects or thanks to the effort of several cybersecurity researchers. Here below I link some of the external work and projects that have been used in one way or another to improve this tool:

* [Salsa Tools](https://github.com/Hackplayers/Salsa-tools)
* [Dinvoke](https://thewover.github.io/Dynamic-Invoke/)
* [SharpSploit](https://github.com/cobbr/SharpSploit)
* [Windows System Call Table](https://j00ru.vexillium.org/syscalls/nt/64/)
* [CheckPlease for Sandbox Evasion](https://github.com/Arvanaghi/CheckPlease)

## Getting Started
### Prerequisites

For the C2 infrastructure is required a Windows Server 2016 or above with python 3.4+ and powershell 5.1+.
The C# agent has been successfully tested on Windows Server 2012, Windows Server 2016, Windows Server 2019, Windows 7, Windows 8.1 and Windows 10. To compile it it's required:
* Visual Studio 2017 or above.
* .NET Framework 4.5 or above.

### Setup

1.- Clone this repository on your C2 server
 ```sh
git clone https://github.com/Kudaes/LOLBITS.git
```
2.- Install Web Server (IIS) through Windows Server Manager. Make sure to install CGI, ASP.NET and .NET Extensibility roles.

[![Server Roles][server-roles]]()

Also install .NET Framework and BITS features for IIS.

[![Server Features][server-features]]()

3.- Execute the **setup.ps1** script **as administrator** to deploy the whole infrastructure and set up the C# agent.

4.- Compile the agent and execute it in the compromised host. The compilation will generate an .exe and an external dependency (**Newtonsoft.Json.dll**). You can generate a single .exe using
[ILMerge](https://github.com/dotnet/ILMerge) or just send both files to the compromised host. To avoid DEBUG output, make sure to compile the project as a **Windows Application**.

[![Windows Application][windows-app]]()

5.- (**Optional**) By default. the **setup.ps1** script will create a new Web Site in your IIS called **lawlbits** listening in the default HTTP port (80/TCP). This new Web Site doesn't use HTTP over TLS and, even though the content of the requests sent by the C# agent to the C2 are encrypted using RC4 with a preshared and randomly generated secret key, it is recommended to set up the use of HTTPS for the new site. In order to do that, I recommend to use [Let's Encrypt](https://weblog.west-wind.com/posts/2016/feb/22/using-lets-encrypt-with-iis-on-windows#the-easy-way-letsencrypt-win-simple) over **lawlbits**, which is one of the easiest ways to set up HTTPS. After that, remember to modify the variable `Url` on Program.cs to use HTTPS instead of HTTP, which is the default behaviour.

## Usage

To obtain the reverse shell just type in `python lawlbin.py` on a cmd of the C2 server and execute the C# agent on the compromised host. 

Since this project borns from the ashes of a previous and failed project, some of the old features have been kept. The old project was a shell where all the available commands would be
executed using exclusively [Living of The Land Binaries](https://github.com/LOLBAS-Project/LOLBAS). That's where the LOL of LOLBITS comes from, and that's why the following features run using exclusively LOLBINS (this could help to bypass AWS and some AV/EDR filters):

* **download**: Download a file from a remote Webdav to the compromised host.
* **base64encode**: Use base64 to encode a local file content.
* **base64decode**: Decode a base64 encoded file.
* **compile**: Compile .cs files into .exe or .dll.

Despite this features could be interesting in some environments (hmm download remote files without using Powershell? I like it!) I kept them just to reuse part of the old code for the
C2 console. Below is a list with some other features that im sure will be more usefull in a classic red team context:

* **inject**: Download from the C2 a shellcode (.bin) or PE (.NET assembly) file and execute it in memory. With this command the payload never touches disk unencrypted, avoiding AV detection. .NET assemblies can only be loaded in the same calling process, while shellcode are allowed to be injected in both own and other processes (only x64 processes).
* **psh**: Generate a Powershell reverse shell. This shell has to be handled by additional software like netcat (just run nc -lvp <port>).
* **send**: To send a file from your C2 to the compromised host just use this option. The sent file will be store **unencrypted** on disk.
* **getsystem**: Attempt to obtain System privileges. High integrity level required.
* **impersonate**: Attempt to steal an access token from other process in order to "become" another user.
* **runas**: Use valid credentials to modify your security context and log in as other (local or domain) user.
* **rev2self**: Remove security context changes performed by getsystem, impersonate or runas.
* **exfiltrate**: Send a file from the compromised host to your C2.

To get usage tips just type in `help` or `<somecommand> help`.

## Contributing

Any contributions will be **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request


## License

Distributed under the GNU License. See `LICENSE` for more information.


## Contact

[My Twitter](https://twitter.com/Kurosh2907) 

[My Linkedin](https://www.linkedin.com/in/kuroshda/)



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[high-level-diagram]: images/diagram.png
[server-roles]: images/iisroles.png
[server-features]: images/iisfeatures.png
[bits-uploads]: images/bitsuploads.png
[fast-cgi]: images/fastcgi.png
[windows-app]: images/windowsapp.png
