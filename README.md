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

LOLBITS is a C# reverse shell that uses Microsoft's [Background Intelligent TransFer Service (BITS)](https://docs.microsoft.com/en-us/windows/win32/bits/background-intelligent-transfer-service-portal) to communicate with the Command and Control backend. The Command and Control backend is hidden behind a apparently harmless flask web application and it's only accesible when the HTTP requests received by the app contain a valid authentication header. 

**LOLBITS** is composed of 3 main elements: 

* The C# agent that is in charge of executing the commands in the compromised host, sending back the output to the C&C server once the process is done.
* The flask web application that acts as a dispatcher. This element is the one that allows to hide the C&C infrastructure behind a harmless website at the same time that supplies the new commands to the agent when an authenticated request is received. 
* The C&C console, used to control the agent.

In order to deny proxies content inspection, all the relevant content sent between the agent and the C&C server is encrypted using RC4 and a preshared secret key. A high level diagram of the infrastructure behaviour would be as it's shown in the following diagram:

[![High level diagram][high-level-diagram]]()

To avoid that the Blue Team could reproduce some of the old requests and discover the C&C infrastructure, each authentication header is generated randomly and is valid only for one single cycle (a cycle is composed of a POST request followed by a GET request). Old authentication headers will be ignored and the harmless website will be displayed for that requests.

## Acknowledgements
Some of this tool features have being implemented reusing code from the CyberVaca's amazing project [Salsa Tools](https://github.com/Hackplayers/Salsa-tools), so a big shout-out to him!
Here you can find him:

* [Twitter](https://twitter.com/CyberVaca_)
* [Github](https://github.com/cybervaca)
* [Linkedin](https://www.linkedin.com/in/luis-vacas-de-santos-034887158/)



## Getting Started
### Prerequisites

For the C&C infrastructure is required a Windows Server 2012 or above with python 3.4+ and the following python depedencies:
* Colorama
```sh
pip install colorama
```
* Flask
```sh
pip install flask
```
The C# agent has been successfully tested on Windows Server 2016, Windows Server 2019, Windows 8.1 and Windows 10. To compile it it's required:
* Visual Studio 2017 or above.
* .NET Framework 4.5 or above.

### Setup

1. Clone this repository on your C&C server
 ```sh
git clone https://github.com/Kudaes/LOLBITS.git
```
2. Install Web Server (IIS) through Windows Server Manager. Make sure to install CGI, ASP.NET and .NET Extensibility roles.

[![Server Roles][server-roles]]()

Also install .NET Framework and BITS features for IIS.

[![Server Features][server-features]]()

3. Install wfastcgi and configuring Fast CGI settings in IIS. This is required since our web application is written in Python. For this step to be
done I followed up [this amazing tutorial](https://medium.com/@rajesh.r6r/deploying-a-python-flask-rest-api-on-iis-d8d9ebf886e9), and I recommend
you to do the same. Come back to this README when you have completed the tutorial's steps 1 and 2.

4. Stop the Default website and create a new one using Internet Information Services Manager. Enable BITS uploads for this new website.

[![Bits Uploads][bits-uploads]]()

5. Move `the content` of the C&C folder of this repository to the physical directory where the new website is deployed. Let's say you have created
the new website pointing to your directory `C:\inetpub\wwwroot\bits`, then this should be that directory tree:
```sh
C:\inetpub\wwwroot\bits
	    |__ /config            
	         |-- auth.txt
	    |__ /files
	         |-- abcde1234          
	         |-- default
	    |__ /lolbins
	         |-- base64decode.py
	         |-- base64encode.py
	         |-- a lot of .py files
	    |__ /templates
	    	 |-- index.html
	    |__ -- decrypt.py
	    |__ -- encrypt.py
	    |__ -- myapp.py
	    |__ --web.config
```
I recommend to grant **full access rights to Everyone** for the website directory (`C:\inetpub\wwwroot\bits` in the example) in order to avoid all kind of access
denied errors. At the end this is just a C&C server...

6. Edit the web.config file. In this file you have to modify two settings:

* `scriptProcessor` property for the web handler. For that, go back to the IIS Manager, click on the IIS server's root and select FastCGI Settings (you should have configured
this when following the tutorial referenced on the step 3). The value of the `scriptProcessor` property should be "Full Path|Arguments".

[![Fast CGI][fast-cgi]]()

Acording with the previous image, my `scriptProcessor` property should have the value **"c:\python3.4\python.exe|c:\python3.4\lib\site-packages\wfastcgi.py"**.

* PYTHONPATH, that should point to your website directory, in this case it would be "C:\inetpub\wwwroot\bits".

7. Modify the **initial setup constants**. 
* Select the password to use as preshared key. Set its value in:
	* Program.cs -> `Password` variable.
	* myapp.py -> `Password` variable.
	* lawlbin.py -> `password` variable.
* Set in the c# agent the url where the flask application is listening.
	* Program.cs -> `Url` variable.
* In myapp.py, set the value of the variables `AuthPath`, `ReadPath` and `Payloads` pointing to the correponding folders in the website directory.
* In lawlbin.py (lolbins folder) set the corresponding values for the variables `baseReadPath`and `baseWritePath` acording with your website directory tree.

8- Compile the agent and execute it in the compromised host. The compilation will generate an exe and an external dependency (**Newtonsoft.Json.dll**). You can generate a single exe using
[ILMerge](https://github.com/dotnet/ILMerge) or just send both files. To avoid DEBUG output, compile the project as a **Windows Application**.

[![Windows Application][windows-app]]()


## Usage

Use this space to show useful examples of how a project can be used. Additional screenshots, code examples and demos work well in this space. You may also link to more resources.

_For more examples, please refer to the [Documentation](https://example.com)_


## Contributing

This is my first time programming in C#, therefore Im pretty sure this code could be improved a lot. Any contributions you make will be **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request


<!-- LICENSE -->
## License

Distributed under the GNU License. See `LICENSE` for more information.


## Contact

[* Twitter](https://twitter.com/Kurro2907) 

[* Linkedin](https://www.linkedin.com/in/kuroshda/)






<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[high-level-diagram]: images/diagram.png
[server-roles]: images/iisroles.png
[server-features]: images/iisfeatures.png
[bits-uploads]: images/bitsuploads.png
[fast-cgi]: images/fastcgi.png
[windows-app]: images/windowsapp.png
