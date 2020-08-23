using System;
using System.Runtime.InteropServices;

namespace LOLBITS.DInvoke
{
    public static class Win32
    {
        public static class Kernel32
        {

            public static uint MEM_COMMIT = 0x1000;
            public static uint MEM_RESERVE = 0x2000;
            public static uint MEM_RESET = 0x80000;
            public static uint MEM_RESET_UNDO = 0x1000000;
            public static uint MEM_LARGE_PAGES = 0x20000000;
            public static uint MEM_PHYSICAL = 0x400000;
            public static uint MEM_TOP_DOWN = 0x100000;
            public static uint MEM_WRITE_WATCH = 0x200000;
            public static uint MEM_COALESCE_PLACEHOLDERS = 0x1;
            public static uint MEM_PRESERVE_PLACEHOLDER = 0x2;
            public static uint MEM_DECOMMIT = 0x4000;
            public static uint MEM_RELEASE = 0x8000;

            public enum LogonFlags
            {
                WithProfile = 1,
                NetCredentialsOnly
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SecurityAttributes
            {
                public int nLength;
                public IntPtr lpSecurityDescriptor;
                public bool bInheritHandle;
            }

            [Flags]
            public enum MemoryAllocationFlags
            {
                Commit = 0x01000,
                Reserve = 0x02000
            }

            [Flags]
            public enum MemoryProtectionFlags
            {
                ExecuteReadWrite = 0x040,
                ReadWrite = 0x004,
                ExecuteRead = 0x020
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_BASE_RELOCATION
            {
                public uint VirtualAdress;
                public uint SizeOfBlock;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_IMPORT_DESCRIPTOR
            {
                public uint OriginalFirstThunk;
                public uint TimeDateStamp;
                public uint ForwarderChain;
                public uint Name;
                public uint FirstThunk;
            }

            public struct SYSTEM_INFO
            {
                public ushort wProcessorArchitecture;
                public ushort wReserved;
                public uint dwPageSize;
                public IntPtr lpMinimumApplicationAddress;
                public IntPtr lpMaximumApplicationAddress;
                public UIntPtr dwActiveProcessorMask;
                public uint dwNumberOfProcessors;
                public uint dwProcessorType;
                public uint dwAllocationGranularity;
                public ushort wProcessorLevel;
                public ushort wProcessorRevision;
            };

            public enum Platform
            {
                x86,
                x64,
                IA64,
                Unknown
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


            [StructLayout(LayoutKind.Sequential)]
            public struct ProcessInformation
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public readonly int dwProcessId;
                public readonly int dwThreadId;
            }

            [Flags]
            public enum ProcessAccessFlags : uint
            {
                PROCESS_ALL_ACCESS = 0x001F0FFF,
                PROCESS_CREATE_PROCESS = 0x0080,
                PROCESS_CREATE_THREAD = 0x0002,
                PROCESS_DUP_HANDLE = 0x0040,
                PROCESS_QUERY_INFORMATION = 0x0400,
                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
                PROCESS_SET_INFORMATION = 0x0200,
                PROCESS_SET_QUOTA = 0x0100,
                PROCESS_SUSPEND_RESUME = 0x0800,
                PROCESS_TERMINATE = 0x0001,
                PROCESS_VM_OPERATION = 0x0008,
                PROCESS_VM_READ = 0x0010,
                PROCESS_VM_WRITE = 0x0020,
                SYNCHRONIZE = 0x00100000
            }

            [Flags]
            public enum FileAccessFlags : uint
            {
                DELETE = 0x10000,
                FILE_READ_DATA = 0x1,
                FILE_READ_ATTRIBUTES = 0x80,
                FILE_READ_EA = 0x8,
                READ_CONTROL = 0x20000,
                FILE_WRITE_DATA = 0x2,
                FILE_WRITE_ATTRIBUTES = 0x100,
                FILE_WRITE_EA = 0x10,
                FILE_APPEND_DATA = 0x4,
                WRITE_DAC = 0x40000,
                WRITE_OWNER = 0x80000,
                SYNCHRONIZE = 0x100000,
                FILE_EXECUTE = 0x20
            }

            [Flags]
            public enum FileShareFlags : uint
            {
                FILE_SHARE_NONE = 0x0,
                FILE_SHARE_READ = 0x1,
                FILE_SHARE_WRITE = 0x2,
                FILE_SHARE_DELETE = 0x4
            }

            [Flags]
            public enum FileOpenFlags : uint
            {
                FILE_DIRECTORY_FILE = 0x1,
                FILE_WRITE_THROUGH = 0x2,
                FILE_SEQUENTIAL_ONLY = 0x4,
                FILE_NO_INTERMEDIATE_BUFFERING = 0x8,
                FILE_SYNCHRONOUS_IO_ALERT = 0x10,
                FILE_SYNCHRONOUS_IO_NONALERT = 0x20,
                FILE_NON_DIRECTORY_FILE = 0x40,
                FILE_CREATE_TREE_CONNECTION = 0x80,
                FILE_COMPLETE_IF_OPLOCKED = 0x100,
                FILE_NO_EA_KNOWLEDGE = 0x200,
                FILE_OPEN_FOR_RECOVERY = 0x400,
                FILE_RANDOM_ACCESS = 0x800,
                FILE_DELETE_ON_CLOSE = 0x1000,
                FILE_OPEN_BY_FILE_ID = 0x2000,
                FILE_OPEN_FOR_BACKUP_INTENT = 0x4000,
                FILE_NO_COMPRESSION = 0x8000
            }

            [Flags]
            public enum StandardRights : uint
            {
                Delete = 0x00010000,
                ReadControl = 0x00020000,
                WriteDac = 0x00040000,
                WriteOwner = 0x00080000,
                Synchronize = 0x00100000,
                Required = 0x000f0000,
                Read = ReadControl,
                Write = ReadControl,
                Execute = ReadControl,
                All = 0x001f0000,

                SpecificRightsAll = 0x0000ffff,
                AccessSystemSecurity = 0x01000000,
                MaximumAllowed = 0x02000000,
                GenericRead = 0x80000000,
                GenericWrite = 0x40000000,
                GenericExecute = 0x20000000,
                GenericAll = 0x10000000
            }

            [Flags]
            public enum ThreadAccess : uint
            {
                Terminate = 0x0001,
                SuspendResume = 0x0002,
                Alert = 0x0004,
                GetContext = 0x0008,
                SetContext = 0x0010,
                SetInformation = 0x0020,
                QueryInformation = 0x0040,
                SetThreadToken = 0x0080,
                Impersonate = 0x0100,
                DirectImpersonation = 0x0200,
                SetLimitedInformation = 0x0400,
                QueryLimitedInformation = 0x0800,
                All = StandardRights.Required | StandardRights.Synchronize | 0x3ff
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
                public IntPtr objectName;
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


        }

        public class WinNT
        {
            public const uint PAGE_NOACCESS = 0x01;
            public const uint PAGE_READONLY = 0x02;
            public const uint PAGE_READWRITE = 0x04;
            public const uint PAGE_WRITECOPY = 0x08;
            public const uint PAGE_EXECUTE = 0x10;
            public const uint PAGE_EXECUTE_READ = 0x20;
            public const uint PAGE_EXECUTE_READWRITE = 0x40;
            public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
            public const uint PAGE_GUARD = 0x100;
            public const uint PAGE_NOCACHE = 0x200;
            public const uint PAGE_WRITECOMBINE = 0x400;
            public const uint PAGE_TARGETS_INVALID = 0x40000000;
            public const uint PAGE_TARGETS_NO_UPDATE = 0x40000000;

            public const uint SEC_COMMIT = 0x08000000;
            public const uint SEC_IMAGE = 0x1000000;
            public const uint SEC_IMAGE_NO_EXECUTE = 0x11000000;
            public const uint SEC_LARGE_PAGES = 0x80000000;
            public const uint SEC_NOCACHE = 0x10000000;
            public const uint SEC_RESERVE = 0x4000000;
            public const uint SEC_WRITECOMBINE = 0x40000000;

            public const uint SE_PRIVILEGE_ENABLED = 0x2;
            public const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1;
            public const uint SE_PRIVILEGE_REMOVED = 0x4;
            public const uint SE_PRIVILEGE_USED_FOR_ACCESS = 0x3;

            public const ulong SE_GROUP_ENABLED = 0x00000004L;
            public const ulong SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002L;
            public const ulong SE_GROUP_INTEGRITY = 0x00000020L;
            public const uint SE_GROUP_INTEGRITY_32 = 0x00000020;
            public const ulong SE_GROUP_INTEGRITY_ENABLED = 0x00000040L;
            public const ulong SE_GROUP_LOGON_ID = 0xC0000000L;
            public const ulong SE_GROUP_MANDATORY = 0x00000001L;
            public const ulong SE_GROUP_OWNER = 0x00000008L;
            public const ulong SE_GROUP_RESOURCE = 0x20000000L;
            public const ulong SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010L;

            public enum _SECURITY_IMPERSONATION_LEVEL
            {
                SecurityAnonymous,
                SecurityIdentification,
                SecurityImpersonation,
                SecurityDelegation
            }

            [Flags()]
            public enum _TOKEN_ACCESS_FLAGS : int
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

            public enum TOKEN_TYPE
            {
                TokenPrimary = 1,
                TokenImpersonation
            }

            public enum _TOKEN_ELEVATION_TYPE
            {
                TokenElevationTypeDefault = 1,
                TokenElevationTypeFull,
                TokenElevationTypeLimited
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _MEMORY_BASIC_INFORMATION32
            {
                public uint BaseAddress;
                public uint AllocationBase;
                public uint AllocationProtect;
                public uint RegionSize;
                public uint State;
                public uint Protect;
                public uint Type;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _MEMORY_BASIC_INFORMATION64
            {
                public ulong BaseAddress;
                public ulong AllocationBase;
                public uint AllocationProtect;
                public uint __alignment1;
                public ulong RegionSize;
                public uint State;
                public uint Protect;
                public uint Type;
                public uint __alignment2;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _LUID_AND_ATTRIBUTES
            {
                public _LUID Luid;
                public uint Attributes;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _LUID
            {
                public uint LowPart;
                public uint HighPart;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_STATISTICS
            {
                public _LUID TokenId;
                public _LUID AuthenticationId;
                public ulong ExpirationTime;
                public TOKEN_TYPE TokenType;
                public _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
                public uint DynamicCharged;
                public uint DynamicAvailable;
                public uint GroupCount;
                public uint PrivilegeCount;
                public _LUID ModifiedId;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_PRIVILEGES
            {
                public uint PrivilegeCount;
                public _LUID_AND_ATTRIBUTES Privileges;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_MANDATORY_LABEL
            {
                public _SID_AND_ATTRIBUTES Label;
            }

            public struct _SID
            {
                public byte Revision;
                public byte SubAuthorityCount;
                public WinNT._SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
                public ulong[] SubAuthority;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _SID_IDENTIFIER_AUTHORITY
            {
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
                public byte[] Value;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _SID_AND_ATTRIBUTES
            {
                public IntPtr Sid;
                public uint Attributes;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _PRIVILEGE_SET
            {
                public uint PrivilegeCount;
                public uint Control;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
                public _LUID_AND_ATTRIBUTES[] Privilege;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_USER
            {
                public _SID_AND_ATTRIBUTES User;
            }

            public enum _SID_NAME_USE
            {
                SidTypeUser = 1,
                SidTypeGroup,
                SidTypeDomain,
                SidTypeAlias,
                SidTypeWellKnownGroup,
                SidTypeDeletedAccount,
                SidTypeInvalid,
                SidTypeUnknown,
                SidTypeComputer,
                SidTypeLabel
            }

            public enum _TOKEN_INFORMATION_CLASS
            {
                TokenUser = 1,
                TokenGroups,
                TokenPrivileges,
                TokenOwner,
                TokenPrimaryGroup,
                TokenDefaultDacl,
                TokenSource,
                TokenType,
                TokenImpersonationLevel,
                TokenStatistics,
                TokenRestrictedSids,
                TokenSessionId,
                TokenGroupsAndPrivileges,
                TokenSessionReference,
                TokenSandBoxInert,
                TokenAuditPolicy,
                TokenOrigin,
                TokenElevationType,
                TokenLinkedToken,
                TokenElevation,
                TokenHasRestrictions,
                TokenAccessInformation,
                TokenVirtualizationAllowed,
                TokenVirtualizationEnabled,
                TokenIntegrityLevel,
                TokenUIAccess,
                TokenMandatoryPolicy,
                TokenLogonSid,
                TokenIsAppContainer,
                TokenCapabilities,
                TokenAppContainerSid,
                TokenAppContainerNumber,
                TokenUserClaimAttributes,
                TokenDeviceClaimAttributes,
                TokenRestrictedUserClaimAttributes,
                TokenRestrictedDeviceClaimAttributes,
                TokenDeviceGroups,
                TokenRestrictedDeviceGroups,
                TokenSecurityAttributes,
                TokenIsRestricted,
                MaxTokenInfoClass
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


            [Flags]
            public enum ACCESS_MASK : uint
            {
                DELETE = 0x00010000,
                READ_CONTROL = 0x00020000,
                WRITE_DAC = 0x00040000,
                WRITE_OWNER = 0x00080000,
                SYNCHRONIZE = 0x00100000,
                STANDARD_RIGHTS_REQUIRED = 0x000F0000,
                STANDARD_RIGHTS_READ = 0x00020000,
                STANDARD_RIGHTS_WRITE = 0x00020000,
                STANDARD_RIGHTS_EXECUTE = 0x00020000,
                STANDARD_RIGHTS_ALL = 0x001F0000,
                SPECIFIC_RIGHTS_ALL = 0x0000FFF,
                ACCESS_SYSTEM_SECURITY = 0x01000000,
                MAXIMUM_ALLOWED = 0x02000000,
                GENERIC_READ = 0x80000000,
                GENERIC_WRITE = 0x40000000,
                GENERIC_EXECUTE = 0x20000000,
                GENERIC_ALL = 0x10000000,
                DESKTOP_READOBJECTS = 0x00000001,
                DESKTOP_CREATEWINDOW = 0x00000002,
                DESKTOP_CREATEMENU = 0x00000004,
                DESKTOP_HOOKCONTROL = 0x00000008,
                DESKTOP_JOURNALRECORD = 0x00000010,
                DESKTOP_JOURNALPLAYBACK = 0x00000020,
                DESKTOP_ENUMERATE = 0x00000040,
                DESKTOP_WRITEOBJECTS = 0x00000080,
                DESKTOP_SWITCHDESKTOP = 0x00000100,
                WINSTA_ENUMDESKTOPS = 0x00000001,
                WINSTA_READATTRIBUTES = 0x00000002,
                WINSTA_ACCESSCLIPBOARD = 0x00000004,
                WINSTA_CREATEDESKTOP = 0x00000008,
                WINSTA_WRITEATTRIBUTES = 0x00000010,
                WINSTA_ACCESSGLOBALATOMS = 0x00000020,
                WINSTA_EXITWINDOWS = 0x00000040,
                WINSTA_ENUMERATE = 0x00000100,
                WINSTA_READSCREEN = 0x00000200,
                WINSTA_ALL_ACCESS = 0x0000037F,

                SECTION_ALL_ACCESS = 0x10000000,
                SECTION_QUERY = 0x0001,
                SECTION_MAP_WRITE = 0x0002,
                SECTION_MAP_READ = 0x0004,
                SECTION_MAP_EXECUTE = 0x0008,
                SECTION_EXTEND_SIZE = 0x0010
            };

        }
        public static class DELEGATES
        {
            /////////////// kernel32.dll ///////////////
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr VirtualProtectEx(IntPtr hProcess, 
                IntPtr lpAddress,
                UIntPtr dwSize,
                uint flNewProtect,
                out uint lpflOldProtect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr GetProcAddress(IntPtr hModule, string procName);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr LoadLibrary(string lpFileName);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr VirtualAlloc(IntPtr baseAddress, UIntPtr size, Kernel32.MemoryAllocationFlags allocationType, Kernel32.MemoryProtectionFlags protection);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr OpenProcess(Kernel32.ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr CreatePipe(ref IntPtr hReadPipe, ref IntPtr hWritePipe, ref Kernel32.SecurityAttributes lpPipeAttributes, int nSize);

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int PssCaptureSnapshot(IntPtr ProcessHandle, Native.PSS_CAPTURE_FLAGS CaptureFlags, int ThreadContextFlags, ref IntPtr SnapshotHandle);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr CreateFile([MarshalAs(UnmanagedType.LPTStr)] string filename, 
                [MarshalAs(UnmanagedType.U4)] Kernel32.FileAccessFlags access,
                [MarshalAs(UnmanagedType.U4)] System.IO.FileShare share,
                IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
                [MarshalAs(UnmanagedType.U4)] System.IO.FileMode creationDisposition,
                [MarshalAs(UnmanagedType.U4)] uint flagsAndAttributes,
                IntPtr templateFile);

            /////////////// advapi32.dll ///////////////

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public delegate bool LookupPrivilegeValue(string lpSystemName, string lpName, out WinNT._LUID lpLuid);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public delegate bool AdjustTokenPrivileges(IntPtr tokenHandle,
                [MarshalAs(UnmanagedType.Bool)]bool disableAllPrivileges,
                ref WinNT._TOKEN_PRIVILEGES newState,
                uint zero,
                WinNT._TOKEN_PRIVILEGES null1,
                out uint null2);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool DuplicateTokenEx(
                IntPtr hExistingToken,
                WinNT._TOKEN_ACCESS_FLAGS dwDesiredAccess,
                IntPtr lpThreadAttributes,
                WinNT._SECURITY_IMPERSONATION_LEVEL impersonationLevel,
                WinNT.TOKEN_TYPE tokenType,
                out IntPtr phNewToken);

        }

    }
}
