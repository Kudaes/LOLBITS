using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace LOLBITS.DInvoke
{
    class Generic
    {
        public static PE.PE_META_DATA GetPeMetaData(IntPtr pModule)
        {
            PE.PE_META_DATA PeMetaData = new PE.PE_META_DATA();
            try
            {
                uint e_lfanew = (uint)Marshal.ReadInt32((IntPtr)((ulong)pModule + 0x3c));
                PeMetaData.Pe = (uint)Marshal.ReadInt32((IntPtr)((ulong)pModule + e_lfanew));

                if (PeMetaData.Pe != 0x4550)
                {
                    throw new InvalidOperationException("Invalid PE signature.");
                }
                PeMetaData.ImageFileHeader = (PE.IMAGE_FILE_HEADER)Marshal.PtrToStructure((IntPtr)((ulong)pModule + e_lfanew + 0x4), typeof(PE.IMAGE_FILE_HEADER));
                IntPtr OptHeader = (IntPtr)((ulong)pModule + e_lfanew + 0x18);
                ushort PEArch = (ushort)Marshal.ReadInt16(OptHeader);
                
                if (PEArch == 0x010b) 
                {
                    PeMetaData.Is32Bit = true;
                    PeMetaData.OptHeader32 = (PE.IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(OptHeader, typeof(PE.IMAGE_OPTIONAL_HEADER32));
                }
                else if (PEArch == 0x020b)
                {
                    PeMetaData.Is32Bit = false;
                    PeMetaData.OptHeader64 = (PE.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(OptHeader, typeof(PE.IMAGE_OPTIONAL_HEADER64));
                }
                else
                {
                    throw new InvalidOperationException("Invalid magic value (PE32/PE32+).");
                }
                
                PE.IMAGE_SECTION_HEADER[] SectionArray = new PE.IMAGE_SECTION_HEADER[PeMetaData.ImageFileHeader.NumberOfSections];
                for (int i = 0; i < PeMetaData.ImageFileHeader.NumberOfSections; i++)
                {
                    IntPtr SectionPtr = (IntPtr)((ulong)OptHeader + PeMetaData.ImageFileHeader.SizeOfOptionalHeader + (uint)(i * 0x28));
                    SectionArray[i] = (PE.IMAGE_SECTION_HEADER)Marshal.PtrToStructure(SectionPtr, typeof(PE.IMAGE_SECTION_HEADER));
                }
                PeMetaData.Sections = SectionArray;
            }
            catch
            {
                throw new InvalidOperationException("Invalid module base specified.");
            }
            return PeMetaData;
        }

        public static Dictionary<string, string> GetApiSetMapping()
        {
            Native.PROCESS_BASIC_INFORMATION pbi = Native.NtQueryInformationProcessBasicInformation((IntPtr)(-1));
            uint ApiSetMapOffset = IntPtr.Size == 4 ? (uint)0x38 : 0x68;

            Dictionary<string, string> ApiSetDict = new Dictionary<string, string>();

            IntPtr pApiSetNamespace = Marshal.ReadIntPtr((IntPtr)((ulong)pbi.PebBaseAddress + ApiSetMapOffset));
            PE.ApiSetNamespace Namespace = (PE.ApiSetNamespace)Marshal.PtrToStructure(pApiSetNamespace, typeof(PE.ApiSetNamespace));
            for (var i = 0; i < Namespace.Count; i++)
            {
                PE.ApiSetNamespaceEntry SetEntry = new PE.ApiSetNamespaceEntry();
                SetEntry = (PE.ApiSetNamespaceEntry)Marshal.PtrToStructure((IntPtr)((ulong)pApiSetNamespace + (ulong)Namespace.EntryOffset + (ulong)(i * Marshal.SizeOf(SetEntry))), typeof(PE.ApiSetNamespaceEntry));
                string ApiSetEntryName = Marshal.PtrToStringUni((IntPtr)((ulong)pApiSetNamespace + (ulong)SetEntry.NameOffset), SetEntry.NameLength / 2) + ".dll";

                PE.ApiSetValueEntry SetValue = new PE.ApiSetValueEntry();
                SetValue = (PE.ApiSetValueEntry)Marshal.PtrToStructure((IntPtr)((ulong)pApiSetNamespace + (ulong)SetEntry.ValueOffset), typeof(PE.ApiSetValueEntry));
                string ApiSetValue = string.Empty;
                if (SetValue.ValueCount != 0)
                {
                    ApiSetValue = Marshal.PtrToStringUni((IntPtr)((ulong)pApiSetNamespace + (ulong)SetValue.ValueOffset), SetValue.ValueCount / 2);
                }

                ApiSetDict.Add(ApiSetEntryName, ApiSetValue);
            }

            return ApiSetDict;
        }

        public static IntPtr GetLoadedModuleAddress(string DLLName)
        {
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                {
                    return Mod.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }

        public static IntPtr LoadModuleFromDisk(string DLLPath)
        {
            Native.UNICODE_STRING uModuleName = new Native.UNICODE_STRING();
            Native.RtlInitUnicodeString(ref uModuleName, DLLPath);

            IntPtr hModule = IntPtr.Zero;
            Native.NTSTATUS CallResult = Native.LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
            if (CallResult != Native.NTSTATUS.Success || hModule == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            return hModule;
        }

        public static IntPtr GetNativeExportAddress(IntPtr ModuleBase, string ExportName)
        {
            Native.ANSI_STRING aFunc = new Native.ANSI_STRING
            {
                Length = (ushort)ExportName.Length,
                MaximumLength = (ushort)(ExportName.Length + 2),
                Buffer = Marshal.StringToCoTaskMemAnsi(ExportName)
            };

            IntPtr pAFunc = Marshal.AllocHGlobal(Marshal.SizeOf(aFunc));
            Marshal.StructureToPtr(aFunc, pAFunc, true);

            IntPtr pFuncAddr = IntPtr.Zero;
            Native.LdrGetProcedureAddress(ModuleBase, pAFunc, IntPtr.Zero, ref pFuncAddr);

            Marshal.FreeHGlobal(pAFunc);

            return pFuncAddr;
        }

        public static IntPtr GetNativeExportAddress(IntPtr ModuleBase, short Ordinal)
        {
            IntPtr pFuncAddr = IntPtr.Zero;
            IntPtr pOrd = (IntPtr)Ordinal;

            Native.LdrGetProcedureAddress(ModuleBase, IntPtr.Zero, pOrd, ref pFuncAddr);

            return pFuncAddr;
        }

        public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                int PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                short OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                long OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                short Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                long pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }

                int ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                int OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                int NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                int NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                int FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                int NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                int OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                    {
                        int FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        int FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((long)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (FunctionPtr == IntPtr.Zero)
            {
                throw new MissingMethodException(ExportName + ", export not found.");
            }
            return FunctionPtr;
        }

        public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero && CanLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(DLLName);
                if (hModule == IntPtr.Zero)
                {
                    throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
                }
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(DLLName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, FunctionName);
        }

        public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
        {
            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
            return funcDelegate.DynamicInvoke(Parameters);
        }

        public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
        {
            IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
            return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
        }

        public static void CallMappedDLLModule(PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            IntPtr lpEntryPoint = PEINFO.Is32Bit ? (IntPtr)((ulong)ModuleMemoryBase + PEINFO.OptHeader32.AddressOfEntryPoint) :
                                                   (IntPtr)((ulong)ModuleMemoryBase + PEINFO.OptHeader64.AddressOfEntryPoint);

            PE.DllMain fDllMain = (PE.DllMain)Marshal.GetDelegateForFunctionPointer(lpEntryPoint, typeof(PE.DllMain));
            bool CallRes = fDllMain(ModuleMemoryBase, PE.DLL_PROCESS_ATTACH, IntPtr.Zero);
            if (!CallRes)
            {
                throw new InvalidOperationException("Failed to call DllMain -> DLL_PROCESS_ATTACH");
            }
        }

        public static object CallMappedDLLModuleExport(PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase, string ExportName, Type FunctionDelegateType, object[] Parameters)
        {
            CallMappedDLLModule(PEINFO, ModuleMemoryBase);

            IntPtr pFunc = GetExportAddress(ModuleMemoryBase, ExportName);

            return DynamicFunctionInvoke(pFunc, FunctionDelegateType, ref Parameters);
        }

    }
}
