using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace LOLBITS.DInvoke
{
    class Map
    {

        public static IntPtr AllocateBytesToMemory(byte[] FileByteArray)
        {
            IntPtr pFile = Marshal.AllocHGlobal(FileByteArray.Length);
            Marshal.Copy(FileByteArray, 0, pFile, FileByteArray.Length);
            return pFile;
        }

        public static IntPtr AllocateFileToMemory(string FilePath)
        {
            if (!File.Exists(FilePath))
            {
                throw new InvalidOperationException("Filepath not found.");
            }

            byte[] bFile = File.ReadAllBytes(FilePath);
            return AllocateBytesToMemory(bFile);
        }

        public static void RelocateModule(PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            PE.IMAGE_DATA_DIRECTORY idd = PEINFO.Is32Bit ? PEINFO.OptHeader32.BaseRelocationTable : PEINFO.OptHeader64.BaseRelocationTable;
            long ImageDelta = PEINFO.Is32Bit ? (long)((ulong)ModuleMemoryBase - PEINFO.OptHeader32.ImageBase) :
                                                (long)((ulong)ModuleMemoryBase - PEINFO.OptHeader64.ImageBase);


            IntPtr pRelocTable = (IntPtr)((ulong)ModuleMemoryBase + idd.VirtualAddress);
            int nextRelocTableBlock = -1;

            while (nextRelocTableBlock != 0)
            {
                PE.IMAGE_BASE_RELOCATION ibr = new PE.IMAGE_BASE_RELOCATION();
                ibr = (PE.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(pRelocTable, typeof(PE.IMAGE_BASE_RELOCATION));

                long RelocCount = ((ibr.SizeOfBlock - Marshal.SizeOf(ibr)) / 2);
                for (int i = 0; i < RelocCount; i++)
                {
                    IntPtr pRelocEntry = (IntPtr)((ulong)pRelocTable + (ulong)Marshal.SizeOf(ibr) + (ulong)(i * 2));
                    ushort RelocValue = (ushort)Marshal.ReadInt16(pRelocEntry);

                    ushort RelocType = (ushort)(RelocValue >> 12);
                    ushort RelocPatch = (ushort)(RelocValue & 0xfff);

                    if (RelocType != 0) 
                    {
                        try
                        {
                            IntPtr pPatch = (IntPtr)((ulong)ModuleMemoryBase + ibr.VirtualAdress + RelocPatch);
                            if (RelocType == 0x3) 
                            {
                                int OriginalPtr = Marshal.ReadInt32(pPatch);
                                Marshal.WriteInt32(pPatch, (OriginalPtr + (int)ImageDelta));
                            }
                            else
                            {
                                long OriginalPtr = Marshal.ReadInt64(pPatch);
                                Marshal.WriteInt64(pPatch, (OriginalPtr + ImageDelta));
                            }
                        }
                        catch
                        {
                            throw new InvalidOperationException("Memory access violation.");
                        }
                    }
                }


                pRelocTable = (IntPtr)((ulong)pRelocTable + ibr.SizeOfBlock);
                nextRelocTableBlock = Marshal.ReadInt32(pRelocTable);
            }
        }

        public static void RewriteModuleIAT(PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            PE.IMAGE_DATA_DIRECTORY idd = PEINFO.Is32Bit ? PEINFO.OptHeader32.ImportTable : PEINFO.OptHeader64.ImportTable;


            IntPtr pImportTable = (IntPtr)((ulong)ModuleMemoryBase + idd.VirtualAddress);

            Native.OSVERSIONINFOEX OSVersion = new Native.OSVERSIONINFOEX();
            Native.RtlGetVersion(ref OSVersion);
            Dictionary<string, string> ApiSetDict = new Dictionary<string, string>();
            if (OSVersion.MajorVersion >= 10)
            {
                ApiSetDict = Generic.GetApiSetMapping();
            }

            int counter = 0;
            Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR iid = new Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR();
            iid = (Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(
                (IntPtr)((ulong)pImportTable + (uint)(Marshal.SizeOf(iid) * counter)),
                typeof(Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)
            );
            while (iid.Name != 0)
            {
 
                string DllName = string.Empty;
                try
                {
                    DllName = Marshal.PtrToStringAnsi((IntPtr)((ulong)ModuleMemoryBase + iid.Name));
                }
                catch { }


                if (DllName == string.Empty)
                {
                    throw new InvalidOperationException("Failed to read DLL name.");
                }
                else
                {

                    if (OSVersion.MajorVersion >= 10 && (DllName.StartsWith("api-") || DllName.StartsWith("ext-")) &&
                        ApiSetDict.ContainsKey(DllName) && ApiSetDict[DllName].Length > 0)
                    {

                        DllName = ApiSetDict[DllName];
                    }

                    IntPtr hModule = Generic.GetLoadedModuleAddress(DllName);
                    if (hModule == IntPtr.Zero)
                    {
                        hModule = Generic.LoadModuleFromDisk(DllName);
                        if (hModule == IntPtr.Zero)
                        {
                            throw new FileNotFoundException(DllName + ", unable to find the specified file.");
                        }
                    }


                    if (PEINFO.Is32Bit)
                    {
                        PE.IMAGE_THUNK_DATA32 oft_itd = new PE.IMAGE_THUNK_DATA32();
                        for (int i = 0; true; i++)
                        {
                            oft_itd = (PE.IMAGE_THUNK_DATA32)Marshal.PtrToStructure((IntPtr)((ulong)ModuleMemoryBase + iid.OriginalFirstThunk + (uint)(i * (sizeof(uint)))), typeof(PE.IMAGE_THUNK_DATA32));
                            IntPtr ft_itd = (IntPtr)((ulong)ModuleMemoryBase + iid.FirstThunk + (ulong)(i * (sizeof(uint))));
                            if (oft_itd.AddressOfData == 0)
                            {
                                break;
                            }

                            if (oft_itd.AddressOfData < 0x80000000) 
                            {
                                IntPtr pImpByName = (IntPtr)((ulong)ModuleMemoryBase + oft_itd.AddressOfData + sizeof(ushort));
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = Generic.GetNativeExportAddress(hModule, Marshal.PtrToStringAnsi(pImpByName));

                                Marshal.WriteInt32(ft_itd, pFunc.ToInt32());
                            }
                            else
                            {
                                ulong fOrdinal = oft_itd.AddressOfData & 0xFFFF;
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = Generic.GetNativeExportAddress(hModule, (short)fOrdinal);

                                Marshal.WriteInt32(ft_itd, pFunc.ToInt32());
                            }
                        }
                    }
                    else
                    {
                        PE.IMAGE_THUNK_DATA64 oft_itd = new PE.IMAGE_THUNK_DATA64();
                        for (int i = 0; true; i++)
                        {
                            oft_itd = (PE.IMAGE_THUNK_DATA64)Marshal.PtrToStructure((IntPtr)((ulong)ModuleMemoryBase + iid.OriginalFirstThunk + (ulong)(i * (sizeof(ulong)))), typeof(PE.IMAGE_THUNK_DATA64));
                            IntPtr ft_itd = (IntPtr)((ulong)ModuleMemoryBase + iid.FirstThunk + (ulong)(i * (sizeof(ulong))));
                            if (oft_itd.AddressOfData == 0)
                            {
                                break;
                            }

                            if (oft_itd.AddressOfData < 0x8000000000000000)
                            {
                                IntPtr pImpByName = (IntPtr)((ulong)ModuleMemoryBase + oft_itd.AddressOfData + sizeof(ushort));
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = Generic.GetNativeExportAddress(hModule, Marshal.PtrToStringAnsi(pImpByName));

                                Marshal.WriteInt64(ft_itd, pFunc.ToInt64());
                            }
                            else
                            {
                                ulong fOrdinal = oft_itd.AddressOfData & 0xFFFF;
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = Generic.GetNativeExportAddress(hModule, (short)fOrdinal);

                                Marshal.WriteInt64(ft_itd, pFunc.ToInt64());
                            }
                        }
                    }
                    counter++;
                    iid = (Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(
                        (IntPtr)((ulong)pImportTable + (uint)(Marshal.SizeOf(iid) * counter)),
                        typeof(Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)
                    );
                }
            }
        }

        public static void SetModuleSectionPermissions(PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            IntPtr BaseOfCode = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.BaseOfCode : (IntPtr)PEINFO.OptHeader64.BaseOfCode;
            Native.NtProtectVirtualMemory((IntPtr)(-1), ref ModuleMemoryBase, ref BaseOfCode, Win32.WinNT.PAGE_READONLY);

            foreach (PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
            {
                bool isRead = (ish.Characteristics & PE.DataSectionFlags.MEM_READ) != 0;
                bool isWrite = (ish.Characteristics & PE.DataSectionFlags.MEM_WRITE) != 0;
                bool isExecute = (ish.Characteristics & PE.DataSectionFlags.MEM_EXECUTE) != 0;
                uint flNewProtect = 0;
                if (isRead & !isWrite & !isExecute)
                {
                    flNewProtect = Win32.WinNT.PAGE_READONLY;
                }
                else if (isRead & isWrite & !isExecute)
                {
                    flNewProtect = Win32.WinNT.PAGE_READWRITE;
                }
                else if (isRead & isWrite & isExecute)
                {
                    flNewProtect = Win32.WinNT.PAGE_EXECUTE_READWRITE;
                }
                else if (isRead & !isWrite & isExecute)
                {
                    flNewProtect = Win32.WinNT.PAGE_EXECUTE_READ;
                }
                else if (!isRead & !isWrite & isExecute)
                {
                    flNewProtect = Win32.WinNT.PAGE_EXECUTE;
                }
                else
                {
                    throw new InvalidOperationException("Unknown section flag, " + ish.Characteristics);
                }

                IntPtr pVirtualSectionBase = (IntPtr)((ulong)ModuleMemoryBase + ish.VirtualAddress);
                IntPtr ProtectSize = (IntPtr)ish.VirtualSize;

               Native.NtProtectVirtualMemory((IntPtr)(-1), ref pVirtualSectionBase, ref ProtectSize, flNewProtect);
            }
        }

        public static PE.PE_MANUAL_MAP MapModuleToMemory(string ModulePath)
        {
            bool isWOW64 = Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
            if (IntPtr.Size == 4 && isWOW64)
            {
                throw new InvalidOperationException("Manual mapping in WOW64 is not supported.");
            }

            IntPtr pModule = AllocateFileToMemory(ModulePath);

            return MapModuleToMemory(pModule);
        }

        public static PE.PE_MANUAL_MAP MapModuleToMemory(IntPtr pModule)
        {
            PE.PE_META_DATA PEINFO = Generic.GetPeMetaData(pModule);


            if ((PEINFO.Is32Bit && IntPtr.Size == 8) || (!PEINFO.Is32Bit && IntPtr.Size == 4))
            {
                Marshal.FreeHGlobal(pModule);
                throw new InvalidOperationException("The module architecture does not match the process architecture.");
            }

            IntPtr BaseAddress = IntPtr.Zero;
            IntPtr RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;
            IntPtr pImage = Native.NtAllocateVirtualMemory(
                (IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize,
                Win32.Kernel32.MEM_COMMIT | Win32.Kernel32.MEM_RESERVE,
                Win32.WinNT.PAGE_READWRITE
            );

            return MapModuleToMemory(pModule, pImage, PEINFO);
        }

        public static PE.PE_MANUAL_MAP MapModuleToMemory(IntPtr pModule, IntPtr pImage, PE.PE_META_DATA PEINFO)
        {
            if ((PEINFO.Is32Bit && IntPtr.Size == 8) || (!PEINFO.Is32Bit && IntPtr.Size == 4))
            {
                Marshal.FreeHGlobal(pModule);
                throw new InvalidOperationException("The module architecture does not match the process architecture.");
            }

            uint SizeOfHeaders = PEINFO.Is32Bit ? PEINFO.OptHeader32.SizeOfHeaders : PEINFO.OptHeader64.SizeOfHeaders;
            uint BytesWritten =Native.NtWriteVirtualMemory((IntPtr)(-1), pImage, pModule, SizeOfHeaders);

            foreach (PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
            {
                IntPtr pVirtualSectionBase = (IntPtr)((ulong)pImage + ish.VirtualAddress);
                IntPtr pRawSectionBase = (IntPtr)((ulong)pModule + ish.PointerToRawData);

                BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
                if (BytesWritten != ish.SizeOfRawData)
                {
                    throw new InvalidOperationException("Failed to write to memory.");
                }
            }

            RelocateModule(PEINFO, pImage);

            RewriteModuleIAT(PEINFO, pImage);

            SetModuleSectionPermissions(PEINFO, pImage);

            Marshal.FreeHGlobal(pModule);

            PE.PE_MANUAL_MAP ManMapObject = new PE.PE_MANUAL_MAP
            {
                ModuleBase = pImage,
                PEINFO = PEINFO
            };

            return ManMapObject;
        }


    }
}
