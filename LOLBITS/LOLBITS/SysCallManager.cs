using System;
using System.Collections.Generic;

namespace LOLBITS
{
    public class SysCallManager
    {
        private readonly Dictionary<string, Dictionary<string, int>> _dicWinServer2008 = new Dictionary<string, Dictionary<string, int>>();
        private readonly Dictionary<string, Dictionary<string, int>> _dicWinServer2012 = new Dictionary<string, Dictionary<string, int>>();
        private readonly Dictionary<string, Dictionary<string, int>> _dicWin7 = new Dictionary<string, Dictionary<string, int>>();
        private readonly Dictionary<string, Dictionary<string, int>> _dicWin8 = new Dictionary<string, Dictionary<string, int>>();
        private readonly Dictionary<string, Dictionary<string, int>> _dicWin10 = new Dictionary<string, Dictionary<string, int>>(); 

        private readonly byte[] _shellCode = {
                    0x4C, 0x8B, 0xD1,             // mov r10, rcx
                    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0x00 <- (sysCall identifier)
                    0x0F, 0x05,                   // sysCall
                    0xC3                          // ret
            };

        public SysCallManager()
        {
            /////////////NtAllocateVirtualMemory
            var val2008 = new Dictionary<string, int>();
            var val2012 = new Dictionary<string, int>();
            var val7 = new Dictionary<string, int>();
            var val8 = new Dictionary<string, int>();
            var val10 = new Dictionary<string, int>();

            val2008.Add("UNIQUE", 0x0015);

            val2012.Add("SP0", 0x0016);
            val2012.Add("R2", 0x0017);

            val7.Add("UNIQUE", 0x0015);

            val8.Add("8.0", 0x0016);
            val8.Add("8.1", 0x0017);

            val10.Add("UNIQUE", 0x0018);
            _dicWinServer2008.Add("NtAllocateVirtualMemory", val2008);
            _dicWinServer2012.Add("NtAllocateVirtualMemory", val2012);
            _dicWin7.Add("NtAllocateVirtualMemory", val7);
            _dicWin8.Add("NtAllocateVirtualMemory", val8);
            _dicWin10.Add("NtAllocateVirtualMemory", val10);

            /////////////NtWriteVirtualMemory
            val2008 = new Dictionary<string, int>();
            val2012 = new Dictionary<string, int>();
            val7 = new Dictionary<string, int>();
            val8 = new Dictionary<string, int>();
            val10 = new Dictionary<string, int>();

            val2008.Add("UNIQUE", 0x0037);

            val2012.Add("SP0", 0x0038);
            val2012.Add("R2", 0x0039);

            val7.Add("UNIQUE", 0x0037);

            val8.Add("8.0", 0x0038);
            val8.Add("8.1", 0x0039);

            val10.Add("UNIQUE", 0x003A);

            _dicWinServer2008.Add("NtWriteVirtualMemory", val2008);
            _dicWinServer2012.Add("NtWriteVirtualMemory", val2012);
            _dicWin7.Add("NtWriteVirtualMemory", val7);
            _dicWin8.Add("NtWriteVirtualMemory", val8);
            _dicWin10.Add("NtWriteVirtualMemory", val10);

            /////////////NtCreateThreadEx
            val2008 = new Dictionary<string, int>();
            val2012 = new Dictionary<string, int>();
            val7 = new Dictionary<string, int>();
            val8 = new Dictionary<string, int>();
            val10 = new Dictionary<string, int>();

            val2008.Add("UNIQUE", 0x00A5);

            val2012.Add("SP0", 0x00AF);
            val2012.Add("R2", 0x00B0);

            val7.Add("UNIQUE", 0x00A5);

            val8.Add("8.0", 0x00AF);
            val8.Add("8.1", 0x00B0);

            val10.Add("1507", 0x00B3);
            val10.Add("1511", 0x00B4);
            val10.Add("1607", 0x00B6);
            val10.Add("1703", 0x00B9);
            val10.Add("1709", 0x00BA);
            val10.Add("1803", 0x00BB);
            val10.Add("1809", 0x00BC);
            val10.Add("1903", 0x00BD);
            val10.Add("1909", 0x00BD);

            _dicWinServer2008.Add("NtCreateThreadEx", val2008);
            _dicWinServer2012.Add("NtCreateThreadEx", val2012);
            _dicWin7.Add("NtCreateThreadEx", val7);
            _dicWin8.Add("NtCreateThreadEx", val8);
            _dicWin10.Add("NtCreateThreadEx", val10);

            /////////////NtOpenProcessToken
            val2008 = new Dictionary<string, int>();
            val2012 = new Dictionary<string, int>();
            val7 = new Dictionary<string, int>();
            val8 = new Dictionary<string, int>();
            val10 = new Dictionary<string, int>();

            val2008.Add("SP0", 0x00F3);
            val2008.Add("SP2", 0x00F3);
            val2008.Add("R2", 0x00F9);
            val2008.Add("R2 SP1", 0x00F9);
            
            val2012.Add("SP0", 0x010B);
            val2012.Add("R2", 0x010E);

            val7.Add("UNIQUE", 0x00F9);

            val8.Add("8.0", 0x010B);
            val8.Add("8.1", 0x010E);

            val10.Add("1507", 0x0114);
            val10.Add("1511", 0x0117);
            val10.Add("1607", 0x0119);
            val10.Add("1703", 0x011D);
            val10.Add("1709", 0x011F);
            val10.Add("1803", 0x0121);
            val10.Add("1809", 0x0122);
            val10.Add("1903", 0x0123);
            val10.Add("1909", 0x0123);

            _dicWinServer2008.Add("NtOpenProcessToken", val2008);
            _dicWinServer2012.Add("NtOpenProcessToken", val2012);
            _dicWin7.Add("NtOpenProcessToken", val7);
            _dicWin8.Add("NtOpenProcessToken", val8);
            _dicWin10.Add("NtOpenProcessToken", val10);

            /////////////NtAdjustPrivilegesToken
            val2008 = new Dictionary<string, int>();
            val2012 = new Dictionary<string, int>();
            val7 = new Dictionary<string, int>();
            val8 = new Dictionary<string, int>();
            val10 = new Dictionary<string, int>();

            val2008.Add("UNIQUE", 0x003E);

            val2012.Add("SP0", 0x003F);
            val2012.Add("R2", 0x0040);

            val7.Add("UNIQUE", 0x003E);

            val8.Add("8.0", 0x003F);
            val8.Add("8.1", 0x0040);

            val10.Add("UNIQUE", 0x0041);
            _dicWinServer2008.Add("NtAdjustPrivilegesToken", val2008);
            _dicWinServer2012.Add("NtAdjustPrivilegesToken", val2012);
            _dicWin7.Add("NtAdjustPrivilegesToken", val7);
            _dicWin8.Add("NtAdjustPrivilegesToken", val8);
            _dicWin10.Add("NtAdjustPrivilegesToken", val10);
        }

        public byte[] GetSysCallAsm(string functionName)
        {
            const string subKey = @"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion";
            var key = Microsoft.Win32.Registry.LocalMachine;
            var sKey = key.OpenSubKey(subKey);

            var product = sKey?.GetValue("ProductName").ToString();
            var release = sKey?.GetValue("ReleaseId").ToString();

            var ver = product?.Split(' ');
            Dictionary<string, Dictionary<string, int>> dict = null;

            if(ver?[1] == "Server")
            {
                switch (ver[2]){
                    case "2008": { dict = _dicWinServer2008; break; }
                    case "2012": { dict = _dicWinServer2012; break; }
                    case "2016": { dict = _dicWin10; break; } //syscall tables for windows server 2016 and 2019 are equivalent to that of windows 10.
                    case "2019": { dict = _dicWin10; break; }
                    default: { return null; }
                }
            }
            else
            {
                switch (ver?[1])
                {
                    case "7": { dict = _dicWin7; break; }
                    case "8": { dict = _dicWin8; break; }
                    case "10": { dict = _dicWin10; break; }
                    default: { return null; }
                }
            }

            var funcName = dict[functionName];
            var sysCallValue = funcName.ContainsKey("UNIQUE") ? funcName["UNIQUE"] : funcName[release];
            var copy = _shellCode;
            var sysCallIdentifierBytes = BitConverter.GetBytes(sysCallValue);
            Buffer.BlockCopy(sysCallIdentifierBytes, 0, copy, 4, sizeof(uint));

            return copy;
        }
    }
}
