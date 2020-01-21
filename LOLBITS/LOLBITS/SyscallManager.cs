using System;
using System.Collections.Generic;

namespace LOLBITS
{
    public class SyscallManager
    {
        private readonly Dictionary<string, Dictionary<string, int>> _dicWinServer2008 = new Dictionary<string, Dictionary<string, int>>();
        private readonly Dictionary<string, Dictionary<string, int>> _dicWinServer2012 = new Dictionary<string, Dictionary<string, int>>();
        private readonly Dictionary<string, Dictionary<string, int>> _dicWin7 = new Dictionary<string, Dictionary<string, int>>();
        private readonly Dictionary<string, Dictionary<string, int>> _dicWin8 = new Dictionary<string, Dictionary<string, int>>();
        private readonly Dictionary<string, Dictionary<string, int>> _dicWin10 = new Dictionary<string, Dictionary<string, int>>(); 

        private readonly byte[] _shellCode = {
                    0x4C, 0x8B, 0xD1,             // mov r10, rcx
                    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0x00 (syscall identifier)
                    0x0F, 0x05,                   // syscall
                    0xC3                          // ret
            };




        public SyscallManager()
        {

            /////////////NtAllocateVirtualMemory
            Dictionary<string, int> Val2008 = new Dictionary<string, int>();
            Dictionary<string, int> Val2012 = new Dictionary<string, int>();
            Dictionary<string, int> Val7 = new Dictionary<string, int>();
            Dictionary<string, int> Val8 = new Dictionary<string, int>();
            Dictionary<string, int> Val10 = new Dictionary<string, int>();

            Val2008.Add("UNIQUE", 0x0015);

            Val2012.Add("SP0", 0x0016);
            Val2012.Add("R2", 0x0017);

            Val7.Add("UNIQUE", 0x0015);

            Val8.Add("8.0", 0x0016);
            Val8.Add("8.1", 0x0017);

            Val10.Add("UNIQUE", 0x0018);
            _dicWinServer2008.Add("NtAllocateVirtualMemory", Val2008);
            _dicWinServer2012.Add("NtAllocateVirtualMemory", Val2012);
            _dicWin7.Add("NtAllocateVirtualMemory", Val7);
            _dicWin8.Add("NtAllocateVirtualMemory", Val8);
            _dicWin10.Add("NtAllocateVirtualMemory", Val10);

            /////////////NtWriteVirtualMemory
            Val2008 = new Dictionary<string, int>();
            Val2012 = new Dictionary<string, int>();
            Val7 = new Dictionary<string, int>();
            Val8 = new Dictionary<string, int>();
            Val10 = new Dictionary<string, int>();

            Val2008.Add("UNIQUE", 0x0037);

            Val2012.Add("SP0", 0x0038);
            Val2012.Add("R2", 0x0039);

            Val7.Add("UNIQUE", 0x0037);

            Val8.Add("8.0", 0x0038);
            Val8.Add("8.1", 0x0039);

            Val10.Add("UNIQUE", 0x003A);

            _dicWinServer2008.Add("NtWriteVirtualMemory", Val2008);
            _dicWinServer2012.Add("NtWriteVirtualMemory", Val2012);
            _dicWin7.Add("NtWriteVirtualMemory", Val7);
            _dicWin8.Add("NtWriteVirtualMemory", Val8);
            _dicWin10.Add("NtWriteVirtualMemory", Val10);

            /////////////NtCreateThreadEx
            Val2008 = new Dictionary<string, int>();
            Val2012 = new Dictionary<string, int>();
            Val7 = new Dictionary<string, int>();
            Val8 = new Dictionary<string, int>();
            Val10 = new Dictionary<string, int>();

            Val2008.Add("UNIQUE", 0x00A5);

            Val2012.Add("SP0", 0x00AF);
            Val2012.Add("R2", 0x00B0);

            Val7.Add("UNIQUE", 0x00A5);

            Val8.Add("8.0", 0x00AF);
            Val8.Add("8.1", 0x00B0);

            Val10.Add("1507", 0x00B3);
            Val10.Add("1511", 0x00B4);
            Val10.Add("1607", 0x00B6);
            Val10.Add("1703", 0x00B9);
            Val10.Add("1709", 0x00BA);
            Val10.Add("1803", 0x00BB);
            Val10.Add("1809", 0x00BC);
            Val10.Add("1903", 0x00BD);
            Val10.Add("1909", 0x00BD);

            _dicWinServer2008.Add("NtCreateThreadEx", Val2008);
            _dicWinServer2012.Add("NtCreateThreadEx", Val2012);
            _dicWin7.Add("NtCreateThreadEx", Val7);
            _dicWin8.Add("NtCreateThreadEx", Val8);
            _dicWin10.Add("NtCreateThreadEx", Val10);

            /////////////NtOpenProcessToken
            Val2008 = new Dictionary<string, int>();
            Val2012 = new Dictionary<string, int>();
            Val7 = new Dictionary<string, int>();
            Val8 = new Dictionary<string, int>();
            Val10 = new Dictionary<string, int>();

            Val2008.Add("SP0", 0x00F3);
            Val2008.Add("SP2", 0x00F3);
            Val2008.Add("R2", 0x00F9);
            Val2008.Add("R2 SP1", 0x00F9);


            Val2012.Add("SP0", 0x010B);
            Val2012.Add("R2", 0x010E);

            Val7.Add("UNIQUE", 0x00F9);

            Val8.Add("8.0", 0x010B);
            Val8.Add("8.1", 0x010E);

            Val10.Add("1507", 0x0114);
            Val10.Add("1511", 0x0117);
            Val10.Add("1607", 0x0119);
            Val10.Add("1703", 0x011D);
            Val10.Add("1709", 0x011F);
            Val10.Add("1803", 0x0121);
            Val10.Add("1809", 0x0122);
            Val10.Add("1903", 0x0123);
            Val10.Add("1909", 0x0123);

            _dicWinServer2008.Add("NtOpenProcessToken", Val2008);
            _dicWinServer2012.Add("NtOpenProcessToken", Val2012);
            _dicWin7.Add("NtOpenProcessToken", Val7);
            _dicWin8.Add("NtOpenProcessToken", Val8);
            _dicWin10.Add("NtOpenProcessToken", Val10);

            /////////////NtAdjustPrivilegesToken
            Val2008 = new Dictionary<string, int>();
            Val2012 = new Dictionary<string, int>();
            Val7 = new Dictionary<string, int>();
            Val8 = new Dictionary<string, int>();
            Val10 = new Dictionary<string, int>();

            Val2008.Add("UNIQUE", 0x003E);

            Val2012.Add("SP0", 0x003F);
            Val2012.Add("R2", 0x0040);

            Val7.Add("UNIQUE", 0x003E);

            Val8.Add("8.0", 0x003F);
            Val8.Add("8.1", 0x0040);

            Val10.Add("UNIQUE", 0x0041);
            _dicWinServer2008.Add("NtAdjustPrivilegesToken", Val2008);
            _dicWinServer2012.Add("NtAdjustPrivilegesToken", Val2012);
            _dicWin7.Add("NtAdjustPrivilegesToken", Val7);
            _dicWin8.Add("NtAdjustPrivilegesToken", Val8);
            _dicWin10.Add("NtAdjustPrivilegesToken", Val10);


        }

        public byte[] GetSysCallAsm(string functionName)
        {

            string subKey = @"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion";
            Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.LocalMachine;
            Microsoft.Win32.RegistryKey sKey = key.OpenSubKey(subKey);

            string product = sKey.GetValue("ProductName").ToString();
            string release = sKey.GetValue("ReleaseId").ToString();

            string[] ver = product.Split(' ');
            Dictionary<string, Dictionary<string, int>> dict = null;

            if(ver[1] == "Server")
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
                switch (ver[1])
                {
                    case "7": { dict = _dicWin7; break; }
                    case "8": { dict = _dicWin8; break; }
                    case "10": { dict = _dicWin10; break; }
                    default: { return null; }
                }
            }

            Dictionary<string, int> funcName = dict[functionName];
            int sysCallValue = funcName.ContainsKey("UNIQUE") ? funcName["UNIQUE"] : funcName[release];
            byte[] copy = _shellCode;
            var sysCallIdentifierBytes = BitConverter.GetBytes(sysCallValue);
            Buffer.BlockCopy(sysCallIdentifierBytes, 0, copy, 4, sizeof(uint));

            return copy;
        }
    }
}
