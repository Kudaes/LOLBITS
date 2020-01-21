using System;

namespace LOLBITS.Loading
{
    public static class BiteArrayToHex
    {
        public static string Convert(byte[] bytearrayAConverter)
        {
            return (BitConverter.ToString(bytearrayAConverter)).Replace("-", "").ToLower();
        }
    }
}