using System;

namespace LOLBITS.Loading
{
    public class ByteArrayToString
    {
        public static string Convert(byte[] toConvert)
        {
            string a = "";

            foreach (Byte b in toConvert) a += (b + " ");

            return a;
        }
    }
}