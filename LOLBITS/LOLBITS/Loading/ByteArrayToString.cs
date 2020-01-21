using System;
using System.Linq;

namespace LOLBITS.Loading
{
    public class ByteArrayToString
    {
        public static string Convert(byte[] toConvert)
        {
            return toConvert.Aggregate("", (current, b) => current + (b + " "));
        }
    }
}