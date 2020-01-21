namespace LOLBITS.Loading
{
    public static class StringHexToByteArray
    {
        public static byte[] Convert(string hex)
        {
            var numberChars = hex.Length;
            var bytes = new byte[numberChars / 2];

            for (var i = 0; i < numberChars; i += 2) 
                bytes[i / 2] = System.Convert.ToByte(hex.Substring(i, 2), 16);

            return bytes;
        }
    }
}