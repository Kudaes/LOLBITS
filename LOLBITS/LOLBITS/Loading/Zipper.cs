using System;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace LOLBITS.Loading
{
    public static class Zipper
    {
        private static void CopyTo(Stream src, Stream dest)
        {
            byte[] bytes = new byte[4096];

            int cnt;

            while ((cnt = src.Read(bytes, 0, bytes.Length)) != 0)
            {
                dest.Write(bytes, 0, cnt);
            }
        }

        public static string Compress(string toCompress)
        {

            byte[] inputBytes = Encoding.UTF8.GetBytes(toCompress);

            using (var outputStream = new MemoryStream())
            {
                using (var gZipStream = new GZipStream(outputStream, CompressionMode.Compress))
                    gZipStream.Write(inputBytes, 0, inputBytes.Length);
                var outputBytes = outputStream.ToArray();
                var outputBase64 = Convert.ToBase64String(outputBytes);
                return outputBase64;

            }
        }

        public static string Decompress(string toDecompress)
        {
            byte[] gZipBuffer = Convert.FromBase64String(toDecompress);
            using (var msi = new MemoryStream(gZipBuffer))
            using (var mso = new MemoryStream())
            {
                using (var gs = new GZipStream(msi, CompressionMode.Decompress))
                {

                    CopyTo(gs, mso);
                }

                return Encoding.UTF8.GetString(mso.ToArray());
            }
        }
    }
}
