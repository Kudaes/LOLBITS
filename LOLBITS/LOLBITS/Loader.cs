using System;
using System.IO;
using System.Text;
using System.IO.Compression;

namespace LOLBITS
{

    public static class BiteArrayToHex
    {
        public static string Convert(byte[] bytearrayAConverter)
        {
            return (BitConverter.ToString(bytearrayAConverter)).Replace("-", "").ToLower();
        }

    }

    public class BiteArrayFromArchive
    {

        public static byte[] ExtraBites(string archiveToRead)
        {
            byte[] extraBites = System.IO.File.ReadAllBytes(archiveToRead);
            return extraBites;
        }


    }

    public static class StringHexToByteArray
    {
        public static byte[] Convert(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];

            for (int i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = System.Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }
    }

    public class ByteArrayToString
    {

        public static string Convert(byte[] toConvert)
        {
            string a = "";
            foreach (Byte b in toConvert)
            {
                a += (b + " ");
            }
            return a;
        }

    }

    public static class Rc4
    {

        public static byte[] Encrypt(byte[] pwd, byte[] data)
        {
            int a, i, j;
            int tmp;

            var key = new int[256];
            var box = new int[256];
            var cipher = new byte[data.Length];

            for (i = 0; i < 256; i++)
            {
                key[i] = pwd[i % pwd.Length];
                box[i] = i;
            }
            for (j = i = 0; i < 256; i++)
            {
                j = (j + box[i] + key[i]) % 256;
                tmp = box[i];
                box[i] = box[j];
                box[j] = tmp;
            }
            for (a = j = i = 0; i < data.Length; i++)
            {
                a++;
                a %= 256;
                j += box[a];
                j %= 256;
                tmp = box[a];
                box[a] = box[j];
                box[j] = tmp;
                var k = box[((box[a] + box[j]) % 256)];
                cipher[i] = (byte)(data[i] ^ k);
            }
            return cipher;
        }

        public static byte[] Decrypt(byte[] pwd, byte[] data)
        {
            return Encrypt(pwd, data);
        }

        public static byte[] StringToByteArray(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

    }

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
