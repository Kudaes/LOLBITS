using System;
using System.IO;
using System.Text;
using System.IO.Compression;

namespace LOLBITS
{

    public class BiteArrayToHex
    {
        public static string Convierte(byte[] bytearray_a_convertir)
        {
            return (BitConverter.ToString(bytearray_a_convertir)).Replace("-", "").ToLower();
        }

    }

    public class BiteArrayFromArchivo
    {

        public static byte[] ExtraeBites(string Archivo_a_leer)
        {
            byte[] Bites_extraidos = System.IO.File.ReadAllBytes(Archivo_a_leer);
            return Bites_extraidos;
        }


    }

    public class StringHEXToByteArray
    {
        public static byte[] Convierte(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];

            for (int i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }
    }

    public class ByteArrayToString
    {

        public static string Convierte(byte[] movidaaconvertir)
        {
            string a = "";
            foreach (Byte b in movidaaconvertir)
            {
                a += (b + " ");
            }
            return a;
        }

    }

    public class RC4
    {

        public static byte[] Encrypt(byte[] pwd, byte[] data)
        {
            int a, i, j, k, tmp;
            int[] key, box;
            byte[] cipher;

            key = new int[256];
            box = new int[256];
            cipher = new byte[data.Length];

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
                k = box[((box[a] + box[j]) % 256)];
                cipher[i] = (byte)(data[i] ^ k);
            }
            return cipher;
        }

        public static byte[] Decrypt(byte[] pwd, byte[] data)
        {
            return Encrypt(pwd, data);
        }

        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

    }

    public class Zipea
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

        public static string Comprime(string movidaacomprimir)
        {

            byte[] inputBytes = Encoding.UTF8.GetBytes(movidaacomprimir);

            using (var outputStream = new MemoryStream())
            {
                using (var gZipStream = new GZipStream(outputStream, CompressionMode.Compress))
                    gZipStream.Write(inputBytes, 0, inputBytes.Length);
                var outputBytes = outputStream.ToArray();
                var outputbase64 = Convert.ToBase64String(outputBytes);
                return outputbase64;

            }
        }
        public static string Descomprime(string movidaadescomprimir)
        {
            byte[] gZipBuffer = Convert.FromBase64String(movidaadescomprimir);
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
