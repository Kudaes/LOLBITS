using System.IO;
using System.Text;

namespace LOLBITS.TokenManagement
{
    /// <summary>
    /// Defines the data protocol for reading and writing strings on our stream.
    /// </summary>
    public class StreamString
    {
        private readonly Stream ioStream;
        private readonly UnicodeEncoding streamEncoding;

        public StreamString(Stream ioStream)
        {
            this.ioStream = ioStream;
            streamEncoding = new UnicodeEncoding();
        }

        public string ReadString()
        {
            var len = ioStream.ReadByte() * 256;
            len += ioStream.ReadByte();
            var inBuffer = new byte[len];
            ioStream.Read(inBuffer, 0, len);

            return streamEncoding.GetString(inBuffer);
        }

        public int WriteString(string outString)
        {
            var outBuffer = streamEncoding.GetBytes(outString);
            var len = outBuffer.Length;

            if (len > ushort.MaxValue) 
                len = ushort.MaxValue;

            ioStream.WriteByte((byte)(len / 256));
            ioStream.WriteByte((byte)(len & 255));
            ioStream.Write(outBuffer, 0, len);
            ioStream.Flush();

            return outBuffer.Length + 2;
        }
    }
}