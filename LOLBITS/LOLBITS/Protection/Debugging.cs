
namespace LOLBITS.Protection
{
    class Debugging
    {
        public static bool areWeSafe()
        {
            return System.Diagnostics.Debugger.IsAttached ? false : true;          
        }
    }
}
