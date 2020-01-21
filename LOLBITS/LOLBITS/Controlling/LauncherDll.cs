using System;
using System.Reflection;
using System.Threading;

namespace LOLBITS.Controlling
{
    public class LauncherDll
    {
        public static void Main(string method, string[] arguments, Assembly dll)
        {
            var obj = new LauncherDll();

            var thr1 = new Thread(ExecuteDllInMemory);

            var a = new object []{ method, arguments, dll };

            thr1.Start(a);
        }

        private static void ExecuteDllInMemory(object args)
        {
            var a = (object[])args;
            var methodArgument = (string)a[0];
            var arguments = (string[])a[1];
            var dll = (Assembly)a[2];
            var myType = dll.GetTypes()[0];
            var method = myType.GetMethod(methodArgument);
            var myInstance = Activator.CreateInstance(myType);

            method?.Invoke(myInstance, new object[] { arguments });
        }
    }
}