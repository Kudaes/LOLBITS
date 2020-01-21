using System;
using System.Reflection;
using System.Threading;

namespace LOLBITS.Controlling
{
    public class LauncherDll
    {
        public static void Main(string method, string[] arguments, Assembly dll)
        {
            LauncherDll obj = new LauncherDll();

            Thread thr1 = new Thread(ExecuteDllInMemory);

            object[] a = new object []{ method, arguments, dll };

            thr1.Start(a);
        }

        public static void ExecuteDllInMemory(object args)
        {
            object[] a = (object[])args;
            string methodArgument = (string)a[0];
            string[] arguments = (string[])a[1];
            Assembly dll = (Assembly)a[2];
            Type myType = dll.GetTypes()[0];
            MethodInfo method = myType.GetMethod(methodArgument);
            object myInstance = Activator.CreateInstance(myType);

            method.Invoke(myInstance, new object[] { arguments });

        }
    }
}