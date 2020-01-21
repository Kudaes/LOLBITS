using System;
using System.Reflection;
using System.Threading;

namespace LOLBITS
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
            string method = (string)a[0];
            string[] arguments = (string[])a[1];
            Assembly dll = (Assembly)a[2];
            Type myType = dll.GetTypes()[0];
            MethodInfo Method = myType.GetMethod(method);
            object myInstance = Activator.CreateInstance(myType);
            Method.Invoke(myInstance, new object[] { arguments });

        }
    }
}