using System;
using System.Reflection;
using System.Threading;

namespace LOLBITS.Controlling
{
    public class LauncherPE
    {
        public static void Main(string method, string[] arguments, Assembly dll)
        {
            var obj = new LauncherPE();

            var thr1 = new Thread(ExecutePEInMemory);

            var a = new object []{ method, arguments, dll };

            thr1.Start(a);
        }

        private static void ExecutePEInMemory(object args)
        {
            var a = (object[])args;
            var methodArgument = (string)a[0];
            var arguments = (string[])a[1];
            var pe = (Assembly)a[2];
            Type[] types = pe.GetTypes();

            MethodInfo method = null;
            Type myType = null;
            foreach (var type in types)
            {
                
                method = type.GetMethod(methodArgument);
                if (method != null)
                {
                    myType = type;
                    break;
                }
            }


            //var myType = dll.GetTypes()[0];
            //var method = myType.GetMethod(methodArgument);
            if (method != null && myType != null)
            {
                var myInstance = Activator.CreateInstance(myType);
                method.Invoke(myInstance, new object[] { arguments });
            }
        }
    }
}