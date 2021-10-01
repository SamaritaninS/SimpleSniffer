using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Windows.Media.Imaging;

namespace SimpleSniffer
{
    public class Sniffer
    {
        [STAThread]
        public static void Main()
        {
             System.Security.Principal.WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent();
             Application.EnableVisualStyles();
             System.Security.Principal.WindowsPrincipal principal = new System.Security.Principal.WindowsPrincipal(identity);

             if (principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
             {
                 Application.Run(new MainForm());
             }
             else
             {
                 System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
                 startInfo.UseShellExecute = true;
                 startInfo.WorkingDirectory = Environment.CurrentDirectory;
                 startInfo.FileName = Application.ExecutablePath;
                 startInfo.Verb = "runas";
                 try
                 {
                     System.Diagnostics.Process.Start(startInfo);
                 }
                 catch
                 {
                     return;
                 }
                 Application.Exit();
             }
        }
    }
}
