# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Recolección Inicial de Información

### Información Básica

Antes que nada, se recomienda tener algún **USB** con **binaries y libraries** conocidas y confiables en él (puedes simplemente obtener ubuntu y copiar las carpetas _/bin_, _/sbin_, _/lib,_ y _/lib64_), luego monta el USB y modifica las variables de entorno para usar esos binaries:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Una vez que hayas configurado el sistema para usar binarios buenos y conocidos, puedes empezar a **extraer información básica**:
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### Información sospechosa

Mientras obtienes la información básica, deberías comprobar cosas extrañas como:

- Los **procesos root** suelen ejecutarse con PIDs bajos, así que si encuentras un proceso root con un PID grande puedes sospechar
- Comprueba los **logins registrados** de usuarios sin una shell dentro de `/etc/passwd`
- Comprueba los **password hashes** dentro de `/etc/shadow` para usuarios sin una shell

### Memory Dump

Para obtener la memoria del sistema en ejecución, se recomienda usar [**LiME**](https://github.com/504ensicsLabs/LiME).\
Para **compilarlo**, necesitas usar el **mismo kernel** que está usando la máquina víctima.

> [!TIP]
> Recuerda que **no puedes instalar LiME ni cualquier otra cosa** en la máquina víctima, ya que hará varios cambios en ella

Así que, si tienes una versión idéntica de Ubuntu, puedes usar `apt-get install lime-forensics-dkms`\
En otros casos, necesitas descargar [**LiME**](https://github.com/504ensicsLabs/LiME) desde github y compilarlo con los correctos kernel headers. Para **obtener los exactos kernel headers** de la máquina víctima, puedes simplemente **copiar el directorio** `/lib/modules/<kernel version>` a tu máquina, y luego **compilar** LiME usando esos:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME soporta 3 **formats**:

- Raw (cada segmento concatenado)
- Padded (igual que raw, pero con ceros en los bits de la derecha)
- Lime (formato recomendado con metadatos

LiME también se puede usar para **enviar el dump via network** en lugar de almacenarlo en el sistema usando algo como: `path=tcp:4444`

### Disk Imaging

#### Shutting down

Antes que nada, necesitarás **apagar el sistema**. Esto no siempre es una opción, ya que a veces el sistema será un servidor de producción que la empresa no puede permitirse apagar.\
Hay **2 formas** de apagar el sistema: un apagado **normal** y un apagado de **"plug the plug"**. La primera permitirá que los **processes** terminen como de costumbre y que el **filesystem** se **sincronice**, pero también permitirá que el posible **malware** destruya evidencia. El enfoque de "pull the plug" puede conllevar **alguna pérdida de información** (no se perderá mucha información, ya que ya hemos tomado una imagen de la memoria) y el **malware no tendrá ninguna oportunidad** de hacer nada al respecto. Por lo tanto, si **sospechas** que puede haber **malware**, simplemente ejecuta el **`sync`** **command** en el sistema y corta la corriente.

#### Taking an image of the disk

Es importante notar que **antes de conectar tu ordenador a cualquier cosa relacionada con el caso**, debes asegurarte de que se va a **montar como solo lectura** para evitar modificar cualquier información.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Análisis preliminar de la imagen de disco

Imagen de una imagen de disco sin más datos.
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
## Buscar malware conocido

### Archivos del sistema modificados

Linux ofrece herramientas para garantizar la integridad de los componentes del sistema, cruciales para detectar archivos potencialmente problemáticos.

- **Sistemas basados en RedHat**: Usa `rpm -Va` para una comprobación completa.
- **Sistemas basados en Debian**: `dpkg --verify` para la verificación inicial, seguido de `debsums | grep -v "OK$"` (después de instalar `debsums` con `apt-get install debsums`) para identificar cualquier problema.

### Detectores de Malware/Rootkit

Lee la siguiente página para aprender sobre herramientas que pueden ser útiles para encontrar malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Buscar programas instalados

Para buscar de forma efectiva programas instalados tanto en sistemas Debian como RedHat, considera aprovechar los logs y bases de datos del sistema junto con comprobaciones manuales en directorios comunes.

- Para Debian, inspecciona _**`/var/lib/dpkg/status`**_ y _**`/var/log/dpkg.log`**_ para obtener detalles sobre las instalaciones de paquetes, usando `grep` para filtrar información específica.
- Los usuarios de RedHat pueden consultar la base de datos RPM con `rpm -qa --root=/mntpath/var/lib/rpm` para listar los paquetes instalados.

Para descubrir software instalado manualmente o fuera de estos gestores de paquetes, explora directorios como _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ y _**`/sbin`**_. Combina listados de directorios con comandos específicos del sistema para identificar ejecutables no asociados con paquetes conocidos, mejorando tu búsqueda de todos los programas instalados.
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
## Recuperar binarios en ejecución eliminados

Imagina un proceso que se ejecutó desde /tmp/exec y luego fue eliminado. Es posible extraerlo
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Triaje de Syscall Trace con SQLite y FTS5

Cuando un proceso sigue en ejecución o puede volver a ejecutarse en un laboratorio, **`strace`** puede proporcionar un trace de comportamiento rápido sin necesitar módulos del kernel ni telemetría completa de EDR. Para traces grandes, evita leer el log en bruto directamente o pegarlo en un LLM: guárdalo en una base de datos **SQLite** y consulta solo el subconjunto mínimo que necesites.

> [!WARNING]
> Adjuntar `strace` cambia la temporización del proceso y puede afectar condiciones de carrera u otros bugs frágiles. Prefiere reproducirlo en una copia/sistema de laboratorio cuando sea posible.

### Capture

Para un proceso nuevo:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Para un proceso en vivo:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Opciones útiles:

- `-ff`: seguir forks/threads y mantener salidas por proceso
- `-ttt`: timestamps de epoch para correlación fácil de timeline
- `-yy`: resolver file descriptors a paths/sockets de respaldo cuando sea posible
- `-s 4096`: evitar que se truncen paths largos y argumentos de buffer

### Normalizar

Un esquema práctico es una fila por syscall y una fila por argumento:
```sql
CREATE TABLE syscalls (
id        INTEGER PRIMARY KEY,
pid       INTEGER NOT NULL,
timestamp REAL    NOT NULL,
name      TEXT    NOT NULL,
ret_val   INTEGER,
errno     TEXT
);

CREATE TABLE syscall_args (
id         INTEGER PRIMARY KEY,
syscall_id INTEGER NOT NULL REFERENCES syscalls(id),
position   INTEGER NOT NULL,
raw        TEXT    NOT NULL,
type       INTEGER NOT NULL
);
```
Esto evita intentar aplanar líneas de syscalls heterogéneas en una sola tabla ancha y mantiene los joins predecibles durante el triage.

### Indexa argumentos con mucho texto con FTS5

La búsqueda ingenua de rutas con `LIKE "%...%"` se vuelve muy lenta en trazas grandes. Crea un índice FTS5 para el texto de los argumentos y busca eso en su lugar:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Ejemplo: recuperar la actividad de archivos en `/tmp` sin escanear cada fila:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Investigaciones de alta señal

- **PATH hijacking / fake sudo**: busca escrituras y actividad de `chmod`/`rename` en `~/.local/bin/`, y luego correlaciona con `execve` posteriores de nombres con aspecto privilegiado como `sudo`.
- **TOCTOU on temporary files**: pivota sobre la misma ruta `/tmp/...` a través de `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` y `execve` para identificar brechas de check/use.
- **Crash root cause**: correlaciona `mmap` de un archivo con escrituras o truncation del mismo inode/ruta por otro proceso, y luego inspecciona la secuencia de signal/exit para `SIGBUS`.
- **Network destination recovery**: filtra `connect`, `sendto`, `sendmsg`, `recvfrom` y argumentos relacionados con sockets para extraer IPs y puertos de peers.

### LLM-assisted trace analysis

If you want an LLM to assist, expose a **read-only** SQLite handle and give it the full schema. Let it issue raw SQL instead of wrapping the database behind narrow helper functions. This usually works better for joins, temporal correlation, and FTS lookups.

Practical rules:

- Keep the database read-only, for example with `sqlite3 'file:trace.db?mode=ro'`.
- Give the model examples of valid `JOIN` and `FTS5 MATCH` queries.
- Do **not** paste raw multi-GB `strace` logs into the prompt.
- Ask focused questions such as:
- "List persistent files written by this program."
- "Did it create or replace executables in user-controlled PATH directories?"
- "Explain why this trace ends in SIGBUS."

## Inspect Autostart locations

### Scheduled Tasks
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
#### Hunt: abuso de Cron/Anacron mediante 0anacron y stubs sospechosos
Los atacantes a menudo editan el stub 0anacron presente en cada directorio /etc/cron.*/ para asegurar la ejecución periódica.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Caza: rollback de hardening de SSH y shells backdoor
Los cambios en sshd_config y en los shells de cuentas del sistema son comunes tras la explotación para preservar el acceso.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: marcadores de Cloud C2 (Dropbox/Cloudflare Tunnel)
- Los beacons de la API de Dropbox normalmente usan api.dropboxapi.com o content.dropboxapi.com sobre HTTPS con tokens Authorization: Bearer.
- Busca en proxy/Zeek/NetFlow tráfico saliente inesperado de Dropbox desde servidores.
- Cloudflare Tunnel (`cloudflared`) proporciona C2 de respaldo sobre outbound 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Rutas donde un malware podría instalarse como un service:

- **/etc/inittab**: Llama scripts de inicialización como rc.sysinit, redirigiendo después a otros startup scripts.
- **/etc/rc.d/** y **/etc/rc.boot/**: Contienen scripts para el inicio de services, siendo el segundo encontrado en versiones antiguas de Linux.
- **/etc/init.d/**: Usado en ciertas versiones de Linux como Debian para almacenar startup scripts.
- Los services también pueden activarse mediante **/etc/inetd.conf** o **/etc/xinetd/**, dependiendo de la variante de Linux.
- **/etc/systemd/system**: Un directorio para scripts del system y service manager.
- **/etc/systemd/system/multi-user.target.wants/**: Contiene enlaces a services que deben iniciarse en un runlevel multi-user.
- **/usr/local/etc/rc.d/**: Para services personalizados o de terceros.
- **\~/.config/autostart/**: Para aplicaciones de automatic startup específicas de un usuario, lo que puede ser un hiding spot para malware dirigido al usuario.
- **/lib/systemd/system/**: Archivos unit por defecto a nivel de system proporcionados por los paquetes instalados.

#### Hunt: systemd timers and transient units

La persistence en Systemd no se limita a archivos `.service`. Investiga units `.timer`, units a nivel de user y **transient units** creadas en runtime.
```bash
# Enumerate timers and inspect referenced services
systemctl list-timers --all
systemctl cat <name>.timer
systemctl cat <name>.service

# Search common system and user paths
find /etc/systemd/system /run/systemd/system /usr/lib/systemd/system -maxdepth 3 \( -name '*.service' -o -name '*.timer' \) -ls
find /home -path '*/.config/systemd/user/*' -type f \( -name '*.service' -o -name '*.timer' \) -ls

# Transient units created via systemd-run often land here
find /run/systemd/transient -maxdepth 2 -type f -ls 2>/dev/null

# Pull execution history for a suspicious unit
journalctl -u <name>.service
journalctl _SYSTEMD_UNIT=<name>.service
```
Transient units are easy to miss because `/run/systemd/transient/` is **non-persistent**. If you are collecting a live image, grab it before shutdown.

### Kernel Modules

Los módulos del kernel de Linux, a menudo utilizados por malware como componentes de rootkit, se cargan al arrancar el sistema. Los directorios y archivos críticos para estos módulos incluyen:

- **/lib/modules/$(uname -r)**: Contiene módulos para la versión del kernel en ejecución.
- **/etc/modprobe.d**: Contiene archivos de configuración para controlar la carga de módulos.
- **/etc/modprobe** and **/etc/modprobe.conf**: Archivos para configuraciones globales de módulos.

### Other Autostart Locations

Linux emplea varios archivos para ejecutar programas automáticamente al iniciar sesión un usuario, lo que potencialmente puede ocultar malware:

- **/etc/profile.d/**\*, **/etc/profile**, and **/etc/bash.bashrc**: Se ejecutan para cualquier inicio de sesión de usuario.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, and **\~/.config/autostart**: Archivos específicos de usuario que se ejecutan al iniciar sesión.
- **/etc/rc.local**: Se ejecuta después de que todos los servicios del sistema han iniciado, marcando el final de la transición a un entorno multiusuario.

## Examine Logs

Los sistemas Linux registran actividades de usuario y eventos del sistema a través de varios archivos de log. Estos logs son fundamentales para identificar accesos no autorizados, infecciones de malware y otros incidentes de seguridad. Los archivos de log clave incluyen:

- **/var/log/syslog** (Debian) or **/var/log/messages** (RedHat): Capturan mensajes y actividades de todo el sistema.
- **/var/log/auth.log** (Debian) or **/var/log/secure** (RedHat): Registran intentos de autenticación, inicios de sesión exitosos y fallidos.
- Use `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` to filter relevant authentication events.
- **/var/log/boot.log**: Contiene mensajes de inicio del sistema.
- **/var/log/maillog** or **/var/log/mail.log**: Registra actividades del servidor de correo, útil para rastrear servicios relacionados con email.
- **/var/log/kern.log**: Almacena mensajes del kernel, incluidos errores y advertencias.
- **/var/log/dmesg**: Contiene mensajes de controladores de dispositivos.
- **/var/log/faillog**: Registra intentos fallidos de inicio de sesión, ayudando en investigaciones de brechas de seguridad.
- **/var/log/cron**: Registra ejecuciones de cron jobs.
- **/var/log/daemon.log**: Rastrea actividades de servicios en segundo plano.
- **/var/log/btmp**: Documenta intentos fallidos de inicio de sesión.
- **/var/log/httpd/**: Contiene logs de error y acceso de Apache HTTPD.
- **/var/log/mysqld.log** or **/var/log/mysql.log**: Registra actividades de la base de datos MySQL.
- **/var/log/xferlog**: Registra transferencias de archivos FTP.
- **/var/log/**: Siempre revisa aquí en busca de logs inesperados.

> [!TIP]
> Los logs del sistema Linux y los subsistemas de auditoría pueden estar deshabilitados o eliminados en un incidente de intrusión o malware. Como los logs en sistemas Linux generalmente contienen parte de la información más útil sobre actividades maliciosas, los intrusos suelen eliminarlos. Por ello, al examinar los archivos de log disponibles, es importante buscar huecos o entradas fuera de orden que puedan indicar eliminación o manipulación.

### Journald triage (`journalctl`)

En hosts Linux modernos, el **systemd journal** suele ser la fuente de mayor valor para **service execution**, **auth events**, **package operations** y **kernel/user-space messages**. Durante una respuesta en vivo, intenta preservar tanto el journal **persistent** (`/var/log/journal/`) como el journal de **runtime** (`/run/log/journal/`), porque la actividad de un atacante de corta duración puede existir solo en el segundo.
```bash
# List available boots and pivot around the suspicious one
journalctl --list-boots
journalctl -b -1

# Review a mounted image or copied journal directory offline
journalctl --directory /mnt/image/var/log/journal --list-boots
journalctl --directory /mnt/image/var/log/journal -b -1

# Inspect a single journal file and check integrity/corruption
journalctl --file system.journal --header
journalctl --file system.journal --verify

# High-signal filters
journalctl -u ssh.service
journalctl _SYSTEMD_UNIT=cron.service
journalctl _UID=0
journalctl _EXE=/usr/sbin/useradd
```
Los campos útiles de journal para el triage incluyen `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, y `MESSAGE`. Si `journald` fue configurado sin almacenamiento persistente, espera solo datos recientes en `/run/log/journal/`.

### Triage del framework de auditoría (`auditd`)

Si `auditd` está habilitado, prefierelo siempre que necesites **atribución de proceso** para cambios en archivos, ejecución de comandos, actividad de inicio de sesión o instalación de paquetes.
```bash
# Fast summaries
aureport --start today --summary -i
aureport --start today --login --failed -i
aureport --start today --executable -i

# Search raw events
ausearch --start today -m EXECVE -i
ausearch --start today -ua 1000 -m USER_CMD,EXECVE -i
ausearch --start today -m SERVICE_START,SERVICE_STOP -i

# Software installation/update events (especially useful on RHEL-like systems)
ausearch -m SOFTWARE_UPDATE -i
```
Cuando las reglas se desplegaron con keys, pivota desde ellas en lugar de hacer grep en logs en bruto:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux mantiene un historial de comandos para cada usuario**, almacenado en:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Además, el comando `last -Faiwx` proporciona una lista de inicios de sesión de usuarios. Revísalo en busca de inicios de sesión desconocidos o inesperados.

Revisa archivos que pueden conceder privilegios extra:

- Revisa `/etc/sudoers` en busca de privilegios de usuario no previstos que hayan sido concedidos.
- Revisa `/etc/sudoers.d/` en busca de privilegios de usuario no previstos que hayan sido concedidos.
- Examina `/etc/groups` para identificar membresías de grupo o permisos inusuales.
- Examina `/etc/passwd` para identificar membresías de grupo o permisos inusuales.

Algunas apps también generan sus propios logs:

- **SSH**: Examina _\~/.ssh/authorized_keys_ y _\~/.ssh/known_hosts_ para conexiones remotas no autorizadas.
- **Gnome Desktop**: Revisa _\~/.recently-used.xbel_ para archivos accedidos recientemente mediante aplicaciones de Gnome.
- **Firefox/Chrome**: Comprueba el historial del navegador y las descargas en _\~/.mozilla/firefox_ o _\~/.config/google-chrome_ en busca de actividades sospechosas.
- **VIM**: Revisa _\~/.viminfo_ para detalles de uso, como rutas de archivos accedidos e historial de búsquedas.
- **Open Office**: Comprueba el acceso reciente a documentos que podría indicar archivos comprometidos.
- **FTP/SFTP**: Revisa los logs en _\~/.ftp_history_ o _\~/.sftp_history_ para transferencias de archivos que podrían no estar autorizadas.
- **MySQL**: Investiga _\~/.mysql_history_ para consultas MySQL ejecutadas, revelando potencialmente actividades no autorizadas en la base de datos.
- **Less**: Analiza _\~/.lesshst_ para el historial de uso, incluidos los archivos vistos y los comandos ejecutados.
- **Git**: Examina _\~/.gitconfig_ y _.git/logs_ del proyecto para cambios en los repositorios.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) es una pequeña pieza de software escrita en Python 3 puro que analiza archivos de log de Linux (`/var/log/syslog*` o `/var/log/messages*` según la distro) para construir tablas de historial de eventos USB.

Es interesante **conocer todos los USB que se han usado** y será más útil si tienes una lista autorizada de USB para encontrar "violation events" (el uso de USB que no están dentro de esa lista).

### Installation
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Ejemplos
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Más ejemplos e información dentro de github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Revisar cuentas de usuario y actividades de inicio de sesión

Examina _**/etc/passwd**_, _**/etc/shadow**_ y los **security logs** en busca de nombres inusuales o cuentas creadas y/o usadas en proximidad cercana a eventos conocidos no autorizados. Además, comprueba posibles ataques de fuerza bruta de sudo.\
Asimismo, revisa archivos como _**/etc/sudoers**_ y _**/etc/groups**_ en busca de privilegios inesperados concedidos a usuarios.\
Por último, busca cuentas con **no passwords** o contraseñas **fácilmente adivinables**.

## Examinar el sistema de archivos

### Analizando las estructuras del sistema de archivos en la investigación de malware

Al investigar incidentes de malware, la estructura del sistema de archivos es una fuente crucial de información, ya que revela tanto la secuencia de eventos como el contenido del malware. Sin embargo, los autores de malware están desarrollando técnicas para dificultar este análisis, como modificar las marcas de tiempo de los archivos o evitar el sistema de archivos para el almacenamiento de datos.

Para contrarrestar estos métodos anti-forenses, es esencial:

- **Realizar un análisis exhaustivo de la línea de tiempo** usando herramientas como **Autopsy** para visualizar líneas de tiempo de eventos o **Sleuth Kit's** `mactime` para datos detallados de línea de tiempo.
- **Investigar scripts inesperados** en el $PATH del sistema, que podrían incluir scripts shell o PHP usados por atacantes.
- **Examinar `/dev` en busca de archivos atípicos**, ya que tradicionalmente contiene archivos especiales, pero puede albergar archivos relacionados con malware.
- **Buscar archivos o directorios ocultos** con nombres como ".. " (punto punto espacio) o "..^G" (punto punto control-G), que podrían ocultar contenido malicioso.
- **Identificar archivos setuid root** usando el comando: `find / -user root -perm -04000 -print` Esto encuentra archivos con permisos elevados, que podrían ser aprovechados por atacantes.
- **Revisar marcas de tiempo de eliminación** en tablas de inodos para detectar eliminaciones masivas de archivos, lo que podría indicar la presencia de rootkits o trojans.
- **Inspeccionar inodos consecutivos** en busca de archivos maliciosos cercanos después de identificar uno, ya que podrían haber sido colocados juntos.
- **Comprobar directorios binarios comunes** (_/bin_, _/sbin_) en busca de archivos modificados recientemente, ya que podrían haber sido alterados por malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Ten en cuenta que un **atacante** puede **modificar** el **tiempo** para hacer que los **archivos parezcan** **legítimos**, pero **no puede** modificar el **inode**. Si encuentras que un **archivo** indica que fue creado y modificado al **mismo tiempo** que el resto de los archivos en la misma carpeta, pero el **inode** es **inesperadamente más grande**, entonces los **timestamps de ese archivo fueron modificados**.

### Triage rápido centrado en inode

Si sospechas de anti-forensics, ejecuta pronto estas comprobaciones centradas en inode:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Cuando un inode sospechoso está en una imagen/dispositivo de sistema de archivos EXT, inspecciona directamente los metadatos del inode:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Campos útiles:
- **Links**: si `0`, ninguna entrada de directorio referencia actualmente al inode.
- **dtime**: marca de tiempo de eliminación establecida cuando el inode fue desvinculado.
- **ctime/mtime**: ayuda a correlacionar cambios de metadatos/contenido con la línea de tiempo del incidente.

### Capabilities, xattrs, and rootkits de userland basados en preload

La persistencia moderna en Linux a menudo evita los binarios obvios `setuid` y, en su lugar, abusa de **file capabilities**, **extended attributes** y el cargador dinámico.
```bash
# Enumerate file capabilities (think cap_setuid, cap_sys_admin, cap_dac_override)
getcap -r / 2>/dev/null

# Inspect extended attributes on suspicious binaries and libraries
getfattr -d -m - /path/to/suspicious/file 2>/dev/null

# Global preload hook affecting every dynamically linked binary
cat /etc/ld.so.preload 2>/dev/null
stat /etc/ld.so.preload 2>/dev/null

# If a suspicious library is referenced, inspect its metadata and links
ls -lah /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib 2>/dev/null | grep -E '\\.so(\\.|$)'
ldd /bin/ls
```
Presta especial atención a las bibliotecas referenciadas desde rutas **escribibles** como `/tmp`, `/dev/shm`, `/var/tmp` o ubicaciones extrañas bajo `/usr/local/lib`. También comprueba binarios con capabilities fuera de la propiedad normal de paquetes y correlaciónalos con los resultados de verificación de paquetes (`rpm -Va`, `dpkg --verify`, `debsums`).

## Compare files of different filesystem versions

### Filesystem Version Comparison Summary

Para comparar versiones del filesystem e identificar cambios, usamos comandos simplificados de `git diff`:

- **Para encontrar archivos nuevos**, compara dos directorios:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Para contenido modificado**, lista los cambios mientras ignoras líneas específicas:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Para detectar archivos eliminados**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Opciones de filtro** (`--diff-filter`) ayudan a acotar cambios específicos como archivos añadidos (`A`), eliminados (`D`) o modificados (`M`).
- `A`: Archivos añadidos
- `C`: Archivos copiados
- `D`: Archivos eliminados
- `M`: Archivos modificados
- `R`: Archivos renombrados
- `T`: Cambios de tipo (p. ej., archivo a symlink)
- `U`: Archivos sin fusionar
- `X`: Archivos desconocidos
- `B`: Archivos rotos

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [Say hi to Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [strace](https://strace.io/)
- [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
