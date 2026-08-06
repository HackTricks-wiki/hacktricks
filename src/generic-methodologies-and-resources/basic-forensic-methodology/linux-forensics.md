# Análisis forense de Linux

{{#include ../../banners/hacktricks-training.md}}

## Recopilación inicial de información

### Información básica

En primer lugar, se recomienda tener algún **USB** con **binaries y libraries de confianza** (puedes obtener Ubuntu y copiar las carpetas _/bin_, _/sbin_, _/lib,_ y _/lib64_), luego montar el USB y modificar las variables de entorno para utilizar esos binaries:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Una vez que hayas configurado el sistema para utilizar binarios fiables y conocidos, puedes comenzar a **extraer información básica**:
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

Mientras obtienes la información básica, deberías comprobar si hay cosas extrañas como:

- Los procesos de **root** normalmente se ejecutan con PIDS bajos, por lo que si encuentras un proceso de root con un PID alto, puedes sospechar
- Comprueba los **inicios de sesión registrados** de usuarios sin una shell dentro de `/etc/passwd`
- Comprueba si hay **hashes de contraseñas** dentro de `/etc/shadow` para usuarios sin una shell

### Volcado de memoria

Para obtener la memoria del sistema en ejecución, se recomienda usar [**LiME**](https://github.com/504ensicsLabs/LiME).\
Para **compilarlo**, necesitas usar el **mismo kernel** que utiliza la máquina víctima.

> [!TIP]
> Recuerda que **no puedes instalar LiME ni ninguna otra cosa** en la máquina víctima, ya que esto realizará varios cambios en ella

Por lo tanto, si tienes una versión idéntica de Ubuntu, puedes usar `apt-get install lime-forensics-dkms`\
En otros casos, necesitas descargar [**LiME**](https://github.com/504ensicsLabs/LiME) desde github y compilarlo con los headers correctos del kernel. Para **obtener los headers exactos del kernel** de la máquina víctima, simplemente puedes **copiar el directorio** `/lib/modules/<kernel version>` a tu máquina y, a continuación, **compilar** LiME utilizándolos:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME admite 3 **formatos**:

- Raw (cada segmento concatenado)
- Padded (igual que raw, pero con ceros en los bits derechos)
- Lime (formato recomendado con metadatos

LiME también puede utilizarse para **enviar el volcado a través de la red** en lugar de almacenarlo en el sistema usando algo como: `path=tcp:4444`

### Adquisición de una imagen de disco

#### Apagado

En primer lugar, tendrás que **apagar el sistema**. Esto no siempre es una opción, ya que a veces el sistema será un servidor de producción que la empresa no puede permitirse apagar.\
Hay **2 formas** de apagar el sistema: un **apagado normal** y un **apagado de "desconectar el enchufe"**. El primero permitirá que los **procesos finalicen como de costumbre** y que el **sistema de archivos** se **sincronice**, pero también permitirá que el posible **malware** **destruya pruebas**. El método de "desconectar el enchufe" puede provocar **cierta pérdida de información** (no se perderá mucha información, ya que ya hemos obtenido una imagen de la memoria) y el **malware no tendrá ninguna oportunidad** de hacer nada al respecto. Por lo tanto, si **sospechas** que puede haber **malware**, simplemente ejecuta el **comando** **`sync`** en el sistema y desconecta el enchufe.

#### Creación de una imagen del disco

Es importante tener en cuenta que **antes de conectar tu ordenador a cualquier elemento relacionado con el caso**, debes asegurarte de que se va a **montar como solo lectura** para evitar modificar cualquier información.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Preanálisis de la imagen de disco

Creación de una imagen de disco sin más datos.
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
## Buscar Malware conocido

### Archivos del sistema modificados

Linux ofrece herramientas para garantizar la integridad de los componentes del sistema, algo crucial para detectar archivos potencialmente problemáticos.<sup>[[1]](#references)</sup>

- **Sistemas basados en RedHat**: Usa `rpm -Va` para realizar una comprobación exhaustiva.
- **Sistemas basados en Debian**: Usa `dpkg --verify` para una verificación inicial, seguida de `debsums | grep -v "OK$"` (después de instalar `debsums` con `apt-get install debsums`) para identificar posibles problemas.

### Detectores de Malware/Rootkit

Lee la siguiente página para obtener información sobre herramientas que pueden ser útiles para encontrar Malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Buscar programas instalados

Para buscar eficazmente programas instalados en sistemas Debian y RedHat, considera aprovechar los logs y las bases de datos del sistema, junto con comprobaciones manuales en directorios comunes.<sup>[[1]](#references)</sup>

- En Debian, inspecciona _**`/var/lib/dpkg/status`**_ y _**`/var/log/dpkg.log`**_ para obtener detalles sobre las instalaciones de paquetes, usando `grep` para filtrar información específica.
- Los usuarios de RedHat pueden consultar la base de datos de RPM con `rpm -qa --root=/mntpath/var/lib/rpm` para enumerar los paquetes instalados.

Para descubrir software instalado manualmente o fuera de estos gestores de paquetes, explora directorios como _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ y _**`/sbin`**_. Combina los listados de directorios con comandos específicos del sistema para identificar ejecutables que no estén asociados a paquetes conocidos, mejorando tu búsqueda de todos los programas instalados.
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

Imagina un proceso que se ejecutó desde /tmp/exec y luego se eliminó. Es posible extraerlo
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Triage de Syscall Trace con SQLite y FTS5

Cuando un proceso todavía está en ejecución o se puede volver a ejecutar en un lab, **`strace`** puede proporcionar un trace de comportamiento rápido sin necesidad de módulos del kernel ni de la telemetría completa de EDR. Para traces grandes, evita leer directamente el log sin procesar o pegarlo en un **LLM**: guárdalo en una base de datos **SQLite** y consulta únicamente el subconjunto mínimo que necesites.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> Adjuntar `strace` cambia el timing del proceso y puede afectar a race conditions u otros bugs frágiles. Cuando sea posible, prioriza reproducirlo en una copia o sistema de lab.

### Captura

Para un proceso nuevo:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Para un proceso en ejecución:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Opciones útiles:

- `-ff`: seguir forks/hilos y mantener salidas por proceso
- `-ttt`: timestamps de epoch para facilitar la correlación de la línea temporal
- `-yy`: resolver descriptores de archivo a rutas/sockets subyacentes cuando sea posible
- `-s 4096`: evitar que se trunquen las rutas largas y los argumentos de buffer

### Normalizar

Un esquema práctico consiste en una fila por syscall y una fila por argumento:
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
Esto evita intentar aplanar líneas heterogéneas de syscalls en una única tabla ancha y mantiene las uniones predecibles durante el triage.

### Indexa los argumentos con mucho texto con FTS5

La búsqueda ingenua de rutas con `LIKE "%...%"` se vuelve muy lenta en traces grandes. Crea un índice FTS5 para el texto de los argumentos y realiza la búsqueda en él:
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

- **PATH hijacking / fake sudo**: busca escrituras y actividad de `chmod`/`rename` en `~/.local/bin/`, y luego correlaciónala con ejecuciones posteriores de nombres con apariencia privilegiada, como `sudo`.
- **TOCTOU en archivos temporales**: sigue la misma ruta `/tmp/...` mediante `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` y `execve` para identificar brechas entre la comprobación y el uso.
- **Causa raíz del crash**: correlaciona el `mmap` de un archivo con escrituras o truncamientos del mismo inode/ruta por otro proceso; después, inspecciona la secuencia de señales/salidas en busca de `SIGBUS`.
- **Recuperación del destino de red**: filtra `connect`, `sendto`, `sendmsg`, `recvfrom` y los argumentos relacionados con sockets para extraer las IP y los puertos del par.

### Análisis de traces asistido por LLM

Si quieres que un LLM te ayude, expón un handle de SQLite de **solo lectura** y proporciónale el esquema completo. Permítele emitir SQL sin procesar en lugar de envolver la base de datos con funciones auxiliares limitadas. Esto suele funcionar mejor para `JOIN`, la correlación temporal y las búsquedas FTS.

Reglas prácticas:

- Mantén la base de datos en modo de solo lectura, por ejemplo con `sqlite3 'file:trace.db?mode=ro'`.
- Proporciona al modelo ejemplos de consultas válidas con `JOIN` y `FTS5 MATCH`.
- **No** pegues logs sin procesar de `strace` de varios GB en el prompt.
- Haz preguntas concretas, como:
- "Enumera los archivos persistentes escritos por este programa."
- "¿Creó o reemplazó ejecutables en directorios del PATH controlados por el usuario?"
- "Explica por qué este trace termina en SIGBUS."

## Inspeccionar las ubicaciones de inicio automático

### Tareas programadas
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
Los atacantes suelen editar el stub 0anacron presente en cada directorio /etc/cron.*/ para garantizar la ejecución periódica.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: Reversión del hardening de SSH y shells backdoor
Los cambios en `sshd_config` y en los shells de las cuentas del sistema son comunes durante el post-exploitation para preservar el acceso.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: marcadores de Cloud C2 (Dropbox/Cloudflare Tunnel)
- Los beacons de Dropbox API suelen usar api.dropboxapi.com o content.dropboxapi.com mediante HTTPS con tokens Authorization: Bearer.
- Busca tráfico de salida inesperado hacia Dropbox desde servidores en proxy/Zeek/NetFlow.
- Cloudflare Tunnel (`cloudflared`) proporciona un C2 de respaldo mediante conexiones salientes por 443.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Servicios

Rutas donde un malware podría instalarse como servicio:

- **/etc/inittab**: Llama a scripts de inicialización como rc.sysinit, que dirigen posteriormente a los scripts de inicio.
- **/etc/rc.d/** y **/etc/rc.boot/**: Contienen scripts para el inicio de servicios; el segundo se encuentra en versiones antiguas de Linux.
- **/etc/init.d/**: Se utiliza en ciertas versiones de Linux, como Debian, para almacenar scripts de inicio.
- Los servicios también pueden activarse mediante **/etc/inetd.conf** o **/etc/xinetd/**, según la variante de Linux.
- **/etc/systemd/system**: Directorio para scripts del gestor del sistema y de servicios.
- **/etc/systemd/system/multi-user.target.wants/**: Contiene enlaces a servicios que deben iniciarse en un nivel de ejecución multiusuario.
- **/usr/local/etc/rc.d/**: Para servicios personalizados o de terceros.
- **\~/.config/autostart/**: Para aplicaciones de inicio automático específicas del usuario; puede ser un lugar donde ocultar malware dirigido a usuarios.
- **/lib/systemd/system/**: Archivos de unidad predeterminados de todo el sistema proporcionados por los paquetes instalados.

#### Búsqueda: systemd timers y transient units

La persistencia de Systemd no se limita a los archivos `.service`. Investiga las unidades `.timer`, las unidades a nivel de usuario y las **transient units** creadas en tiempo de ejecución.
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
Las unidades transitorias son fáciles de pasar por alto porque `/run/systemd/transient/` es **no persistente**. Si estás recopilando una imagen en vivo, cópialo antes del apagado.

### Módulos del kernel

Los módulos del kernel de Linux, utilizados con frecuencia por el malware como componentes de rootkit, se cargan durante el arranque del sistema. Los directorios y archivos críticos para estos módulos incluyen:

- **/lib/modules/$(uname -r)**: Contiene los módulos correspondientes a la versión del kernel en ejecución.
- **/etc/modprobe.d**: Contiene archivos de configuración para controlar la carga de módulos.
- **/etc/modprobe** y **/etc/modprobe.conf**: Archivos para la configuración global de los módulos.

### Otras ubicaciones de Autostart

Linux utiliza varios archivos para ejecutar programas automáticamente cuando un usuario inicia sesión, que potencialmente pueden contener malware:

- **/etc/profile.d/**\*, **/etc/profile** y **/etc/bash.bashrc**: Se ejecutan cuando inicia sesión cualquier usuario.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile** y **~/.config/autostart**: Archivos específicos del usuario que se ejecutan cuando este inicia sesión.
- **/etc/rc.local**: Se ejecuta después de que se hayan iniciado todos los servicios del sistema, marcando el final de la transición a un entorno multiusuario.

## Examinar logs

Los sistemas Linux registran las actividades de los usuarios y los eventos del sistema mediante diversos archivos de log. Estos logs son fundamentales para identificar accesos no autorizados, infecciones de malware y otros incidentes de seguridad.<sup>[[2]](#references)</sup> Entre los archivos de log clave se incluyen:

- **/var/log/syslog** (Debian) o **/var/log/messages** (RedHat): Capturan mensajes y actividades de todo el sistema.
- **/var/log/auth.log** (Debian) o **/var/log/secure** (RedHat): Registran intentos de autenticación e inicios de sesión correctos y fallidos.
- Utiliza `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` para filtrar eventos de autenticación relevantes.
- **/var/log/boot.log**: Contiene mensajes del arranque del sistema.
- **/var/log/maillog** o **/var/log/mail.log**: Registran las actividades del servidor de correo, lo que resulta útil para rastrear servicios relacionados con el correo electrónico.
- **/var/log/kern.log**: Almacena mensajes del kernel, incluidos errores y advertencias.
- **/var/log/dmesg**: Contiene mensajes de los controladores de dispositivos.
- **/var/log/faillog**: Registra intentos de inicio de sesión fallidos, lo que ayuda en las investigaciones de brechas de seguridad.
- **/var/log/cron**: Registra las ejecuciones de tareas cron.
- **/var/log/daemon.log**: Rastrea las actividades de los servicios en segundo plano.
- **/var/log/btmp**: Documenta los intentos de inicio de sesión fallidos.
- **/var/log/httpd/**: Contiene los logs de error y acceso de Apache HTTPD.
- **/var/log/mysqld.log** o **/var/log/mysql.log**: Registran las actividades de la base de datos MySQL.
- **/var/log/xferlog**: Registra las transferencias de archivos FTP.
- **/var/log/**: Comprueba siempre si existen logs inesperados aquí.

> [!TIP]
> Los logs del sistema Linux y los subsistemas de auditoría pueden estar deshabilitados o haber sido eliminados durante una intrusión o un incidente de malware. Dado que los logs de los sistemas Linux generalmente contienen parte de la información más útil sobre actividades maliciosas, los intrusos los eliminan habitualmente. Por lo tanto, al examinar los archivos de log disponibles, es importante buscar brechas o entradas desordenadas que puedan indicar una eliminación o manipulación.

### Triage de Journald (`journalctl`)

En los hosts Linux modernos, el **journal de systemd** suele ser la fuente de mayor valor para la **ejecución de servicios**, los **eventos de autenticación**, las **operaciones de paquetes** y los **mensajes del kernel y del espacio de usuario**. Durante la respuesta en vivo, intenta preservar tanto el journal **persistente** (`/var/log/journal/`) como el journal **de ejecución** (`/run/log/journal/`), ya que la actividad de un atacante de corta duración podría existir únicamente en este último.<sup>[[5]](#references)</sup>
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
Los campos útiles de journal para el triage incluyen `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` y `MESSAGE`. Si journald se configuró sin almacenamiento persistente, espera encontrar únicamente datos recientes en `/run/log/journal/`.

### Triage del framework de auditoría (`auditd`)

Si `auditd` está habilitado, priorízalo siempre que necesites **atribución de procesos** para cambios en archivos, ejecución de comandos, actividad de inicio de sesión o instalación de paquetes.<sup>[[6]](#references)</sup>
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
Cuando las reglas se desplegaron con claves, pivota a partir de ellas en lugar de hacer grep en los logs sin procesar:
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

Además, el comando `last -Faiwx` proporciona una lista de inicios de sesión de los usuarios. Revísala para detectar inicios de sesión desconocidos o inesperados.

Revisa los archivos que pueden conceder privilegios adicionales:

- Revisa `/etc/sudoers` en busca de privilegios de usuario no previstos que puedan haberse concedido.
- Revisa `/etc/sudoers.d/` en busca de privilegios de usuario no previstos que puedan haberse concedido.
- Examina `/etc/groups` para identificar membresías de grupos o permisos inusuales.
- Examina `/etc/passwd` para identificar membresías de grupos o permisos inusuales.

Algunas aplicaciones también generan sus propios logs:

- **SSH**: Examina _\~/.ssh/authorized_keys_ y _\~/.ssh/known_hosts_ en busca de conexiones remotas no autorizadas.
- **Gnome Desktop**: Revisa _\~/.recently-used.xbel_ para consultar los archivos a los que se ha accedido recientemente mediante aplicaciones de Gnome.
- **Firefox/Chrome**: Comprueba el historial y las descargas del navegador en _\~/.mozilla/firefox_ o _\~/.config/google-chrome_ en busca de actividades sospechosas.
- **VIM**: Revisa _\~/.viminfo_ para obtener detalles de uso, como rutas de archivos accedidas e historial de búsquedas.
- **Open Office**: Comprueba el acceso reciente a documentos que pueda indicar archivos comprometidos.
- **FTP/SFTP**: Revisa los logs en _\~/.ftp_history_ o _\~/.sftp_history_ para detectar transferencias de archivos que puedan ser no autorizadas.
- **MySQL**: Investiga _\~/.mysql_history_ en busca de consultas de MySQL ejecutadas, que podrían revelar actividades no autorizadas en la base de datos.
- **Less**: Analiza _\~/.lesshst_ para consultar el historial de uso, incluidos los archivos visualizados y los comandos ejecutados.
- **Git**: Examina _\~/.gitconfig_ y _.git/logs_ del proyecto en busca de cambios en los repositorios.

### Logs de USB

[**usbrip**](https://github.com/snovvcrash/usbrip) es un pequeño software escrito íntegramente en Python 3 que analiza los archivos de log de Linux (`/var/log/syslog*` o `/var/log/messages*`, según la distro) para crear tablas del historial de eventos USB.

Es interesante **conocer todos los USB que se han utilizado** y será más útil si tienes una lista autorizada de USB para encontrar "eventos de violación" (el uso de USB que no están incluidos en esa lista).

### Instalación
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
Más ejemplos e información dentro del github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Revisar las cuentas de usuario y las actividades de inicio de sesión

Examine _**/etc/passwd**_, _**/etc/shadow**_ y los **security logs** en busca de nombres o cuentas inusuales creados o utilizados cerca de eventos no autorizados conocidos. Además, compruebe posibles ataques de fuerza bruta contra sudo.\
Asimismo, revise archivos como _**/etc/sudoers**_ y _**/etc/groups**_ en busca de privilegios inesperados otorgados a usuarios.\
Por último, busque cuentas **sin contraseñas** o con contraseñas **fáciles de adivinar**.<sup>[[1]](#references)</sup>

## Examinar el sistema de archivos

### Analizar las estructuras del sistema de archivos en una investigación de malware

Al investigar incidentes de malware, la estructura del sistema de archivos es una fuente crucial de información, ya que revela tanto la secuencia de eventos como el contenido del malware. Sin embargo, los autores de malware están desarrollando técnicas para dificultar este análisis, como modificar las marcas de tiempo de los archivos o evitar el sistema de archivos para almacenar datos.<sup>[[1]](#references)</sup>

Para contrarrestar estos métodos anti-forensics, es esencial:

- **Realizar un análisis exhaustivo de la línea temporal** utilizando herramientas como **Autopsy** para visualizar las líneas temporales de eventos o `mactime` de **Sleuth Kit** para obtener datos detallados de la línea temporal.
- **Investigar scripts inesperados** en el $PATH del sistema, que podrían incluir scripts de shell o PHP utilizados por atacantes.
- **Examinar `/dev` en busca de archivos atípicos**, ya que tradicionalmente contiene archivos especiales, pero podría albergar archivos relacionados con malware.
- **Buscar archivos o directorios ocultos** con nombres como ".. " (dos puntos y un espacio) o "..^G" (dos puntos y control-G), que podrían ocultar contenido malicioso.
- **Identificar archivos setuid root** utilizando el comando: `find / -user root -perm -04000 -print` Esto encuentra archivos con permisos elevados, que podrían ser abusados por atacantes.
- **Revisar las marcas de tiempo de eliminación** en las tablas de inodos para detectar eliminaciones masivas de archivos, lo que posiblemente indique la presencia de rootkits o troyanos.
- **Inspeccionar los inodos consecutivos** en busca de archivos maliciosos cercanos después de identificar uno, ya que podrían haber sido colocados juntos.
- **Comprobar los directorios binarios comunes** (_/bin_, _/sbin_) en busca de archivos modificados recientemente, ya que podrían haber sido alterados por malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Ten en cuenta que un **atacante** puede **modificar** la **hora** para hacer que los **archivos parezcan** **legítimos**, pero no puede modificar el **inode**. Si encuentras que un **archivo** indica que fue creado y modificado al **mismo tiempo** que el resto de los archivos de la misma carpeta, pero el **inode** es **inesperadamente mayor**, entonces las **marcas de tiempo** de ese archivo fueron modificadas.

### Triage rápida centrada en el inode

Si sospechas de anti-forensics, ejecuta estas comprobaciones centradas en el inode al principio:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Cuando un inode sospechoso se encuentra en una imagen/dispositivo de un sistema de archivos EXT, inspecciona directamente los metadatos del inode:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Campos útiles:
- **Links**: si es `0`, ninguna entrada de directorio referencia actualmente al inode.
- **dtime**: marca de tiempo de eliminación establecida cuando se desvinculó el inode.
- **ctime/mtime**: ayuda a correlacionar los cambios de metadatos/contenido con la línea temporal del incidente.

### Capabilities, xattrs y rootkits de userland basados en preload

La persistencia moderna en Linux suele evitar los binarios `setuid` obvios y, en su lugar, abusa de las **file capabilities**, los **extended attributes** y el cargador dinámico.
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
Presta especial atención a las libraries referenciadas desde rutas **writable** como `/tmp`, `/dev/shm`, `/var/tmp` o ubicaciones inusuales bajo `/usr/local/lib`. Comprueba también si hay binaries con capabilities fuera de la propiedad normal de los paquetes y correlaciónalos con los resultados de verificación de paquetes (`rpm -Va`, `dpkg --verify`, `debsums`).

## Comparar archivos de diferentes versiones del filesystem

### Resumen de la comparación de versiones del filesystem

Para comparar versiones del filesystem y localizar cambios, usamos comandos simplificados de `git diff`:<sup>[[3]](#references)</sup>

- **Para encontrar archivos nuevos**, compara dos directorios:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Para el contenido modificado**, enumera los cambios ignorando líneas específicas:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Para detectar archivos eliminados**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- Las **opciones de filtrado** (`--diff-filter`) ayudan a limitar los resultados a cambios específicos, como archivos añadidos (`A`), eliminados (`D`) o modificados (`M`).
- `A`: Archivos añadidos
- `C`: Archivos copiados
- `D`: Archivos eliminados
- `M`: Archivos modificados
- `R`: Archivos renombrados
- `T`: Cambios de tipo (por ejemplo, de archivo a enlace simbólico)
- `U`: Archivos sin fusionar
- `X`: Archivos desconocidos
- `B`: Archivos dañados

## Referencias

- [1] [Guía de campo de análisis forense de malware para sistemas Linux: Guías de campo de análisis forense digital – Capítulo 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Explicación de los logs de Linux](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [Documentación de `git diff` – opción `--diff-filter`](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Aplicación de parches para la persistencia: cómo el malware DripDropper para Linux se mueve por la cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Análisis forense de los journals de Linux](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - Auditoría del sistema](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [¡Saluda a Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [Extensión SQLite FTS5](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
