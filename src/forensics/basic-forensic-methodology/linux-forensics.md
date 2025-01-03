# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Recolección Inicial de Información

### Información Básica

Primero que nada, se recomienda tener un **USB** con **binaries y bibliotecas bien conocidos** (puedes simplemente obtener ubuntu y copiar las carpetas _/bin_, _/sbin_, _/lib,_ y _/lib64_), luego monta el USB y modifica las variables de entorno para usar esos binaries:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Una vez que hayas configurado el sistema para usar binarios buenos y conocidos, puedes comenzar a **extraer información básica**:
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

Mientras obtienes la información básica, debes verificar cosas extrañas como:

- **Los procesos de root** generalmente se ejecutan con PIDS bajos, así que si encuentras un proceso de root con un PID grande, puedes sospechar.
- Verifica los **inicios de sesión registrados** de usuarios sin un shell dentro de `/etc/passwd`.
- Verifica los **hashes de contraseñas** dentro de `/etc/shadow` para usuarios sin un shell.

### Volcado de memoria

Para obtener la memoria del sistema en ejecución, se recomienda usar [**LiME**](https://github.com/504ensicsLabs/LiME).\
Para **compilarlo**, necesitas usar el **mismo kernel** que está utilizando la máquina víctima.

> [!NOTE]
> Recuerda que **no puedes instalar LiME ni nada más** en la máquina víctima, ya que hará varios cambios en ella.

Así que, si tienes una versión idéntica de Ubuntu, puedes usar `apt-get install lime-forensics-dkms`\
En otros casos, necesitas descargar [**LiME**](https://github.com/504ensicsLabs/LiME) de github y compilarlo con los encabezados de kernel correctos. Para **obtener los encabezados de kernel exactos** de la máquina víctima, puedes simplemente **copiar el directorio** `/lib/modules/<kernel version>` a tu máquina, y luego **compilar** LiME usándolos:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME soporta 3 **formatos**:

- Raw (cada segmento concatenado)
- Padded (igual que raw, pero con ceros en los bits de la derecha)
- Lime (formato recomendado con metadatos)

LiME también se puede usar para **enviar el volcado a través de la red** en lugar de almacenarlo en el sistema usando algo como: `path=tcp:4444`

### Imagen de disco

#### Apagado

Primero que nada, necesitarás **apagar el sistema**. Esto no siempre es una opción, ya que a veces el sistema será un servidor de producción que la empresa no puede permitirse apagar.\
Hay **2 maneras** de apagar el sistema, un **apagado normal** y un **apagado de "desenchufar"**. El primero permitirá que los **procesos se terminen como de costumbre** y que el **sistema de archivos** esté **sincronizado**, pero también permitirá que el posible **malware** **destruya evidencia**. El enfoque de "desenchufar" puede conllevar **alguna pérdida de información** (no se perderá mucha información ya que ya tomamos una imagen de la memoria) y el **malware no tendrá ninguna oportunidad** de hacer algo al respecto. Por lo tanto, si **sospechas** que puede haber un **malware**, simplemente ejecuta el **comando** **`sync`** en el sistema y desenchufa.

#### Tomando una imagen del disco

Es importante notar que **antes de conectar tu computadora a cualquier cosa relacionada con el caso**, necesitas asegurarte de que se va a **montar como solo lectura** para evitar modificar cualquier información.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Análisis previo de la imagen del disco

Imágenes de una imagen de disco sin más datos.
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

Linux ofrece herramientas para garantizar la integridad de los componentes del sistema, crucial para detectar archivos potencialmente problemáticos.

- **Sistemas basados en RedHat**: Use `rpm -Va` para una verificación completa.
- **Sistemas basados en Debian**: `dpkg --verify` para una verificación inicial, seguido de `debsums | grep -v "OK$"` (después de instalar `debsums` con `apt-get install debsums`) para identificar cualquier problema.

### Detectores de Malware/Rootkit

Lea la siguiente página para aprender sobre herramientas que pueden ser útiles para encontrar malware:

{{#ref}}
malware-analysis.md
{{#endref}}

## Buscar programas instalados

Para buscar de manera efectiva programas instalados en sistemas Debian y RedHat, considere aprovechar los registros del sistema y bases de datos junto con verificaciones manuales en directorios comunes.

- Para Debian, inspeccione _**`/var/lib/dpkg/status`**_ y _**`/var/log/dpkg.log`**_ para obtener detalles sobre las instalaciones de paquetes, utilizando `grep` para filtrar información específica.
- Los usuarios de RedHat pueden consultar la base de datos RPM con `rpm -qa --root=/mntpath/var/lib/rpm` para listar los paquetes instalados.

Para descubrir software instalado manualmente o fuera de estos gestores de paquetes, explore directorios como _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ y _**`/sbin`**_. Combine listados de directorios con comandos específicos del sistema para identificar ejecutables no asociados con paquetes conocidos, mejorando su búsqueda de todos los programas instalados.
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

Imagina un proceso que se ejecutó desde /tmp/exec y luego fue eliminado. Es posible extraerlo.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Inspeccionar ubicaciones de inicio automático

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
### Servicios

Rutas donde un malware podría instalarse como un servicio:

- **/etc/inittab**: Llama a scripts de inicialización como rc.sysinit, dirigiendo posteriormente a scripts de inicio.
- **/etc/rc.d/** y **/etc/rc.boot/**: Contienen scripts para el inicio de servicios, siendo este último encontrado en versiones más antiguas de Linux.
- **/etc/init.d/**: Usado en ciertas versiones de Linux como Debian para almacenar scripts de inicio.
- Los servicios también pueden ser activados a través de **/etc/inetd.conf** o **/etc/xinetd/**, dependiendo de la variante de Linux.
- **/etc/systemd/system**: Un directorio para scripts del gestor de sistema y servicios.
- **/etc/systemd/system/multi-user.target.wants/**: Contiene enlaces a servicios que deben iniciarse en un nivel de ejecución multiusuario.
- **/usr/local/etc/rc.d/**: Para servicios personalizados o de terceros.
- **\~/.config/autostart/**: Para aplicaciones de inicio automático específicas del usuario, que pueden ser un escondite para malware dirigido a usuarios.
- **/lib/systemd/system/**: Archivos de unidad predeterminados a nivel de sistema proporcionados por paquetes instalados.

### Módulos del Kernel

Los módulos del kernel de Linux, a menudo utilizados por malware como componentes de rootkit, se cargan al inicio del sistema. Los directorios y archivos críticos para estos módulos incluyen:

- **/lib/modules/$(uname -r)**: Contiene módulos para la versión del kernel en ejecución.
- **/etc/modprobe.d**: Contiene archivos de configuración para controlar la carga de módulos.
- **/etc/modprobe** y **/etc/modprobe.conf**: Archivos para configuraciones globales de módulos.

### Otras Ubicaciones de Autoinicio

Linux emplea varios archivos para ejecutar automáticamente programas al iniciar sesión del usuario, potencialmente albergando malware:

- **/etc/profile.d/**\*, **/etc/profile**, y **/etc/bash.bashrc**: Se ejecutan para cualquier inicio de sesión de usuario.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, y **\~/.config/autostart**: Archivos específicos del usuario que se ejecutan al iniciar sesión.
- **/etc/rc.local**: Se ejecuta después de que todos los servicios del sistema han comenzado, marcando el final de la transición a un entorno multiusuario.

## Examinar Registros

Los sistemas Linux rastrean las actividades de los usuarios y los eventos del sistema a través de varios archivos de registro. Estos registros son fundamentales para identificar accesos no autorizados, infecciones de malware y otros incidentes de seguridad. Los archivos de registro clave incluyen:

- **/var/log/syslog** (Debian) o **/var/log/messages** (RedHat): Capturan mensajes y actividades a nivel de sistema.
- **/var/log/auth.log** (Debian) o **/var/log/secure** (RedHat): Registran intentos de autenticación, inicios de sesión exitosos y fallidos.
- Usa `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` para filtrar eventos de autenticación relevantes.
- **/var/log/boot.log**: Contiene mensajes de inicio del sistema.
- **/var/log/maillog** o **/var/log/mail.log**: Registra actividades del servidor de correo, útil para rastrear servicios relacionados con el correo electrónico.
- **/var/log/kern.log**: Almacena mensajes del kernel, incluidos errores y advertencias.
- **/var/log/dmesg**: Contiene mensajes del controlador de dispositivos.
- **/var/log/faillog**: Registra intentos de inicio de sesión fallidos, ayudando en investigaciones de violaciones de seguridad.
- **/var/log/cron**: Registra ejecuciones de trabajos cron.
- **/var/log/daemon.log**: Rastrear actividades de servicios en segundo plano.
- **/var/log/btmp**: Documenta intentos de inicio de sesión fallidos.
- **/var/log/httpd/**: Contiene registros de errores y acceso de Apache HTTPD.
- **/var/log/mysqld.log** o **/var/log/mysql.log**: Registra actividades de la base de datos MySQL.
- **/var/log/xferlog**: Registra transferencias de archivos FTP.
- **/var/log/**: Siempre verifica si hay registros inesperados aquí.

> [!NOTE]
> Los registros del sistema Linux y los subsistemas de auditoría pueden estar deshabilitados o eliminados en un incidente de intrusión o malware. Debido a que los registros en los sistemas Linux generalmente contienen información muy útil sobre actividades maliciosas, los intrusos los eliminan rutinariamente. Por lo tanto, al examinar los archivos de registro disponibles, es importante buscar brechas o entradas fuera de orden que puedan ser una indicación de eliminación o manipulación.

**Linux mantiene un historial de comandos para cada usuario**, almacenado en:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Además, el comando `last -Faiwx` proporciona una lista de inicios de sesión de usuarios. Verifícalo en busca de inicios de sesión desconocidos o inesperados.

Verifica archivos que pueden otorgar privilegios adicionales:

- Revisa `/etc/sudoers` en busca de privilegios de usuario no anticipados que puedan haberse otorgado.
- Revisa `/etc/sudoers.d/` en busca de privilegios de usuario no anticipados que puedan haberse otorgado.
- Examina `/etc/groups` para identificar cualquier membresía o permisos de grupo inusuales.
- Examina `/etc/passwd` para identificar cualquier membresía o permisos de grupo inusuales.

Algunas aplicaciones también generan sus propios registros:

- **SSH**: Examina _\~/.ssh/authorized_keys_ y _\~/.ssh/known_hosts_ para conexiones remotas no autorizadas.
- **Gnome Desktop**: Revisa _\~/.recently-used.xbel_ para archivos accedidos recientemente a través de aplicaciones de Gnome.
- **Firefox/Chrome**: Verifica el historial del navegador y las descargas en _\~/.mozilla/firefox_ o _\~/.config/google-chrome_ en busca de actividades sospechosas.
- **VIM**: Revisa _\~/.viminfo_ para detalles de uso, como rutas de archivos accedidos e historial de búsqueda.
- **Open Office**: Verifica el acceso reciente a documentos que puedan indicar archivos comprometidos.
- **FTP/SFTP**: Revisa los registros en _\~/.ftp_history_ o _\~/.sftp_history_ para transferencias de archivos que podrían no estar autorizadas.
- **MySQL**: Investiga _\~/.mysql_history_ para consultas de MySQL ejecutadas, que podrían revelar actividades no autorizadas en la base de datos.
- **Less**: Analiza _\~/.lesshst_ para el historial de uso, incluidos archivos vistos y comandos ejecutados.
- **Git**: Examina _\~/.gitconfig_ y el proyecto _.git/logs_ para cambios en los repositorios.

### Registros USB

[**usbrip**](https://github.com/snovvcrash/usbrip) es un pequeño software escrito en Python 3 puro que analiza archivos de registro de Linux (`/var/log/syslog*` o `/var/log/messages*` dependiendo de la distribución) para construir tablas de historial de eventos USB.

Es interesante **conocer todos los USB que se han utilizado** y será más útil si tienes una lista autorizada de USB para encontrar "eventos de violación" (el uso de USB que no están dentro de esa lista).

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

## Revisar Cuentas de Usuario y Actividades de Inicio de Sesión

Examine el _**/etc/passwd**_, _**/etc/shadow**_ y **registros de seguridad** en busca de nombres inusuales o cuentas creadas y/o utilizadas en estrecha proximidad a eventos no autorizados conocidos. Además, verifique posibles ataques de fuerza bruta a sudo.\
Además, revise archivos como _**/etc/sudoers**_ y _**/etc/groups**_ en busca de privilegios inesperados otorgados a los usuarios.\
Finalmente, busque cuentas con **sin contraseñas** o **contraseñas fácilmente adivinables**.

## Examinar el Sistema de Archivos

### Analizando Estructuras del Sistema de Archivos en la Investigación de Malware

Al investigar incidentes de malware, la estructura del sistema de archivos es una fuente crucial de información, revelando tanto la secuencia de eventos como el contenido del malware. Sin embargo, los autores de malware están desarrollando técnicas para obstaculizar este análisis, como modificar las marcas de tiempo de los archivos o evitar el sistema de archivos para el almacenamiento de datos.

Para contrarrestar estos métodos anti-forenses, es esencial:

- **Realizar un análisis de línea de tiempo exhaustivo** utilizando herramientas como **Autopsy** para visualizar líneas de tiempo de eventos o `mactime` de **Sleuth Kit** para datos de línea de tiempo detallados.
- **Investigar scripts inesperados** en el $PATH del sistema, que podrían incluir scripts de shell o PHP utilizados por atacantes.
- **Examinar `/dev` en busca de archivos atípicos**, ya que tradicionalmente contiene archivos especiales, pero puede albergar archivos relacionados con malware.
- **Buscar archivos o directorios ocultos** con nombres como ".. " (punto punto espacio) o "..^G" (punto punto control-G), que podrían ocultar contenido malicioso.
- **Identificar archivos setuid root** utilizando el comando: `find / -user root -perm -04000 -print` Esto encuentra archivos con permisos elevados, que podrían ser abusados por atacantes.
- **Revisar marcas de tiempo de eliminación** en tablas de inodos para detectar eliminaciones masivas de archivos, lo que podría indicar la presencia de rootkits o troyanos.
- **Inspeccionar inodos consecutivos** en busca de archivos maliciosos cercanos después de identificar uno, ya que pueden haber sido colocados juntos.
- **Verificar directorios binarios comunes** (_/bin_, _/sbin_) en busca de archivos modificados recientemente, ya que estos podrían haber sido alterados por malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!NOTE]
> Tenga en cuenta que un **atacante** puede **modificar** el **tiempo** para hacer que los **archivos aparezcan** **legítimos**, pero **no puede** modificar el **inode**. Si encuentra que un **archivo** indica que fue creado y modificado al **mismo tiempo** que el resto de los archivos en la misma carpeta, pero el **inode** es **inesperadamente más grande**, entonces los **timestamps de ese archivo fueron modificados**.

## Comparar archivos de diferentes versiones del sistema de archivos

### Resumen de comparación de versiones del sistema de archivos

Para comparar versiones del sistema de archivos y localizar cambios, utilizamos comandos simplificados de `git diff`:

- **Para encontrar nuevos archivos**, compare dos directorios:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Para contenido modificado**, enumere los cambios ignorando líneas específicas:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Para detectar archivos eliminados**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Las opciones de filtro** (`--diff-filter`) ayudan a reducir a cambios específicos como archivos añadidos (`A`), eliminados (`D`) o modificados (`M`).
- `A`: Archivos añadidos
- `C`: Archivos copiados
- `D`: Archivos eliminados
- `M`: Archivos modificados
- `R`: Archivos renombrados
- `T`: Cambios de tipo (por ejemplo, de archivo a symlink)
- `U`: Archivos no fusionados
- `X`: Archivos desconocidos
- `B`: Archivos rotos

## Referencias

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Libro: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

{{#include ../../banners/hacktricks-training.md}}
