# Forense de Linux

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
¡Accede hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**artículos oficiales de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Recopilación de Información Inicial

### Información Básica

En primer lugar, se recomienda tener una **USB** con **binarios y bibliotecas conocidos de calidad** (puedes simplemente obtener Ubuntu y copiar las carpetas _/bin_, _/sbin_, _/lib_ y _/lib64_), luego montar la USB y modificar las variables de entorno para utilizar esos binarios:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Una vez que hayas configurado el sistema para usar binarios buenos y conocidos, puedes comenzar **a extraer alguna información básica**:
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

Mientras se obtiene la información básica, se debe verificar cosas extrañas como:

- Los **procesos de root** generalmente se ejecutan con PIDS bajos, por lo que si encuentras un proceso de root con un PID alto, puedes sospechar.
- Verificar los **inicios de sesión registrados** de usuarios sin shell dentro de `/etc/passwd`.
- Revisar los **hashes de contraseñas** dentro de `/etc/shadow` para usuarios sin shell.

### Volcado de memoria

Para obtener la memoria del sistema en ejecución, se recomienda utilizar [**LiME**](https://github.com/504ensicsLabs/LiME).\
Para **compilarlo**, necesitas utilizar el **mismo kernel** que está utilizando la máquina víctima.

{% hint style="info" %}
Recuerda que **no puedes instalar LiME ni nada más** en la máquina víctima, ya que hará varios cambios en ella.
{% endhint %}

Entonces, si tienes una versión idéntica de Ubuntu, puedes usar `apt-get install lime-forensics-dkms`\
En otros casos, necesitas descargar [**LiME**](https://github.com/504ensicsLabs/LiME) desde github y compilarlo con los encabezados de kernel correctos. Para **obtener los encabezados de kernel exactos** de la máquina víctima, simplemente **copia el directorio** `/lib/modules/<versión del kernel>` a tu máquina, y luego **compila** LiME utilizando esos encabezados:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME admite 3 **formatos**:

* Crudo (cada segmento concatenado)
* Acolchado (igual que crudo, pero con ceros en los bits derechos)
* Lime (formato recomendado con metadatos)

LiME también se puede utilizar para **enviar el volcado a través de la red** en lugar de almacenarlo en el sistema usando algo como: `path=tcp:4444`

### Imagen de disco

#### Apagado

En primer lugar, necesitarás **apagar el sistema**. Esto no siempre es una opción, ya que a veces el sistema será un servidor de producción que la empresa no puede permitirse apagar.\
Hay **2 formas** de apagar el sistema, un **apagado normal** y un **apagado "desenchufar"**. El primero permitirá que los **procesos terminen como de costumbre** y que el **sistema de archivos** se **sincronice**, pero también permitirá que el posible **malware** **destruya evidencia**. El enfoque de "desenchufar" puede implicar **alguna pérdida de información** (no se perderá mucha información, ya que ya tomamos una imagen de la memoria) y el **malware no tendrá oportunidad** de hacer nada al respecto. Por lo tanto, si **sospechas** que puede haber un **malware**, simplemente ejecuta el **comando `sync`** en el sistema y desenchufa.

#### Tomar una imagen del disco

Es importante tener en cuenta que **antes de conectar tu computadora a cualquier cosa relacionada con el caso**, debes asegurarte de que se va a **montar como solo lectura** para evitar modificar cualquier información.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Análisis previo de la imagen del disco

Crear una imagen del disco sin más datos.
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
Obtenga acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Buscar Malware conocido

### Archivos del sistema modificados

Linux ofrece herramientas para garantizar la integridad de los componentes del sistema, crucial para detectar archivos potencialmente problemáticos.

- **Sistemas basados en RedHat**: Utilice `rpm -Va` para una verificación exhaustiva.
- **Sistemas basados en Debian**: `dpkg --verify` para verificación inicial, seguido de `debsums | grep -v "OK$"` (después de instalar `debsums` con `apt-get install debsums`) para identificar cualquier problema.

### Detectores de Malware/Rootkit

Lea la siguiente página para conocer herramientas que pueden ser útiles para encontrar malware:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Buscar programas instalados

Para buscar de manera efectiva programas instalados en sistemas Debian y RedHat, considere aprovechar los registros y bases de datos del sistema junto con verificaciones manuales en directorios comunes.

- Para Debian, inspeccione **_`/var/lib/dpkg/status`_** y **_`/var/log/dpkg.log`_** para obtener detalles sobre las instalaciones de paquetes, utilizando `grep` para filtrar información específica.

- Los usuarios de RedHat pueden consultar la base de datos RPM con `rpm -qa --root=/mntpath/var/lib/rpm` para listar los paquetes instalados.

Para descubrir software instalado manualmente o fuera de estos gestores de paquetes, explore directorios como **_`/usr/local`_**, **_`/opt`_**, **_`/usr/sbin`_**, **_`/usr/bin`_**, **_`/bin`_**, y **_`/sbin`_**. Combine listados de directorios con comandos específicos del sistema para identificar ejecutables no asociados con paquetes conocidos, mejorando su búsqueda de todos los programas instalados.
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias **más avanzadas** del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recuperar Binarios en Ejecución Eliminados

Imagina un proceso que se ejecutó desde /tmp/exec y fue eliminado. Es posible extraerlo.
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

Rutas donde un malware podría estar instalado como un servicio:

- **/etc/inittab**: Llama a scripts de inicialización como rc.sysinit, dirigiéndose a scripts de inicio adicionales.
- **/etc/rc.d/** y **/etc/rc.boot/**: Contienen scripts para el inicio de servicios, siendo este último encontrado en versiones antiguas de Linux.
- **/etc/init.d/**: Utilizado en ciertas versiones de Linux como Debian para almacenar scripts de inicio.
- Los servicios también pueden ser activados a través de **/etc/inetd.conf** o **/etc/xinetd/**, dependiendo de la variante de Linux.
- **/etc/systemd/system**: Un directorio para scripts del sistema y del administrador de servicios.
- **/etc/systemd/system/multi-user.target.wants/**: Contiene enlaces a servicios que deben iniciarse en un nivel de ejecución multiusuario.
- **/usr/local/etc/rc.d/**: Para servicios personalizados o de terceros.
- **~/.config/autostart/**: Para aplicaciones de inicio automático específicas del usuario, que pueden ser un lugar de ocultación para malware dirigido al usuario.
- **/lib/systemd/system/**: Archivos de unidad predeterminados de todo el sistema proporcionados por paquetes instalados.


### Módulos del Kernel

Los módulos del kernel de Linux, a menudo utilizados por malware como componentes de rootkit, se cargan al inicio del sistema. Los directorios y archivos críticos para estos módulos incluyen:

- **/lib/modules/$(uname -r)**: Contiene módulos para la versión del kernel en ejecución.
- **/etc/modprobe.d**: Contiene archivos de configuración para controlar la carga de módulos.
- **/etc/modprobe** y **/etc/modprobe.conf**: Archivos para configuraciones globales de módulos.

### Otras Ubicaciones de Inicio Automático

Linux emplea varios archivos para ejecutar programas automáticamente al iniciar sesión de usuario, potencialmente albergando malware:

- **/etc/profile.d/***, **/etc/profile** y **/etc/bash.bashrc**: Ejecutados para cualquier inicio de sesión de usuario.
- **~/.bashrc**, **~/.bash_profile**, **~/.profile** y **~/.config/autostart**: Archivos específicos del usuario que se ejecutan al iniciar sesión.
- **/etc/rc.local**: Se ejecuta después de que todos los servicios del sistema se han iniciado, marcando el final de la transición a un entorno multiusuario.

## Examinar Registros

Los sistemas Linux registran las actividades de los usuarios y los eventos del sistema a través de varios archivos de registro. Estos registros son fundamentales para identificar accesos no autorizados, infecciones de malware y otros incidentes de seguridad. Los archivos de registro clave incluyen:

- **/var/log/syslog** (Debian) o **/var/log/messages** (RedHat): Capturan mensajes y actividades en todo el sistema.
- **/var/log/auth.log** (Debian) o **/var/log/secure** (RedHat): Registran intentos de autenticación, inicios de sesión exitosos y fallidos.
- Utiliza `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` para filtrar eventos de autenticación relevantes.
- **/var/log/boot.log**: Contiene mensajes de inicio del sistema.
- **/var/log/maillog** o **/var/log/mail.log**: Registra actividades del servidor de correo electrónico, útil para rastrear servicios relacionados con el correo electrónico.
- **/var/log/kern.log**: Almacena mensajes del kernel, incluidos errores y advertencias.
- **/var/log/dmesg**: Contiene mensajes de controladores de dispositivos.
- **/var/log/faillog**: Registra intentos de inicio de sesión fallidos, ayudando en investigaciones de violaciones de seguridad.
- **/var/log/cron**: Registra la ejecución de trabajos cron.
- **/var/log/daemon.log**: Realiza un seguimiento de las actividades de los servicios en segundo plano.
- **/var/log/btmp**: Documenta intentos de inicio de sesión fallidos.
- **/var/log/httpd/**: Contiene registros de errores y accesos de Apache HTTPD.
- **/var/log/mysqld.log** o **/var/log/mysql.log**: Registra actividades de la base de datos MySQL.
- **/var/log/xferlog**: Registra transferencias de archivos FTP.
- **/var/log/**: Siempre verifica los registros inesperados aquí.

{% hint style="info" %}
Los registros del sistema y los subsistemas de auditoría de Linux pueden estar deshabilitados o eliminados en un incidente de intrusión o malware. Debido a que los registros en los sistemas Linux generalmente contienen información muy útil sobre actividades maliciosas, los intrusos rutinariamente los eliminan. Por lo tanto, al examinar los archivos de registro disponibles, es importante buscar lagunas o entradas fuera de orden que puedan ser una indicación de eliminación o manipulación.
{% endhint %}

**Linux mantiene un historial de comandos para cada usuario**, almacenado en:

- ~/.bash_history
- ~/.zsh_history
- ~/.zsh_sessions/*
- ~/.python_history
- ~/.*_history

Además, el comando `last -Faiwx` proporciona una lista de inicios de sesión de usuario. Revísalo en busca de inicios de sesión desconocidos o inesperados.

Revisa archivos que puedan otorgar privilegios adicionales:

- Revisa `/etc/sudoers` para privilegios de usuario no anticipados que puedan haber sido otorgados.
- Revisa `/etc/sudoers.d/` para privilegios de usuario no anticipados que puedan haber sido otorgados.
- Examina `/etc/groups` para identificar membresías o permisos de grupo inusuales.
- Examina `/etc/passwd` para identificar membresías o permisos de grupo inusuales.

Algunas aplicaciones también generan sus propios registros:

- **SSH**: Examina _~/.ssh/authorized_keys_ y _~/.ssh/known_hosts_ para conexiones remotas no autorizadas.
- **Escritorio Gnome**: Revisa _~/.recently-used.xbel_ para archivos accedidos recientemente a través de aplicaciones de Gnome.
- **Firefox/Chrome**: Verifica el historial y descargas del navegador en _~/.mozilla/firefox_ o _~/.config/google-chrome_ en busca de actividades sospechosas.
- **VIM**: Revisa _~/.viminfo_ para detalles de uso, como rutas de archivos accedidos e historial de búsquedas.
- **Open Office**: Verifica el acceso a documentos recientes que puedan indicar archivos comprometidos.
- **FTP/SFTP**: Revisa los registros en _~/.ftp_history_ o _~/.sftp_history_ para transferencias de archivos que podrían ser no autorizadas.
- **MySQL**: Investiga _~/.mysql_history_ para consultas de MySQL ejecutadas, revelando potencialmente actividades no autorizadas en la base de datos.
- **Less**: Analiza _~/.lesshst_ para historial de uso, incluidos archivos vistos y comandos ejecutados.
- **Git**: Examina _~/.gitconfig_ y el proyecto _.git/logs_ para cambios en repositorios.

### Registros USB

[**usbrip**](https://github.com/snovvcrash/usbrip) es un pequeño software escrito en Python 3 puro que analiza archivos de registro de Linux (`/var/log/syslog*` o `/var/log/messages*` dependiendo de la distribución) para construir tablas de historial de eventos USB.

Es interesante **conocer todos los USB que se han utilizado** y será más útil si tienes una lista autorizada de USB para encontrar "eventos de violación" (el uso de USB que no están en esa lista).

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
## Revisar Cuentas de Usuario y Actividades de Inicio de Sesión

Examine los archivos _**/etc/passwd**_, _**/etc/shadow**_ y los **registros de seguridad** en busca de nombres inusuales o cuentas creadas y utilizadas en proximidad a eventos no autorizados conocidos. Además, verifique posibles ataques de fuerza bruta sudo.\
Además, revise archivos como _**/etc/sudoers**_ y _**/etc/groups**_ en busca de privilegios inesperados otorgados a usuarios.\
Finalmente, busque cuentas sin contraseñas o contraseñas **fáciles de adivinar**.

## Examinar el Sistema de Archivos

### Analizando Estructuras del Sistema de Archivos en Investigaciones de Malware

Cuando se investigan incidentes de malware, la estructura del sistema de archivos es una fuente crucial de información, revelando tanto la secuencia de eventos como el contenido del malware. Sin embargo, los autores de malware están desarrollando técnicas para dificultar este análisis, como modificar las marcas de tiempo de los archivos o evitar el sistema de archivos para el almacenamiento de datos.

Para contrarrestar estos métodos antiforense, es esencial:

- **Realizar un análisis detallado de la línea de tiempo** utilizando herramientas como **Autopsy** para visualizar las líneas de tiempo de eventos o `mactime` de **Sleuth Kit** para obtener datos detallados de la línea de tiempo.
- **Investigar scripts inesperados** en la variable $PATH del sistema, que podrían incluir scripts de shell o PHP utilizados por atacantes.
- **Examinar `/dev` en busca de archivos atípicos**, ya que tradicionalmente contiene archivos especiales, pero puede contener archivos relacionados con malware.
- **Buscar archivos o directorios ocultos** con nombres como ".. " (punto punto espacio) o "..^G" (punto punto control-G), que podrían ocultar contenido malicioso.
- **Identificar archivos setuid root** utilizando el comando:
```find / -user root -perm -04000 -print```
Esto encuentra archivos con permisos elevados, que podrían ser abusados por atacantes.
- **Revisar las marcas de tiempo de eliminación** en las tablas de inodos para detectar eliminaciones masivas de archivos, lo que podría indicar la presencia de rootkits o troyanos.
- **Inspeccionar inodos consecutivos** en busca de archivos maliciosos cercanos después de identificar uno, ya que podrían haber sido colocados juntos.
- **Verificar directorios binarios comunes** (_/bin_, _/sbin_) en busca de archivos modificados recientemente, ya que podrían ser alterados por malware.
```bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
```
{% hint style="info" %}
Ten en cuenta que un **atacante** puede **modificar** la **hora** para que los **archivos parezcan** **legítimos**, pero no puede modificar el **inode**. Si descubres que un **archivo** indica que fue creado y modificado al **mismo tiempo** que el resto de los archivos en la misma carpeta, pero el **inode** es **inesperadamente más grande**, entonces los **timestamps de ese archivo fueron modificados**.
{% endhint %}

## Comparar archivos de diferentes versiones de sistemas de archivos

### Resumen de la Comparación de Versiones del Sistema de Archivos

Para comparar versiones de sistemas de archivos y señalar cambios, utilizamos comandos simplificados de `git diff`:

- **Para encontrar archivos nuevos**, compara dos directorios:
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
- **Opciones de filtro** (`--diff-filter`) ayudan a reducir los cambios específicos como archivos añadidos (`A`), eliminados (`D`), o modificados (`M`).
- `A`: Archivos añadidos
- `C`: Archivos copiados
- `D`: Archivos eliminados
- `M`: Archivos modificados
- `R`: Archivos renombrados
- `T`: Cambios de tipo (por ejemplo, archivo a enlace simbólico)
- `U`: Archivos no fusionados
- `X`: Archivos desconocidos
- `B`: Archivos rotos

## Referencias

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Libro: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**oficial mercancía de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
¡Accede hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
