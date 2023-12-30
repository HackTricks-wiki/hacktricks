# Forense en Linux

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, potenciados por las herramientas comunitarias **más avanzadas**.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Recopilación de Información Inicial

### Información Básica

En primer lugar, se recomienda tener algún **USB** con **binarios y bibliotecas bien conocidos en él** (puedes simplemente obtener ubuntu y copiar las carpetas _/bin_, _/sbin_, _/lib,_ y _/lib64_), luego montar el USB y modificar las variables de entorno para usar esos binarios:
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

Mientras obtienes la información básica, debes buscar cosas extrañas como:

* **Procesos de root** suelen ejecutarse con PIDs bajos, así que si encuentras un proceso de root con un PID alto podrías sospechar
* Verifica **inicios de sesión registrados** de usuarios sin una shell dentro de `/etc/passwd`
* Busca **hashes de contraseñas** dentro de `/etc/shadow` para usuarios sin una shell

### Volcado de Memoria

Para obtener la memoria del sistema en ejecución, se recomienda usar [**LiME**](https://github.com/504ensicsLabs/LiME).\
Para **compilarlo**, necesitas usar el **mismo kernel** que está utilizando la máquina víctima.

{% hint style="info" %}
Recuerda que **no puedes instalar LiME ni ninguna otra cosa** en la máquina víctima ya que hará varios cambios en ella
{% endhint %}

Entonces, si tienes una versión idéntica de Ubuntu puedes usar `apt-get install lime-forensics-dkms`\
En otros casos, necesitas descargar [**LiME**](https://github.com/504ensicsLabs/LiME) de github y compilarlo con los encabezados de kernel correctos. Para **obtener los encabezados de kernel exactos** de la máquina víctima, puedes simplemente **copiar el directorio** `/lib/modules/<versión del kernel>` a tu máquina, y luego **compilar** LiME usándolos:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME soporta 3 **formatos**:

* Raw (cada segmento concatenado)
* Padded (igual que raw, pero con ceros en los bits correctos)
* Lime (formato recomendado con metadatos)

LiME también puede ser utilizado para **enviar el volcado a través de la red** en lugar de almacenarlo en el sistema usando algo como: `path=tcp:4444`

### Imagen de Disco

#### Apagando

Primero que nada, necesitarás **apagar el sistema**. Esto no siempre es una opción ya que a veces el sistema será un servidor de producción que la empresa no puede permitirse apagar.\
Hay **2 maneras** de apagar el sistema, un **apagado normal** y un apagado de **"desconectar el enchufe"**. El primero permitirá que los **procesos terminen como de costumbre** y el **sistema de archivos** se **sincronice**, pero también permitirá que el posible **malware** **destruya evidencia**. El enfoque de "desconectar el enchufe" puede conllevar **alguna pérdida de información** (no se perderá mucha información ya que ya tomamos una imagen de la memoria) y el **malware no tendrá ninguna oportunidad** de hacer nada al respecto. Por lo tanto, si **sospechas** que puede haber un **malware**, simplemente ejecuta el **comando `sync`** en el sistema y desconecta el enchufe.

#### Tomando una imagen del disco

Es importante notar que **antes de conectar tu computadora a cualquier cosa relacionada con el caso**, necesitas estar seguro de que va a ser **montada como solo lectura** para evitar modificar cualquier información.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Preanálisis de imagen de disco

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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, potenciados por las herramientas comunitarias **más avanzadas** del mundo.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Búsqueda de Malware conocido

### Archivos del Sistema Modificados

Algunos sistemas Linux tienen una característica para **verificar la integridad de muchos componentes instalados**, proporcionando una manera efectiva de identificar archivos inusuales o fuera de lugar. Por ejemplo, `rpm -Va` en Linux está diseñado para verificar todos los paquetes que fueron instalados usando RedHat Package Manager.
```bash
#RedHat
rpm -Va
#Debian
dpkg --verify
debsums | grep -v "OK$" #apt-get install debsums
```
### Detectores de Malware/Rootkits

Lee la siguiente página para aprender sobre herramientas que pueden ser útiles para encontrar malware:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Buscar programas instalados

### Gestor de Paquetes

En sistemas basados en Debian, el archivo _**/var/lib/dpkg/status**_ contiene detalles sobre los paquetes instalados y el archivo _**/var/log/dpkg.log**_ registra información cuando se instala un paquete.\
En distribuciones de Linux relacionadas con RedHat, el comando **`rpm -qa --root=/mntpath/var/lib/rpm`** listará los contenidos de una base de datos RPM en un sistema.
```bash
#Debian
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
#RedHat
rpm -qa --root=/ mntpath/var/lib/rpm
```
### Otros

**No todos los programas instalados se listarán con los comandos anteriores** porque algunas aplicaciones no están disponibles como paquetes para ciertos sistemas y deben instalarse desde el código fuente. Por lo tanto, una revisión de ubicaciones como _**/usr/local**_ y _**/opt**_ puede revelar otras aplicaciones que han sido compiladas e instaladas desde el código fuente.
```bash
ls /opt /usr/local
```
Otra buena idea es **verificar** las **carpetas comunes** dentro de **$PATH** para **binarios no relacionados** con **paquetes instalados:**
```bash
#Both lines are going to print the executables in /sbin non related to installed packages
#Debian
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
#RedHat
find /sbin/ –exec rpm -qf {} \; | grep "is not"
```
```markdown
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, potenciados por las herramientas comunitarias **más avanzadas** del mundo.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recuperar Binarios Eliminados en Ejecución

![](<../../.gitbook/assets/image (641).png>)

## Inspeccionar Ubicaciones de Autostart

### Tareas Programadas
```
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

Es extremadamente común que el malware se arraigue como un nuevo servicio no autorizado. Linux tiene varios scripts que se utilizan para iniciar servicios cuando la computadora se enciende. El script de inicio de inicialización _**/etc/inittab**_ llama a otros scripts como rc.sysinit y varios scripts de inicio bajo el directorio _**/etc/rc.d/**_, o _**/etc/rc.boot/**_ en algunas versiones antiguas. En otras versiones de Linux, como Debian, los scripts de inicio se almacenan en el directorio _**/etc/init.d/**_. Además, algunos servicios comunes están habilitados en _**/etc/inetd.conf**_ o _**/etc/xinetd/**_ dependiendo de la versión de Linux. Los investigadores digitales deben inspeccionar cada uno de estos scripts de inicio en busca de entradas anómalas.

* _**/etc/inittab**_
* _**/etc/rc.d/**_
* _**/etc/rc.boot/**_
* _**/etc/init.d/**_
* _**/etc/inetd.conf**_
* _**/etc/xinetd/**_
* _**/etc/systemd/system**_
* _**/etc/systemd/system/multi-user.target.wants/**_

### Módulos del Kernel

En los sistemas Linux, los módulos del kernel se utilizan comúnmente como componentes de rootkit para paquetes de malware. Los módulos del kernel se cargan cuando el sistema se inicia en base a la información de configuración en los directorios `/lib/modules/'uname -r'` y `/etc/modprobe.d`, y el archivo `/etc/modprobe` o `/etc/modprobe.conf`. Estas áreas deben ser inspeccionadas en busca de elementos relacionados con malware.

### Otras Ubicaciones de Autostart

Hay varios archivos de configuración que Linux utiliza para lanzar automáticamente un ejecutable cuando un usuario inicia sesión en el sistema que pueden contener rastros de malware.

* _**/etc/profile.d/\***_ , _**/etc/profile**_ , _**/etc/bash.bashrc**_ se ejecutan cuando cualquier cuenta de usuario inicia sesión.
* _**∼/.bashrc**_ , _**∼/.bash\_profile**_ , _**\~/.profile**_ , _**∼/.config/autostart**_ se ejecutan cuando el usuario específico inicia sesión.
* _**/etc/rc.local**_ Tradicionalmente se ejecuta después de que todos los servicios normales del sistema se han iniciado, al final del proceso de cambio a un nivel de ejecución multiusuario.

## Examinar Registros

Busque en todos los archivos de registro disponibles en el sistema comprometido rastros de ejecución maliciosa y actividades asociadas como la creación de un nuevo servicio.

### Registros Puros

Los eventos de **inicio de sesión** registrados en los registros del sistema y de seguridad, incluidos los inicios de sesión a través de la red, pueden revelar que **malware** o un **intruso obtuvo acceso** a un sistema comprometido a través de una cuenta determinada en un momento específico. Otros eventos alrededor del momento de una infección por malware pueden ser capturados en registros del sistema, incluyendo la **creación** de un **nuevo** **servicio** o nuevas cuentas alrededor del momento de un incidente.\
Inicios de sesión de sistema interesantes:

* **/var/log/syslog** (debian) o **/var/log/messages** (Redhat)
* Muestra mensajes generales e información sobre el sistema. Es un registro de datos de toda la actividad en todo el sistema global.
* **/var/log/auth.log** (debian) o **/var/log/secure** (Redhat)
* Mantiene registros de autenticación tanto para inicios de sesión exitosos como fallidos, y procesos de autenticación. El almacenamiento depende del tipo de sistema.
* `cat /var/log/auth.log | grep -iE "session opened for|accepted password|new session|not in sudoers"`
* **/var/log/boot.log**: mensajes de inicio y información de arranque.
* **/var/log/maillog** o **var/log/mail.log:** es para registros del servidor de correo, útil para información de servicios relacionados con correo como postfix, smtpd o que se ejecutan en su servidor.
* **/var/log/kern.log**: mantiene registros y advertencias del Kernel. Los registros de actividad del Kernel (por ejemplo, dmesg, kern.log, klog) pueden mostrar que un servicio en particular se bloqueó repetidamente, lo que podría indicar que se instaló una versión troyanizada inestable.
* **/var/log/dmesg**: un repositorio para mensajes de controladores de dispositivos. Use **dmesg** para ver mensajes en este archivo.
* **/var/log/faillog:** registra información sobre inicios de sesión fallidos. Por lo tanto, es útil para examinar posibles violaciones de seguridad como hacks de credenciales de inicio de sesión y ataques de fuerza bruta.
* **/var/log/cron**: mantiene un registro de mensajes relacionados con Crond (trabajos cron). Como cuando el demonio cron inició un trabajo.
* **/var/log/daemon.log:** lleva un registro de los servicios en segundo plano en ejecución pero no los representa gráficamente.
* **/var/log/btmp**: lleva nota de todos los intentos de inicio de sesión fallidos.
* **/var/log/httpd/**: un directorio que contiene archivos error\_log y access\_log del demonio Apache httpd. Cada error que encuentra httpd se guarda en el archivo **error\_log**. Piense en problemas de memoria y otros errores relacionados con el sistema. **access\_log** registra todas las solicitudes que llegan a través de HTTP.
* **/var/log/mysqld.log** o **/var/log/mysql.log**: archivo de registro de MySQL que registra cada mensaje de depuración, fallo y éxito, incluyendo el inicio, detención y reinicio del demonio MySQL mysqld. El sistema decide el directorio. RedHat, CentOS, Fedora y otros sistemas basados en RedHat utilizan /var/log/mariadb/mariadb.log. Sin embargo, Debian/Ubuntu utilizan el directorio /var/log/mysql/error.log.
* **/var/log/xferlog**: mantiene sesiones de transferencia de archivos FTP. Incluye información como nombres de archivos y transferencias FTP iniciadas por el usuario.
* **/var/log/\*** : Siempre debe verificar si hay registros inesperados en este directorio

{% hint style="info" %}
Los registros del sistema Linux y los subsistemas de auditoría pueden estar deshabilitados o eliminados en un incidente de intrusión o malware. Debido a que los registros en los sistemas Linux generalmente contienen información muy útil sobre actividades maliciosas, los intrusos los eliminan rutinariamente. Por lo tanto, al examinar los archivos de registro disponibles, es importante buscar huecos o entradas fuera de orden que puedan ser una indicación de eliminación o manipulación.
{% endhint %}

### Historial de Comandos

Muchos sistemas Linux están configurados para mantener un historial de comandos para cada cuenta de usuario:

* \~/.bash\_history
* \~/.history
* \~/.sh\_history
* \~/.\*\_history

### Inicios de Sesión

Usando el comando `last -Faiwx` es posible obtener la lista de usuarios que han iniciado sesión.\
Se recomienda verificar si esos inicios de sesión tienen sentido:

* ¿Algún usuario desconocido?
* ¿Algún usuario que no debería tener una shell iniciada?

Esto es importante ya que los **atacantes** a veces pueden copiar `/bin/bash` dentro de `/bin/false` para que usuarios como **lightdm** puedan **iniciar sesión**.

Tenga en cuenta que también puede **ver esta información leyendo los registros**.

### Rastros de Aplicaciones

* **SSH**: Las conexiones a sistemas realizadas usando SSH hacia y desde un sistema comprometido resultan en entradas en archivos para cada cuenta de usuario (_**∼/.ssh/authorized\_keys**_ y _**∼/.ssh/known\_keys**_). Estas entradas pueden revelar el nombre de host o la dirección IP de los hosts remotos.
* **Escritorio Gnome**: Las cuentas de usuario pueden tener un archivo _**∼/.recently-used.xbel**_ que contiene información sobre archivos que se accedieron recientemente utilizando aplicaciones que se ejecutan en el escritorio Gnome.
* **VIM**: Las cuentas de usuario pueden tener un archivo _**∼/.viminfo**_ que contiene detalles sobre el uso de VIM, incluyendo el historial de cadenas de búsqueda y rutas a archivos que se abrieron usando vim.
* **Open Office**: Archivos recientes.
* **MySQL**: Las cuentas de usuario pueden tener un archivo _**∼/.mysql\_history**_ que contiene consultas ejecutadas usando MySQL.
* **Less**: Las cuentas de usuario pueden tener un archivo _**∼/.lesshst**_ que contiene detalles sobre el uso de less, incluyendo el historial de cadenas de búsqueda y comandos de shell ejecutados a través de less.

### Registros USB

[**usbrip**](https://github.com/snovvcrash/usbrip) es un pequeño software escrito en Python 3 puro que analiza archivos de registro de Linux (`/var/log/syslog*` o `/var/log/messages*` dependiendo de la distribución) para construir tablas de historial de eventos USB.

Es interesante **saber todos los USB que se han utilizado** y será más útil si tiene una lista autorizada de USB para encontrar "eventos de violación" (el uso de USB que no están dentro de esa lista).

### Instalación
```
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Ejemplos
```
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Más ejemplos e información dentro de github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, impulsados por las herramientas comunitarias **más avanzadas**.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Revisar Cuentas de Usuario y Actividades de Inicio de Sesión

Examina los archivos _**/etc/passwd**_, _**/etc/shadow**_ y los **registros de seguridad** en busca de nombres inusuales o cuentas creadas y/o utilizadas en proximidad a eventos no autorizados conocidos. Además, verifica posibles ataques de fuerza bruta a sudo.\
Además, revisa archivos como _**/etc/sudoers**_ y _**/etc/groups**_ para privilegios inesperados otorgados a usuarios.\
Finalmente, busca cuentas con **sin contraseñas** o contraseñas **fácilmente adivinables**.

## Examinar el Sistema de Archivos

Las estructuras de datos del sistema de archivos pueden proporcionar cantidades sustanciales de **información** relacionada con un incidente de **malware**, incluyendo el **momento** de los eventos y el contenido **actual** del **malware**.\
El **malware** está siendo diseñado cada vez más para **obstaculizar el análisis del sistema de archivos**. Algunos malwares alteran las marcas de tiempo en archivos maliciosos para dificultar su localización con análisis de línea de tiempo. Otros códigos maliciosos están diseñados para almacenar cierta información solo en memoria para minimizar la cantidad de datos almacenados en el sistema de archivos.\
Para lidiar con tales técnicas antiforense, es necesario prestar **atención cuidadosa al análisis de línea de tiempo** de las marcas de tiempo del sistema de archivos y a los archivos almacenados en ubicaciones comunes donde se podría encontrar malware.

* Utilizando **autopsy** puedes ver la línea de tiempo de eventos que pueden ser útiles para descubrir actividad sospechosa. También puedes usar la función `mactime` de **Sleuth Kit** directamente.
* Busca **scripts inesperados** dentro de **$PATH** (¿quizás algunos scripts sh o php?)
* Los archivos en `/dev` solían ser archivos especiales, puedes encontrar aquí archivos no especiales relacionados con malware.
* Busca archivos y **directorios ocultos** o inusuales, como “.. ” (espacio punto punto) o “..^G ” (control-G punto punto)
* Copias de /bin/bash con setuid en el sistema `find / -user root -perm -04000 –print`
* Revisa las marcas de tiempo de **inodos eliminados para grandes cantidades de archivos que se eliminaron al mismo tiempo**, lo que podría indicar actividad maliciosa como la instalación de un rootkit o un servicio troyanizado.
* Dado que los inodos se asignan en base al siguiente disponible, **archivos maliciosos colocados en el sistema alrededor del mismo tiempo pueden ser asignados inodos consecutivos**. Por lo tanto, después de localizar un componente del malware, puede ser productivo inspeccionar los inodos vecinos.
* También revisa directorios como _/bin_ o _/sbin_ ya que la **hora de modificación o cambio** de archivos nuevos o modificados puede ser interesante.
* Es interesante ver los archivos y carpetas de un directorio **ordenados por fecha de creación** en lugar de alfabéticamente para ver cuáles archivos o carpetas son más recientes (los últimos suelen serlo).

Puedes verificar los archivos más recientes de una carpeta usando `ls -laR --sort=time /bin`\
Puedes verificar los inodos de los archivos dentro de una carpeta usando `ls -lai /bin |sort -n`

{% hint style="info" %}
Ten en cuenta que un **atacante** puede **modificar** la **hora** para hacer que los **archivos parezcan** **legítimos**, pero **no puede** modificar el **inodo**. Si encuentras que un **archivo** indica que fue creado y modificado al **mismo tiempo** que el resto de los archivos en la misma carpeta, pero el **inodo** es **inesperadamente grande**, entonces las **marcas de tiempo de ese archivo fueron modificadas**.
{% endhint %}

## Comparar archivos de diferentes versiones del sistema de archivos

#### Encontrar archivos añadidos
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### Encontrar contenido modificado
```bash
git diff --no-index --diff-filter=M _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/ | grep -E "^\+" | grep -v "Installed-Time"
```
#### Encontrar archivos eliminados
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### Otros filtros

**`-diff-filter=[(A|C|D|M|R|T|U|X|B)…​[*]]`**

Selecciona solo archivos que son Añadidos (`A`), Copiados (`C`), Eliminados (`D`), Modificados (`M`), Renombrados (`R`), y que han cambiado de tipo (es decir, archivo regular, enlace simbólico, submódulo, …​) (`T`), no fusionados (`U`), desconocidos (`X`), o que han roto su emparejamiento (`B`). Cualquier combinación de los caracteres de filtro (incluyendo ninguno) puede ser utilizada. Cuando se añade `*` (Todo-o-nada) a la combinación, todos los caminos son seleccionados si hay algún archivo que coincida con otros criterios en la comparación; si no hay ningún archivo que coincida con otros criterios, nada es seleccionado.

Además, **estas letras mayúsculas pueden convertirse en minúsculas para excluir**. Por ejemplo, `--diff-filter=ad` excluye caminos añadidos y eliminados.

Nota que no todos los diffs pueden presentar todos los tipos. Por ejemplo, los diffs del índice al árbol de trabajo nunca pueden tener entradas Añadidas (porque el conjunto de caminos incluidos en el diff está limitado por lo que está en el índice). De manera similar, las entradas copiadas y renombradas no pueden aparecer si la detección para esos tipos está desactivada.

## Referencias

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? o ¿quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, potenciados por las herramientas comunitarias **más avanzadas**.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
