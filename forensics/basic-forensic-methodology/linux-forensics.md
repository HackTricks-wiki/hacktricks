# Forense en Linux

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** con las herramientas de la comunidad **más avanzadas** del mundo.\
Obtenga acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabaja en una **empresa de ciberseguridad**? ¿Quiere ver su **empresa anunciada en HackTricks**? ¿O quiere tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenga el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únase al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígame** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparta sus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Recopilación de información inicial

### Información básica

En primer lugar, se recomienda tener una **USB** con **binarios y bibliotecas bien conocidos** (puede obtener Ubuntu y copiar las carpetas _/bin_, _/sbin_, _/lib_ y _/lib64_), luego montar la USB y modificar las variables de entorno para usar esos binarios:
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

Mientras se obtiene la información básica, se debe revisar cosas extrañas como:

* **Procesos root** que generalmente se ejecutan con PIDs bajos, por lo que si encuentras un proceso root con un PID grande, puedes sospechar.
* Revisa los **inicios de sesión registrados** de usuarios sin shell dentro de `/etc/passwd`.
* Revisa los **hashes de contraseñas** dentro de `/etc/shadow` para usuarios sin shell.

### Volcado de memoria

Para obtener la memoria del sistema en ejecución, se recomienda usar [**LiME**](https://github.com/504ensicsLabs/LiME).

Para **compilarlo**, necesitas usar el **mismo kernel** que está usando la máquina víctima.

{% hint style="info" %}
Recuerda que **no puedes instalar LiME o cualquier otra cosa** en la máquina víctima, ya que esto hará varios cambios en ella.
{% endhint %}

Entonces, si tienes una versión idéntica de Ubuntu, puedes usar `apt-get install lime-forensics-dkms`.\
En otros casos, necesitas descargar [**LiME**](https://github.com/504ensicsLabs/LiME) desde github y compilarlo con los encabezados de kernel correctos. Para **obtener los encabezados de kernel exactos** de la máquina víctima, simplemente puedes **copiar el directorio** `/lib/modules/<versión del kernel>` a tu máquina, y luego **compilar** LiME usando estos.
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME admite 3 **formatos**:

* Raw (todos los segmentos concatenados juntos)
* Padded (igual que Raw, pero con ceros en los bits derechos)
* Lime (formato recomendado con metadatos)

LiME también se puede utilizar para **enviar el volcado a través de la red** en lugar de almacenarlo en el sistema usando algo como: `path=tcp:4444`

### Imagen de disco

#### Apagado

En primer lugar, deberá **apagar el sistema**. Esto no siempre es una opción ya que a veces el sistema será un servidor de producción que la empresa no puede permitirse apagar.\
Hay **2 formas** de apagar el sistema, un **apagado normal** y un **apagado "desenchufando"**. El primero permitirá que los **procesos terminen como de costumbre** y que el **sistema de archivos** se **sincronice**, pero también permitirá que el posible **malware** **destruya evidencia**. El enfoque de "desenchufar" puede llevar a **alguna pérdida de información** (no se perderá mucha información ya que ya tomamos una imagen de la memoria) y el **malware no tendrá ninguna oportunidad** de hacer nada al respecto. Por lo tanto, si **sospecha** que puede haber un **malware**, simplemente ejecute el **comando `sync`** en el sistema y desenchufe.

#### Tomando una imagen del disco

Es importante tener en cuenta que **antes de conectar su computadora a cualquier cosa relacionada con el caso**, debe asegurarse de que se va a **montar como solo lectura** para evitar modificar cualquier información.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Preanálisis de la imagen de disco

Crear una imagen de disco sin más datos.
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
![](<../../.gitbook/assets/image (9) (1) (2).png>)

Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y automatizar fácilmente flujos de trabajo impulsados por las herramientas comunitarias más avanzadas del mundo.\
Obtenga acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Buscar Malware conocido

### Archivos del sistema modificados

Algunos sistemas Linux tienen una función para verificar la integridad de muchos componentes instalados, proporcionando una forma efectiva de identificar archivos inusuales o fuera de lugar. Por ejemplo, `rpm -Va` en Linux está diseñado para verificar todos los paquetes que se instalaron usando RedHat Package Manager.
```bash
#RedHat
rpm -Va
#Debian
dpkg --verify
debsums | grep -v "OK$" #apt-get install debsums
```
### Detectores de Malware/Rootkit

Lee la siguiente página para aprender sobre herramientas que pueden ser útiles para encontrar malware:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Buscar programas instalados

### Gestor de paquetes

En sistemas basados en Debian, el archivo _**/var/lib/dpkg/status**_ contiene detalles sobre los paquetes instalados y el archivo _**/var/log/dpkg.log**_ registra información cuando se instala un paquete.\
En distribuciones de Linux RedHat y relacionadas, el comando **`rpm -qa --root=/ mntpath/var/lib/rpm`** mostrará el contenido de una base de datos RPM en un sistema.
```bash
#Debian
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
#RedHat
rpm -qa --root=/ mntpath/var/lib/rpm
```
### Otros

**No todos los programas instalados se listarán con los comandos anteriores** porque algunas aplicaciones no están disponibles como paquetes para ciertos sistemas y deben ser instaladas desde la fuente. Por lo tanto, una revisión de ubicaciones como _**/usr/local**_ y _**/opt**_ puede revelar otras aplicaciones que han sido compiladas e instaladas desde el código fuente.
```bash
ls /opt /usr/local
```
Otra buena idea es **verificar** las **carpetas comunes** dentro de **$PATH** en busca de **binarios no relacionados** con **paquetes instalados:**
```bash
#Both lines are going to print the executables in /sbin non related to installed packages
#Debian
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
#RedHat
find /sbin/ –exec rpm -qf {} \; | grep "is not"
```
![](<../../.gitbook/assets/image (9) (1) (2).png>)

Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y automatizar fácilmente flujos de trabajo impulsados por las herramientas de la comunidad más avanzadas del mundo.\
Obtenga acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recuperar Binarios en Ejecución Eliminados

![](<../../.gitbook/assets/image (641).png>)

## Inspeccionar ubicaciones de inicio automático

### Tareas Programadas
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

Es extremadamente común que el malware se enraíce como un nuevo servicio no autorizado. Linux tiene varios scripts que se utilizan para iniciar servicios cuando la computadora se inicia. El script de inicio de inicialización _**/etc/inittab**_ llama a otros scripts como rc.sysinit y varios scripts de inicio en el directorio _**/etc/rc.d/**_, o _**/etc/rc.boot/**_ en algunas versiones antiguas. En otras versiones de Linux, como Debian, los scripts de inicio se almacenan en el directorio _**/etc/init.d/**_. Además, algunos servicios comunes se habilitan en _**/etc/inetd.conf**_ o _**/etc/xinetd/**_ dependiendo de la versión de Linux. Los investigadores digitales deben inspeccionar cada uno de estos scripts de inicio en busca de entradas anómalas.

* _**/etc/inittab**_
* _**/etc/rc.d/**_
* _**/etc/rc.boot/**_
* _**/etc/init.d/**_
* _**/etc/inetd.conf**_
* _**/etc/xinetd/**_
* _**/etc/systemd/system**_
* _**/etc/systemd/system/multi-user.target.wants/**_

### Módulos del kernel

En los sistemas Linux, los módulos del kernel se utilizan comúnmente como componentes de rootkit para paquetes de malware. Los módulos del kernel se cargan cuando el sistema se inicia en función de la información de configuración en los directorios `/lib/modules/'uname -r'` y `/etc/modprobe.d`, y el archivo `/etc/modprobe` o `/etc/modprobe.conf`. Estas áreas deben ser inspeccionadas en busca de elementos relacionados con malware.

### Otras ubicaciones de inicio automático

Existen varios archivos de configuración que Linux utiliza para lanzar automáticamente un ejecutable cuando un usuario inicia sesión en el sistema que puede contener rastros de malware.

* _**/etc/profile.d/\***_ , _**/etc/profile**_ , _**/etc/bash.bashrc**_ se ejecutan cuando cualquier cuenta de usuario inicia sesión.
* _**∼/.bashrc**_ , _**∼/.bash\_profile**_ , _**\~/.profile**_ , _**∼/.config/autostart**_ se ejecutan cuando el usuario específico inicia sesión.
* _**/etc/rc.local**_ Se ejecuta tradicionalmente después de que se inician todos los servicios normales del sistema, al final del proceso de cambio a un nivel de ejecución multiusuario.

## Examinar registros

Busque en todos los archivos de registro disponibles en el sistema comprometido rastros de ejecución maliciosa y actividades asociadas, como la creación de un nuevo servicio.

### Registros puros

Los eventos de **inicio de sesión** registrados en los registros del sistema y de seguridad, incluidos los inicios de sesión a través de la red, pueden revelar que el **malware** o un **intruso obtuvo acceso** a un sistema comprometido a través de una cuenta determinada en un momento específico. Otros eventos alrededor del momento de una infección de malware pueden capturarse en los registros del sistema, incluida la **creación** de un **nuevo servicio** o nuevas cuentas alrededor del momento de un incidente.\
Inicios de sesión del sistema interesantes:

* **/var/log/syslog** (debian) o **/var/log/messages** (Redhat)
  * Muestra mensajes y información generales sobre el sistema. Es un registro de datos de toda la actividad en todo el sistema global.
* **/var/log/auth.log** (debian) o **/var/log/secure** (Redhat)
  * Mantiene registros de autenticación tanto para inicios de sesión exitosos como fallidos y procesos de autenticación. El almacenamiento depende del tipo de sistema.
  * `cat /var/log/auth.log | grep -iE "session opened for|accepted password|new session|not in sudoers"`
* **/var/log/boot.log**: mensajes de inicio y información de inicio.
* **/var/log/maillog** o **var/log/mail.log:** es para registros del servidor de correo, útil para postfix, smtpd o información de servicios relacionados con el correo electrónico que se ejecutan en su servidor.
* **/var/log/kern.log**: mantiene los registros y advertencias del kernel. Los registros de actividad del kernel (por ejemplo, dmesg, kern.log, klog) pueden mostrar que un servicio en particular se bloqueó repetidamente, lo que indica potencialmente que se instaló una versión troyanizada inestable.
* **/var/log/dmesg**: un repositorio para mensajes de controlador de dispositivo. Use **dmesg** para ver mensajes en este archivo.
* **/var/log/faillog:** registra información sobre inicios de sesión fallidos. Por lo tanto, es útil para examinar posibles violaciones de seguridad como hackeos de credenciales de inicio de sesión y ataques de fuerza bruta.
* **/var/log/cron**: mantiene un registro de mensajes relacionados con Crond (trabajos cron). Como cuando el demonio cron inició un trabajo.
* **/var/log/daemon.log:** realiza un seguimiento de los servicios en segundo plano en ejecución, pero no los representa gráficamente.
* **/var/log/btmp**: realiza una nota de todos los intentos de inicio de sesión fallidos.
* **/var/log/httpd/**: un directorio que contiene archivos error\_log y access\_log del demonio Apache httpd. Cada error que encuentra httpd se guarda en el archivo **error\_log**. Piense en problemas de memoria y otros errores relacionados con el sistema. **access\_log** registra todas las solicitudes que llegan a través de HTTP.
* **/var/log/mysqld.log** o **/var/log/mysql.log**: archivo de registro de MySQL que registra cada mensaje de depuración, falla y éxito, incluido el inicio, detención y reinicio del demonio MySQL mysqld. El sistema decide sobre el directorio. RedHat, CentOS, Fedora y otros sistemas basados en RedHat utilizan /var/log/mariadb/mariadb.log. Sin embargo, Debian/Ubuntu utiliza el directorio /var/log/mysql/error.log.
* **/var/log/xferlog**: mantiene sesiones de transferencia de archivos FTP. Incluye información como nombres de archivo y transferencias FTP iniciadas por el usuario.
* **/var/log/\*** : Siempre debe verificar los registros inesperados en este directorio.

{% hint style="info" %}
Los registros y los subsistemas de auditoría del sistema Linux pueden estar desactivados o eliminados en un incidente de intrusión o malware. Debido a que los registros en los sistemas Linux generalmente contienen información más útil sobre actividades maliciosas, los intrusos los eliminan rutinariamente. Por lo tanto, al examinar los archivos de registro disponibles, es importante buscar lagunas o entradas fuera de orden que puedan ser una indicación de eliminación o manipulación.
{% endhint %}

### Historial de comandos

Muchos sistemas Linux están configurados para mantener un historial de comandos para cada cuenta de usuario:

* \~/.bash\_history
* \~/.history
* \~/.sh\_history
* \~/.\*\_history

### Inicios de sesión

Usando el comando `last -Faiwx` es posible obtener la lista de usuarios que han iniciado sesión.\
Se recomienda verificar si esos inicios de sesión tienen sentido:

* ¿Hay algún usuario desconocido?
* ¿Hay algún usuario que no debería tener una shell iniciada?

Esto es importante ya que los **atacantes** a veces pueden copiar `/bin/bash` dentro de `/bin/false` para que los usuarios como **lightdm** puedan **iniciar sesión**.

Tenga en cuenta que también puede **ver esta información leyendo los registros**.

### Rastros de aplicaciones

* **SSH**: Las conexiones a sistemas realizadas mediante SSH desde y hacia un sistema comprometido dan como resultado la creación de entradas en archivos para cada cuenta de usuario (_**∼/.ssh/authorized\_keys**_ y _**∼/.ssh/known\_keys**_). Estas entradas pueden revelar el nombre de host o la dirección IP de los hosts remotos.
* **Escritorio Gnome**: Las cuentas de usuario pueden tener un archivo _**∼/.recently-used.xbel**_ que contiene información sobre los archivos que se accedieron recientemente utilizando aplicaciones que se ejecutan en el escritorio Gnome.
* **VIM**: Las cuentas de usuario pueden tener un archivo _**∼/.viminfo**_ que contiene detalles sobre el uso de VIM, incluida la historia de cadenas de búsqueda y las rutas a los archivos que se abrieron con vim.
* **Open Office**: Archivos recientes.
* **MySQL**: Las cuentas de usuario pueden tener un archivo _**∼/.mysql\_history**_ que contiene consultas ejecutadas con MySQL.
* **Less**: Las cuentas de usuario pueden tener un archivo _**∼/.lesshst**_ que contiene detalles sobre el uso de less, incluida la historia de cadenas de búsqueda y los comandos de shell ejecutados a través de less.

### Registros USB

[**usbrip**](https://github.com/snovvcrash/usbrip) es un pequeño software escrito en Python 3 puro que analiza los archivos de registro de Linux (`/var/log/syslog*` o `/var/log/messages*`
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
Más ejemplos e información dentro de Github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Utilice [**Trickest**](https://trickest.io/) para construir y **automatizar flujos de trabajo** con las herramientas de la comunidad **más avanzadas** del mundo.\
Obtenga acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Revisar cuentas de usuario y actividades de inicio de sesión

Examine los archivos _**/etc/passwd**_, _**/etc/shadow**_ y los **registros de seguridad** en busca de nombres o cuentas inusuales creadas y/o utilizadas en proximidad cercana a eventos no autorizados conocidos. Además, verifique posibles ataques de fuerza bruta de sudo.\
Además, verifique archivos como _**/etc/sudoers**_ y _**/etc/groups**_ para detectar privilegios inesperados otorgados a los usuarios.\
Finalmente, busque cuentas sin contraseñas o con contraseñas **fáciles de adivinar**.

## Examinar el sistema de archivos

Las estructuras de datos del sistema de archivos pueden proporcionar cantidades sustanciales de **información** relacionada con un incidente de **malware**, incluyendo el **momento** de los eventos y el **contenido** real del **malware**.\
El **malware** se está diseñando cada vez más para **frustrar el análisis del sistema de archivos**. Algunos malware alteran las marcas de fecha y hora en los archivos maliciosos para hacer que sea más difícil encontrarlos con el análisis de la línea de tiempo. Otros códigos maliciosos están diseñados para almacenar solo cierta información en la memoria para minimizar la cantidad de datos almacenados en el sistema de archivos.\
Para lidiar con tales técnicas antiforense, es necesario prestar **atención cuidadosa al análisis de la línea de tiempo** de las marcas de fecha y hora del sistema de archivos y a los archivos almacenados en ubicaciones comunes donde se puede encontrar malware.

* Usando **autopsy** puede ver la línea de tiempo de eventos que pueden ser útiles para descubrir actividades sospechosas. También puede usar la función `mactime` de **Sleuth Kit** directamente.
* Verifique la existencia de **scripts inesperados** dentro de **$PATH** (¿tal vez algunos scripts sh o php?)
* Los archivos en `/dev` solían ser archivos especiales, puede encontrar archivos no especiales aquí relacionados con malware.
* Busque archivos y directorios inusuales o **ocultos**, como ".. " (punto punto espacio) o "..^G " (punto punto control-G)
* Copias setuid de /bin/bash en el sistema `find / -user root -perm -04000 –print`
* Revise las marcas de fecha y hora de los **inodos eliminados para grandes cantidades de archivos eliminados alrededor del mismo tiempo**, lo que podría indicar actividad maliciosa como la instalación de un rootkit o servicio troyanizado.
* Debido a que los inodos se asignan en función del siguiente disponible, **los archivos maliciosos colocados en el sistema alrededor del mismo tiempo pueden asignarse inodos consecutivos**. Por lo tanto, después de que se localiza un componente de malware, puede ser productivo inspeccionar los inodos vecinos.
* También verifique directorios como _/bin_ o _/sbin_ ya que la **hora modificada y/o cambiada** de los archivos nuevos o modificados puede ser interesante.
* Es interesante ver los archivos y carpetas de un directorio **ordenados por fecha de creación** en lugar de alfabéticamente para ver cuáles son los archivos o carpetas más recientes (los últimos suelen ser los más interesantes).

Puede verificar los archivos más recientes de una carpeta usando `ls -laR --sort=time /bin`\
Puede verificar los inodos de los archivos dentro de una carpeta usando `ls -lai /bin |sort -n`

{% hint style="info" %}
Tenga en cuenta que un **atacante** puede **modificar** la **hora** para hacer que los **archivos parezcan legítimos**, pero no puede modificar el **inodo**. Si encuentra que un **archivo** indica que se creó y modificó al **mismo tiempo** que el resto de los archivos en la misma carpeta, pero el **inodo** es **inesperadamente más grande**, entonces las **marcas de tiempo de ese archivo fueron modificadas**.
{% endhint %}

## Comparar archivos de diferentes versiones del sistema de archivos

#### Encontrar archivos agregados
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

Selecciona solo los archivos que han sido Añadidos (`A`), Copiados (`C`), Eliminados (`D`), Modificados (`M`), Renombrados (`R`), y han cambiado su tipo (es decir, archivo regular, enlace simbólico, submódulo, …​) (`T`), están sin fusionar (`U`), son Desconocidos (`X`), o han tenido su emparejamiento Roto (`B`). Se pueden usar cualquier combinación de los caracteres de filtro (incluyendo ninguno). Cuando se agrega `*` (Todo-o-nada) a la combinación, se seleccionan todos los caminos si hay algún archivo que coincida con otros criterios en la comparación; si no hay ningún archivo que coincida con otros criterios, no se selecciona nada.

Además, **estas letras mayúsculas se pueden convertir en minúsculas para excluir**. Por ejemplo, `--diff-filter=ad` excluye los caminos añadidos y eliminados.

Tenga en cuenta que no todas las diferencias pueden presentar todos los tipos. Por ejemplo, las diferencias desde el índice al árbol de trabajo nunca pueden tener entradas Añadidas (porque el conjunto de caminos incluidos en la diferencia está limitado por lo que está en el índice). De manera similar, las entradas copiadas y renombradas no pueden aparecer si la detección de esos tipos está desactivada.

## Referencias

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿o quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

**Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas de la comunidad más avanzadas del mundo.\
Obtenga acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
