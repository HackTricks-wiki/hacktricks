# Espacios de nombres

{{#include ../../../../../banners/hacktricks-training.md}}

Los espacios de nombres son la característica del kernel que hace que un contenedor parezca "su propia máquina" a pesar de que en realidad es solo un árbol de procesos del host. No crean un kernel nuevo ni virtualizan todo, pero permiten que el kernel presente vistas distintas de recursos seleccionados a diferentes grupos de procesos. Esa es la base de la ilusión del contenedor: la carga de trabajo ve un sistema de archivos, tabla de procesos, pila de red, hostname, recursos IPC y un modelo de identidad de usuario/grupo que parecen locales, aunque el sistema subyacente esté compartido.

Por eso los espacios de nombres son el primer concepto que la mayoría encuentra al aprender cómo funcionan los contenedores. Al mismo tiempo, son uno de los conceptos más malinterpretados porque los lectores suelen asumir que "tiene namespaces" significa "está aislado de forma segura". En realidad, un espacio de nombres solo aísla la clase específica de recursos para la que fue diseñado. Un proceso puede tener un PID namespace privado y seguir siendo peligroso porque tiene un bind mount escribible del host. Puede tener un network namespace privado y seguir siendo peligroso porque retiene `CAP_SYS_ADMIN` y se ejecuta sin seccomp. Los namespaces son fundamentales, pero solo son una capa dentro del límite final.

## Tipos de espacios de nombres

Los contenedores Linux suelen apoyarse simultáneamente en varios tipos de namespaces. El **mount namespace** da al proceso una tabla de mounts separada y, por tanto, una vista controlada del filesystem. El **PID namespace** cambia la visibilidad y numeración de procesos para que la carga de trabajo vea su propio árbol de procesos. El **network namespace** aísla interfaces, rutas, sockets y el estado del firewall. El **IPC namespace** aísla SysV IPC y las colas de mensajes POSIX. El **UTS namespace** aísla el hostname y el NIS domain name. El **user namespace** remapea los IDs de usuario y grupo para que root dentro del contenedor no signifique necesariamente root en el host. El **cgroup namespace** virtualiza la jerarquía de cgroups visible, y el **time namespace** virtualiza relojes seleccionados en kernels más recientes.

Cada uno de estos namespaces resuelve un problema distinto. Por eso el análisis práctico de seguridad de contenedores a menudo se reduce a comprobar **qué namespaces están aislados** y **cuáles se han compartido deliberadamente con el host**.

## Compartición de espacios de nombres con el host

Muchas evasiones de contenedores no comienzan con una vulnerabilidad del kernel. Comienzan con un operador debilitando deliberadamente el modelo de aislamiento. Los ejemplos `--pid=host`, `--network=host`, y `--userns=host` son **Docker/Podman-style CLI flags** usadas aquí como ejemplos concretos de compartición de namespaces con el host. Otros runtimes expresan la misma idea de forma distinta. En Kubernetes los equivalentes suelen aparecer como ajustes de Pod como `hostPID: true`, `hostNetwork: true`, o `hostIPC: true`. En stacks de runtime de más bajo nivel, como containerd o CRI-O, el mismo comportamiento suele alcanzarse mediante la configuración OCI generada en lugar de a través de una flag orientada al usuario con el mismo nombre. En todos estos casos, el resultado es similar: la carga de trabajo deja de recibir la vista por defecto de namespaces aislados.

Por eso las revisiones de namespaces nunca deberían quedar en "el proceso está en algún namespace". La pregunta importante es si el namespace es privado para el contenedor, compartido con contenedores hermanos o unido directamente al host. En Kubernetes la misma idea aparece con flags como `hostPID`, `hostNetwork` y `hostIPC`. Los nombres cambian entre plataformas, pero el patrón de riesgo es el mismo: un namespace compartido con el host hace que los privilegios restantes del contenedor y el estado del host alcanzable sean mucho más relevantes.

## Inspección

La visión general más simple es:
```bash
ls -l /proc/self/ns
```
Cada entrada es un enlace simbólico con un identificador similar a un inode. Si dos procesos apuntan al mismo identificador de namespace, están en el mismo namespace de ese tipo. Eso hace que `/proc` sea un lugar muy útil para comparar el proceso actual con otros procesos interesantes en la máquina.

Estos comandos rápidos suelen ser suficientes para empezar:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
A partir de ahí, el siguiente paso es comparar el proceso del container con procesos del host o vecinos y determinar si un namespace es realmente privado o no.

### Enumerando instancias de Namespace desde el Host

Cuando ya tienes acceso al host y quieres entender cuántos namespace distintos de un tipo dado existen, `/proc` proporciona un inventario rápido:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
Si quieres encontrar qué procesos pertenecen a un identificador de namespace específico, cambia de `readlink` a `ls -l` y usa grep para buscar el número de namespace objetivo:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Estos comandos son útiles porque te permiten saber si un host está ejecutando una sola workload aislada, varias workloads aisladas, o una mezcla de instancias con namespace compartidos y privados.

### Entrando en un namespace objetivo

Cuando el proceso que llama tiene privilegios suficientes, `nsenter` es la forma estándar de unirse al namespace de otro proceso:
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
El objetivo de listar estas formas juntas no es que cada evaluación necesite todas ellas, sino que la post-exploitation específica por namespace suele volverse mucho más sencilla una vez que el operador conoce la sintaxis exacta de entrada en lugar de recordar solo la forma para todos los namespaces.

## Páginas

Las siguientes páginas explican cada namespace con más detalle:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

Mientras las lees, ten en cuenta dos ideas. Primero, cada namespace aísla solo un tipo de vista. Segundo, un namespace privado solo es útil si el resto del modelo de privilegios sigue haciendo que ese aislamiento tenga sentido.

## Valores predeterminados de runtime

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | Nuevos mount, PID, network, IPC y UTS namespaces por defecto; los user namespaces están disponibles pero no habilitados por defecto en setups rootful estándar | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Nuevos namespaces por defecto; rootless Podman usa automáticamente un user namespace; los defaults del cgroup namespace dependen de la versión de cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Los Pods **no** comparten el PID, network o IPC del host por defecto; la red de Pod es privada para el Pod, no para cada contenedor individual; los user namespaces son opt-in vía `spec.hostUsers: false` en clusters compatibles | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitiendo la opción de user-namespace, configuraciones de workloads privilegiados |
| containerd / CRI-O under Kubernetes | Usualmente siguen los valores predeterminados de Pods de Kubernetes | mismo que la fila de Kubernetes; las especificaciones CRI/OCI directas también pueden solicitar unirse a namespaces del host |

La regla principal de portabilidad es sencilla: el **concepto** de compartir namespaces del host es común entre runtimes, pero la **sintaxis** es específica de cada runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
