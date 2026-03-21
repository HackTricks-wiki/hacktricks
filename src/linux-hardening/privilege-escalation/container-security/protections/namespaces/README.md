# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces son la característica del kernel que hace que un container parezca "su propia máquina" aunque en realidad sea solo un árbol de procesos del host. No crean un nuevo kernel ni virtualizan todo, pero permiten al kernel presentar distintas vistas de recursos seleccionados a diferentes grupos de procesos. Esa es la esencia de la ilusión del container: la workload ve un sistema de archivos, tabla de procesos, pila de red, hostname, recursos IPC y un modelo de identidad de usuario/grupo que parecen locales, aunque el sistema subyacente esté compartido.

Por eso namespaces son el primer concepto que la mayoría encuentra al aprender cómo funcionan los containers. Al mismo tiempo, son uno de los conceptos más malentendidos porque los lectores a menudo asumen que "tiene namespaces" significa "está aislado de forma segura". En realidad, un namespace solo aísla la clase específica de recursos para la que fue diseñado. Un proceso puede tener un PID namespace privado y seguir siendo peligroso porque tiene un host bind mount escribible. Puede tener un network namespace privado y seguir siendo peligroso porque conserva `CAP_SYS_ADMIN` y se ejecuta sin seccomp. Los namespaces son fundamentales, pero son solo una capa en la frontera final.

## Namespace Types

Linux containers suelen apoyarse en varios tipos de namespace al mismo tiempo. El **mount namespace** proporciona al proceso una tabla de mounts separada y, por tanto, una vista controlada del sistema de archivos. El **PID namespace** cambia la visibilidad y la numeración de procesos para que la workload vea su propio árbol de procesos. El **network namespace** aísla interfaces, rutas, sockets y el estado del firewall. El **IPC namespace** aísla SysV IPC y las colas de mensajes POSIX. El **UTS namespace** aísla el hostname y el NIS domain name. El **user namespace** remapea los user y group IDs de modo que root dentro del container no implica necesariamente root en el host. El **cgroup namespace** virtualiza la jerarquía de cgroup visible, y el **time namespace** virtualiza relojes seleccionados en kernels más recientes.

Cada uno de estos namespaces resuelve un problema distinto. Por eso el análisis práctico de la seguridad en containers a menudo se reduce a comprobar **qué namespaces están aislados** y **cuáles se han compartido deliberadamente con el host**.

## Host Namespace Sharing

Muchas container breakouts no comienzan con una vulnerabilidad del kernel. Comienzan con un operador que debilita deliberadamente el modelo de aislamiento. Los ejemplos `--pid=host`, `--network=host`, y `--userns=host` son **Docker/Podman-style CLI flags** usados aquí como ejemplos concretos de host namespace sharing. Otros runtimes expresan la misma idea de manera diferente. En Kubernetes los equivalentes suelen aparecer como settings del Pod tales como `hostPID: true`, `hostNetwork: true`, o `hostIPC: true`. En stacks de runtime de bajo nivel como containerd o CRI-O, el mismo comportamiento a menudo se alcanza a través de la configuración runtime OCI generada en lugar de mediante una flag visible para el usuario con el mismo nombre. En todos estos casos, el resultado es similar: la workload ya no recibe la vista por defecto de namespaces aislados.

Por eso las revisiones de namespaces nunca deben quedarse en "el proceso está en algún namespace". La pregunta importante es si el namespace es privado para el container, compartido con containers hermanos, o unido directamente al host. En Kubernetes la misma idea aparece con flags como `hostPID`, `hostNetwork`, y `hostIPC`. Los nombres cambian entre plataformas, pero el patrón de riesgo es el mismo: un host namespace compartido hace que los privilegios restantes del container y el estado del host accesible sean mucho más significativos.

## Inspection

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
A partir de ahí, el siguiente paso es comparar el container process con procesos del host o procesos vecinos y determinar si un namespace es realmente privado o no.

### Enumerando instancias de namespace desde el host

Cuando ya tienes acceso al host y quieres entender cuántos namespace distintos de un tipo dado existen, `/proc` ofrece un inventario rápido:
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
Si quieres encontrar qué procesos pertenecen a un identificador de namespace específico, cambia de `readlink` a `ls -l` y usa grep para el número de namespace objetivo:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Estos comandos son útiles porque permiten determinar si un host está ejecutando una única carga de trabajo aislada, varias cargas de trabajo aisladas, o una mezcla de instancias de espacios de nombres compartidos y privados.

### Entrar en un espacio de nombres objetivo

Cuando el proceso que invoca tiene privilegios suficientes, `nsenter` es la forma estándar de unirse al espacio de nombres de otro proceso:
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
El propósito de listar estas formas juntas no es que cada evaluación requiera todas ellas, sino que la post-exploitation específica de namespace a menudo se vuelve mucho más fácil una vez que el operador conoce la sintaxis de entrada exacta en lugar de recordar solo la forma para todos los namespaces.

## Pages

Las páginas siguientes explican cada namespace con más detalle:

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

Al leerlas, ten en cuenta dos ideas. Primero, cada namespace aísla solo un tipo de vista. Segundo, un namespace privado es útil solo si el resto del modelo de privilegios sigue haciendo que ese aislamiento sea significativo.

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | Nuevos namespaces de mount, PID, network, IPC y UTS por defecto; los user namespaces están disponibles pero no están habilitados por defecto en setups rootful estándar | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Nuevos namespaces por defecto; rootless Podman usa automáticamente un user namespace; los valores por defecto del cgroup namespace dependen de la versión de cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Los Pods do **not** share host PID, network, or IPC by default; el networking del Pod es privado para el Pod, no para cada contenedor individual; los user namespaces son opt-in via `spec.hostUsers: false` en clusters soportados | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Por lo general siguen los valores por defecto de los Pods de Kubernetes | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

La regla principal de portabilidad es simple: el **concepto** de compartir namespaces del host es común entre runtimes, pero la **sintaxis** es específica de cada runtime.
