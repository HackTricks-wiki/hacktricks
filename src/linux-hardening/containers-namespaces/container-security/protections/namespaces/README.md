# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces son la funcionalidad del kernel que hace que un contenedor parezca "su propia máquina", aunque en realidad solo sea un árbol de procesos del host. No crean un kernel nuevo ni virtualizan todo, pero permiten que el kernel presente diferentes vistas de recursos seleccionados a distintos grupos de procesos. Ese es el núcleo de la ilusión del contenedor: el workload ve un sistema de archivos, una tabla de procesos, una pila de red, un hostname, recursos IPC y un modelo de identidad de usuarios/grupos que parecen locales, aunque el sistema subyacente sea compartido.

Por eso namespaces son el primer concepto con el que se encuentra la mayoría de la gente cuando aprende cómo funcionan los contenedores. Al mismo tiempo, son uno de los conceptos más malinterpretados, porque a menudo se asume que "tener namespaces" significa "estar aislado de forma segura". En realidad, un namespace solo aísla la clase específica de recursos para la que fue diseñado. Un proceso puede tener un namespace de PID privado y seguir siendo peligroso porque tiene un bind mount del host con permisos de escritura. Puede tener un namespace de red privado y seguir siendo peligroso porque conserva `CAP_SYS_ADMIN` y se ejecuta sin seccomp. Namespaces son fundamentales, pero solo constituyen una capa del boundary final.

## Tipos de Namespace

Los contenedores Linux suelen depender de varios tipos de namespace al mismo tiempo. El **mount namespace** proporciona al proceso una tabla de montajes independiente y, por tanto, una vista controlada del sistema de archivos. El **PID namespace** modifica la visibilidad y numeración de los procesos para que el workload vea su propio árbol de procesos. El **network namespace** aísla interfaces, rutas, sockets y el estado del firewall. El **IPC namespace** aísla SysV IPC y las colas de mensajes POSIX. El **UTS namespace** aísla el hostname y el nombre de dominio NIS. El **user namespace** remapea los IDs de usuarios y grupos, de modo que root dentro del contenedor no necesariamente significa root en el host. El **cgroup namespace** virtualiza la jerarquía de cgroups visible, y el **time namespace** virtualiza determinados relojes en los kernels más recientes.

Cada uno de estos namespaces resuelve un problema diferente. Por eso el análisis práctico de container security suele reducirse a comprobar **qué namespaces están aislados** y **cuáles se han compartido deliberadamente con el host**.

## Compartición de Namespaces del Host

Muchos container breakouts no comienzan con una vulnerabilidad del kernel. Comienzan cuando un operador debilita deliberadamente el modelo de aislamiento. Los ejemplos `--pid=host`, `--network=host` y `--userns=host` son **flags de CLI de estilo Docker/Podman** utilizados aquí como ejemplos concretos de compartición de namespaces del host. Otros runtimes expresan la misma idea de forma diferente. En Kubernetes, los equivalentes suelen aparecer como ajustes del Pod, como `hostPID: true`, `hostNetwork: true` o `hostIPC: true`. En stacks de runtime de nivel inferior, como containerd o CRI-O, normalmente se alcanza el mismo comportamiento mediante la configuración de runtime OCI generada, en lugar de mediante un flag orientado al usuario con el mismo nombre. En todos estos casos, el resultado es similar: el workload deja de recibir la vista de namespace aislada predeterminada.

Por eso las revisiones de namespaces nunca deben detenerse en "el proceso está en algún namespace". La pregunta importante es si el namespace es privado del contenedor, compartido con contenedores hermanos o unido directamente al host. En Kubernetes, la misma idea aparece con flags como `hostPID`, `hostNetwork` y `hostIPC`. Los nombres cambian entre plataformas, pero el patrón de riesgo es el mismo: un namespace compartido con el host hace que los privilegios restantes del contenedor y el estado del host que puede alcanzar sean mucho más relevantes.

## Inspección

La vista general más sencilla es:
```bash
ls -l /proc/self/ns
```
Cada entrada es un enlace simbólico con un identificador similar a un inode. Si dos procesos apuntan al mismo identificador de namespace, están en el mismo namespace de ese tipo. Esto hace que `/proc` sea un lugar muy útil para comparar el proceso actual con otros procesos interesantes de la máquina.

Estos comandos rápidos suelen ser suficientes para comenzar:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Desde ahí, el siguiente paso consiste en comparar el proceso del container con los procesos del host o de containers vecinos y determinar si un namespace es realmente privado o no.

### Enumeración de instancias de namespaces desde el host

Cuando ya tienes acceso al host y quieres saber cuántos namespaces distintos de un tipo determinado existen, `/proc` proporciona un inventario rápido:
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
Si quieres averiguar qué procesos pertenecen a un identificador de namespace específico, cambia de `readlink` a `ls -l` y busca con grep el número de namespace objetivo:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Estos comandos son útiles porque permiten determinar si un host ejecuta una carga de trabajo aislada, varias cargas de trabajo aisladas o una combinación de instancias de namespaces compartidas y privadas.

### Entrar en el namespace de destino

Cuando el caller tiene privilegios suficientes, `nsenter` es la forma estándar de unirse al namespace de otro proceso:
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
El objetivo de enumerar estas formas juntas no es que cada assessment necesite todas, sino que el post-exploitation específico de un namespace suele ser mucho más sencillo cuando el operador conoce la sintaxis exacta de entrada, en lugar de recordar únicamente la forma all-namespaces.

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

Mientras las lees, ten presentes dos ideas. Primero, cada namespace aísla únicamente un tipo de vista. Segundo, un namespace privado solo es útil si el resto del modelo de privilegios sigue haciendo que ese aislamiento sea significativo.

## Valores predeterminados del runtime

| Runtime / plataforma | Configuración predeterminada de los namespaces | Debilitamiento manual común |
| --- | --- | --- |
| Docker Engine | Nuevos namespaces de mount, PID, network, IPC y UTS de forma predeterminada; los user namespaces están disponibles, pero no están habilitados de forma predeterminada en configuraciones rootful estándar | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Nuevos namespaces de forma predeterminada; Podman rootless utiliza automáticamente un user namespace; los valores predeterminados del cgroup namespace dependen de la versión de cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Los Pods **no** comparten los namespaces de PID, network o IPC del host de forma predeterminada; el networking del Pod es privado para el Pod, no para cada container individual; los user namespaces se habilitan de forma opt-in mediante `spec.hostUsers: false` en clusters compatibles | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitir el opt-in del user namespace, configuraciones de workloads privilegiados |
| containerd / CRI-O bajo Kubernetes | Normalmente siguen los valores predeterminados de los Pods de Kubernetes | igual que en la fila de Kubernetes; las especificaciones CRI/OCI directas también pueden solicitar joins a namespaces del host |

La regla principal de portabilidad es sencilla: el **concepto** de compartir namespaces del host es común entre runtimes, pero la **sintaxis** es específica de cada runtime.

{{#include ../../../../../banners/hacktricks-training.md}}
