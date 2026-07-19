# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces son la funcionalidad del kernel que hace que un contenedor parezca "su propia máquina", aunque en realidad solo sea un árbol de procesos del host. No crean un kernel nuevo ni virtualizan todo, pero permiten que el kernel presente diferentes vistas de recursos seleccionados a distintos grupos de procesos. Ese es el núcleo de la ilusión del contenedor: la carga de trabajo ve un sistema de archivos, una tabla de procesos, una pila de red, un hostname, recursos IPC y un modelo de identidad de usuarios/grupos que parecen locales, aunque el sistema subyacente sea compartido.

Por eso namespaces son el primer concepto con el que se encuentra la mayoría de las personas al aprender cómo funcionan los contenedores. Al mismo tiempo, son uno de los conceptos más malinterpretados, porque los lectores suelen asumir que "tener namespaces" significa "estar aislado de forma segura". En realidad, un namespace solo aísla la clase específica de recursos para la que fue diseñado. Un proceso puede tener un namespace de PID privado y seguir siendo peligroso porque tiene un bind mount del host con permisos de escritura. Puede tener un namespace de red privado y seguir siendo peligroso porque conserva `CAP_SYS_ADMIN` y se ejecuta sin seccomp. Namespaces son fundamentales, pero solo constituyen una capa del límite final.

## Tipos de namespace

Los contenedores Linux suelen depender de varios tipos de namespace al mismo tiempo. El **mount namespace** proporciona al proceso una tabla de montajes independiente y, por tanto, una vista controlada del sistema de archivos. El **PID namespace** cambia la visibilidad y numeración de los procesos, de modo que la carga de trabajo ve su propio árbol de procesos. El **network namespace** aísla interfaces, rutas, sockets y el estado del firewall. El **IPC namespace** aísla IPC de SysV y las colas de mensajes POSIX. El **UTS namespace** aísla el hostname y el nombre de dominio NIS. El **user namespace** remapea los IDs de usuarios y grupos, de modo que root dentro del contenedor no significa necesariamente root en el host. El **cgroup namespace** virtualiza la jerarquía de cgroups visible, y el **time namespace** virtualiza determinados relojes en kernels más recientes.

Cada uno de estos namespaces resuelve un problema diferente. Por eso el análisis práctico de la seguridad de contenedores suele consistir en comprobar **qué namespaces están aislados** y **cuáles se han compartido deliberadamente con el host**.

## Compartición de namespaces del host

Muchos container breakouts no comienzan con una vulnerabilidad del kernel. Comienzan cuando un operador debilita deliberadamente el modelo de aislamiento. Los ejemplos `--pid=host`, `--network=host` y `--userns=host` son **flags de CLI al estilo Docker/Podman** utilizados aquí como ejemplos concretos de compartición de namespaces del host. Otros runtimes expresan la misma idea de forma diferente. En Kubernetes, los equivalentes suelen aparecer como ajustes del Pod, como `hostPID: true`, `hostNetwork: true` o `hostIPC: true`. En stacks de runtime de nivel inferior, como containerd o CRI-O, normalmente se alcanza el mismo comportamiento mediante la configuración de runtime OCI generada, en lugar de mediante un flag orientado al usuario con el mismo nombre. En todos estos casos, el resultado es similar: la carga de trabajo deja de recibir la vista de namespaces aislada predeterminada.

Por eso las revisiones de namespaces nunca deben detenerse en "el proceso está en algún namespace". La pregunta importante es si el namespace es privado para el contenedor, compartido con contenedores hermanos o unido directamente al host. En Kubernetes, la misma idea aparece con flags como `hostPID`, `hostNetwork` y `hostIPC`. Los nombres cambian entre plataformas, pero el patrón de riesgo es el mismo: un namespace del host compartido hace que los privilegios restantes del contenedor y el estado accesible del host sean mucho más relevantes.

## Inspección

La descripción general más sencilla es:
```bash
ls -l /proc/self/ns
```
Cada entrada es un enlace simbólico con un identificador similar a un inode. Si dos procesos apuntan al mismo identificador de namespace, están en el mismo namespace de ese tipo. Esto hace que `/proc` sea un lugar muy útil para comparar el proceso actual con otros procesos interesantes de la máquina.

Estos comandos rápidos suelen ser suficientes para empezar:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Desde ahí, el siguiente paso es comparar el proceso del container con los procesos del host o de containers vecinos y determinar si un namespace es realmente privado o no.

### Enumerating Namespace Instances From The Host

Cuando ya tienes acceso al host y quieres saber cuántos namespaces distintos de un tipo determinado existen, `/proc` ofrece un inventario rápido:
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
Estos comandos son útiles porque permiten determinar si un host ejecuta un workload aislado, varios workloads aislados o una combinación de instancias de namespace compartidas y privadas.

### Entrar en un namespace objetivo

Cuando el proceso que realiza la llamada tiene privilegios suficientes, `nsenter` es la forma estándar de unirse al namespace de otro proceso:
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
El objetivo de enumerar estas formas juntas no es que cada assessment necesite todas, sino que el post-exploitation específico de un namespace a menudo se vuelve mucho más sencillo cuando el operador conoce la sintaxis exacta de entrada, en lugar de recordar únicamente la forma para todos los namespaces.

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

Mientras las lees, ten presentes dos ideas. Primero, cada namespace aísla únicamente un tipo de vista. Segundo, un namespace privado solo es útil si el resto del modelo de privilegios sigue haciendo significativo ese aislamiento.

## Valores predeterminados del runtime

| Runtime / plataforma | Configuración predeterminada de los namespaces | Debilitamiento manual común |
| --- | --- | --- |
| Docker Engine | Nuevos namespaces de mount, PID, network, IPC y UTS de forma predeterminada; los user namespaces están disponibles, pero no se habilitan de forma predeterminada en configuraciones rootful estándar | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Nuevos namespaces de forma predeterminada; Podman rootless utiliza automáticamente un user namespace; los valores predeterminados del cgroup namespace dependen de la versión de cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Los Pods **no** comparten de forma predeterminada los namespaces de PID, network o IPC del host; el networking del Pod es privado para el Pod, no para cada container individual; los user namespaces se habilitan de forma opcional mediante `spec.hostUsers: false` en clusters compatibles | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitir la habilitación del user namespace, configuraciones de workloads privilegiados |
| containerd / CRI-O bajo Kubernetes | Normalmente siguen los valores predeterminados de los Pods de Kubernetes | igual que en la fila de Kubernetes; las especificaciones CRI/OCI directas también pueden solicitar uniones a los namespaces del host |

La principal regla de portabilidad es sencilla: el **concepto** de compartir namespaces del host es común entre los runtimes, pero la **sintaxis** es específica de cada runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
