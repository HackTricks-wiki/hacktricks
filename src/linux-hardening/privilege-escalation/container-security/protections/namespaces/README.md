# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces son la característica del kernel que hace que un container se perciba como "su propia máquina" aunque en realidad sea solo un árbol de procesos del host. No crean un kernel nuevo ni virtualizan todo, pero permiten que el kernel presente vistas distintas de recursos seleccionados a diferentes grupos de procesos. Esa es la esencia de la ilusión del container: la carga de trabajo ve un sistema de archivos, tabla de procesos, pila de red, nombre de host, recursos IPC y un modelo de identidad de usuario/grupo que parecen locales, aunque el sistema subyacente se comparte.

Por eso los namespaces son el primer concepto con el que la mayoría se encuentra al aprender cómo funcionan los containers. Al mismo tiempo, son uno de los conceptos más malinterpretados porque los lectores a menudo asumen que "tiene namespaces" significa "está aislado de forma segura". En realidad, un namespace solo aísla la clase específica de recursos para la que fue diseñado. Un proceso puede tener un PID namespace privado y aun así ser peligroso porque tiene un host bind mount escribible. Puede tener un network namespace privado y aun así ser peligroso porque conserva `CAP_SYS_ADMIN` y se ejecuta sin seccomp. Los namespaces son fundamentales, pero solo son una capa en el límite final.

## Namespace Types

Linux containers suelen apoyarse en varios tipos de namespace al mismo tiempo. El **mount namespace** proporciona al proceso una tabla de mounts separada y, por tanto, una vista controlada del sistema de archivos. El **PID namespace** cambia la visibilidad y la numeración de procesos para que la carga de trabajo vea su propio árbol de procesos. El **network namespace** aísla interfaces, rutas, sockets y el estado del firewall. El **IPC namespace** aísla SysV IPC y las colas de mensajes POSIX. El **UTS namespace** aísla el hostname y el NIS domain name. El **user namespace** remapea los IDs de usuario y grupo para que root dentro del container no signifique necesariamente root en el host. El **cgroup namespace** virtualiza la jerarquía de cgroups visible, y el **time namespace** virtualiza relojes seleccionados en kernels más recientes.

Cada uno de estos namespaces resuelve un problema distinto. Por eso, el análisis práctico de seguridad de containers suele reducirse a comprobar **qué namespaces están aislados** y **cuáles se han compartido deliberadamente con el host**.

## Host Namespace Sharing

Muchos breakouts de container no comienzan con una vulnerabilidad del kernel. Comienzan con un operador que debilita deliberadamente el modelo de aislamiento. Los ejemplos `--pid=host`, `--network=host` y `--userns=host` son **banderas CLI al estilo Docker/Podman** usadas aquí como ejemplos concretos de compartición de namespaces con el host. Otros runtimes expresan la misma idea de manera distinta. En Kubernetes los equivalentes suelen aparecer como ajustes de Pod como `hostPID: true`, `hostNetwork: true` o `hostIPC: true`. En pilas de runtime de bajo nivel como containerd o CRI-O, el mismo comportamiento suele alcanzarse mediante la configuración de runtime OCI generada en lugar de mediante una flag orientada al usuario con el mismo nombre. En todos estos casos, el resultado es similar: la carga de trabajo deja de recibir la vista de namespaces aislada por defecto.

Por eso las revisiones de namespaces nunca deberían detenerse en "el proceso está en algún namespace". La pregunta importante es si el namespace es privado para el container, compartido con contenedores hermanos o unido directamente al host. En Kubernetes la misma idea aparece con flags como `hostPID`, `hostNetwork` y `hostIPC`. Los nombres cambian entre plataformas, pero el patrón de riesgo es el mismo: un namespace del host compartido hace que los privilegios restantes del container y el estado del host alcanzable cobren mucho más importancia.

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
A partir de ahí, el siguiente paso es comparar el proceso del container con procesos del host o vecinos y determinar si un namespace es realmente privado o no.

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
Si quieres encontrar qué procesos pertenecen a un identificador de namespace específico, cambia de `readlink` a `ls -l` y haz grep del número de namespace objetivo:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Estos comandos son útiles porque permiten determinar si un host está ejecutando una única carga de trabajo aislada, varias cargas de trabajo aisladas, o una mezcla de instancias de namespace compartidas y privadas.

### Entrar en un namespace objetivo

Cuando quien invoca tiene privilegios suficientes, `nsenter` es la forma estándar de unirse al namespace de otro proceso:
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
El objetivo de listar estas formas juntas no es que cada evaluación necesite todas ellas, sino que el post-exploitation específico de namespace a menudo se vuelve mucho más fácil una vez que el operador conoce la sintaxis de entrada exacta en lugar de recordar solo la forma all-namespaces.

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

Al leerlas, tenga en cuenta dos ideas. Primero, cada namespace aísla solo un tipo de vista. Segundo, un namespace privado solo es útil si el resto del modelo de privilegios sigue haciendo que ese aislamiento sea significativo.

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | New mount, PID, network, IPC, and UTS namespaces by default; user namespaces are available but not enabled by default in standard rootful setups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | New namespaces by default; rootless Podman automatically uses a user namespace; cgroup namespace defaults depend on cgroup version | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Usually follow Kubernetes Pod defaults | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

La regla principal de portabilidad es simple: el concepto de compartir namespaces del host es común entre runtimes, pero la sintaxis es específica del runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
