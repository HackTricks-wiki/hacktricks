# Espacio de nombres PID

{{#include ../../../../banners/hacktricks-training.md}}

## Información básica

El espacio de nombres PID (Process IDentifier) es una característica del kernel de Linux que proporciona aislamiento de procesos al permitir que un grupo de procesos tenga su propio conjunto de PIDs únicos, separado de los PIDs en otros espacios de nombres. Esto es particularmente útil en la containerización, donde el aislamiento de procesos es esencial para la seguridad y la gestión de recursos.

Cuando se crea un nuevo espacio de nombres PID, al primer proceso en ese espacio se le asigna el PID 1. Este proceso se convierte en el proceso "init" del nuevo espacio de nombres y es responsable de gestionar otros procesos dentro del espacio. Cada proceso posterior creado dentro del espacio de nombres tendrá un PID único dentro de ese espacio, y estos PIDs serán independientes de los PIDs en otros espacios de nombres.

Desde la perspectiva de un proceso dentro de un espacio de nombres PID, solo puede ver a otros procesos en el mismo espacio de nombres. No es consciente de los procesos en otros espacios de nombres y no puede interactuar con ellos usando las herramientas tradicionales de gestión de procesos (p. ej., `kill`, `wait`, etc.). Esto proporciona un nivel de aislamiento que ayuda a evitar que los procesos interfieran entre sí.

### Cómo funciona:

1. Cuando se crea un nuevo proceso (p. ej., usando la llamada al sistema `clone()`), el proceso puede ser asignado a un espacio de nombres PID nuevo o existente. **Si se crea un nuevo espacio de nombres, el proceso se convierte en el proceso "init" de ese espacio de nombres**.
2. El **kernel** mantiene un **mapeo entre los PIDs en el nuevo espacio de nombres y los PIDs correspondientes** en el espacio de nombres padre (es decir, el espacio de nombres desde el cual se creó el nuevo espacio). Este mapeo **permite al kernel traducir los PIDs cuando es necesario**, como al enviar señales entre procesos en diferentes espacios de nombres.
3. **Los procesos dentro de un espacio de nombres PID solo pueden ver e interactuar con otros procesos en el mismo espacio de nombres**. No son conscientes de los procesos en otros espacios de nombres, y sus PIDs son únicos dentro de su espacio.
4. Cuando se **destruye un espacio de nombres PID** (p. ej., cuando el proceso "init" del espacio de nombres sale), **todos los procesos dentro de ese espacio de nombres son terminados**. Esto asegura que todos los recursos asociados con el espacio de nombres se limpien correctamente.

## Laboratorio:

### Crear diferentes espacios de nombres

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: No se puede asignar memoria</summary>

Cuando `unshare` se ejecuta sin la opción `-f`, se produce un error debido a la forma en que Linux maneja los nuevos espacios de nombres PID (Process ID). Los detalles clave y la solución se describen a continuación:

1. **Explicación del problema**:

- El kernel de Linux permite que un proceso cree nuevos espacios de nombres usando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo espacio de nombres PID (denominado proceso "unshare") no entra en el nuevo espacio; solo lo hacen sus procesos hijos.
- Ejecutar %unshare -p /bin/bash% inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos hijos están en el espacio de nombres PID original.
- El primer proceso hijo de `/bin/bash` en el nuevo espacio de nombres se convierte en PID 1. Cuando este proceso termina, provoca la limpieza del espacio de nombres si no hay otros procesos, ya que PID 1 tiene el rol especial de adoptar procesos huérfanos. El kernel de Linux entonces desactivará la asignación de PID en ese espacio de nombres.

2. **Consecuencia**:

- La salida de PID 1 en un nuevo espacio de nombres conduce a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto hace que la función `alloc_pid` falle al intentar asignar un nuevo PID al crear un proceso, produciendo el error "No se puede asignar memoria".

3. **Solución**:
- El problema puede resolverse usando la opción `-f` con `unshare`. Esta opción hace que `unshare` haga fork de un nuevo proceso después de crear el nuevo espacio de nombres PID.
- Ejecutar %unshare -fp /bin/bash% asegura que el comando `unshare` se convierta en PID 1 en el nuevo espacio de nombres. `/bin/bash` y sus procesos hijos quedan entonces contenidos de forma segura dentro de este nuevo espacio, evitando la salida prematura de PID 1 y permitiendo la asignación normal de PIDs.

Al asegurarse de que `unshare` se ejecute con la bandera `-f`, el nuevo espacio de nombres PID se mantiene correctamente, permitiendo que `/bin/bash` y sus subprocesos operen sin encontrarse con el error de asignación de memoria.

</details>

Montando una nueva instancia del sistema de archivos `/proc` usando el parámetro `--mount-proc`, se garantiza que el nuevo espacio de nombres de montaje tenga una vista **exacta y aislada de la información de procesos específica de ese espacio de nombres**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Comprueba en qué namespace está tu proceso
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Encontrar todos los espacios de nombres PID
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Tenga en cuenta que el usuario root del PID namespace inicial (por defecto) puede ver todos los procesos, incluso los que están en nuevos PID namespaces, por eso podemos ver todos los PID namespaces.

### Entrar en un PID namespace
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Cuando entras dentro de un PID namespace desde el namespace por defecto, todavía podrás ver todos los procesos. Y el proceso de ese PID ns podrá ver el nuevo bash en el PID ns.

Además, solo puedes **entrar en otro PID namespace de proceso si eres root**. Y **no puedes** **entrar** en otro namespace **sin un descriptor** apuntando a él (como `/proc/self/ns/pid`)

## Notas recientes de explotación

### CVE-2025-31133: abuso de `maskedPaths` para alcanzar PIDs del host

runc ≤1.2.7 permitía a atacantes que controlaban imágenes de contenedor o cargas de trabajo `runc exec` reemplazar el `/dev/null` del lado del contenedor justo antes de que el runtime enmascarara entradas sensibles de procfs. Cuando la carrera tiene éxito, `/dev/null` puede convertirse en un symlink que apunte a cualquier ruta del host (por ejemplo `/proc/sys/kernel/core_pattern`), de modo que el nuevo PID namespace del contenedor hereda de repente acceso de lectura/escritura a los controles globales de procfs del host aunque nunca haya salido de su propio namespace. Una vez que `core_pattern` o `/proc/sysrq-trigger` son escribibles, generar un coredump o activar SysRq provoca ejecución de código o denegación de servicio en el host PID namespace.

Flujo práctico:

1. Construye un OCI bundle cuyo rootfs reemplace `/dev/null` con un enlace a la ruta del host que quieras (`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`).
2. Inicia el contenedor antes de que se aplique la corrección para que runc monte por bind el objetivo de procfs del host sobre el enlace.
3. Dentro del namespace del contenedor, escribe en el archivo de procfs ahora expuesto (por ejemplo, apunta `core_pattern` a un helper de reverse shell) y provoca el fallo de cualquier proceso para forzar al kernel del host a ejecutar tu helper en el contexto PID 1.

Puedes auditar rápidamente si un bundle está enmascarando los archivos correctos antes de iniciarlo:
```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```
Si el runtime carece de una entrada de enmascaramiento que esperas (o la omite porque `/dev/null` desapareció), considera el container como con posible visibilidad de PID del host.

### Inyección de namespace con `insject`

El `insject` de NCC Group se carga como una payload LD_PRELOAD que hookea una etapa tardía en el programa objetivo (por defecto `main`) y ejecuta una secuencia de llamadas `setns()` después de `execve()`. Eso te permite adjuntarte desde el host (o desde otro container) al PID namespace de la víctima *después* de que su runtime se haya inicializado, preservando su vista de `/proc/<pid>` sin tener que copiar binarios en el sistema de ficheros del container. Como `insject` puede aplazar la unión al PID namespace hasta que hace fork, puedes mantener un thread en el namespace del host (con CAP_SYS_PTRACE) mientras otro thread ejecuta en el PID namespace objetivo, creando potentes primitivas para debugging u ofensivas.

Ejemplo de uso:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Puntos clave al abusar de o defenderse contra namespace injection:

- Usa `-S/--strict` para forzar que `insject` aborte si ya existen hilos o si las uniones de namespaces fallan; de lo contrario podrías dejar hilos parcialmente migrados que abarquen los espacios PID del host y del contenedor.
- Nunca adjuntes herramientas que aún mantengan descriptores de archivos host con permiso de escritura a menos que también te unas al mount namespace; de lo contrario, cualquier proceso dentro del PID namespace puede hacer ptrace a tu helper y reutilizar esos descriptores para manipular recursos del host.

## Referencias

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}
