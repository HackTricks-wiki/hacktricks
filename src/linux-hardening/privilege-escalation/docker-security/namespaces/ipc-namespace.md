# IPC Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Información Básica

Un namespace IPC (Comunicación entre Procesos) es una característica del núcleo de Linux que proporciona **aislamiento** de objetos IPC de System V, como colas de mensajes, segmentos de memoria compartida y semáforos. Este aislamiento asegura que los procesos en **diferentes namespaces IPC no pueden acceder ni modificar directamente los objetos IPC de los demás**, proporcionando una capa adicional de seguridad y privacidad entre grupos de procesos.

### Cómo funciona:

1. Cuando se crea un nuevo namespace IPC, comienza con un **conjunto completamente aislado de objetos IPC de System V**. Esto significa que los procesos que se ejecutan en el nuevo namespace IPC no pueden acceder ni interferir con los objetos IPC en otros namespaces o en el sistema host por defecto.
2. Los objetos IPC creados dentro de un namespace son visibles y **accesibles solo para los procesos dentro de ese namespace**. Cada objeto IPC se identifica mediante una clave única dentro de su namespace. Aunque la clave puede ser idéntica en diferentes namespaces, los objetos en sí están aislados y no pueden ser accedidos entre namespaces.
3. Los procesos pueden moverse entre namespaces utilizando la llamada al sistema `setns()` o crear nuevos namespaces utilizando las llamadas al sistema `unshare()` o `clone()` con la bandera `CLONE_NEWIPC`. Cuando un proceso se mueve a un nuevo namespace o crea uno, comenzará a utilizar los objetos IPC asociados con ese namespace.

## Laboratorio:

### Crear diferentes Namespaces

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, aseguras que el nuevo espacio de montaje tenga una **vista precisa y aislada de la información del proceso específica para ese espacio de nombres**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Cuando se ejecuta `unshare` sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos espacios de nombres de PID (ID de Proceso). Los detalles clave y la solución se describen a continuación:

1. **Explicación del Problema**:

- El núcleo de Linux permite a un proceso crear nuevos espacios de nombres utilizando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo espacio de nombres de PID (denominado proceso "unshare") no entra en el nuevo espacio de nombres; solo lo hacen sus procesos hijos.
- Ejecutar `%unshare -p /bin/bash%` inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos hijos están en el espacio de nombres de PID original.
- El primer proceso hijo de `/bin/bash` en el nuevo espacio de nombres se convierte en PID 1. Cuando este proceso sale, desencadena la limpieza del espacio de nombres si no hay otros procesos, ya que PID 1 tiene el papel especial de adoptar procesos huérfanos. El núcleo de Linux desactivará entonces la asignación de PID en ese espacio de nombres.

2. **Consecuencia**:

- La salida de PID 1 en un nuevo espacio de nombres lleva a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto resulta en que la función `alloc_pid` no puede asignar un nuevo PID al crear un nuevo proceso, produciendo el error "Cannot allocate memory".

3. **Solución**:
- El problema se puede resolver utilizando la opción `-f` con `unshare`. Esta opción hace que `unshare` cree un nuevo proceso después de crear el nuevo espacio de nombres de PID.
- Ejecutar `%unshare -fp /bin/bash%` asegura que el comando `unshare` mismo se convierta en PID 1 en el nuevo espacio de nombres. `/bin/bash` y sus procesos hijos están entonces contenidos de manera segura dentro de este nuevo espacio de nombres, previniendo la salida prematura de PID 1 y permitiendo la asignación normal de PID.

Al asegurarte de que `unshare` se ejecute con la bandera `-f`, el nuevo espacio de nombres de PID se mantiene correctamente, permitiendo que `/bin/bash` y sus subprocesos operen sin encontrar el error de asignación de memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Verifica en qué namespace se encuentra tu proceso
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Encontrar todos los namespaces IPC
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar dentro de un IPC namespace
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
Además, solo puedes **entrar en otro espacio de nombres de proceso si eres root**. Y **no puedes** **entrar** en otro espacio de nombres **sin un descriptor** que apunte a él (como `/proc/self/ns/net`).

### Crear objeto IPC
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## Referencias

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
