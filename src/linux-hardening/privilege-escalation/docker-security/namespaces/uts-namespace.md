# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Información básica

Un UTS (UNIX Time-Sharing System) namespace es una característica del kernel de Linux que proporciona **aislamiento de dos identificadores del sistema**: el **hostname** y el **NIS** (Network Information Service) domain name. Este aislamiento permite que cada UTS namespace tenga su **propio hostname independiente y NIS domain name**, lo cual es especialmente útil en escenarios de containerization donde cada container debería aparecer como un sistema separado con su propio hostname.

### Cómo funciona:

1. Cuando se crea un nuevo UTS namespace, comienza con una **copia del hostname y NIS domain name desde su namespace padre**. Esto significa que, al crearse, el nuevo namespace **comparte los mismos identificadores que su namespace padre**. Sin embargo, cualquier cambio posterior al hostname o al NIS domain name dentro del namespace no afectará a otros namespaces.
2. Los procesos dentro de un UTS namespace **pueden cambiar el hostname y el NIS domain name** usando las llamadas al sistema `sethostname()` y `setdomainname()`, respectivamente. Estos cambios son locales al namespace y no afectan a otros namespaces ni al host system.
3. Los procesos pueden moverse entre namespaces usando la llamada al sistema `setns()` o crear nuevos namespaces usando las llamadas `unshare()` o `clone()` con la bandera `CLONE_NEWUTS`. Cuando un proceso se mueve a un nuevo namespace o crea uno, comenzará a usar el hostname y el NIS domain name asociados a ese namespace.

## Laboratorio:

### Crear diferentes Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (ID de proceso) namespaces. The key details and the solution are outlined below:

1. **Explicación del problema**:

- El kernel de Linux permite que un proceso cree nuevos namespaces usando la system call `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo namespace PID (referido como el proceso "unshare") no entra en el nuevo namespace; solo lo hacen sus procesos hijo.
- Ejecutar %unshare -p /bin/bash% inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos hijo están en el namespace PID original.
- El primer proceso hijo de `/bin/bash` en el nuevo namespace se convierte en PID 1. Cuando ese proceso termina, provoca la limpieza del namespace si no hay otros procesos, ya que PID 1 tiene el rol especial de adoptar procesos huérfanos. El kernel de Linux entonces deshabilitará la asignación de PIDs en ese namespace.

2. **Consecuencia**:

- La salida de PID 1 en un nuevo namespace conduce a la limpieza de la flag `PIDNS_HASH_ADDING`. Esto provoca que la función `alloc_pid` falle al asignar un nuevo PID al crear un proceso, produciendo el error "Cannot allocate memory".

3. **Solución**:
- El problema se puede resolver usando la opción `-f` con `unshare`. Esta opción hace que `unshare` cree un nuevo proceso hijo (fork) después de crear el nuevo namespace PID.
- Ejecutar %unshare -fp /bin/bash% asegura que el propio comando `unshare` se convierta en PID 1 en el nuevo namespace. `/bin/bash` y sus procesos hijo quedan entonces contenidos de forma segura dentro de este nuevo namespace, evitando la terminación prematura de PID 1 y permitiendo la asignación normal de PIDs.

Al garantizar que `unshare` se ejecute con la opción `-f`, el nuevo namespace PID se mantiene correctamente, permitiendo que `/bin/bash` y sus subprocesos funcionen sin encontrar el error de asignación de memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Comprobar en qué namespace se encuentra tu proceso
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Encontrar todos los UTS namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar en un UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Abusar del host UTS sharing

Si un contenedor se inicia con `--uts=host`, se une al host UTS namespace en lugar de obtener uno aislado. Con capacidades como `--cap-add SYS_ADMIN`, el código en el contenedor puede cambiar el host hostname/NIS name vía `sethostname()`/`setdomainname()`:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Cambiar el nombre del host puede manipular logs/alerts, confundir cluster discovery o romper TLS/SSH configs que fijan el hostname.

### Detectar containers que comparten UTS con el host
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
