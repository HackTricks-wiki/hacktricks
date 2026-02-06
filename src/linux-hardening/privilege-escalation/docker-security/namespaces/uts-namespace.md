# Espacio de nombres UTS

{{#include ../../../../banners/hacktricks-training.md}}

## Información básica

Un espacio de nombres UTS (UNIX Time-Sharing System) es una característica del kernel de Linux que proporciona i**aislamiento de dos identificadores del sistema**: el **hostname** y el **NIS** (Network Information Service) nombre de dominio. Este aislamiento permite que cada espacio de nombres UTS tenga su **propio hostname y nombre de dominio del NIS independientes**, lo cual es especialmente útil en escenarios de containerization donde cada contenedor debe aparecer como un sistema separado con su propio hostname.

### Cómo funciona:

1. Cuando se crea un nuevo espacio de nombres UTS, comienza con una **copia del hostname y del nombre de dominio del NIS de su espacio de nombres padre**. Esto significa que, al crearlo, el nuevo espacio de nombres s**comparte los mismos identificadores que su padre**. Sin embargo, cualquier cambio posterior en el hostname o en el nombre de dominio del NIS dentro del espacio de nombres no afectará a otros espacios de nombres.
2. Los procesos dentro de un espacio de nombres UTS **pueden cambiar el hostname y el nombre de dominio del NIS** usando las llamadas al sistema `sethostname()` y `setdomainname()`, respectivamente. Estos cambios son locales al espacio de nombres y no afectan a otros espacios de nombres ni al sistema host.
3. Los procesos pueden moverse entre espacios de nombres usando la llamada al sistema `setns()` o crear nuevos espacios de nombres usando las llamadas al sistema `unshare()` o `clone()` con la bandera `CLONE_NEWUTS`. Cuando un proceso se mueve a un nuevo espacio de nombres o crea uno, comenzará a usar el hostname y el nombre de dominio del NIS asociados a ese espacio de nombres.

## Laboratorio:

### Crear diferentes espacios de nombres

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, aseguras que el nuevo mount namespace tenga una **vista precisa y aislada de la información de procesos específica de ese namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Cuando `unshare` se ejecuta sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos PID (Process ID) namespaces. Los detalles clave y la solución se describen a continuación:

1. **Explicación del problema**:

- El kernel de Linux permite que un proceso cree nuevos namespaces usando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo PID namespace (denominado proceso "unshare") no entra en el nuevo namespace; solo lo hacen sus procesos hijos.
- Ejecutar %unshare -p /bin/bash% inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos hijos están en el PID namespace original.
- El primer proceso hijo de `/bin/bash` en el nuevo namespace se convierte en PID 1. Cuando este proceso termina, desencadena la limpieza del namespace si no hay otros procesos, ya que PID 1 tiene el rol especial de adoptar procesos huérfanos. El kernel de Linux entonces deshabilitará la asignación de PID en ese namespace.

2. **Consecuencia**:

- La salida de PID 1 en un nuevo namespace conduce a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto hace que la función `alloc_pid` falle al asignar un nuevo PID al crear un proceso, produciendo el error "Cannot allocate memory".

3. **Solución**:
- El problema puede resolverse usando la opción `-f` con `unshare`. Esta opción hace que `unshare` haga fork de un nuevo proceso después de crear el nuevo PID namespace.
- Ejecutar %unshare -fp /bin/bash% asegura que el propio comando `unshare` se convierta en PID 1 en el nuevo namespace. `/bin/bash` y sus procesos hijos quedan entonces contenidos de forma segura dentro de este nuevo namespace, evitando la salida prematura de PID 1 y permitiendo la asignación normal de PID.

Al asegurarse de que `unshare` se ejecute con la bandera `-f`, el nuevo PID namespace se mantiene correctamente, permitiendo que `/bin/bash` y sus subprocesos funcionen sin encontrar el error de asignación de memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Comprueba en qué namespace está tu proceso
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
### Entrar en un namespace UTS
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Abusar del UTS compartido del host

Si un contenedor se inicia con `--uts=host`, se une al namespace UTS del host en lugar de obtener uno aislado. Con capacidades como `--cap-add SYS_ADMIN`, el código dentro del contenedor puede cambiar el hostname/nombre NIS del host mediante `sethostname()`/`setdomainname()`:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Cambiar el nombre del host puede manipular los registros/alertas, confundir el descubrimiento del clúster o romper las configuraciones TLS/SSH que fijan el nombre del host.

### Detectar contenedores que comparten UTS con el host
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
