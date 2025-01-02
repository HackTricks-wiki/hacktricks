# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Información Básica

Un namespace UTS (UNIX Time-Sharing System) es una característica del núcleo de Linux que proporciona **aislamiento de dos identificadores del sistema**: el **nombre de host** y el **nombre de dominio NIS** (Network Information Service). Este aislamiento permite que cada namespace UTS tenga su **propio nombre de host y nombre de dominio NIS** independientes, lo cual es particularmente útil en escenarios de contenedorización donde cada contenedor debe aparecer como un sistema separado con su propio nombre de host.

### Cómo funciona:

1. Cuando se crea un nuevo namespace UTS, comienza con una **copia del nombre de host y del nombre de dominio NIS de su namespace padre**. Esto significa que, al momento de la creación, el nuevo namespace **comparte los mismos identificadores que su padre**. Sin embargo, cualquier cambio posterior en el nombre de host o en el nombre de dominio NIS dentro del namespace no afectará a otros namespaces.
2. Los procesos dentro de un namespace UTS **pueden cambiar el nombre de host y el nombre de dominio NIS** utilizando las llamadas al sistema `sethostname()` y `setdomainname()`, respectivamente. Estos cambios son locales al namespace y no afectan a otros namespaces o al sistema host.
3. Los procesos pueden moverse entre namespaces utilizando la llamada al sistema `setns()` o crear nuevos namespaces utilizando las llamadas al sistema `unshare()` o `clone()` con la bandera `CLONE_NEWUTS`. Cuando un proceso se mueve a un nuevo namespace o crea uno, comenzará a usar el nombre de host y el nombre de dominio NIS asociados con ese namespace.

## Laboratorio:

### Crear diferentes Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, aseguras que el nuevo espacio de montaje tenga una **vista precisa y aislada de la información del proceso específica de ese espacio de nombres**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Cuando se ejecuta `unshare` sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos espacios de nombres de PID (ID de Proceso). Los detalles clave y la solución se describen a continuación:

1. **Explicación del Problema**:

- El núcleo de Linux permite a un proceso crear nuevos espacios de nombres utilizando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo espacio de nombres de PID (denominado proceso "unshare") no entra en el nuevo espacio de nombres; solo lo hacen sus procesos hijos.
- Ejecutar `%unshare -p /bin/bash%` inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos hijos están en el espacio de nombres de PID original.
- El primer proceso hijo de `/bin/bash` en el nuevo espacio de nombres se convierte en PID 1. Cuando este proceso sale, desencadena la limpieza del espacio de nombres si no hay otros procesos, ya que PID 1 tiene el papel especial de adoptar procesos huérfanos. El núcleo de Linux deshabilitará entonces la asignación de PID en ese espacio de nombres.

2. **Consecuencia**:

- La salida de PID 1 en un nuevo espacio de nombres lleva a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto resulta en que la función `alloc_pid` falle al intentar asignar un nuevo PID al crear un nuevo proceso, produciendo el error "Cannot allocate memory".

3. **Solución**:
- El problema se puede resolver utilizando la opción `-f` con `unshare`. Esta opción hace que `unshare` cree un nuevo proceso después de crear el nuevo espacio de nombres de PID.
- Ejecutar `%unshare -fp /bin/bash%` asegura que el comando `unshare` en sí se convierta en PID 1 en el nuevo espacio de nombres. `/bin/bash` y sus procesos hijos están entonces contenidos de manera segura dentro de este nuevo espacio de nombres, previniendo la salida prematura de PID 1 y permitiendo la asignación normal de PID.

Al asegurarte de que `unshare` se ejecute con la bandera `-f`, el nuevo espacio de nombres de PID se mantiene correctamente, permitiendo que `/bin/bash` y sus subprocesos operen sin encontrar el error de asignación de memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Verifica en qué namespace está tu proceso
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Encontrar todos los namespaces UTS
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar dentro de un namespace UTS
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}
