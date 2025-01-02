# PID Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Información Básica

El namespace PID (Identificador de Proceso) es una característica en el núcleo de Linux que proporciona aislamiento de procesos al permitir que un grupo de procesos tenga su propio conjunto de PIDs únicos, separado de los PIDs en otros namespaces. Esto es particularmente útil en la contenedorización, donde el aislamiento de procesos es esencial para la seguridad y la gestión de recursos.

Cuando se crea un nuevo namespace PID, el primer proceso en ese namespace se le asigna el PID 1. Este proceso se convierte en el proceso "init" del nuevo namespace y es responsable de gestionar otros procesos dentro del namespace. Cada proceso subsiguiente creado dentro del namespace tendrá un PID único dentro de ese namespace, y estos PIDs serán independientes de los PIDs en otros namespaces.

Desde la perspectiva de un proceso dentro de un namespace PID, solo puede ver otros procesos en el mismo namespace. No es consciente de los procesos en otros namespaces y no puede interactuar con ellos utilizando herramientas tradicionales de gestión de procesos (por ejemplo, `kill`, `wait`, etc.). Esto proporciona un nivel de aislamiento que ayuda a prevenir que los procesos interfieran entre sí.

### Cómo funciona:

1. Cuando se crea un nuevo proceso (por ejemplo, utilizando la llamada al sistema `clone()`), el proceso puede ser asignado a un nuevo namespace PID o a uno existente. **Si se crea un nuevo namespace, el proceso se convierte en el proceso "init" de ese namespace**.
2. El **núcleo** mantiene un **mapeo entre los PIDs en el nuevo namespace y los PIDs correspondientes** en el namespace padre (es decir, el namespace del cual se creó el nuevo namespace). Este mapeo **permite que el núcleo traduzca PIDs cuando sea necesario**, como al enviar señales entre procesos en diferentes namespaces.
3. **Los procesos dentro de un namespace PID solo pueden ver e interactuar con otros procesos en el mismo namespace**. No son conscientes de los procesos en otros namespaces, y sus PIDs son únicos dentro de su namespace.
4. Cuando un **namespace PID es destruido** (por ejemplo, cuando el proceso "init" del namespace sale), **todos los procesos dentro de ese namespace son terminados**. Esto asegura que todos los recursos asociados con el namespace se limpien adecuadamente.

## Laboratorio:

### Crear diferentes Namespaces

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Cuando se ejecuta `unshare` sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos namespaces de PID (ID de Proceso). Los detalles clave y la solución se describen a continuación:

1. **Explicación del Problema**:

- El núcleo de Linux permite que un proceso cree nuevos namespaces utilizando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo namespace de PID (denominado el proceso "unshare") no entra en el nuevo namespace; solo lo hacen sus procesos hijos.
- Ejecutar `%unshare -p /bin/bash%` inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos hijos están en el namespace de PID original.
- El primer proceso hijo de `/bin/bash` en el nuevo namespace se convierte en PID 1. Cuando este proceso sale, desencadena la limpieza del namespace si no hay otros procesos, ya que PID 1 tiene el papel especial de adoptar procesos huérfanos. El núcleo de Linux deshabilitará entonces la asignación de PID en ese namespace.

2. **Consecuencia**:

- La salida de PID 1 en un nuevo namespace lleva a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto resulta en que la función `alloc_pid` falla al intentar asignar un nuevo PID al crear un nuevo proceso, produciendo el error "Cannot allocate memory".

3. **Solución**:
- El problema se puede resolver utilizando la opción `-f` con `unshare`. Esta opción hace que `unshare` cree un nuevo proceso después de crear el nuevo namespace de PID.
- Ejecutar `%unshare -fp /bin/bash%` asegura que el comando `unshare` mismo se convierta en PID 1 en el nuevo namespace. `/bin/bash` y sus procesos hijos están entonces contenidos de manera segura dentro de este nuevo namespace, previniendo la salida prematura de PID 1 y permitiendo la asignación normal de PID.

Al asegurarse de que `unshare` se ejecute con la bandera `-f`, el nuevo namespace de PID se mantiene correctamente, permitiendo que `/bin/bash` y sus subprocesos operen sin encontrar el error de asignación de memoria.

</details>

Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, aseguras que el nuevo namespace de montaje tenga una **vista precisa y aislada de la información del proceso específica para ese namespace**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Ver en qué namespace está tu proceso
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Encontrar todos los espacios de nombres PID
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Tenga en cuenta que el usuario root del espacio de nombres PID inicial (predeterminado) puede ver todos los procesos, incluso los que están en nuevos espacios de nombres PID, por eso podemos ver todos los espacios de nombres PID.

### Entrar dentro de un espacio de nombres PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Cuando entras dentro de un namespace PID desde el namespace por defecto, aún podrás ver todos los procesos. Y el proceso de ese namespace PID podrá ver el nuevo bash en el namespace PID.

Además, solo puedes **entrar en otro namespace PID de proceso si eres root**. Y **no puedes** **entrar** en otro namespace **sin un descriptor** que apunte a él (como `/proc/self/ns/pid`)

## Referencias

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
