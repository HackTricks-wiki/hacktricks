# Espacio de nombres PID

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Información Básica

El espacio de nombres PID (Process IDentifier) es una característica en el kernel de Linux que proporciona aislamiento de procesos al permitir que un grupo de procesos tenga su propio conjunto de PIDs únicos, separados de los PIDs en otros espacios de nombres. Esto es particularmente útil en la contenerización, donde el aislamiento de procesos es esencial para la seguridad y la gestión de recursos.

Cuando se crea un nuevo espacio de nombres PID, el primer proceso en ese espacio se le asigna el PID 1. Este proceso se convierte en el proceso "init" del nuevo espacio y es responsable de gestionar otros procesos dentro del espacio. Cada proceso posterior creado dentro del espacio tendrá un PID único dentro de ese espacio, y estos PIDs serán independientes de los PIDs en otros espacios de nombres.

Desde la perspectiva de un proceso dentro de un espacio de nombres PID, solo puede ver otros procesos en el mismo espacio. No es consciente de los procesos en otros espacios de nombres y no puede interactuar con ellos utilizando herramientas tradicionales de gestión de procesos (por ejemplo, `kill`, `wait`, etc.). Esto proporciona un nivel de aislamiento que ayuda a evitar que los procesos interfieran entre sí.

### Cómo funciona:

1. Cuando se crea un nuevo proceso (por ejemplo, utilizando la llamada al sistema `clone()`), el proceso puede asignarse a un espacio de nombres PID nuevo o existente. **Si se crea un nuevo espacio, el proceso se convierte en el proceso "init" de ese espacio**.
2. El **kernel** mantiene un **mapeo entre los PIDs en el nuevo espacio y los PIDs correspondientes** en el espacio padre (es decir, el espacio desde el cual se creó el nuevo espacio). Este mapeo **permite al kernel traducir los PIDs cuando sea necesario**, como al enviar señales entre procesos en diferentes espacios de nombres.
3. **Los procesos dentro de un espacio de nombres PID solo pueden ver e interactuar con otros procesos en el mismo espacio**. No son conscientes de los procesos en otros espacios de nombres y sus PIDs son únicos dentro de su espacio.
4. Cuando se **destruye un espacio de nombres PID** (por ejemplo, cuando el proceso "init" del espacio sale), **todos los procesos dentro de ese espacio se terminan**. Esto asegura que todos los recursos asociados con el espacio se limpien correctamente.

## Laboratorio:

### Crear diferentes Espacios de Nombres

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: No se puede asignar memoria</summary>

Cuando se ejecuta `unshare` sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos espacios de nombres de PID (Identificador de Proceso). A continuación se describen los detalles clave y la solución:

1. **Explicación del Problema**:
- El kernel de Linux permite a un proceso crear nuevos espacios de nombres utilizando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo espacio de nombres de PID (llamado proceso "unshare") no entra en el nuevo espacio de nombres; solo lo hacen sus procesos hijos.
- Ejecutar `%unshare -p /bin/bash%` inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos hijos están en el espacio de nombres de PID original.
- El primer proceso hijo de `/bin/bash` en el nuevo espacio de nombres se convierte en PID 1. Cuando este proceso sale, desencadena la limpieza del espacio de nombres si no hay otros procesos, ya que el PID 1 tiene el papel especial de adoptar procesos huérfanos. El kernel de Linux deshabilitará entonces la asignación de PID en ese espacio de nombres.

2. **Consecuencia**:
- La salida de PID 1 en un nuevo espacio de nombres conduce a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto provoca que la función `alloc_pid` falle al asignar un nuevo PID al crear un nuevo proceso, lo que produce el error "No se puede asignar memoria".

3. **Solución**:
- El problema se puede resolver utilizando la opción `-f` con `unshare`. Esta opción hace que `unshare` bifurque un nuevo proceso después de crear el nuevo espacio de nombres de PID.
- Al ejecutar `%unshare -fp /bin/bash%`, se asegura de que el comando `unshare` se convierta en PID 1 en el nuevo espacio de nombres. `/bin/bash` y sus procesos hijos quedan contenidos de forma segura en este nuevo espacio de nombres, evitando la salida prematura de PID 1 y permitiendo una asignación normal de PID.

Al garantizar que `unshare` se ejecute con la bandera `-f`, el nuevo espacio de nombres de PID se mantiene correctamente, lo que permite que `/bin/bash` y sus subprocesos funcionen sin encontrar el error de asignación de memoria.

</details>

Al montar una nueva instancia del sistema de archivos `/proc` si se utiliza el parámetro `--mount-proc`, se asegura de que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información de procesos específica de ese espacio de nombres**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Comprobar en qué espacio de nombres está su proceso
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Encontrar todos los espacios de nombres de PID

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

Tenga en cuenta que el usuario root desde el espacio de nombres PID inicial (predeterminado) puede ver todos los procesos, incluso los que están en nuevos espacios de nombres PID, por eso podemos ver todos los espacios de nombres PID.

### Entrar dentro de un espacio de nombres PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Cuando entras dentro de un espacio de nombres PID desde el espacio de nombres predeterminado, seguirás pudiendo ver todos los procesos. Y el proceso de ese espacio de nombres PID podrá ver el nuevo bash en el espacio de nombres PID.

Además, solo puedes **entrar en otro espacio de nombres de PID si eres root**. Y **no puedes** **entrar** en otro espacio de nombres **sin un descriptor** que apunte a él (como `/proc/self/ns/pid`)

## Referencias
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
