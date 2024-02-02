# Espacio de nombres PID

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

El espacio de nombres PID (Identificador de Proceso) es una característica del kernel de Linux que proporciona aislamiento de procesos al permitir que un grupo de procesos tenga su propio conjunto de PIDs únicos, separados de los PIDs en otros espacios de nombres. Esto es particularmente útil en la contenerización, donde el aislamiento de procesos es esencial para la seguridad y la gestión de recursos.

Cuando se crea un nuevo espacio de nombres PID, al primer proceso en ese espacio de nombres se le asigna el PID 1. Este proceso se convierte en el proceso "init" del nuevo espacio de nombres y es responsable de gestionar otros procesos dentro del espacio de nombres. Cada proceso subsiguiente creado dentro del espacio de nombres tendrá un PID único dentro de ese espacio de nombres, y estos PIDs serán independientes de los PIDs en otros espacios de nombres.

Desde la perspectiva de un proceso dentro de un espacio de nombres PID, solo puede ver otros procesos en el mismo espacio de nombres. No es consciente de los procesos en otros espacios de nombres y no puede interactuar con ellos utilizando herramientas tradicionales de gestión de procesos (por ejemplo, `kill`, `wait`, etc.). Esto proporciona un nivel de aislamiento que ayuda a prevenir que los procesos interfieran entre sí.

### Cómo funciona:

1. Cuando se crea un nuevo proceso (por ejemplo, utilizando la llamada al sistema `clone()`), el proceso puede ser asignado a un nuevo o existente espacio de nombres PID. **Si se crea un nuevo espacio de nombres, el proceso se convierte en el proceso "init" de ese espacio de nombres**.
2. El **kernel** mantiene un **mapeo entre los PIDs en el nuevo espacio de nombres y los PIDs correspondientes** en el espacio de nombres padre (es decir, el espacio de nombres desde el cual se creó el nuevo espacio de nombres). Este mapeo **permite al kernel traducir los PIDs cuando sea necesario**, como al enviar señales entre procesos en diferentes espacios de nombres.
3. **Los procesos dentro de un espacio de nombres PID solo pueden ver e interactuar con otros procesos en el mismo espacio de nombres**. No son conscientes de los procesos en otros espacios de nombres, y sus PIDs son únicos dentro de su espacio de nombres.
4. Cuando un **espacio de nombres PID se destruye** (por ejemplo, cuando el proceso "init" del espacio de nombres sale), **todos los procesos dentro de ese espacio de nombres son terminados**. Esto asegura que todos los recursos asociados con el espacio de nombres se limpien adecuadamente.

## Laboratorio:

### Crear diferentes Espacios de Nombres

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: No se puede asignar memoria</summary>

Si ejecutas la línea anterior sin `-f` obtendrás ese error.\
El error es causado porque el proceso con PID 1 sale del nuevo namespace.

Después de que bash comienza a ejecutarse, bash generará varios subprocesos nuevos para hacer algunas cosas. Si ejecutas unshare sin -f, bash tendrá el mismo pid que el proceso "unshare" actual. El proceso "unshare" actual llama al systemcall unshare, crea un nuevo pid namespace, pero el proceso "unshare" actual no está en el nuevo pid namespace. Es el comportamiento deseado del kernel de linux: el proceso A crea un nuevo namespace, el propio proceso A no será puesto en el nuevo namespace, solo los subprocesos del proceso A serán puestos en el nuevo namespace. Entonces, cuando ejecutas:
</details>
```
unshare -p /bin/bash
```
El proceso unshare ejecutará /bin/bash, y /bin/bash generará varios subprocesos, el primer subproceso de bash se convertirá en el PID 1 del nuevo espacio de nombres, y el subproceso saldrá después de completar su trabajo. Entonces, el PID 1 del nuevo espacio de nombres sale.

El proceso PID 1 tiene una función especial: debe convertirse en el proceso padre de todos los procesos huérfanos. Si el proceso PID 1 en el espacio de nombres raíz sale, el kernel entrará en pánico. Si el proceso PID 1 en un subespacio de nombres sale, el kernel de Linux llamará a la función disable_pid_allocation, que limpiará la bandera PIDNS_HASH_ADDING en ese espacio de nombres. Cuando el kernel de Linux crea un nuevo proceso, el kernel llamará a la función alloc_pid para asignar un PID en un espacio de nombres, y si la bandera PIDNS_HASH_ADDING no está establecida, la función alloc_pid devolverá un error -ENOMEM. Por eso recibiste el error "Cannot allocate memory".

Puedes resolver este problema utilizando la opción '-f':
```
unshare -fp /bin/bash
```
```markdown
Si ejecutas unshare con la opción '-f', unshare bifurcará un nuevo proceso después de crear el nuevo espacio de nombres de pid. Y ejecutará /bin/bash en el nuevo proceso. El nuevo proceso será el pid 1 del nuevo espacio de nombres de pid. Luego, bash también bifurcará varios subprocesos para realizar algunas tareas. Como bash mismo es el pid 1 del nuevo espacio de nombres de pid, sus subprocesos pueden salir sin ningún problema.

Copiado de [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, te aseguras de que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información del proceso específica para ese espacio de nombres**.

#### Docker
```
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Verifica en qué namespace están tus procesos
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Encuentra todos los espacios de nombres de PID

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

Tenga en cuenta que el usuario root del espacio de nombres de PID inicial (predeterminado) puede ver todos los procesos, incluso los que están en nuevos espacios de nombres de PID, por eso podemos ver todos los espacios de nombres de PID.

### Entrar dentro de un espacio de nombres de PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Cuando ingresas en un espacio de nombres PID desde el espacio de nombres predeterminado, todavía podrás ver todos los procesos. Y el proceso de ese espacio de nombres PID podrá ver el nuevo bash en el espacio de nombres PID.

Además, solo puedes **entrar en el espacio de nombres PID de otro proceso si eres root**. Y **no puedes** **entrar** en otro espacio de nombres **sin un descriptor** que apunte a él (como `/proc/self/ns/pid`)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
