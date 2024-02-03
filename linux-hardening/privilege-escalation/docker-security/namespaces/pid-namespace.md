# Espacio de nombres PID

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
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

Cuando se ejecuta `unshare` sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos espacios de nombres de PID (ID de Proceso). Los detalles clave y la solución se describen a continuación:

1. **Explicación del Problema**:
- El núcleo de Linux permite que un proceso cree nuevos espacios de nombres utilizando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo espacio de nombres de PID (referido como el proceso "unshare") no entra en el nuevo espacio de nombres; solo lo hacen sus procesos hijos.
- Ejecutar `%unshare -p /bin/bash%` inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos hijos están en el espacio de nombres de PID original.
- El primer proceso hijo de `/bin/bash` en el nuevo espacio de nombres se convierte en PID 1. Cuando este proceso termina, desencadena la limpieza del espacio de nombres si no hay otros procesos, ya que el PID 1 tiene el rol especial de adoptar procesos huérfanos. El núcleo de Linux deshabilitará entonces la asignación de PID en ese espacio de nombres.

2. **Consecuencia**:
- La salida del PID 1 en un nuevo espacio de nombres conduce a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto resulta en que la función `alloc_pid` falle al asignar un nuevo PID al crear un nuevo proceso, produciendo el error "No se puede asignar memoria".

3. **Solución**:
- El problema se puede resolver utilizando la opción `-f` con `unshare`. Esta opción hace que `unshare` bifurque un nuevo proceso después de crear el nuevo espacio de nombres de PID.
- Ejecutar `%unshare -fp /bin/bash%` asegura que el comando `unshare` mismo se convierta en PID 1 en el nuevo espacio de nombres. `/bin/bash` y sus procesos hijos están entonces contenidos de manera segura dentro de este nuevo espacio de nombres, evitando la salida prematura del PID 1 y permitiendo la asignación normal de PID.

Asegurándose de que `unshare` se ejecute con la bandera `-f`, el nuevo espacio de nombres de PID se mantiene correctamente, permitiendo que `/bin/bash` y sus subprocesos operen sin encontrar el error de asignación de memoria.

</details>

Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, te aseguras de que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información del proceso específica para ese espacio de nombres**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Verifica en qué namespace están tus procesos
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Encuentra todos los espacios de nombres PID

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

# Referencias
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
