# Espacio de nombres PID

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información básica

El espacio de nombres PID (Process IDentifier) es una característica del kernel de Linux que proporciona aislamiento de procesos al permitir que un grupo de procesos tenga su propio conjunto de PIDs únicos, separados de los PIDs en otros espacios de nombres. Esto es particularmente útil en la contenerización, donde el aislamiento de procesos es esencial para la seguridad y la gestión de recursos.

Cuando se crea un nuevo espacio de nombres PID, el primer proceso en ese espacio de nombres se le asigna el PID 1. Este proceso se convierte en el proceso "init" del nuevo espacio de nombres y es responsable de gestionar otros procesos dentro del espacio de nombres. Cada proceso posterior creado dentro del espacio de nombres tendrá un PID único dentro de ese espacio de nombres, y estos PIDs serán independientes de los PIDs en otros espacios de nombres.

Desde la perspectiva de un proceso dentro de un espacio de nombres PID, solo puede ver otros procesos en el mismo espacio de nombres. No es consciente de los procesos en otros espacios de nombres, y no puede interactuar con ellos utilizando herramientas tradicionales de gestión de procesos (por ejemplo, `kill`, `wait`, etc.). Esto proporciona un nivel de aislamiento que ayuda a evitar que los procesos interfieran entre sí.

### Cómo funciona:

1. Cuando se crea un nuevo proceso (por ejemplo, mediante la llamada al sistema `clone()`), el proceso puede asignarse a un espacio de nombres PID nuevo o existente. **Si se crea un nuevo espacio de nombres, el proceso se convierte en el proceso "init" de ese espacio de nombres**.
2. El **kernel** mantiene un **mapeo entre los PIDs en el nuevo espacio de nombres y los PIDs correspondientes** en el espacio de nombres padre (es decir, el espacio de nombres del que se creó el nuevo espacio de nombres). Este mapeo **permite al kernel traducir los PIDs cuando sea necesario**, como cuando se envían señales entre procesos en diferentes espacios de nombres.
3. **Los procesos dentro de un espacio de nombres PID solo pueden ver e interactuar con otros procesos en el mismo espacio de nombres**. No son conscientes de los procesos en otros espacios de nombres, y sus PIDs son únicos dentro de su espacio de nombres.
4. Cuando se **destruye un espacio de nombres PID** (por ejemplo, cuando el proceso "init" del espacio de nombres sale), **todos los procesos dentro de ese espacio de nombres se terminan**. Esto asegura que todos los recursos asociados con el espacio de nombres se limpien correctamente.

## Laboratorio:

### Crear diferentes espacios de nombres

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: No se puede asignar memoria</summary>

Si ejecutas la línea anterior sin `-f`, obtendrás ese error.\
El error es causado por el proceso PID 1 que sale del nuevo namespace.

Después de que bash comience a ejecutarse, bifurcará varios subprocesos nuevos para hacer algunas cosas. Si ejecutas unshare sin -f, bash tendrá el mismo PID que el proceso "unshare" actual. El proceso "unshare" actual llama al sistema de llamadas unshare, crea un nuevo namespace de PID, pero el proceso "unshare" actual no está en el nuevo namespace de PID. Es el comportamiento deseado del kernel de Linux: el proceso A crea un nuevo namespace, el proceso A en sí mismo no se colocará en el nuevo namespace, solo los subprocesos del proceso A se colocarán en el nuevo namespace. Entonces, cuando ejecutas:
```
unshare -p /bin/bash
```
El proceso unshare ejecutará /bin/bash, y /bin/bash bifurcará varios subprocesos, el primer subproceso de bash se convertirá en PID 1 del nuevo espacio de nombres, y el subproceso saldrá después de completar su trabajo. Por lo tanto, el PID 1 del nuevo espacio de nombres sale.

El proceso PID 1 tiene una función especial: debe convertirse en el proceso padre de todos los procesos huérfanos. Si el proceso PID 1 en el espacio de nombres raíz sale, el kernel entrará en pánico. Si el proceso PID 1 en un subespacio de nombres sale, el kernel de Linux llamará a la función disable\_pid\_allocation, que limpiará la bandera PIDNS\_HASH\_ADDING en ese espacio de nombres. Cuando el kernel de Linux crea un nuevo proceso, llama a la función alloc\_pid para asignar un PID en un espacio de nombres, y si la bandera PIDNS\_HASH\_ADDING no está establecida, la función alloc\_pid devolverá un error -ENOMEM. Es por eso que se produce el error "Cannot allocate memory".

Puede resolver este problema utilizando la opción '-f':
```
unshare -fp /bin/bash
```
Si ejecutas unshare con la opción '-f', unshare bifurcará un nuevo proceso después de crear el nuevo espacio de nombres pid. Y ejecutará /bin/bash en el nuevo proceso. El nuevo proceso será el pid 1 del nuevo espacio de nombres pid. Luego, bash también bifurcará varios subprocesos para realizar algunas tareas. Como bash en sí mismo es el pid 1 del nuevo espacio de nombres pid, sus subprocesos pueden salir sin ningún problema.

Copiado de [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, aseguras que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información de procesos específica de ese espacio de nombres**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Verificar en qué namespace se encuentra su proceso
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Encontrar todos los espacios de nombres PID

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

Ten en cuenta que el usuario root del PID namespace inicial (por defecto) puede ver todos los procesos, incluso los que están en nuevos PID namespaces, por eso podemos ver todos los PID namespaces.

### Entrar dentro de un PID namespace
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Cuando entras en un espacio de nombres PID desde el espacio de nombres predeterminado, aún podrás ver todos los procesos. Y el proceso de ese espacio de nombres PID podrá ver el nuevo bash en el espacio de nombres PID.

Además, solo puedes **entrar en otro espacio de nombres de proceso si eres root**. Y no puedes **entrar** en otro espacio de nombres **sin un descriptor** que apunte a él (como `/proc/self/ns/pid`).
