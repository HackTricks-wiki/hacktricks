# Espacio de nombres de red

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

Un espacio de nombres de red es una característica del kernel de Linux que proporciona aislamiento del stack de red, permitiendo que **cada espacio de nombres de red tenga su propia configuración de red independiente**, interfaces, direcciones IP, tablas de enrutamiento y reglas de firewall. Este aislamiento es útil en varios escenarios, como la contenerización, donde cada contenedor debe tener su propia configuración de red, independiente de otros contenedores y del sistema anfitrión.

### Cómo funciona:

1. Cuando se crea un nuevo espacio de nombres de red, comienza con un **stack de red completamente aislado**, sin **interfaces de red** excepto la interfaz de bucle (lo). Esto significa que los procesos que se ejecutan en el nuevo espacio de nombres de red no pueden comunicarse con procesos en otros espacios de nombres o con el sistema anfitrión por defecto.
2. Se pueden crear **interfaces de red virtuales**, como pares veth, y moverse entre espacios de nombres de red. Esto permite establecer conectividad de red entre espacios de nombres o entre un espacio de nombres y el sistema anfitrión. Por ejemplo, un extremo de un par veth puede colocarse en el espacio de nombres de red de un contenedor, y el otro extremo puede conectarse a un **puente** u otra interfaz de red en el espacio de nombres del anfitrión, proporcionando conectividad de red al contenedor.
3. Las interfaces de red dentro de un espacio de nombres pueden tener sus **propias direcciones IP, tablas de enrutamiento y reglas de firewall**, independientes de otros espacios de nombres. Esto permite que los procesos en diferentes espacios de nombres de red tengan diferentes configuraciones de red y operen como si estuvieran ejecutándose en sistemas en red separados.
4. Los procesos pueden moverse entre espacios de nombres utilizando la llamada al sistema `setns()`, o crear nuevos espacios de nombres utilizando las llamadas al sistema `unshare()` o `clone()` con la bandera `CLONE_NEWNET`. Cuando un proceso se mueve a un nuevo espacio de nombres o crea uno, comenzará a usar la configuración de red y las interfaces asociadas con ese espacio de nombres.

## Laboratorio:

### Crear diferentes Espacios de Nombres

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, te aseguras de que el nuevo namespace de montaje tenga una **vista precisa y aislada de la información de procesos específica de ese namespace**.

<details>

<summary>Error: bash: fork: No se puede asignar memoria</summary>

Si ejecutas la línea anterior sin `-f`, obtendrás ese error.\
El error es causado porque el proceso PID 1 sale del nuevo namespace.

Después de que bash comienza a ejecutarse, bash generará varios subprocesos nuevos para hacer algunas cosas. Si ejecutas unshare sin -f, bash tendrá el mismo pid que el proceso "unshare" actual. El proceso "unshare" actual llama al systemcall unshare, crea un nuevo namespace de pid, pero el proceso "unshare" actual no está en el nuevo namespace de pid. Es el comportamiento deseado del kernel de Linux: el proceso A crea un nuevo namespace, el propio proceso A no será puesto en el nuevo namespace, solo los subprocesos del proceso A serán puestos en el nuevo namespace. Entonces, cuando ejecutas:
```
unshare -p /bin/bash
```
El proceso unshare ejecutará /bin/bash, y /bin/bash generará varios subprocesos, el primer subproceso de bash se convertirá en el PID 1 del nuevo espacio de nombres, y el subproceso saldrá después de completar su trabajo. Por lo tanto, el PID 1 del nuevo espacio de nombres sale.

El proceso PID 1 tiene una función especial: debe convertirse en el proceso padre de todos los procesos huérfanos. Si el proceso PID 1 en el espacio de nombres raíz sale, el kernel entrará en pánico. Si el proceso PID 1 en un subespacio de nombres sale, el kernel de Linux llamará a la función disable_pid_allocation, que limpiará la bandera PIDNS_HASH_ADDING en ese espacio de nombres. Cuando el kernel de Linux crea un nuevo proceso, el kernel llamará a la función alloc_pid para asignar un PID en un espacio de nombres, y si la bandera PIDNS_HASH_ADDING no está establecida, la función alloc_pid devolverá un error -ENOMEM. Esa es la razón por la que obtuviste el error "Cannot allocate memory".

Puedes resolver este problema utilizando la opción '-f':
```
unshare -fp /bin/bash
```
```markdown
Si ejecutas unshare con la opción '-f', unshare bifurcará un nuevo proceso después de crear el nuevo espacio de nombres de pid. Y ejecutará /bin/bash en el nuevo proceso. El nuevo proceso será el pid 1 del nuevo espacio de nombres de pid. Luego, bash también bifurcará varios subprocesos para realizar algunas tareas. Como bash es el pid 1 del nuevo espacio de nombres de pid, sus subprocesos pueden salir sin ningún problema.

Copiado de [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

#### Docker
```
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### Comprueba en qué espacio de nombres está tu proceso
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Encuentra todos los espacios de nombres de red

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar dentro de un Namespace de Red
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
También, solo puedes **entrar en otro espacio de nombres de proceso si eres root**. Y **no puedes** **entrar** en otro espacio de nombres **sin un descriptor** que apunte a él (como `/proc/self/ns/net`).

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
