# Espacio de nombres de red

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

Un espacio de nombres de red es una característica del kernel de Linux que proporciona aislamiento del stack de red, permitiendo **que cada espacio de nombres de red tenga su propia configuración de red independiente**, interfaces, direcciones IP, tablas de enrutamiento y reglas de firewall. Este aislamiento es útil en varios escenarios, como la contenerización, donde cada contenedor debe tener su propia configuración de red, independiente de otros contenedores y del sistema anfitrión.

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
Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, te aseguras de que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información del proceso específica para ese espacio de nombres**.

<details>

<summary>Error: bash: fork: No se puede asignar memoria</summary>

Cuando se ejecuta `unshare` sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos espacios de nombres de PID (ID de Proceso). Los detalles clave y la solución se describen a continuación:

1. **Explicación del Problema**:
- El núcleo de Linux permite que un proceso cree nuevos espacios de nombres utilizando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo espacio de nombres de PID (referido como el proceso "unshare") no entra en el nuevo espacio de nombres; solo lo hacen sus procesos hijos.
- Ejecutar `%unshare -p /bin/bash%` inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos hijos están en el espacio de nombres de PID original.
- El primer proceso hijo de `/bin/bash` en el nuevo espacio de nombres se convierte en PID 1. Cuando este proceso sale, desencadena la limpieza del espacio de nombres si no hay otros procesos, ya que el PID 1 tiene el rol especial de adoptar procesos huérfanos. El núcleo de Linux deshabilitará entonces la asignación de PID en ese espacio de nombres.

2. **Consecuencia**:
- La salida del PID 1 en un nuevo espacio de nombres conduce a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto resulta en que la función `alloc_pid` falle al asignar un nuevo PID al crear un nuevo proceso, produciendo el error "No se puede asignar memoria".

3. **Solución**:
- El problema se puede resolver utilizando la opción `-f` con `unshare`. Esta opción hace que `unshare` bifurque un nuevo proceso después de crear el nuevo espacio de nombres de PID.
- Ejecutar `%unshare -fp /bin/bash%` asegura que el comando `unshare` mismo se convierta en PID 1 en el nuevo espacio de nombres. `/bin/bash` y sus procesos hijos están entonces contenidos de manera segura dentro de este nuevo espacio de nombres, previniendo la salida prematura del PID 1 y permitiendo la asignación normal de PID.

Asegurándote de que `unshare` se ejecute con la bandera `-f`, el nuevo espacio de nombres de PID se mantiene correctamente, permitiendo que `/bin/bash` y sus subprocesos operen sin encontrar el error de asignación de memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### &#x20;Verifica en qué espacio de nombres está tu proceso
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
También, solo puedes **entrar en otro namespace de proceso si eres root**. Y **no puedes** **entrar** en otro namespace **sin un descriptor** que apunte a él (como `/proc/self/ns/net`).

# Referencias
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
