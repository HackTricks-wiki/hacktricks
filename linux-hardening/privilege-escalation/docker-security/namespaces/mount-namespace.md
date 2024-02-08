# Espacio de nombres de montaje

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de GitHub.

</details>

## Información Básica

Un espacio de nombres de montaje es una característica del kernel de Linux que proporciona aislamiento de los puntos de montaje del sistema de archivos vistos por un grupo de procesos. Cada espacio de nombres de montaje tiene su propio conjunto de puntos de montaje del sistema de archivos, y **los cambios en los puntos de montaje en un espacio de nombres no afectan a otros espacios de nombres**. Esto significa que los procesos que se ejecutan en diferentes espacios de nombres de montaje pueden tener vistas diferentes de la jerarquía del sistema de archivos.

Los espacios de nombres de montaje son particularmente útiles en la contenerización, donde cada contenedor debe tener su propio sistema de archivos y configuración, aislado de otros contenedores y del sistema host.

### Cómo funciona:

1. Cuando se crea un nuevo espacio de nombres de montaje, se inicializa con una **copia de los puntos de montaje de su espacio de nombres padre**. Esto significa que, en el momento de la creación, el nuevo espacio de nombres comparte la misma vista del sistema de archivos que su padre. Sin embargo, cualquier cambio posterior en los puntos de montaje dentro del espacio de nombres no afectará al padre ni a otros espacios de nombres.
2. Cuando un proceso modifica un punto de montaje dentro de su espacio de nombres, como montar o desmontar un sistema de archivos, el **cambio es local a ese espacio de nombres** y no afecta a otros espacios de nombres. Esto permite que cada espacio de nombres tenga su propia jerarquía de sistema de archivos independiente.
3. Los procesos pueden moverse entre espacios de nombres utilizando la llamada al sistema `setns()`, o crear nuevos espacios de nombres utilizando las llamadas al sistema `unshare()` o `clone()` con la bandera `CLONE_NEWNS`. Cuando un proceso se mueve a un nuevo espacio de nombres o crea uno, comenzará a utilizar los puntos de montaje asociados con ese espacio de nombres.
4. **Los descriptores de archivos y los inodos se comparten entre espacios de nombres**, lo que significa que si un proceso en un espacio de nombres tiene un descriptor de archivo abierto que apunta a un archivo, puede **pasar ese descriptor de archivo** a un proceso en otro espacio de nombres, y **ambos procesos accederán al mismo archivo**. Sin embargo, la ruta del archivo puede no ser la misma en ambos espacios de nombres debido a diferencias en los puntos de montaje.

## Laboratorio:

### Crear diferentes Espacios de Nombres

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` si se utiliza el parámetro `--mount-proc`, se asegura de que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información de procesos específica de ese espacio de nombres**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Cuando se ejecuta `unshare` sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos espacios de nombres de PID (Identificador de Proceso). A continuación se detallan los aspectos clave y la solución:

1. **Explicación del Problema**:
- El kernel de Linux permite a un proceso crear nuevos espacios de nombres utilizando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo espacio de nombres de PID (llamado proceso "unshare") no entra en el nuevo espacio de nombres; solo lo hacen sus procesos secundarios.
- Ejecutar `%unshare -p /bin/bash%` inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos secundarios están en el espacio de nombres de PID original.
- El primer proceso secundario de `/bin/bash` en el nuevo espacio de nombres se convierte en PID 1. Cuando este proceso sale, desencadena la limpieza del espacio de nombres si no hay otros procesos, ya que PID 1 tiene el papel especial de adoptar procesos huérfanos. El kernel de Linux deshabilitará entonces la asignación de PID en ese espacio de nombres.

2. **Consecuencia**:
- La salida de PID 1 en un nuevo espacio de nombres conduce a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto resulta en que la función `alloc_pid` falle al asignar un nuevo PID al crear un nuevo proceso, lo que produce el error "Cannot allocate memory".

3. **Solución**:
- El problema se puede resolver utilizando la opción `-f` con `unshare`. Esta opción hace que `unshare` bifurque un nuevo proceso después de crear el nuevo espacio de nombres de PID.
- Al ejecutar `%unshare -fp /bin/bash%`, se asegura de que el comando `unshare` en sí mismo se convierta en PID 1 en el nuevo espacio de nombres. Luego, `/bin/bash` y sus procesos secundarios están contenidos de manera segura dentro de este nuevo espacio de nombres, evitando la salida prematura de PID 1 y permitiendo una asignación normal de PID.

Al garantizar que `unshare` se ejecute con la bandera `-f`, el nuevo espacio de nombres de PID se mantiene correctamente, lo que permite que `/bin/bash` y sus subprocesos funcionen sin encontrar el error de asignación de memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Verificar en qué espacio de nombres está su proceso
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Encontrar todos los espacios de nombres de montaje

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar dentro de un espacio de nombres de montaje
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
También, solo puedes **entrar en otro espacio de nombres de proceso si eres root**. Y no puedes **entrar** en otro espacio de nombres **sin un descriptor** que apunte a él (como `/proc/self/ns/mnt`).

Dado que los nuevos montajes solo son accesibles dentro del espacio de nombres, es posible que un espacio de nombres contenga información sensible que solo se pueda acceder desde él.

### Montar algo
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```
## Referencias
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
