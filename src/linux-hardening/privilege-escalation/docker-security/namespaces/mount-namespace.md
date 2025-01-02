# Mount Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Información Básica

Un mount namespace es una característica del núcleo de Linux que proporciona aislamiento de los puntos de montaje del sistema de archivos vistos por un grupo de procesos. Cada mount namespace tiene su propio conjunto de puntos de montaje del sistema de archivos, y **los cambios en los puntos de montaje en un namespace no afectan a otros namespaces**. Esto significa que los procesos que se ejecutan en diferentes mount namespaces pueden tener diferentes vistas de la jerarquía del sistema de archivos.

Los mount namespaces son particularmente útiles en la contenedorización, donde cada contenedor debe tener su propio sistema de archivos y configuración, aislados de otros contenedores y del sistema host.

### Cómo funciona:

1. Cuando se crea un nuevo mount namespace, se inicializa con una **copia de los puntos de montaje de su namespace padre**. Esto significa que, al momento de la creación, el nuevo namespace comparte la misma vista del sistema de archivos que su padre. Sin embargo, cualquier cambio posterior en los puntos de montaje dentro del namespace no afectará al padre ni a otros namespaces.
2. Cuando un proceso modifica un punto de montaje dentro de su namespace, como montar o desmontar un sistema de archivos, el **cambio es local a ese namespace** y no afecta a otros namespaces. Esto permite que cada namespace tenga su propia jerarquía de sistema de archivos independiente.
3. Los procesos pueden moverse entre namespaces utilizando la llamada al sistema `setns()`, o crear nuevos namespaces utilizando las llamadas al sistema `unshare()` o `clone()` con la bandera `CLONE_NEWNS`. Cuando un proceso se mueve a un nuevo namespace o crea uno, comenzará a usar los puntos de montaje asociados con ese namespace.
4. **Los descriptores de archivo e inodos se comparten entre namespaces**, lo que significa que si un proceso en un namespace tiene un descriptor de archivo abierto que apunta a un archivo, puede **pasar ese descriptor de archivo** a un proceso en otro namespace, y **ambos procesos accederán al mismo archivo**. Sin embargo, la ruta del archivo puede no ser la misma en ambos namespaces debido a las diferencias en los puntos de montaje.

## Laboratorio:

### Crear diferentes Namespaces

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, aseguras que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información del proceso específica de ese espacio de nombres**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Cuando se ejecuta `unshare` sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos espacios de nombres de PID (ID de Proceso). Los detalles clave y la solución se describen a continuación:

1. **Explicación del Problema**:

- El núcleo de Linux permite a un proceso crear nuevos espacios de nombres utilizando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo espacio de nombres de PID (denominado proceso "unshare") no entra en el nuevo espacio de nombres; solo lo hacen sus procesos hijos.
- Ejecutar `%unshare -p /bin/bash%` inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos hijos están en el espacio de nombres de PID original.
- El primer proceso hijo de `/bin/bash` en el nuevo espacio de nombres se convierte en PID 1. Cuando este proceso sale, desencadena la limpieza del espacio de nombres si no hay otros procesos, ya que PID 1 tiene el papel especial de adoptar procesos huérfanos. El núcleo de Linux deshabilitará entonces la asignación de PID en ese espacio de nombres.

2. **Consecuencia**:

- La salida de PID 1 en un nuevo espacio de nombres lleva a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto resulta en que la función `alloc_pid` no puede asignar un nuevo PID al crear un nuevo proceso, produciendo el error "Cannot allocate memory".

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
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Encontrar todos los espacios de nombres de montaje
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```

```bash
findmnt
```
### Entrar dentro de un namespace de montaje
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Además, solo puedes **entrar en otro espacio de nombres de proceso si eres root**. Y **no puedes** **entrar** en otro espacio de nombres **sin un descriptor** que apunte a él (como `/proc/self/ns/mnt`).

Debido a que los nuevos montajes solo son accesibles dentro del espacio de nombres, es posible que un espacio de nombres contenga información sensible que solo se puede acceder desde él.

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

```
# findmnt # List existing mounts
TARGET                                SOURCE                                                                                                           FSTYPE     OPTIONS
/                                     /dev/mapper/web05--vg-root

# unshare --mount  # run a shell in a new mount namespace
# mount --bind /usr/bin/ /mnt/
# ls /mnt/cp
/mnt/cp
# exit  # exit the shell, and hence the mount namespace
# ls /mnt/cp
ls: cannot access '/mnt/cp': No such file or directory

## Notice there's different files in /tmp
# ls /tmp
revshell.elf

# ls /mnt/tmp
krb5cc_75401103_X5yEyy
systemd-private-3d87c249e8a84451994ad692609cd4b6-apache2.service-77w9dT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-resolved.service-RnMUhT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-timesyncd.service-FAnDql
vmware-root_662-2689143848

```
## Referencias

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux](https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux)

{{#include ../../../../banners/hacktricks-training.md}}
