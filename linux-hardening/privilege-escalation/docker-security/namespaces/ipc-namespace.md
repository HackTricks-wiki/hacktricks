# Espacio de nombres IPC

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

Un espacio de nombres IPC (Inter-Process Communication) es una característica del kernel de Linux que proporciona **aislamiento** de objetos IPC de System V, como colas de mensajes, segmentos de memoria compartida y semáforos. Este aislamiento garantiza que los procesos en **diferentes espacios de nombres IPC no puedan acceder directamente o modificar los objetos IPC de los demás**, proporcionando una capa adicional de seguridad y privacidad entre grupos de procesos.

### Cómo funciona:

1. Cuando se crea un nuevo espacio de nombres IPC, comienza con un **conjunto completamente aislado de objetos IPC de System V**. Esto significa que los procesos que se ejecutan en el nuevo espacio de nombres IPC no pueden acceder o interferir con los objetos IPC en otros espacios de nombres o en el sistema host de forma predeterminada.
2. Los objetos IPC creados dentro de un espacio de nombres son visibles y **accesibles solo para los procesos dentro de ese espacio de nombres**. Cada objeto IPC se identifica por una clave única dentro de su espacio de nombres. Aunque la clave puede ser idéntica en diferentes espacios de nombres, los objetos mismos están aislados y no pueden ser accedidos entre espacios de nombres.
3. Los procesos pueden moverse entre espacios de nombres utilizando la llamada al sistema `setns()` o crear nuevos espacios de nombres utilizando las llamadas al sistema `unshare()` o `clone()` con la bandera `CLONE_NEWIPC`. Cuando un proceso se mueve a un nuevo espacio de nombres o crea uno, comenzará a utilizar los objetos IPC asociados con ese espacio de nombres.

## Laboratorio:

### Crear diferentes Espacios de Nombres

#### Línea de comandos
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` si se utiliza el parámetro `--mount-proc`, se asegura de que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información de procesos específica de ese espacio de nombres**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Cuando se ejecuta `unshare` sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos espacios de nombres de PID (Identificador de Proceso). A continuación se describen los detalles clave y la solución:

1. **Explicación del Problema**:
- El kernel de Linux permite a un proceso crear nuevos espacios de nombres utilizando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo espacio de nombres de PID (llamado proceso "unshare") no entra en el nuevo espacio de nombres; solo lo hacen sus procesos secundarios.
- Ejecutar `%unshare -p /bin/bash%` inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos secundarios están en el espacio de nombres de PID original.
- El primer proceso secundario de `/bin/bash` en el nuevo espacio de nombres se convierte en PID 1. Cuando este proceso sale, desencadena la limpieza del espacio de nombres si no hay otros procesos, ya que PID 1 tiene el papel especial de adoptar procesos huérfanos. El kernel de Linux deshabilitará entonces la asignación de PID en ese espacio de nombres.

2. **Consecuencia**:
- La salida de PID 1 en un nuevo espacio de nombres conduce a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto resulta en que la función `alloc_pid` falle al asignar un nuevo PID al crear un nuevo proceso, lo que produce el error "Cannot allocate memory".

3. **Solución**:
- El problema se puede resolver utilizando la opción `-f` con `unshare`. Esta opción hace que `unshare` bifurque un nuevo proceso después de crear el nuevo espacio de nombres de PID.
- Al ejecutar `%unshare -fp /bin/bash%`, se asegura de que el comando `unshare` mismo se convierta en PID 1 en el nuevo espacio de nombres. Luego, `/bin/bash` y sus procesos secundarios están contenidos de manera segura dentro de este nuevo espacio de nombres, evitando la salida prematura de PID 1 y permitiendo una asignación normal de PID.

Al garantizar que `unshare` se ejecute con la bandera `-f`, el nuevo espacio de nombres de PID se mantiene correctamente, lo que permite que `/bin/bash` y sus subprocesos funcionen sin encontrar el error de asignación de memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Verificar en qué espacio de nombres está su proceso
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Encontrar todos los espacios de nombres IPC

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Entrar dentro de un espacio de nombres IPC
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
También, solo puedes **entrar en otro espacio de nombres de proceso si eres root**. Y **no puedes** **entrar** en otro espacio de nombres **sin un descriptor** que apunte a él (como `/proc/self/ns/net`).

### Crear objeto IPC
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## Referencias
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)



<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
