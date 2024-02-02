# Espacio de nombres IPC

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

Un espacio de nombres IPC (Comunicación Entre Procesos) es una característica del kernel de Linux que proporciona **aislamiento** de objetos IPC de System V, como colas de mensajes, segmentos de memoria compartida y semáforos. Este aislamiento asegura que los procesos en **diferentes espacios de nombres IPC no puedan acceder o modificar directamente los objetos IPC de los demás**, proporcionando una capa adicional de seguridad y privacidad entre grupos de procesos.

### Cómo funciona:

1. Cuando se crea un nuevo espacio de nombres IPC, comienza con un **conjunto completamente aislado de objetos IPC de System V**. Esto significa que los procesos que se ejecutan en el nuevo espacio de nombres IPC no pueden acceder o interferir con los objetos IPC en otros espacios de nombres o en el sistema anfitrión por defecto.
2. Los objetos IPC creados dentro de un espacio de nombres son visibles y **accesibles solo para los procesos dentro de ese espacio de nombres**. Cada objeto IPC se identifica por una clave única dentro de su espacio de nombres. Aunque la clave puede ser idéntica en diferentes espacios de nombres, los objetos en sí están aislados y no se pueden acceder entre espacios de nombres.
3. Los procesos pueden moverse entre espacios de nombres utilizando la llamada al sistema `setns()` o crear nuevos espacios de nombres utilizando las llamadas al sistema `unshare()` o `clone()` con la bandera `CLONE_NEWIPC`. Cuando un proceso se mueve a un nuevo espacio de nombres o crea uno, comenzará a usar los objetos IPC asociados con ese espacio de nombres.

## Laboratorio:

### Crear diferentes Espacios de Nombres

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, te aseguras de que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información del proceso específica para ese espacio de nombres**.

<details>

<summary>Error: bash: fork: No se puede asignar memoria</summary>

Si ejecutas la línea anterior sin `-f`, obtendrás ese error.\
El error es causado porque el proceso PID 1 sale en el nuevo espacio de nombres.

Después de que bash comienza a ejecutarse, bash generará varios subprocesos nuevos para hacer algunas cosas. Si ejecutas unshare sin -f, bash tendrá el mismo pid que el proceso "unshare" actual. El proceso "unshare" actual llama al systemcall unshare, crea un nuevo espacio de nombres pid, pero el proceso "unshare" actual no está en el nuevo espacio de nombres pid. Es el comportamiento deseado del kernel de Linux: el proceso A crea un nuevo espacio de nombres, el propio proceso A no se colocará en el nuevo espacio de nombres, solo los subprocesos del proceso A se colocarán en el nuevo espacio de nombres. Entonces, cuando ejecutas:
</details>
```
unshare -p /bin/bash
```
El proceso unshare ejecutará /bin/bash, y /bin/bash generará varios subprocesos, el primer subproceso de bash se convertirá en el PID 1 del nuevo espacio de nombres, y el subproceso saldrá después de completar su trabajo. Por lo tanto, el PID 1 del nuevo espacio de nombres sale.

El proceso PID 1 tiene una función especial: debe convertirse en el proceso padre de todos los procesos huérfanos. Si el proceso PID 1 en el espacio de nombres raíz sale, el kernel entrará en pánico. Si el proceso PID 1 en un subespacio de nombres sale, el kernel de Linux llamará a la función disable_pid_allocation, que limpiará la bandera PIDNS_HASH_ADDING en ese espacio de nombres. Cuando el kernel de Linux crea un nuevo proceso, el kernel llamará a la función alloc_pid para asignar un PID en un espacio de nombres, y si la bandera PIDNS_HASH_ADDING no está establecida, la función alloc_pid devolverá un error -ENOMEM. Por eso recibiste el error "Cannot allocate memory".

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
```
### &#x20;Verifica en qué espacio de nombres está tu proceso
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Encuentra todos los espacios de nombres IPC

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
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
<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
