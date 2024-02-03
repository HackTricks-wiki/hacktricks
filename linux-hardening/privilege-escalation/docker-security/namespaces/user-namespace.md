# Espacio de nombres de usuario

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

Un espacio de nombres de usuario es una característica del kernel de Linux que **proporciona aislamiento de las asignaciones de ID de usuario y grupo**, permitiendo que cada espacio de nombres de usuario tenga su **propio conjunto de ID de usuario y grupo**. Este aislamiento permite que los procesos que se ejecutan en diferentes espacios de nombres de usuario **tengan diferentes privilegios y propiedades**, incluso si comparten las mismas ID de usuario y grupo numéricamente.

Los espacios de nombres de usuario son particularmente útiles en la contenerización, donde cada contenedor debe tener su propio conjunto independiente de ID de usuario y grupo, permitiendo una mejor seguridad y aislamiento entre contenedores y el sistema anfitrión.

### Cómo funciona:

1. Cuando se crea un nuevo espacio de nombres de usuario, **comienza con un conjunto vacío de asignaciones de ID de usuario y grupo**. Esto significa que cualquier proceso que se ejecute en el nuevo espacio de nombres de usuario **inicialmente no tendrá privilegios fuera del espacio de nombres**.
2. Se pueden establecer asignaciones de ID entre las ID de usuario y grupo en el nuevo espacio de nombres y las del espacio de nombres padre (o anfitrión). Esto **permite que los procesos en el nuevo espacio de nombres tengan privilegios y propiedades correspondientes a las ID de usuario y grupo en el espacio de nombres padre**. Sin embargo, las asignaciones de ID pueden restringirse a rangos y subconjuntos específicos de ID, permitiendo un control detallado sobre los privilegios otorgados a los procesos en el nuevo espacio de nombres.
3. Dentro de un espacio de nombres de usuario, **los procesos pueden tener privilegios completos de root (UID 0) para operaciones dentro del espacio de nombres**, mientras que aún tienen privilegios limitados fuera del espacio de nombres. Esto permite **que los contenedores se ejecuten con capacidades similares a las de root dentro de su propio espacio de nombres sin tener privilegios completos de root en el sistema anfitrión**.
4. Los procesos pueden moverse entre espacios de nombres utilizando la llamada al sistema `setns()` o crear nuevos espacios de nombres utilizando las llamadas al sistema `unshare()` o `clone()` con la bandera `CLONE_NEWUSER`. Cuando un proceso se mueve a un nuevo espacio de nombres o crea uno, comenzará a usar las asignaciones de ID de usuario y grupo asociadas con ese espacio de nombres.

## Laboratorio:

### Crear diferentes Espacios de Nombres

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, te aseguras de que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información del proceso específica de ese espacio de nombres**.

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
- Ejecutar `%unshare -fp /bin/bash%` asegura que el comando `unshare` mismo se convierta en PID 1 en el nuevo espacio de nombres. `/bin/bash` y sus procesos hijos están entonces contenidos de manera segura dentro de este nuevo espacio de nombres, evitando la salida prematura del PID 1 y permitiendo la asignación normal de PID.

Asegurándote de que `unshare` se ejecute con la bandera `-f`, el nuevo espacio de nombres de PID se mantiene correctamente, permitiendo que `/bin/bash` y sus subprocesos operen sin encontrar el error de asignación de memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Para utilizar el espacio de nombres de usuario, el demonio de Docker necesita iniciarse con **`--userns-remap=default`** (En Ubuntu 14.04, esto se puede hacer modificando `/etc/default/docker` y luego ejecutando `sudo service docker restart`)

### &#x20;Verifica en qué espacio de nombres está tu proceso
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Es posible verificar el mapeo de usuario desde el contenedor de docker con:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
O desde el host con:
```bash
cat /proc/<pid>/uid_map
```
### Encuentra todos los espacios de nombres de usuario

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar dentro de un espacio de nombres de Usuario
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
También, solo puedes **entrar en el espacio de nombres de otro proceso si eres root**. Y **no puedes** **entrar** en otro espacio de nombres **sin un descriptor** que apunte a él (como `/proc/self/ns/user`).

### Crear nuevo espacio de nombres de Usuario (con mapeos)

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %}
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Recuperación de Capacidades

En el caso de los namespaces de usuario, **cuando se crea un nuevo namespace de usuario, el proceso que entra en el namespace recibe un conjunto completo de capacidades dentro de ese namespace**. Estas capacidades permiten al proceso realizar operaciones privilegiadas como **montar** **sistemas de archivos**, crear dispositivos o cambiar la propiedad de archivos, pero **solo dentro del contexto de su namespace de usuario**.

Por ejemplo, cuando tienes la capacidad `CAP_SYS_ADMIN` dentro de un namespace de usuario, puedes realizar operaciones que típicamente requieren esta capacidad, como montar sistemas de archivos, pero solo dentro del contexto de tu namespace de usuario. Cualquier operación que realices con esta capacidad no afectará al sistema anfitrión ni a otros namespaces.

{% hint style="warning" %}
Por lo tanto, aunque obtener un nuevo proceso dentro de un nuevo User namespace **te devolverá todas las capacidades** (CapEff: 000001ffffffffff), en realidad **solo puedes usar las relacionadas con el namespace** (montar, por ejemplo) pero no todas. Por lo tanto, esto por sí solo no es suficiente para escapar de un contenedor Docker.
{% endhint %}
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
Probando: 0x143 . . . Error
```
# Referencias
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
