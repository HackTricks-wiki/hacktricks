# Espacio de Usuario

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

Un espacio de usuario es una característica del kernel de Linux que **proporciona aislamiento de los mapeos de ID de usuario y grupo**, permitiendo que cada espacio de usuario tenga su **propio conjunto de IDs de usuario y grupo**. Este aislamiento permite que los procesos que se ejecutan en diferentes espacios de usuario **tengan diferentes privilegios y propietarios**, incluso si comparten los mismos IDs de usuario y grupo numéricamente.

Los espacios de usuario son particularmente útiles en la contenerización, donde cada contenedor debe tener su propio conjunto independiente de IDs de usuario y grupo, lo que permite una mejor seguridad y aislamiento entre los contenedores y el sistema host.

### Cómo funciona:

1. Cuando se crea un nuevo espacio de usuario, **comienza con un conjunto vacío de mapeos de ID de usuario y grupo**. Esto significa que cualquier proceso que se ejecute en el nuevo espacio de usuario **inicialmente no tendrá privilegios fuera del espacio de usuario**.
2. Se pueden establecer mapeos de ID entre los IDs de usuario y grupo en el nuevo espacio de usuario y los del espacio de usuario padre (o host). Esto **permite que los procesos en el nuevo espacio de usuario tengan privilegios y propietarios correspondientes a los IDs de usuario y grupo en el espacio de usuario padre**. Sin embargo, los mapeos de ID pueden estar restringidos a rangos específicos y subconjuntos de IDs, lo que permite un control detallado sobre los privilegios otorgados a los procesos en el nuevo espacio de usuario.
3. Dentro de un espacio de usuario, **los procesos pueden tener privilegios de root completos (UID 0) para operaciones dentro del espacio de usuario**, mientras siguen teniendo privilegios limitados fuera del espacio de usuario. Esto permite que **los contenedores se ejecuten con capacidades similares a root dentro de su propio espacio de usuario sin tener privilegios de root completos en el sistema host**.
4. Los procesos pueden moverse entre espacios de usuario utilizando la llamada al sistema `setns()` o crear nuevos espacios de usuario utilizando las llamadas al sistema `unshare()` o `clone()` con la bandera `CLONE_NEWUSER`. Cuando un proceso se mueve a un nuevo espacio de usuario o crea uno, comenzará a utilizar los mapeos de ID de usuario y grupo asociados con ese espacio de usuario.

## Laboratorio:

### Crear diferentes Espacios de Usuario

#### Línea de Comandos
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` si se utiliza el parámetro `--mount-proc`, se asegura de que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información de procesos específica para ese espacio de nombres**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Cuando `unshare` se ejecuta sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos espacios de nombres de PID (Identificador de Proceso). A continuación se detallan los aspectos clave y la solución:

1. **Explicación del Problema**:
- El kernel de Linux permite que un proceso cree nuevos espacios de nombres utilizando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo espacio de nombres de PID (llamado proceso "unshare") no entra en el nuevo espacio de nombres; solo lo hacen sus procesos secundarios.
- Ejecutar `%unshare -p /bin/bash%` inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos secundarios están en el espacio de nombres de PID original.
- El primer proceso secundario de `/bin/bash` en el nuevo espacio de nombres se convierte en PID 1. Cuando este proceso sale, desencadena la limpieza del espacio de nombres si no hay otros procesos, ya que PID 1 tiene el papel especial de adoptar procesos huérfanos. El kernel de Linux deshabilitará entonces la asignación de PID en ese espacio de nombres.

2. **Consecuencia**:
- La salida de PID 1 en un nuevo espacio de nombres conduce a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto resulta en que la función `alloc_pid` falle al asignar un nuevo PID al crear un nuevo proceso, lo que produce el error "Cannot allocate memory".

3. **Solución**:
- El problema se puede resolver utilizando la opción `-f` con `unshare`. Esta opción hace que `unshare` bifurque un nuevo proceso después de crear el nuevo espacio de nombres de PID.
- Al ejecutar `%unshare -fp /bin/bash%`, se asegura de que el comando `unshare` en sí mismo se convierta en PID 1 en el nuevo espacio de nombres. `/bin/bash` y sus procesos secundarios quedan contenidos de manera segura dentro de este nuevo espacio de nombres, evitando la salida prematura de PID 1 y permitiendo una asignación normal de PID.

Al garantizar que `unshare` se ejecute con la bandera `-f`, el nuevo espacio de nombres de PID se mantiene correctamente, lo que permite que `/bin/bash` y sus subprocesos funcionen sin encontrar el error de asignación de memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Para utilizar el espacio de nombres de usuario, el demonio de Docker debe iniciarse con **`--userns-remap=default`** (En Ubuntu 14.04, esto se puede hacer modificando `/etc/default/docker` y luego ejecutando `sudo service docker restart`)

### &#x20;Verifique en qué espacio de nombres se encuentra su proceso
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Es posible verificar el mapa de usuarios del contenedor de Docker con:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
O desde el host con:
```bash
cat /proc/<pid>/uid_map
```
### Encontrar todos los espacios de nombres de usuario

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Entrar dentro de un espacio de nombres de usuario
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
También, solo puedes **entrar en otro espacio de nombres de proceso si eres root**. Y **no puedes** **entrar** en otro espacio de nombres **sin un descriptor** que apunte a él (como `/proc/self/ns/user`).

### Crear un nuevo espacio de nombres de usuario (con mapeos)
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

En el caso de los espacios de nombres de usuario, **cuando se crea un nuevo espacio de nombres de usuario, el proceso que ingresa al espacio de nombres recibe un conjunto completo de capacidades dentro de ese espacio de nombres**. Estas capacidades permiten que el proceso realice operaciones privilegiadas como **montar sistemas de archivos**, crear dispositivos o cambiar la propiedad de archivos, pero **solo dentro del contexto de su espacio de nombres de usuario**.

Por ejemplo, cuando tienes la capacidad `CAP_SYS_ADMIN` dentro de un espacio de nombres de usuario, puedes realizar operaciones que normalmente requieren esta capacidad, como montar sistemas de archivos, pero solo dentro del contexto de tu espacio de nombres de usuario. Cualquier operación que realices con esta capacidad no afectará al sistema host u otros espacios de nombres.

{% hint style="warning" %}
Por lo tanto, incluso si obtener un nuevo proceso dentro de un nuevo espacio de nombres de usuario **te devolverá todas las capacidades** (CapEff: 000001ffffffffff), en realidad solo puedes **utilizar las relacionadas con el espacio de nombres** (como montar), pero no todas. Por lo tanto, esto por sí solo no es suficiente para escapar de un contenedor Docker.
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
## Referencias
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
