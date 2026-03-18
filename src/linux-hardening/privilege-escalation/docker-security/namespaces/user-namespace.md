# Espacio de nombres de usuario

{{#include ../../../../banners/hacktricks-training.md}}

{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Referencias

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)



## Información básica

Un user namespace es una característica del kernel de Linux que **proporciona aislamiento de los mapeos de IDs de usuario y grupo**, permitiendo que cada user namespace tenga su **propio conjunto de IDs de usuario y grupo**. Este aislamiento permite que los procesos que se ejecutan en diferentes user namespaces **tengan distintos privilegios y propiedad**, incluso si comparten numéricamente los mismos IDs de usuario y grupo.

Los user namespaces son especialmente útiles en la contenedorización, donde cada contenedor debe tener su propio conjunto independiente de IDs de usuario y grupo, permitiendo una mejor seguridad y aislamiento entre los contenedores y el sistema anfitrión.

### Cómo funciona:

1. Cuando se crea un nuevo user namespace, este **comienza con un conjunto vacío de mapeos de IDs de usuario y grupo**. Esto significa que cualquier proceso que se ejecute en el nuevo namespace **inicialmente no tendrá privilegios fuera del namespace**.
2. Se pueden establecer mapeos de IDs entre los IDs de usuario y grupo en el nuevo namespace y los del namespace padre (o anfitrión). Esto **permite que los procesos en el nuevo namespace tengan privilegios y propiedad correspondientes a los IDs de usuario y grupo en el namespace padre**. Sin embargo, los mapeos de IDs pueden restringirse a rangos y subconjuntos específicos de IDs, permitiendo un control fino sobre los privilegios otorgados a los procesos en el nuevo namespace.
3. Dentro de un user namespace, **los procesos pueden tener privilegios de root completos (UID 0) para operaciones dentro del namespace**, mientras que siguen teniendo privilegios limitados fuera del namespace. Esto permite que **los contenedores se ejecuten con capacidades similares a root dentro de su propio namespace sin tener privilegios de root completos en el sistema anfitrión**.
4. Los procesos pueden moverse entre namespaces usando la llamada al sistema `setns()` o crear nuevos namespaces usando las llamadas al sistema `unshare()` o `clone()` con la bandera `CLONE_NEWUSER`. Cuando un proceso se mueve a un nuevo namespace o crea uno, comenzará a usar los mapeos de IDs de usuario y grupo asociados con ese namespace.

## Laboratorio:

### Crear diferentes espacios de nombres

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, aseguras que el nuevo namespace de montaje tenga una **vista precisa y aislada de la información de procesos específica de ese namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Cuando `unshare` se ejecuta sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos PID (Process ID) namespaces. Los detalles clave y la solución se describen a continuación:

1. **Explicación del problema**:

- El kernel de Linux permite que un proceso cree nuevos namespaces usando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo PID namespace (denominado proceso "unshare") no entra en el nuevo namespace; solo lo hacen sus procesos hijos.
- Ejecutar `%unshare -p /bin/bash%` inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos hijos están en el namespace PID original.
- El primer proceso hijo de `/bin/bash` en el nuevo namespace se convierte en PID 1. Cuando este proceso termina, provoca la limpieza del namespace si no hay otros procesos, ya que PID 1 tiene el rol especial de adoptar procesos huérfanos. El kernel de Linux entonces desactivará la asignación de PID en ese namespace.

2. **Consecuencia**:

- La salida de PID 1 en un nuevo namespace conduce a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto hace que la función `alloc_pid` falle al intentar asignar un nuevo PID al crear un proceso, produciendo el error "Cannot allocate memory".

3. **Solución**:
- El problema puede resolverse usando la opción `-f` con `unshare`. Esta opción hace que `unshare` haga fork de un nuevo proceso después de crear el nuevo PID namespace.
- Ejecutar `%unshare -fp /bin/bash%` asegura que el propio comando `unshare` se convierta en PID 1 en el nuevo namespace. `/bin/bash` y sus procesos hijos quedan así contenidos de forma segura dentro de este nuevo namespace, evitando la salida prematura de PID 1 y permitiendo la asignación normal de PID.

Al asegurarte de que `unshare` se ejecute con la bandera `-f`, el nuevo PID namespace se mantiene correctamente, permitiendo que `/bin/bash` y sus subprocesos operen sin encontrar el error de asignación de memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Para usar user namespace, el daemon de Docker debe iniciarse con **`--userns-remap=default`** (En ubuntu 14.04, esto puede hacerse modificando `/etc/default/docker` y luego ejecutando `sudo service docker restart`)

### Comprueba en qué namespace está tu proceso
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Es posible comprobar el mapa de usuarios desde el contenedor docker con:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
O desde el host con:
```bash
cat /proc/<pid>/uid_map
```
### Encontrar todos los User namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar dentro de un User namespace
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Además, solo puedes **entrar en el namespace de otro proceso si eres root**. Y **no puedes** **entrar** en otro namespace **sin un descriptor** que apunte a él (como `/proc/self/ns/user`).

### Crear un nuevo User namespace (con mapeos)
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Reglas de mapeo de UID/GID sin privilegios

Cuando el proceso que escribe en `uid_map`/`gid_map` **no tiene CAP_SETUID/CAP_SETGID en el parent user namespace**, el kernel aplica reglas más estrictas: sólo se permite un **único mapeo** para el UID/GID efectivo del llamador, y para `gid_map` **debe deshabilitar primero `setgroups(2)`** escribiendo `deny` en `/proc/<pid>/setgroups`.
```bash
# Check whether setgroups is allowed in this user namespace
cat /proc/self/setgroups   # allow|deny

# For unprivileged gid_map writes, disable setgroups first
echo deny > /proc/self/setgroups
```
### Montajes con mapeo de ID (MOUNT_ATTR_IDMAP)

ID-mapped mounts **asocian un mapeo de namespace de usuario a un punto de montaje**, de modo que la propiedad de los archivos se remapea cuando se accede a través de ese montaje. Esto se usa comúnmente en container runtimes (especialmente rootless) para **compartir rutas del host sin `chown` recursivo**, al mismo tiempo que se aplica la traducción de UID/GID del namespace de usuario.

Desde una perspectiva ofensiva, **si puedes crear un mount namespace y mantener `CAP_SYS_ADMIN` dentro de tu namespace de usuario**, y el sistema de ficheros soporta ID-mapped mounts, puedes remapear vistas de propiedad de bind mounts. Esto **no cambia la propiedad en disco**, pero puede hacer que archivos que de otro modo no serían escribibles aparezcan como propiedad de tu UID/GID mapeado dentro del namespace.

### Recuperación de capabilities

En el caso de los namespaces de usuario, **cuando se crea un nuevo namespace de usuario, al proceso que entra en el namespace se le concede un conjunto completo de capabilities dentro de ese namespace**. Estas capabilities permiten al proceso realizar operaciones privilegiadas como **montar** **sistemas de archivos**, crear dispositivos o cambiar la propiedad de archivos, pero **solo dentro del contexto de su namespace de usuario**.

Por ejemplo, cuando tienes la `CAP_SYS_ADMIN` capability dentro de un namespace de usuario, puedes realizar operaciones que normalmente requieren esta capability, como montar sistemas de archivos, pero solo dentro del contexto de tu namespace de usuario. Cualquier operación que realices con esta capability no afectará al sistema host ni a otros namespaces.

> [!WARNING]
> Therefore, even if getting a new process inside a new User namespace **will give you all the capabilities back** (CapEff: 000001ffffffffff), you actually can **only use the ones related to the namespace** (mount for example) but not every one. So, this on its own is not enough to escape from a Docker container.
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
```
{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Referencias

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

{{#include ../../../../banners/hacktricks-training.md}}
