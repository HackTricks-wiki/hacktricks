# Espacio de nombres de usuario

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información básica

Un espacio de nombres de usuario es una característica del kernel de Linux que **proporciona el aislamiento de las asignaciones de ID de usuario y grupo**, permitiendo que cada espacio de nombres de usuario tenga su **propio conjunto de ID de usuario y grupo**. Este aislamiento permite que los procesos que se ejecutan en diferentes espacios de nombres de usuario **tengan diferentes privilegios y propietarios**, incluso si comparten los mismos ID de usuario y grupo numéricamente.

Los espacios de nombres de usuario son particularmente útiles en la contenerización, donde cada contenedor debe tener su propio conjunto independiente de ID de usuario y grupo, permitiendo una mejor seguridad y aislamiento entre los contenedores y el sistema host.

### Cómo funciona:

1. Cuando se crea un nuevo espacio de nombres de usuario, **comienza con un conjunto vacío de asignaciones de ID de usuario y grupo**. Esto significa que cualquier proceso que se ejecute en el nuevo espacio de nombres de usuario **inicialmente no tendrá privilegios fuera del espacio de nombres**.
2. Se pueden establecer asignaciones de ID entre los ID de usuario y grupo en el nuevo espacio de nombres y los del espacio de nombres padre (o host). Esto **permite que los procesos en el nuevo espacio de nombres tengan privilegios y propietarios correspondientes a los ID de usuario y grupo en el espacio de nombres padre**. Sin embargo, las asignaciones de ID se pueden restringir a rangos y subconjuntos específicos de ID, lo que permite un control detallado sobre los privilegios otorgados a los procesos en el nuevo espacio de nombres.
3. Dentro de un espacio de nombres de usuario, **los procesos pueden tener privilegios de root completos (UID 0) para operaciones dentro del espacio de nombres**, mientras que aún tienen privilegios limitados fuera del espacio de nombres. Esto permite que **los contenedores se ejecuten con capacidades similares a las de root dentro de su propio espacio de nombres sin tener privilegios de root completos en el sistema host**.
4. Los procesos pueden moverse entre espacios de nombres utilizando la llamada al sistema `setns()` o crear nuevos espacios de nombres utilizando las llamadas al sistema `unshare()` o `clone()` con la bandera `CLONE_NEWUSER`. Cuando un proceso se mueve a un nuevo espacio de nombres o crea uno, comenzará a usar las asignaciones de ID de usuario y grupo asociadas con ese espacio de nombres.

## Laboratorio:

### Crear diferentes espacios de nombres

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` utilizando el parámetro `--mount-proc`, se asegura de que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información de proceso específica de ese espacio de nombres**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Si ejecutas la línea anterior sin `-f`, obtendrás ese error.\
El error es causado por el proceso PID 1 que sale en el nuevo espacio de nombres.

Después de que bash comience a ejecutarse, bifurcará varios nuevos subprocesos para hacer algunas cosas. Si ejecutas unshare sin -f, bash tendrá el mismo PID que el proceso "unshare" actual. El proceso "unshare" actual llama al sistema de llamadas unshare, crea un nuevo espacio de nombres de PID, pero el proceso "unshare" actual no está en el nuevo espacio de nombres de PID. Es el comportamiento deseado del kernel de Linux: el proceso A crea un nuevo espacio de nombres, el proceso A en sí mismo no se colocará en el nuevo espacio de nombres, solo los subprocesos del proceso A se colocarán en el nuevo espacio de nombres. Entonces, cuando ejecutas:
```
unshare -p /bin/bash
```
El proceso unshare ejecutará /bin/bash, y /bin/bash bifurcará varios subprocesos, el primer subproceso de bash se convertirá en PID 1 del nuevo espacio de nombres, y el subproceso saldrá después de completar su trabajo. Por lo tanto, el PID 1 del nuevo espacio de nombres sale.

El proceso PID 1 tiene una función especial: debe convertirse en el proceso padre de todos los procesos huérfanos. Si el proceso PID 1 en el espacio de nombres raíz sale, el kernel entrará en pánico. Si el proceso PID 1 en un subespacio de nombres sale, el kernel de Linux llamará a la función disable\_pid\_allocation, que limpiará la bandera PIDNS\_HASH\_ADDING en ese espacio de nombres. Cuando el kernel de Linux crea un nuevo proceso, llama a la función alloc\_pid para asignar un PID en un espacio de nombres, y si la bandera PIDNS\_HASH\_ADDING no está establecida, la función alloc\_pid devolverá un error -ENOMEM. Es por eso que aparece el error "Cannot allocate memory".

Puede resolver este problema utilizando la opción '-f':
```
unshare -fp /bin/bash
```
Si ejecutas unshare con la opción '-f', unshare bifurcará un nuevo proceso después de crear el nuevo espacio de nombres pid. Y ejecutará /bin/bash en el nuevo proceso. El nuevo proceso será el pid 1 del nuevo espacio de nombres pid. Luego, bash también bifurcará varios subprocesos para realizar algunas tareas. Como bash en sí mismo es el pid 1 del nuevo espacio de nombres pid, sus subprocesos pueden salir sin ningún problema.

Copiado de [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Para usar el espacio de nombres de usuario, el demonio de Docker debe iniciarse con **`--userns-remap=default`** (En Ubuntu 14.04, esto se puede hacer modificando `/etc/default/docker` y luego ejecutando `sudo service docker restart`)

### &#x20;Comprobar en qué espacio de nombres se encuentra su proceso
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
También, solo puedes **entrar en otro namespace de proceso si eres root**. Y no puedes **entrar** en otro namespace **sin un descriptor** que apunte a él (como `/proc/self/ns/user`).

### Crear un nuevo User namespace (con mapeos)

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %} (This tag should not be translated)
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Recuperando capacidades

En el caso de los espacios de nombres de usuario, **cuando se crea un nuevo espacio de nombres de usuario, el proceso que entra en el espacio de nombres recibe un conjunto completo de capacidades dentro de ese espacio de nombres**. Estas capacidades permiten al proceso realizar operaciones privilegiadas como **montar** **sistemas de archivos**, crear dispositivos o cambiar la propiedad de archivos, pero **solo dentro del contexto de su espacio de nombres de usuario**.

Por ejemplo, cuando tienes la capacidad `CAP_SYS_ADMIN` dentro de un espacio de nombres de usuario, puedes realizar operaciones que normalmente requieren esta capacidad, como montar sistemas de archivos, pero solo dentro del contexto de tu espacio de nombres de usuario. Cualquier operación que realices con esta capacidad no afectará al sistema host ni a otros espacios de nombres.

{% hint style="warning" %}
Por lo tanto, incluso si obtener un nuevo proceso dentro de un nuevo espacio de nombres de usuario **te devolverá todas las capacidades** (CapEff: 000001ffffffffff), en realidad solo puedes **usar las relacionadas con el espacio de nombres** (como montar) pero no todas. Por lo tanto, esto por sí solo no es suficiente para escapar de un contenedor Docker.
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
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
