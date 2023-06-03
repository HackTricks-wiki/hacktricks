# Espacio de nombres de CGroup

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información básica

Un espacio de nombres de CGroup es una característica del kernel de Linux que proporciona **aislamiento de jerarquías de cgroup para procesos que se ejecutan dentro de un espacio de nombres**. Los cgroups, abreviatura de **control groups**, son una característica del kernel que permite organizar procesos en grupos jerárquicos para administrar y hacer cumplir **límites en los recursos del sistema** como la CPU, la memoria y la E/S.

Si bien los espacios de nombres de cgroup no son un tipo de espacio de nombres separado como los que discutimos anteriormente (PID, montaje, red, etc.), están relacionados con el concepto de aislamiento de espacio de nombres. **Los espacios de nombres de cgroup virtualizan la vista de la jerarquía de cgroup**, de modo que los procesos que se ejecutan dentro de un espacio de nombres de cgroup tienen una vista diferente de la jerarquía en comparación con los procesos que se ejecutan en el host o en otros espacios de nombres.

### Cómo funciona:

1. Cuando se crea un nuevo espacio de nombres de cgroup, **comienza con una vista de la jerarquía de cgroup basada en el cgroup del proceso que lo crea**. Esto significa que los procesos que se ejecutan en el nuevo espacio de nombres de cgroup solo verán un subconjunto de toda la jerarquía de cgroup, limitado al subárbol de cgroup que tiene como raíz el cgroup del proceso que lo crea.
2. Los procesos dentro de un espacio de nombres de cgroup **verán su propio cgroup como la raíz de la jerarquía**. Esto significa que, desde la perspectiva de los procesos dentro del espacio de nombres, su propio cgroup aparece como la raíz, y no pueden ver ni acceder a cgroups fuera de su propio subárbol.
3. Los espacios de nombres de cgroup no proporcionan directamente el aislamiento de recursos; **solo proporcionan el aislamiento de la vista de la jerarquía de cgroup**. **El control y el aislamiento de recursos todavía son aplicados por los subsistemas de cgroup** (por ejemplo, cpu, memoria, etc.) en sí mismos.

Para obtener más información sobre CGroups, consulte:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Laboratorio:

### Crear diferentes espacios de nombres

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` utilizando el parámetro `--mount-proc`, se asegura de que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información de proceso específica de ese espacio de nombres**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Si ejecutas la línea anterior sin `-f`, obtendrás ese error.\
El error es causado por el proceso PID 1 que sale en el nuevo espacio de nombres.

Después de que bash comience a ejecutarse, bifurcará varios nuevos subprocesos para hacer algunas cosas. Si ejecutas unshare sin -f, bash tendrá el mismo PID que el proceso "unshare" actual. El proceso "unshare" actual llama al sistema de llamadas unshare, crea un nuevo espacio de nombres de PID, pero el proceso "unshare" actual no está en el nuevo espacio de nombres de PID. Es el comportamiento deseado del kernel de Linux: el proceso A crea un nuevo espacio de nombres, el proceso A en sí mismo no se colocará en el nuevo espacio de nombres, solo los subprocesos del proceso A se colocarán en el nuevo espacio de nombres. Por lo tanto, cuando ejecutas:
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
### &#x20;Verificar en qué espacio de nombres está su proceso
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Encontrar todos los espacios de nombres de CGroup

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Entrar dentro de un namespace CGroup
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
También, solo puedes **entrar en otro namespace de proceso si eres root**. Y no puedes **entrar** en otro namespace **sin un descriptor** que apunte a él (como `/proc/self/ns/cgroup`).
