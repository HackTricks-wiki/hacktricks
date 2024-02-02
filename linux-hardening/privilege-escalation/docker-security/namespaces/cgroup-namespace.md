# Espacio de nombres CGroup

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

Un espacio de nombres cgroup es una característica del kernel de Linux que proporciona **aislamiento de jerarquías de cgroup para procesos que se ejecutan dentro de un espacio de nombres**. Los cgroups, abreviatura de **control groups**, son una característica del kernel que permite organizar procesos en grupos jerárquicos para gestionar y aplicar **límites a los recursos del sistema** como CPU, memoria y E/S.

Aunque los espacios de nombres cgroup no son un tipo de espacio de nombres separado como los otros que discutimos anteriormente (PID, montaje, red, etc.), están relacionados con el concepto de aislamiento de espacio de nombres. **Los espacios de nombres cgroup virtualizan la vista de la jerarquía de cgroup**, de modo que los procesos que se ejecutan dentro de un espacio de nombres cgroup tienen una vista diferente de la jerarquía en comparación con los procesos que se ejecutan en el host u otros espacios de nombres.

### Cómo funciona:

1. Cuando se crea un nuevo espacio de nombres cgroup, **comienza con una vista de la jerarquía de cgroup basada en el cgroup del proceso creador**. Esto significa que los procesos que se ejecutan en el nuevo espacio de nombres cgroup solo verán un subconjunto de toda la jerarquía de cgroup, limitado al subárbol de cgroup enraizado en el cgroup del proceso creador.
2. Los procesos dentro de un espacio de nombres cgroup **verán su propio cgroup como la raíz de la jerarquía**. Esto significa que, desde la perspectiva de los procesos dentro del espacio de nombres, su propio cgroup aparece como la raíz, y no pueden ver ni acceder a cgroups fuera de su propio subárbol.
3. Los espacios de nombres cgroup no proporcionan directamente aislamiento de recursos; **solo proporcionan aislamiento de la vista de la jerarquía de cgroup**. **El control y aislamiento de recursos todavía son aplicados por los subsistemas de cgroup** (por ejemplo, cpu, memoria, etc.) en sí mismos.

Para más información sobre CGroups consulta:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Laboratorio:

### Crear diferentes Espacios de Nombres

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, te aseguras de que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información del proceso específica para ese espacio de nombres**.

<details>

<summary>Error: bash: fork: No se puede asignar memoria</summary>

Si ejecutas la línea anterior sin `-f`, obtendrás ese error.\
El error es causado porque el proceso PID 1 sale en el nuevo espacio de nombres.

Después de que bash comience a ejecutarse, bash generará varios subprocesos nuevos para hacer algunas cosas. Si ejecutas unshare sin -f, bash tendrá el mismo pid que el proceso "unshare" actual. El proceso "unshare" actual llama a la llamada al sistema unshare, crea un nuevo espacio de nombres pid, pero el proceso "unshare" actual no está en el nuevo espacio de nombres pid. Es el comportamiento deseado del kernel de Linux: el proceso A crea un nuevo espacio de nombres, el propio proceso A no se colocará en el nuevo espacio de nombres, solo los subprocesos del proceso A se colocarán en el nuevo espacio de nombres. Entonces, cuando ejecutas:
</details>
```
unshare -p /bin/bash
```
El proceso unshare ejecutará /bin/bash, y /bin/bash generará varios subprocesos, el primer subproceso de bash se convertirá en el PID 1 del nuevo espacio de nombres, y el subproceso saldrá después de completar su trabajo. Entonces, el PID 1 del nuevo espacio de nombres sale.

El proceso PID 1 tiene una función especial: debe convertirse en el proceso padre de todos los procesos huérfanos. Si el proceso PID 1 en el espacio de nombres raíz sale, el kernel entrará en pánico. Si el proceso PID 1 en un subespacio de nombres sale, el kernel de Linux llamará a la función disable_pid_allocation, que limpiará la bandera PIDNS_HASH_ADDING en ese espacio de nombres. Cuando el kernel de Linux crea un nuevo proceso, el kernel llamará a la función alloc_pid para asignar un PID en un espacio de nombres, y si la bandera PIDNS_HASH_ADDING no está establecida, la función alloc_pid devolverá un error -ENOMEM. Por eso recibiste el error "Cannot allocate memory".

Puedes resolver este problema utilizando la opción '-f':
```
unshare -fp /bin/bash
```
Si ejecutas unshare con la opción '-f', unshare bifurcará un nuevo proceso después de crear el nuevo espacio de nombres pid. Y ejecutará /bin/bash en el nuevo proceso. El nuevo proceso será el pid 1 del nuevo espacio de nombres pid. Luego, bash también bifurcará varios subprocesos para realizar algunas tareas. Como bash es el pid 1 del nuevo espacio de nombres pid, sus subprocesos pueden salir sin ningún problema.

Copiado de [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Comprueba en qué espacio de nombres se encuentra tu proceso
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Encuentra todos los espacios de nombres CGroup

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar dentro de un espacio de nombres CGroup
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
También, solo puedes **entrar en otro espacio de nombres de proceso si eres root**. Y **no puedes** **entrar** en otro espacio de nombres **sin un descriptor** que apunte a él (como `/proc/self/ns/cgroup`).

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
