# Espacio de nombres CGroup

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Información Básica

Un espacio de nombres CGroup es una característica del kernel de Linux que proporciona **aislamiento de jerarquías de cgroups para procesos que se ejecutan dentro de un espacio de nombres**. Los cgroups, abreviatura de **grupos de control**, son una característica del kernel que permite organizar procesos en grupos jerárquicos para gestionar y hacer cumplir **límites en los recursos del sistema** como CPU, memoria y E/S.

Si bien los espacios de nombres de cgroups no son un tipo de espacio de nombres separado como los que discutimos anteriormente (PID, montaje, red, etc.), están relacionados con el concepto de aislamiento de espacios de nombres. **Los espacios de nombres de cgroups virtualizan la vista de la jerarquía de cgroups**, de modo que los procesos que se ejecutan dentro de un espacio de nombres de cgroups tienen una vista diferente de la jerarquía en comparación con los procesos que se ejecutan en el host u otros espacios de nombres.

### Cómo funciona:

1. Cuando se crea un nuevo espacio de nombres de cgroups, **comienza con una vista de la jerarquía de cgroups basada en el cgroup del proceso que lo crea**. Esto significa que los procesos que se ejecutan en el nuevo espacio de nombres de cgroups solo verán un subconjunto de toda la jerarquía de cgroups, limitada al subárbol de cgroups enraizado en el cgroup del proceso que lo crea.
2. Los procesos dentro de un espacio de nombres de cgroups **verán su propio cgroup como la raíz de la jerarquía**. Esto significa que, desde la perspectiva de los procesos dentro del espacio de nombres, su propio cgroup aparece como la raíz, y no pueden ver ni acceder a cgroups fuera de su propio subárbol.
3. Los espacios de nombres de cgroups no proporcionan directamente aislamiento de recursos; **solo proporcionan aislamiento de la vista de la jerarquía de cgroups**. **El control y aislamiento de recursos aún son aplicados por los subsistemas de cgroups** (por ejemplo, cpu, memoria, etc.) en sí mismos.

Para obtener más información sobre CGroups, consulta:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Laboratorio:

### Crear diferentes Espacios de Nombres

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` si se utiliza el parámetro `--mount-proc`, se asegura de que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información de procesos específica para ese espacio de nombres**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Cuando se ejecuta `unshare` sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos espacios de nombres de PID (Identificador de Proceso). A continuación se describen los detalles clave y la solución:

1. **Explicación del Problema**:
- El kernel de Linux permite que un proceso cree nuevos espacios de nombres utilizando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo espacio de nombres de PID (llamado proceso "unshare") no entra en el nuevo espacio de nombres; solo lo hacen sus procesos secundarios.
- Ejecutar `%unshare -p /bin/bash%` inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos secundarios están en el espacio de nombres de PID original.
- El primer proceso secundario de `/bin/bash` en el nuevo espacio de nombres se convierte en PID 1. Cuando este proceso sale, desencadena la limpieza del espacio de nombres si no hay otros procesos, ya que PID 1 tiene el papel especial de adoptar procesos huérfanos. El kernel de Linux deshabilitará entonces la asignación de PID en ese espacio de nombres.

2. **Consecuencia**:
- La salida de PID 1 en un nuevo espacio de nombres conduce a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto resulta en que la función `alloc_pid` falle al asignar un nuevo PID al crear un nuevo proceso, lo que produce el error "Cannot allocate memory".

3. **Solución**:
- El problema se puede resolver utilizando la opción `-f` con `unshare`. Esta opción hace que `unshare` bifurque un nuevo proceso después de crear el nuevo espacio de nombres de PID.
- Al ejecutar `%unshare -fp /bin/bash%`, se asegura de que el comando `unshare` se convierta en PID 1 en el nuevo espacio de nombres. `/bin/bash` y sus procesos secundarios están entonces contenidos de forma segura dentro de este nuevo espacio de nombres, evitando la salida prematura de PID 1 y permitiendo una asignación normal de PID.

Al garantizar que `unshare` se ejecute con la bandera `-f`, el nuevo espacio de nombres de PID se mantiene correctamente, lo que permite que `/bin/bash` y sus subprocesos funcionen sin encontrar el error de asignación de memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Verificar en qué espacio de nombres está su proceso
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

### Entrar dentro de un espacio de nombres de CGroup
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
También, solo puedes **entrar en otro espacio de nombres de proceso si eres root**. Y **no puedes** **entrar** en otro espacio de nombres **sin un descriptor** que apunte a él (como `/proc/self/ns/cgroup`).

## Referencias
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
