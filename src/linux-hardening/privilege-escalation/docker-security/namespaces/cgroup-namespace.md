# CGroup Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Información Básica

Un cgroup namespace es una característica del kernel de Linux que proporciona **aislamiento de jerarquías de cgroup para procesos que se ejecutan dentro de un namespace**. Los cgroups, abreviatura de **grupos de control**, son una característica del kernel que permite organizar procesos en grupos jerárquicos para gestionar y hacer cumplir **límites en los recursos del sistema** como CPU, memoria y E/S.

Aunque los cgroup namespaces no son un tipo de namespace separado como los otros que discutimos anteriormente (PID, mount, network, etc.), están relacionados con el concepto de aislamiento de namespace. **Los cgroup namespaces virtualizan la vista de la jerarquía de cgroup**, de modo que los procesos que se ejecutan dentro de un cgroup namespace tienen una vista diferente de la jerarquía en comparación con los procesos que se ejecutan en el host u otros namespaces.

### Cómo funciona:

1. Cuando se crea un nuevo cgroup namespace, **comienza con una vista de la jerarquía de cgroup basada en el cgroup del proceso creador**. Esto significa que los procesos que se ejecutan en el nuevo cgroup namespace solo verán un subconjunto de toda la jerarquía de cgroup, limitado al subárbol de cgroup enraizado en el cgroup del proceso creador.
2. Los procesos dentro de un cgroup namespace **verán su propio cgroup como la raíz de la jerarquía**. Esto significa que, desde la perspectiva de los procesos dentro del namespace, su propio cgroup aparece como la raíz, y no pueden ver ni acceder a cgroups fuera de su propio subárbol.
3. Los cgroup namespaces no proporcionan directamente aislamiento de recursos; **solo proporcionan aislamiento de la vista de la jerarquía de cgroup**. **El control y aislamiento de recursos aún son aplicados por los subsistemas de cgroup** (por ejemplo, cpu, memoria, etc.) mismos.

Para más información sobre CGroups consulta:

{{#ref}}
../cgroups.md
{{#endref}}

## Laboratorio:

### Crear diferentes Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, aseguras que el nuevo espacio de montaje tenga una **vista precisa y aislada de la información del proceso específica para ese espacio de nombres**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Cuando se ejecuta `unshare` sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos espacios de nombres de PID (Identificación de Proceso). Los detalles clave y la solución se describen a continuación:

1. **Explicación del Problema**:

- El núcleo de Linux permite a un proceso crear nuevos espacios de nombres utilizando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo espacio de nombres de PID (denominado proceso "unshare") no entra en el nuevo espacio de nombres; solo lo hacen sus procesos hijos.
- Ejecutar `%unshare -p /bin/bash%` inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos hijos están en el espacio de nombres de PID original.
- El primer proceso hijo de `/bin/bash` en el nuevo espacio de nombres se convierte en PID 1. Cuando este proceso sale, desencadena la limpieza del espacio de nombres si no hay otros procesos, ya que PID 1 tiene el papel especial de adoptar procesos huérfanos. El núcleo de Linux deshabilitará entonces la asignación de PID en ese espacio de nombres.

2. **Consecuencia**:

- La salida de PID 1 en un nuevo espacio de nombres lleva a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto resulta en que la función `alloc_pid` falle al intentar asignar un nuevo PID al crear un nuevo proceso, produciendo el error "Cannot allocate memory".

3. **Solución**:
- El problema se puede resolver utilizando la opción `-f` con `unshare`. Esta opción hace que `unshare` cree un nuevo proceso después de crear el nuevo espacio de nombres de PID.
- Ejecutar `%unshare -fp /bin/bash%` asegura que el comando `unshare` se convierta en PID 1 en el nuevo espacio de nombres. `/bin/bash` y sus procesos hijos están entonces contenidos de manera segura dentro de este nuevo espacio de nombres, previniendo la salida prematura de PID 1 y permitiendo la asignación normal de PID.

Al asegurarte de que `unshare` se ejecute con la bandera `-f`, el nuevo espacio de nombres de PID se mantiene correctamente, permitiendo que `/bin/bash` y sus subprocesos operen sin encontrar el error de asignación de memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Verifica en qué namespace está tu proceso
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Encontrar todos los espacios de nombres CGroup
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar dentro de un namespace CGroup
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
También, solo puedes **entrar en otro espacio de nombres de proceso si eres root**. Y **no puedes** **entrar** en otro espacio de nombres **sin un descriptor** que apunte a él (como `/proc/self/ns/cgroup`).

## Referencias

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
