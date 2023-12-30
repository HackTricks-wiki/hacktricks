# CGroups

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

Los **grupos de control de Linux**, también conocidos como cgroups, son una característica del kernel de Linux que permite **limitar**, regular y priorizar los **recursos del sistema** para un conjunto de procesos. Los cgroups ofrecen una manera de **gestionar y aislar el uso de recursos** (CPU, memoria, E/S de disco, red, etc.) de grupos de procesos en un sistema. Esto puede ser útil para muchos propósitos, como limitar los recursos disponibles para un grupo particular de procesos, aislar ciertos tipos de cargas de trabajo de otros, o priorizar el uso de recursos del sistema entre diferentes grupos de procesos.

Hay **dos versiones de cgroups**, 1 y 2, y ambas están actualmente en uso y pueden configurarse simultáneamente en un sistema. La **diferencia más significativa** entre la versión 1 de cgroups y la **versión 2** es que esta última introdujo una nueva organización jerárquica para los cgroups, donde los grupos pueden organizarse en una **estructura de árbol** con relaciones de padres e hijos. Esto permite un control más flexible y detallado sobre la asignación de recursos entre diferentes grupos de procesos.

Además de la nueva organización jerárquica, la versión 2 de cgroups también introdujo **varios otros cambios y mejoras**, como soporte para **nuevos controladores de recursos**, mejor soporte para aplicaciones heredadas y un rendimiento mejorado.

En general, la **versión 2 de cgroups ofrece más características y mejor rendimiento** que la versión 1, pero esta última aún puede usarse en ciertos escenarios donde la compatibilidad con sistemas más antiguos es una preocupación.

Puedes listar los cgroups v1 y v2 para cualquier proceso mirando su archivo cgroup en /proc/\<pid>. Puedes comenzar mirando los cgroups de tu shell con este comando:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
No te alarmes si el **output es significativamente más corto** en tu sistema; esto simplemente significa que probablemente **solo tienes cgroups v2**. Cada línea de salida aquí comienza con un número y es un cgroup diferente. Aquí hay algunos consejos sobre cómo leerlo:

* **Los números 2–12 son para cgroups v1**. Los **controladores** para esos están listados al lado del número.
* **El número 1** también es para **versión 1**, pero no tiene un controlador. Este cgroup es solo para **propósitos de gestión** (en este caso, systemd lo configuró).
* La última línea, **número 0**, es para **cgroups v2**. No se ven controladores aquí. En un sistema que no tiene cgroups v1, esta será la única línea de salida.
* **Los nombres son jerárquicos y parecen partes de rutas de archivos**. Puedes ver en este ejemplo que algunos de los cgroups se nombran /user.slice y otros /user.slice/user-1000.slice/session-2.scope.
* El nombre /testcgroup se creó para mostrar que en cgroups v1, los cgroups para un proceso pueden ser completamente independientes.
* **Los nombres bajo user.slice** que incluyen sesión son sesiones de inicio de sesión, asignadas por systemd. Los verás cuando estés mirando los cgroups de una shell. Los **cgroups** para tus **servicios del sistema** estarán **bajo system.slice**.

### Visualizando cgroups

Los cgroups se acceden típicamente **a través del sistema de archivos**. Esto contrasta con la interfaz tradicional de llamadas al sistema Unix para interactuar con el kernel.\
Para explorar la configuración de cgroup de una shell, puedes mirar en el archivo `/proc/self/cgroup` para encontrar el cgroup de la shell, y luego navegar al directorio `/sys/fs/cgroup` (o `/sys/fs/cgroup/unified`) y buscar un **directorio con el mismo nombre que el cgroup**. Cambiar a este directorio y mirar alrededor te permitirá ver los **ajustes e información de uso de recursos para el cgroup**.

<figure><img src="../../../.gitbook/assets/image (10) (2) (2).png" alt=""><figcaption></figcaption></figure>

Entre los muchos archivos que pueden estar aquí, **los archivos de interfaz de cgroup primarios comienzan con `cgroup`**. Comienza mirando `cgroup.procs` (usar cat está bien), que lista los procesos en el cgroup. Un archivo similar, `cgroup.threads`, también incluye hilos.

<figure><img src="../../../.gitbook/assets/image (1) (1) (5).png" alt=""><figcaption></figcaption></figure>

La mayoría de los cgroups utilizados para shells tienen estos dos controladores, que pueden controlar la **cantidad de memoria** utilizada y el **número total de procesos en el cgroup**. Para interactuar con un controlador, busca los **archivos que coincidan con el prefijo del controlador**. Por ejemplo, si quieres ver el número de hilos que se ejecutan en el cgroup, consulta pids.current:

<figure><img src="../../../.gitbook/assets/image (3) (5).png" alt=""><figcaption></figcaption></figure>

Un valor de **max significa que este cgroup no tiene un límite específico**, pero debido a que los cgroups son jerárquicos, un cgroup más abajo en la cadena de subdirectorios podría limitarlo.

### Manipulando y Creando cgroups

Para poner un proceso en un cgroup, **escribe su PID en su archivo `cgroup.procs` como root:**
```shell-session
# echo pid > cgroup.procs
```
Así es como funcionan muchos cambios en cgroups. Por ejemplo, si quieres **limitar el número máximo de PIDs de un cgroup** (a, digamos, 3,000 PIDs), hazlo de la siguiente manera:
```shell-session
# echo 3000 > pids.max
```
**Crear cgroups es más complicado**. Técnicamente, es tan fácil como crear un subdirectorio en algún lugar del árbol de cgroup; al hacerlo, el kernel crea automáticamente los archivos de interfaz. Si un cgroup no tiene procesos, puedes eliminar el cgroup con rmdir incluso con los archivos de interfaz presentes. Lo que puede confundirte son las reglas que rigen los cgroups, que incluyen:

* Solo puedes poner **procesos en cgroups de nivel externo ("hoja")**. Por ejemplo, si tienes cgroups llamados /my-cgroup y /my-cgroup/my-subgroup, no puedes poner procesos en /my-cgroup, pero en /my-cgroup/my-subgroup está bien. (Una excepción es si los cgroups no tienen controladores, pero no profundicemos más).
* Un cgroup **no puede tener un controlador que no esté en su cgroup padre**.
* Debes **especificar explícitamente los controladores para los cgroups hijos**. Haces esto a través del archivo `cgroup.subtree_control`; por ejemplo, si quieres que un cgroup hijo tenga los controladores de cpu y pids, escribe +cpu +pids en este archivo.

Una excepción a estas reglas es el **cgroup raíz** que se encuentra en la parte inferior de la jerarquía. Puedes **colocar procesos en este cgroup**. Una razón por la que podrías querer hacer esto es para desvincular un proceso del control de systemd.

Incluso sin controladores habilitados, puedes ver el uso de CPU de un cgroup mirando su archivo cpu.stat:

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption></figcaption></figure>

Dado que este es el uso acumulado de CPU durante toda la vida útil del cgroup, puedes ver cómo un servicio consume tiempo de procesador incluso si genera muchos subprocesos que eventualmente terminan.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
