## CGroups

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información básica

Los **grupos de control de Linux**, también conocidos como cgroups, son una característica del kernel de Linux que permite **limitar**, controlar y priorizar los **recursos del sistema** para una colección de procesos. Los cgroups proporcionan una forma de **gestionar y aislar el uso de recursos** (CPU, memoria, E/S de disco, red, etc.) de grupos de procesos en un sistema. Esto puede ser útil para muchos propósitos, como limitar los recursos disponibles para un grupo particular de procesos, aislar ciertos tipos de cargas de trabajo de otros o priorizar el uso de recursos del sistema entre diferentes grupos de procesos.

Existen **dos versiones de cgroups**, 1 y 2, y ambas se utilizan actualmente y se pueden configurar simultáneamente en un sistema. La diferencia **más significativa** entre la versión 1 y la **versión 2** de cgroups es que esta última introdujo una nueva organización jerárquica para los cgroups, donde los grupos se pueden organizar en una estructura **similar a un árbol** con relaciones padre-hijo. Esto permite un control más flexible y detallado sobre la asignación de recursos entre diferentes grupos de procesos.

Además de la nueva organización jerárquica, la versión 2 de cgroups también introdujo **varios otros cambios y mejoras**, como el soporte para **nuevos controladores de recursos**, un mejor soporte para aplicaciones heredadas y un mejor rendimiento.

En general, cgroups **versión 2 ofrece más características y mejor rendimiento** que la versión 1, pero esta última aún puede ser utilizada en ciertos escenarios donde la compatibilidad con sistemas más antiguos es una preocupación.

Puede listar los cgroups v1 y v2 para cualquier proceso mirando su archivo cgroup en /proc/\<pid>. Puede comenzar mirando los cgroups de su shell con este comando:
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
No te alarmes si la **salida es significativamente más corta** en tu sistema; esto solo significa que probablemente **solo tengas cgroups v2**. Cada línea de salida aquí comienza con un número y es un cgroup diferente. Aquí hay algunos consejos sobre cómo leerlo:

* Los números 2-12 son para cgroups v1. Los **controladores** para esos se enumeran junto al número.
* El número 1 también es para la **versión 1**, pero no tiene un controlador. Este cgroup es solo para **propósitos de gestión** (en este caso, systemd lo configuró).
* La última línea, el número 0, es para **cgroups v2**. No hay controladores visibles aquí. En un sistema que no tiene cgroups v1, esta será la única línea de salida.
* Los **nombres son jerárquicos y parecen partes de rutas de archivos**. Puedes ver en este ejemplo que algunos de los cgroups se llaman /user.slice y otros /user.slice/user-1000.slice/session-2.scope.
* El nombre /testcgroup se creó para mostrar que en cgroups v1, los cgroups para un proceso pueden ser completamente independientes.
* Los nombres bajo user.slice que incluyen sesión son sesiones de inicio de sesión, asignadas por systemd. Los verás cuando estés mirando los cgroups de una shell. Los cgroups para tus servicios del sistema estarán bajo system.slice.

### Visualización de cgroups

Los cgroups se **acceden típicamente a través del sistema de archivos**. Esto es en contraste con la interfaz de llamada al sistema Unix tradicional para interactuar con el kernel.\
Para explorar la configuración de cgroup de una shell, puedes mirar en el archivo `/proc/self/cgroup` para encontrar el cgroup de la shell, y luego navegar al directorio `/sys/fs/cgroup` (o `/sys/fs/cgroup/unified`) y buscar un **directorio con el mismo nombre que el cgroup**. Cambiar a este directorio y mirar alrededor te permitirá ver los diversos **ajustes e información de uso de recursos para el cgroup**.

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

Entre los muchos archivos que pueden estar aquí, **los archivos de interfaz de cgroup primarios comienzan con `cgroup`**. Comienza mirando `cgroup.procs` (usar cat está bien), que lista los procesos en el cgroup. Un archivo similar, `cgroup.threads`, también incluye hilos.

<figure><img src="../../../.gitbook/assets/image (1) (1) (5).png" alt=""><figcaption></figcaption></figure>

La mayoría de los cgroups utilizados para shells tienen estos dos controladores, que pueden controlar la **cantidad de memoria** utilizada y el **número total de procesos en el cgroup**. Para interactuar con un controlador, busca los **archivos que coincidan con el prefijo del controlador**. Por ejemplo, si quieres ver el número de hilos que se ejecutan en el cgroup, consulta pids.current:

<figure><img src="../../../.gitbook/assets/image (3) (5).png" alt=""><figcaption></figcaption></figure>

Un valor de **max significa que este cgroup no tiene un límite específico**, pero debido a que los cgroups son jerárquicos, un cgroup hacia abajo en la cadena de subdirectorios podría limitarlo.

### Manipulación y creación de cgroups

Para poner un proceso en un cgroup, **escribe su PID en su archivo `cgroup.procs` como root:**
```shell-session
# echo pid > cgroup.procs
```
Así es como funcionan muchos cambios en cgroups. Por ejemplo, si desea **limitar el número máximo de PIDs de un cgroup** (a, digamos, 3.000 PIDs), hágalo de la siguiente manera:
```shell-session
# echo 3000 > pids.max
```
**Crear cgroups es más complicado**. Técnicamente, es tan fácil como crear un subdirectorio en algún lugar del árbol de cgroups; cuando lo haces, el kernel crea automáticamente los archivos de interfaz. Si un cgroup no tiene procesos, puedes eliminar el cgroup con rmdir incluso con los archivos de interfaz presentes. Lo que puede confundirte son las reglas que rigen los cgroups, incluyendo:

* Solo puedes poner **procesos en cgroups de nivel externo ("hoja")**. Por ejemplo, si tienes cgroups llamados /my-cgroup y /my-cgroup/my-subgroup, no puedes poner procesos en /my-cgroup, pero /my-cgroup/my-subgroup está bien. (Una excepción es si los cgroups no tienen controladores, pero no profundicemos más).
* Un cgroup **no puede tener un controlador que no esté en su cgroup padre**.
* Debes **especificar explícitamente los controladores para los cgroups hijos**. Lo haces a través del archivo `cgroup.subtree_control`; por ejemplo, si quieres que un cgroup hijo tenga los controladores de cpu y pids, escribe +cpu +pids en este archivo.

Una excepción a estas reglas es el **cgroup raíz** que se encuentra en la parte inferior de la jerarquía. Puedes **colocar procesos en este cgroup**. Una razón por la que podrías querer hacer esto es para separar un proceso del control de systemd.

Incluso sin controladores habilitados, puedes ver el uso de CPU de un cgroup mirando su archivo cpu.stat:

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption></figcaption></figure>

Debido a que este es el uso acumulado de CPU durante toda la vida útil del cgroup, puedes ver cómo un servicio consume tiempo de procesador incluso si genera muchos subprocesos que eventualmente terminan.
