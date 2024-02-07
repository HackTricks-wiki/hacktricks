# CGroups

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Información Básica

**Linux Control Groups**, o **cgroups**, son una característica del kernel de Linux que permite la asignación, limitación y priorización de recursos del sistema como CPU, memoria y E/S de disco entre grupos de procesos. Ofrecen un mecanismo para **gestionar y aislar el uso de recursos** de colecciones de procesos, beneficioso para propósitos como limitación de recursos, aislamiento de carga de trabajo y priorización de recursos entre diferentes grupos de procesos.

Existen **dos versiones de cgroups**: versión 1 y versión 2. Ambas pueden ser utilizadas simultáneamente en un sistema. La distinción principal es que **cgroups versión 2** introduce una **estructura jerárquica en forma de árbol**, permitiendo una distribución de recursos más matizada y detallada entre grupos de procesos. Además, la versión 2 trae varias mejoras, incluyendo:

Además de la nueva organización jerárquica, cgroups versión 2 también introdujo **varios otros cambios y mejoras**, como soporte para **nuevos controladores de recursos**, mejor soporte para aplicaciones heredadas y mejor rendimiento.

En general, cgroups **versión 2 ofrece más características y mejor rendimiento** que la versión 1, pero esta última aún puede ser utilizada en ciertos escenarios donde la compatibilidad con sistemas más antiguos es una preocupación.

Puedes listar los cgroups v1 y v2 para cualquier proceso mirando su archivo cgroup en /proc/\<pid>. Puedes empezar mirando los cgroups de tu shell con este comando:
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
La estructura de salida es la siguiente:

- **Números 2-12**: cgroups v1, donde cada línea representa un cgroup diferente. Los controladores para estos se especifican junto al número.
- **Número 1**: También cgroups v1, pero únicamente con fines de gestión (establecido por, por ejemplo, systemd), y carece de un controlador.
- **Número 0**: Representa cgroups v2. No se enumeran controladores, y esta línea es exclusiva en sistemas que solo ejecutan cgroups v2.
- Los **nombres son jerárquicos**, se asemejan a rutas de archivos, lo que indica la estructura y relación entre diferentes cgroups.
- Nombres como /user.slice o /system.slice especifican la categorización de cgroups, con user.slice típicamente para sesiones de inicio de sesión gestionadas por systemd y system.slice para servicios del sistema.

### Visualización de cgroups

El sistema de archivos se utiliza típicamente para acceder a **cgroups**, divergiendo de la interfaz de llamada al sistema Unix utilizada tradicionalmente para interacciones con el kernel. Para investigar la configuración de cgroups de una shell, se debe examinar el archivo **/proc/self/cgroup**, que revela el cgroup de la shell. Luego, al navegar hasta el directorio **/sys/fs/cgroup** (o **`/sys/fs/cgroup/unified`**) y localizar un directorio que comparta el nombre del cgroup, se pueden observar varios ajustes e información de uso de recursos pertinentes al cgroup.

![Sistema de archivos de Cgroup](../../../.gitbook/assets/image%20(10)%20(2)%20(2).png)

Los archivos de interfaz clave para cgroups tienen como prefijo **cgroup**. El archivo **cgroup.procs**, que se puede ver con comandos estándar como cat, enumera los procesos dentro del cgroup. Otro archivo, **cgroup.threads**, incluye información de hilos.

![Cgroup Procs](../../../.gitbook/assets/image%20(1)%20(1)%20(5).png)

Los cgroups que gestionan shells típicamente abarcan dos controladores que regulan el uso de memoria y el recuento de procesos. Para interactuar con un controlador, se deben consultar los archivos que llevan el prefijo del controlador. Por ejemplo, **pids.current** se referiría para determinar el recuento de hilos en el cgroup.

![Memoria de Cgroup](../../../.gitbook/assets/image%20(3)%20(5).png)

La indicación de **max** en un valor sugiere la ausencia de un límite específico para el cgroup. Sin embargo, debido a la naturaleza jerárquica de los cgroups, los límites podrían ser impuestos por un cgroup en un nivel inferior en la jerarquía de directorios.


### Manipulación y Creación de cgroups

Los procesos se asignan a cgroups escribiendo su ID de proceso (PID) en el archivo `cgroup.procs`. Esto requiere privilegios de root. Por ejemplo, para agregar un proceso:
```bash
echo [pid] > cgroup.procs
```
Del mismo modo, **modificar atributos de cgroup, como establecer un límite de PID**, se realiza escribiendo el valor deseado en el archivo relevante. Para establecer un máximo de 3,000 PIDs para un cgroup:
```bash
echo 3000 > pids.max
```
**Crear nuevos cgroups** implica crear un nuevo subdirectorio dentro de la jerarquía de cgroups, lo que hace que el kernel genere automáticamente los archivos de interfaz necesarios. Aunque los cgroups sin procesos activos pueden eliminarse con `rmdir`, ten en cuenta ciertas restricciones:

- **Los procesos solo pueden ubicarse en cgroups hoja** (es decir, los más anidados en una jerarquía).
- **Un cgroup no puede tener un controlador ausente en su padre**.
- **Los controladores para los cgroups hijos deben declararse explícitamente** en el archivo `cgroup.subtree_control`. Por ejemplo, para habilitar los controladores de CPU y PID en un cgroup hijo:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
El **cgroup raíz** es una excepción a estas reglas, permitiendo la colocación directa de procesos. Esto se puede utilizar para eliminar procesos del manejo de systemd.

**Monitorear el uso de CPU** dentro de un cgroup es posible a través del archivo `cpu.stat`, que muestra el tiempo total de CPU consumido, útil para rastrear el uso en los subprocesos de un servicio:

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption>Estadísticas de uso de CPU como se muestra en el archivo cpu.stat</figcaption></figure>

## Referencias
* **Libro: Cómo funciona Linux, 3ra edición: Lo que todo superusuario debería saber por Brian Ward**
