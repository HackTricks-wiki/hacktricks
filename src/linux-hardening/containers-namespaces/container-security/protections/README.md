# Descripción general de las protecciones de los containers

{{#include ../../../../banners/hacktricks-training.md}}

La idea más importante del hardening de containers es que no existe un único control llamado "container security". Lo que se denomina aislamiento de containers es realmente el resultado de varios mecanismos de seguridad y gestión de recursos de Linux que trabajan conjuntamente. Si la documentación describe solo uno de ellos, los lectores tienden a sobreestimar su solidez. Si la documentación enumera todos ellos sin explicar cómo interactúan, los lectores obtienen un catálogo de nombres, pero ningún modelo real. Esta sección intenta evitar ambos errores.

En el centro del modelo están los **namespaces**, que aíslan lo que el workload puede ver. Proporcionan al proceso una vista privada o parcialmente privada de los montajes del filesystem, los PIDs, las redes, los objetos IPC, los hostnames, las asignaciones de usuarios/grupos, las rutas de cgroup y algunos relojes. Pero los namespaces por sí solos no deciden qué puede hacer un proceso. Ahí es donde entran las siguientes capas.

Los **cgroups** controlan el uso de recursos. No son principalmente un límite de aislamiento en el mismo sentido que los mount o PID namespaces, pero son cruciales desde el punto de vista operativo porque restringen la memoria, la CPU, los PIDs, la E/S y el acceso a dispositivos. También son relevantes para la seguridad porque históricas técnicas de breakout abusaron de funciones de cgroup modificables, especialmente en entornos cgroup v1.

Las **Capabilities** dividen el antiguo modelo de root todopoderoso en unidades de privilegio más pequeñas. Esto es fundamental para los containers porque muchos workloads todavía se ejecutan como UID 0 dentro del container. Por tanto, la pregunta no es simplemente "¿el proceso es root?", sino "¿qué capabilities sobrevivieron, dentro de qué namespaces y bajo qué restricciones de seccomp y MAC?". Por eso un proceso root en un container puede estar relativamente restringido, mientras que un proceso root en otro container puede ser prácticamente indistinguible de host root en la práctica.

**seccomp** filtra syscalls y reduce la superficie de ataque del kernel expuesta al workload. A menudo es el mecanismo que bloquea llamadas claramente peligrosas como `unshare`, `mount`, `keyctl` u otras syscalls utilizadas en cadenas de breakout. Aunque un proceso tenga una capability que permitiría realizar una operación, seccomp todavía puede bloquear la ruta de la syscall antes de que el kernel la procese por completo.

**AppArmor** y **SELinux** añaden Mandatory Access Control sobre las comprobaciones normales del filesystem y de privilegios. Son especialmente importantes porque siguen siendo relevantes incluso cuando un container tiene más capabilities de las que debería. Un workload puede tener el privilegio teórico para intentar una acción, pero aun así se le puede impedir ejecutarla porque su etiqueta o perfil prohíbe el acceso a la ruta, el objeto o la operación correspondientes.

Por último, existen capas de hardening adicionales que reciben menos atención, pero que importan con frecuencia en ataques reales: `no_new_privs`, rutas de procfs ocultas, rutas del sistema de solo lectura, root filesystems de solo lectura y valores predeterminados cuidadosos del runtime. Estos mecanismos suelen detener la "última milla" de un compromiso, especialmente cuando un atacante intenta convertir la ejecución de código en una obtención más amplia de privilegios.

El resto de esta carpeta explica cada uno de estos mecanismos con más detalle, incluyendo qué hace realmente la primitiva del kernel, cómo observarla localmente, cómo la utilizan los runtimes habituales y cómo los operadores la debilitan accidentalmente.

## Leer a continuación

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

Muchos escapes reales también dependen del contenido del host que se haya montado en el workload, por lo que, después de leer las protecciones principales, resulta útil continuar con:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
