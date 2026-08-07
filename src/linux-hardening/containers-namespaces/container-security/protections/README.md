# Descripción general de las protecciones de contenedores

{{#include ../../../../banners/hacktricks-training.md}}

La idea más importante en el hardening de contenedores es que no existe un único control llamado "container security". Lo que la gente denomina aislamiento de contenedores es, en realidad, el resultado de varios mecanismos de seguridad y gestión de recursos de Linux que funcionan conjuntamente. Si la documentación describe solo uno de ellos, los lectores tienden a sobreestimar su eficacia. Si la documentación enumera todos sin explicar cómo interactúan, los lectores obtienen un catálogo de nombres, pero no un modelo real. Esta sección intenta evitar ambos errores.

En el centro del modelo se encuentran los **namespaces**, que aíslan lo que la workload puede ver. Proporcionan al proceso una vista privada o parcialmente privada de los montajes del filesystem, los PIDs, la red, los objetos IPC, los hostnames, las asignaciones de usuarios/grupos, las rutas de cgroup y algunos relojes. Pero los namespaces por sí solos no determinan qué puede hacer un proceso. Ahí es donde entran las siguientes capas.

Los **cgroups** regulan el uso de recursos. No son principalmente un límite de aislamiento en el mismo sentido que los mount namespaces o PID namespaces, pero son cruciales desde el punto de vista operativo porque restringen la memoria, la CPU, los PIDs, la E/S y el acceso a dispositivos. También tienen relevancia para la seguridad porque las técnicas históricas de breakout abusaban de funcionalidades de cgroup que permitían escritura, especialmente en entornos cgroup v1.

Las **capabilities** dividen el antiguo modelo de root con todos los privilegios en unidades de privilegio más pequeñas. Esto es fundamental para los contenedores porque muchas workloads todavía se ejecutan como UID 0 dentro del contenedor. Por tanto, la pregunta no es simplemente "¿el proceso es root?", sino "¿qué capabilities sobrevivieron, dentro de qué namespaces y bajo qué restricciones de seccomp y MAC?" Por eso un proceso root en un contenedor puede estar relativamente restringido, mientras que un proceso root en otro contenedor puede ser, en la práctica, casi indistinguible de root en el host.

**seccomp** filtra syscalls y reduce la superficie de ataque del kernel expuesta a la workload. Este suele ser el mecanismo que bloquea llamadas claramente peligrosas como `unshare`, `mount`, `keyctl` u otras syscalls utilizadas en cadenas de breakout. Aunque un proceso tenga una capability que, de otro modo, permitiría una operación, seccomp aún puede bloquear la ruta de la syscall antes de que el kernel la procese por completo.

**AppArmor** y **SELinux** añaden Mandatory Access Control sobre las comprobaciones normales del filesystem y de privilegios. Son especialmente importantes porque siguen siendo relevantes incluso cuando un contenedor tiene más capabilities de las que debería. Una workload puede poseer el privilegio teórico para intentar una acción, pero aun así se le puede impedir llevarla a cabo porque su etiqueta o perfil prohíbe el acceso a la ruta, el objeto o la operación correspondiente.

Por último, existen capas adicionales de hardening que reciben menos atención, pero que suelen ser importantes en ataques reales: `no_new_privs`, rutas de procfs masked, rutas del sistema de solo lectura, root filesystems de solo lectura y valores predeterminados del runtime cuidadosamente configurados. Estos mecanismos suelen detener el "último tramo" de un compromiso, especialmente cuando un atacante intenta convertir la ejecución de código en una ampliación de privilegios más amplia.

El resto de esta carpeta explica cada uno de estos mecanismos con más detalle, incluido lo que hace realmente la primitiva del kernel, cómo observarla localmente, cómo la utilizan los runtimes habituales y cómo los operadores la debilitan accidentalmente.

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

Muchos escapes reales también dependen del contenido del host que se haya montado en la workload, por lo que, después de leer las protecciones principales, resulta útil continuar con:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}

{{#include ../../../../banners/hacktricks-training.md}}
