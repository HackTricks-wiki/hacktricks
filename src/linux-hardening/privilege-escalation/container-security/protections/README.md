# Visión general de las protecciones de contenedores

{{#include ../../../../banners/hacktricks-training.md}}

La idea más importante en el endurecimiento de contenedores es que no existe un único control llamado "container security". Lo que la gente llama container isolation es, en realidad, el resultado de varios mecanismos de Linux para seguridad y gestión de recursos que trabajan conjuntamente. Si la documentación describe solo uno de ellos, los lectores tienden a sobrestimar su fortaleza. Si la documentación enumera todos sin explicar cómo interactúan, los lectores obtienen un catálogo de nombres pero ningún modelo real. Esta sección intenta evitar ambos errores.

En el centro del modelo están **namespaces**, que aíslan lo que el workload puede ver. Proporcionan al proceso una vista privada o parcialmente privada de mounts del sistema de archivos, PIDs, networking, objetos IPC, hostnames, mappings de usuario/grupo, rutas de cgroup y algunos relojes. Pero los namespaces por sí solos no deciden qué puede hacer un proceso. Ahí es donde entran las siguientes capas.

**cgroups** gobiernan el uso de recursos. No son principalmente un límite de aislamiento en el mismo sentido que los mount o PID namespaces, pero son cruciales operativamente porque restringen memoria, CPU, PIDs, I/O y acceso a dispositivos. También tienen relevancia en seguridad porque técnicas históricas de escape abusaban de características de cgroup escribibles, especialmente en entornos cgroup v1.

**Capabilities** fragmentan el antiguo modelo de root todopoderoso en unidades de privilegio más pequeñas. Esto es fundamental para contenedores porque muchas cargas de trabajo todavía se ejecutan como UID 0 dentro del contenedor. La cuestión, por tanto, no es simplemente "is the process root?", sino "which capabilities survived, inside which namespaces, under which seccomp and MAC restrictions?" Por eso un proceso root en un contenedor puede estar relativamente restringido mientras que un proceso root en otro contenedor puede, en la práctica, ser casi indistinguible del root del host.

**seccomp** filtra syscalls y reduce la superficie de ataque del kernel expuesta al workload. A menudo es el mecanismo que bloquea llamadas obviamente peligrosas como `unshare`, `mount`, `keyctl` u otras syscalls usadas en cadenas de escape. Incluso si un proceso tiene una capability que de otro modo permitiría una operación, seccomp puede bloquear la ruta del syscall antes de que el kernel la procese completamente.

**AppArmor** y **SELinux** añaden Mandatory Access Control sobre las comprobaciones normales de sistema de archivos y privilegios. Son particularmente importantes porque siguen teniendo efecto incluso cuando un contenedor tiene más capabilities de las que debería. Un workload puede poseer el privilegio teórico para intentar una acción pero aún así verse impedido de realizarla porque su etiqueta o perfil prohíbe el acceso al path, objeto u operación relevante.

Finalmente, hay capas adicionales de hardening que reciben menos atención pero que importan regularmente en ataques reales: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems y defaults de runtime cuidadosos. Estos mecanismos suelen detener la "última milla" de una compromisión, especialmente cuando un atacante intenta convertir la ejecución de código en una ganancia de privilegios más amplia.

El resto de esta carpeta explica cada uno de estos mecanismos con más detalle, incluyendo qué hace realmente la primitiva del kernel, cómo observarla localmente, cómo la usan los runtimes comunes y cómo los operadores la debilitan accidentalmente.

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

Muchas escapes reales también dependen del contenido del host que se montó en el workload, así que después de leer las protecciones principales es útil continuar con:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
