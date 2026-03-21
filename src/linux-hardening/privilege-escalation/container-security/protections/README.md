# Resumen de protecciones de contenedores

{{#include ../../../../banners/hacktricks-training.md}}

La idea más importante en el hardening de contenedores es que no existe un único control llamado "container security". Lo que la gente llama "container isolation" es en realidad el resultado de varios mecanismos de seguridad y gestión de recursos de Linux trabajando juntos. Si la documentación describe solo uno de ellos, los lectores tienden a sobrestimar su fortaleza. Si la documentación enumera todos sin explicar cómo interactúan, los lectores obtienen un catálogo de nombres pero no un modelo real. Esta sección intenta evitar ambos errores.

En el centro del modelo están **namespaces**, que aíslan lo que la carga de trabajo puede ver. Proporcionan al proceso una vista privada o parcialmente privada de montajes del sistema de archivos, PIDs, networking, objetos IPC, hostnames, mapeos de usuario/grupo, rutas de cgroup y algunos relojes. Pero los namespaces por sí solos no deciden lo que un proceso puede hacer. Ahí es donde entran las siguientes capas.

**cgroups** gobiernan el uso de recursos. No son principalmente un límite de aislamiento en el mismo sentido que los mount o PID namespaces, pero son cruciales operativamente porque limitan memoria, CPU, PIDs, I/O y acceso a dispositivos. También tienen relevancia en seguridad porque técnicas históricas de breakout abusaron de características de cgroup escribibles, especialmente en entornos de cgroup v1.

**capabilities** dividen el antiguo modelo de root todopoderoso en unidades de privilegio más pequeñas. Esto es fundamental para contenedores porque muchas cargas de trabajo todavía se ejecutan como UID 0 dentro del contenedor. La cuestión no es solo "¿es el proceso root?", sino más bien "¿qué capabilities sobrevivieron, dentro de qué namespaces, bajo qué restricciones seccomp y MAC?" Por eso un proceso root en un contenedor puede estar relativamente restringido mientras que un proceso root en otro contenedor puede ser en la práctica casi indistinguible del root del host.

**seccomp** filtra syscalls y reduce la superficie de ataque del kernel expuesta a la carga de trabajo. A menudo es el mecanismo que bloquea llamadas obviamente peligrosas como `unshare`, `mount`, `keyctl` u otras syscalls usadas en cadenas de breakout. Incluso si un proceso tiene una capability que de otro modo permitiría una operación, seccomp aún puede bloquear la ruta de la syscall antes de que el kernel la procese completamente.

**AppArmor** y **SELinux** añaden Mandatory Access Control además de las comprobaciones normales de sistema de archivos y privilegios. Estas son particularmente importantes porque siguen teniendo efecto incluso cuando un contenedor tiene más capacidades de las que debería. Una carga de trabajo puede poseer el privilegio teórico para intentar una acción pero aun así verse impedida porque su label o profile prohíbe el acceso a la ruta, objeto u operación relevante.

Finalmente, hay capas adicionales de hardening que reciben menos atención pero que importan regularmente en ataques reales: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems, y valores predeterminados de runtime cautelosos. Estos mecanismos a menudo detienen la "última milla" de una compromisión, especialmente cuando un atacante intenta convertir ejecución de código en una ganancia de privilegios más amplia.

El resto de esta carpeta explica cada uno de estos mecanismos con más detalle, incluyendo qué hace realmente el primitivo del kernel, cómo observarlo localmente, cómo lo usan los runtimes comunes y cómo los operadores lo debilitan accidentalmente.

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

Muchas evasiones reales también dependen de qué contenido del host se montó dentro de la carga de trabajo, así que después de leer las protecciones centrales es útil continuar con:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
