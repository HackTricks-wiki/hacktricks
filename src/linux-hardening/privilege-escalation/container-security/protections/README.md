# Visión general de protecciones de contenedores

{{#include ../../../../banners/hacktricks-training.md}}

La idea más importante en el hardening de contenedores es que no existe un único control llamado "container security". Lo que la gente llama aislamiento de contenedores es en realidad el resultado de varios mecanismos de seguridad y gestión de recursos de Linux trabajando juntos. Si la documentación describe solo uno de ellos, los lectores tienden a sobreestimar su fortaleza. Si la documentación lista todos sin explicar cómo interactúan, los lectores obtienen un catálogo de nombres pero ningún modelo real. Esta sección intenta evitar ambos errores.

En el centro del modelo están **namespaces**, que aíslan lo que la carga de trabajo puede ver. Proporcionan al proceso una vista privada o parcialmente privada de los montajes del sistema de archivos, PIDs, la red, objetos IPC, nombres de host, asignaciones de usuario/grupo, rutas de cgroup y algunos relojes. Pero las **namespaces** por sí solas no deciden lo que un proceso está autorizado a hacer. Ahí entran las siguientes capas.

**cgroups** gobiernan el uso de recursos. No son primordialmente un límite de aislamiento en el mismo sentido que las namespaces de montaje o PID, pero son cruciales operativamente porque restringen memoria, CPU, PIDs, I/O y acceso a dispositivos. También tienen relevancia para la seguridad porque técnicas históricas de escape abusaron de características de cgroup escribibles, especialmente en entornos cgroup v1.

**Capabilities** dividen el antiguo modelo de root todopoderoso en unidades de privilegio más pequeñas. Esto es fundamental para los contenedores porque muchas cargas de trabajo aún se ejecutan como UID 0 dentro del contenedor. La cuestión, por tanto, no es simplemente "¿es el proceso root?", sino "¿qué capabilities sobrevivieron, dentro de qué namespaces, bajo qué restricciones seccomp y MAC?" Por eso un proceso root en un contenedor puede estar relativamente restringido mientras que un proceso root en otro contenedor puede, en la práctica, ser casi indistinguible del root del host.

**seccomp** filtra las llamadas al sistema y reduce la superficie de ataque del kernel expuesta a la carga de trabajo. A menudo es el mecanismo que bloquea llamadas obviamente peligrosas como `unshare`, `mount`, `keyctl` u otras syscalls usadas en cadenas de escape. Incluso si un proceso tiene una capability que de otro modo permitiría una operación, seccomp puede bloquear la ruta de la syscall antes de que el kernel la procese completamente.

**AppArmor** y **SELinux** añaden Control de Acceso Mandatorio además de las comprobaciones normales de sistema de archivos y privilegios. Son particularmente importantes porque siguen importando incluso cuando un contenedor tiene más capabilities de las que debería. Una carga de trabajo puede poseer el privilegio teórico para intentar una acción pero aún así verse impedida de llevarla a cabo porque su etiqueta o perfil prohíbe el acceso a la ruta, objeto u operación relevante.

Finalmente, hay capas adicionales de hardening que reciben menos atención pero que importan regularmente en ataques reales: `no_new_privs`, rutas de procfs enmascaradas, rutas del sistema de solo lectura, sistemas de archivos root de solo lectura y valores por defecto de runtime cuidadosamente definidos. Estos mecanismos a menudo detienen la "última milla" de una compromisión, especialmente cuando un atacante intenta convertir la ejecución de código en una mayor ganancia de privilegios.

El resto de esta carpeta explica cada uno de estos mecanismos con más detalle, incluyendo lo que el primitivo del kernel hace realmente, cómo observarlo localmente, cómo lo usan los runtimes comunes y cómo los operadores lo debilitan accidentalmente.

## Read Next

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

Muchos escapes reales también dependen de qué contenido del host se montó dentro de la carga de trabajo, así que después de leer las protecciones centrales es útil continuar con:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
