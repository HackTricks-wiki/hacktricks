# Rutas enmascaradas

{{#include ../../../../banners/hacktricks-training.md}}

Las rutas enmascaradas son protecciones en tiempo de ejecución que ocultan ubicaciones del sistema de archivos especialmente sensibles y orientadas al kernel desde el contenedor mediante bind-mounting sobre ellas o haciéndolas inaccesibles de otro modo. El propósito es evitar que una workload interactúe directamente con interfaces que las aplicaciones ordinarias no necesitan, especialmente dentro de procfs.

Esto importa porque muchos container escapes y trucos que afectan al host comienzan leyendo o escribiendo archivos especiales bajo `/proc` o `/sys`. Si esas ubicaciones están enmascaradas, el atacante pierde el acceso directo a una parte útil de la superficie de control del kernel incluso después de obtener ejecución de código dentro del contenedor.

## Operación

Los runtimes comúnmente enmascaran rutas seleccionadas como:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

La lista exacta depende del runtime y de la configuración del host. Lo importante es que la ruta se vuelve inaccesible o es reemplazada desde el punto de vista del contenedor, aunque siga existiendo en el host.

## Laboratorio

Inspecciona la configuración de masked-path expuesta por Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Inspecciona el comportamiento real de los mounts dentro del workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Impacto en la seguridad

El enmascaramiento no establece la principal frontera de aislamiento, pero elimina varios objetivos de alto valor en post-explotación. Sin enmascaramiento, un contenedor comprometido puede ser capaz de inspeccionar el estado del kernel, leer información sensible de procesos o de claves, o interactuar con objetos de procfs/sysfs que nunca deberían haber sido visibles para la aplicación.

## Configuraciones incorrectas

El error principal es desenmascarar amplias clases de rutas por conveniencia o depuración. En Podman esto puede aparecer como `--security-opt unmask=ALL` o desenmascarado dirigido. En Kubernetes, una exposición excesiva de proc puede aparecer mediante `procMount: Unmasked`. Otro problema grave es exponer el `/proc` o `/sys` del host mediante un bind mount, lo que anula por completo la idea de una vista reducida del contenedor.

## Abuso

Si el enmascaramiento es débil o está ausente, comience identificando qué rutas sensibles de procfs/sysfs son accesibles directamente:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Si una ruta supuestamente enmascarada es accesible, inspecciónala cuidadosamente:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Qué pueden revelar estos comandos:

- /proc/timer_list puede exponer datos del temporizador y del planificador del host. Esto es mayormente una primitiva de reconocimiento, pero confirma que el contenedor puede leer información del kernel que normalmente está oculta.
- /proc/keys es mucho más sensible. Dependiendo de la configuración del host, puede revelar entradas del keyring, descripciones de claves y relaciones entre servicios del host que usan el subsistema de keyring del kernel.
- /sys/firmware ayuda a identificar el modo de arranque, las interfaces de firmware y detalles de la plataforma que son útiles para el fingerprinting del host y para entender si la carga de trabajo está viendo el estado a nivel de host.
- /proc/config.gz puede revelar la configuración del kernel en ejecución, lo que es valioso para coincidir los prerequisitos de exploits públicos del kernel o para entender por qué una característica específica es accesible.
- /proc/sched_debug expone el estado del planificador y a menudo evita la expectativa intuitiva de que el espacio de nombres PID debería ocultar por completo la información de procesos no relacionados.

Resultados interesantes incluyen lecturas directas de esos archivos, evidencia de que los datos pertenecen al host en lugar de a una vista de contenedor restringida, o acceso a otras ubicaciones de procfs/sysfs que comúnmente están enmascaradas por defecto.

## Checks

El objetivo de estas comprobaciones es determinar qué rutas el runtime ocultó intencionalmente y si la carga de trabajo actual todavía ve un sistema de archivos orientado al kernel reducido.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Lo interesante aquí:

- Una larga lista de rutas enmascaradas es normal en runtimes reforzados.
- La falta de enmascaramiento en entradas sensibles de procfs merece una inspección más detallada.
- Si una ruta sensible es accesible y el contenedor también tiene capacidades elevadas o montajes amplios del host, la exposición importa más.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por defecto | Docker define una lista predeterminada de rutas enmascaradas | exponer montajes del host proc/sys, `--privileged` |
| Podman | Habilitado por defecto | Podman aplica rutas enmascaradas por defecto a menos que se desenmascaren manualmente | `--security-opt unmask=ALL`, desenmascaramiento dirigido, `--privileged` |
| Kubernetes | Hereda los valores predeterminados del runtime | Usa el comportamiento de enmascaramiento del runtime subyacente a menos que la configuración del Pod debilite la exposición de proc | `procMount: Unmasked`, patrones de cargas de trabajo privilegiadas, montajes amplios del host |
| containerd / CRI-O under Kubernetes | Predeterminado del runtime | Por lo general aplica rutas enmascaradas de OCI/runtime a menos que se sobrescriba | cambios directos en la configuración del runtime, mismas vías de debilitamiento de Kubernetes |

Las rutas enmascaradas suelen estar presentes por defecto. El problema operativo principal no es su ausencia en el runtime, sino el desenmascaramiento deliberado o los montajes de enlace del host que anulan la protección.
{{#include ../../../../banners/hacktricks-training.md}}
