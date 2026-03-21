# Rutas enmascaradas

{{#include ../../../../banners/hacktricks-training.md}}

Las rutas enmascaradas son protecciones en tiempo de ejecución que ocultan ubicaciones del sistema de archivos especialmente sensibles orientadas al kernel desde el contenedor, ya sea montándolas por bind-mounting o haciéndolas inaccesibles de otro modo. El propósito es impedir que una carga de trabajo interactúe directamente con interfaces que las aplicaciones ordinarias no necesitan, especialmente dentro de procfs.

Esto importa porque muchas container escapes y técnicas que afectan al host comienzan leyendo o escribiendo archivos especiales bajo `/proc` o `/sys`. Si esas ubicaciones están enmascaradas, el atacante pierde el acceso directo a una parte útil de la superficie de control del kernel incluso después de obtener ejecución de código dentro del contenedor.

## Funcionamiento

Los runtimes suelen enmascarar rutas seleccionadas como:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

La lista exacta depende del runtime y de la configuración del host. La propiedad importante es que la ruta se vuelve inaccesible o sustituida desde el punto de vista del contenedor, aunque aún exista en el host.

## Laboratorio

Inspecciona la configuración masked-path expuesta por Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Inspeccione el comportamiento real de montaje dentro de la carga de trabajo:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Impacto en la seguridad

El enmascaramiento no crea la principal frontera de aislamiento, pero elimina varios objetivos de alto valor en post-explotación. Sin enmascaramiento, un contenedor comprometido puede inspeccionar el estado del kernel, leer información sensible de procesos o de claves, o interactuar con objetos de procfs/sysfs que nunca deberían haber sido visibles para la aplicación.

## Misconfiguraciones

El error principal es desmascarar clases amplias de rutas por conveniencia o depuración. En Podman esto puede aparecer como `--security-opt unmask=ALL` o desmascarado dirigido. En Kubernetes, una exposición excesivamente amplia de proc puede aparecer mediante `procMount: Unmasked`. Otro problema serio es exponer el host `/proc` o `/sys` a través de un bind mount, lo que anula por completo la idea de una vista reducida del contenedor.

## Abuso

Si el enmascaramiento es débil o está ausente, comienza identificando qué rutas sensibles de procfs/sysfs son directamente accesibles:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Si una ruta supuestamente enmascarada es accesible, inspecciónela cuidadosamente:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Lo que estos comandos pueden revelar:

- `/proc/timer_list` puede exponer datos de temporizadores y del planificador del host. Esto es principalmente una primitiva de reconocimiento, pero confirma que el contenedor puede leer información orientada al kernel que normalmente está oculta.
- `/proc/keys` es mucho más sensible. Dependiendo de la configuración del host, puede revelar entradas del keyring, descripciones de claves y las relaciones entre servicios del host que usan el subsistema keyring del kernel.
- `/sys/firmware` ayuda a identificar el modo de arranque, las interfaces de firmware y detalles de la plataforma que son útiles para el fingerprinting del host y para entender si la carga de trabajo está viendo el estado a nivel de host.
- `/proc/config.gz` puede revelar la configuración del kernel en ejecución, lo cual es valioso para coincidir con requisitos previos de exploits públicos del kernel o para entender por qué una característica específica es alcanzable.
- `/proc/sched_debug` expone el estado del planificador y a menudo elude la expectativa intuitiva de que el PID namespace debería ocultar por completo la información de procesos no relacionados.

Resultados interesantes incluyen lecturas directas de esos archivos, evidencia de que los datos pertenecen al host en lugar de a una vista de contenedor restringida, o acceso a otras ubicaciones de procfs/sysfs que comúnmente están enmascaradas por defecto.

## Comprobaciones

El objetivo de estas comprobaciones es determinar qué rutas el runtime ocultó intencionalmente y si la carga de trabajo actual aún ve un sistema de archivos orientado al kernel reducido.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Lo interesante aquí:

- Una larga lista de rutas enmascaradas es normal en runtimes reforzados.
- La falta de enmascaramiento en entradas sensibles de procfs merece una inspección más detallada.
- Si una ruta sensible es accesible y el contenedor también tiene capacidades elevadas o montajes amplios, la exposición importa más.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker defines a default masked path list | exponer montajes del host proc/sys, `--privileged` |
| Podman | Enabled by default | Podman applies default masked paths unless unmasked manually | `--security-opt unmask=ALL`, desenmascarado dirigido, `--privileged` |
| Kubernetes | Inherits runtime defaults | Uses the underlying runtime's masking behavior unless Pod settings weaken proc exposure | `procMount: Unmasked`, patrones de cargas de trabajo privilegiadas, montajes amplios del host |
| containerd / CRI-O under Kubernetes | Runtime default | Usually applies OCI/runtime masked paths unless overridden | cambios directos en la configuración del runtime, mismas vías de debilitamiento de Kubernetes |

Las rutas enmascaradas suelen estar presentes por defecto. El problema operativo principal no es su ausencia en el runtime, sino el desenmascarado deliberado o los montajes bind del host que anulan la protección.
