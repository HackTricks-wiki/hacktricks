# Rutas enmascaradas

{{#include ../../../../banners/hacktricks-training.md}}

Las rutas enmascaradas son protecciones en tiempo de ejecución que ocultan ubicaciones del sistema de archivos especialmente sensibles orientadas al kernel desde el contenedor mediante bind-mounting sobre ellas u otros métodos que las hagan inaccesibles. El propósito es evitar que una workload interactúe directamente con interfaces que las aplicaciones ordinarias no necesitan, especialmente dentro de procfs.

Esto importa porque muchos container escapes y trucos que afectan al host comienzan leyendo o escribiendo archivos especiales bajo `/proc` o `/sys`. Si esas ubicaciones están enmascaradas, el atacante pierde acceso directo a una parte útil de la superficie de control del kernel incluso después de obtener ejecución de código dentro del contenedor.

## Operation

Los runtimes comúnmente enmascaran rutas seleccionadas como:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

La lista exacta depende del runtime y de la configuración del host. La propiedad importante es que la ruta se vuelve inaccesible o reemplazada desde el punto de vista del contenedor aunque todavía exista en el host.

## Laboratorio

Inspecciona la configuración masked-path expuesta por Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Inspeccione el comportamiento real de mount dentro del workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Impacto en la seguridad

El enmascaramiento no crea el límite principal de aislamiento, pero elimina varios objetivos de alto valor post-exploitation. Sin enmascaramiento, un contenedor comprometido puede inspeccionar el estado del kernel, leer información sensible de procesos o de claves, o interactuar con objetos procfs/sysfs que nunca deberían haber sido visibles para la aplicación.

## Errores de configuración

El error principal es desenmascarar amplias clases de rutas por conveniencia o depuración. En Podman esto puede aparecer como `--security-opt unmask=ALL` o desenmascaramiento dirigido. En Kubernetes, una exposición excesivamente amplia de proc puede aparecer a través de `procMount: Unmasked`. Otro problema serio es exponer el `/proc` o `/sys` del host mediante un bind mount, lo que elude por completo la idea de una vista reducida del contenedor.

## Abuso

Si el enmascaramiento es débil o está ausente, comience identificando qué rutas sensibles de procfs/sysfs son accesibles directamente:
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
What these commands can reveal:

- `/proc/timer_list` can expose host timer and scheduler data. This is mostly a reconnaissance primitive, but it confirms that the container can read kernel-facing information that is normally hidden.
- `/proc/keys` is much more sensitive. Depending on the host configuration, it may reveal keyring entries, key descriptions, and relationships between host services using the kernel keyring subsystem.
- `/sys/firmware` helps identify boot mode, firmware interfaces, and platform details that are useful for host fingerprinting and for understanding whether the workload is seeing host-level state.
- `/proc/config.gz` may reveal the running kernel configuration, which is valuable for matching public kernel exploit prerequisites or understanding why a specific feature is reachable.
- `/proc/sched_debug` exposes scheduler state and often bypasses the intuitive expectation that the PID namespace should hide unrelated process information completely.

Resultados interesantes incluyen lecturas directas de esos archivos, evidencia de que los datos pertenecen al host en lugar de a una vista de container restringida, o acceso a otras ubicaciones de procfs/sysfs que suelen estar enmascaradas por defecto.

## Comprobaciones

El objetivo de estas comprobaciones es determinar qué rutas el runtime ocultó intencionalmente y si el workload actual todavía ve un sistema de archivos orientado al kernel reducido.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Lo interesante aquí:

- Una lista larga de rutas enmascaradas es normal en runtimes hardened.
- La falta de enmascaramiento en entradas sensibles de procfs merece una inspección más detallada.
- Si una ruta sensible es accesible y el contenedor además tiene capacidades elevadas o montajes amplios, la exposición importa más.

## Valores predeterminados del runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker define una lista de rutas enmascaradas por defecto | exponer montajes host proc/sys, `--privileged` |
| Podman | Enabled by default | Podman aplica rutas enmascaradas por defecto a menos que se desmascaren manualmente | `--security-opt unmask=ALL`, desenmascaramiento dirigido, `--privileged` |
| Kubernetes | Inherits runtime defaults | Usa el comportamiento de enmascaramiento del runtime subyacente a menos que la configuración del Pod debilite la exposición de proc | `procMount: Unmasked`, patrones de workloads privilegiados, montajes amplios del host |
| containerd / CRI-O under Kubernetes | Runtime default | Normalmente aplica las rutas enmascaradas de OCI/runtime a menos que se anulen | cambios directos en la configuración del runtime, mismas vías de debilitamiento en Kubernetes |

Las rutas enmascaradas suelen estar presentes por defecto. El principal problema operativo no es su ausencia en el runtime, sino el desenmascaramiento deliberado o los bind mounts del host que anulan la protección.
{{#include ../../../../banners/hacktricks-training.md}}
