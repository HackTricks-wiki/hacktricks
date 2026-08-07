# Rutas enmascaradas

{{#include ../../../../banners/hacktricks-training.md}}

Las rutas enmascaradas son protecciones en tiempo de ejecución que ocultan del container ubicaciones del sistema de archivos especialmente sensibles orientadas al kernel, montándolas mediante bind-mount o haciéndolas inaccesibles de cualquier otra forma. El objetivo es impedir que un workload interactúe directamente con interfaces que las aplicaciones normales no necesitan, especialmente dentro de procfs.

Esto es importante porque muchos container escapes y trucos que afectan al host comienzan leyendo o escribiendo archivos especiales bajo `/proc` o `/sys`. Si esas ubicaciones están enmascaradas, el atacante pierde el acceso directo a una parte útil de la superficie de control del kernel incluso después de obtener code execution dentro del container.

## Funcionamiento

Los runtimes suelen enmascarar rutas seleccionadas, como:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

La lista exacta depende del runtime y de la configuración del host. La propiedad importante es que la ruta se vuelve inaccesible o es reemplazada desde el punto de vista del container, aunque siga existiendo en el host.

## Lab

Inspecciona la configuración de masked paths expuesta por Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Inspecciona el comportamiento real del montaje dentro de la carga de trabajo:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Impacto en la seguridad

El masking no crea el límite principal de aislamiento, pero elimina varios objetivos de alto valor para el post-exploitation. Sin masking, un contenedor comprometido puede ser capaz de inspeccionar el estado del kernel, leer información confidencial de procesos o de claves, o interactuar con objetos de procfs/sysfs que nunca deberían haber sido visibles para la aplicación.

## Configuraciones incorrectas

El error principal es desactivar el masking de clases amplias de paths por comodidad o para debugging. En Podman, esto puede aparecer como `--security-opt unmask=ALL` o como un unmasking específico. En Kubernetes, una exposición excesivamente amplia de proc puede aparecer mediante `procMount: Unmasked`. Otro problema grave es exponer el `/proc` o `/sys` del host mediante un bind mount, lo que evita por completo la idea de una vista reducida del contenedor.

## Abuse

Si el masking es débil o inexistente, empieza identificando qué paths confidenciales de procfs/sysfs son directamente accesibles:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Si una ruta supuestamente enmascarada es accesible, inspecciónala detenidamente:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Qué pueden revelar estos comandos:

- `/proc/timer_list` puede exponer datos de timers y del scheduler del host. Esto es principalmente un primitive de reconnaissance, pero confirma que el container puede leer información orientada al kernel que normalmente está oculta.
- `/proc/keys` es mucho más sensible. Dependiendo de la configuración del host, puede revelar entradas del keyring, descripciones de claves y relaciones entre servicios del host que usan el subsistema de keyring del kernel.
- `/sys/firmware` ayuda a identificar el modo de arranque, las interfaces del firmware y detalles de la plataforma útiles para el fingerprinting del host y para comprender si el workload está viendo el estado del nivel del host.
- `/proc/config.gz` puede revelar la configuración del kernel en ejecución, lo que resulta valioso para comparar los requisitos previos de exploits públicos del kernel o comprender por qué una función específica es accesible.
- `/proc/sched_debug` expone el estado del scheduler y a menudo contradice la expectativa intuitiva de que el PID namespace debería ocultar por completo la información de procesos no relacionados.

Entre los resultados interesantes se incluyen lecturas directas de esos archivos, evidencias de que los datos pertenecen al host y no a una vista restringida del container, o acceso a otras ubicaciones de procfs/sysfs que normalmente están masked de forma predeterminada.

## Checks

El objetivo de estos checks es determinar qué paths ocultó intencionadamente el runtime y si el workload actual todavía ve un filesystem orientado al kernel reducido.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Qué es interesante aquí:

- Una lista larga de rutas enmascaradas es normal en runtimes reforzados.
- La ausencia de enmascaramiento en entradas sensibles de procfs merece una inspección más detallada.
- Si se puede acceder a una ruta sensible y el contenedor también tiene capabilities potentes o montajes amplios, la exposición es más importante.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Habilitado de forma predeterminada | Docker define una lista predeterminada de rutas enmascaradas | exponer montajes proc/sys del host, `--privileged` |
| Podman | Habilitado de forma predeterminada | Podman aplica rutas enmascaradas predeterminadas salvo que se quite manualmente el enmascaramiento | `--security-opt unmask=ALL`, quitar el enmascaramiento de forma específica, `--privileged` |
| Kubernetes | Hereda los valores predeterminados del runtime | Usa el comportamiento de enmascaramiento del runtime subyacente salvo que la configuración del Pod debilite la exposición de proc | `procMount: Unmasked`, patrones de workloads privilegiados, montajes amplios del host |
| containerd / CRI-O bajo Kubernetes | Valor predeterminado del runtime | Normalmente aplica las rutas enmascaradas de OCI/runtime salvo que se sobrescriban | cambios directos en la configuración del runtime, las mismas vías de debilitamiento de Kubernetes |

Las rutas enmascaradas suelen estar presentes de forma predeterminada. El principal problema operativo no es su ausencia en el runtime, sino quitar deliberadamente el enmascaramiento o usar bind mounts del host que anulen la protección.

{{#include ../../../../banners/hacktricks-training.md}}
