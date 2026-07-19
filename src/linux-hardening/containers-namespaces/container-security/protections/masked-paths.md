# Rutas enmascaradas

{{#include ../../../../banners/hacktricks-training.md}}

Las rutas enmascaradas son protecciones de runtime que ocultan del contenedor ubicaciones del sistema de archivos especialmente sensibles y orientadas al kernel, montándolas mediante bind mount o haciendo que no sean accesibles de otra forma. El objetivo es impedir que una workload interactúe directamente con interfaces que las aplicaciones normales no necesitan, especialmente dentro de procfs.

Esto es importante porque muchos container escapes y trucos que afectan al host comienzan leyendo o escribiendo archivos especiales bajo `/proc` o `/sys`. Si esas ubicaciones están enmascaradas, el atacante pierde el acceso directo a una parte útil de la superficie de control del kernel incluso después de obtener ejecución de código dentro del contenedor.

## Funcionamiento

Los runtimes suelen enmascarar rutas seleccionadas como:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

La lista exacta depende del runtime y de la configuración del host. La propiedad importante es que la ruta se vuelve inaccesible o es reemplazada desde el punto de vista del contenedor, aunque siga existiendo en el host.

## Laboratorio

Inspecciona la configuración de rutas enmascaradas expuesta por Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Inspecciona el comportamiento real del montaje dentro de la carga de trabajo:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Impacto de seguridad

El enmascaramiento no crea el límite principal de aislamiento, pero elimina varios objetivos de alto valor durante el post-exploitation. Sin enmascaramiento, un contenedor comprometido podría inspeccionar el estado del kernel, leer información sensible de procesos o de keying, o interactuar con objetos de procfs/sysfs que nunca deberían haber sido visibles para la aplicación.

## Configuraciones incorrectas

El error principal consiste en desenmascarar clases amplias de rutas por conveniencia o para debugging. En Podman esto puede aparecer como `--security-opt unmask=ALL` o mediante un desenmascaramiento dirigido. En Kubernetes, una exposición excesivamente amplia de proc puede aparecer mediante `procMount: Unmasked`. Otro problema grave consiste en exponer el `/proc` o `/sys` del host mediante un bind mount, lo que evita por completo la idea de una vista reducida del contenedor.

## Abuso

Si el enmascaramiento es débil o inexistente, empieza identificando qué rutas sensibles de procfs/sysfs son directamente accesibles:
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

- `/proc/timer_list` puede exponer datos del host sobre los temporizadores y el scheduler. Esto es principalmente un recurso de reconnaissance, pero confirma que el contenedor puede leer información orientada al kernel que normalmente está oculta.
- `/proc/keys` es mucho más sensible. Dependiendo de la configuración del host, puede revelar entradas del keyring, descripciones de claves y relaciones entre servicios del host que utilizan el subsistema de keyring del kernel.
- `/sys/firmware` ayuda a identificar el modo de arranque, las interfaces del firmware y detalles de la plataforma útiles para fingerprinting del host y para comprender si el workload está viendo el estado del host.
- `/proc/config.gz` puede revelar la configuración del kernel en ejecución, lo que resulta útil para comprobar los requisitos previos de exploits públicos del kernel o comprender por qué una función específica es accesible.
- `/proc/sched_debug` expone el estado del scheduler y a menudo contradice la expectativa intuitiva de que el PID namespace debería ocultar por completo la información de procesos no relacionados.

Entre los resultados interesantes se incluyen lecturas directas de esos archivos, evidencias de que los datos pertenecen al host y no a una vista restringida del contenedor, o acceso a otras ubicaciones de procfs/sysfs que normalmente están masked de forma predeterminada.

## Comprobaciones

El objetivo de estas comprobaciones es determinar qué paths ocultó intencionadamente el runtime y si el workload actual todavía ve un filesystem orientado al kernel reducido.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Qué es interesante aquí:

- Una lista larga de rutas masked es normal en runtimes reforzados.
- La ausencia de masking en entradas sensibles de procfs merece una inspección más detallada.
- Si una ruta sensible es accesible y el container también tiene capabilities potentes o mounts amplios, la exposición es más importante.

## Defaults del Runtime

| Runtime / platform | Estado por defecto | Comportamiento por defecto | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por defecto | Docker define una lista de rutas masked por defecto | exponer mounts de proc/sys del host, `--privileged` |
| Podman | Habilitado por defecto | Podman aplica rutas masked por defecto salvo que se desmascaren manualmente | `--security-opt unmask=ALL`, unmasking específico, `--privileged` |
| Kubernetes | Hereda los defaults del runtime | Usa el comportamiento de masking del runtime subyacente salvo que los ajustes de Pod debiliten la exposición de proc | `procMount: Unmasked`, patrones de workloads privilegiados, mounts amplios del host |
| containerd / CRI-O bajo Kubernetes | Default del runtime | Normalmente aplica rutas masked de OCI/runtime salvo que se sobrescriban | cambios directos en la configuración del runtime, las mismas vías de debilitamiento de Kubernetes |

Las rutas masked suelen estar presentes por defecto. El problema operativo principal no es su ausencia en el runtime, sino el unmasking deliberado o los bind mounts del host que anulan la protección.
{{#include ../../../../banners/hacktricks-training.md}}
