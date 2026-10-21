# Rutas enmascaradas

{{#include ../../../../banners/hacktricks-training.md}}

Las rutas enmascaradas son protecciones en tiempo de ejecución que ocultan al contenedor ubicaciones del sistema de archivos especialmente sensibles para el kernel, montando sobre ellas un bind mount o impidiendo de otro modo el acceso. La especificación de runtime de OCI define `maskedPaths` como rutas absolutas que no deben poder leerse dentro del contenedor. <sup>[[1]](#references)</sup>

Esto es importante porque muchos escapes de contenedores y técnicas que afectan al host comienzan leyendo o escribiendo archivos especiales bajo `/proc` o `/sys`. Si esas ubicaciones están enmascaradas, el atacante pierde acceso directo a una parte útil de la superficie de control del kernel, incluso después de obtener ejecución de código dentro del contenedor.

## Funcionamiento

Los runtimes suelen enmascarar rutas seleccionadas como:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

La lista exacta depende del runtime y de la configuración del host. Lo importante es que, desde el punto de vista del contenedor, la ruta se vuelve inaccesible o se sustituye, aunque siga existiendo en el host.

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

Una ruta listada no es necesariamente legible: runc puede ocultar un archivo con un montaje bind de `/dev/null` y un directorio con un tmpfs vacío de solo lectura. Comprueba el punto de montaje exacto, no solo si `ls` se ejecuta correctamente. <sup>[[4]](#references)</sup>

## Impacto de seguridad

El enmascaramiento no crea el límite principal de aislamiento, pero elimina varios objetivos de alto valor para el post-exploitation. Sin enmascaramiento, un contenedor comprometido podría inspeccionar el estado del kernel, leer información sensible sobre procesos o claves, o interactuar con objetos de procfs/sysfs que nunca deberían haber estado visibles para la aplicación.

## Configuraciones incorrectas

El error principal es quitar el enmascaramiento de categorías amplias de rutas por comodidad o para depurar. En Podman, esto puede hacerse con `--security-opt unmask=ALL` o quitando el enmascaramiento de rutas específicas. <sup>[[2]](#references)</sup> En Kubernetes, una exposición demasiado amplia de proc puede configurarse mediante `procMount: Unmasked`; las versiones actuales de Kubernetes requieren `spec.hostUsers: false` (un user namespace) para esta configuración, mientras que las versiones 1.12–1.29 no aplicaban ese requisito. <sup>[[3]](#references)</sup> Otro problema grave es exponer el `/proc` o `/sys` del host mediante un montaje bind, lo que anula por completo la idea de una vista reducida del contenedor.

## Abuso

Si el enmascaramiento es débil o no existe, empieza por identificar qué rutas sensibles de procfs/sysfs son accesibles directamente:

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

Si una ruta supuestamente enmascarada es accesible, inspecciónala detenidamente:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

Qué pueden revelar estos comandos:

- `/proc/timer_list` puede exponer datos del temporizador y del planificador del host. Esto es principalmente una primitiva de reconocimiento, pero confirma que el contenedor puede leer información del kernel que normalmente está oculta.
- `/proc/keys` enumera metadatos solo de las claves para las que el lector tiene permiso de **view**, sujeto a las comprobaciones de LSM. Puede revelar tipos y descripciones de claves, pero no vuelca las cargas útiles de las claves. <sup>[[6]](#references)</sup>
- `/sys/firmware` ayuda a identificar el modo de arranque, las interfaces de firmware y los detalles de la plataforma, útiles para fingerprinting del host y para entender si la carga de trabajo está viendo el estado del host.
- `/proc/config.gz` puede revelar la configuración del kernel en ejecución, lo que resulta valioso para comprobar los requisitos previos de exploits públicos del kernel o entender por qué se puede acceder a una función concreta.
- `/proc/sched_debug` expone el estado del planificador y a menudo contradice la expectativa intuitiva de que el PID namespace debería ocultar por completo la información de procesos no relacionados.

Entre los resultados interesantes se incluyen lecturas directas de esos archivos, pruebas de que los datos pertenecen al host y no a una vista restringida del contenedor, o acceso a otras ubicaciones de procfs/sysfs que suelen estar enmascaradas de forma predeterminada.

### Race de origen de máscara durante el inicio del contenedor

En implementaciones vulnerables de runc, las máscaras de archivos dependen del inode de `/dev/null` del contenedor. Un atacante que pueda coordinar contenedores simultáneos con montajes compartidos, incluidos pasos paralelos de BuildKit, puede provocar una race durante el inicio y eliminar `/dev/null` antes de que runc lo monte sobre los archivos de procfs que deben enmascararse. Entonces, el runtime trata el **origen** que falta como si faltara un destino de máscara y omite silenciosamente esas máscaras de archivos. El fallo depende de una race durante la configuración del runtime; eliminar `/dev/null` después del inicio no revierte una máscara ya instalada. <sup>[[4]](#references)</sup>

Después de una prueba controlada, compara la lista de máscaras solicitadas con los puntos de montaje exactos dentro del nuevo contenedor. <sup>[[4]](#references)</sup> `findmnt -M` comprueba el punto de montaje indicado, en lugar de recurrir a un montaje padre; si `findmnt` no está disponible, inspecciona `/proc/self/mountinfo`. <sup>[[5]](#references)</sup> Que `ls` tenga éxito o que `cat` no devuelva contenido no demuestra que la máscara esté ausente. <sup>[[4]](#references)</sup>

Usa las [comprobaciones siguientes](#checks) para comparar las máscaras solicitadas con los montajes exactos del nuevo contenedor.

Una máscara de archivo omitida puede exponer datos de procfs si los permisos normales y la política de LSM lo permiten. Por sí sola, **no** hace que `/proc/sys` sea escribible: ese es un control independiente de [read-only-path](read-only-paths.md). La sustitución distinta del enlace simbólico de `/dev/null`, que puede redirigir un montaje bind a un destino de procfs escribible, se aborda en [race del runtime del PID namespace](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs). <sup>[[4]](#references)</sup>

## Comprobaciones

El objetivo de estas comprobaciones es determinar qué rutas ocultó intencionalmente el runtime y si la carga de trabajo actual sigue viendo un sistema de archivos orientado al kernel reducido.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

Usa una comprobación de montaje exacto porque un archivo enmascarado puede seguir existiendo y una lectura puede devolver un resultado vacío desde `/dev/null`. La ausencia de un punto de montaje es un hallazgo que se debe investigar, no una prueba por sí sola de que se puedan leer datos del host. <sup>[[4]](#references)[[5]](#references)</sup>

Qué resulta interesante aquí:

- Una lista extensa de rutas enmascaradas es normal en runtimes reforzados.
- La falta de enmascaramiento en entradas sensibles de procfs merece una inspección más detallada.
- Si se puede acceder a una ruta sensible y el contenedor también tiene capacidades potentes o montajes amplios, la exposición es más importante.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual habitual |
| --- | --- | --- | --- |
| Docker Engine | Habilitado de forma predeterminada | Docker define una lista predeterminada de rutas enmascaradas | Exponer montajes host de proc/sys, `--privileged` |
| Podman | Habilitado de forma predeterminada | Podman aplica rutas enmascaradas predeterminadas, salvo que se quiten manualmente | `--security-opt unmask=ALL`, quitar el enmascaramiento de rutas concretas, `--privileged` |
| Kubernetes | Hereda los valores predeterminados del runtime | Usa el comportamiento de enmascaramiento del runtime subyacente, salvo que la configuración del Pod debilite la exposición de proc | `procMount: Unmasked` (requiere `hostUsers: false` en las versiones actuales), patrones de cargas de trabajo privilegiadas, montajes host amplios |
| containerd / CRI-O en Kubernetes | Valor predeterminado del runtime | Normalmente aplica las rutas enmascaradas de OCI/runtime, salvo que se anulen | Cambios directos en la configuración del runtime, las mismas vías de debilitamiento de Kubernetes |

Las rutas enmascaradas suelen estar presentes de forma predeterminada. El principal problema operativo no es su ausencia en el runtime, sino quitarlas deliberadamente o usar montajes bind del host que anulan la protección.

## References

- [1] [Open Container Initiative - Configuración de contenedores Linux: rutas enmascaradas](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Documentación de Podman - opciones de seguridad de `podman run`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Documentación de Kubernetes - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [Aviso de runc: condición de carrera en el origen del montaje de rutas enmascaradas](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [Manual de findmnt(8)](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [Manual de keyrings(7)](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}
