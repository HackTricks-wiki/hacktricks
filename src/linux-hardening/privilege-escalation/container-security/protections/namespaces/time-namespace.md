# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

El time namespace virtualiza selected monotonic-style clocks en lugar del host wall clock. En la práctica, esto significa private offsets para **`CLOCK_MONOTONIC`** y **`CLOCK_BOOTTIME`**, además de las vistas estrechamente relacionadas **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** y **`CLOCK_BOOTTIME_ALARM`**. No virtualiza **`CLOCK_REALTIME`**, así que `date` y la lógica de expiración de certificados siguen observando el host wall clock salvo que otro mecanismo interfiera.

El propósito principal es permitir que un proceso observe controlled elapsed-time offsets sin cambiar la global time view del host. Esto es útil para checkpoint/restore workflows, deterministic testing y advanced runtime behavior. Normalmente no es un control de aislamiento destacado como mount o user namespaces, pero aun así contribuye a que el proceso sea más self-contained.

Desde un punto de vista ofensivo, este namespace suele ser más relevante para **reconnaissance**, timer skew y runtime understanding que para un breakout directo. Aun así, importa porque más container runtimes y checkpoint/restore workflows ahora pueden solicitarlo explícitamente.

## Lab

Si el host kernel y userspace lo soportan, puedes inspeccionar el namespace con:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
cat /proc/uptime
date
```
Support varía según las versiones del kernel y de las herramientas, así que esta página trata más de entender el mecanismo que de esperar verlo en cada entorno de laboratorio. La observación importante es que `date` aún debería reflejar el reloj del host, mientras que los valores basados en monotonic/boottime son los que cambian cuando se configuran offsets distintos de cero.

### Creation Nuance

Time namespaces son ligeramente inusuales en comparación con mount, PID, o network namespaces:

- `unshare(CLONE_NEWTIME)` crea un nuevo time namespace para **future children**.
- La tarea que llama permanece en su actual time namespace.
- `/proc/<pid>/ns/time_for_children` por lo tanto suele ser más interesante que `/proc/<pid>/ns/time` al depurar la configuración de runtime.

La ventana de escritura también es especial. Los offsets en `/proc/<pid>/timens_offsets` deben escribirse antes de que el nuevo time namespace esté completamente poblado con tareas en ejecución; en la práctica, los runtimes hacen esto durante la estrecha ventana de configuración entre la creación del namespace y el inicio del payload final. Una vez que ya hay una tarea ejecutándose allí, escrituras posteriores fallan con `EACCES`. Por eso los runtimes de bajo nivel manejan la configuración de time-namespace como un paso temprano de bootstrap en lugar de intentar parchear offsets desde dentro de un proceso de contenedor ya iniciado.

### Time Offsets

Los time namespaces de Linux exponen los offsets por namespace a través de `/proc/<pid>/timens_offsets`. El formato es un conjunto de nombres o IDs de clock más deltas de segundos/nanosegundos relativos al time namespace inicial.

En la práctica, el flujo de trabajo más fiable orientado al usuario es dejar que `unshare` escriba esos offsets por ti:
```bash
sudo unshare -UrT --fork --mount-proc --monotonic 86400 --boottime 604800 bash
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
El punto importante no es la sintaxis exacta del comando, sino el comportamiento: un container puede observar una vista similar a uptime diferente sin cambiar el reloj wall clock del host.

### `unshare` Helper Flags

Las versiones recientes de `util-linux` proporcionan flags de conveniencia que escriben los offsets automáticamente durante la creación del namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Estas flags son principalmente una mejora de usabilidad, pero también facilitan reconocer la feature en documentación, test harnesses y runtime wrappers.

## Runtime Usage

Los Time namespaces son más nuevos y se usan con menos frecuencia de forma universal que mount o PID namespaces. OCI Runtime Specification v1.1 añadió soporte explícito para el namespace `time` y el campo `linux.timeOffsets`, y los runtimes modernos pueden mapear esos datos en el flujo de bootstrap del kernel. Un fragmento mínimo de OCI se ve así:
```json
{
"linux": {
"namespaces": [
{ "type": "time" }
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Esto importa porque convierte el namespacing de tiempo de una primitiva de kernel de nicho en algo que los runtimes pueden solicitar de forma portable. También explica por qué los internals del runtime necesitan un paso explícito de sincronización: el offset debe escribirse en `/proc/<pid>/timens_offsets` antes de que el payload del container entre por completo en el nuevo namespace.

Pilas de checkpoint/restore como CRIU son una de las principales razones reales por las que esto existe. Sin time namespaces, restaurar un workload pausado haría que los relojes monotonic y boot-time saltaran por la cantidad de tiempo que el workload pasó suspendido.

## Security Impact

Hay menos historias clásicas de breakout centradas en el time namespace que en otros tipos de namespace. El riesgo aquí no suele ser que el time namespace habilite directamente la escape, sino que los lectores lo ignoren por completo y, por tanto, pasen por alto cómo runtimes avanzados pueden estar moldeando el comportamiento de los procesos.

En entornos especializados, las vistas alteradas de monotonic o boottime pueden afectar:

- el comportamiento de timeout y retry
- watchdogs y la lógica de lease
- el comportamiento de `timerfd`, `nanosleep`, y `clock_nanosleep`
- forensics de checkpoint/restore
- telemetría de tiempo transcurrido y heurísticas basadas en uptime

Así que, aunque rara vez sea el primer namespace que abusas, puede explicar absolutamente un comportamiento de temporización "imposible" durante una assessment.

## Abuse

Normalmente no hay una primitive directa de breakout aquí, pero el comportamiento alterado del clock aún puede ser útil para entender el entorno de ejecución, identificar características avanzadas del runtime y detectar lógica basada en timers que se mide contra relojes monotonic en lugar de wall clock time:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Si estás comparando dos procesos, las diferencias aquí pueden ayudar a explicar comportamiento extraño de temporización, artefactos de checkpoint/restore o desajustes de logging específicos del entorno.

Ángulos prácticos relevantes para un atacante:

- confundir lógica de backoff, sleep o watchdog implementada con relojes monotonic
- explicar por qué `/proc/uptime` y el comportamiento impulsado por timers no coinciden con las expectativas de wall-clock del host
- reconocer flujos de trabajo de CRIU/checkpoint-restore y otras funciones avanzadas del runtime
- detectar entornos donde unir un target time namespace con `nsenter -T -t <pid> -- ...` puede reproducir el comportamiento de timers local al container para debugging o post-exploitation

Impacto:

- casi siempre reconocimiento o comprensión del entorno
- útil para explicar anomalías de logging, uptime o checkpoint/restore
- útil para analizar sleeps, retries y timers basados en monotonic-time
- normalmente no es un mecanismo directo de container-escape por sí mismo

El matiz importante de abuso es que los time namespaces no virtualizan `CLOCK_REALTIME`, así que por sí solos no permiten a un atacante falsificar el wall clock del host ni romper directamente comprobaciones de expiración de certificados en todo el sistema. Su valor está sobre todo en confundir lógica basada en monotonic-time, reproducir bugs específicos del entorno o entender el comportamiento avanzado del runtime.

## Checks

Estas comprobaciones tratan principalmente de confirmar si el runtime está usando un private time namespace en absoluto y si realmente estableció offsets distintos de cero.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
lsns -t time 2>/dev/null                    # Host-side inventory when available
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
```
Qué es interesante aquí:

- En muchos entornos estos valores no llevarán a un hallazgo de seguridad inmediato, pero sí te indican si hay una función especializada del runtime en uso.
- Si `time_for_children` difiere de `time`, el llamador puede haber preparado un time namespace solo para hijos en el que no ha entrado él mismo.
- Si `date` coincide con el host pero los valores basados en monotonic/boottime no, probablemente estás viendo time namespacing en lugar de manipulación del wall-clock.
- Si estás comparando dos procesos, las diferencias aquí pueden explicar comportamientos confusos de timing o checkpoint/restore.

Para la mayoría de los container breakouts, el time namespace no es el primer control que vas a investigar. Aun así, una sección completa de container-security debería mencionarlo porque forma parte del modelo moderno del kernel y, ocasionalmente, importa en escenarios avanzados del runtime.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
