# Namespace de tiempo

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El namespace de tiempo virtualiza determinados relojes de estilo monotónico en lugar del reloj de pared del host. En la práctica, esto significa offsets privados para **`CLOCK_MONOTONIC`** y **`CLOCK_BOOTTIME`**, además de las vistas estrechamente relacionadas **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** y **`CLOCK_BOOTTIME_ALARM`**. No virtualiza **`CLOCK_REALTIME`**, por lo que `date` y la lógica de expiración de certificados siguen observando el reloj de pared del host, a menos que interfiera algún otro mecanismo.<sup>[[1]](#references)</sup>

El objetivo principal es permitir que un proceso observe offsets controlados del tiempo transcurrido sin cambiar la vista temporal global del host. Esto resulta útil para workflows de checkpoint/restore, testing determinista y comportamientos avanzados del runtime. Normalmente no es un control de isolation principal, como los namespaces de mount o user, pero aun así contribuye a que el entorno del proceso sea más autocontenido.

Desde un punto de vista ofensivo, este namespace suele ser más relevante para el **reconocimiento, el desfase de timers y la comprensión del runtime** que para un breakout directo. Aun así, es importante porque cada vez más container runtimes y workflows de checkpoint/restore pueden solicitarlo explícitamente.

## Lab

Si el kernel del host y el userspace lo soportan, puedes inspeccionar el namespace con:
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
La compatibilidad varía según las versiones del kernel y de las herramientas, por lo que esta página trata más de comprender el mecanismo que de esperar que sea visible en todos los entornos de laboratorio. La observación importante es que `date` debería seguir reflejando el reloj de pared del host, mientras que los valores basados en monotonic/boottime son los que cambian cuando se configuran offsets distintos de cero.

### Matiz de creación

Los time namespaces son ligeramente inusuales en comparación con los mount, PID o network namespaces:<sup>[[1]](#references)</sup>

- `unshare(CLONE_NEWTIME)` crea un nuevo time namespace para **los futuros procesos hijos**.
- La tarea que realiza la llamada permanece en su time namespace actual.
- Por ello, `/proc/<pid>/ns/time_for_children` suele ser más interesante que `/proc/<pid>/ns/time` al depurar la configuración del runtime.

La ventana de escritura también es especial. Los offsets de `/proc/<pid>/timens_offsets` deben escribirse antes de que el nuevo time namespace se complete con tareas en ejecución; en la práctica, los runtimes hacen esto durante la estrecha ventana de configuración entre la creación del namespace y el inicio del payload final. Una vez que ya hay una tarea en ejecución, las escrituras posteriores fallan con `EACCES`. Por eso los runtimes de bajo nivel gestionan la configuración del time namespace como un paso temprano de bootstrap, en lugar de intentar modificar los offsets desde dentro de un proceso de contenedor ya iniciado.<sup>[[1]](#references)</sup>

### Offsets de tiempo

Los time namespaces de Linux exponen los offsets por namespace a través de `/proc/<pid>/timens_offsets`. El formato consiste en un conjunto de nombres o IDs de relojes, además de deltas de segundos/nanosegundos relativos al time namespace inicial.<sup>[[1]](#references)</sup>

En la práctica, el flujo de trabajo orientado al usuario más fiable consiste en dejar que `unshare` escriba esos offsets por ti:
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
El punto importante no es la sintaxis exacta del comando, sino el comportamiento: un container puede observar una vista similar a `uptime` diferente sin cambiar el reloj de pared del host.

### Banderas auxiliares de `unshare`

Las versiones recientes de `util-linux` proporcionan flags de conveniencia que escriben los offsets automáticamente durante la creación del namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Estas flags son principalmente una mejora de usabilidad, pero también facilitan reconocer la funcionalidad en la documentación, los test harnesses y los wrappers de runtime.

## Uso en runtime

Los espacios de nombres de tiempo son más recientes y se utilizan menos universalmente que los espacios de nombres `mount` o `PID`. OCI Runtime Specification v1.1 añadió compatibilidad explícita con el espacio de nombres `time` y el campo `linux.timeOffsets`, y los runtimes modernos pueden asignar esos datos al flujo de arranque del kernel. Un fragmento mínimo de OCI tiene este aspecto:
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
Esto es importante porque convierte el time namespacing, antes una primitiva de kernel de uso especializado, en algo que los runtimes pueden solicitar de forma portable. También explica por qué los componentes internos del runtime necesitan un paso explícito de sincronización: el offset debe escribirse en `/proc/<pid>/timens_offsets` antes de que el payload del contenedor entre completamente en el nuevo namespace.

Las pilas de checkpoint/restore, como CRIU, son una de las principales razones prácticas por las que esto existe. Sin time namespaces, restaurar una carga de trabajo pausada haría que los relojes monotónicos y de tiempo de arranque avanzaran repentinamente en una cantidad equivalente al tiempo que la carga de trabajo permaneció suspendida.<sup>[[2]](#references)</sup>

## Impacto de seguridad

Hay menos casos clásicos de breakout centrados en el time namespace que en otros tipos de namespaces. El riesgo aquí normalmente no consiste en que el time namespace permita escapar directamente, sino en que los lectores lo ignoren por completo y, por lo tanto, no comprendan cómo los runtimes avanzados pueden modificar el comportamiento de los procesos.

En entornos especializados, las vistas monotónicas o de boottime modificadas pueden afectar a:

- el comportamiento de los timeouts y reintentos
- los watchdogs y la lógica de leases
- el comportamiento de `timerfd`, `nanosleep` y `clock_nanosleep`
- el análisis forense de checkpoint/restore
- la telemetría del tiempo transcurrido y las heurísticas basadas en el uptime

Por lo tanto, aunque rara vez sea el primer namespace que abuses, puede explicar perfectamente un comportamiento temporal "imposible" durante un assessment.

## Abuse

Normalmente no existe aquí una primitiva de breakout directa, pero el comportamiento alterado del reloj aún puede ser útil para comprender el entorno de ejecución, identificar funciones avanzadas del runtime y detectar lógica basada en temporizadores que se mide contra relojes monotónicos en lugar del tiempo del reloj de pared:
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
Si estás comparando dos procesos, las diferencias aquí pueden ayudar a explicar comportamientos de temporización extraños, artefactos de checkpoint/restore o discrepancias de logging específicas del entorno.

Ángulos prácticos relevantes para un atacante:

- confundir la lógica de backoff, sleep o watchdog implementada con relojes monotónicos
- explicar por qué `/proc/uptime` y el comportamiento controlado por temporizadores no coinciden con las expectativas del wall clock del host
- reconocer workflows de CRIU/checkpoint-restore y otras funciones avanzadas del runtime
- detectar entornos donde unirse al time namespace de un objetivo con `nsenter -T -t <pid> -- ...` puede reproducir el comportamiento de los temporizadores locales del container para debugging o post-exploitation

Impacto:

- casi siempre reconnaissance o comprensión del entorno
- útil para explicar anomalías de logging, uptime o checkpoint/restore
- útil para analizar sleeps, reintentos y temporizadores basados en tiempo monotónico
- normalmente no es un mecanismo directo de container escape por sí solo

El matiz importante sobre el abuso es que los time namespaces no virtualizan `CLOCK_REALTIME`, por lo que, por sí solos, no permiten a un atacante falsificar el wall clock del host ni romper directamente las comprobaciones de expiración de certificados en todo el sistema. Su valor reside principalmente en confundir la lógica basada en tiempo monotónico, reproducir bugs específicos del entorno o comprender comportamientos avanzados del runtime.

## Comprobaciones

Estas comprobaciones tratan principalmente de confirmar si el runtime está utilizando un time namespace privado y si realmente ha establecido offsets distintos de cero.
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
Qué resulta interesante aquí:

- En muchos entornos, estos valores no darán lugar a un hallazgo de seguridad inmediato, pero sí indican si se está utilizando una función especializada del runtime.
- Si `time_for_children` difiere de `time`, es posible que el caller haya preparado un time namespace exclusivo para los hijos en el que él mismo no ha entrado.
- Si `date` coincide con el host, pero los valores basados en monotonic/boottime no lo hacen, probablemente estás observando un time namespace en lugar de una manipulación del reloj de pared.
- Si comparas dos procesos, las diferencias aquí pueden explicar comportamientos confusos relacionados con el timing o con checkpoint/restore.

Para la mayoría de los container breakouts, el time namespace no será el primer control que investigarás. Aun así, una sección completa sobre container security debería mencionarlo porque forma parte del modelo moderno del kernel y ocasionalmente resulta relevante en escenarios avanzados de runtime.

## Referencias

- [1] [Página del manual de Linux `time_namespaces(7)`](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [2] [Time Namespaces: Per-Container Clock Offsets for CLOCK_MONOTONIC / CLOCK_BOOTTIME - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
