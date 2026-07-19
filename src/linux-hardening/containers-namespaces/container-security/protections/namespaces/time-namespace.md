# Namespace de tiempo

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El namespace de tiempo virtualiza relojes seleccionados de estilo monotónico en lugar del reloj de pared del host. En la práctica, esto significa offsets privados para **`CLOCK_MONOTONIC`** y **`CLOCK_BOOTTIME`**, además de las vistas estrechamente relacionadas **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** y **`CLOCK_BOOTTIME_ALARM`**. No virtualiza **`CLOCK_REALTIME`**, por lo que `date` y la lógica de expiración de certificados siguen observando el reloj de pared del host, a menos que interfiera algún otro mecanismo.

El objetivo principal es permitir que un proceso observe offsets controlados de tiempo transcurrido sin cambiar la vista temporal global del host. Esto resulta útil para workflows de checkpoint/restore, pruebas deterministas y comportamientos avanzados del runtime. Normalmente no es un control de aislamiento tan destacado como los mount o user namespaces, pero aun así contribuye a que el entorno del proceso sea más autosuficiente.

Desde un punto de vista ofensivo, este namespace suele ser más relevante para el **reconocimiento, el desfase de timers y la comprensión del runtime** que para un breakout directo. Aun así, es importante porque cada vez más container runtimes y workflows de checkpoint/restore pueden solicitarlo explícitamente.

## Laboratorio

Si el kernel del host y el userspace lo admiten, puedes inspeccionar el namespace con:
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
El soporte varía según las versiones del kernel y de las herramientas, por lo que esta página trata más de comprender el mecanismo que de esperar que sea visible en todos los entornos de laboratorio. La observación importante es que `date` debería seguir reflejando el reloj de pared del host, mientras que los valores basados en monotonic/boottime son los que cambian cuando se configuran offsets distintos de cero.

### Matiz de creación

Los time namespaces son ligeramente inusuales en comparación con los mount, PID o network namespaces:

- `unshare(CLONE_NEWTIME)` crea un nuevo time namespace para los **procesos hijos futuros**.
- La tarea que realiza la llamada permanece en su time namespace actual.
- Por lo tanto, `/proc/<pid>/ns/time_for_children` suele ser más interesante que `/proc/<pid>/ns/time` al depurar la configuración del runtime.

La ventana de escritura también es especial. Los offsets de `/proc/<pid>/timens_offsets` deben escribirse antes de que el nuevo time namespace se haya poblado completamente con tareas en ejecución; en la práctica, los runtimes hacen esto durante la breve ventana de configuración entre la creación del namespace y el inicio del payload final. Una vez que ya hay una tarea ejecutándose allí, las escrituras posteriores fallan con `EACCES`. Por eso los runtimes de bajo nivel gestionan la configuración del time namespace como un paso temprano de bootstrap, en lugar de intentar modificar los offsets desde dentro de un proceso de contenedor ya iniciado.

### Offsets de tiempo

Los time namespaces de Linux exponen los offsets por namespace a través de `/proc/<pid>/timens_offsets`. El formato consiste en un conjunto de nombres o IDs de relojes, además de deltas de segundos/nanosegundos relativos al time namespace inicial.

En la práctica, el workflow más fiable para el usuario es dejar que `unshare` escriba esos offsets por ti:
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
El punto importante no es la sintaxis exacta del comando, sino el comportamiento: un contenedor puede observar una vista diferente del tiempo de actividad sin cambiar el reloj de pared del host.

### `unshare` Helper Flags

Las versiones recientes de `util-linux` proporcionan flags de conveniencia que escriben los offsets automáticamente durante la creación del namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Estos flags son principalmente una mejora de usabilidad, pero también facilitan reconocer la funcionalidad en la documentación, los entornos de prueba y los wrappers de runtime.

## Uso en Runtime

Los namespaces de tiempo son más recientes y se utilizan de forma menos generalizada que los namespaces de mount o PID. OCI Runtime Specification v1.1 añadió soporte explícito para el namespace `time` y el campo `linux.timeOffsets`, y los runtimes modernos pueden asignar esos datos al flujo de arranque del kernel. Un fragmento mínimo de OCI es el siguiente:
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
Esto importa porque convierte el time namespacing, de una primitiva de kernel poco común, en algo que los runtimes pueden solicitar de forma portable. También explica por qué los componentes internos del runtime necesitan un paso de sincronización explícito: el offset debe escribirse en `/proc/<pid>/timens_offsets` antes de que el payload del container entre por completo en el nuevo namespace.

Las pilas de checkpoint/restore, como CRIU, son una de las principales razones prácticas por las que esto existe. Sin time namespaces, restaurar una workload pausada haría que los relojes monotonic y de tiempo de arranque avanzaran de golpe en una cantidad equivalente al tiempo que la workload permaneció suspendida.

## Impacto de seguridad

Hay menos casos clásicos de breakout centrados en el time namespace que en otros tipos de namespaces. El riesgo normalmente no consiste en que el time namespace permita directamente un escape, sino en que los lectores lo ignoren por completo y, por tanto, no comprendan cómo los runtimes avanzados pueden modificar el comportamiento de los procesos.

En entornos especializados, las vistas monotonic o boottime modificadas pueden afectar a:

- comportamiento de timeout y retry
- watchdogs y lógica de lease
- comportamiento de `timerfd`, `nanosleep` y `clock_nanosleep`
- análisis forense de checkpoint/restore
- telemetría del tiempo transcurrido y heurísticas basadas en uptime

Por lo tanto, aunque rara vez sea el primer namespace que abuses, puede explicar perfectamente comportamientos de tiempo "imposibles" durante un assessment.

## Abuso

Normalmente no existe aquí una primitiva de breakout directa, pero el comportamiento alterado del reloj aún puede ser útil para comprender el entorno de ejecución, identificar funciones avanzadas del runtime y detectar lógica basada en temporizadores que se mide utilizando relojes monotonic en lugar del tiempo de reloj de pared:
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
Si estás comparando dos procesos, las diferencias aquí pueden ayudar a explicar comportamientos de temporización inusuales, artefactos de checkpoint/restore o discrepancias de logging específicas del entorno.

Ángulos prácticos relevantes para un atacante:

- confundir la lógica de backoff, sleep o watchdog implementada con relojes monotónicos
- explicar por qué `/proc/uptime` y el comportamiento basado en temporizadores no coinciden con las expectativas del reloj de pared del host
- reconocer flujos de trabajo de CRIU/checkpoint-restore y otras funciones avanzadas del runtime
- detectar entornos en los que unirse al time namespace objetivo con `nsenter -T -t <pid> -- ...` puede reproducir el comportamiento de los temporizadores locales del contenedor para debugging o post-exploitation

Impacto:

- casi siempre relacionado con reconnaissance o la comprensión del entorno
- útil para explicar anomalías de logging, uptime o checkpoint/restore
- útil para analizar sleeps, reintentos y temporizadores basados en tiempo monotónico
- normalmente no es un mecanismo directo de container-escape por sí solo

El matiz importante del abuso es que los time namespaces no virtualizan `CLOCK_REALTIME`, por lo que no permiten por sí mismos que un atacante falsifique el reloj de pared del host ni que rompa directamente las comprobaciones de expiración de certificados en todo el sistema. Su valor reside principalmente en confundir la lógica basada en tiempo monotónico, reproducir bugs específicos del entorno o comprender comportamientos avanzados del runtime.

## Comprobaciones

Estas comprobaciones se centran principalmente en confirmar si el runtime está usando un time namespace privado y si realmente configuró offsets distintos de cero.
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

- En muchos entornos, estos valores no darán lugar a un hallazgo de seguridad inmediato, pero sí indican si se está utilizando una función especializada del runtime.
- Si `time_for_children` difiere de `time`, el caller puede haber preparado un time namespace exclusivo para los hijos en el que no ha entrado él mismo.
- Si `date` coincide con el host, pero los valores basados en monotonic/boottime no lo hacen, probablemente estás observando time namespacing en lugar de manipulación del reloj de pared.
- Si comparas dos procesos, las diferencias aquí pueden explicar comportamientos de temporización o de checkpoint/restore confusos.

Para la mayoría de los container breakouts, el time namespace no es el primer control que investigarás. Aun así, una sección completa sobre container security debería mencionarlo porque forma parte del modelo moderno del kernel y ocasionalmente es relevante en escenarios avanzados de runtime.

## Referencias

- [Página del manual de Linux `time_namespaces(7)`](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
