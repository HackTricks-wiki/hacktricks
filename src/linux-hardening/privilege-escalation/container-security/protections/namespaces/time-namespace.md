# Espacio de nombres de tiempo

{{#include ../../../../../banners/hacktricks-training.md}}

## Visión general

El espacio de nombres de tiempo virtualiza relojes seleccionados, especialmente **`CLOCK_MONOTONIC`** y **`CLOCK_BOOTTIME`**. Es un espacio de nombres más nuevo y más especializado que los espacios de nombres mount, PID, network o user, y rara vez es lo primero que un operador piensa al hablar sobre el hardening de contenedores. Aun así, forma parte de la familia moderna de namespaces y vale la pena entenderlo conceptualmente.

El propósito principal es permitir que un proceso observe desplazamientos controlados para ciertos relojes sin cambiar la vista temporal global del host. Esto es útil para flujos de trabajo checkpoint/restore, pruebas deterministas y algunos comportamientos avanzados en tiempo de ejecución. Normalmente no es un control de aislamiento que destaque de la misma manera que los espacios de nombres mount o user, pero aun así contribuye a que el entorno del proceso sea más autosuficiente.

## Laboratorio

Si el kernel del host y el espacio de usuario lo soportan, puedes inspeccionar el espacio de nombres con:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
El soporte varía según la versión del kernel y de las herramientas, por lo que esta página trata más de entender el mecanismo que de esperar que sea visible en todos los entornos de laboratorio.

### Desplazamientos de tiempo

Los time namespaces de Linux virtualizan los desplazamientos para `CLOCK_MONOTONIC` y `CLOCK_BOOTTIME`. Los desplazamientos actuales por namespace se exponen a través de `/proc/<pid>/timens_offsets`, que en kernels compatibles también pueden ser modificados por un proceso que posea `CAP_SYS_TIME` dentro del namespace correspondiente:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
El archivo contiene deltas en nanosegundos. Ajustar `monotonic` por dos días cambia observaciones tipo uptime dentro de ese namespace sin cambiar el wall clock del host.

### `unshare` Helper Flags

Versiones recientes de `util-linux` proporcionan flags de conveniencia que escriben los offsets automáticamente:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Estas flags son, en su mayoría, una mejora de usabilidad, pero también facilitan reconocer la característica en la documentación y en las pruebas.

## Uso en tiempo de ejecución

Los time namespaces son más recientes y se usan menos universalmente que los mount o PID namespaces. OCI Runtime Specification v1.1 añadió soporte explícito para el namespace `time` y el campo `linux.timeOffsets`, y versiones más recientes de `runc` implementan esa parte del modelo. Un fragmento mínimo de OCI se ve así:
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
Esto importa porque convierte time namespacing, que antes era una primitiva del kernel de nicho, en algo que los runtimes pueden solicitar de forma portable.

## Impacto en la seguridad

Hay menos historias clásicas de breakout centradas en el time namespace que en otros tipos de namespace. El riesgo aquí generalmente no es que el time namespace habilite directamente un escape, sino que los lectores lo ignoren por completo y, por tanto, no adviertan cómo los runtimes avanzados pueden estar moldeando el comportamiento de los procesos. En entornos especializados, las vistas de reloj alteradas pueden afectar checkpoint/restore, observability o las suposiciones forenses.

## Abuso

Normalmente no hay una breakout primitive directa aquí, pero el comportamiento del reloj alterado aún puede ser útil para entender el execution environment e identificar advanced runtime features:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Si comparas dos procesos, las diferencias aquí pueden ayudar a explicar comportamientos de temporización extraños, artefactos de checkpoint/restore, o desajustes de registro específicos del entorno.

Impacto:

- casi siempre reconnaissance o comprensión del entorno
- útil para explicar registros, uptime, o anomalías de checkpoint/restore
- normalmente no es por sí mismo un mecanismo directo de container-escape

El matiz importante de abuso es que los namespaces de tiempo no virtualizan `CLOCK_REALTIME`, por lo que por sí solos no permiten a un atacante falsificar el reloj del host ni romper directamente las comprobaciones de caducidad de certificados a nivel del sistema. Su valor radica principalmente en confundir lógica basada en tiempo monotónico, reproducir bugs específicos del entorno o comprender comportamiento avanzado en tiempo de ejecución.

## Comprobaciones

Estas comprobaciones tratan principalmente de confirmar si el runtime está usando un time namespace privado en absoluto.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Lo interesante aquí:

- En muchos entornos, estos valores no provocarán un hallazgo de seguridad inmediato, pero sí indican si una característica especializada de runtime está en juego.
- Si estás comparando dos procesos, las diferencias aquí pueden explicar comportamientos confusos de timing o de checkpoint/restore.

Para la mayoría de los container breakouts, el time namespace no es el primer control que investigarás. Aun así, una sección completa de container-security debería mencionarlo porque forma parte del moderno kernel model y ocasionalmente importa en escenarios avanzados de runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
