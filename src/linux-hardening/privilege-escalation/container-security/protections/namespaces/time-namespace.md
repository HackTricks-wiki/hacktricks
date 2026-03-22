# Namespace de tiempo

{{#include ../../../../../banners/hacktricks-training.md}}

## Visión general

El namespace de tiempo virtualiza relojes seleccionados, especialmente **`CLOCK_MONOTONIC`** y **`CLOCK_BOOTTIME`**. Es un namespace más nuevo y más especializado que los namespaces de mount, PID, network o user, y rara vez es lo primero en lo que piensa un operador al hablar de container hardening. Aun así, forma parte de la familia moderna de namespaces y vale la pena comprenderlo conceptualmente.

El propósito principal es permitir que un proceso observe offsets controlados para ciertos relojes sin cambiar la vista de tiempo global del host. Esto es útil para workflows de checkpoint/restore, pruebas deterministas y algunos comportamientos avanzados en runtime. Normalmente no es un control de aislamiento destacado de la misma manera que los namespaces de mount o user, pero sigue contribuyendo a que el entorno del proceso sea más autocontenido.

## Laboratorio

Si el kernel del host y el userspace lo soportan, puedes inspeccionar el namespace con:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
El soporte varía según las versiones del kernel y las herramientas, por lo que esta página trata más de entender el mecanismo que de esperar verlo en todos los entornos de laboratorio.

### Desplazamientos de tiempo

Los namespaces de tiempo de Linux virtualizan los desplazamientos para `CLOCK_MONOTONIC` y `CLOCK_BOOTTIME`. Los desplazamientos actuales por namespace se exponen a través de `/proc/<pid>/timens_offsets`, que en kernels compatibles también pueden ser modificados por un proceso que posea `CAP_SYS_TIME` dentro del namespace correspondiente:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
El archivo contiene deltas en nanosegundos. Ajustar `monotonic` por dos días cambia observaciones similares a uptime dentro de ese namespace sin cambiar el host wall clock.

### `unshare` Helper Flags

Versiones recientes de `util-linux` proporcionan flags de conveniencia que escriben los offsets automáticamente:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Estas flags son en su mayoría una mejora de usabilidad, pero también facilitan reconocer la característica en la documentación y en las pruebas.

## Uso en tiempo de ejecución

Los time namespaces son más recientes y están menos extendidos que los mount o PID namespaces. OCI Runtime Specification v1.1 añadió soporte explícito para el `time` namespace y el campo `linux.timeOffsets`, y las versiones más recientes de `runc` implementan esa parte del modelo. Un fragmento OCI mínimo se ve así:
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
Esto importa porque convierte al time namespacing de una primitiva del kernel de nicho en algo que los runtimes pueden solicitar de forma portable.

## Impacto en la seguridad

Hay menos casos clásicos de escape centrados en el time namespace que en otros tipos de namespace. El riesgo aquí generalmente no es que el time namespace habilite directamente escapes, sino que los lectores lo ignoren por completo y, por tanto, no detecten cómo los runtimes avanzados pueden estar moldeando el comportamiento de los procesos. En entornos especializados, vistas de reloj alteradas pueden afectar checkpoint/restore, la observabilidad o las suposiciones forenses.

## Abuso

Normalmente no existe una primitiva de escape directa aquí, pero el comportamiento de reloj alterado aún puede ser útil para comprender el entorno de ejecución e identificar características avanzadas del runtime:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Si estás comparando dos procesos, las diferencias aquí pueden ayudar a explicar comportamientos de temporización extraños, artefactos de checkpoint/restore, o desajustes de registro específicos del entorno.

Impacto:

- casi siempre reconocimiento o comprensión del entorno
- útil para explicar anomalías en registro, tiempo de actividad, o checkpoint/restore
- normalmente no constituye por sí mismo un mecanismo directo de container-escape

Un matiz importante sobre su abuso es que los namespaces de tiempo no virtualizan `CLOCK_REALTIME`, por lo que por sí solos no permiten a un atacante falsificar el reloj del host ni romper directamente las comprobaciones de caducidad de certificados a nivel del sistema. Su valor radica principalmente en confundir la lógica basada en tiempo monotónico, reproducir bugs específicos del entorno, o entender comportamiento avanzado en tiempo de ejecución.

## Checks

Estas comprobaciones se centran principalmente en confirmar si el runtime está usando un namespace de tiempo privado.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Qué resulta interesante aquí:

- En muchos entornos, estos valores no conducirán a un hallazgo de seguridad inmediato, pero sí indican si una característica de runtime especializada está en juego.
- Si estás comparando dos procesos, las diferencias aquí pueden explicar temporizaciones confusas o el comportamiento de checkpoint/restore.

Para la mayoría de los container breakouts, el time namespace no es el primer control que investigarás. Aun así, una sección completa de container-security debería mencionarlo porque forma parte del modelo moderno del kernel y, ocasionalmente, importa en escenarios avanzados de runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
