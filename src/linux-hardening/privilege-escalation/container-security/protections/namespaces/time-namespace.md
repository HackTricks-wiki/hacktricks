# Espacio de nombres de tiempo

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El time namespace virtualiza relojes seleccionados, especialmente **`CLOCK_MONOTONIC`** y **`CLOCK_BOOTTIME`**. Es un namespace más nuevo y más especializado que los namespaces de mount, PID, network o user, y rara vez es lo primero que un operador considera al hablar de container hardening. Aun así, forma parte de la familia moderna de namespaces y vale la pena entenderlo conceptualmente.

El propósito principal es permitir que un proceso observe offsets controlados para ciertos relojes sin cambiar la vista de tiempo global del host. Esto es útil para flujos de trabajo de checkpoint/restore, pruebas deterministas y algunos comportamientos avanzados en tiempo de ejecución. Normalmente no es un control de aislamiento principal del mismo modo que los namespaces de mount o user, pero aun así contribuye a que el entorno del proceso sea más autocontenido.

## Laboratorio

Si el kernel del host y userspace lo soportan, puedes inspeccionar el namespace con:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
El soporte varía según la versión del kernel y de las herramientas, por lo que esta página trata más de entender el mecanismo que de esperar que esté visible en todos los entornos de laboratorio.

### Desplazamientos de tiempo

Los namespaces de tiempo de Linux virtualizan los desplazamientos para `CLOCK_MONOTONIC` y `CLOCK_BOOTTIME`. Los desplazamientos actuales por namespace se exponen a través de `/proc/<pid>/timens_offsets`, que en kernels con soporte también pueden ser modificados por un proceso que tenga `CAP_SYS_TIME` dentro del namespace relevante:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
El archivo contiene deltas en nanosegundos. Ajustar `monotonic` en dos días cambia las observaciones tipo uptime dentro de ese namespace sin alterar el reloj de pared del host.

### Flags auxiliares de `unshare`

Las versiones recientes de `util-linux` ofrecen flags de conveniencia que escriben los offsets automáticamente:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Estas banderas son principalmente una mejora de usabilidad, pero también facilitan reconocer la característica en la documentación y en las pruebas.

## Uso en tiempo de ejecución

Los espacios de nombres `time` son más recientes y menos ampliamente utilizados que los espacios de nombres de mount o PID. OCI Runtime Specification v1.1 añadió soporte explícito para el `time` namespace y el campo `linux.timeOffsets`, y las versiones más recientes de `runc` implementan esa parte del modelo. Un fragmento OCI mínimo se ve así:
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
Esto importa porque convierte el espacio de nombres de tiempo, de un primitivo del kernel de nicho, en algo que los runtimes pueden solicitar de forma portátil.

## Impacto en la seguridad

Hay menos casos clásicos de escape centrados en el espacio de nombres de tiempo que en otros tipos de espacio de nombres. El riesgo aquí no suele ser que el espacio de nombres de tiempo permita directamente un escape, sino que los lectores lo ignoren por completo y, por tanto, no detecten cómo los runtimes avanzados pueden estar moldeando el comportamiento de los procesos. En entornos especializados, vistas de reloj alteradas pueden afectar el checkpoint/restore, la observability o las suposiciones forenses.

## Abuso

Normalmente no existe aquí un primitivo de escape directo, pero el comportamiento del reloj alterado aún puede ser útil para entender el entorno de ejecución e identificar características avanzadas de los runtimes:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Si estás comparando dos procesos, las diferencias aquí pueden ayudar a explicar comportamientos extraños relacionados con el tiempo, artefactos de checkpoint/restore o desajustes en los registros específicos del entorno.

Impacto:

- casi siempre reconocimiento o comprensión del entorno
- útil para explicar anomalías en logging, uptime o checkpoint/restore
- normalmente no es, por sí solo, un mecanismo directo de container-escape

La matiz importante sobre el abuso es que los namespaces de tiempo no virtualizan `CLOCK_REALTIME`, por lo que por sí solos no permiten que un atacante falsifique el reloj del host ni que rompan directamente las comprobaciones de caducidad de certificados a nivel del sistema. Su valor radica principalmente en confundir lógica basada en tiempo monotónico, reproducir errores específicos del entorno o comprender el comportamiento avanzado en tiempo de ejecución.

## Comprobaciones

Estas comprobaciones se centran principalmente en confirmar si el runtime está usando un namespace de tiempo privado.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Lo interesante aquí:

- En muchos entornos, estos valores no conducirán a un hallazgo de seguridad inmediato, pero sí indican si una característica especializada del entorno de ejecución está en juego.
- Si comparas dos procesos, las diferencias aquí pueden explicar una sincronización confusa o el comportamiento de checkpoint/restore.

Para la mayoría de los container breakouts, el time namespace no es el primer control que investigarás. Aun así, una sección completa de container-security debería mencionarlo, porque forma parte del modelo moderno del kernel y, ocasionalmente, es relevante en escenarios avanzados de entorno de ejecución.
