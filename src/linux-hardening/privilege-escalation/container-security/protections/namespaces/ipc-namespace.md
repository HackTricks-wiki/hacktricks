# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Visión general

The IPC namespace isolates **System V IPC objects** and **POSIX message queues**. That includes shared memory segments, semaphores, and message queues that would otherwise be visible across unrelated processes on the host. In practical terms, this prevents a contenedor from casually attaching to IPC objects belonging to other workloads or the host.

Compared with mount, PID, or user namespaces, the IPC namespace is often discussed less often, but that should not be confused with irrelevance. Shared memory and related IPC mechanisms can contain highly useful state. If the host IPC namespace is exposed, the workload may gain visibility into inter-process coordination objects or data that was never intended to cross the container boundary.

## Funcionamiento

When the runtime creates a fresh IPC namespace, the process gets its own isolated set of IPC identifiers. This means commands such as `ipcs` show only the objects available in that namespace. If the container instead joins the host IPC namespace, those objects become part of a shared global view.

This matters especially in environments where applications or services use shared memory heavily. Even when the contenedor cannot directly break out through IPC alone, the namespace may leak information or enable cross-process interference that materially helps a later attack.

## Laboratorio

You can create a private IPC namespace with:
```bash
sudo unshare --ipc --fork bash
ipcs
```
Y compare el comportamiento en tiempo de ejecución con:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Uso en tiempo de ejecución

Docker y Podman aíslan IPC por defecto. Kubernetes normalmente asigna al Pod su propio namespace de IPC, compartido por los contenedores dentro del mismo Pod pero no con el host por defecto. Compartir el IPC con el host es posible, pero debe considerarse una reducción significativa de aislamiento en lugar de una opción de runtime menor.

## Configuraciones incorrectas

El error obvio es `--ipc=host` o `hostIPC: true`. Esto puede hacerse por compatibilidad con software heredado o por conveniencia, pero cambia el modelo de confianza sustancialmente. Otro problema recurrente es simplemente pasar por alto IPC porque parece menos dramático que el PID del host o la red del host. En realidad, si la carga de trabajo maneja navegadores, bases de datos, cargas de trabajo científicas u otro software que haga un uso intensivo de la memoria compartida, la superficie de IPC puede ser muy relevante.

## Abuso

Cuando se comparte el IPC del host, un atacante puede inspeccionar o interferir con objetos de memoria compartida, obtener nueva información sobre el comportamiento del host o de cargas de trabajo vecinas, o combinar la información obtenida allí con visibilidad de procesos y capacidades de estilo ptrace. Compartir IPC suele ser una debilidad auxiliar más que la vía completa de escape, pero las debilidades auxiliares importan porque acortan y estabilizan cadenas de ataque reales.

El primer paso útil es enumerar qué objetos IPC son visibles:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Si se comparte el IPC namespace del host, segmentos grandes de memoria compartida o propietarios de objetos interesantes pueden revelar el comportamiento de la aplicación de inmediato:
```bash
ipcs -m -p
ipcs -q -p
```
En algunos entornos, los contenidos de `/dev/shm` por sí mismos leak nombres de archivo, artefactos o tokens que vale la pena revisar:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC sharing rara vez otorga host root de forma inmediata por sí solo, pero puede exponer datos y canales de coordinación que facilitan mucho los ataques posteriores a procesos.

### Ejemplo completo: `/dev/shm` Recuperación de secretos

El caso de abuso completo más realista es el robo de datos más que la fuga directa. Si host IPC o un amplio diseño de memoria compartida están expuestos, a veces se pueden recuperar directamente artefactos sensibles:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impacto:

- extracción de secretos o material de sesión dejado en la memoria compartida
- información sobre las aplicaciones actualmente activas en el host
- mejor focalización para ataques posteriores basados en PID-namespace o ptrace

El uso compartido de IPC se entiende por tanto mejor como un **amplificador de ataques** que como una primitiva independiente de escape del host.

## Comprobaciones

Estos comandos están pensados para responder si la carga de trabajo tiene una vista IPC privada, si hay objetos significativos de memoria compartida o de mensajes visibles, y si `/dev/shm` expone artefactos útiles.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Lo interesante aquí:

- Si `ipcs -a` revela objetos pertenecientes a usuarios o servicios inesperados, el namespace puede no estar tan aislado como se espera.
- Los segmentos de memoria compartida grandes o inusuales suelen merecer seguimiento.
- Un montaje amplio de `/dev/shm` no es automáticamente un bug, pero en algunos entornos leaks nombres de archivo, artefactos y secretos transitorios.

IPC rara vez recibe tanta atención como los tipos de namespace más grandes, pero en entornos que lo usan intensamente, compartirlo con el host es, en gran medida, una decisión de seguridad.
