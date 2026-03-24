# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Visión general

El IPC namespace aísla **System V IPC objects** y **POSIX message queues**. Esto incluye segmentos de memoria compartida, semáforos y colas de mensajes que, de otro modo, serían visibles entre procesos no relacionados en el host. En términos prácticos, esto evita que un contenedor se adjunte casualmente a objetos IPC que pertenecen a otras cargas de trabajo o al host.

Comparado con mount, PID, o user namespaces, el IPC namespace se discute con menos frecuencia, pero eso no debe confundirse con irrelevancia. La memoria compartida y los mecanismos IPC relacionados pueden contener estado altamente útil. Si el host IPC namespace está expuesto, la carga de trabajo puede obtener visibilidad de objetos de coordinación entre procesos o datos que nunca fueron destinados a cruzar la frontera del contenedor.

## Funcionamiento

Cuando el runtime crea un IPC namespace nuevo, el proceso obtiene su propio conjunto aislado de identificadores IPC. Esto significa que comandos como `ipcs` muestran solo los objetos disponibles en ese namespace. Si el contenedor en cambio se une al host IPC namespace, esos objetos pasan a formar parte de una vista global compartida.

Esto importa especialmente en entornos donde las aplicaciones o servicios usan memoria compartida de forma intensiva. Incluso cuando el contenedor no puede escapar directamente a través del IPC por sí solo, el namespace puede provocar un leak de información o permitir interferencias entre procesos que ayuden de forma material a un ataque posterior.

## Laboratorio

Puedes crear un IPC namespace privado con:
```bash
sudo unshare --ipc --fork bash
ipcs
```
Y compara el comportamiento en tiempo de ejecución con:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Uso en tiempo de ejecución

Docker y Podman aíslan IPC por defecto. Kubernetes normalmente le da al Pod su propio espacio de nombres de IPC, compartido por los contenedores en el mismo Pod pero no con el host por defecto. Compartir IPC con el host es posible, pero debe considerarse una reducción significativa del aislamiento en lugar de una opción menor de runtime.

## Malconfiguraciones

El error obvio es `--ipc=host` o `hostIPC: true`. Esto puede hacerse por compatibilidad con software heredado o por conveniencia, pero cambia sustancialmente el modelo de confianza. Otro problema recurrente es pasar por alto IPC porque parece menos dramático que host PID o host networking. En realidad, si la carga de trabajo gestiona navegadores, bases de datos, cargas científicas u otro software que usa intensivamente memoria compartida, la superficie de IPC puede ser muy relevante.

## Abuso

Cuando se comparte IPC con el host, un atacante puede inspeccionar o interferir con objetos de memoria compartida, obtener nueva información sobre el comportamiento del host o de cargas de trabajo vecinas, o combinar la información obtenida allí con visibilidad de procesos y capacidades estilo ptrace. Compartir IPC suele ser una debilidad de soporte más que la ruta completa de breakout, pero las debilidades de soporte importan porque acortan y estabilizan cadenas de ataque reales.

El primer paso útil es enumerar qué objetos de IPC son visibles:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Si el namespace IPC del host está compartido, los grandes segmentos de memoria compartida o los propietarios de objetos interesantes pueden revelar inmediatamente el comportamiento de la aplicación:
```bash
ipcs -m -p
ipcs -q -p
```
En algunos entornos, los contenidos de `/dev/shm` en sí mismos leak nombres de archivo, artefactos o tokens que vale la pena comprobar:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Compartir IPC rara vez otorga host root de forma inmediata por sí solo, pero puede exponer datos y canales de coordinación que hacen que los ataques posteriores a procesos sean mucho más fáciles.

### Ejemplo completo: Recuperación de secretos en `/dev/shm`

El caso de abuso completo más realista es el robo de datos en lugar de la evasión directa. Si host IPC o una amplia disposición de memoria compartida están expuestos, a veces se pueden recuperar directamente artefactos sensibles:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impacto:

- extracción de secretos o material de sesión dejado en shared memory
- visibilidad de las aplicaciones actualmente activas en el host
- mejor focalización para ataques posteriores basados en PID-namespace o ptrace

El uso compartido de IPC se entiende por tanto mejor como un **amplificador de ataque** que como una primitiva de escape del host independiente.

## Comprobaciones

Estos comandos están destinados a responder si la carga de trabajo tiene una vista privada de IPC, si hay objetos de shared-memory o message significativos visibles, y si `/dev/shm` en sí expone artefactos útiles.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Lo interesante aquí:

- Si `ipcs -a` revela objetos pertenecientes a usuarios o servicios inesperados, el namespace puede no estar tan aislado como se espera.
- Los segmentos de memoria compartida grandes o inusuales a menudo merecen ser investigados.
- Un montaje amplio de `/dev/shm` no es automáticamente un bug, pero en algunos entornos leaks nombres de archivo, artefactos y secretos transitorios.

IPC rara vez recibe tanta atención como los tipos de namespace más grandes, pero en entornos que lo usan intensamente, compartirlo con el host es, en gran medida, una decisión de seguridad.
{{#include ../../../../../banners/hacktricks-training.md}}
