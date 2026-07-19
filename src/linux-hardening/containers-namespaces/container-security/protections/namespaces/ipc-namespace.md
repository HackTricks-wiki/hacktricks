# Namespace de IPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El namespace de IPC aísla los **objetos IPC de System V** y las **colas de mensajes POSIX**. Esto incluye segmentos de memoria compartida, semáforos y colas de mensajes que, de otro modo, serían visibles para procesos no relacionados en el host. En términos prácticos, esto evita que un contenedor se conecte fácilmente a objetos IPC pertenecientes a otras cargas de trabajo o al host.

En comparación con los namespaces de mount, PID o user, el namespace de IPC se trata con menor frecuencia, pero esto no debe confundirse con irrelevancia. La memoria compartida y los mecanismos IPC relacionados pueden contener información de estado muy útil. Si el namespace de IPC del host está expuesto, la carga de trabajo puede obtener visibilidad sobre objetos o datos de coordinación entre procesos que nunca debieron atravesar los límites del contenedor.

## Operación

Cuando el runtime crea un namespace de IPC nuevo, el proceso obtiene su propio conjunto aislado de identificadores IPC. Esto significa que comandos como `ipcs` muestran únicamente los objetos disponibles en ese namespace. Si, en cambio, el contenedor se une al namespace de IPC del host, esos objetos pasan a formar parte de una vista global compartida.

Esto es especialmente importante en entornos donde las aplicaciones o los servicios utilizan mucho la memoria compartida. Aunque el contenedor no pueda escapar directamente mediante IPC por sí solo, el namespace puede filtrar información o permitir interferencias entre procesos que ayuden materialmente en un ataque posterior.

## Laboratorio

Puedes crear un namespace de IPC privado con:
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

Docker y Podman aíslan IPC de forma predeterminada. Kubernetes normalmente proporciona al Pod su propio namespace de IPC, compartido entre los containers del mismo Pod, pero no con el host de forma predeterminada. Compartir el IPC del host es posible, pero debe considerarse una reducción significativa del aislamiento, no una opción menor del runtime.

## Configuraciones incorrectas

El error obvio es `--ipc=host` o `hostIPC: true`. Esto puede hacerse por compatibilidad con software legacy o por conveniencia, pero cambia sustancialmente el modelo de confianza. Otro problema recurrente es simplemente pasar por alto IPC porque parece menos dramático que el host PID o el host networking. En realidad, si el workload gestiona navegadores, bases de datos, workloads científicos u otro software que utilice intensivamente la memoria compartida, la superficie de IPC puede ser muy relevante.

## Abuso

Cuando se comparte el IPC del host, un atacante puede inspeccionar o interferir con objetos de memoria compartida, obtener nuevos indicios sobre el comportamiento del host o de workloads vecinos, o combinar la información obtenida allí con la visibilidad de procesos y capacidades similares a ptrace. Compartir IPC suele ser una debilidad de apoyo, más que la ruta completa de breakout, pero las debilidades de apoyo son importantes porque acortan y estabilizan las attack chains reales.

El primer paso útil es enumerar qué objetos de IPC son visibles:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Si se comparte el IPC namespace del host, los segmentos de memoria compartida grandes o los propietarios de objetos interesantes pueden revelar inmediatamente el comportamiento de la aplicación:
```bash
ipcs -m -p
ipcs -q -p
```
En algunos entornos, el contenido de `/dev/shm` puede hacer leak de nombres de archivo, artefactos o tokens que vale la pena comprobar:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Compartir IPC rara vez proporciona root instantáneo del host por sí solo, pero puede exponer datos y canales de coordinación que facilitan mucho los ataques posteriores contra procesos.

### Ejemplo completo: recuperación de secretos de `/dev/shm`

El caso de abuso completo más realista es el robo de datos, no el escape directo. Si se expone el IPC del host o un diseño amplio de memoria compartida, a veces se pueden recuperar directamente artefactos sensibles:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impacto:

- extracción de secretos o material de sesión dejado en la memoria compartida
- información sobre las aplicaciones actualmente activas en el host
- mejor orientación para ataques posteriores basados en el PID namespace o `ptrace`

Por lo tanto, el uso compartido de IPC se entiende mejor como un **amplificador de ataques** que como una primitiva independiente de escape del host.

## Comprobaciones

Estos comandos sirven para determinar si la workload tiene una vista de IPC privada, si hay objetos significativos de memoria compartida o mensajes visibles y si `/dev/shm` expone artefactos útiles.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Qué resulta interesante aquí:

- Si `ipcs -a` revela objetos propiedad de usuarios o servicios inesperados, es posible que el namespace no esté tan aislado como se esperaba.
- Los segmentos de memoria compartida grandes o inusuales suelen merecer una investigación más detallada.
- Un montaje amplio de `/dev/shm` no es automáticamente un bug, pero en algunos entornos leaks filenames, artifacts y secretos transitorios.

IPC rara vez recibe tanta atención como los tipos de namespace más importantes, pero en entornos que lo utilizan mucho, compartirlo con el host es claramente una decisión de seguridad.
{{#include ../../../../../banners/hacktricks-training.md}}
