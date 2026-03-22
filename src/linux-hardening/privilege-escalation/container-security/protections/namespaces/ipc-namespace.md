# Espacio de nombres IPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El espacio de nombres IPC aísla **System V IPC objects** y **POSIX message queues**. Eso incluye segmentos de memoria compartida, semáforos y colas de mensajes que, de otro modo, serían visibles entre procesos no relacionados en el host. En términos prácticos, esto evita que un container se conecte casualmente a objetos IPC pertenecientes a otras cargas de trabajo o al host.

En comparación con mount, PID o user namespaces, el espacio de nombres IPC se discute con menos frecuencia, pero eso no debe confundirse con irrelevancia. La memoria compartida y los mecanismos IPC relacionados pueden contener estado muy útil. Si el host IPC namespace está expuesto, la carga de trabajo puede obtener visibilidad sobre objetos de coordinación entre procesos o datos que nunca se pretendió que cruzaran la frontera del container.

## Funcionamiento

Cuando el runtime crea un nuevo espacio de nombres IPC, el proceso obtiene su propio conjunto aislado de identificadores IPC. Esto significa que comandos como `ipcs` muestran solo los objetos disponibles en ese espacio de nombres. Si el container en su lugar se une al host IPC namespace, esos objetos pasan a formar parte de una vista global compartida.

Esto importa especialmente en entornos donde las aplicaciones o servicios usan memoria compartida de forma intensiva. Incluso cuando el container no puede escapar directamente solo a través de IPC, el espacio de nombres puede leak información o permitir interferencias entre procesos que ayuden materialmente a un ataque posterior.

## Laboratorio

Puedes crear un espacio de nombres IPC privado con:
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

Docker y Podman aíslan IPC por defecto. Kubernetes típicamente da al Pod su propio IPC namespace, compartido por los contenedores en el mismo Pod pero no, por defecto, con el host. El uso compartido de host IPC es posible, pero debe considerarse una reducción significativa del aislamiento en lugar de una opción menor de tiempo de ejecución.

## Malconfiguraciones

El error más obvio es `--ipc=host` o `hostIPC: true`. Esto puede hacerse por compatibilidad con software heredado o por conveniencia, pero cambia sustancialmente el modelo de confianza. Otro problema recurrente es simplemente pasar por alto IPC porque parece menos dramático que host PID o host networking. En realidad, si el workload maneja browsers, databases, scientific workloads u otro software que hace uso intensivo de shared memory, la superficie de IPC puede ser muy relevante.

## Abuso

Cuando se comparte host IPC, un atacante puede inspeccionar o interferir con shared memory objects, obtener nueva información sobre el comportamiento del host o de workloads vecinos, o combinar la información aprendida allí con la visibilidad de procesos y capacidades ptrace-style. IPC sharing suele ser una debilidad de soporte más que la ruta completa de breakout, pero las debilidades de soporte importan porque acortan y estabilizan las cadenas de ataque reales.

El primer paso útil es enumerar qué objetos IPC son visibles en absoluto:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Si el IPC namespace del host se comparte, grandes segmentos de memoria compartida o propietarios de objetos interesantes pueden revelar inmediatamente el comportamiento de la aplicación:
```bash
ipcs -m -p
ipcs -q -p
```
En algunos entornos, el contenido de `/dev/shm` en sí puede leak filenames, artifacts, or tokens que vale la pena revisar:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
El intercambio de IPC rara vez concede root del host de forma instantánea por sí mismo, pero puede exponer datos y canales de coordinación que facilitan mucho los ataques posteriores a procesos.

### Ejemplo completo: Recuperación de secretos en `/dev/shm`

El caso de abuso más realista es el robo de datos en lugar de una fuga directa. Si el IPC del host o una disposición amplia de memoria compartida están expuestos, a veces se pueden recuperar directamente artefactos sensibles:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impacto:

- extracción de secretos o material de sesión dejado en la memoria compartida
- información sobre las aplicaciones actualmente activas en el host
- mejor orientación para posteriores ataques basados en PID-namespace o ptrace

El uso compartido de IPC se entiende por tanto mejor como un **amplificador de ataques** que como una primitiva independiente de escape del host.

## Comprobaciones

Estos comandos están pensados para responder si la carga de trabajo tiene una vista IPC privada, si existen objetos significativos de memoria compartida o de mensajes visibles, y si `/dev/shm` expone por sí mismo artefactos útiles.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Lo interesante aquí:

- Si `ipcs -a` revela objetos propiedad de usuarios o servicios inesperados, el namespace puede no estar tan aislado como se espera.
- Los segmentos de memoria compartida grandes o inusuales a menudo merecen seguimiento.
- Un montaje amplio de `/dev/shm` no es automáticamente un fallo, pero en algunos entornos it leaks nombres de archivo, artefactos y secretos transitorios.

IPC rara vez recibe tanta atención como los tipos de namespace más grandes, pero en entornos que lo usan intensivamente, compartirlo con el host es, en gran medida, una decisión de seguridad.
{{#include ../../../../../banners/hacktricks-training.md}}
