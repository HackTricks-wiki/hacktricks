# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Visión general

El cgroup namespace no reemplaza a los cgroups y no impone por sí mismo límites de recursos. En su lugar, cambia **cómo aparece la jerarquía de cgroup** para el proceso. En otras palabras, virtualiza la información de la ruta de cgroup visible para que el workload vea una vista limitada al contenedor en lugar de la jerarquía completa del host.

Esto es principalmente una característica de visibilidad y reducción de información. Ayuda a que el entorno parezca autocontenible y revela menos sobre la disposición de cgroup del host. Puede sonar modesto, pero sigue siendo importante porque la visibilidad innecesaria de la estructura del host puede facilitar el reconocimiento y simplificar cadenas de explotación dependientes del entorno.

## Operación

Sin un cgroup namespace privado, un proceso puede ver rutas de cgroup relativas al host que exponen más de la jerarquía de la máquina de lo necesario. Con un cgroup namespace privado, `/proc/self/cgroup` y observaciones relacionadas se vuelven más localizadas a la vista del propio contenedor. Esto es particularmente útil en pilas de runtime modernas que quieren que el workload vea un entorno más limpio y que revele menos del host.

## Laboratorio

Puedes inspeccionar un cgroup namespace con:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
Y compara el comportamiento en tiempo de ejecución con:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
El cambio tiene más que ver con lo que el proceso puede ver, no con si existe cgroup enforcement.

## Impacto en la seguridad

El cgroup namespace se entiende mejor como una **visibility-hardening layer**. Por sí sola no evitará un breakout si el container tiene writable cgroup mounts, broad capabilities, o un entorno peligroso de cgroup v1. Sin embargo, si el host cgroup namespace está compartido, el proceso aprende más sobre cómo está organizado el sistema y puede resultarle más fácil alinear host-relative cgroup paths con otras observaciones.

Así que, aunque este namespace no suele ser la estrella de los container breakout writeups, aún contribuye al objetivo más amplio de minimizar la host information leakage.

## Abuso

El valor de abuso inmediato es principalmente reconocimiento. Si el host cgroup namespace está compartido, compara las rutas visibles y busca detalles de la jerarquía que revelen información del host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Si también se exponen rutas de cgroup escribibles, combina esa visibilidad con una búsqueda de interfaces heredadas peligrosas:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
El namespace en sí rara vez proporciona un escape instantáneo, pero a menudo facilita mapear el entorno antes de probar cgroup-based abuse primitives.

### Ejemplo completo: Shared cgroup Namespace + Writable cgroup v1

El cgroup namespace por sí solo normalmente no es suficiente para el escape. La escalada práctica ocurre cuando host-revealing cgroup paths se combinan con writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Si esos archivos son accesibles y escribibles, pivotea inmediatamente al flujo completo de explotación `release_agent` de [cgroups.md](../cgroups.md). El impacto es la ejecución de código en el host desde dentro del contenedor.

Sin interfaces de cgroup escribibles, el impacto suele limitarse al reconocimiento.

## Comprobaciones

El objetivo de estos comandos es ver si el proceso tiene una vista de namespace de cgroup privada o si está aprendiendo más sobre la jerarquía del host de lo que realmente necesita.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
- Si el identificador del namespace coincide con un proceso del host que te interesa, el cgroup namespace puede estar compartido.
- Las rutas que revelan información del host en `/proc/self/cgroup` aportan reconocimiento útil incluso cuando no son explotables directamente.
- Si los puntos de montaje de cgroup también son escribibles, la cuestión de la visibilidad se vuelve mucho más importante.

El cgroup namespace debería tratarse como una capa de hardening enfocada a la visibilidad en lugar de un mecanismo primario de prevención de escapes. Exponer innecesariamente la estructura de cgroup del host aumenta el valor de reconocimiento para el atacante.
{{#include ../../../../../banners/hacktricks-training.md}}
