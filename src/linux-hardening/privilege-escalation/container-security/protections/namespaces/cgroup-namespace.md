# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El cgroup namespace no reemplaza a los cgroups ni aplica por sí mismo límites de recursos. En su lugar, cambia **cómo aparece la jerarquía de cgroups** al proceso. En otras palabras, virtualiza la información visible de la ruta de cgroup para que la carga de trabajo vea una vista limitada al contenedor en vez de la jerarquía completa del host.

Esto es principalmente una característica de visibilidad y reducción de información. Ayuda a que el entorno parezca autocontenido y revela menos sobre la disposición de cgroups del host. Puede parecer modesto, pero sigue siendo importante porque la visibilidad innecesaria de la estructura del host puede facilitar el reconocimiento y simplificar cadenas de explotación dependientes del entorno.

## Funcionamiento

Sin un cgroup namespace privado, un proceso puede ver rutas de cgroup relativas al host que exponen más de la jerarquía de la máquina de lo necesario. Con un cgroup namespace privado, `/proc/self/cgroup` y observaciones relacionadas se vuelven más localizadas a la vista del contenedor. Esto es particularmente útil en stacks de runtime modernos que desean que la carga de trabajo vea un entorno más limpio y que revele menos del host.

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
El cambio se refiere principalmente a lo que el proceso puede ver, no a si existe el enforcement de cgroup.

## Impacto en la seguridad

El cgroup namespace debe entenderse mejor como una **capa de endurecimiento de visibilidad**. Por sí sola no detendrá un breakout si el container tiene writable cgroup mounts, capacidades amplias, o un entorno peligroso de cgroup v1. Sin embargo, si el host cgroup namespace está compartido, el proceso aprende más sobre cómo está organizada la sistema y puede resultarle más fácil alinear rutas de cgroup relativas al host con otras observaciones.

Así que, aunque este namespace no suele ser la estrella en los container breakout writeups, sigue contribuyendo al objetivo más amplio de minimizar la fuga de información del host.

## Abuso

El valor inmediato para abuso es mayormente reconnaissance. Si el host cgroup namespace está compartido, compare las rutas visibles y busque detalles de la jerarquía que revelen información del host:
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
El namespace por sí solo rara vez proporciona un escape instantáneo, pero a menudo facilita mapear el entorno antes de probar cgroup-based abuse primitives.

### Ejemplo completo: Shared cgroup Namespace + Writable cgroup v1

El cgroup namespace por sí solo normalmente no es suficiente para un escape. La escalada práctica ocurre cuando host-revealing cgroup paths se combinan con writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Si esos archivos son accesibles y escribibles, pivot inmediatamente al flujo completo de explotación `release_agent` desde [cgroups.md](../cgroups.md). El impacto es ejecución de código en el host desde dentro del contenedor.

Sin interfaces cgroup escribibles, el impacto suele limitarse al reconocimiento.

## Comprobaciones

El objetivo de estos comandos es ver si el proceso tiene una vista privada del cgroup namespace o si está obteniendo más información sobre la host hierarchy de la que realmente necesita.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Lo interesante aquí:

- Si el identificador del namespace coincide con un proceso del host que te interesa, el cgroup namespace puede estar compartido.
- Rutas del host que revelan información en `/proc/self/cgroup` son reconocimiento útil incluso cuando no son directamente explotables.
- Si los cgroup mounts también son escribibles, la cuestión de visibilidad se vuelve mucho más importante.

El cgroup namespace debe tratarse como una capa de endurecimiento de la visibilidad en lugar de como un mecanismo primario de prevención de escapes. Exponer la estructura de cgroup del host innecesariamente añade valor de reconocimiento para el atacante.
