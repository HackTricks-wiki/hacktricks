# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Resumen

El cgroup namespace no reemplaza los cgroups ni impone límites de recursos por sí mismo. En su lugar, cambia **cómo aparece la jerarquía de cgroups** para el proceso. En otras palabras, virtualiza la información de la ruta de cgroup visible de modo que la carga de trabajo vea una vista con alcance de contenedor en lugar de la jerarquía completa del host.

Esto es principalmente una característica de visibilidad y reducción de información. Ayuda a que el entorno parezca autónomo y revela menos sobre la disposición de cgroups del host. Puede parecer modesto, pero sigue siendo importante porque la visibilidad innecesaria de la estructura del host puede facilitar el reconocimiento y simplificar cadenas de explotación dependientes del entorno.

## Funcionamiento

Sin un cgroup namespace privado, un proceso puede ver rutas de cgroup relativas al host que exponen más de la jerarquía de la máquina de lo necesario. Con un cgroup namespace privado, `/proc/self/cgroup` y observaciones relacionadas se localizan más en la vista propia del contenedor. Esto es particularmente útil en entornos de ejecución modernos que quieren que la carga de trabajo vea un entorno más limpio y que revele menos sobre el host.

## Laboratorio

Puedes inspeccionar un cgroup namespace con:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
Y compare el comportamiento en tiempo de ejecución con:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
El cambio se refiere principalmente a lo que el proceso puede ver, no a si existe cgroup enforcement.

## Impacto en la seguridad

El cgroup namespace se entiende mejor como una **capa para endurecer la visibilidad**. Por sí solo no evitará un breakout si el container tiene montajes de cgroup escribibles, capacidades amplias, o un entorno peligroso de cgroup v1. Sin embargo, si el host cgroup namespace está compartido, el proceso obtiene más información sobre cómo está organizado el sistema y puede resultarle más fácil alinear rutas de cgroup relativas al host con otras observaciones.

Así que, aunque este namespace no suele ser la estrella de los container breakout writeups, aún contribuye al objetivo más amplio de minimizar host information leakage.

## Abuso

El valor inmediato para abuso es principalmente reconnaissance. Si el host cgroup namespace está compartido, compara las rutas visibles y busca detalles de la jerarquía que revelen el host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Si también se exponen rutas de cgroup con permisos de escritura, combina esa visibilidad con una búsqueda de interfaces heredadas peligrosas:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
El namespace en sí raramente proporciona un escape instantáneo, pero con frecuencia facilita mapear el entorno antes de probar cgroup-based abuse primitives.

### Ejemplo completo: Shared cgroup Namespace + Writable cgroup v1

El cgroup namespace por sí solo normalmente no es suficiente para escape. La escalada práctica ocurre cuando host-revealing cgroup paths se combinan con writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Si esos archivos son accesibles y escribibles, cambia de inmediato al flujo completo de explotación `release_agent` en [cgroups.md](../cgroups.md). El impacto es la ejecución de código en el host desde dentro del contenedor.

Sin interfaces cgroup escribibles, el impacto suele limitarse al reconocimiento.

## Comprobaciones

El objetivo de estos comandos es ver si el proceso tiene una vista privada del cgroup namespace o si está obteniendo más información sobre la jerarquía del host de la que realmente necesita.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Lo interesante aquí:

- Si el identificador del namespace coincide con un proceso del host que te importa, el cgroup namespace puede estar compartido.
- Las rutas en `/proc/self/cgroup` que revelan información del host son reconocimiento útil incluso cuando no son explotables directamente.
- Si los montajes de cgroup también son escribibles, la cuestión de visibilidad se vuelve mucho más importante.

El cgroup namespace debería tratarse como una capa de endurecimiento de visibilidad en lugar de como un mecanismo principal de prevención de escapes. Exponer la estructura de cgroup del host innecesariamente añade valor de reconocimiento para el atacante.
{{#include ../../../../../banners/hacktricks-training.md}}
