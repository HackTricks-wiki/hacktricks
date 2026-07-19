# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El cgroup namespace no reemplaza los cgroups ni aplica límites de recursos por sí mismo. En su lugar, cambia **cómo aparece la jerarquía de cgroups** para el proceso. En otras palabras, virtualiza la información visible de las rutas de cgroups para que la carga de trabajo vea una vista limitada al contenedor en lugar de la jerarquía completa del host.

Esta es principalmente una funcionalidad de visibilidad y reducción de información. Ayuda a que el entorno parezca autocontenido y revela menos información sobre la estructura de cgroups del host. Puede parecer algo modesto, pero sigue siendo importante, ya que una visibilidad innecesaria de la estructura del host puede facilitar el reconocimiento y simplificar cadenas de exploits dependientes del entorno.

## Operación

Sin un cgroup namespace privado, un proceso puede ver rutas de cgroups relativas al host que exponen una parte mayor de la jerarquía de la máquina de la que resulta útil. Con un cgroup namespace privado, `/proc/self/cgroup` y otras observaciones relacionadas se vuelven más específicas de la propia vista del contenedor. Esto resulta especialmente útil en stacks de runtime modernos que quieren que la carga de trabajo vea un entorno más limpio y que revele menos información del host.

La virtualización también afecta a `/proc/<pid>/mountinfo>`, no solo a `/proc/<pid>/cgroup`. Cuando lees otro proceso desde una perspectiva de un cgroup namespace diferente, las rutas situadas fuera de la raíz de tu namespace se muestran con componentes `../` iniciales, lo que constituye una pista útil de que estás observando por encima de tu subtree delegado. Un detalle importante para labs y post-exploitation es que un cgroup namespace recién creado suele necesitar un **remount de cgroupfs desde dentro de ese namespace** antes de que `mountinfo` refleje correctamente la nueva raíz. De lo contrario, es posible que aún veas una raíz de montaje como `/..`, lo que significa que el montaje heredado todavía expone una vista enraizada en un ancestro, aunque el namespace ya haya cambiado.

## Laboratorio

Puedes inspeccionar un cgroup namespace con:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Si quieres que `mountinfo` muestre con mayor claridad la nueva raíz de cgroup-namespace, vuelve a montar el sistema de archivos cgroup desde dentro del nuevo namespace y compara de nuevo:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Y compara el comportamiento en tiempo de ejecución con:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
El cambio se centra principalmente en lo que el proceso puede ver, no en si existe la aplicación de políticas de cgroup.

## Impacto en la seguridad

El cgroup namespace se entiende mejor como una **capa de hardening de visibilidad**. Por sí solo, no impedirá un breakout si el contenedor tiene montajes de cgroup con permisos de escritura, capabilities amplias o un entorno cgroup v1 peligroso. Sin embargo, si se comparte el cgroup namespace del host, el proceso obtiene más información sobre cómo está organizado el sistema y puede resultarle más fácil relacionar las rutas de cgroup relativas al host con otras observaciones.

En **cgroup v2**, el namespace empieza a ser algo más importante porque las reglas de delegación son más estrictas. Si la jerarquía se monta con `nsdelegate`, el kernel trata los cgroup namespaces como límites de delegación: los archivos de control de los ancestros deben permanecer fuera del alcance del delegado, y las escrituras en la raíz del namespace están restringidas a archivos seguros para la delegación, como `cgroup.procs`, `cgroup.threads` y `cgroup.subtree_control`. Esto no convierte al namespace en una primitive de escape por sí solo, pero cambia lo que una carga comprometida puede inspeccionar y dónde puede crear sub-cgroups de forma segura.

Por tanto, aunque este namespace no suele ser el protagonista de los writeups sobre container breakout, sigue contribuyendo al objetivo general de minimizar la filtración de información del host y limitar la delegación de cgroup.

## Abuse

El valor inmediato para el abuse consiste principalmente en el reconocimiento. Si se comparte el cgroup namespace del host, compara las rutas visibles y busca detalles de la jerarquía que revelen información del host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Si también se exponen rutas de cgroup con permisos de escritura, combina esa visibilidad con una búsqueda de interfaces legacy peligrosas:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
El namespace en sí rara vez proporciona un escape inmediato, pero a menudo facilita el mapeo del entorno antes de probar primitives de abuso basadas en cgroups.

Una comprobación rápida de la realidad del runtime también ayuda a priorizar la ruta de ataque. Docker expone `--cgroupns=host|private`, mientras que Podman admite `host`, `private`, `container:<id>` y `ns:<path>`. Específicamente en Podman, el valor predeterminado suele ser **`host` en cgroup v1** y **`private` en cgroup v2**, por lo que identificar simplemente la versión de cgroup ya indica qué postura del namespace es más probable, incluso antes de inspeccionar la configuración OCI completa.

### Reconocimiento moderno de v2: ¿Es este un subtree delegado?

En los hosts modernos, la pregunta interesante a menudo no es `release_agent`, sino si el proceso actual se encuentra dentro de un subtree **cgroup v2** delegado con suficiente visibilidad o acceso de escritura para crear grupos anidados:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Interpretación útil:

- `cgroup2fs` significa que estás en la jerarquía unificada v2, por lo que las cadenas clásicas de `release_agent` exclusivas de v1 no deberían ser tu primera opción.
- `cgroup.controllers` muestra qué controladores están disponibles desde el padre y, por tanto, a qué controladores podría propagarse potencialmente el subárbol actual para sus hijos.
- `cgroup.subtree_control` muestra qué controladores están realmente habilitados para los descendientes.
- `cgroup.events` expone `populated=0/1`, lo cual resulta útil para observar si un subárbol se ha quedado vacío, pero **no es una primitiva de ejecución de código en el host** como `release_agent` en v1.

Si ya tienes privilegios suficientes para inspeccionar directamente el namespace de otro proceso, compara las vistas con:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Ejemplo completo: Shared cgroup Namespace + Writable cgroup v1

El cgroup namespace por sí solo normalmente no basta para lograr un escape. La escalada práctica ocurre cuando las rutas de cgroup que revelan el host se combinan con interfaces de cgroup v1 con permisos de escritura:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Si esos archivos son accesibles y permiten escritura, haz pivot inmediatamente al flujo completo de explotación de `release_agent` de [cgroups.md](../cgroups.md). El impacto es la ejecución de código en el host desde dentro del container.

Sin interfaces de cgroup con permisos de escritura, el impacto suele limitarse a reconnaissance.

## Comprobaciones

El objetivo de estos comandos es comprobar si el proceso tiene una vista privada del namespace de cgroup o si está obteniendo más información sobre la jerarquía del host de la que realmente necesita.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Qué es interesante aquí:

- Si el identificador del namespace coincide con un proceso del host que te interesa, el cgroup namespace podría estar compartido.
- Las rutas que revelan el host en `/proc/self/cgroup` o las entradas con raíz en un ancestro en `mountinfo` son útiles para el reconocimiento, incluso cuando no son directamente explotables.
- Si se utiliza `cgroup2fs`, céntrate en la delegación, los controladores visibles y los subárboles con permisos de escritura, en lugar de asumir que aún existen las primitivas antiguas de v1.
- Si los cgroup mounts también tienen permisos de escritura, la cuestión de la visibilidad se vuelve mucho más importante.

El cgroup namespace debe considerarse una capa de hardening de la visibilidad, no un mecanismo principal de prevención de escapes. Exponer innecesariamente la estructura de cgroups del host añade valor de reconocimiento para el atacante.

## Referencias

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
