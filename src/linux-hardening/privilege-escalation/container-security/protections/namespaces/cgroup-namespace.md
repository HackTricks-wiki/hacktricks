# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

El cgroup namespace no reemplaza a los cgroups y no aplica por sí mismo límites de recursos. En su lugar, cambia **cómo la jerarquía cgroup aparece** al proceso. En otras palabras, virtualiza la información visible de la ruta cgroup para que el workload vea una vista con alcance de container en lugar de la jerarquía completa del host.

Esto es principalmente una función de visibilidad y reducción de información. Ayuda a que el entorno parezca autosuficiente y revela menos sobre el diseño de cgroup del host. Puede sonar modesto, pero sigue siendo importante porque una visibilidad innecesaria de la estructura del host puede ayudar al reconocimiento y simplificar cadenas de exploit dependientes del entorno.

## Operation

Sin un private cgroup namespace, un proceso puede ver rutas cgroup relativas al host que exponen más de la jerarquía de la máquina de lo que es útil. Con un private cgroup namespace, `/proc/self/cgroup` y observaciones relacionadas pasan a estar más localizadas en la propia vista del container. Esto es especialmente útil en stacks de runtime modernos que quieren que el workload vea un entorno más limpio y que revele menos del host.

La virtualización también afecta a `/proc/<pid>/mountinfo`, no solo a `/proc/<pid>/cgroup`. Cuando lees otro proceso desde una perspectiva de cgroup-namespace diferente, las rutas fuera de la raíz de tu namespace se muestran con componentes iniciales `../`, lo que es una pista útil de que estás viendo por encima de tu subárbol delegado. Un matiz útil para labs y post-exploitation es que un cgroup namespace recién creado a menudo necesita un **cgroupfs remount desde dentro de ese namespace** antes de que `mountinfo` refleje la nueva raíz de forma limpia. De lo contrario, aún puedes ver una mount root como `/..`, lo que significa que el mount heredado sigue exponiendo una vista enraizada en un ancestro aunque el namespace en sí ya haya cambiado.

## Lab

You can inspect a cgroup namespace with:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Si quieres que `mountinfo` muestre más claramente la nueva raíz de cgroup-namespace, vuelve a montar el filesystem cgroup desde dentro del nuevo namespace y compara de nuevo:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Y compare el comportamiento en tiempo de ejecución con:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
El cambio trata principalmente sobre lo que el proceso puede ver, no sobre si existe enforcement de cgroup.

## Security Impact

El cgroup namespace se entiende mejor como una **capa de hardening de visibilidad**. Por sí solo no detendrá un breakout si el container tiene mounts de cgroup escribibles, capacidades amplias o un entorno cgroup v1 peligroso. Sin embargo, si el host cgroup namespace se comparte, el proceso aprende más sobre cómo está organizado el sistema y puede resultarle más fácil alinear rutas de cgroup relativas al host con otras observaciones.

En **cgroup v2**, el namespace empieza a importar un poco más porque las reglas de delegation son más estrictas. Si la jerarquía se monta con `nsdelegate`, el kernel trata los cgroup namespaces como límites de delegation: se supone que los archivos de control ancestros permanecen fuera del alcance del delegatee, y las escrituras en la raíz del namespace se restringen a archivos seguros para delegation como `cgroup.procs`, `cgroup.threads` y `cgroup.subtree_control`. Esto aún no convierte al namespace en un primitive de escape por sí mismo, pero sí cambia qué puede inspeccionar una carga comprometida y dónde puede crear sub-cgroups de forma segura.

Así que, aunque este namespace no suele ser el protagonista en writeups de breakout de container, sigue contribuyendo al objetivo general de minimizar la leak de información del host y de restringir la delegation de cgroup.

## Abuse

El valor inmediato de abuse es sobre todo reconnaissance. Si el host cgroup namespace se comparte, compara las rutas visibles y busca detalles de jerarquía que revelen información del host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Si también se exponen rutas cgroup escribibles, combina esa visibilidad con una búsqueda de interfaces legacy peligrosas:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
El namespace en sí rara vez da una escape instantáneo, pero a menudo facilita mapear el entorno antes de probar primitives de abuso basadas en cgroup.

Una comprobación rápida de la realidad en runtime también ayuda a priorizar la ruta de ataque. Docker expone `--cgroupns=host|private`, mientras que Podman soporta `host`, `private`, `container:<id>` y `ns:<path>`. En Podman específicamente, el valor por defecto suele ser **`host` en cgroup v1** y **`private` en cgroup v2**, así que identificar simplemente la versión de cgroup ya te dice qué postura de namespace es más probable incluso antes de inspeccionar la configuración OCI completa.

### Modern v2 Recon: Is This A Delegated Subtree?

En hosts modernos, la pregunta interesante a menudo no es `release_agent`, sino si el proceso actual está dentro de un subtree delegado de **cgroup v2** con suficiente visibilidad o acceso de escritura para construir grupos anidados:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Interpretación útil:

- `cgroup2fs` means you are in the unified v2 hierarchy, so classic v1-only `release_agent` chains should stop being your first guess.
- `cgroup.controllers` muestra qué controllers están disponibles desde el parent y, por lo tanto, a qué podrían distribuirse los children del subtree actual.
- `cgroup.subtree_control` muestra qué controllers están realmente habilitados para los descendants.
- `cgroup.events` expone `populated=0/1`, lo cual es útil para vigilar si un subtree se ha quedado vacío, pero **no** es un primitive de host-code-execution como v1 `release_agent`.

Si ya tienes suficiente privilege para inspeccionar directamente otro process namespace, compara views con:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Ejemplo completo: Shared cgroup Namespace + Writable cgroup v1

El cgroup namespace por sí solo normalmente no es suficiente para escapar. La escalada práctica ocurre cuando las rutas de cgroup que revelan el host se combinan con interfaces cgroup v1 escribibles:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Si esos archivos son accesibles y escribibles, haz pivot inmediatamente al flujo completo de explotación de `release_agent` desde [cgroups.md](../cgroups.md). El impacto es ejecución de código en el host desde dentro del contenedor.

Sin interfaces de cgroup escribibles, el impacto suele limitarse a reconocimiento.

## Checks

El objetivo de estos comandos es ver si el proceso tiene una vista privada del espacio de nombres de cgroup o si está aprendiendo más sobre la jerarquía del host de lo que realmente necesita.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Qué es interesante aquí:

- Si el identificador del namespace coincide con un proceso del host que te importa, el cgroup namespace puede estar compartido.
- Las rutas que revelan el host en `/proc/self/cgroup` o las entradas con raíz en el ancestro en `mountinfo` son útiles para reconnaissance incluso cuando no son directamente explotables.
- Si se usa `cgroup2fs`, céntrate en delegation, en los controllers visibles y en subárboles escribibles, en lugar de asumir que todavía existen los antiguos primitives de v1.
- Si los montajes de cgroup también son escribibles, la cuestión de la visibilidad se vuelve mucho más importante.

El cgroup namespace debería tratarse como una capa de visibility-hardening más que como un mecanismo principal de escape-prevention. Exponer innecesariamente la estructura de cgroup del host añade valor de reconnaissance para el atacante.

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
