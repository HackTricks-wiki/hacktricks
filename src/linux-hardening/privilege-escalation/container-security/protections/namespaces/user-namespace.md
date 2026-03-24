# Espacio de nombres de usuario

{{#include ../../../../../banners/hacktricks-training.md}}

## Visión general

El espacio de nombres de usuario cambia el significado de los IDs de usuario y grupo permitiendo que el kernel mapee los IDs visibles dentro del namespace a IDs diferentes fuera de él. Esta es una de las protecciones modernas más importantes para contenedores porque aborda directamente el mayor problema histórico en los contenedores clásicos: **el root dentro del contenedor solía estar incómodamente cerca del root en el host**.

Con los espacios de nombres de usuario, un proceso puede ejecutarse como UID 0 dentro del contenedor y aun así corresponder a un rango de UID no privilegiados en el host. Eso significa que el proceso puede comportarse como root para muchas tareas dentro del contenedor mientras es mucho menos poderoso desde el punto de vista del host. Esto no resuelve todos los problemas de seguridad de contenedores, pero cambia significativamente las consecuencias de una compromisión del contenedor.

## Operación

Un espacio de nombres de usuario tiene archivos de mapeo como `/proc/self/uid_map` y `/proc/self/gid_map` que describen cómo los IDs del namespace se traducen a IDs del padre. Si el root dentro del namespace se mapea a un UID de host no privilegiado, entonces operaciones que requerirían root real en el host simplemente no tienen el mismo peso. Por eso los espacios de nombres de usuario son centrales para **rootless containers** y por qué son una de las mayores diferencias entre los antiguos defaults de contenedores rootful y los diseños modernos de menor privilegio.

El punto es sutil pero crucial: el root dentro del contenedor no se elimina, se **traduce**. El proceso aún experimenta un entorno similar a root localmente, pero el host no debería tratarlo como root completo.

## Laboratorio

Una prueba manual es:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Esto hace que el usuario actual aparezca como root dentro del namespace, mientras que fuera de él sigue sin ser root del host. Es una de las mejores demos simples para entender por qué los user namespaces son tan valiosos.

En containers, puedes comparar la asignación visible con:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
La salida exacta depende de si el engine está usando user namespace remapping o una configuración rootful más tradicional.

También puedes leer el mapeo desde el lado del host con:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Uso en tiempo de ejecución

Rootless Podman es uno de los ejemplos más claros de que los espacios de nombres de usuario son tratados como un mecanismo de seguridad de primera clase. Rootless Docker también depende de ellos. El soporte userns-remap de Docker mejora la seguridad en despliegues con daemon con privilegios (rootful) también, aunque históricamente muchas implementaciones lo dejaron deshabilitado por razones de compatibilidad. El soporte de Kubernetes para los espacios de nombres de usuario ha mejorado, pero la adopción y las configuraciones por defecto varían según el runtime, la distro y la política del cluster. Los sistemas Incus/LXC también dependen en gran medida de las ideas de UID/GID shifting e idmapping.

La tendencia general está clara: los entornos que usan en serio los espacios de nombres de usuario suelen ofrecer una respuesta mejor a "¿qué significa realmente 'root' en un contenedor?" que los entornos que no lo hacen.

## Detalles avanzados de mapeo

Cuando un proceso sin privilegios escribe en `uid_map` o `gid_map`, el kernel aplica reglas más estrictas que las que aplica a un escritor en el espacio de nombres padre con privilegios. Solo se permiten mapeos limitados, y para `gid_map` el escritor normalmente necesita deshabilitar `setgroups(2)` primero:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Este detalle importa porque explica por qué la configuración de user-namespace a veces falla en experimentos rootless y por qué los runtimes necesitan lógica auxiliar cuidadosa para la delegación de UID/GID.

Another advanced feature is the **ID-mapped mount**. Instead of changing on-disk ownership, an ID-mapped mount applies a user-namespace mapping to a mount so that ownership appears translated through that mount view. This is especially relevant in rootless and modern runtime setups because it allows shared host paths to be used without recursive `chown` operations. Security-wise, the feature changes how writable a bind mount appears from inside the namespace, even though it does not rewrite the underlying filesystem metadata.

Por último, recuerda que cuando un proceso crea o entra en un nuevo user namespace, recibe un conjunto completo de capabilities **dentro de ese namespace**. Eso no significa que de repente haya adquirido poder global sobre el host. Significa que esas capabilities solo pueden usarse donde el modelo de namespaces y otras protecciones lo permitan. Esta es la razón por la que `unshare -U` puede de repente permitir operaciones privilegiadas locales al namespace, como montar, sin que eso elimine directamente la frontera de root del host.

## Misconfiguraciones

La principal debilidad es simplemente no usar user namespaces en entornos donde serían factibles. Si el root del container se mapea demasiado directamente al root del host, los mounts de host con capacidad de escritura y las operaciones privilegiadas del kernel se vuelven mucho más peligrosos. Otro problema es forzar el sharing del user namespace del host o desactivar el remapping por compatibilidad sin reconocer cuánto cambia eso el límite de confianza.

Los user namespaces también deben considerarse junto con el resto del modelo. Incluso cuando están activos, una API de runtime ampliamente expuesta o una configuración de runtime muy débil aún pueden permitir escalada de privilegios por otras vías. Pero sin ellos, muchas clases antiguas de breakout son mucho más fáciles de explotar.

## Abuso

Si el container es rootful sin separación de user namespace, un bind mount del host con capacidad de escritura se vuelve mucho más peligroso porque el proceso puede realmente estar escribiendo como root del host. Las capabilities peligrosas igualmente cobran más significado. El atacante ya no necesita luchar tanto contra la frontera de traducción porque esa frontera casi no existe.

La presencia o ausencia de user namespace debe comprobarse temprano al evaluar una ruta de breakout de container. No responde a todas las preguntas, pero muestra inmediatamente si el "root in container" tiene relevancia directa sobre el host.

El patrón de abuso más práctico es confirmar el mapeo y luego probar inmediatamente si el contenido montado del host es escribible con privilegios relevantes para el host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Si el archivo se crea como real host root, user namespace isolation está efectivamente ausente para esa ruta. En ese punto, los abusos clásicos de host-file se vuelven realistas:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Una confirmación más segura durante una evaluación en vivo es escribir un marcador benigno en lugar de modificar archivos críticos:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Estas comprobaciones importan porque responden rápidamente a la pregunta real: ¿root en este container se mapea lo suficientemente cerca de host root como para que un writable host mount se convierta inmediatamente en una vía de compromiso del host?

### Ejemplo completo: Recuperando capacidades locales del namespace

Si seccomp permite `unshare` y el entorno permite un nuevo namespace de usuario, el proceso puede recuperar un conjunto completo de capacidades dentro de ese nuevo namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Esto, por sí solo, no constituye un host escape. Importa porque los user namespaces pueden reactivar acciones privilegiadas locales al namespace que posteriormente se combinan con weak mounts, vulnerable kernels o superficies de runtime mal expuestas.

## Comprobaciones

Estos comandos están pensados para responder la pregunta más importante de esta página: ¿a qué equivale root dentro de este container en el host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- Si el proceso es UID 0 y los mapas muestran un host-root mapping directo o muy cercano, el contenedor es mucho más peligroso.
- Si root se mapea a un host range sin privilegios, esa es una línea base mucho más segura y normalmente indica un aislamiento real de user namespace.
- Los archivos de mapping son más valiosos que `id` por sí solos, porque `id` solo muestra la identidad local del namespace.

Si la carga de trabajo se ejecuta como UID 0 y el mapping muestra que esto corresponde estrechamente al host root, debes interpretar el resto de los privilegios del contenedor de forma mucho más estricta.
{{#include ../../../../../banners/hacktricks-training.md}}
