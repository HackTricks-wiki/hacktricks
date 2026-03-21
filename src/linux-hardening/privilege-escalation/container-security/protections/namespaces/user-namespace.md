# Namespace de usuario

{{#include ../../../../../banners/hacktricks-training.md}}

## Visión general

El namespace de usuario cambia el significado de los IDs de usuario y grupo permitiendo que el kernel mapee los IDs vistos dentro del namespace a IDs diferentes fuera de él. Esta es una de las protecciones modernas más importantes para contenedores porque aborda directamente el mayor problema histórico de los contenedores clásicos: **root dentro del contenedor solía estar demasiado cercano al root en el host**.

Con los namespaces de usuario, un proceso puede ejecutarse como UID 0 dentro del contenedor y aun así corresponder a un rango de UID no privilegiados en el host. Eso significa que el proceso puede comportarse como root para muchas tareas dentro del contenedor, mientras que desde el punto de vista del host es mucho menos poderoso. Esto no resuelve todos los problemas de seguridad de los contenedores, pero cambia significativamente las consecuencias de un compromiso del contenedor.

## Funcionamiento

Un namespace de usuario tiene archivos de mapeo como `/proc/self/uid_map` y `/proc/self/gid_map` que describen cómo los IDs del namespace se traducen a IDs del padre. Si el root dentro del namespace se mapea a un UID no privilegiado en el host, entonces las operaciones que normalmente requerirían root real en el host simplemente no tienen el mismo peso. Por eso los namespaces de usuario son centrales para **rootless containers** y por qué son una de las mayores diferencias entre las antiguas configuraciones predeterminadas de contenedores con root y los diseños modernos de mínimo privilegio.

El punto es sutil pero crucial: el root dentro del contenedor no se elimina, se **traduce**. El proceso aún experimenta un entorno similar a root localmente, pero el host no debería tratarlo como root completo.

## Laboratorio

Una prueba manual es:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Esto hace que el usuario actual aparezca como root dentro del namespace, aunque siga sin ser root del host fuera de él. Es una de las mejores demos sencillas para entender por qué los user namespaces son tan valiosos.

En contenedores, puedes comparar el mapeo visible con:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
El resultado exacto depende de si el engine está usando user namespace remapping o una configuración rootful más tradicional.

También puedes leer el mapeo desde el lado del host con:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Uso en tiempo de ejecución

Rootless Podman es uno de los ejemplos más claros de tratar los espacios de nombres de usuario como un mecanismo de seguridad de primera clase. Rootless Docker también depende de ellos. El soporte userns-remap de Docker mejora la seguridad en despliegues con daemon con root, aunque históricamente muchas instalaciones lo dejaron deshabilitado por razones de compatibilidad. El soporte de Kubernetes para user namespaces ha mejorado, pero la adopción y las configuraciones por defecto varían según el runtime, la distro y la política del clúster. Los sistemas Incus/LXC también dependen en gran medida del desplazamiento de UID/GID y de las ideas de idmapping.

La tendencia general es clara: los entornos que usan seriamente los espacios de nombres de usuario suelen ofrecer una mejor respuesta a "¿qué significa realmente el root dentro del contenedor?" que los entornos que no lo hacen.

## Detalles avanzados del mapeo

Cuando un proceso sin privilegios escribe en `uid_map` o `gid_map`, el kernel aplica reglas más estrictas que las que aplica a un escritor privilegiado en el namespace padre. Solo se permiten mapeos limitados, y para `gid_map` el escritor normalmente necesita deshabilitar `setgroups(2)` primero:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Este detalle importa porque explica por qué la configuración de espacios de nombres de usuario a veces falla en experimentos rootless y por qué los runtimes necesitan lógica auxiliar cuidadosa para la delegación de UID/GID.

Otra característica avanzada es el **montaje mapeado por ID (ID-mapped mount)**. En lugar de cambiar la propiedad en disco, un montaje mapeado por ID aplica un mapeo de espacio de nombres de usuario a un mount de modo que la propiedad parece traducida a través de esa vista del montaje. Esto es especialmente relevante en entornos rootless y configuraciones de runtime modernas porque permite usar rutas compartidas del host sin operaciones recursivas de `chown`. Desde el punto de vista de seguridad, la característica cambia cómo aparece un bind mount como escribible desde dentro del espacio de nombres, aunque no reescribe los metadatos subyacentes del sistema de archivos.

Por último, recuerda que cuando un proceso crea o entra en un nuevo espacio de nombres de usuario, recibe un conjunto completo de capacidades **dentro de ese espacio de nombres**. Eso no significa que de repente haya ganado poder global sobre el host. Significa que esas capacidades solo pueden usarse donde el modelo de espacios de nombres y otras protecciones lo permitan. Por eso `unshare -U` puede de repente permitir montar o realizar operaciones privilegiadas locales al espacio de nombres sin eliminar directamente el límite de root del host.

## Misconfiguraciones

La principal debilidad es simplemente no usar espacios de nombres de usuario en entornos donde serían factibles. Si el root del contenedor se mapea demasiado directamente al root del host, los bind mounts del host con permisos de escritura y las operaciones privilegiadas del kernel se vuelven mucho más peligrosas. Otro problema es forzar el compartido del espacio de nombres de usuario del host o desactivar el remapeo por compatibilidad sin reconocer cuánto cambia eso la frontera de confianza.

Los espacios de nombres de usuario también deben considerarse junto con el resto del modelo. Incluso cuando están activos, una exposición amplia de la API del runtime o una configuración de runtime muy débil puede todavía permitir escalada de privilegios por otras vías. Pero sin ellos, muchas clases antiguas de breakout se vuelven mucho más fáciles de explotar.

## Abuso

Si el contenedor tiene root (rootful) sin separación de espacios de nombres de usuario, un bind mount del host escribible se vuelve mucho más peligroso porque el proceso puede estar realmente escribiendo como root del host. Las capacidades peligrosas igualmente adquieren más significado. El atacante ya no necesita luchar tanto contra la frontera de traducción porque esa frontera apenas existe.

La presencia o ausencia de espacios de nombres de usuario debe comprobarse temprano al evaluar una ruta de breakout de un contenedor. No responde a todas las preguntas, pero muestra inmediatamente si "root en el contenedor" tiene relevancia directa para el host.

El patrón de abuso más práctico es confirmar el mapeo y luego probar de inmediato si el contenido montado del host es escribible con privilegios relevantes para el host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Si el archivo se crea como el root real del host, el aislamiento de user namespace queda efectivamente ausente para esa ruta. En ese punto, los abusos clásicos de archivos del host se vuelven realistas:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Una confirmación más segura en una evaluación en vivo es escribir un marcador benigno en lugar de modificar archivos críticos:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Estas comprobaciones importan porque responden de forma rápida a la pregunta real: ¿mapea root en este container lo suficientemente cerca al root del host como para que un writable host mount se convierta inmediatamente en una vía de compromiso del host?

### Ejemplo completo: Recuperando capacidades locales del namespace

Si seccomp permite `unshare` y el entorno autoriza un nuevo user namespace, el proceso puede recuperar un conjunto completo de capacidades dentro de ese nuevo namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Esto no es por sí mismo un host escape. La razón por la que importa es que los user namespaces pueden reactivar acciones privilegiadas namespace-local que más tarde se combinan con mounts débiles, vulnerable kernels o runtime surfaces mal expuestas.

## Comprobaciones

Estos comandos están pensados para responder la pregunta más importante en esta página: ¿a qué equivale root dentro de este container en el host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- Si el proceso es UID 0 y los maps muestran un host-root mapping directo o muy cercano, el container es mucho más peligroso.
- Si root se mapea a un unprivileged host range, esa es una línea base mucho más segura y suele indicar real user namespace isolation.
- Los mapping files son más valiosos que `id` solo, porque `id` solo muestra la identidad namespace-local.

Si la workload se ejecuta como UID 0 y el mapping muestra que esto corresponde estrechamente con host root, debes interpretar el resto de los privileges del container de forma mucho más estricta.
