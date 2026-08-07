# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El user namespace cambia el significado de los identificadores de usuario y grupo al permitir que el kernel asigne los IDs observados dentro del namespace a IDs diferentes fuera de este. Esta es una de las protecciones modernas más importantes para los containers porque aborda directamente el mayor problema histórico de los containers clásicos: **root dentro del container solía estar incómodamente cerca de root en el host**.

Con los user namespaces, un proceso puede ejecutarse como UID 0 dentro del container y, aun así, corresponder a un rango de UID sin privilegios en el host. Esto significa que el proceso puede comportarse como root para muchas tareas dentro del container, mientras tiene mucho menos poder desde el punto de vista del host. Esto no resuelve todos los problemas de seguridad de los containers, pero cambia significativamente las consecuencias de un compromiso del container.

## Funcionamiento

Un user namespace tiene archivos de mapeo como `/proc/self/uid_map` y `/proc/self/gid_map`, que describen cómo se traducen los IDs del namespace a los IDs del namespace padre. Si root dentro del namespace se asigna a un UID sin privilegios del host, las operaciones que requerirían ser realmente root en el host simplemente no tienen el mismo alcance. Por eso los user namespaces son fundamentales para los **rootless containers** y constituyen una de las mayores diferencias entre los antiguos valores predeterminados de los containers rootful y los diseños modernos basados en el mínimo privilegio.

El punto es sutil, pero crucial: root dentro del container no desaparece, sino que se **traduce**. El proceso sigue experimentando localmente un entorno similar al de root, pero el host no debería tratarlo como root con todos los privilegios.

## Lab

Una prueba manual es:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Esto hace que el usuario actual aparezca como root dentro del namespace, aunque siga sin ser el root del host fuera de este. Es una de las mejores demostraciones sencillas para entender por qué los user namespaces son tan valiosos.

En los containers, puedes comparar el mapping visible con:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
La salida exacta depende de si el engine utiliza user namespace remapping o una configuración rootful más tradicional.

También puedes leer el mapping desde el host con:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Uso en tiempo de ejecución

Rootless Podman es uno de los ejemplos más claros de user namespaces tratados como un mecanismo de seguridad de primera clase. Rootless Docker también depende de ellos. La compatibilidad de Docker con `userns-remap` mejora la seguridad en despliegues con daemon rootful, aunque históricamente muchos despliegues la dejaban deshabilitada por motivos de compatibilidad. La compatibilidad de Kubernetes con user namespaces ha mejorado, pero la adopción y los valores predeterminados varían según el runtime, la distro y la política del clúster. Los sistemas Incus/LXC también dependen en gran medida del desplazamiento de UID/GID y de las ideas de idmapping.

La tendencia general es clara: los entornos que utilizan user namespaces seriamente suelen ofrecer una mejor respuesta a la pregunta "¿qué significa realmente root dentro de un contenedor?" que los entornos que no lo hacen.

## Detalles avanzados del mapeo

Cuando un proceso sin privilegios escribe en `uid_map` o `gid_map`, el kernel aplica reglas más estrictas que cuando lo hace un escritor con privilegios del namespace padre. Solo se permiten mapeos limitados y, para `gid_map`, el escritor normalmente debe deshabilitar primero `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Este detalle importa porque explica por qué la configuración de user namespaces a veces falla en experimentos rootless y por qué los runtimes necesitan una lógica auxiliar cuidadosa en torno a la delegación de UID/GID.

Otra feature avanzada es el **ID-mapped mount**. En lugar de cambiar la propiedad en disco, un ID-mapped mount aplica un mapping de user namespace a un mount, de modo que la propiedad aparece traducida a través de esa vista del mount. Esto es especialmente relevante en configuraciones rootless y de runtimes modernos porque permite usar paths compartidos del host sin realizar operaciones recursivas de `chown`. Desde el punto de vista de la seguridad, la feature cambia lo writable que parece un bind mount desde dentro del namespace, aunque no reescribe los metadatos subyacentes del filesystem.

Por último, recuerda que, cuando un proceso crea o entra en un nuevo user namespace, recibe un conjunto completo de capabilities **dentro de ese namespace**. Eso no significa que de repente haya obtenido poder global sobre el host. Significa que esas capabilities solo pueden usarse donde el modelo de namespaces y otras protecciones lo permitan. Por eso `unshare -U` puede hacer que montar o realizar operaciones privilegiadas locales al namespace sea posible de repente, sin hacer que desaparezca directamente el límite de root del host.

## Misconfiguraciones

La principal debilidad consiste simplemente en no usar user namespaces en entornos donde serían viables. Si el root del contenedor se mapea de forma demasiado directa al root del host, los mounts writable del host y las operaciones privilegiadas del kernel se vuelven mucho más peligrosos. Otro problema es forzar el uso compartido del user namespace del host o deshabilitar el remapping por motivos de compatibilidad sin reconocer cuánto cambia esto el trust boundary.

Los user namespaces también deben considerarse junto con el resto del modelo. Incluso cuando están activos, una exposición amplia de la API del runtime o una configuración muy débil del runtime todavía pueden permitir privilege escalation mediante otros paths. Pero sin ellos, muchas clases antiguas de breakout son mucho más fáciles de explotar.

## Abuso

Si el contenedor es rootful sin separación mediante user namespaces, un writable host bind mount se vuelve mucho más peligroso porque el proceso podría estar escribiendo realmente como root del host. Las capabilities peligrosas también adquieren mayor importancia. El atacante ya no necesita luchar tanto contra el límite de traducción porque dicho límite apenas existe.

La presencia o ausencia de user namespaces debe comprobarse al principio al evaluar un path de container breakout. No responde a todas las preguntas, pero muestra inmediatamente si "root en el contenedor" tiene relevancia directa sobre el host.

El patrón de abuso más práctico consiste en confirmar el mapping y comprobar inmediatamente si el contenido montado desde el host es writable con privilegios relevantes para el host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Si el archivo se crea como el root real del host, el aislamiento del user namespace está efectivamente ausente para esa ruta. En ese punto, los abusos clásicos de archivos del host se vuelven realistas:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Una confirmación más segura durante una evaluación en vivo es escribir un marcador benigno en lugar de modificar archivos críticos:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Estas comprobaciones son importantes porque responden rápidamente a la pregunta real: ¿root en este contenedor se asigna de forma suficientemente cercana a root del host como para que un montaje del host con permisos de escritura se convierta inmediatamente en una vía de compromiso del host?

### Ejemplo completo: Recuperar capabilities locales del namespace

Si seccomp permite `unshare` y el entorno permite crear un nuevo user namespace, el proceso puede recuperar un conjunto completo de capabilities dentro de ese nuevo namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Esto no es por sí mismo un host escape. La razón por la que importa es que los user namespaces pueden volver a habilitar acciones privilegiadas locales al namespace que posteriormente se combinan con montajes débiles, kernels vulnerables o superficies del runtime mal expuestas.

## Comprobaciones

Estos comandos están destinados a responder la pregunta más importante de esta página: ¿a qué se asigna en el host el root dentro de este contenedor?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Qué resulta interesante aquí:

- Si el proceso tiene UID 0 y los mapas muestran una asignación directa o muy cercana al root del host, el contenedor es mucho más peligroso.
- Si root se asigna a un rango no privilegiado del host, es una base mucho más segura y normalmente indica un aislamiento real mediante user namespace.
- Los archivos de asignación son más valiosos que `id` por sí solo, porque `id` solo muestra la identidad local del namespace.

Si la workload se ejecuta como UID 0 y la asignación muestra que esto corresponde estrechamente al root del host, debes interpretar de forma mucho más estricta el resto de los privilegios del contenedor.

{{#include ../../../../../banners/hacktricks-training.md}}
