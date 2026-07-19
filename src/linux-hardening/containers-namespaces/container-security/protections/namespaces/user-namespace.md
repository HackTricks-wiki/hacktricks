# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El user namespace cambia el significado de los ID de usuario y grupo al permitir que el kernel asigne los ID vistos dentro del namespace a otros ID fuera de este. Esta es una de las protecciones modernas más importantes para containers porque aborda directamente el mayor problema histórico de los containers clásicos: **root dentro del container solía estar incómodamente cerca de root en el host**.

Con los user namespaces, un proceso puede ejecutarse como UID 0 dentro del container y seguir correspondiendo a un rango de UID sin privilegios en el host. Esto significa que el proceso puede comportarse como root para muchas tareas dentro del container, mientras tiene mucho menos poder desde el punto de vista del host. Esto no resuelve todos los problemas de seguridad de los containers, pero cambia significativamente las consecuencias de un compromiso del container.

## Funcionamiento

Un user namespace tiene archivos de mapeo como `/proc/self/uid_map` y `/proc/self/gid_map`, que describen cómo se traducen los ID del namespace a los ID del namespace padre. Si root dentro del namespace se asigna a un UID sin privilegios del host, las operaciones que requerirían root real en el host simplemente no tienen el mismo alcance. Por eso los user namespaces son fundamentales para los **rootless containers** y constituyen una de las mayores diferencias entre las configuraciones predeterminadas de containers rootful más antiguas y los diseños modernos de mínimo privilegio.

El punto es sutil, pero crucial: root dentro del container no desaparece, sino que se **traduce**. El proceso sigue experimentando localmente un entorno similar al de root, pero el host no debería tratarlo como root completo.

## Lab

Una prueba manual es:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Esto hace que el usuario actual aparezca como root dentro del namespace, aunque siga sin ser root del host fuera de él. Es una de las mejores demostraciones sencillas para entender por qué los user namespaces son tan valiosos.

En containers, puedes comparar el mapping visible con:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
El resultado exacto depende de si el engine utiliza user namespace remapping o una configuración rootful más tradicional.

También puedes leer el mapeo desde el lado del host con:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Uso en tiempo de ejecución

Rootless Podman es uno de los ejemplos más claros de user namespaces tratados como un mecanismo de seguridad de primera clase. Rootless Docker también depende de ellos. La compatibilidad de Docker con userns-remap también mejora la seguridad en implementaciones con daemon rootful, aunque históricamente muchas implementaciones la dejaron deshabilitada por razones de compatibilidad. La compatibilidad de Kubernetes con user namespaces ha mejorado, pero la adopción y los valores predeterminados varían según el runtime, la distro y la política del clúster. Los sistemas Incus/LXC también dependen en gran medida del desplazamiento de UID/GID y de las ideas de idmapping.

La tendencia general es clara: los entornos que utilizan user namespaces seriamente suelen ofrecer una respuesta mejor a "¿qué significa realmente root dentro de un contenedor?" que los entornos que no lo hacen.

## Detalles avanzados del mapeo

Cuando un proceso sin privilegios escribe en `uid_map` o `gid_map`, el kernel aplica reglas más estrictas que cuando escribe un proceso padre con privilegios en el namespace padre. Solo se permiten mapeos limitados y, para `gid_map`, normalmente el proceso que escribe debe deshabilitar primero `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Este detalle importa porque explica por qué la configuración de user namespace a veces falla en experimentos rootless y por qué los runtimes necesitan una lógica auxiliar cuidadosa en torno a la delegación de UID/GID.

Otra feature avanzada es el **ID-mapped mount**. En lugar de cambiar la ownership en disco, un ID-mapped mount aplica un mapping de user namespace a un mount, de modo que la ownership aparece traducida a través de esa vista del mount. Esto es especialmente relevante en configuraciones rootless y de runtimes modernos porque permite usar rutas compartidas del host sin realizar operaciones recursivas de `chown`. Desde el punto de vista de la seguridad, esta feature cambia cómo de writable parece un bind mount desde dentro del namespace, aunque no reescribe los metadatos subyacentes del filesystem.

Por último, recuerda que cuando un proceso crea o entra en un nuevo user namespace, recibe un conjunto completo de capabilities **dentro de ese namespace**. Eso no significa que haya obtenido de repente poder global sobre el host. Significa que esas capabilities solo pueden usarse donde el modelo de namespaces y las demás protecciones lo permitan. Esta es la razón por la que `unshare -U` puede hacer posibles de repente operaciones de mounting o operaciones privilegiadas locales al namespace sin hacer que desaparezca directamente el límite de root del host.

## Misconfigurations

La principal debilidad consiste simplemente en no usar user namespaces en entornos donde serían viables. Si root dentro del container se mapea demasiado directamente a root del host, los host mounts writable y las operaciones privilegiadas del kernel se vuelven mucho más peligrosos. Otro problema es forzar el uso compartido del user namespace del host o desactivar el remapping por motivos de compatibilidad sin reconocer cuánto cambia esto el trust boundary.

Los user namespaces también deben considerarse junto con el resto del modelo. Aunque estén activos, una exposición amplia de la API del runtime o una configuración del runtime muy débil todavía puede permitir privilege escalation mediante otras rutas. Pero sin ellos, muchas clases antiguas de breakout se vuelven mucho más fáciles de explotar.

## Abuse

Si el container es rootful sin separación mediante user namespace, un host bind mount writable se vuelve mucho más peligroso porque el proceso podría estar escribiendo realmente como root del host. Las capabilities peligrosas también adquieren mayor relevancia. El attacker ya no necesita luchar tanto contra el límite de traducción porque dicho límite apenas existe.

La presencia o ausencia de user namespace debe comprobarse al principio al evaluar una ruta de container breakout. No responde a todas las preguntas, pero muestra inmediatamente si "root en el container" tiene relevancia directa para el host.

El patrón de abuse más práctico consiste en confirmar el mapping y comprobar inmediatamente si el contenido montado desde el host es writable con privilegios relevantes para el host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Si el archivo se crea como root real del host, el aislamiento del user namespace está efectivamente ausente para esa ruta. En ese punto, los abusos clásicos de archivos del host se vuelven realistas:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Una confirmación más segura en una evaluación en vivo es escribir un marcador inocuo en lugar de modificar archivos críticos:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Estas comprobaciones son importantes porque responden rápidamente a la pregunta real: ¿root dentro de este contenedor se asigna de forma suficientemente cercana a root del host como para que un mount del host con permisos de escritura se convierta inmediatamente en una vía para comprometer el host?

### Ejemplo completo: Recuperar capabilities locales del namespace

Si seccomp permite `unshare` y el entorno permite crear un nuevo user namespace, el proceso puede recuperar un conjunto completo de capabilities dentro de ese nuevo namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Esto no constituye por sí solo un escape del host. La razón por la que importa es que los user namespaces pueden volver a habilitar acciones privilegiadas locales al namespace que posteriormente se combinan con montajes débiles, kernels vulnerables o superficies de runtime expuestas de forma incorrecta.

## Comprobaciones

Estos comandos están destinados a responder la pregunta más importante de esta página: ¿a qué se mapea root dentro de este contenedor en el host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Qué resulta interesante aquí:

- Si el proceso tiene UID 0 y los mapas muestran una asignación directa o muy cercana a host root, el contenedor es mucho más peligroso.
- Si root se asigna a un rango de host sin privilegios, esa es una base mucho más segura y normalmente indica un aislamiento real mediante user namespace.
- Los archivos de asignación son más valiosos que `id` por sí solo, porque `id` únicamente muestra la identidad local del namespace.

Si el workload se ejecuta como UID 0 y la asignación muestra que esto corresponde estrechamente a host root, debes interpretar de forma mucho más estricta el resto de los privilegios del contenedor.
{{#include ../../../../../banners/hacktricks-training.md}}
