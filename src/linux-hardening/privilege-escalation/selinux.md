{{#include ../../banners/hacktricks-training.md}}

# SELinux en Contenedores

[Introducción y ejemplo de la documentación de redhat](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) es un **sistema de etiquetado**. Cada **proceso** y cada objeto del sistema de **archivos** tiene una **etiqueta**. Las políticas de SELinux definen reglas sobre lo que se **permite hacer a una etiqueta de proceso con todas las demás etiquetas** en el sistema.

Los motores de contenedores lanzan **procesos de contenedor con una única etiqueta SELinux confinada**, generalmente `container_t`, y luego establecen el contenedor dentro del contenedor para que esté etiquetado como `container_file_t`. Las reglas de la política de SELinux básicamente dicen que los **procesos `container_t` solo pueden leer/escribir/ejecutar archivos etiquetados como `container_file_t`**. Si un proceso de contenedor escapa del contenedor e intenta escribir en contenido en el host, el núcleo de Linux deniega el acceso y solo permite que el proceso de contenedor escriba en contenido etiquetado como `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# Usuarios de SELinux

Hay usuarios de SELinux además de los usuarios regulares de Linux. Los usuarios de SELinux son parte de una política de SELinux. Cada usuario de Linux está mapeado a un usuario de SELinux como parte de la política. Esto permite que los usuarios de Linux hereden las restricciones y las reglas y mecanismos de seguridad impuestos a los usuarios de SELinux.

{{#include ../../banners/hacktricks-training.md}}
