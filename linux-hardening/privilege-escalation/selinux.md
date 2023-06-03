# SELinux en Contenedores

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) es un **sistema de etiquetado**. Cada **proceso** y cada **objeto del sistema de archivos** tiene una **etiqueta**. Las políticas de SELinux definen reglas sobre lo que una **etiqueta de proceso puede hacer con todas las demás etiquetas** en el sistema.

Los motores de contenedores lanzan **procesos de contenedor con una sola etiqueta SELinux confinada**, generalmente `container_t`, y luego establecen que el contenedor dentro del contenedor tenga la etiqueta `container_file_t`. Las reglas de la política de SELinux básicamente dicen que los **procesos `container_t` solo pueden leer/escribir/ejecutar archivos etiquetados como `container_file_t`**. Si un proceso de contenedor escapa del contenedor e intenta escribir en el contenido del host, el kernel de Linux deniega el acceso y solo permite que el proceso de contenedor escriba en el contenido etiquetado como `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# Usuarios SELinux

Además de los usuarios regulares de Linux, existen usuarios SELinux. Los usuarios SELinux forman parte de una política SELinux. Cada usuario de Linux se asigna a un usuario SELinux como parte de la política. Esto permite que los usuarios de Linux hereden las restricciones y reglas de seguridad y mecanismos aplicados a los usuarios SELinux.
