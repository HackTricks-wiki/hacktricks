<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


# SELinux en Contenedores

[Introducción y ejemplo de la documentación de redhat](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) es un **sistema de etiquetado**. Cada **proceso** y cada **objeto del sistema de archivos** tiene una **etiqueta**. Las políticas de SELinux definen reglas sobre lo que un **proceso con etiqueta** tiene permitido hacer con todas las demás **etiquetas** en el sistema.

Los motores de contenedores lanzan **procesos de contenedores con una sola etiqueta SELinux confinada**, generalmente `container_t`, y luego establecen que el contenedor dentro del contenedor tenga la etiqueta `container_file_t`. Las reglas de la política de SELinux básicamente dicen que los **procesos `container_t` solo pueden leer/escribir/ejecutar archivos etiquetados como `container_file_t`**. Si un proceso de contenedor escapa del contenedor e intenta escribir en el contenido del host, el kernel de Linux deniega el acceso y solo permite que el proceso de contenedor escriba en el contenido etiquetado como `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# Usuarios SELinux

Existen usuarios SELinux además de los usuarios regulares de Linux. Los usuarios SELinux forman parte de una política SELinux. Cada usuario de Linux se asigna a un usuario SELinux como parte de la política. Esto permite a los usuarios de Linux heredar las restricciones y reglas de seguridad y mecanismos aplicados a los usuarios SELinux.
