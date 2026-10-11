# Indicadores de escalada mediante sesiones y servicios de disco en SUSE

{{#include ../../banners/hacktricks-training.md}}

## Autorización de sesiones SSH mediante PAM

CVE-2025-6018 afectó a configuraciones de PAM de SUSE 15 en las que una pila de autenticación SSH cargaba `pam_env` antes de que la pila de sesión cargara `pam_systemd`. Cuando `pam_env` leía el archivo `.pam_environment` de un usuario, este podía proporcionar valores `XDG_SEAT` y `XDG_VTNR` que hacían que Polkit considerara la sesión SSH como físicamente activa. Entonces, una acción `allow_active=yes` podía quedar disponible para un usuario remoto. Esto modifica la autorización de la sesión; no garantiza por sí solo el acceso a root. SUSE corrigió el comportamiento predeterminado de lectura del entorno del usuario en `pam` y la ubicación del módulo generada por `pam-config`.<sup>[[1]](#references)[[2]](#references)</sup>

Inspecciona la cadena de inclusión efectiva de `/etc/pam.d/sshd`, el orden de `pam_env.so` y `pam_systemd.so`, y cualquier opción explícita `user_readenv=1`. Un paquete `pam` con el parche cambia el valor predeterminado, pero una opción explícita puede seguir solicitando la lectura del entorno del usuario. Un paquete `pam-config` más reciente no demuestra que se haya regenerado una pila PAM modificada localmente o desactualizada. Comprueba conjuntamente la versión del paquete del proveedor y la configuración real.<sup>[[1]](#references)[[2]](#references)</sup>

## Ruta del servicio de disco para usuarios activos

CVE-2025-6019 era una ruta de escalada en `libblockdev` utilizada a través de `udisks2`: durante un cambio de tamaño de XFS, un sistema de archivos proporcionado por un atacante podía montarse temporalmente sin la restricción `nosuid` esperada. Esta ruta requiere un servicio UDisks D-Bus utilizable, compatibilidad con el cambio de tamaño de XFS, una acción de Polkit relevante disponible para el usuario y una versión afectada del paquete de la biblioteca. CVE-2025-6018 es una forma de obtener una sesión de usuario activo, pero un usuario que ya esté activo puede acceder a la ruta del servicio de disco de forma independiente.<sup>[[3]](#references)</sup>

Para una revisión pasiva, comprueba los metadatos del servicio UDisks, la política `org.freedesktop.udisks2.modify-device`, `xfs_growfs` y el paquete `libbd_fs2` instalado. SUSE indica que la versión `2.26-150400.3.5.1` de `libbd_fs2` corrige el problema en openSUSE Leap 15.6; la versión corregida exacta depende del producto. La presencia de la política y del paquete son solo indicios, no una prueba de que un usuario pueda montar o cambiar el tamaño de un dispositivo. Evita modificar los montajes o invocar métodos D-Bus durante la enumeración.<sup>[[3]](#references)</sup>

## References

- [1] [Aviso de SUSE para CVE-2025-6018](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [Actualización de seguridad de SUSE para pam-config](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [Aviso de SUSE para CVE-2025-6019](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
