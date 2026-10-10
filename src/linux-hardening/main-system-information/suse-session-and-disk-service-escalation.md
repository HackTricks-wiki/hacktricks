# Indicadores de escalada mediante sesiones y servicios de disco en SUSE

{{#include ../../banners/hacktricks-training.md}}

## Autorización de sesiones SSH mediante PAM

CVE-2025-6018 afectó a configuraciones de PAM de SUSE 15 en las que una pila de autenticación SSH cargaba `pam_env` antes de que la pila de sesión cargara `pam_systemd`. Cuando `pam_env` leía el archivo `.pam_environment` de un usuario, este podía proporcionar valores de `XDG_SEAT` y `XDG_VTNR` que hacían que una sesión SSH pareciera físicamente activa para Polkit. Así, una acción `allow_active=yes` podía quedar disponible para un usuario remoto. Esto modifica la autorización de la sesión; por sí solo, no garantiza el acceso root. SUSE corrigió el comportamiento predeterminado del entorno de usuario en `pam` y la ubicación del módulo generada por `pam-config`.<sup>[[1]](#references)[[2]](#references)</sup>

Inspecciona la cadena efectiva de inclusiones de `/etc/pam.d/sshd`, el orden de `pam_env.so` y `pam_systemd.so`, y cualquier opción explícita `user_readenv=1`. Un paquete `pam` con el parche cambia el valor predeterminado, pero una opción explícita aún puede solicitar la lectura del entorno del usuario. Un paquete `pam-config` más reciente no demuestra que se haya regenerado una pila PAM modificada localmente o desactualizada. Comprueba tanto la versión del paquete del proveedor como la configuración real.<sup>[[1]](#references)[[2]](#references)</sup>

## Ruta del servicio de disco para usuarios activos

CVE-2025-6019 era una ruta de escalada en `libblockdev` utilizada a través de `udisks2`: durante un redimensionamiento de XFS, un sistema de archivos proporcionado por un atacante podía montarse temporalmente sin la restricción `nosuid` esperada. La ruta requiere un servicio UDisks D-Bus utilizable, compatibilidad con el redimensionamiento de XFS, una acción Polkit pertinente disponible para el usuario y un paquete de biblioteca afectado. CVE-2025-6018 es una forma de obtener una sesión de usuario activo, pero un usuario que ya está activo puede acceder a la ruta del servicio de disco de forma independiente.<sup>[[3]](#references)</sup>

Para una revisión pasiva, comprueba los metadatos del servicio UDisks, la política `org.freedesktop.udisks2.modify-device`, `xfs_growfs` y el paquete `libbd_fs2` instalado. SUSE indica que la versión `2.26-150400.3.5.1` de `libbd_fs2` corrige el problema en openSUSE Leap 15.6; la versión exacta que lo corrige depende del producto. La presencia de la política y del paquete son solo indicios, no prueban que un usuario pueda montar o redimensionar un dispositivo. Evita cambiar los montajes o invocar métodos D-Bus durante la enumeración.<sup>[[3]](#references)</sup>

## References

- [1] [Aviso de SUSE sobre CVE-2025-6018](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [Actualización de seguridad de SUSE para pam-config](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [Aviso de SUSE sobre CVE-2025-6019](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
