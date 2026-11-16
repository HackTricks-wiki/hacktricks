# Endurecimiento de Linux

{{#include ../banners/hacktricks-training.md}}

Usa esta sección para investigar hosts Linux, comprender los límites de privilegios y revisar los controles que restringen el acceso local. Empieza con los [conceptos básicos de Linux](linux-basics/README.md) y la [lista de verificación de escalada de privilegios](main-system-information/linux-privilege-escalation-checklist.md) para una evaluación general y, después, consulta el tema pertinente a continuación.

- [Conceptos básicos de Linux](linux-basics/README.md): metodología de escalada de privilegios, comandos útiles, variables de entorno y evasiones de restricciones.
- [Información principal del sistema](main-system-information/README.md): kernel, módulos, sudo, comportamiento del sistema de archivos, jails y la lista de verificación de escalada.
- [Información de usuarios](user-information/README.md): identidades de Linux, grupos, reenvío del agente SSH e integración con Active Directory.
- [Archivos interesantes y permisos](interesting-files-permissions/README.md): rutas con permisos de escritura, capabilities, comportamiento de SUID, NFS, expansión de comodines y SELinux.
- [Información de red](network-information/README.md): servicios locales, sockets y ejemplos de explotación relacionados con la red.
- [Información de software](software-information/README.md): módulos de autenticación y superficies de ataque específicas de aplicaciones.
- [Procesos, crontab, systemd y D-Bus](processes-crontab-systemd-dbus/README.md): ejecución programada y comunicación entre procesos.
- [Contenedores y namespaces](containers-namespaces/README.md): runtimes, límites de aislamiento y hardening de contenedores.
- [Abuso de archivos de control de políticas de AppArmor](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive): evalúa si un helper privilegiado puede escribir en un archivo de control de AppArmor abierto por un usuario local.
- [Post-exploitation](post-exploitation/README.md): descubrimiento de credenciales, persistencia y técnicas de seguimiento a nivel de host.

En kernels afectados, un usuario sin privilegios puede abrir un archivo de control de políticas de AppArmor en securityfs, aunque se deniegue una escritura directa. Si un helper privilegiado hereda ese archivo como stdout, su escritura puede modificar la política cargada; esta es una vía de ataque local distinta de simplemente encontrar un perfil de contenedor débil. Antes de probarla, comprueba las correcciones del kernel y del helper proporcionadas por el proveedor.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Aviso técnico de Qualys sobre CrackArmor](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Base de conocimientos sobre la vulnerabilidad CrackArmor de Ubuntu](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
