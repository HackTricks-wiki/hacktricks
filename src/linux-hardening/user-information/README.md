# Información de usuario

{{#include ../../banners/hacktricks-training.md}}

La identidad del usuario, la pertenencia a grupos y las credenciales delegadas determinan a qué recursos puede acceder un proceso. Comprueba la identidad efectiva y los grupos suplementarios antes de investigar las rutas de acceso que se indican a continuación.

- [Usuarios, sesiones y artefactos de credenciales](user-and-session-triage.md) abarca la enumeración de cuentas, los inicios de sesión activos, los artefactos de SSH y del shell, y los almacenes de credenciales.
- [UID real, efectivo y guardado](euid-ruid-suid.md) explica los cambios de identidad relacionados con los programas SUID y la ejecución de procesos.
- [Grupos interesantes para la escalada de privilegios en Linux](interesting-groups-linux-pe/README.md) abarca el acceso concedido por grupos, incluido LXD/LXC.
- [Explotación del agente de reenvío de SSH](ssh-forward-agent-exploitation.md) examina los riesgos de las credenciales de SSH reenviadas.
- [Active Directory en Linux](linux-active-directory.md) abarca los hosts unidos a un entorno AD.

{{#include ../../banners/hacktricks-training.md}}
