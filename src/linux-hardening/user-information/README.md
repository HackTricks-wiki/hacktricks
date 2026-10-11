# Información del usuario

{{#include ../../banners/hacktricks-training.md}}

La identidad del usuario, la pertenencia a grupos y las credenciales delegadas determinan a qué recursos puede acceder un proceso. Comprueba la identidad efectiva y los grupos suplementarios antes de investigar las rutas de acceso siguientes.

- [Usuarios, sesiones y artefactos de credenciales](user-and-session-triage.md) cubre la enumeración de cuentas, los inicios de sesión activos, los artefactos de SSH y del shell, y los almacenes de credenciales.
- [UID de usuario real, efectivo y guardado](euid-ruid-suid.md) explica los cambios de identidad relacionados con los programas SUID y la ejecución de procesos.
- [Grupos interesantes para la escalada de privilegios en Linux](interesting-groups-linux-pe/README.md) cubre el acceso concedido por grupos, incluido LXD/LXC.
- [Explotación del agente de reenvío de SSH](ssh-forward-agent-exploitation.md) examina los riesgos de las credenciales SSH reenviadas.
- [Active Directory en Linux](linux-active-directory.md) cubre los hosts unidos a un entorno de AD.

{{#include ../../banners/hacktricks-training.md}}
