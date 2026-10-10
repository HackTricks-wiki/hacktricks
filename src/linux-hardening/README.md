# Fortalecimiento de Linux

{{#include ../banners/hacktricks-training.md}}

Usa esta sección para investigar hosts Linux, comprender los límites de privilegios y revisar los controles que restringen el acceso local. Empieza con los [conceptos básicos de Linux](linux-basics/README.md) y la [lista de comprobación de privilege escalation](main-system-information/linux-privilege-escalation-checklist.md) para realizar una evaluación general; después, consulta el tema pertinente a continuación.

- [Conceptos básicos de Linux](linux-basics/README.md): metodología de privilege escalation, comandos útiles, variables de entorno y métodos para eludir restricciones.
- [Información principal del sistema](main-system-information/README.md): kernel, módulos, sudo, comportamiento del sistema de archivos, jails y la lista de comprobación de privilege escalation.
- [Información de usuarios](user-information/README.md): identidades y grupos de Linux, reenvío del agente SSH e integración con Active Directory.
- [Archivos y permisos interesantes](interesting-files-permissions/README.md): rutas con permisos de escritura, capabilities, comportamiento de SUID, NFS, expansión de comodines y SELinux.
- [Información de red](network-information/README.md): servicios locales, sockets y ejemplos de explotación relacionados con la red.
- [Información de software](software-information/README.md): módulos de autenticación y superficies de ataque específicas de aplicaciones.
- [Procesos, crontab, systemd y D-Bus](processes-crontab-systemd-dbus/README.md): ejecución programada y comunicación entre procesos.
- [Contenedores y namespaces](containers-namespaces/README.md): runtimes, límites de aislamiento y hardening de contenedores.
- [Post-exploitation](post-exploitation/README.md): búsqueda de credenciales, persistencia y técnicas posteriores a la intrusión en el host.
{{#include ../banners/hacktricks-training.md}}
