# Archivos interesantes y permisos

{{#include ../../banners/hacktricks-training.md}}

La propiedad de los archivos, el acceso de escritura, las opciones de montaje y los privilegios de ejecución pueden cambiar el alcance efectivo de un usuario local. Empieza por identificar el archivo o la ruta de ejecución objetivo y, luego, consulta la página correspondiente:

- [SUID, SGID, ACLs y archivos sensibles](suid-sgid-and-acl-triage.md) ofrece un flujo de trabajo inicial para los privilegios de ejecución y los permisos de acceso ocultos.
- [Escritura arbitraria de archivos como root](write-to-root.md) describe cómo convertir las escrituras en rutas privilegiadas en una escalada de privilegios.
- [Capacidades de Linux](linux-capabilities.md) explica las capacidades por proceso y por archivo.
- [Abuso de bibliotecas compartidas SUID y del linker](suid-shared-library-and-linker-abuse.md) aborda la carga dinámica en torno a binarios privilegiados.
- [Ejemplo de escalada de privilegios mediante `ld.so`](ld.so.conf-example.md) analiza un caso de configuración del linker.
- [Configuración incorrecta de NFS con `no_root_squash` y `no_all_squash`](nfs-no_root_squash-misconfiguration-pe.md) aborda la asignación de identidades en sistemas de archivos remotos.
- [Trucos con comodines](wildcards-spare-tricks.md) aborda la expansión de argumentos en comandos privilegiados.
- [SELinux](selinux.md) explica la aplicación de políticas y los pasos de investigación pertinentes.
{{#include ../../banners/hacktricks-training.md}}
