{{#include ../../banners/hacktricks-training.md}}

# Línea base

Una línea base consiste en tomar una instantánea de ciertas partes de un sistema para **compararla con un estado futuro para resaltar cambios**.

Por ejemplo, puedes calcular y almacenar el hash de cada archivo del sistema de archivos para poder averiguar qué archivos fueron modificados.\
Esto también se puede hacer con las cuentas de usuario creadas, procesos en ejecución, servicios en ejecución y cualquier otra cosa que no debería cambiar mucho, o en absoluto.

## Monitoreo de Integridad de Archivos

El Monitoreo de Integridad de Archivos (FIM) es una técnica de seguridad crítica que protege los entornos de TI y los datos al rastrear cambios en los archivos. Implica dos pasos clave:

1. **Comparación de Línea Base:** Establecer una línea base utilizando atributos de archivo o sumas de verificación criptográficas (como MD5 o SHA-2) para comparaciones futuras y detectar modificaciones.
2. **Notificación de Cambio en Tiempo Real:** Recibir alertas instantáneas cuando los archivos son accedidos o alterados, típicamente a través de extensiones del kernel del sistema operativo.

## Herramientas

- [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
- [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## Referencias

- [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)

{{#include ../../banners/hacktricks-training.md}}
