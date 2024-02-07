<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


# Línea base

Una línea base consiste en tomar una instantánea de ciertas partes de un sistema para **compararla con un estado futuro y resaltar cambios**.

Por ejemplo, puedes calcular y almacenar el hash de cada archivo del sistema de archivos para poder averiguar qué archivos fueron modificados.\
Esto también se puede hacer con las cuentas de usuario creadas, procesos en ejecución, servicios en ejecución y cualquier otra cosa que no debería cambiar mucho, o en absoluto.

## Monitoreo de Integridad de Archivos

El Monitoreo de Integridad de Archivos (FIM) es una técnica de seguridad crítica que protege los entornos de TI y los datos mediante el seguimiento de cambios en los archivos. Involucra dos pasos clave:

1. **Comparación de Línea Base:** Establecer una línea base utilizando atributos de archivo o sumas de verificación criptográficas (como MD5 o SHA-2) para comparaciones futuras y detectar modificaciones.
2. **Notificación de Cambios en Tiempo Real:** Recibir alertas instantáneas cuando se acceden o modifican archivos, típicamente a través de extensiones del kernel del sistema operativo.

## Herramientas

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

# Referencias

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


<details>
