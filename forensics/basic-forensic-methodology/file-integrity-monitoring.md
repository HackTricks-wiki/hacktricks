<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Línea Base

Una línea base consiste en tomar una instantánea de ciertas partes de un sistema para **compararla con un estado futuro y resaltar cambios**.

Por ejemplo, puedes calcular y almacenar el hash de cada archivo del sistema de archivos para poder determinar qué archivos fueron modificados.\
Esto también se puede hacer con las cuentas de usuario creadas, procesos en ejecución, servicios en funcionamiento y cualquier otra cosa que no debería cambiar mucho, o en absoluto.

## Monitoreo de Integridad de Archivos

El monitoreo de integridad de archivos es una de las técnicas más poderosas utilizadas para asegurar infraestructuras de TI y datos empresariales contra una amplia variedad de amenazas conocidas y desconocidas.\
El objetivo es generar una **línea base de todos los archivos** que deseas monitorear y luego **periódicamente** **verificar** esos archivos para posibles **cambios** (en el contenido, atributo, metadatos, etc.).

1\. **Comparación de línea base,** donde uno o más atributos del archivo serán capturados o calculados y almacenados como una línea base que se puede comparar en el futuro. Esto puede ser tan simple como la fecha y hora del archivo, sin embargo, dado que estos datos pueden ser fácilmente falsificados, se suele utilizar un enfoque más confiable. Esto puede incluir evaluar periódicamente el checksum criptográfico de un archivo monitoreado, (por ejemplo, utilizando el algoritmo de hashing MD5 o SHA-2) y luego comparar el resultado con el checksum calculado previamente.

2\. **Notificación de cambio en tiempo real**, que generalmente se implementa dentro o como una extensión del kernel del sistema operativo que marcará cuando se accede o modifica un archivo.

## Herramientas

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

# Referencias

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
