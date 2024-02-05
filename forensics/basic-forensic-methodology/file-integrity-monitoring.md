<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Línea base

Una línea base consiste en tomar una instantánea de ciertas partes de un sistema para **compararla con un estado futuro y resaltar los cambios**.

Por ejemplo, puedes calcular y almacenar el hash de cada archivo del sistema de archivos para poder averiguar qué archivos se modificaron.\
Esto también se puede hacer con las cuentas de usuario creadas, procesos en ejecución, servicios en ejecución y cualquier otra cosa que no debería cambiar mucho, o en absoluto.

## Monitoreo de Integridad de Archivos

El monitoreo de integridad de archivos es una de las técnicas más poderosas utilizadas para asegurar las infraestructuras de TI y los datos comerciales contra una amplia variedad de amenazas tanto conocidas como desconocidas.\
El objetivo es generar una **línea base de todos los archivos** que deseas monitorear y luego **verificar periódicamente** esos archivos en busca de posibles **cambios** (en el contenido, atributo, metadatos, etc.).

1\. **Comparación de línea base**, donde se capturará o calculará uno o más atributos de archivo y se almacenarán como una línea base que se puede comparar en el futuro. Esto puede ser tan simple como la hora y la fecha del archivo, sin embargo, dado que estos datos se pueden falsificar fácilmente, típicamente se utiliza un enfoque más confiable. Esto puede incluir evaluar periódicamente el checksum criptográfico de un archivo monitoreado, (por ejemplo, utilizando el algoritmo de hash MD5 o SHA-2) y luego comparar el resultado con el checksum calculado previamente.

2\. **Notificación de cambio en tiempo real**, que generalmente se implementa dentro o como una extensión al núcleo del sistema operativo que señalará cuando se accede o modifica un archivo.

## Herramientas

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

# Referencias

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
