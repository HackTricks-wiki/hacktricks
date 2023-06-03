# Baseline

Una línea base consiste en tomar una instantánea de ciertas partes de un sistema para **compararla con un estado futuro y resaltar los cambios**.

Por ejemplo, se pueden calcular y almacenar los hashes de cada archivo del sistema de archivos para poder averiguar qué archivos se modificaron.\
Esto también se puede hacer con las cuentas de usuario creadas, los procesos en ejecución, los servicios en ejecución y cualquier otra cosa que no debería cambiar mucho, o en absoluto.

## Monitoreo de integridad de archivos

El monitoreo de integridad de archivos es una de las técnicas más poderosas utilizadas para asegurar las infraestructuras de TI y los datos comerciales contra una amplia variedad de amenazas conocidas y desconocidas.\
El objetivo es generar una **línea base de todos los archivos** que se desean monitorear y luego **verificar periódicamente** esos archivos en busca de posibles **cambios** (en el contenido, atributo, metadatos, etc.).

1\. **Comparación de línea base**, en la que se capturará o calculará uno o más atributos de archivo y se almacenarán como una línea base que se puede comparar en el futuro. Esto puede ser tan simple como la hora y la fecha del archivo, sin embargo, dado que estos datos se pueden falsificar fácilmente, se utiliza un enfoque más confiable. Esto puede incluir evaluar periódicamente el checksum criptográfico de un archivo monitoreado (por ejemplo, usando el algoritmo de hash MD5 o SHA-2) y luego comparar el resultado con el checksum calculado previamente.

2\. **Notificación de cambio en tiempo real**, que generalmente se implementa dentro o como una extensión del kernel del sistema operativo que señalará cuando se acceda o modifique un archivo.

## Herramientas

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

# Referencias

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
