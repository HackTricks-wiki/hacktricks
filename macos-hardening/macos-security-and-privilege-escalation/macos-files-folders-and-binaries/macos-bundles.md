# Bundles de macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información básica

Básicamente, un bundle es una **estructura de directorios** dentro del sistema de archivos. Curiosamente, por defecto este directorio **parece un objeto único en Finder**.

El bundle más **común** que encontraremos es el **bundle `.app`**, pero muchos otros ejecutables también se empaquetan como bundles, como **`.framework`** y **`.systemextension`** o **`.kext`**.

Los tipos de recursos contenidos en un bundle pueden consistir en aplicaciones, bibliotecas, imágenes, documentación, archivos de encabezado, etc. Todos estos archivos están dentro de `<aplicación>.app/Contents/`.
```bash
ls -lR /Applications/Safari.app/Contents
```
*   `Contents/_CodeSignature`

    Contiene información de **firmado de código** sobre la aplicación (es decir, hashes, etc.).
*   `Contents/MacOS`

    Contiene el **binario de la aplicación** (que se ejecuta cuando el usuario hace doble clic en el icono de la aplicación en la interfaz de usuario).
*   `Contents/Resources`

    Contiene **elementos de la interfaz de usuario de la aplicación**, como imágenes, documentos y archivos nib/xib (que describen varias interfaces de usuario).
* `Contents/Info.plist`\
  El "archivo de configuración principal" de la aplicación. Apple señala que "el sistema depende de la presencia de este archivo para identificar información relevante sobre la aplicación y cualquier archivo relacionado".
  * Los **archivos Plist** contienen información de configuración. Puede encontrar información sobre el significado de las claves plist en [https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)
  *   Las parejas que pueden ser de interés al analizar una aplicación incluyen:\\

      * **CFBundleExecutable**

      Contiene el **nombre del binario de la aplicación** (que se encuentra en Contents/MacOS).

      * **CFBundleIdentifier**

      Contiene el identificador de paquete de la aplicación (a menudo utilizado por el sistema para **identificar globalmente** la aplicación).

      * **LSMinimumSystemVersion**

      Contiene la **versión más antigua** de **macOS** con la que es compatible la aplicación.
