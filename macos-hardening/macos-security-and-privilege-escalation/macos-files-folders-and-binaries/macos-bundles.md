# Paquetes macOS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

Básicamente, un paquete es una **estructura de directorio** dentro del sistema de archivos. Curiosamente, por defecto este directorio **parece un objeto único en Finder**.&#x20;

El paquete **común** que encontraremos con frecuencia es el paquete **`.app`**, pero muchos otros ejecutables también están empaquetados como paquetes, tales como **`.framework`** y **`.systemextension`** o **`.kext`**.

Los tipos de recursos contenidos dentro de un paquete pueden consistir en aplicaciones, bibliotecas, imágenes, documentación, archivos de cabecera, etc. Todos estos archivos están dentro de `<aplicación>.app/Contents/`
```bash
ls -lR /Applications/Safari.app/Contents
```
* `Contents/_CodeSignature` -> Contiene **información de firma de código** sobre la aplicación (es decir, hashes, etc.).
* `openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64`
* `Contents/MacOS` -> Contiene el **binario de la aplicación** (que se ejecuta cuando el usuario hace doble clic en el icono de la aplicación en la UI).
* `Contents/Resources` -> Contiene **elementos de la UI de la aplicación**, como imágenes, documentos y archivos nib/xib (que describen diversas interfaces de usuario).
* `Contents/Info.plist` -> El principal “**archivo de configuración**” de la aplicación. Apple señala que “el sistema depende de la presencia de este archivo para identificar información relevante sobre \[la] aplicación y cualquier archivo relacionado”.
* Los **archivos Plist** contienen información de configuración. Puedes encontrar información sobre el significado de las claves plist en [https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)
*   Pares que pueden ser de interés al analizar una aplicación incluyen:\\

* **CFBundleExecutable**

Contiene el **nombre del binario de la aplicación** (encontrado en Contents/MacOS).

* **CFBundleIdentifier**

Contiene el identificador de paquete de la aplicación (a menudo utilizado por el sistema para **identificar globalmente** la aplicación).

* **LSMinimumSystemVersion**

Contiene la **versión más antigua** de **macOS** con la que la aplicación es compatible.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en github.

</details>
