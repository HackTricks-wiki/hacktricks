# Paquetes de macOS

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

Los paquetes en macOS sirven como contenedores para una variedad de recursos que incluyen aplicaciones, bibliotecas y otros archivos necesarios, haciéndolos aparecer como objetos únicos en Finder, como los familiares archivos `*.app`. El paquete más comúnmente encontrado es el paquete `.app`, aunque otros tipos como `.framework`, `.systemextension` y `.kext` también son prevalentes.

### Componentes Esenciales de un Paquete

Dentro de un paquete, particularmente dentro del directorio `<aplicación>.app/Contents/`, se albergan una variedad de recursos importantes:

- **_CodeSignature**: Este directorio almacena detalles de firma de código vitales para verificar la integridad de la aplicación. Puedes inspeccionar la información de firma de código usando comandos como:
%%%bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
%%%
- **MacOS**: Contiene el binario ejecutable de la aplicación que se ejecuta al interactuar con el usuario.
- **Resources**: Un repositorio para los componentes de la interfaz de usuario de la aplicación, incluidas imágenes, documentos y descripciones de interfaz (archivos nib/xib).
- **Info.plist**: Actúa como el archivo de configuración principal de la aplicación, crucial para que el sistema reconozca e interactúe con la aplicación de manera apropiada.

#### Claves Importantes en Info.plist

El archivo `Info.plist` es fundamental para la configuración de la aplicación, contiene claves como:

- **CFBundleExecutable**: Especifica el nombre del archivo ejecutable principal ubicado en el directorio `Contents/MacOS`.
- **CFBundleIdentifier**: Proporciona un identificador global para la aplicación, utilizado extensamente por macOS para la gestión de aplicaciones.
- **LSMinimumSystemVersion**: Indica la versión mínima de macOS requerida para que la aplicación se ejecute.

### Explorando Paquetes

Para explorar el contenido de un paquete, como `Safari.app`, se puede usar el siguiente comando:
%%%bash
ls -lR /Applications/Safari.app/Contents
%%%

Esta exploración revela directorios como `_CodeSignature`, `MacOS`, `Resources`, y archivos como `Info.plist`, cada uno sirviendo un propósito único desde asegurar la aplicación hasta definir su interfaz de usuario y parámetros operativos.

#### Directorios Adicionales de Paquetes

Además de los directorios comunes, los paquetes también pueden incluir:

- **Frameworks**: Contiene frameworks empaquetados utilizados por la aplicación.
- **PlugIns**: Un directorio para complementos y extensiones que mejoran las capacidades de la aplicación.
- **XPCServices**: Contiene servicios XPC utilizados por la aplicación para comunicación fuera del proceso.

Esta estructura asegura que todos los componentes necesarios estén encapsulados dentro del paquete, facilitando un entorno de aplicación modular y seguro.

Para obtener información más detallada sobre las claves de `Info.plist` y sus significados, la documentación de desarrolladores de Apple proporciona recursos extensos: [Referencia de Claves Info.plist de Apple](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
