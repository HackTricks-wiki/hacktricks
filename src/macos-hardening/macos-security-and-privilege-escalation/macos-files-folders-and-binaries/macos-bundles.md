# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Información Básica

Los bundles en macOS sirven como contenedores para una variedad de recursos, incluyendo aplicaciones, bibliotecas y otros archivos necesarios, haciéndolos aparecer como objetos únicos en Finder, como los familiares archivos `*.app`. El bundle más comúnmente encontrado es el bundle `.app`, aunque otros tipos como `.framework`, `.systemextension` y `.kext` también son prevalentes.

### Componentes Esenciales de un Bundle

Dentro de un bundle, particularmente en el directorio `<application>.app/Contents/`, se albergan una variedad de recursos importantes:

- **\_CodeSignature**: Este directorio almacena detalles de firma de código vitales para verificar la integridad de la aplicación. Puedes inspeccionar la información de firma de código usando comandos como: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
- **MacOS**: Contiene el binario ejecutable de la aplicación que se ejecuta al interactuar el usuario.
- **Resources**: Un repositorio para los componentes de la interfaz de usuario de la aplicación, incluyendo imágenes, documentos y descripciones de la interfaz (archivos nib/xib).
- **Info.plist**: Actúa como el archivo de configuración principal de la aplicación, crucial para que el sistema reconozca e interactúe con la aplicación de manera adecuada.

#### Claves Importantes en Info.plist

El archivo `Info.plist` es una piedra angular para la configuración de la aplicación, conteniendo claves como:

- **CFBundleExecutable**: Especifica el nombre del archivo ejecutable principal ubicado en el directorio `Contents/MacOS`.
- **CFBundleIdentifier**: Proporciona un identificador global para la aplicación, utilizado extensamente por macOS para la gestión de aplicaciones.
- **LSMinimumSystemVersion**: Indica la versión mínima de macOS requerida para que la aplicación se ejecute.

### Explorando Bundles

Para explorar el contenido de un bundle, como `Safari.app`, se puede usar el siguiente comando: `bash ls -lR /Applications/Safari.app/Contents`

Esta exploración revela directorios como `_CodeSignature`, `MacOS`, `Resources`, y archivos como `Info.plist`, cada uno sirviendo un propósito único desde asegurar la aplicación hasta definir su interfaz de usuario y parámetros operativos.

#### Directorios Adicionales de Bundles

Más allá de los directorios comunes, los bundles también pueden incluir:

- **Frameworks**: Contiene frameworks empaquetados utilizados por la aplicación. Los frameworks son como dylibs con recursos adicionales.
- **PlugIns**: Un directorio para plug-ins y extensiones que mejoran las capacidades de la aplicación.
- **XPCServices**: Contiene servicios XPC utilizados por la aplicación para comunicación fuera de proceso.

Esta estructura asegura que todos los componentes necesarios estén encapsulados dentro del bundle, facilitando un entorno de aplicación modular y seguro.

Para obtener información más detallada sobre las claves de `Info.plist` y sus significados, la documentación para desarrolladores de Apple proporciona recursos extensos: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

{{#include ../../../banners/hacktricks-training.md}}
