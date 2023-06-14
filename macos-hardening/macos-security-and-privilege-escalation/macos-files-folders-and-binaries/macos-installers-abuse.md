## Información básica de Pkg

Un paquete de instalación de macOS (también conocido como archivo `.pkg`) es un formato de archivo utilizado por macOS para **distribuir software**. Estos archivos son como una **caja que contiene todo lo que un software** necesita para instalarse y ejecutarse correctamente.

El archivo del paquete en sí es un archivo que contiene una **jerarquía de archivos y directorios que se instalarán en el equipo de destino**. También puede incluir **scripts** para realizar tareas antes y después de la instalación, como configurar archivos de configuración o limpiar versiones antiguas del software.

### Jerarquía

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt=""><figcaption></figcaption></figure>

* **Distribución (xml)**: Personalizaciones (título, texto de bienvenida...) y comprobaciones de script/instalación
* **PackageInfo (xml)**: Información, requisitos de instalación, ubicación de instalación, rutas a scripts para ejecutar
* **Lista de materiales (bom)**: Lista de archivos para instalar, actualizar o eliminar con permisos de archivo
* **Carga útil (archivo CPIO comprimido con gzip)**: Archivos para instalar en la `ubicación de instalación` de PackageInfo
* **Scripts (archivo CPIO comprimido con gzip)**: Scripts de pre y post instalación y más recursos extraídos a un directorio temporal para su ejecución.

### Descompresión
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
## Información básica de DMG

Los archivos DMG, o imágenes de disco de Apple, son un formato de archivo utilizado por el sistema operativo macOS de Apple para imágenes de disco. Un archivo DMG es esencialmente una **imagen de disco montable** (contiene su propio sistema de archivos) que contiene datos de bloque sin procesar, generalmente comprimidos y a veces cifrados. Cuando abres un archivo DMG, macOS lo **monta como si fuera un disco físico**, lo que te permite acceder a su contenido.

### Jerarquía

<figure><img src="../../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

La jerarquía de un archivo DMG puede ser diferente según el contenido. Sin embargo, para los DMG de aplicaciones, generalmente sigue esta estructura:

* Nivel superior: este es la raíz de la imagen del disco. A menudo contiene la aplicación y posiblemente un enlace a la carpeta de Aplicaciones.
  * Aplicación (.app): esta es la aplicación real. En macOS, una aplicación es típicamente un paquete que contiene muchos archivos y carpetas individuales que conforman la aplicación.
  * Enlace de Aplicaciones: este es un acceso directo a la carpeta de Aplicaciones en macOS. El propósito de esto es hacer que sea fácil para ti instalar la aplicación. Puedes arrastrar el archivo .app a este acceso directo para instalar la aplicación.

## Escalada de privilegios a través del abuso de pkg

### Ejecución desde directorios públicos

Si un script de pre o post instalación se está ejecutando, por ejemplo, desde **`/var/tmp/Installerutil`**, un atacante podría controlar ese script para escalar privilegios cada vez que se ejecute. Otro ejemplo similar:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt=""><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Esta es una [función pública](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que varios instaladores y actualizadores llamarán para **ejecutar algo como root**. Esta función acepta la **ruta** del **archivo** a **ejecutar** como parámetro, sin embargo, si un atacante pudiera **modificar** este archivo, podría **abusar** de su ejecución con root para **escalar privilegios**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Para obtener más información, consulte esta charla: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Ejecución mediante montaje

Si un instalador escribe en `/tmp/fixedname/bla/bla`, es posible **crear un montaje** sobre `/tmp/fixedname` sin propietarios para que pueda **modificar cualquier archivo durante la instalación** para abusar del proceso de instalación.

Un ejemplo de esto es **CVE-2021-26089** que logró **sobrescribir un script periódico** para obtener la ejecución como root. Para obtener más información, consulte la charla: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg como malware

### Carga útil vacía

Es posible generar un archivo **`.pkg`** con **scripts de pre y post-instalación** sin ninguna carga útil.

### JS en xml de distribución

Es posible agregar etiquetas **`<script>`** en el archivo **xml de distribución** del paquete y ese código se ejecutará y puede **ejecutar comandos** usando **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Referencias

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabaja en una **empresa de ciberseguridad**? ¿Quiere ver su **empresa anunciada en HackTricks**? ¿O quiere tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFT exclusivos**](https://opensea.io/collection/the-peass-family)
* Obtenga el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únase al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegramas**](https://t.me/peass) o **sígame** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparta sus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
