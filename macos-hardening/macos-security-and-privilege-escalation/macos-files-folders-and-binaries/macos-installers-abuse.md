# Abuso de Instaladores en macOS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica de Pkg

Un **paquete instalador** de macOS (también conocido como archivo `.pkg`) es un formato de archivo utilizado por macOS para **distribuir software**. Estos archivos son como una **caja que contiene todo lo que un software** necesita para instalarse y funcionar correctamente.

El archivo del paquete en sí es un archivo que contiene una **jerarquía de archivos y directorios que se instalarán en el** ordenador objetivo. También puede incluir **scripts** para realizar tareas antes y después de la instalación, como configurar archivos de configuración o limpiar versiones antiguas del software.

### Jerarquía

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt=""><figcaption></figcaption></figure>

* **Distribución (xml)**: Personalizaciones (título, texto de bienvenida…) y verificaciones de script/instalación
* **PackageInfo (xml)**: Información, requisitos de instalación, ubicación de instalación, rutas a scripts para ejecutar
* **Lista de materiales (bom)**: Lista de archivos para instalar, actualizar o eliminar con permisos de archivo
* **Carga útil (archivo CPIO comprimido con gzip)**: Archivos para instalar en la `ubicación de instalación` desde PackageInfo
* **Scripts (archivo CPIO comprimido con gzip)**: Scripts de preinstalación y postinstalación y más recursos extraídos a un directorio temporal para su ejecución.

### Descomprimir
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

Los archivos DMG, o Apple Disk Images, son un formato de archivo utilizado por macOS de Apple para imágenes de disco. Un archivo DMG es esencialmente una **imagen de disco montable** (contiene su propio sistema de archivos) que contiene datos de bloques en bruto típicamente comprimidos y a veces encriptados. Cuando abres un archivo DMG, macOS lo **monta como si fuera un disco físico**, permitiéndote acceder a su contenido.

### Jerarquía

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

La jerarquía de un archivo DMG puede ser diferente basada en el contenido. Sin embargo, para DMGs de aplicaciones, usualmente sigue esta estructura:

* Nivel Superior: Esta es la raíz de la imagen de disco. A menudo contiene la aplicación y posiblemente un enlace a la carpeta Aplicaciones.
* Aplicación (.app): Esta es la aplicación real. En macOS, una aplicación es típicamente un paquete que contiene muchos archivos y carpetas individuales que componen la aplicación.
* Enlace a Aplicaciones: Este es un acceso directo a la carpeta Aplicaciones en macOS. El propósito de esto es facilitar la instalación de la aplicación. Puedes arrastrar el archivo .app a este acceso directo para instalar la app.

## Privesc a través del abuso de pkg

### Ejecución desde directorios públicos

Si un script de preinstalación o postinstalación se está ejecutando, por ejemplo, desde **`/var/tmp/Installerutil`**, un atacante podría controlar ese script para escalar privilegios cada vez que se ejecute. O otro ejemplo similar:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt=""><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Esta es una [función pública](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que varios instaladores y actualizadores llamarán para **ejecutar algo como root**. Esta función acepta la **ruta** del **archivo** a **ejecutar** como parámetro, sin embargo, si un atacante pudiera **modificar** este archivo, sería capaz de **abusar** de su ejecución con root para **escalar privilegios**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Para más información, consulta esta charla: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Ejecución mediante montaje

Si un instalador escribe en `/tmp/fixedname/bla/bla`, es posible **crear un montaje** sobre `/tmp/fixedname` con noowners para que puedas **modificar cualquier archivo durante la instalación** y abusar del proceso de instalación.

Un ejemplo de esto es **CVE-2021-26089** que logró **sobrescribir un script periódico** para obtener ejecución como root. Para más información, echa un vistazo a la charla: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg como malware

### Payload Vacío

Es posible generar un archivo **`.pkg`** solo con **scripts de preinstalación y postinstalación** sin ningún payload.

### JS en Distribution xml

Es posible agregar etiquetas **`<script>`** en el archivo **distribution xml** del paquete y ese código se ejecutará y puede **ejecutar comandos** usando **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Referencias

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
