# Archivos, Carpetas, Binarios y Memoria de macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Diseño jerárquico de archivos

* **/Applications**: Las aplicaciones instaladas deben estar aquí. Todos los usuarios podrán acceder a ellas.
* **/bin**: Binarios de línea de comandos
* **/cores**: Si existe, se utiliza para almacenar volcados de núcleo
* **/dev**: Todo se trata como un archivo, por lo que es posible que veas dispositivos de hardware almacenados aquí.
* **/etc**: Archivos de configuración
* **/Library**: Se pueden encontrar muchos subdirectorios y archivos relacionados con preferencias, cachés y registros. Existe una carpeta Library en la raíz y en el directorio de cada usuario.
* **/private**: No documentado, pero muchos de los directorios mencionados son enlaces simbólicos al directorio privado.
* **/sbin**: Binarios esenciales del sistema (relacionados con la administración)
* **/System**: Archivo para hacer que OS X funcione. Aquí deberías encontrar principalmente archivos específicos de Apple (no de terceros).
* **/tmp**: Los archivos se eliminan después de 3 días (es un enlace simbólico a /private/tmp)
* **/Users**: Directorio de inicio para los usuarios.
* **/usr**: Configuración y binarios del sistema
* **/var**: Archivos de registro
* **/Volumes**: Las unidades montadas aparecerán aquí.
* **/.vol**: Al ejecutar `stat a.txt`, obtendrás algo como `16777223 7545753 -rw-r--r-- 1 nombredeusuario wheel ...`, donde el primer número es el número de identificación del volumen donde se encuentra el archivo y el segundo es el número de inodo. Puedes acceder al contenido de este archivo a través de /.vol/ con esa información ejecutando `cat /.vol/16777223/7545753`

### Carpetas de aplicaciones

* Las **aplicaciones del sistema** se encuentran en `/System/Applications`
* Las aplicaciones **instaladas** generalmente se instalan en `/Applications` o en `~/Applications`
* Los datos de la **aplicación** se pueden encontrar en `/Library/Application Support` para las aplicaciones que se ejecutan como root y en `~/Library/Application Support` para las aplicaciones que se ejecutan como el usuario.
* Los **daemonios** de aplicaciones de terceros que **necesitan ejecutarse como root** generalmente se encuentran en `/Library/PrivilegedHelperTools/`
* Las aplicaciones **sandboxed** se mapean en la carpeta `~/Library/Containers`. Cada aplicación tiene una carpeta con el nombre del ID de paquete de la aplicación (`com.apple.Safari`).
* El **kernel** se encuentra en `/System/Library/Kernels/kernel`
* Las **extensiones de kernel de Apple** se encuentran en `/System/Library/Extensions`
* Las **extensiones de kernel de terceros** se almacenan en `/Library/Extensions`

### Archivos con Información Sensible

macOS almacena información como contraseñas en varios lugares:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Instaladores pkg vulnerables

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## Extensiones Específicas de OS X

* **`.dmg`**: Los archivos de imagen de disco de Apple son muy frecuentes para los instaladores.
* **`.kext`**: Debe seguir una estructura específica y es la versión de OS X de un controlador (es un paquete).
* **`.plist`**: También conocido como lista de propiedades, almacena información en formato XML o binario.
* Pueden ser XML o binarios. Los binarios se pueden leer con:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Aplicaciones de Apple que siguen una estructura de directorios (es un paquete).
* **`.dylib`**: Bibliotecas dinámicas (como los archivos DLL de Windows)
* **`.pkg`**: Son iguales que los archivos xar (formato de archivo extensible). El comando installer se puede utilizar para instalar el contenido de estos archivos.
* **`.DS_Store`**: Este archivo está en cada directorio, guarda los atributos y personalizaciones del directorio.
* **`.Spotlight-V100`**: Esta carpeta aparece en el directorio raíz de cada volumen del sistema.
* **`.metadata_never_index`**: Si este archivo está en la raíz de un volumen, Spotlight no indexará ese volumen.
* **`.noindex`**: Los archivos y carpetas con esta extensión no serán indexados por Spotlight.
### Paquetes de macOS

Básicamente, un paquete es una **estructura de directorios** dentro del sistema de archivos. Curiosamente, por defecto este directorio **se ve como un objeto único en Finder** (como `.app`).&#x20;

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Caché compartida de Dyld

En macOS (y iOS), todas las bibliotecas compartidas del sistema, como los frameworks y dylibs, se **combinan en un solo archivo**, llamado **caché compartida de Dyld**. Esto mejora el rendimiento, ya que el código se puede cargar más rápido.

Similar a la caché compartida de Dyld, el kernel y las extensiones del kernel también se compilan en una caché del kernel, que se carga al iniciar el sistema.

Para extraer las bibliotecas del archivo único de la caché compartida de dylib, era posible utilizar la herramienta binaria [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip), que puede que no funcione en la actualidad:

{% code overflow="wrap" %}
```bash
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
```
{% endcode %}

## Permisos especiales de archivos

### Permisos de carpeta

En una **carpeta**, **leer** permite **listarla**, **escribir** permite **eliminar** y **escribir** archivos en ella, y **ejecutar** permite **atravesar** el directorio. Por lo tanto, por ejemplo, un usuario con **permiso de lectura sobre un archivo** dentro de un directorio donde no tiene permiso de **ejecución no podrá leer** el archivo.

### Modificadores de bandera

Existen algunas banderas que se pueden establecer en los archivos y que harán que el archivo se comporte de manera diferente. Puedes **verificar las banderas** de los archivos dentro de un directorio con `ls -lO /ruta/directorio`

* **`uchg`**: Conocida como bandera **uchange**, evitará cualquier acción que cambie o elimine el **archivo**. Para establecerla, usa: `chflags uchg archivo.txt`
* El usuario root puede **eliminar la bandera** y modificar el archivo.
* **`restricted`**: Esta bandera hace que el archivo esté **protegido por SIP** (no se puede agregar esta bandera a un archivo).
* **`Sticky bit`**: Si un directorio tiene el sticky bit, **solo** el **propietario del directorio o root pueden renombrar o eliminar** archivos. Normalmente se establece en el directorio /tmp para evitar que los usuarios normales eliminen o muevan archivos de otros usuarios.

### **ACL de archivos**

Las ACL de archivos contienen **ACE** (Entradas de Control de Acceso) donde se pueden asignar permisos más **granulares** a diferentes usuarios.

Es posible otorgar estos permisos a una **carpeta**: `listar`, `buscar`, `agregar_archivo`, `agregar_subdirectorio`, `eliminar_hijo`, `eliminar_hijo`.\
Y a un **archivo**: `leer`, `escribir`, `anexar`, `ejecutar`.

Cuando el archivo contiene ACL, verás un "+" al listar los permisos, como en:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Puedes **leer los ACLs** del archivo con:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Puedes encontrar **todos los archivos con ACLs** con (esto es muuuy lento):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Recursos Fork | ADS de macOS

Esta es una forma de obtener **Flujos de Datos Alternativos en máquinas macOS**. Puedes guardar contenido dentro de un atributo extendido llamado **com.apple.ResourceFork** dentro de un archivo al guardarlo en **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Puedes **encontrar todos los archivos que contienen este atributo extendido** con:

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

## **Binarios universales y** Formato Mach-o

Los binarios de Mac OS generalmente se compilan como **binarios universales**. Un **binario universal** puede **soportar múltiples arquitecturas en el mismo archivo**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Volcado de memoria en macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Categoría de riesgo de archivos en Mac OS

El archivo `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` contiene el riesgo asociado a los archivos dependiendo de la extensión del archivo.

Las posibles categorías incluyen las siguientes:

* **LSRiskCategorySafe**: **Totalmente** **seguro**; Safari se abrirá automáticamente después de la descarga.
* **LSRiskCategoryNeutral**: Sin advertencia, pero **no se abrirá automáticamente**.
* **LSRiskCategoryUnsafeExecutable**: **Desencadena** una **advertencia** "Este archivo es una aplicación..."
* **LSRiskCategoryMayContainUnsafeExecutable**: Esto es para cosas como archivos que contienen un ejecutable. **Desencadena una advertencia a menos que Safari pueda determinar que todo el contenido es seguro o neutral**.

## Archivos de registro

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contiene información sobre archivos descargados, como la URL desde donde se descargaron.
* **`/var/log/system.log`**: Registro principal de los sistemas OSX. com.apple.syslogd.plist es responsable de la ejecución del registro del sistema (puede verificar si está desactivado buscando "com.apple.syslogd" en `launchctl list`.
* **`/private/var/log/asl/*.asl`**: Estos son los registros del sistema de Apple que pueden contener información interesante.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Almacena archivos y aplicaciones accedidos recientemente a través de "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Almacena elementos para iniciar al arrancar el sistema.
* **`$HOME/Library/Logs/DiskUtility.log`**: Archivo de registro para la aplicación DiskUtility (información sobre unidades, incluidas las USB).
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Datos sobre puntos de acceso inalámbricos.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lista de demonios desactivados.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
