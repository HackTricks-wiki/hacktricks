# Archivos, Carpetas, Binarios y Memoria de macOS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Estructura jerárquica de archivos

* **/Applications**: Las aplicaciones instaladas deben estar aquí. Todos los usuarios podrán acceder a ellas.
* **/bin**: Binarios de línea de comandos
* **/cores**: Si existe, se utiliza para almacenar volcados de memoria
* **/dev**: Todo se trata como un archivo, por lo que puedes ver dispositivos de hardware almacenados aquí.
* **/etc**: Archivos de configuración
* **/Library**: Aquí se pueden encontrar muchos subdirectorios y archivos relacionados con preferencias, cachés y registros. Existe una carpeta Library en la raíz y en el directorio de cada usuario.
* **/private**: No documentado, pero muchos de los directorios mencionados son enlaces simbólicos al directorio privado.
* **/sbin**: Binarios esenciales del sistema (relacionados con la administración)
* **/System**: Archivo para hacer funcionar OS X. Deberías encontrar principalmente archivos específicos de Apple aquí (no de terceros).
* **/tmp**: Los archivos se eliminan después de 3 días (es un enlace simbólico a /private/tmp)
* **/Users**: Directorio principal para los usuarios.
* **/usr**: Configuración y binarios del sistema
* **/var**: Archivos de registro
* **/Volumes**: Las unidades montadas aparecerán aquí.
* **/.vol**: Al ejecutar `stat a.txt` obtienes algo como `16777223 7545753 -rw-r--r-- 1 username wheel ...` donde el primer número es el número de identificación del volumen donde existe el archivo y el segundo es el número de inodo. Puedes acceder al contenido de este archivo a través de /.vol/ con esa información ejecutando `cat /.vol/16777223/7545753`

### Carpetas de Aplicaciones

* Las **aplicaciones del sistema** se encuentran bajo `/System/Applications`
* Las aplicaciones **instaladas** generalmente se instalan en `/Applications` o en `~/Applications`
* Los **datos de la aplicación** se pueden encontrar en `/Library/Application Support` para las aplicaciones que se ejecutan como root y `~/Library/Application Support` para aplicaciones que se ejecutan como el usuario.
* Los **daemons** de aplicaciones de terceros que **necesitan ejecutarse como root** generalmente se ubican en `/Library/PrivilegedHelperTools/`
* Las aplicaciones **sandboxed** se mapean en la carpeta `~/Library/Containers`. Cada aplicación tiene una carpeta nombrada de acuerdo con el ID del paquete de la aplicación (`com.apple.Safari`).
* El **kernel** se encuentra en `/System/Library/Kernels/kernel`
* Las **extensiones del kernel de Apple** se encuentran en `/System/Library/Extensions`
* Las **extensiones del kernel de terceros** se almacenan en `/Library/Extensions`

### Archivos con Información Sensible

MacOS almacena información como contraseñas en varios lugares:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Instaladores pkg Vulnerables

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## Extensiones Específicas de OS X

* **`.dmg`**: Los archivos de imagen de disco de Apple son muy frecuentes para instaladores.
* **`.kext`**: Debe seguir una estructura específica y es la versión de OS X de un controlador. (es un paquete)
* **`.plist`**: También conocido como lista de propiedades, almacena información en formato XML o binario.
* Puede ser XML o binario. Los binarios se pueden leer con:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Aplicaciones de Apple que siguen la estructura de directorios (Es un paquete).
* **`.dylib`**: Bibliotecas dinámicas (como los archivos DLL de Windows)
* **`.pkg`**: Son lo mismo que xar (formato de archivo extensible). El comando de instalación se puede usar para instalar el contenido de estos archivos.
* **`.DS_Store`**: Este archivo está en cada directorio, guarda los atributos y personalizaciones del directorio.
* **`.Spotlight-V100`**: Esta carpeta aparece en el directorio raíz de cada volumen en el sistema.
* **`.metadata_never_index`**: Si este archivo está en la raíz de un volumen, Spotlight no indexará ese volumen.
* **`.noindex`**: Los archivos y carpetas con esta extensión no serán indexados por Spotlight.

### Paquetes de macOS

Básicamente, un paquete es una **estructura de directorio** dentro del sistema de archivos. Curiosamente, por defecto este directorio **parece un solo objeto en Finder** (como `.app`).&#x20;

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld Shared Cache

En macOS (y iOS) todas las bibliotecas compartidas del sistema, como frameworks y dylibs, se **combinan en un solo archivo**, llamado **dyld shared cache**. Esto mejora el rendimiento, ya que el código se puede cargar más rápido.

Similar al dyld shared cache, el kernel y las extensiones del kernel también se compilan en un caché del kernel, que se carga en el momento del arranque.

Para extraer las bibliotecas del archivo único dylib shared cache era posible usar el binario [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) que podría no estar funcionando hoy en día, pero también puedes usar [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

{% code overflow="wrap" %}
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

En versiones anteriores, podrías ser capaz de encontrar la **caché compartida** en **`/System/Library/dyld/`**.

En iOS puedes encontrarlas en **`/System/Library/Caches/com.apple.dyld/`**.

{% hint style="success" %}
Ten en cuenta que incluso si la herramienta `dyld_shared_cache_util` no funciona, puedes pasar el **binario dyld compartido a Hopper** y Hopper será capaz de identificar todas las bibliotecas y permitirte **seleccionar cuál** quieres investigar:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## Permisos Especiales de Archivos

### Permisos de carpetas

En una **carpeta**, **leer** permite **listarla**, **escribir** permite **eliminar** y **escribir** archivos en ella, y **ejecutar** permite **atravesar** el directorio. Por lo tanto, por ejemplo, un usuario con **permiso de lectura sobre un archivo** dentro de un directorio donde **no tiene permiso de ejecución** **no podrá leer** el archivo.

### Modificadores de banderas

Hay algunas banderas que se pueden establecer en los archivos que harán que el archivo se comporte de manera diferente. Puedes **verificar las banderas** de los archivos dentro de un directorio con `ls -lO /path/directory`

* **`uchg`**: Conocida como bandera **uchange**, **evitará cualquier acción** que cambie o elimine el **archivo**. Para establecerla haz: `chflags uchg file.txt`
* El usuario root podría **eliminar la bandera** y modificar el archivo
* **`restricted`**: Esta bandera hace que el archivo esté **protegido por SIP** (no puedes agregar esta bandera a un archivo).
* **`Sticky bit`**: Si un directorio con sticky bit, **solo** el **propietario del directorio o root pueden renombrar o eliminar** archivos. Típicamente esto se establece en el directorio /tmp para evitar que los usuarios ordinarios eliminen o muevan archivos de otros usuarios.

### **ACLs de Archivos**

Las **ACLs** de archivos contienen **ACE** (Entradas de Control de Acceso) donde se pueden asignar **permisos más granulares** a diferentes usuarios.

Es posible otorgar a un **directorio** estos permisos: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Y a un **archivo**: `read`, `write`, `append`, `execute`.

Cuando el archivo contiene ACLs encontrarás un "+" al listar los permisos como en:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Puedes **leer las ACLs** del archivo con:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Puedes encontrar **todos los archivos con ACLs** con (esto es muuuy lento):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Resource Forks | macOS ADS

Esta es una forma de obtener **Alternate Data Streams en MacOS**. Puedes guardar contenido dentro de un atributo extendido llamado **com.apple.ResourceFork** dentro de un archivo guardándolo en **file/..namedfork/rsrc**.
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
## **Binarios universales y** formato Mach-o

Los binarios de Mac OS suelen compilarse como **binarios universales**. Un **binario universal** puede **soportar múltiples arquitecturas en el mismo archivo**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Volcado de memoria en macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Archivos de categoría de riesgo en Mac OS

Los archivos `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` contienen el riesgo asociado a archivos dependiendo de la extensión del archivo.

Las posibles categorías incluyen las siguientes:

* **LSRiskCategorySafe**: **Totalmente** **seguro**; Safari lo abrirá automáticamente después de la descarga
* **LSRiskCategoryNeutral**: Sin advertencia, pero **no se abre automáticamente**
* **LSRiskCategoryUnsafeExecutable**: **Desencadena** una **advertencia** “Este archivo es una aplicación...”
* **LSRiskCategoryMayContainUnsafeExecutable**: Esto es para cosas como archivos comprimidos que contienen un ejecutable. **Desencadena una advertencia a menos que Safari pueda determinar que todo el contenido es seguro o neutral**.

## Archivos de registro

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contiene información sobre archivos descargados, como la URL de donde se descargaron.
* **`/var/log/system.log`**: Registro principal de los sistemas OSX. com.apple.syslogd.plist es responsable de la ejecución del registro del sistema (puedes verificar si está desactivado buscando "com.apple.syslogd" en `launchctl list`).
* **`/private/var/log/asl/*.asl`**: Estos son los registros del sistema de Apple que pueden contener información interesante.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Almacena archivos y aplicaciones accedidos recientemente a través de "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Almacena elementos para lanzar al inicio del sistema
* **`$HOME/Library/Logs/DiskUtility.log`**: Archivo de registro para la aplicación DiskUtility (información sobre unidades, incluyendo USBs)
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Datos sobre puntos de acceso inalámbricos.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lista de demonios desactivados.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
