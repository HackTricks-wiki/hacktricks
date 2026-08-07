# Archivos, carpetas, binarios y memoria de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Estructura de la jerarquía de archivos

- **/Applications**: Las aplicaciones instaladas deberían estar aquí. Todos los usuarios podrán acceder a ellas.
- **/bin**: Binarios de línea de comandos
- **/cores**: Si existe, se utiliza para almacenar core dumps
- **/dev**: Todo se trata como un archivo, por lo que aquí pueden aparecer dispositivos de hardware.
- **/etc**: Archivos de configuración
- **/Library**: Aquí se encuentran muchos subdirectorios y archivos relacionados con preferencias, cachés y logs. Existe una carpeta Library en la raíz y en el directorio de cada usuario.
- **/private**: No está documentado, pero muchas de las carpetas mencionadas son enlaces simbólicos al directorio private.
- **/sbin**: Binarios esenciales del sistema (relacionados con la administración)
- **/System**: Archivos necesarios para que OS X funcione. Aquí deberían encontrarse principalmente archivos específicos de Apple (no de terceros).
- **/tmp**: Los archivos se eliminan después de 3 días (es un enlace blando a /private/tmp)
- **/Users**: Directorio personal de los usuarios.
- **/usr**: Binarios de configuración y del sistema
- **/var**: Archivos de log
- **/Volumes**: Las unidades montadas aparecen aquí.
- **/.vol**: Al ejecutar `stat a.txt` se obtiene algo como `16777223 7545753 -rw-r--r-- 1 username wheel ...`, donde el primer número es el identificador del volumen donde existe el archivo y el segundo es el número de inode. Se puede acceder al contenido de este archivo a través de /.vol/ con esa información ejecutando `cat /.vol/16777223/7545753`

### Carpetas de aplicaciones

- Las **aplicaciones del sistema** se encuentran en `/System/Applications`
- Las aplicaciones **instaladas** suelen instalarse en `/Applications` o en `~/Applications`
- Los **datos de las aplicaciones** pueden encontrarse en `/Library/Application Support` para las aplicaciones que se ejecutan como root y en `~/Library/Application Support` para las aplicaciones que se ejecutan como el usuario.
- Los **daemons** de aplicaciones de terceros que **necesitan ejecutarse como root** suelen encontrarse en `/Library/PrivilegedHelperTools/`
- Las aplicaciones **Sandboxed** se asignan a la carpeta `~/Library/Containers`. Cada aplicación tiene una carpeta cuyo nombre corresponde al bundle ID de la aplicación (`com.apple.Safari`).
- El **kernel** se encuentra en `/System/Library/Kernels/kernel`
- Las **extensiones del kernel de Apple** se encuentran en `/System/Library/Extensions`
- Las **extensiones del kernel de terceros** se almacenan en `/Library/Extensions`

### Archivos con información sensible

MacOS almacena información como contraseñas en varios lugares:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Instaladores pkg vulnerables


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Extensiones específicas de OS X

- **`.dmg`**: Los archivos Apple Disk Image son muy habituales para los instaladores.
- **`.kext`**: Debe seguir una estructura específica y es la versión de OS X de un driver. (es un bundle)
- **`.plist`**: También conocido como property list, almacena información en formato XML o binario.
- Puede ser XML o binario. Los binarios se pueden leer con:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Aplicaciones de Apple que siguen una estructura de directorios (es un bundle).
- **`.dylib`**: Librerías dinámicas (como los archivos DLL de Windows)
- **`.pkg`**: Son iguales que xar (formato eXtensible Archive). El comando installer puede utilizarse para instalar el contenido de estos archivos.
- **`.DS_Store`**: Este archivo se encuentra en cada directorio y guarda los atributos y personalizaciones del directorio.
- **`.Spotlight-V100`**: Esta carpeta aparece en el directorio raíz de cada volumen del sistema.
- **`.metadata_never_index`**: Si este archivo se encuentra en la raíz de un volumen, Spotlight no indexará dicho volumen.
- **`.noindex`**: Los archivos y carpetas con esta extensión no serán indexados por Spotlight.
- **`.sdef`**: Archivos dentro de bundles que especifican cómo es posible interactuar con la aplicación desde un AppleScript.

### Bundles de macOS

Un bundle es un **directorio** que **parece un objeto en Finder** (un ejemplo de Bundle son los archivos `*.app`).


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

En macOS (e iOS), todas las librerías compartidas del sistema, como frameworks y dylibs, se **combinan en un único archivo**, llamado **dyld shared cache**. Esto mejoró el rendimiento, ya que el código puede cargarse más rápido.

En macOS se encuentra en `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` y, en versiones antiguas, es posible que puedas encontrar la **shared cache** en **`/System/Library/dyld/`**.\
En iOS se pueden encontrar en **`/System/Library/Caches/com.apple.dyld/`**.

Al igual que la dyld shared cache, el kernel y las extensiones del kernel también se compilan en una kernel cache, que se carga durante el arranque.

Para extraer las librerías del archivo único de la shared cache de dylibs, era posible utilizar el binario [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip), que puede que actualmente no funcione, pero también puedes utilizar [**dyldextractor**](https://github.com/arandomdev/dyldextractor):
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Ten en cuenta que, aunque la herramienta `dyld_shared_cache_util` no funcione, puedes pasar el **shared dyld binary a Hopper** y Hopper podrá identificar todas las libraries y permitirte **seleccionar cuál** quieres investigar:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Algunos extractors no funcionarán porque las dylibs están prelinked con direcciones hardcodeadas, por lo que podrían saltar a direcciones desconocidas.

> [!TIP]
> También es posible descargar el Shared Library Cache de otros dispositivos \*OS en macos usando un emulador de Xcode. Se descargarán dentro de: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, como:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapeo de SLC

**`dyld`** usa el syscall **`shared_region_check_np`** para saber si el SLC ha sido mapeado (que devuelve la dirección) y **`shared_region_map_and_slide_np`** para mapear el SLC.

Ten en cuenta que, aunque el SLC se deslice durante el primer uso, todos los **procesos** usan la **misma copia**, lo que **eliminaba la protección ASLR** si el atacante podía ejecutar procesos en el sistema. Esto se explotó en el pasado y se solucionó con shared region pager.

Los branch pools son pequeñas dylibs Mach-O que crean pequeños espacios entre los mapeos de imágenes, haciendo imposible interponer las funciones.

### Anulación de SLCs

Usando las variables de entorno:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Esto permitirá cargar un nuevo shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`** y reemplazando manualmente las libraries con symlinks al shared cache y las libraries reales (tendrás que extraerlas)

## Permisos especiales de archivos

### Permisos de carpetas

En una **carpeta**, **read** permite **listar su contenido**, **write** permite **eliminar** y **escribir** archivos en ella, y **execute** permite **atravesar** el directorio. Por ejemplo, un usuario con **permiso de lectura sobre un archivo** dentro de un directorio en el que **no tiene permiso de ejecución** **no podrá leer** el archivo.

### Modificadores de flags

Hay algunos flags que se pueden establecer en los archivos y que harán que estos se comporten de forma diferente. Puedes **comprobar los flags** de los archivos dentro de un directorio con `ls -lO /path/directory`

- **`uchg`**: Conocido como flag **uchange**, **impedirá cualquier acción** que cambie o elimine el **archivo**. Para establecerlo: `chflags uchg file.txt`
- El usuario root podría **eliminar el flag** y modificar el archivo
- **`restricted`**: Este flag hace que el archivo esté **protegido por SIP** (no puedes añadir este flag a un archivo).
- **`Sticky bit`**: Si un directorio tiene el sticky bit, **solo el propietario del directorio o root pueden renombrar o eliminar** archivos. Normalmente se establece en el directorio /tmp para evitar que los usuarios normales eliminen o muevan los archivos de otros usuarios.

Todos los flags se pueden encontrar en el archivo `sys/stat.h` (encuéntralo usando `mdfind stat.h | grep stat.h`) y son:

- `UF_SETTABLE` 0x0000ffff: Máscara de flags modificables por el propietario.
- `UF_NODUMP` 0x00000001: No volcar el archivo.
- `UF_IMMUTABLE` 0x00000002: El archivo no puede modificarse.
- `UF_APPEND` 0x00000004: Solo se pueden añadir datos al archivo.
- `UF_OPAQUE` 0x00000008: El directorio es opaco con respecto a union.
- `UF_COMPRESSED` 0x00000020: El archivo está comprimido (algunos file-systems).
- `UF_TRACKED` 0x00000040: No se envían notificaciones de eliminaciones o cambios de nombre para archivos que tengan este flag establecido.
- `UF_DATAVAULT` 0x00000080: Se requiere entitlement para leer y escribir.
- `UF_HIDDEN` 0x00008000: Indica que este elemento no debería mostrarse en una GUI.
- `SF_SUPPORTED` 0x009f0000: Máscara de flags compatibles con el superusuario.
- `SF_SETTABLE` 0x3fff0000: Máscara de flags modificables por el superusuario.
- `SF_SYNTHETIC` 0xc0000000: Máscara de flags sintéticos de solo lectura del sistema.
- `SF_ARCHIVED` 0x00010000: El archivo está archivado.
- `SF_IMMUTABLE` 0x00020000: El archivo no puede modificarse.
- `SF_APPEND` 0x00040000: Solo se pueden añadir datos al archivo.
- `SF_RESTRICTED` 0x00080000: Se requiere entitlement para escribir.
- `SF_NOUNLINK` 0x00100000: El elemento no puede eliminarse, renombrarse ni montarse.
- `SF_FIRMLINK` 0x00800000: El archivo es un firmlink.
- `SF_DATALESS` 0x40000000: El archivo es un objeto sin datos.

### **ACLs de archivos**

Las **ACLs** de archivos contienen **ACE** (Access Control Entries), donde se pueden asignar **permisos más granulares** a diferentes usuarios.

Es posible conceder a un **directorio** estos permisos: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Y a un **archivo**: `read`, `write`, `append`, `execute`.

Cuando el archivo contiene ACLs, verás un **"+" al listar los permisos, como en**:
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
Puedes encontrar **todos los archivos con ACLs** con (esto es muuuuy lento):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Atributos extendidos

Los atributos extendidos tienen un nombre y cualquier valor deseado, y se pueden ver usando `ls -@` y manipular mediante el comando `xattr`. Algunos atributos extendidos comunes son:

- `com.apple.resourceFork`: Compatibilidad con resource fork. También visible como `filename/..namedfork/rsrc`
- `com.apple.quarantine`: macOS: mecanismo de cuarentena de Gatekeeper (III/6)
- `metadata:*`: macOS: varios metadatos, como `_backup_excludeItem` o `kMD*`
- `com.apple.lastuseddate` (#PS): Fecha del último uso del archivo
- `com.apple.FinderInfo`: macOS: información de Finder (por ejemplo, Tags de color)
- `com.apple.TextEncoding`: Especifica la codificación de texto de los archivos de texto ASCII
- `com.apple.logd.metadata`: Usado por logd en archivos de `/var/db/diagnostics`
- `com.apple.genstore.*`: Almacenamiento generacional (`/.DocumentRevisions-V100` en la raíz del sistema de archivos)
- `com.apple.rootless`: macOS: Usado por System Integrity Protection para etiquetar archivos (III/10)
- `com.apple.uuidb.boot-uuid`: Marcas de logd de las épocas de arranque con un UUID único
- `com.apple.decmpfs`: macOS: Compresión transparente de archivos (II/7)
- `com.apple.cprotect`: \*OS: Datos de cifrado por archivo (III/11)
- `com.apple.installd.*`: \*OS: Metadatos usados por installd, por ejemplo, `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Esta es una forma de obtener **Alternate Data Streams en máquinas MacOS**. Se puede guardar contenido dentro de un atributo extendido llamado **com.apple.ResourceFork** dentro de un archivo, guardándolo en **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Puedes **encontrar todos los archivos que contienen este atributo extendido** con:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

El atributo extendido `com.apple.decmpfs` indica que el archivo está almacenado de forma cifrada, `ls -l` mostrará un **tamaño de 0** y los datos comprimidos se encuentran dentro de este atributo. Cada vez que se acceda al archivo, se descifrará en memoria.

Este atributo puede verse con `ls -lO`, donde aparece indicado como comprimido, ya que los archivos comprimidos también están etiquetados con el flag `UF_COMPRESSED`. Si a un archivo comprimido se le elimina este flag con `chflags nocompressed </path/to/file>`, el sistema no sabrá que el archivo estaba comprimido y, por tanto, no podrá descomprimirlo ni acceder a los datos (pensará que realmente está vacío).

La herramienta afscexpand puede utilizarse para forzar la descompresión de un archivo.


### Ubicaciones de configuración interesantes (macOS)

| Ruta / Ubicación | Propósito / Qué configura | Seguridad / Potencial de ataque |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Almacena los archivos plist de feature flags de Apple que controlan comportamientos opcionales o experimentales en system daemons / frameworks | Si un atacante puede eludir SIP u obtener privilegios, manipularlos podría habilitar rutas de código ocultas o desactivar medidas de protección |
| `/System/Library/CoreServices/systemVersion.plist` | Contiene metadatos de la versión de macOS (ProductVersion, BuildVersion) utilizados por aplicaciones / instaladores para controlar el comportamiento | Su modificación puede engañar a aplicaciones o instaladores para que acepten versiones del sistema operativo no compatibles o desbloqueen funciones |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Preferencias de aplicaciones / de todo el sistema | Si se puede escribir en ellas, los atacantes pueden inyectar configuraciones para dirigir el comportamiento de las aplicaciones, desactivar protecciones o provocar una configuración incorrecta |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Definiciones plist para daemons y agents en segundo plano | La inserción o manipulación de plist maliciosos (si los permisos lo permiten) habilita persistencia o escaladas de privilegios |
| `/etc/hosts` | Mapeos de nombres de host ↔ IP utilizados por el resolvedor DNS del sistema | Redirigir nombres de dominio, interceptar tráfico y suplantar servicios bajo control local |
| `/etc/sudoers` | Define quién puede ejecutar comandos con `sudo` y bajo qué condiciones | Un archivo sudoers alterado puede conceder root o privilegios indebidos a cuentas de atacantes |
| `/private/var/db/dslocal/nodes/Default/users/` | Archivos plist de definición de cuentas de usuario locales | Su manipulación permite crear o modificar cuentas de usuario, hashes de contraseñas o metadatos de usuario |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Instalar o modificar kexts puede proporcionar control a nivel de kernel; SIP / las políticas de firma los protegen considerablemente |
| `/private/var/db/SystemPolicyConfiguration/` | Almacena la configuración para la aplicación de políticas del sistema (por ejemplo, Gatekeeper y la notarización) | Su manipulación puede permitir eludir comprobaciones de políticas o reglas de confianza |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Binarios auxiliares y archivos de configuración de SSH | Una configuración incorrecta puede provocar una seguridad SSH débil, acceso no autorizado o algoritmos inseguros |
| `/System/Library/Sandbox/Profiles` | Perfiles de sandbox del sistema (SBPL) utilizados para restringir las acciones de los procesos | Reemplazar o alterar los perfiles puede abrir vectores de escape de sandbox o debilitar el aislamiento |

> **Nota**: Muchas de estas rutas se encuentran en directorios protegidos por SIP (por ejemplo, `/System`) y están protegidas contra escritura a menos que SIP esté desactivado o se eluda.


## **Binarios universales y formato** Mach-o

Los binarios de Mac OS normalmente se compilan como **binarios universales**. Un **binario universal** puede **admitir múltiples arquitecturas en el mismo archivo**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Volcado de memoria de macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Archivos de categorías de riesgo de Mac OS

El directorio `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` es donde se almacena la información sobre el **riesgo asociado a diferentes extensiones de archivo**. Este directorio clasifica los archivos en varios niveles de riesgo, lo que influye en cómo Safari gestiona estos archivos después de descargarlos. Las categorías son las siguientes:

- **LSRiskCategorySafe**: Los archivos de esta categoría se consideran **completamente seguros**. Safari abrirá automáticamente estos archivos después de descargarlos.
- **LSRiskCategoryNeutral**: Estos archivos no muestran advertencias y Safari **no los abre automáticamente**.
- **LSRiskCategoryUnsafeExecutable**: Los archivos de esta categoría **activan una advertencia** indicando que el archivo es una aplicación. Esto sirve como medida de seguridad para alertar al usuario.
- **LSRiskCategoryMayContainUnsafeExecutable**: Esta categoría es para archivos, como los archivos comprimidos, que podrían contener un ejecutable. Safari **activará una advertencia** a menos que pueda verificar que todo el contenido es seguro o neutral.

## Archivos de registro

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contiene información sobre los archivos descargados, como la URL desde la que se descargaron.
- **`/var/log/system.log`**: Registro principal de los sistemas OSX. com.apple.syslogd.plist es responsable de la ejecución del syslogging (puedes comprobar si está desactivado buscando "com.apple.syslogd" en `launchctl list`.
- **`/private/var/log/asl/*.asl`**: Estos son los Apple System Logs, que pueden contener información interesante.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Almacena los archivos y aplicaciones a los que se ha accedido recientemente mediante "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Almacena los elementos que se ejecutarán al iniciar el sistema
- **`$HOME/Library/Logs/DiskUtility.log`**: Archivo de registro de la aplicación DiskUtility (información sobre unidades, incluidas las USB)
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Datos sobre puntos de acceso inalámbricos.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lista de daemons desactivados.

{{#include ../../../banners/hacktricks-training.md}}
