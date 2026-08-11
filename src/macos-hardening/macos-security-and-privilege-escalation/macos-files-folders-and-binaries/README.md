# Archivos, carpetas, binarios y memoria de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Diseño de la jerarquía de archivos

Apple documenta el sistema de archivos de macOS como una jerarquía de dominios del sistema, locales, de red y de usuario. El contenido exacto varía según la versión del sistema operativo, y las ubicaciones del sistema están cada vez más protegidas o sintetizadas. <sup>[[1]](#references)</sup>

- **/Applications**: Las aplicaciones instaladas deberían estar aquí. Todos los usuarios podrán acceder a ellas.
- **/bin**: Binarios de línea de comandos
- **/cores**: Si existe, se utiliza para almacenar core dumps
- **/dev**: Todo se trata como un archivo, por lo que aquí pueden aparecer dispositivos de hardware.
- **/etc**: Archivos de configuración
- **/Library**: Aquí pueden encontrarse muchos subdirectorios y archivos relacionados con preferencias, cachés y logs. Existe una carpeta Library en la raíz y en el directorio de cada usuario.
- **/private**: No documentado, pero muchas de las carpetas mencionadas son symbolic links al directorio private.
- **/sbin**: Binarios esenciales del sistema (relacionados con la administración)
- **/System**: Archivos requeridos por macOS; este árbol contiene principalmente componentes proporcionados por Apple.
- **/tmp**: Archivos temporales (un symbolic link a `/private/tmp`). Las instalaciones históricas normalmente limpiaban los archivos temporales antiguos según un calendario periódico, a veces descrito como de tres días, pero el momento actual de limpieza depende del sistema y de la política; no debe confiarse en que los datos permanezcan allí.
- **/Users**: Directorio de inicio de los usuarios.
- **/usr**: Configuración y binarios del sistema
- **/var**: Archivos de log
- **/Volumes**: Los volúmenes montados aparecen aquí.
- **/.vol**: Al ejecutar `stat a.txt` se obtiene algo como `16777223 7545753 -rw-r--r-- 1 username wheel ...`, donde el primer número es el identificador del volumen donde existe el archivo y el segundo es el número de inode. Se puede acceder al contenido de este archivo a través de /.vol/ usando esa información y ejecutando `cat /.vol/16777223/7545753`

### Carpetas de aplicaciones

- Las **aplicaciones del sistema** se encuentran en `/System/Applications`
- Las aplicaciones **instaladas** normalmente se instalan en `/Applications` o en `~/Applications`
- Los datos de las aplicaciones pueden encontrarse en `/Library/Application Support` para las aplicaciones que se ejecutan como root y en `~/Library/Application Support` para las aplicaciones que se ejecutan como el usuario.
- Los **daemons** de aplicaciones de terceros que **necesitan ejecutarse como root** normalmente se encuentran en `/Library/PrivilegedHelperTools/`.
- Las aplicaciones **Sandboxed** se asignan a la carpeta `~/Library/Containers`. Cada aplicación tiene una carpeta cuyo nombre corresponde al bundle ID de la aplicación (`com.apple.Safari`).
- El **kernel** se encuentra en `/System/Library/Kernels/kernel`
- Las kernel extensions de **Apple** se encuentran en `/System/Library/Extensions`
- Las kernel extensions de **terceros** se almacenan en `/Library/Extensions`

### Archivos con información sensible

macOS almacena información sensible, incluidas credenciales, en varios lugares:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Instaladores pkg vulnerables


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Extensiones específicas de OS X

- **`.dmg`**: Los archivos Apple Disk Image son muy frecuentes en los instaladores.
- **`.kext`**: Debe seguir una estructura específica y es la versión de OS X de un driver. (es un bundle)
- **`.plist`**: Una property list almacena información estructurada en formato XML o binario.
- Puede ser XML o binario. Los binarios se pueden leer con:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Un application bundle que sigue la estructura de directorios estándar de macOS.
- **`.dylib`**: Bibliotecas dinámicas (como los archivos DLL de Windows)
- **`.pkg`**: Son iguales que xar (formato eXtensible Archive). El comando installer se puede utilizar para instalar el contenido de estos archivos.
- **`.DS_Store`**: Este archivo se encuentra en cada directorio y guarda los atributos y personalizaciones del directorio.
- **`.Spotlight-V100`**: Esta carpeta aparece en el directorio raíz de cada volumen del sistema.
- **`.metadata_never_index`**: Si este archivo se encuentra en la raíz de un volumen, Spotlight no indexará ese volumen.
- **`.noindex`**: Los archivos y carpetas con esta extensión no serán indexados por Spotlight.
- **`.sdef`**: Un archivo de definición de scripting que describe cómo AppleScript puede interactuar con una aplicación.

### Bundles de macOS

Un bundle es un directorio con una jerarquía estandarizada que Finder puede presentar como un único objeto; los application bundles utilizan la extensión `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

En macOS e iOS, las bibliotecas y frameworks del sistema utilizados habitualmente se preenlazan en la **dyld shared cache**, lo que mejora el rendimiento de inicio de las aplicaciones. Aunque se trata como una única caché lógica, las versiones actuales pueden almacenarla como una caché principal más varios archivos de subcaché, en lugar de literalmente en un solo archivo. Su formato y ubicación son detalles de implementación que cambian entre versiones del sistema operativo. <sup>[[3]](#references)</sup>

En macOS se encuentra en `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` y en versiones anteriores es posible que la **shared cache** se encuentre en **`/System/Library/dyld/`**.\
En iOS se pueden encontrar en **`/System/Library/Caches/com.apple.dyld/`**.

De forma similar a la dyld shared cache, el kernel y las kernel extensions también se compilan en una kernel cache, que se carga durante el arranque.

Las versiones anteriores podían extraerse con [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Esa build podría no admitir los formatos de caché actuales; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) es otra opción:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Ten en cuenta que, aunque la herramienta `dyld_shared_cache_util` no funcione, puedes pasar el **binario dyld compartido a Hopper** y Hopper podrá identificar todas las bibliotecas y permitirte **seleccionar cuál** quieres investigar:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Algunos extractores no funcionarán, ya que las dylibs están preenlazadas con direcciones codificadas de forma fija, por lo que podrían saltar a direcciones desconocidas.

> [!TIP]
> También es posible descargar la Shared Library Cache de otros dispositivos \*OS en macOS usando un emulador en Xcode. Se descargarán dentro de: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, como:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapeo de SLC

**`dyld`** utiliza la syscall **`shared_region_check_np`** para saber si la SLC ha sido mapeada (lo que devuelve la dirección) y **`shared_region_map_and_slide_np`** para mapear la SLC.

Ten en cuenta que, aunque la SLC se deslice durante el primer uso, todos los **procesos** utilizan la **misma copia**, lo que **eliminaba la protección ASLR** si el atacante podía ejecutar procesos en el sistema. Esto se explotó en el pasado y se solucionó con shared region pager.

Los branch pools son pequeñas dylibs Mach-O que crean pequeños espacios entre los mapeos de imágenes, haciendo imposible interponer las funciones.

### Anulación de SLC

Usando las variables de entorno:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Esto permitirá cargar una nueva shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`** y reemplazar manualmente las bibliotecas con symlinks a la shared cache con las reales (será necesario extraerlas)

## Permisos especiales de archivos

### Permisos de carpetas

Para un directorio, **read** permite listar entradas, **write** permite crear o eliminar entradas y **execute** permite atravesarlo. En consecuencia, un usuario que pueda leer un archivo, pero no pueda atravesar un directorio principal, no podrá acceder a ese archivo mediante su ruta. <sup>[[4]](#references)</sup>

### Modificadores de flags

Los archivos pueden contener flags que alteran su comportamiento. Inspecciona los flags de un directorio con `ls -lO /path/directory`.

- **`uchg`**: Conocido como flag **uchange**, **impedirá cualquier acción** que cambie o elimine el **archivo**. Para establecerlo, ejecuta: `chflags uchg file.txt`
- El usuario root podría **eliminar el flag** y modificar el archivo
- **`restricted`**: Este flag hace que el archivo esté **protegido por SIP** (no puedes añadir este flag a un archivo).
- **`Sticky bit`**: En un directorio con el sticky bit establecido, solo el propietario del archivo, el propietario del directorio o root pueden renombrar o eliminar una entrada. Normalmente está habilitado en `/tmp` para evitar que los usuarios eliminen o muevan archivos de otros usuarios.

Todos los flags se pueden encontrar en el archivo `sys/stat.h` (encuéntralo usando `mdfind stat.h | grep stat.h`) y son:

- `UF_SETTABLE` 0x0000ffff: Máscara de flags modificables por el propietario.
- `UF_NODUMP` 0x00000001: No volcar el archivo.
- `UF_IMMUTABLE` 0x00000002: El archivo no puede modificarse.
- `UF_APPEND` 0x00000004: Las escrituras en el archivo solo pueden añadirse al final.
- `UF_OPAQUE` 0x00000008: El directorio es opaco con respecto a union.
- `UF_COMPRESSED` 0x00000020: El archivo está comprimido (algunos sistemas de archivos).
- `UF_TRACKED` 0x00000040: No se envían notificaciones de eliminaciones o renombrados para archivos que tienen este flag establecido.
- `UF_DATAVAULT` 0x00000080: Se requiere entitlement para leer y escribir.
- `UF_HIDDEN` 0x00008000: Indica que este elemento no debe mostrarse en una GUI.
- `SF_SUPPORTED` 0x009f0000: Máscara de flags compatibles con el superusuario.
- `SF_SETTABLE` 0x3fff0000: Máscara de flags modificables por el superusuario.
- `SF_SYNTHETIC` 0xc0000000: Máscara de flags sintéticos de solo lectura del sistema.
- `SF_ARCHIVED` 0x00010000: El archivo está archivado.
- `SF_IMMUTABLE` 0x00020000: El archivo no puede modificarse.
- `SF_APPEND` 0x00040000: Las escrituras en el archivo solo pueden añadirse al final.
- `SF_RESTRICTED` 0x00080000: Se requiere entitlement para escribir.
- `SF_NOUNLINK` 0x00100000: El elemento no puede eliminarse, renombrarse ni montarse.
- `SF_FIRMLINK` 0x00800000: El archivo es un firmlink.
- `SF_DATALESS` 0x40000000: El archivo es un objeto sin datos.

### **ACLs de archivos**

Las **ACLs** de archivos contienen **ACE** (Access Control Entries), donde se pueden asignar **permisos más granulares** a distintos usuarios.

Es posible conceder a un **directorio** estos permisos: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Para un **archivo**: `read`, `write`, `append` y `execute`.

Cuando el archivo contiene ACLs, **encontrarás un "+" al listar los permisos, como en**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Puedes **leer las ACL** del archivo con:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Puedes encontrar **todos los archivos con ACLs** con el siguiente comando (es muy lento):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Extended Attributes

Los extended attributes son valores de metadatos con nombre que se almacenan por separado de los atributos ordinarios de un archivo. Se pueden listar con `ls -l@` e inspeccionar o modificar con `xattr`. <sup>[[5]](#references)</sup> Algunos extended attributes comunes son:

- `com.apple.resourceFork`: Compatibilidad con resource fork. También visible como `filename/..namedfork/rsrc`
- `com.apple.quarantine`: Metadatos de cuarentena de macOS Gatekeeper
- `metadata:*`: Metadatos de macOS, como `_backup_excludeItem` o `kMD*`
- `com.apple.lastuseddate` (#PS): Fecha del último uso del archivo
- `com.apple.FinderInfo`: Información de macOS Finder, como las etiquetas de color
- `com.apple.TextEncoding`: Especifica la codificación de texto de los archivos de texto ASCII
- `com.apple.logd.metadata`: Usado por logd en archivos de `/var/db/diagnostics`
- `com.apple.genstore.*`: Almacenamiento generacional (`/.DocumentRevisions-V100` en la raíz del sistema de archivos)
- `com.apple.rootless`: Metadatos de macOS asociados con System Integrity Protection
- `com.apple.uuidb.boot-uuid`: Marcas de logd de las épocas de arranque con un UUID único
- `com.apple.decmpfs`: Metadatos de compresión transparente de archivos de macOS
- `com.apple.cprotect`: \*OS: Datos de cifrado por archivo (III/11)
- `com.apple.installd.*`: \*OS: Metadatos usados por installd, p. ej., `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Los resource forks proporcionan un flujo de datos alternativo en macOS. El contenido se puede almacenar en el extended attribute `com.apple.ResourceFork` y acceder a través de `file/..namedfork/rsrc`.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Puedes **encontrar todos los archivos que contienen este atributo extendido** con:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

El atributo extendido `com.apple.decmpfs` almacena metadatos para la compresión transparente; no indica cifrado. Dependiendo del formato de compresión, los datos comprimidos pueden almacenarse en el atributo o en un resource fork, y se descomprimen de forma transparente al leerse.

El flag `UF_COMPRESSED` aparece como `compressed` en `ls -lO`. No lo borres manualmente: hacerlo puede provocar que el sistema interprete incorrectamente la representación comprimida.

El comando que borra el flag se muestra aquí porque resulta útil durante una revisión forense, pero ejecutarlo contra un archivo comprimido puede hacer que dicho archivo aparezca vacío o sea inaccesible hasta que se reparen sus metadatos:
```bash
chflags nocompressed /path/to/file
```
La utilidad integrada `/usr/bin/afscexpand` puede forzar la expansión de archivos comprimidos de forma transparente. La utilidad independiente de terceros `afsctool` también puede inspeccionar o descomprimir la compresión del sistema de archivos de Apple, pero no debe confundirse con el comando integrado. <sup>[[8]](#references)</sup>


### Ubicaciones de configuración interesantes (macOS)

| Ruta / Ubicación | Propósito / Qué configura | Seguridad / Potencial de ataque |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Almacena los archivos plist de indicadores de funcionalidades de Apple que controlan comportamientos opcionales o experimentales en daemons / frameworks del sistema | Si un atacante puede evadir SIP u obtener privilegios, manipularlos podría habilitar rutas de código ocultas o desactivar protecciones |
| `/System/Library/CoreServices/systemVersion.plist` | Contiene metadatos de la versión de macOS (ProductVersion, BuildVersion) utilizados por aplicaciones / instaladores para controlar el comportamiento | Su modificación puede engañar a aplicaciones o instaladores para que acepten versiones de SO no compatibles o desbloqueen funcionalidades |
| `/Library/Preferences/com.apple.*.plist` y `~/Library/Preferences/*.plist` | Preferencias de aplicaciones / de todo el sistema | Si se pueden escribir, los atacantes pueden inyectar configuraciones para dirigir el comportamiento de las aplicaciones, desactivar protecciones o causar una configuración incorrecta |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Definiciones plist para daemons y agentes en segundo plano | La inserción o manipulación de plists maliciosos (si los permisos lo permiten) habilita persistencia o escaladas de privilegios |
| `/etc/hosts` | Asignaciones de nombres de host ↔ IP utilizadas por el resolvedor DNS del sistema | Redirección de nombres de dominio, interceptación de tráfico y suplantación de servicios bajo control local |
| `/etc/sudoers` | Define quién puede ejecutar comandos con `sudo` y bajo qué condiciones | Un archivo sudoers corrupto puede conceder root o privilegios indebidos a cuentas de atacantes |
| `/private/var/db/dslocal/nodes/Default/users/` | Archivos plist de definición de cuentas de usuario locales | Su manipulación permite crear o modificar cuentas de usuario, hashes de contraseñas o metadatos de usuario |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Extensiones del kernel / drivers | Instalar o modificar kexts puede conducir al control a nivel del kernel; SIP / las políticas de firma los protegen ampliamente |
| `/private/var/db/SystemPolicyConfiguration/` | Almacena la configuración para la aplicación de políticas del sistema (por ejemplo, Gatekeeper y la notarización) | Manipularlos puede permitir eludir comprobaciones de políticas o reglas de confianza |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Binarios auxiliares y archivos de configuración de SSH | Una configuración incorrecta conduce a una seguridad débil de SSH, acceso no autorizado o algoritmos inseguros |
| `/System/Library/Sandbox/Profiles` | Perfiles de sandbox del sistema (SBPL) utilizados para restringir las acciones de los procesos | Reemplazar o alterar los perfiles puede abrir vectores de escape de la sandbox o debilitar el aislamiento |

> **Nota**: Muchas de estas rutas se encuentran bajo directorios protegidos por SIP (por ejemplo, `/System`) y están protegidas contra escritura, a menos que SIP esté desactivado o se haya evadido.


## Binarios universales y formato Mach-O

Mach-O es el formato de ejecutables nativo de macOS. Un binario universal, o fat, agrupa varios slices de Mach-O específicos de cada arquitectura en un solo archivo; la página dedicada explica ambos formatos:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Volcado de memoria de macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Riesgo de archivos y metadatos de handlers

LaunchServices, la cuarentena de archivos y Gatekeeper influyen conjuntamente en cómo macOS gestiona los archivos descargados y selecciona aplicaciones para extensiones y esquemas de URL. Sus bases de datos y archivos de recursos internos cambian entre versiones; utiliza las páginas dedicadas en lugar de tratar una ruta privada de CoreTypes como una interfaz de políticas estable:

En las versiones que exponen los metadatos de riesgo heredados de CoreTypes en `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, las categorías habituales son:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: contenido considerado lo bastante seguro para abrirse automáticamente según la política aplicable de la aplicación.
- **`LSRiskCategoryNeutral`**: contenido que normalmente no activa una advertencia y no se abre automáticamente.
- **`LSRiskCategoryUnsafeExecutable`**: contenido ejecutable para el que el usuario debería recibir una advertencia de la aplicación.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: contenedores, como archivos comprimidos, que pueden contener contenido ejecutable y requieren una inspección adicional.

Estos son detalles de implementación, no una API pública de políticas estable; confirma los metadatos reales y el comportamiento de Safari/Gatekeeper en la versión de macOS bajo prueba.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Archivos de registro

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contiene información sobre archivos descargados, como la URL desde la que se descargaron.
- **Unified log**: En las versiones actuales de macOS, consulta los eventos del sistema y de las aplicaciones con `log show` y `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** y **`/private/var/log/asl/*.asl`**: Artefactos de registro heredados que aún pueden ser relevantes en sistemas antiguos. En esas versiones, `/System/Library/LaunchDaemons/com.apple.syslogd.plist` configura `syslogd`; `launchctl list | grep com.apple.syslogd` puede ayudar a determinar si el servicio está cargado.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Almacena los archivos y aplicaciones a los que se ha accedido recientemente mediante "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Ruta de preferencias heredada asociada a los elementos de inicio de sesión; las versiones modernas de macOS utilizan mecanismos adicionales.
- **`$HOME/Library/Logs/DiskUtility.log`**: Registro heredado de Disk Utility que puede contener información sobre unidades, incluidos dispositivos USB.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Datos sobre puntos de acceso inalámbricos.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Datos heredados de sobrescritura de launchd.

## References

- [1] [Apple - Guía de programación del sistema de archivos](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Guía de programación de Bundle](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Foros de Apple Developer - descripción general de la caché compartida de dyld](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Guía de programación del sistema de archivos: seguridad del sistema de archivos de macOS](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - página del manual de macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - página del manual de macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - página del manual de macOS](https://manp.gs/mac/1/afscexpand)
{{#include ../../../banners/hacktricks-training.md}}
