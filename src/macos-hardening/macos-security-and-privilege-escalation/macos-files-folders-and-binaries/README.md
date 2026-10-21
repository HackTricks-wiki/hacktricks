# Archivos, carpetas, binarios y memoria de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Estructura de la jerarquía de archivos

Apple documenta el sistema de archivos de macOS como una jerarquía de dominios del sistema, locales, de red y de usuario. El contenido exacto varía según la versión del sistema operativo, y las ubicaciones del sistema están cada vez más protegidas o se generan de forma sintética. <sup>[[1]](#references)</sup>

- **/Applications**: Aquí deberían estar las apps instaladas. Todos los usuarios podrán acceder a ellas.
- **/bin**: Binarios de línea de comandos
- **/cores**: Si existe, se usa para almacenar volcados de memoria
- **/dev**: Todo se trata como un archivo, por lo que aquí puedes encontrar dispositivos de hardware.
- **/etc**: Archivos de configuración
- **/Library**: Aquí se encuentran muchos subdirectorios y archivos relacionados con preferencias, cachés y logs. Hay una carpeta Library en la raíz y otra en el directorio de cada usuario.
- **/private**: No está documentado, pero muchas de las carpetas mencionadas son enlaces simbólicos al directorio private.
- **/sbin**: Binarios esenciales del sistema (relacionados con la administración)
- **/System**: Archivos necesarios para macOS; este árbol contiene principalmente componentes proporcionados por Apple.
- **/tmp**: Archivos temporales (un enlace simbólico a `/private/tmp`). Las instalaciones antiguas solían limpiar periódicamente los archivos temporales antiguos, a veces después de tres días, pero el momento de la limpieza actual depende del sistema y de las políticas; no confíes en que los datos permanezcan allí.
- **/Users**: Directorio de inicio de los usuarios.
- **/usr**: Configuración y binarios del sistema
- **/var**: Archivos de log
- **/Volumes**: Aquí aparecen los volúmenes montados.
- **/.vol**: Al ejecutar `stat a.txt`, obtienes algo parecido a `16777223 7545753 -rw-r--r-- 1 username wheel ...`, donde el primer número es el ID del volumen en el que se encuentra el archivo y el segundo es el número de inode. Puedes acceder al contenido de este archivo a través de /.vol/ con esa información ejecutando `cat /.vol/16777223/7545753`

### Carpetas de aplicaciones

- Las **aplicaciones del sistema** se encuentran en `/System/Applications`
- Las aplicaciones **instaladas** suelen instalarse en `/Applications` o en `~/Applications`
- Los **datos de las aplicaciones** pueden encontrarse en `/Library/Application Support` para las aplicaciones que se ejecutan como root y en `~/Library/Application Support` para las aplicaciones que se ejecutan como usuario.
- Los **daemons** de aplicaciones de terceros que **deben ejecutarse como root** suelen estar en `/Library/PrivilegedHelperTools/`.
- Las apps **sandboxed** se asignan a la carpeta `~/Library/Containers`. Cada app tiene una carpeta con el nombre de su bundle ID (`com.apple.Safari`).
- El **kernel** se encuentra en `/System/Library/Kernels/kernel`
- Las **extensiones del kernel de Apple** se encuentran en `/System/Library/Extensions`
- Las **extensiones del kernel de terceros** se almacenan en `/Library/Extensions`

### Archivos con información sensible

macOS almacena información sensible, incluidas credenciales, en varios lugares:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Instaladores pkg vulnerables


{{#ref}}
macos-installers-abuse.md
{{#endref}}

Para ver la diferencia entre el volumen Data, que permite escritura, y el volumen System sellado que aparece en esta jerarquía, consulta [macOS Sealed System Volume & DataVault](../macos-security-protections/macos-sealed-system-volume-and-datavault.md).

## Extensiones específicas de OS X

- **`.dmg`**: Los archivos Apple Disk Image son muy comunes para los instaladores.
- **`.kext`**: Debe seguir una estructura específica y es la versión de OS X de un driver. (es un bundle)
- **`.plist`**: Un property list almacena información estructurada en formato XML o binario.
  - Puede ser XML o binario. Los archivos binarios se pueden leer con:
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Un bundle de aplicación que sigue la estructura de directorios estándar de macOS.
- **`.dylib`**: Librerías dinámicas (como los archivos DLL de Windows)
- **`.pkg`**: Los paquetes de instalación flat modernos son archivos XAR, pero `.pkg` es un formato de instalador, no un sinónimo de XAR. Los paquetes de instalación antiguos con estructura de bundle son directorios. Consulta [macOS installers](macos-installers-abuse.md) para ver la estructura y la inspección de paquetes. <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`**: Este archivo se encuentra en cada directorio y guarda sus atributos y personalizaciones.
- **`.Spotlight-V100`**: Esta carpeta aparece en el directorio raíz de cada volumen del sistema.
- **`.metadata_never_index`**: Si este archivo está en la raíz de un volumen, Spotlight no indexará ese volumen.
- **`.noindex`**: Los archivos y carpetas con esta extensión no serán indexados por Spotlight.
- **`.sdef`**: Un archivo de definición de scripting que describe cómo AppleScript puede interactuar con una aplicación.

### Bundles de macOS

Un bundle es un directorio con una jerarquía estandarizada que Finder puede mostrar como un único objeto; los bundles de aplicaciones usan la extensión `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

En macOS e iOS, las librerías y frameworks del sistema de uso común se preenlazan en la **dyld shared cache**, lo que mejora el rendimiento de inicio de las aplicaciones. Aunque se trata como una única caché lógica, las versiones actuales pueden almacenarla como una caché principal y varios archivos de subcaché, en lugar de literalmente en un solo archivo. Su formato y ubicación son detalles de implementación que cambian según la versión del sistema operativo. <sup>[[3]](#references)</sup>

En macOS se encuentra en `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` y en versiones anteriores es posible que encuentres la **shared cache** en **`/System/Library/dyld/`**.\
En iOS puedes encontrarlas en **`/System/Library/Caches/com.apple.dyld/`**.

Al igual que la dyld shared cache, el kernel y las extensiones del kernel también se compilan en una kernel cache, que se carga durante el arranque.

Las versiones antiguas se podían extraer con [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Es posible que esa build no admita los formatos de caché actuales; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) es otra opción:

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> Ten en cuenta que, aunque la herramienta `dyld_shared_cache_util` no funcione, puedes pasarle a **Hopper el binario dyld compartido** y Hopper podrá identificar todas las bibliotecas y dejarte **seleccionar cuál** quieres investigar:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Algunos extractores no funcionarán porque los dylibs están preenlazados con direcciones codificadas, por lo que podrían saltar a direcciones desconocidas.

> [!TIP]
> También es posible descargar la Shared Library Cache de otros dispositivos \*OS en macOS usando un emulador en Xcode. Se descargarán en: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, como:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Asignación de SLC

**`dyld`** usa la syscall **`shared_region_check_np`** para comprobar si se ha asignado la SLC (que devuelve la dirección) y **`shared_region_map_and_slide_np`** para asignar la SLC.

Ten en cuenta que, aunque la SLC se reubique en el primer uso, todos los **procesos** usan la **misma copia**, lo que **eliminó la protección ASLR** si el atacante podía ejecutar procesos en el sistema. Esto se explotó en el pasado y se corrigió con shared region pager.

Branch pools son pequeños dylibs Mach-O que crean espacios reducidos entre las asignaciones de imágenes, lo que hace imposible interponer las funciones.

### Restricciones del entorno de shared cache

`DYLD_SHARED_CACHE_DIR` indica un directorio de caché, mientras que `DYLD_SHARED_REGION` selecciona un modo de shared region. La grafía anterior `DYLD_DHARED_REGION` no era válida, y `avoid` no es un valor válido para `DYLD_SHARED_CACHE_DIR`. La versión actual de dyld restringe el modo `private` según el permiso de AMFI para usar shared caches personalizadas, por lo que establecer variables de entorno por sí solo no demuestra que un proceso pueda cargar una caché de reemplazo. <sup>[[10]](#references)</sup>

## Permisos especiales de archivos

### Permisos de carpetas

En un directorio, **read** permite listar las entradas, **write** permite crear o eliminar entradas, y **execute** permite recorrerlo. Por tanto, un usuario que puede leer un archivo, pero no recorrer un directorio principal, no puede acceder a ese archivo mediante su ruta. <sup>[[4]](#references)</sup>

### Modificadores de flags

Los archivos pueden tener flags que alteran su comportamiento. Inspecciona los flags de un directorio con `ls -lO /path/directory`.

- **`uchg`**: Conocido como flag **uchange**, **impide cualquier acción** que modifique o elimine el **archivo**. Para establecerlo, ejecuta: `chflags uchg file.txt`
  - El propietario del archivo o root pueden quitar este flag de **usuario** con `chflags nouchg file.txt`; no ofrece protección frente a ninguno de ellos. El flag de inmutabilidad de **sistema** independiente (`schg`) está restringido a root. <sup>[[11]](#references)</sup>
- **`restricted`**: Este flag hace que el archivo esté **protegido por SIP** (no puedes añadir este flag a un archivo).
- **`Sticky bit`**: En un directorio con el sticky bit establecido, solo el propietario del archivo, el propietario del directorio o root pueden renombrar o eliminar una entrada. Normalmente está habilitado en `/tmp` para impedir que los usuarios eliminen o muevan archivos de otros usuarios.

Todos los flags están definidos en el archivo `sys/stat.h` (búscalo con `mdfind stat.h | grep stat.h`) y son:

- `UF_SETTABLE` 0x0000ffff: Máscara de flags que puede cambiar el propietario.
- `UF_NODUMP` 0x00000001: No volcar el archivo.
- `UF_IMMUTABLE` 0x00000002: El archivo no se puede modificar.
- `UF_APPEND` 0x00000004: Solo se pueden añadir datos al archivo.
- `UF_OPAQUE` 0x00000008: El directorio es opaco con respecto a union.
- `UF_COMPRESSED` 0x00000020: El archivo está comprimido (algunos sistemas de archivos).
- `UF_TRACKED` 0x00000040: No se notifican eliminaciones ni cambios de nombre de archivos que tengan este flag.
- `UF_DATAVAULT` 0x00000080: Se requiere un entitlement para leer y escribir.
- `UF_HIDDEN` 0x00008000: Indica que este elemento no debería mostrarse en una GUI.
- `SF_SUPPORTED` 0x009f0000: Máscara de flags compatibles con el superusuario.
- `SF_SETTABLE` 0x3fff0000: Máscara de flags que puede cambiar el superusuario.
- `SF_SYNTHETIC` 0xc0000000: Máscara de flags sintéticos de solo lectura del sistema.
- `SF_ARCHIVED` 0x00010000: El archivo está archivado.
- `SF_IMMUTABLE` 0x00020000: El archivo no se puede modificar.
- `SF_APPEND` 0x00040000: Solo se pueden añadir datos al archivo.
- `SF_RESTRICTED` 0x00080000: Se requiere un entitlement para escribir.
- `SF_NOUNLINK` 0x00100000: El elemento no se puede eliminar, renombrar ni usar como punto de montaje.
- `SF_FIRMLINK` 0x00800000: El archivo es un firmlink.
- `SF_DATALESS` 0x40000000: El archivo es un objeto sin datos.

### **ACL de archivos**

Las **ACL** de archivos contienen **ACE** (entradas de control de acceso) que permiten asignar **permisos más granulares** a distintos usuarios.

Es posible conceder estos permisos a un **directorio**: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Para un **archivo**: `read`, `write`, `append` y `execute`.

Cuando el archivo contiene ACL, verás un **"+" al listar los permisos, como en**:

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

Puedes encontrar **todos los archivos con ACL** con el siguiente comando (esto es muy lento):

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### Atributos extendidos

Los atributos extendidos son valores de metadatos con nombre que se almacenan por separado de los atributos ordinarios de un archivo. Enuméralos con `ls -l@` e inspecciónalos o modifícalos con `xattr`. <sup>[[5]](#references)</sup> Algunos atributos extendidos comunes son:

- `com.apple.resourceFork`: compatibilidad con la bifurcación de recursos. También es visible como `filename/..namedfork/rsrc`
- `com.apple.quarantine`: metadatos de cuarentena de macOS Gatekeeper
- `metadata:*`: metadatos de macOS, como `_backup_excludeItem` o `kMD*`
- `com.apple.lastuseddate` (#PS): fecha del último uso del archivo
- `com.apple.FinderInfo`: información de macOS Finder, como las etiquetas de color
- `com.apple.TextEncoding`: especifica la codificación de texto de los archivos de texto ASCII
- `com.apple.logd.metadata`: lo usa logd en archivos de `/var/db/diagnostics`
- `com.apple.genstore.*`: almacenamiento generacional (`/.DocumentRevisions-V100` en la raíz del sistema de archivos)
- `com.apple.rootless`: metadatos de macOS asociados con System Integrity Protection
- `com.apple.uuidb.boot-uuid`: marcas de logd de épocas de arranque con UUID único
- `com.apple.decmpfs`: metadatos de compresión transparente de archivos de macOS
- `com.apple.cprotect`: \*OS: datos de cifrado por archivo (III/11)
- `com.apple.installd.*`: \*OS: metadatos usados por installd, p. ej., `installType`, `uniqueInstallID`

### Bifurcaciones de recursos | macOS ADS

Las bifurcaciones de recursos proporcionan un flujo de datos alternativo en macOS. El contenido puede almacenarse en el atributo extendido `com.apple.ResourceFork` y accederse mediante `file/..namedfork/rsrc`.

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

El atributo extendido `com.apple.decmpfs` almacena metadatos para la compresión transparente; no indica cifrado. Según el formato de compresión, los datos comprimidos pueden almacenarse en el atributo o en una bifurcación de recursos, y se descomprimen de forma transparente al leerlos.

El indicador `UF_COMPRESSED` aparece como `compressed` en `ls -lO`. No lo borres manualmente: hacerlo puede provocar que el sistema interprete incorrectamente la representación comprimida.

El comando que borra el indicador se muestra aquí porque resulta útil durante una revisión forense, pero ejecutarlo en un archivo comprimido puede hacer que parezca vacío o inaccesible hasta que se repare sus metadatos:

```bash
chflags nocompressed /path/to/file
```

La utilidad integrada `/usr/bin/afscexpand` puede forzar la expansión de archivos comprimidos de forma transparente. La utilidad independiente de terceros `afsctool` también puede inspeccionar o descomprimir archivos comprimidos con el sistema de archivos de Apple, pero no debe confundirse con el comando integrado. <sup>[[8]](#references)</sup>


### Ubicaciones de configuración interesantes (macOS)

| Ruta / Ubicación | Propósito / Qué configura | Seguridad / Potencial de ataque |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Almacena los archivos plist de indicadores de funciones de Apple que controlan comportamientos opcionales o experimentales en los daemons / frameworks del sistema | Si un atacante puede eludir SIP u obtener privilegios, manipular estos archivos podría habilitar rutas de código ocultas o desactivar medidas de protección |
| `/System/Library/CoreServices/systemVersion.plist` | Contiene metadatos de la versión de macOS (ProductVersion, BuildVersion) que las aplicaciones / instaladores utilizan para decidir qué comportamientos aplicar | La modificación puede engañar a aplicaciones o instaladores para que acepten versiones de SO no compatibles o desbloqueen funciones |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Preferencias de aplicaciones / del sistema | Si se pueden escribir, los atacantes pueden inyectar ajustes para dirigir el comportamiento de las aplicaciones, desactivar protecciones o provocar una configuración incorrecta |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Definiciones plist de daemons y agents en segundo plano | La inserción o manipulación de plist (si los permisos lo permiten) habilita persistencia o escaladas de privilegios |
| `/etc/hosts` | Asignaciones de nombres de host ↔ IP que utiliza el resolvedor DNS del sistema | Redirección de nombres de dominio, interceptación de tráfico y suplantación de servicios bajo control local |
| `/etc/sudoers` | Define quién puede ejecutar comandos con `sudo` y en qué condiciones | Un archivo sudoers manipulado puede conceder acceso root o privilegios indebidos a cuentas de atacantes |
| `/private/var/db/dslocal/nodes/Default/users/` | Archivos plist que definen las cuentas de usuario locales | La manipulación permite crear o modificar cuentas de usuario, hashes de contraseñas o metadatos de usuario |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Extensiones del kernel / drivers | Instalar o modificar kexts puede dar lugar a control a nivel del kernel; están fuertemente protegidos por SIP / políticas de firma |
| `/private/var/db/SystemPolicyConfiguration/` | Almacena la configuración para la aplicación de políticas del sistema (p. ej., Gatekeeper, notarización) | Manipular estos archivos puede permitir eludir comprobaciones de políticas o reglas de confianza |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Binarios auxiliares de SSH y archivos de configuración | Una configuración incorrecta puede debilitar la seguridad de SSH, permitir accesos no autorizados o habilitar algoritmos inseguros |
| `/System/Library/Sandbox/Profiles` | Perfiles de sandbox del sistema (SBPL) que se utilizan para restringir las acciones de los procesos | Reemplazar o alterar perfiles puede abrir vectores de escape del sandbox o debilitar el aislamiento |

> **Nota**: Muchas de estas rutas se encuentran en directorios protegidos por SIP (p. ej., `/System`) y están protegidas contra escritura, salvo que SIP esté desactivado o se eluda.  


## Binarios universales y formato Mach-O

Mach-O es el formato ejecutable nativo de macOS. Un binario universal, o fat, agrupa varios slices de Mach-O específicos de cada arquitectura en un solo archivo; la página dedicada explica ambos formatos:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Volcado de memoria de macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Riesgo de archivos y metadatos de gestores

LaunchServices, la cuarentena de archivos y Gatekeeper influyen conjuntamente en cómo macOS gestiona los archivos descargados y selecciona aplicaciones para extensiones y esquemas de URL. Sus bases de datos y archivos de recursos internos cambian entre versiones; consulta las páginas dedicadas en lugar de tratar una ruta privada de CoreTypes como una interfaz de políticas estable:

En las versiones que exponen los metadatos de riesgo heredados de CoreTypes en `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, las categorías habituales son:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: contenido considerado suficientemente seguro para abrirse automáticamente según la política de aplicación correspondiente.
- **`LSRiskCategoryNeutral`**: contenido que normalmente no genera una advertencia ni se abre automáticamente.
- **`LSRiskCategoryUnsafeExecutable`**: contenido ejecutable para el que el usuario debería recibir una advertencia de la aplicación.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: contenedores como archivos comprimidos que pueden incluir contenido ejecutable y requieren una inspección adicional.

Estos son detalles de implementación, no una API pública de políticas estable; confirma los metadatos reales y el comportamiento de Safari/Gatekeeper en la versión de macOS que estés probando.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Archivos de registro

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contiene información sobre los archivos descargados, como la URL desde la que se descargaron.
- **Registro unificado**: En las versiones actuales de macOS, consulta los eventos del sistema y las aplicaciones con `log show` y `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** y **`/private/var/log/asl/*.asl`**: Artefactos de registro heredados que aún pueden ser relevantes en sistemas antiguos. En esas versiones, `/System/Library/LaunchDaemons/com.apple.syslogd.plist` configura `syslogd`; `launchctl list | grep com.apple.syslogd` puede ayudar a determinar si el servicio está cargado.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Almacena los archivos y aplicaciones a los que se ha accedido recientemente mediante "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Ruta de preferencias heredada asociada a los elementos de inicio de sesión; las versiones modernas de macOS usan mecanismos adicionales.
- **`$HOME/Library/Logs/DiskUtility.log`**: Registro heredado de Disk Utility que puede contener información sobre unidades, incluidos dispositivos USB.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Datos sobre puntos de acceso inalámbricos.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Datos heredados de sobrescritura de launchd.



## References

- [1] [Apple - Guía de programación del sistema de archivos](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Guía de programación de bundles](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Foros para desarrolladores de Apple - Descripción general de la caché compartida de dyld](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Guía de programación del sistema de archivos: seguridad del sistema de archivos de macOS](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - Página del manual de macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - Página del manual de macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - Página del manual de macOS](https://manp.gs/mac/1/afscexpand)
- [9] [Foros para desarrolladores de Apple - Desempaquetado de archivos de Apple](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld - DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple - Seguridad de scripts de shell: indicadores especiales de permisos de archivos](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple - Tareas de firma de código: paquetes de instalación](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
