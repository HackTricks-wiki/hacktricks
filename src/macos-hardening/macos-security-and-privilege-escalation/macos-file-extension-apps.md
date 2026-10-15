# Controladores de apps de macOS para extensiones de archivo y esquemas URL

{{#include ../../banners/hacktricks-training.md}}

## Base de datos de LaunchServices

Esta es una base de datos de todas las aplicaciones instaladas en macOS que se puede consultar para obtener información sobre cada aplicación instalada, como los **esquemas URL**, los **tipos de documento**, los **UTI** y los controladores predeterminados compatibles.

Es posible volcar esta base de datos con:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

O usando la herramienta [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** es el cerebro de la base de datos. Proporciona **varios servicios XPC**, como `.lsd.installation`, `.lsd.open`, `.lsd.openurl` y otros. Pero también **requiere que las aplicaciones tengan ciertos entitlements** para poder usar las funcionalidades XPC expuestas, como `.launchservices.changedefaulthandler` o `.launchservices.changeurlschemehandler`, para cambiar las aplicaciones predeterminadas para tipos MIME o esquemas URL, entre otras.

**`/System/Library/CoreServices/launchservicesd`** anuncia el servicio `com.apple.coreservices.launchservicesd` y se le puede consultar para obtener información sobre las aplicaciones en ejecución. Se puede consultar con la herramienta del sistema **`/usr/bin/lsappinfo`** o con [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Desde la perspectiva de un operador, ten en cuenta que normalmente hay **dos vistas útiles**:

- La **base de datos de registro** gestionada por LaunchServices / `lsd` (respaldada por archivos `.csstore`).
- Los **valores predeterminados efectivos por usuario**, almacenados en `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, dentro del array `LSHandlers`.

Esta distinción es importante: una aplicación puede estar **registrada** para manejar un tipo o esquema, pero la **aplicación predeterminada actual** puede seguir siendo otro bundle ID.

En las versiones recientes de macOS, la búsqueda de aplicaciones para registrar no se limita a `/Applications`: las apps ubicadas en otras carpetas accesibles y visibles para Spotlight, así como en volúmenes montados o compartidos, pueden aparecer en el registro. Por tanto, durante el análisis, conserva la información de `path` y del volumen obtenida con `lsregister -dump` y no des por sentado que anular el registro de una aplicación será permanente mientras el bundle siga siendo detectable.<sup>[[4]](#references)</sup>

## Controladores de extensiones de archivo y esquemas URL

La siguiente línea puede ser útil para encontrar las aplicaciones que pueden abrir archivos según su extensión:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```

O usa algo como [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):

```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```

También puedes comprobar las extensiones compatibles con una aplicación haciendo lo siguiente:

```bash
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
				<string>css</string>
				<string>pdf</string>
				<string>webarchive</string>
				<string>webbookmark</string>
				<string>webhistory</string>
				<string>webloc</string>
				<string>download</string>
				<string>safariextz</string>
				<string>gif</string>
				<string>html</string>
				<string>htm</string>
				<string>js</string>
				<string>jpg</string>
				<string>jpeg</string>
				<string>jp2</string>
				<string>txt</string>
				<string>text</string>
				<string>png</string>
				<string>tiff</string>
				<string>tif</string>
				<string>url</string>
				<string>ico</string>
				<string>xhtml</string>
				<string>xht</string>
				<string>xml</string>
				<string>xbl</string>
				<string>svg</string>
```

## Enumerar los handlers efectivos

El archivo más útil para los **valores predeterminados del usuario actual** suele ser:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Para hacer dump de los handlers de **URL scheme** desde allí:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Para volcar los manejadores de **content-type / UTI**:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Para resolver el árbol UTI de un archivo de muestra:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

Si quieres una CLI más intuitiva para consultar o cambiar los valores predeterminados:

```bash
# Classic tool
# https://github.com/moretension/duti
duti -x jpg                    # Show current default for extension
duti -s com.apple.Safari public.html all
duti -s com.apple.Finder ftp   # Set default for ftp://

# Newer tool
# https://github.com/jackchuka/dutix
dutix targets show public.html
dutix targets show ftp
dutix apps show Safari
```

### Overrides `Open With` por archivo

La resolución del controlador también tiene una capa **específica para cada archivo**. Antes de recurrir al UTI del archivo y al valor predeterminado global del usuario, LaunchServices comprueba el atributo extendido `com.apple.LaunchServices.OpenWith`. Finder lo crea cuando se selecciona **Abrir siempre con** para un archivo; su valor es una lista de propiedades binaria que contiene una ruta de aplicación, un identificador de paquete y un selector de versión.<sup>[[3]](#references)</sup>

Inspecciónalo y decodifícalo sin confiar en la extensión del nombre de archivo:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Esto resulta útil cuando un único señuelo se abre con una aplicación inesperada, aunque `duti`, `dutix` o `LSHandlers` indiquen un valor predeterminado global benigno. En un laboratorio controlado, se puede copiar el valor opaco exacto de un archivo configurado mediante Finder; al eliminarlo, se restaura la resolución normal basada en el tipo:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Claves interesantes de Info.plist

Al hacer una revisión inicial de un bundle de aplicación, estas claves son las más importantes:

- **`CFBundleDocumentTypes`**: grupos de documentos que el bundle afirma que puede abrir.
- **`LSItemContentTypes`**: la forma **moderna / preferida** de asociar tipos de documentos con UTIs.
- **`LSHandlerRank`**: clasificación que usa LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: esquemas de URI personalizados que implementa la app.
- **`UTExportedTypeDeclarations`**: UTIs de los que la app es **propietaria**.
- **`UTImportedTypeDeclarations`**: UTIs de los que la app no es propietaria, pero que quiere que el sistema reconozca.

Un comando útil para una revisión inicial rápida es:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Un detalle sutil pero importante: si está presente **`LSItemContentTypes`**, las claves antiguas, como **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** y **`CFBundleTypeOSTypes`**, son, en la práctica, datos heredados de compatibilidad. Para resolver qué manejador se usa realmente, prioriza primero la ruta UTI.

## Notas ofensivas

Las aplicaciones no necesitan ejecutarse para que sus declaraciones como manejador resulten interesantes, pero **escribir un bundle `.app` por sí solo no garantiza que se registre de inmediato**. Finder puede registrar una aplicación al descubrirla, incluso cuando un usuario explora su carpeta; el registro también puede ocurrir durante el arranque o el inicio de sesión, o mediante una llamada explícita de registro. Comprueba `lsregister -dump` antes de probar una declaración. El registro por sí solo no inicia la aplicación ni hace que sea el manejador predeterminado efectivo.<sup>[[5]](#references)</sup> Para conocer los requisitos previos de persistencia, consulta [URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices).

Esto resulta útil tanto para la **investigación de persistencia / secuestro** como para las **cadenas de acceso inicial**:

- Una aplicación maliciosa puede declarar una **extensión poco común** o una **UTI personalizada** y esperar a que la víctima abra el archivo señuelo.
- Una aplicación maliciosa puede registrar un **esquema de URL personalizado** accesible desde un navegador, una aplicación Electron, un documento de Office, un cliente de chat u otra aplicación auxiliar.<sup>[[1]](#references)</sup>
- Para distinguir la resolución predeterminada normal de las pruebas de un manejador candidato específico, invoca el esquema mediante LaunchServices con `open 'targetscheme://host/path?value=test'` y, luego, apunta a un bundle registrado específico con `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Esto resulta útil para auditar cómo la aplicación receptora valida y decodifica componentes de URL controlados por un atacante.<sup>[[1]](#references)</sup>
- Si editas un bundle de aplicación después de compilarlo, puedes forzar a LaunchServices a volver a analizarlo con:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Al probar bundles sospechosos, presta especial atención a:

- **`LSHandlerRank=Owner`** en tipos poco comunes.
- Arrays **`CFBundleDocumentTypes`** amplios que reclamen muchas extensiones.
- Apps auxiliares o wrapper cuyo único comportamiento interesante se active mediante un handler de documentos o URI.
- Archivos similares a accesos directos (`.webloc`, `.inetloc`, `.fileloc`) que terminan delegando en LaunchServices. Para trucos de tipo `.fileloc` y aspectos relacionados con Gatekeeper, consulta [esta otra página](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

### Parámetros URL reenviados a opciones posteriores

La confirmación del protocolo externo de un navegador solo autoriza abrir el handler; no hace que los parámetros de la URL sean fiables. Sigue el parser de URL de la app receptora hasta cualquier biblioteca, motor multimedia, proceso auxiliar u opción de escritura de archivos. Busca un prefijo en las claves de consulta que convierta los campos de la URL en nombres de opciones posteriores. Prueba separadores literales y codificados con porcentajes usando un marcador inocuo en una cuenta desechable.<sup>[[6]](#references)</sup>

Verifica la **opción final aceptada por el componente posterior**, no solo el análisis inicial de la app. Un handler permitía que las claves de consulta con prefijo llegaran a comandos de entrada de mpv; bloquear esa opción aún dejaba disponible una vía de escritura de archivos. Prueba la clase de opciones accesible, no solo una clave peligrosa conocida.<sup>[[7]](#references)</sup>

### Handler integrado `applescript://`

El handler de URL `applescript://com.apple.scripteditor` acepta `action=new` y un parámetro `script` codificado en URL. Por tanto, un enlace del navegador puede abrir Script Editor con AppleScript controlado por el atacante ya cargado en el editor, evitando tener que pegarlo en Terminal. **Esto no ejecuta el script automáticamente**: el navegador puede preguntar si se debe abrir Script Editor, y el usuario debe ejecutar el script.<sup>[[8]](#references)</sup>

Las versiones recientes de macOS pueden mostrar una advertencia sobre el documento de script, mientras que XProtect analiza AppleScript durante la ejecución.<sup>[[8]](#references)[[9]](#references)</sup>

Usa una prueba local inocua para comprobar el handler y los avisos en la versión de macOS evaluada; solo debe rellenar el editor hasta que se haga clic en **Ejecutar**.<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

Si tu objetivo es lograr ejecución pasiva de código con solo navegar a una carpeta o seleccionar un archivo, consulta también la página dedicada a los generadores de Quick Look [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), ya que se trata de una superficie de gestión de archivos diferente, aunque estrechamente relacionada.



## References

- [1] [Objective-See - Explotación remota de Mac mediante esquemas de URL personalizados](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypass de Gate: un análisis más detallado de las fallas de Gatekeeper en macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Cómo abre macOS un archivo en la app correcta](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Control de LaunchServices en macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Conceptos de Launch Services](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - Investigación sobre ejecución de comandos mediante el esquema de URL de IINA](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - Gestión insegura de las opciones de mpv en su esquema de URL](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - La técnica ClickFix usa Script Editor en lugar de Terminal](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Protecciones de Terminal y scripts](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}
