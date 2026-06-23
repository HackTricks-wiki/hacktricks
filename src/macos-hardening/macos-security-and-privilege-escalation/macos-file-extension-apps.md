# Controladores de apps de extensiones de archivo y esquemas URL en macOS

{{#include ../../banners/hacktricks-training.md}}

## Base de datos de LaunchServices

Esta es una base de datos de todas las aplicaciones instaladas en macOS que se puede consultar para obtener información sobre cada aplicación instalada, como los **URL schemes** compatibles, los **document types**, los **UTIs** y los controladores predeterminados.

Es posible volcar esta base de datos con:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
O usando la herramienta [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** es el cerebro de la base de datos. Proporciona **varios servicios XPC** como `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, y más. Pero también **requiere algunos entitlements** para que las aplicaciones puedan usar las funcionalidades XPC expuestas, como `.launchservices.changedefaulthandler` o `.launchservices.changeurlschemehandler` para cambiar las apps por defecto para tipos MIME o esquemas URL y otros.

**`/System/Library/CoreServices/launchservicesd`** reclama el servicio `com.apple.coreservices.launchservicesd` y se puede consultar para obtener información sobre las aplicaciones en ejecución. Se puede consultar con la herramienta del sistema **`/usr/bin/lsappinfo`** o con [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Desde la perspectiva de un operador, ten en cuenta que normalmente hay **dos vistas útiles**:

- La **base de datos de registro** gestionada por LaunchServices / `lsd` (respaldada por archivos `.csstore`).
- Los **defaults efectivos por usuario** almacenados en `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` dentro del array `LSHandlers`.

Esta distinción importa: una aplicación puede estar **registrada** como capaz de manejar un tipo o esquema, pero el **default actual** puede seguir siendo otro bundle ID.

## File Extension & URL scheme app handlers

La siguiente línea puede ser útil para encontrar las aplicaciones que pueden abrir archivos dependiendo de la extensión:
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
También puedes comprobar las extensiones compatibles por una aplicación haciendo:
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
## Enumerando handlers efectivos

El archivo más útil para los **defaults del usuario actual** suele ser:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Para volcar los handlers de **URL scheme** desde él:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Para volcar los handlers de **content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Para resolver el árbol UTI de un archivo de ejemplo:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Si quieres una CLI más amigable para consultar o cambiar defaults:
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
## Claves interesantes de Info.plist

Al analizar un bundle de aplicación, estas claves son las más importantes:

- **`CFBundleDocumentTypes`**: grupos de documentos que el bundle declara que puede abrir.
- **`LSItemContentTypes`**: la forma **moderna / preferida** de vincular tipos de documento a UTIs.
- **`LSHandlerRank`**: rango usado por LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: esquemas URI personalizados implementados por la app.
- **`UTExportedTypeDeclarations`**: UTIs que la app **posee**.
- **`UTImportedTypeDeclarations`**: UTIs que la app no posee pero quiere que el sistema reconozca.

Un comando útil para un análisis rápido es:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Un detalle sutil pero importante: si **`LSItemContentTypes`** está presente, las claves antiguas como **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** y **`CFBundleTypeOSTypes`** son, en la práctica, datos de compatibilidad heredada. Para la resolución real del handler, céntrate primero en la ruta UTI.

## Offensive notes

Las aplicaciones no necesitan ejecutarse para volverse interesantes. Un bundle `.app` soltado o clonado puede ser **parsed automatically by `lsd` as soon as it is written to disk**, y sus tipos de documento / esquemas URL declarados pueden registrarse sin que el usuario llegue a lanzar nunca el bundle.

Esto es útil tanto para la investigación de **persistence / hijacking** como para cadenas de **initial-access**:

- Una app maliciosa puede reclamar una **rare extension** o una **custom UTI** y esperar a que la víctima abra el archivo señuelo.
- Una app maliciosa puede registrar un **custom URL scheme** accesible desde un browser, una app Electron, un documento office, un chat client o otra app helper.
- Si editas un bundle de una app después de compilarlo, puedes forzar a LaunchServices a volver a parsearlo con:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Al probar bundles sospechosos, presta especial atención a:

- **`LSHandlerRank=Owner`** en tipos poco comunes.
- Matrices **`CFBundleDocumentTypes`** amplias que reclaman muchas extensiones.
- **Helper / wrapper apps** cuyo único comportamiento interesante está detrás de un document o URI handler.
- Archivos parecidos a **shortcut** (`.webloc`, `.inetloc`, `.fileloc`) que terminan enviando la ejecución a LaunchServices. Para trucos de estilo `.fileloc` y ángulos relacionados con Gatekeeper, revisa [esta otra página](macos-security-protections/macos-fs-tricks/README.md).

Si tu objetivo es la ejecución pasiva de código simplemente al navegar a una carpeta o seleccionar un archivo, revisa también la página dedicada a [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), ya que esa es una superficie de file-handler diferente pero estrechamente relacionada.

## References

- [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
{{#include ../../banners/hacktricks-training.md}}
