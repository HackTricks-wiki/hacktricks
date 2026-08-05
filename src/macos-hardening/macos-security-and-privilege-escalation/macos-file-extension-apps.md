# Controladores de extensiones de archivo y esquemas de URL en macOS

{{#include ../../banners/hacktricks-training.md}}

## Base de datos de LaunchServices

Esta es una base de datos de todas las aplicaciones instaladas en macOS que se puede consultar para obtener información sobre cada aplicación instalada, como los **esquemas de URL**, los **tipos de documentos**, los **UTI** y los controladores predeterminados.

Es posible volcar esta base de datos con:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
O usando la herramienta [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** es el cerebro de la base de datos. Proporciona **varios servicios XPC**, como `.lsd.installation`, `.lsd.open`, `.lsd.openurl` y otros. Sin embargo, también **requiere ciertos entitlements** para que las aplicaciones puedan usar las funcionalidades XPC expuestas, como `.launchservices.changedefaulthandler` o `.launchservices.changeurlschemehandler`, para cambiar las aplicaciones predeterminadas para tipos MIME o esquemas de URL, entre otras.

**`/System/Library/CoreServices/launchservicesd`** reclama el servicio `com.apple.coreservices.launchservicesd` y se puede consultar para obtener información sobre las aplicaciones en ejecución. Se puede consultar con la herramienta del sistema **`/usr/bin/lsappinfo`** o con [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Desde la perspectiva de un operador, ten en cuenta que normalmente hay **dos vistas útiles**:

- La **base de datos de registro** gestionada por LaunchServices / `lsd` (respaldada por archivos `.csstore`).
- Los **valores predeterminados efectivos por usuario** almacenados en `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, dentro del array `LSHandlers`.

Esta distinción es importante: una aplicación puede estar **registrada** como capaz de gestionar un tipo o esquema, pero el **valor predeterminado actual** puede seguir siendo otro bundle ID.

## Gestores de aplicaciones para extensiones de archivo y esquemas de URL

La siguiente línea puede ser útil para encontrar las aplicaciones que pueden abrir archivos según la extensión:
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
También puedes comprobar las extensiones compatibles con una aplicación haciendo:
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
## Enumeración de manejadores efectivos

El archivo más útil para los **valores predeterminados del usuario actual** suele ser:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Para volcar los handlers de **URL scheme** desde él:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Para volcar los controladores de **content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Para resolver el árbol UTI de un archivo de muestra:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Si quieres una CLI más amigable para consultar o cambiar los valores predeterminados:
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

Al hacer triage de un application bundle, estas claves son las más importantes:

- **`CFBundleDocumentTypes`**: grupos de documentos que el bundle afirma poder abrir.
- **`LSItemContentTypes`**: la forma **moderna / preferida** de asociar tipos de documentos con UTIs.
- **`LSHandlerRank`**: clasificación utilizada por LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: esquemas URI personalizados implementados por la app.
- **`UTExportedTypeDeclarations`**: UTIs de las que la app es **propietaria**.
- **`UTImportedTypeDeclarations`**: UTIs de las que la app no es propietaria, pero que quiere que el sistema reconozca.

Un comando útil para un triage rápido es:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Un detalle sutil pero importante: si **`LSItemContentTypes`** está presente, las claves antiguas como **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** y **`CFBundleTypeOSTypes`** son, en la práctica, datos de compatibilidad heredados. Para la resolución real de handlers, prioriza primero la ruta UTI.

## Notas ofensivas

Las aplicaciones no necesitan ejecutarse para resultar interesantes. Un bundle `.app` depositado o clonado puede ser **analizado automáticamente por `lsd` en cuanto se escribe en el disco**, y sus tipos de documentos / esquemas URL declarados pueden registrarse sin que el usuario llegue a iniciar el bundle.

Esto resulta útil tanto para la **investigación de persistence / hijacking** como para **cadenas de initial access**:

- Una app maliciosa puede reclamar una **extensión poco común** o una **UTI personalizada** y esperar a que la víctima abra el archivo señuelo.
- Una app maliciosa puede registrar un **esquema URL personalizado** accesible desde un navegador, una app de Electron, un documento de Office, un cliente de chat u otra app auxiliar.<sup>[[1]](#references)</sup>
- Si editas un bundle de app después de compilarlo, puedes forzar a LaunchServices a volver a analizarlo con:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Al probar bundles sospechosos, presta especial atención a:

- **`LSHandlerRank=Owner`** en tipos poco comunes.
- Arrays **`CFBundleDocumentTypes`** amplios que afirman admitir muchas extensiones.
- Apps helper / wrapper cuyo único comportamiento interesante se encuentra detrás de un handler de documentos o URI.
- Archivos similares a accesos directos (`.webloc`, `.inetloc`, `.fileloc`) que terminan delegando en LaunchServices. Para trucos de tipo `.fileloc` y otros ángulos relacionados con Gatekeeper, consulta [esta otra página](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Si tu objetivo es lograr code-execution pasiva simplemente al navegar a una carpeta o seleccionar un archivo, consulta también la página dedicada a los [generadores de Quick Look](macos-proces-abuse/macos-quicklook-generators.md), ya que se trata de una superficie de file handlers diferente, aunque estrechamente relacionada.

## Referencias

- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
