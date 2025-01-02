# Controladores de aplicaciones de extensión de archivo y esquema de URL de macOS

{{#include ../../banners/hacktricks-training.md}}

## Base de datos de LaunchServices

Esta es una base de datos de todas las aplicaciones instaladas en macOS que se puede consultar para obtener información sobre cada aplicación instalada, como los esquemas de URL que admite y los tipos MIME.

Es posible volcar esta base de datos con:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
O usando la herramienta [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** es el cerebro de la base de datos. Proporciona **varios servicios XPC** como `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, y más. Pero también **requiere algunos derechos** para que las aplicaciones puedan usar las funcionalidades XPC expuestas, como `.launchservices.changedefaulthandler` o `.launchservices.changeurlschemehandler` para cambiar aplicaciones predeterminadas para tipos MIME o esquemas de URL y otros.

**`/System/Library/CoreServices/launchservicesd`** reclama el servicio `com.apple.coreservices.launchservicesd` y se puede consultar para obtener información sobre las aplicaciones en ejecución. Se puede consultar con la herramienta del sistema /**`usr/bin/lsappinfo`** o con [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

## Controladores de aplicaciones de extensión de archivo y esquema de URL

La siguiente línea puede ser útil para encontrar las aplicaciones que pueden abrir archivos dependiendo de la extensión:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
O utiliza algo como [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
También puedes verificar las extensiones soportadas por una aplicación haciendo:
```
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
{{#include ../../banners/hacktricks-training.md}}
