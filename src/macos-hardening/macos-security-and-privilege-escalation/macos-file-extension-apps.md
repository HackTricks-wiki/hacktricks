# Gestionnaires d'applications pour les extensions de fichiers macOS et les schémas d'URL

{{#include ../../banners/hacktricks-training.md}}

## Base de données LaunchServices

C'est une base de données de toutes les applications installées sur macOS qui peut être interrogée pour obtenir des informations sur chaque application installée, telles que les schémas d'URL qu'elle prend en charge et les types MIME.

Il est possible d'extraire cette base de données avec :
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ou en utilisant l'outil [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** est le cerveau de la base de données. Il fournit **plusieurs services XPC** comme `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, et plus encore. Mais il **nécessite également certaines attributions** aux applications pour pouvoir utiliser les fonctionnalités XPC exposées, comme `.launchservices.changedefaulthandler` ou `.launchservices.changeurlschemehandler` pour changer les applications par défaut pour les types mime ou les schémas d'url, et d'autres.

**`/System/Library/CoreServices/launchservicesd`** revendique le service `com.apple.coreservices.launchservicesd` et peut être interrogé pour obtenir des informations sur les applications en cours d'exécution. Il peut être interrogé avec l'outil système /**`usr/bin/lsappinfo`** ou avec [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

## Gestionnaires d'applications pour les extensions de fichiers et les schémas d'URL

La ligne suivante peut être utile pour trouver les applications qui peuvent ouvrir des fichiers en fonction de l'extension :
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Ou utilisez quelque chose comme [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps) :
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Vous pouvez également vérifier les extensions prises en charge par une application en faisant :
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
