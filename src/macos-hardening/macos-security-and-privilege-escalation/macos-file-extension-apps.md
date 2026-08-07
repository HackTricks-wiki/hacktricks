# Gestionnaires d’extensions de fichiers et de schémas d’URL sur macOS

{{#include ../../banners/hacktricks-training.md}}

## Base de données LaunchServices

Il s’agit d’une base de données regroupant toutes les applications installées sur macOS, qui peut être interrogée afin d’obtenir des informations sur chaque application installée, telles que les **URL schemes**, les **document types**, les **UTIs** et les gestionnaires par défaut.

Il est possible d’exporter cette base de données avec :
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ou en utilisant l’outil [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** est le cerveau de la base de données. Il fournit **plusieurs services XPC** tels que `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, et bien d’autres. Mais il **requiert également certains entitlements** pour que les applications puissent utiliser les fonctionnalités XPC exposées, comme `.launchservices.changedefaulthandler` ou `.launchservices.changeurlschemehandler` pour modifier les applications par défaut pour les types MIME ou les schémas d’URL, entre autres.

**`/System/Library/CoreServices/launchservicesd`** revendique le service `com.apple.coreservices.launchservicesd` et peut être interrogé pour obtenir des informations sur les applications en cours d’exécution. Il peut être interrogé avec l’outil système **`/usr/bin/lsappinfo`** ou avec [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Du point de vue d’un operator, gardez généralement à l’esprit qu’il existe **deux vues utiles** :

- La **base de données d’enregistrement** gérée par LaunchServices / `lsd` (soutenue par les fichiers `.csstore`).
- Les **valeurs par défaut effectives de l’utilisateur** stockées dans `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, dans le tableau `LSHandlers`.

Cette distinction est importante : une application peut être **enregistrée** comme étant capable de gérer un type ou un schéma, alors que le **gestionnaire par défaut actuel** peut toujours être un autre bundle ID.

## Gestionnaires d’applications pour les extensions de fichiers et les schémas d’URL

La ligne suivante peut être utile pour trouver les applications capables d’ouvrir des fichiers en fonction de leur extension :
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
Vous pouvez également vérifier les extensions prises en charge par une application en exécutant :
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
## Énumération des gestionnaires effectifs

Le fichier le plus utile pour les **valeurs par défaut de l'utilisateur actuel** est généralement :
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Pour extraire les gestionnaires de **URL scheme** à partir de celui-ci :
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Pour extraire les gestionnaires de **content-type / UTI** :
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Pour résoudre l’arborescence UTI d’un fichier d’exemple :
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Si vous souhaitez une CLI plus conviviale pour interroger ou modifier les valeurs par défaut :
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
## Clés intéressantes d’Info.plist

Lors de l’analyse initiale d’un bundle d’application, ces clés sont les plus importantes :

- **`CFBundleDocumentTypes`** : groupes de documents que le bundle indique pouvoir ouvrir.
- **`LSItemContentTypes`** : méthode **moderne / préférée** pour associer les types de documents aux UTI.
- **`LSHandlerRank`** : classement utilisé par LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`** : schémas d’URI personnalisés implémentés par l’application.
- **`UTExportedTypeDeclarations`** : UTI dont l’application est **propriétaire**.
- **`UTImportedTypeDeclarations`** : UTI dont l’application n’est pas propriétaire, mais qu’elle souhaite faire reconnaître par le système.

Une commande pratique pour une analyse rapide est :
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Un détail subtil mais important : si **`LSItemContentTypes`** est présent, les anciennes clés telles que **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** et **`CFBundleTypeOSTypes`** sont essentiellement des données de compatibilité legacy. Pour la résolution effective des handlers, concentrez-vous d'abord sur le chemin UTI.

## Notes offensives

Les applications n'ont pas besoin d'être exécutées pour devenir intéressantes. Un bundle `.app` déposé ou cloné peut être **analysé automatiquement par `lsd` dès qu'il est écrit sur le disque**, et ses types de documents / URL schemes déclarés peuvent être enregistrés sans que l'utilisateur ne lance jamais le bundle.

Cela est utile à la fois pour la **recherche sur la persistence / le hijacking** et pour les **initial-access chains** :

- Une application malveillante peut revendiquer une **extension rare** ou un **UTI custom** et attendre que la victime ouvre le fichier leurre.
- Une application malveillante peut enregistrer un **custom URL scheme** accessible depuis un navigateur, une application Electron, un document bureautique, un client de chat ou une autre application helper.<sup>[[1]](#references)</sup>
- Si vous modifiez un app bundle après sa création, vous pouvez forcer LaunchServices à l'analyser à nouveau avec :
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Lors du test de bundles suspects, accordez une attention particulière aux éléments suivants :

- **`LSHandlerRank=Owner`** sur des types peu courants.
- Les tableaux **`CFBundleDocumentTypes`** étendus revendiquant de nombreuses extensions.
- Les applications **helper / wrapper** dont le seul comportement intéressant se trouve derrière un gestionnaire de document ou d’URI.
- Les fichiers ressemblant à des raccourcis (`.webloc`, `.inetloc`, `.fileloc`) qui finissent par déléguer à LaunchServices. Pour les techniques de type `.fileloc` et les angles associés à Gatekeeper, consultez [cette autre page](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Si votre objectif est l’exécution passive de code en parcourant simplement un dossier ou en sélectionnant un fichier, consultez également la page dédiée aux [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), car il s’agit d’une surface de gestionnaire de fichiers différente, mais étroitement liée.

## Références


- [1] [Objective-See - Exploitation à distance d’un Mac via des schémas d’URL personnalisés](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Contourner la porte : examen approfondi des failles de Gatekeeper sur macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
