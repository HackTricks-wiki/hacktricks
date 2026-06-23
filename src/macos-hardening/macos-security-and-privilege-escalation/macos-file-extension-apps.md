# Gestionnaires d’applications pour les extensions de fichier et les schémas URL macOS

{{#include ../../banners/hacktricks-training.md}}

## Base de données LaunchServices

Ceci est une base de données de toutes les applications installées sur macOS, que l’on peut interroger pour obtenir des informations sur chaque application installée, telles que les **URL schemes** pris en charge, les **document types**, les **UTIs**, et les gestionnaires par défaut.

Il est possible de dumper cette base de données avec :
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ou en utilisant l'outil [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** est le cerveau de la base de données. Il fournit **plusieurs services XPC** comme `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, et d’autres. Mais il **requiert aussi certains entitlements** pour que les applications puissent utiliser les fonctionnalités XPC exposées, comme `.launchservices.changedefaulthandler` ou `.launchservices.changeurlschemehandler` pour changer les applications par défaut pour les types MIME ou les URL schemes, et d’autres.

**`/System/Library/CoreServices/launchservicesd`** revendique le service `com.apple.coreservices.launchservicesd` et peut être interrogé pour obtenir des informations sur les applications en cours d’exécution. Il peut être interrogé avec l’outil système **`/usr/bin/lsappinfo`** ou avec [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

D’un point de vue opérateur, gardez à l’esprit qu’il existe généralement **deux vues utiles** :

- La **base de données d’enregistrement** gérée par LaunchServices / `lsd` (soutenue par des fichiers `.csstore`).
- Les **defaults effectifs par utilisateur** stockés dans `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` à l’intérieur du tableau `LSHandlers`.

Cette distinction est importante : une application peut être **enregistrée** comme pouvant gérer un type ou un scheme, mais le **default actuel** peut encore être un autre bundle ID.

## File Extension & URL scheme app handlers

La ligne suivante peut être utile pour trouver les applications qui peuvent ouvrir des fichiers selon l’extension :
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Ou utilisez quelque chose comme [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Vous pouvez également vérifier les extensions prises en charge par une application en faisant :
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

Le fichier le plus utile pour les **defaults de l'utilisateur actuel** est généralement :
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Pour extraire les handlers du **URL scheme** depuis celui-ci :
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Pour vider les gestionnaires **content-type / UTI** :
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Pour résoudre l’arbre UTI d’un fichier d’exemple :
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Si vous voulez une CLI plus conviviale pour interroger ou modifier les valeurs par défaut :
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
## Clés Info.plist intéressantes

Lors du triage d’un application bundle, ces clés comptent le plus :

- **`CFBundleDocumentTypes`** : groupes de documents que le bundle prétend pouvoir ouvrir.
- **`LSItemContentTypes`** : la façon **moderne / préférée** de lier des types de documents à des UTIs.
- **`LSHandlerRank`** : classement utilisé par LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`** : schémas URI personnalisés implémentés par l’app.
- **`UTExportedTypeDeclarations`** : UTIs que l’app **possède**.
- **`UTImportedTypeDeclarations`** : UTIs que l’app ne possède pas mais que le système doit reconnaître.

Une commande rapide de triage utile est :
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Un détail subtil mais important : si **`LSItemContentTypes`** est présent, les anciennes clés comme **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** et **`CFBundleTypeOSTypes`** ne sont en pratique que des données de compatibilité legacy. Pour la résolution réelle du handler, concentrez-vous d’abord sur le chemin UTI.

## Offensive notes

Les applications n’ont pas besoin d’être exécutées pour devenir intéressantes. Un bundle `.app` déposé ou cloné peut être **parsed automatiquement par `lsd` dès qu’il est écrit sur le disque**, et ses types de documents / schémas URL déclarés peuvent être enregistrés sans que l’utilisateur ne lance jamais le bundle.

C’est utile à la fois pour la **recherche sur la persistance / hijacking** et pour les **chaînes d’accès initial** :

- Une app malveillante peut revendiquer une **extension rare** ou un **UTI personnalisé** et attendre que la victime ouvre le fichier leurre.
- Une app malveillante peut enregistrer un **schéma URL personnalisé** accessible depuis un navigateur, une app Electron, un document Office, un client de chat ou une autre app helper.
- Si vous modifiez un bundle d’app après sa construction, vous pouvez forcer LaunchServices à le re-parser avec :
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Lors de l’analyse de bundles suspects, prêtez une attention particulière à :

- **`LSHandlerRank=Owner`** sur des types peu courants.
- Des tableaux **`CFBundleDocumentTypes`** très larges, revendiquant de nombreuses extensions.
- Des **helper / wrapper apps** dont le seul comportement intéressant se cache derrière un handler de document ou d’URI.
- Des fichiers de type **raccourci** (`.webloc`, `.inetloc`, `.fileloc`) qui finissent par être transmis à LaunchServices. Pour les tricks de style `.fileloc` et les angles Gatekeeper liés, consultez [this other page](macos-security-protections/macos-fs-tricks/README.md).

Si votre objectif est une exécution de code passive en se contentant de parcourir un dossier ou de sélectionner un fichier, consultez aussi la page dédiée aux [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), car il s’agit d’une surface de file-handler différente mais étroitement liée.

## References

- **Objective-See - Remote Mac Exploitation Via Custom URL Schemes**](https://objective-see.org/blog/blog_0x38.html)
- **Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS**](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
{{#include ../../banners/hacktricks-training.md}}
