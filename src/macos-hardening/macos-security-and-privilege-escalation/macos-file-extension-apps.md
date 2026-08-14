# Gestionnaires d’extensions de fichiers et de schémas d’URL dans macOS

{{#include ../../banners/hacktricks-training.md}}

## Base de données LaunchServices

Il s’agit d’une base de données de toutes les applications installées dans macOS, qui peut être interrogée pour obtenir des informations sur chaque application installée, comme les **schémas d’URL**, les **types de documents**, les **UTI** et les gestionnaires par défaut.

Il est possible de dumper cette base de données avec :
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ou en utilisant l’outil [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** est le cerveau de la base de données. Il fournit **plusieurs services XPC**, comme `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, etc. Cependant, il **requiert également certains entitlements** pour que les applications puissent utiliser les fonctionnalités XPC exposées, comme `.launchservices.changedefaulthandler` ou `.launchservices.changeurlschemehandler` pour modifier les applications par défaut associées aux types MIME ou aux schémas d’URL, entre autres.

**`/System/Library/CoreServices/launchservicesd`** revendique le service `com.apple.coreservices.launchservicesd` et peut être interrogé pour obtenir des informations sur les applications en cours d’exécution. Il peut être interrogé avec l’outil système **`/usr/bin/lsappinfo`** ou avec [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Du point de vue de l’opérateur, gardez à l’esprit qu’il existe généralement **deux vues utiles** :

- La **base de données d’enregistrement** gérée par LaunchServices / `lsd` (soutenue par les fichiers `.csstore`).
- Les **valeurs par défaut effectives par utilisateur**, stockées dans `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, au sein du tableau `LSHandlers`.

Cette distinction est importante : une application peut être **enregistrée** comme pouvant gérer un type ou un schéma, mais le **gestionnaire par défaut actuel** peut toujours être un autre bundle ID.

Sur les versions récentes de macOS, la découverte des enregistrements n’est pas limitée à `/Applications` : les applications présentes dans d’autres dossiers visibles par Spotlight et accessibles, ainsi que sur des volumes montés ou partagés, peuvent entrer dans le registre. Par conséquent, conservez les informations de `path` et de volume issues de `lsregister -dump` pendant le triage et ne supposez pas que la désinscription d’une application est durable tant que le bundle reste détectable.<sup>[[4]](#references)</sup>

## Gestionnaires d’applications pour extensions de fichiers et schémas d’URL

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

Le fichier le plus utile pour les **paramètres par défaut de l'utilisateur actuel** est généralement :
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Pour extraire les gestionnaires de **URL scheme** depuis celui-ci :
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Pour dumper les gestionnaires de **content-type / UTI** :
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
### Substitutions `Open With` spécifiques à chaque fichier

La résolution du gestionnaire comporte également une couche **spécifique au fichier**. Avant de revenir à l’UTI du fichier et à la valeur par défaut globale de l’utilisateur, LaunchServices vérifie l’attribut étendu `com.apple.LaunchServices.OpenWith`. Finder le crée lorsque **Always Open With** est sélectionné pour un fichier ; sa valeur est une liste de propriétés binaire contenant le chemin d’une application, son identifiant de bundle et un sélecteur de version.<sup>[[3]](#references)</sup>

Inspectez-la et décodez-la sans faire confiance à l’extension du nom de fichier :
```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```
Cela est utile lorsqu’un seul leurre s’ouvre avec une application inattendue, même si `duti`, `dutix` ou `LSHandlers` signale une valeur par défaut globale bénigne. Dans un lab contrôlé, la valeur opaque exacte peut être copiée depuis un fichier configuré via Finder ; sa suppression rétablit la résolution normale basée sur le type :
```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```
## Clés Info.plist intéressantes

Lors de l’analyse initiale d’un bundle d’application, ces clés sont les plus importantes :

- **`CFBundleDocumentTypes`** : groupes de documents que le bundle déclare pouvoir ouvrir.
- **`LSItemContentTypes`** : méthode **moderne / préférée** pour associer les types de documents aux UTI.
- **`LSHandlerRank`** : classement utilisé par LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`** : schémas URI personnalisés implémentés par l’application.
- **`UTExportedTypeDeclarations`** : UTI dont l’application est **propriétaire**.
- **`UTImportedTypeDeclarations`** : UTI dont l’application n’est pas propriétaire, mais qu’elle souhaite faire reconnaître par le système.

Une commande utile pour une analyse initiale rapide est :
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Un détail subtil mais important : si **`LSItemContentTypes`** est présent, les anciennes clés telles que **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** et **`CFBundleTypeOSTypes`** sont essentiellement des données de compatibilité legacy. Pour la résolution effective des handlers, privilégiez d’abord le chemin UTI.

## Notes offensives

Les applications n’ont pas besoin d’être exécutées pour devenir intéressantes. Un bundle `.app` déposé ou cloné peut être **parsed automatiquement par `lsd` dès qu’il est écrit sur le disque**, et ses types de documents / schémas d’URL déclarés peuvent être enregistrés sans que l’utilisateur ne lance jamais le bundle.

Cela est utile à la fois pour la recherche sur la **persistence / hijacking** et pour les **initial-access chains** :

- Une application malveillante peut revendiquer une **extension rare** ou un **UTI custom**, puis attendre que la victime ouvre le fichier leurre.
- Une application malveillante peut enregistrer un **custom URL scheme** accessible depuis un navigateur, une application Electron, un document office, un client de chat ou une autre application helper.<sup>[[1]](#references)</sup>
- Pour séparer la résolution normale par défaut du test d’un handler candidat particulier, invoquez le schéma via LaunchServices avec `open 'targetscheme://host/path?value=test'`, puis ciblez un bundle enregistré spécifique avec `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Cela est utile pour auditer la manière dont l’application réceptrice valide et décode les composants d’URL contrôlés par l’attaquant.<sup>[[1]](#references)</sup>
- Si vous modifiez un bundle d’application après sa création, vous pouvez forcer LaunchServices à l’analyser de nouveau avec :
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Lors du test de bundles suspects, accordez une attention particulière aux éléments suivants :

- **`LSHandlerRank=Owner`** sur des types peu courants.
- Les tableaux **`CFBundleDocumentTypes`** étendus revendiquant de nombreuses extensions.
- Les apps helper / wrapper dont le seul comportement intéressant se trouve derrière un document ou un URI handler.
- Les fichiers semblables à des raccourcis (`.webloc`, `.inetloc`, `.fileloc`) qui finissent par être transmis à LaunchServices. Pour les techniques de type `.fileloc` et les angles d’attaque associés à Gatekeeper, consultez [cette autre page](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Si votre objectif est une passive code-execution déclenchée par le simple fait de parcourir un dossier ou de sélectionner un fichier, consultez également la page dédiée aux [générateurs Quick Look](macos-proces-abuse/macos-quicklook-generators.md), car il s’agit d’une surface de file-handler différente, mais étroitement liée.



## References

- [1] [Objective-See - Exploitation à distance d’un Mac via des Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Contourner la barrière : examen approfondi des failles de Gatekeeper sur macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Comment macOS ouvre un fichier avec la bonne app](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Contrôler LaunchServices dans macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
