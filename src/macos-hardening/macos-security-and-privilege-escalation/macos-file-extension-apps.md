# Gestionnaires d’applications pour les extensions de fichiers et les schémas d’URL macOS

{{#include ../../banners/hacktricks-training.md}}

## Base de données LaunchServices

Cette base de données répertorie toutes les applications installées sur macOS. Elle peut être interrogée pour obtenir des informations sur chacune d’elles, telles que les **schémas d’URL**, les **types de documents**, les **UTI** et les gestionnaires par défaut.

Il est possible d’extraire cette base de données avec :

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Ou en utilisant l’outil [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** est le cerveau de la base de données. Il fournit **plusieurs services XPC** tels que `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, et d’autres. Mais il **exige également certaines entitlements** pour permettre aux applications d’utiliser les fonctionnalités XPC exposées, comme `.launchservices.changedefaulthandler` ou `.launchservices.changeurlschemehandler` pour modifier les applications par défaut pour les types MIME ou les schémas URL, entre autres.

**`/System/Library/CoreServices/launchservicesd`** revendique le service `com.apple.coreservices.launchservicesd` et peut être interrogé pour obtenir des informations sur les applications en cours d’exécution. Il peut être interrogé avec l’outil système **`/usr/bin/lsappinfo`** ou avec [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Du point de vue d’un opérateur, gardez à l’esprit qu’il existe généralement **deux vues utiles** :

- La **base de données d’enregistrement** gérée par LaunchServices / `lsd` (stockée dans des fichiers `.csstore`).
- Les **valeurs par défaut effectives par utilisateur**, stockées dans `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, dans le tableau `LSHandlers`.

Cette distinction est importante : une application peut être **enregistrée** comme pouvant gérer un type ou un schéma, mais l’**application par défaut actuelle** peut toujours être un autre bundle ID.

Dans les versions récentes de macOS, la découverte des applications enregistrées ne se limite pas à `/Applications` : les applications présentes dans d’autres dossiers visibles par Spotlight et accessibles, ainsi que sur des volumes montés ou partagés, peuvent être ajoutées au registre. Par conséquent, lors du triage, conservez les informations `path` et de volume provenant de `lsregister -dump` et ne supposez pas que la désinscription d’une application sera durable tant que le bundle reste détectable.<sup>[[4]](#references)</sup>

## Gestionnaires d’applications pour les extensions de fichier et les schémas URL

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

Le fichier le plus utile pour les **valeurs par défaut de l’utilisateur actuel** est généralement :

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Pour extraire les gestionnaires de **schémas d’URL** à partir de cette application :

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

Si vous souhaitez une CLI plus conviviale pour interroger ou modifier les paramètres par défaut :

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

### Remplacements `Open With` par fichier

La résolution du gestionnaire comporte également une couche **spécifique au fichier**. Avant de se rabattre sur l’UTI du fichier et le réglage global par défaut de l’utilisateur, LaunchServices vérifie l’attribut étendu `com.apple.LaunchServices.OpenWith`. Finder le crée lorsque **Toujours ouvrir avec** est sélectionné pour un fichier ; sa valeur est une liste de propriétés binaire contenant le chemin d’une application, son identifiant de bundle et un sélecteur de version.<sup>[[3]](#references)</sup>

Inspectez-le et décodez-le sans vous fier à l’extension du nom de fichier :

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

C’est utile lorsqu’un leurre unique s’ouvre avec une application inattendue, même si `duti`, `dutix` ou `LSHandlers` indique une valeur par défaut globale inoffensive. Dans un laboratoire contrôlé, la valeur opaque exacte peut être copiée depuis un fichier configuré via Finder ; sa suppression rétablit la résolution normale basée sur le type :

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Clés Info.plist intéressantes

Lors du triage d’un bundle d’application, ces clés sont les plus importantes :

- **`CFBundleDocumentTypes`** : groupes de documents que le bundle déclare pouvoir ouvrir.
- **`LSItemContentTypes`** : méthode **moderne / privilégiée** pour associer les types de documents aux UTI.
- **`LSHandlerRank`** : classement utilisé par LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`** : schémas URI personnalisés implémentés par l’application.
- **`UTExportedTypeDeclarations`** : UTI dont l’application est **propriétaire**.
- **`UTImportedTypeDeclarations`** : UTI dont l’application n’est pas propriétaire, mais qu’elle souhaite faire reconnaître par le système.

Une commande de triage rapide utile est :

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Un détail subtil mais important : si **`LSItemContentTypes`** est présent, les clés plus anciennes telles que **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** et **`CFBundleTypeOSTypes`** sont essentiellement des données de compatibilité héritées. Pour la résolution effective des handlers, concentrez-vous d’abord sur le chemin UTI.

## Notes offensives

Les applications n’ont pas besoin d’être exécutées pour que leurs associations de handlers deviennent intéressantes, mais **écrire un bundle `.app` ne garantit pas à lui seul son enregistrement immédiat**. Finder peut enregistrer une application lorsqu’il la découvre, notamment lorsqu’un utilisateur parcourt son dossier ; l’enregistrement peut également avoir lieu au démarrage, à la connexion ou par un appel explicite à l’enregistrement. Vérifiez `lsregister -dump` avant de tester une association. L’enregistrement, à lui seul, ne lance pas l’application et n’en fait pas le handler par défaut effectif.<sup>[[5]](#references)</sup> Pour connaître les prérequis de persistance, consultez [Gestionnaires de schémas d’URL et de types de fichiers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices).

Cette technique est utile à la fois pour la **recherche sur la persistence / le hijacking** et pour les **chaînes d’accès initial** :

- Une application malveillante peut revendiquer une **extension rare** ou un **UTI personnalisé**, puis attendre que la victime ouvre le fichier leurre.
- Une application malveillante peut enregistrer un **schéma d’URL personnalisé** accessible depuis un navigateur, une application Electron, un document bureautique, un client de chat ou une autre application auxiliaire.<sup>[[1]](#references)</sup>
- Pour distinguer la résolution normale du handler par défaut du test d’un handler candidat en particulier, invoquez le schéma via LaunchServices avec `open 'targetscheme://host/path?value=test'`, puis ciblez un bundle enregistré spécifique avec `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. C’est utile pour auditer la façon dont l’application destinataire valide et décode les composants d’URL contrôlés par un attaquant.<sup>[[1]](#references)</sup>
- Si vous modifiez un bundle d’application après sa création, vous pouvez forcer LaunchServices à l’analyser de nouveau avec :

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Lors du test de bundles suspects, portez une attention particulière aux éléments suivants :

- **`LSHandlerRank=Owner`** pour des types peu courants.
- Les tableaux **`CFBundleDocumentTypes`** étendus qui revendiquent de nombreuses extensions.
- Les applications helper / wrapper dont le seul comportement intéressant se trouve derrière un gestionnaire de document ou d’URI.
- Les fichiers de type raccourci (`.webloc`, `.inetloc`, `.fileloc`) qui finissent par déclencher LaunchServices. Pour les astuces de type `.fileloc` et les angles d’attaque liés à Gatekeeper, consultez [cette autre page](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

### Paramètres d’URL transmis aux options en aval

La confirmation d’un navigateur pour un protocole externe autorise uniquement l’ouverture du gestionnaire ; elle ne rend pas fiables les paramètres de l’URL. Suivez l’analyseur d’URL de l’application destinataire jusqu’à toute bibliothèque, tout moteur multimédia, processus helper ou option d’écriture de fichier. Recherchez un préfixe de clé de requête qui transforme les champs de l’URL en noms d’options en aval. Testez les séparateurs littéraux et encodés en pourcentage avec un marqueur inoffensif dans un compte temporaire.<sup>[[6]](#references)</sup>

Vérifiez **l’option finale acceptée par le composant en aval**, et pas seulement l’analyse initiale de l’application. Un gestionnaire permettait à des clés de requête préfixées d’atteindre les commandes d’entrée de mpv ; bloquer cette option laissait tout de même une voie d’écriture de fichier. Testez la catégorie d’options accessible, pas uniquement une clé dangereuse connue.<sup>[[7]](#references)</sup>

### Gestionnaire intégré `applescript://`

Le gestionnaire d’URL `applescript://com.apple.scripteditor` accepte `action=new` et un paramètre `script` encodé dans l’URL. Un lien de navigateur peut donc ouvrir Script Editor avec un AppleScript contrôlé par un attaquant déjà présent dans l’éditeur, sans passer par un collage dans Terminal. **Cela ne provoque pas une exécution automatique** : le navigateur peut demander l’autorisation d’ouvrir Script Editor, et l’utilisateur doit exécuter le script.<sup>[[8]](#references)</sup>

Les versions récentes de macOS peuvent afficher un avertissement pour les documents de script, tandis que XProtect analyse AppleScript lors de son exécution.<sup>[[8]](#references)[[9]](#references)</sup>

Utilisez une sonde locale inoffensive pour vérifier le gestionnaire et les invites sur la version de macOS évaluée ; elle doit uniquement remplir l’éditeur jusqu’à ce que **Run** soit cliqué.<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

Si votre objectif est d’obtenir une exécution passive de code en vous contentant de parcourir un dossier ou de sélectionner un fichier, consultez également la page dédiée aux [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), car il s’agit d’une surface de gestion des fichiers différente, mais étroitement liée.



## References

- [1] [Objective-See - Exploitation à distance de Mac via des schémas d’URL personnalisés](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Contourner Gatekeeper : examen approfondi des failles de Gatekeeper sur macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Comment macOS ouvre un fichier dans la bonne application](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Contrôler LaunchServices dans macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Concepts de Launch Services](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - Recherche sur l’exécution de commandes via le schéma d’URL d’IINA](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - Gestion non sécurisée des options mpv dans son schéma d’URL](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - La technique ClickFix utilise Script Editor plutôt que Terminal](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Protections de Terminal et des scripts](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}
