# Bundles sur macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Les bundles sur macOS servent de conteneurs pour une variété de ressources, y compris des applications, des libraries, et d'autres fichiers nécessaires, les faisant apparaître comme des objets uniques dans Finder, comme les familiers `*.app`. Le bundle le plus couramment rencontré est le bundle `.app`, bien que d'autres types comme `.framework`, `.systemextension`, et `.kext` soient également répandus.

### Composants essentiels d'un bundle

Within a bundle, particularly within the `<application>.app/Contents/` directory, a variety of important resources are housed:

- **\_CodeSignature**: Ce répertoire stocke les détails de la signature du code indispensables pour vérifier l'intégrité de l'application. Vous pouvez inspecter les informations de signature de code en utilisant des commandes comme :
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Contient le binaire exécutable de l'application qui s'exécute lors de l'interaction de l'utilisateur.
- **Resources**: Un dépôt pour les composants de l'interface utilisateur de l'application, y compris images, documents et descriptions d'interface (nib/xib files).
- **Info.plist**: Fait office de fichier de configuration principal de l'application, crucial pour que le système reconnaisse et interagisse correctement avec l'application.

#### Important Keys in Info.plist

Le fichier `Info.plist` est une pierre angulaire de la configuration de l'application, contenant des clés telles que :

- **CFBundleExecutable**: Spécifie le nom du fichier exécutable principal situé dans le répertoire `Contents/MacOS`.
- **CFBundleIdentifier**: Fournit un identifiant global pour l'application, utilisé de manière intensive par macOS pour la gestion des applications.
- **LSMinimumSystemVersion**: Indique la version minimale de macOS requise pour exécuter l'application.

### Exploring Bundles

Pour explorer le contenu d'un bundle, comme `Safari.app`, la commande suivante peut être utilisée : `bash ls -lR /Applications/Safari.app/Contents`

Cette exploration révèle des répertoires tels que `_CodeSignature`, `MacOS`, `Resources`, et des fichiers comme `Info.plist`, chacun remplissant un rôle unique, de la sécurisation de l'application à la définition de son interface utilisateur et de ses paramètres opérationnels.

#### Additional Bundle Directories

Au-delà des répertoires courants, les bundles peuvent aussi inclure :

- **Frameworks**: Contient les frameworks bundlés utilisés par l'application. Les frameworks sont comme des dylibs avec des ressources supplémentaires.
- **PlugIns**: Un répertoire pour les plug-ins et extensions qui améliorent les capacités de l'application.
- **XPCServices**: Contient les services XPC utilisés par l'application pour la communication hors-processus.

Cette structure garantit que tous les composants nécessaires sont encapsulés dans le bundle, facilitant un environnement d'application modulaire et sécurisé.

Pour des informations plus détaillées sur les clés de `Info.plist` et leur signification, la documentation Apple Developer fournit des ressources étendues : [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Notes de sécurité et vecteurs d'abus

- **Gatekeeper / App Translocation**: Lorsqu'un bundle mis en quarantaine est exécuté pour la première fois, macOS effectue une vérification approfondie de la signature et peut l'exécuter depuis un chemin transloqué randomisé. Une fois accepté, les lancements ultérieurs n'effectuent que des vérifications superficielles ; les fichiers de ressources dans `Resources/`, `PlugIns/`, les nibs, etc., n'étaient historiquement pas vérifiés. Depuis macOS 13 Ventura, une vérification approfondie est appliquée au premier lancement et la nouvelle permission TCC *App Management* restreint les processus tiers de modifier d'autres bundles sans le consentement de l'utilisateur, mais les systèmes plus anciens restent vulnérables.
- **Bundle Identifier collisions**: Plusieurs cibles embarquées (PlugIns, helper tools) réutilisant le même `CFBundleIdentifier` peuvent casser la validation de la signature et occasionnellement permettre du URL‑scheme hijacking/confusion. Énumérez toujours les sous‑bundles et vérifiez l'unicité des identifiants.

## Resource Hijacking (Dirty NIB / NIB Injection)

Avant Ventura, le remplacement des ressources UI dans une application signée pouvait bypasser la signature de code superficielle et permettre l'exécution de code avec les entitlements de l'application. Les recherches actuelles (2024) montrent que cela fonctionne encore sur les systèmes pré‑Ventura et sur des builds non mis en quarantaine :

1. Copier l'application cible vers un emplacement en écriture (par ex., `/tmp/Victim.app`).
2. Remplacer `Contents/Resources/MainMenu.nib` (ou tout nib déclaré dans `NSMainNibFile`) par un fichier malveillant qui instancie `NSAppleScript`, `NSTask`, etc.
3. Lancer l'application. Le nib malveillant s'exécute sous le bundle ID de la victime et hérite des entitlements (TCC grants, microphone/camera, etc.).
4. Ventura+ atténue cela en vérifiant en profondeur le bundle au premier lancement et en exigeant la permission *App Management* pour les modifications ultérieures, rendant la persistance plus difficile mais les attaques au premier lancement sur les anciens macOS restent applicables.

Minimal malicious nib payload example (compile xib to nib with `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking dans les Bundles

Parce que les recherches `@rpath` privilégient les Frameworks/PlugIns inclus, déposer une bibliothèque malveillante dans `Contents/Frameworks/` ou `Contents/PlugIns/` peut modifier l'ordre de chargement lorsque le binaire principal est signé sans validation des bibliothèques ou avec un ordre `LC_RPATH` faible.

Étapes typiques lors de l'exploitation d'un bundle non signé/ad‑hoc :
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
- Le Hardened runtime, lorsque `com.apple.security.cs.disable-library-validation` est absent, bloque les dylibs tiers ; vérifiez d'abord les entitlements.
- Les XPC services sous `Contents/XPCServices/` chargent souvent des sibling frameworks — patchez leurs binaries de la même manière pour des chemins de persistence ou de privilege escalation.

## Aide-mémoire d'inspection rapide
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

- [Mettre process injection en évidence dans les vue(s) : exploitation des apps macOS utilisant des nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering — article (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}
