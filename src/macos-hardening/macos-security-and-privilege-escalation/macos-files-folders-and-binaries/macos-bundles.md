# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Les bundles dans macOS servent de conteneurs pour une variété de ressources, y compris des applications, des bibliothèques et d'autres fichiers nécessaires, les faisant apparaître comme des objets uniques dans le Finder, tels que les fichiers familiers `*.app`. Le bundle le plus couramment rencontré est le bundle `.app`, bien que d'autres types comme `.framework`, `.systemextension` et `.kext` soient également répandus.

### Composants essentiels d'un bundle

Au sein d'un bundle, en particulier dans le répertoire `<application>.app/Contents/`, une variété de ressources importantes sont hébergées :

- **\_CodeSignature** : Ce répertoire stocke les détails de signature de code essentiels pour vérifier l'intégrité de l'application. Vous pouvez inspecter les informations de signature de code en utilisant des commandes comme : %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
- **MacOS** : Contient le binaire exécutable de l'application qui s'exécute lors de l'interaction de l'utilisateur.
- **Resources** : Un dépôt pour les composants de l'interface utilisateur de l'application, y compris des images, des documents et des descriptions d'interface (fichiers nib/xib).
- **Info.plist** : Sert de fichier de configuration principal de l'application, crucial pour que le système reconnaisse et interagisse avec l'application de manière appropriée.

#### Clés importantes dans Info.plist

Le fichier `Info.plist` est une pierre angulaire pour la configuration de l'application, contenant des clés telles que :

- **CFBundleExecutable** : Spécifie le nom du fichier exécutable principal situé dans le répertoire `Contents/MacOS`.
- **CFBundleIdentifier** : Fournit un identifiant global pour l'application, utilisé de manière extensive par macOS pour la gestion des applications.
- **LSMinimumSystemVersion** : Indique la version minimale de macOS requise pour que l'application fonctionne.

### Exploration des bundles

Pour explorer le contenu d'un bundle, tel que `Safari.app`, la commande suivante peut être utilisée : `bash ls -lR /Applications/Safari.app/Contents`

Cette exploration révèle des répertoires comme `_CodeSignature`, `MacOS`, `Resources`, et des fichiers comme `Info.plist`, chacun ayant un but unique allant de la sécurisation de l'application à la définition de son interface utilisateur et de ses paramètres opérationnels.

#### Répertoires supplémentaires de bundle

Au-delà des répertoires communs, les bundles peuvent également inclure :

- **Frameworks** : Contient des frameworks regroupés utilisés par l'application. Les frameworks sont comme des dylibs avec des ressources supplémentaires.
- **PlugIns** : Un répertoire pour les plug-ins et extensions qui améliorent les capacités de l'application.
- **XPCServices** : Contient des services XPC utilisés par l'application pour la communication inter-processus.

Cette structure garantit que tous les composants nécessaires sont encapsulés au sein du bundle, facilitant un environnement d'application modulaire et sécurisé.

Pour des informations plus détaillées sur les clés `Info.plist` et leurs significations, la documentation des développeurs Apple fournit des ressources étendues : [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

{{#include ../../../banners/hacktricks-training.md}}
