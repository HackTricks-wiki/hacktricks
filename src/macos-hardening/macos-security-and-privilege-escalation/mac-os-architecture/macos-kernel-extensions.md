# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Les extensions de noyau (Kexts) sont des **paquets** avec une **extension `.kext`** qui sont **chargés directement dans l'espace noyau de macOS**, fournissant des fonctionnalités supplémentaires au système d'exploitation principal.

### Exigences

Évidemment, c'est si puissant qu'il est **compliqué de charger une extension de noyau**. Voici les **exigences** qu'une extension de noyau doit respecter pour être chargée :

- Lors de **l'entrée en mode de récupération**, les **extensions de noyau doivent être autorisées** à être chargées :

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- L'extension de noyau doit être **signée avec un certificat de signature de code de noyau**, qui ne peut être **accordé que par Apple**. Qui examinera en détail l'entreprise et les raisons pour lesquelles cela est nécessaire.
- L'extension de noyau doit également être **notariée**, Apple pourra la vérifier pour détecter des logiciels malveillants.
- Ensuite, l'utilisateur **root** est celui qui peut **charger l'extension de noyau** et les fichiers à l'intérieur du paquet doivent **appartenir à root**.
- Pendant le processus de téléchargement, le paquet doit être préparé dans un **emplacement protégé non-root** : `/Library/StagedExtensions` (nécessite l'octroi `com.apple.rootless.storage.KernelExtensionManagement`).
- Enfin, lors de la tentative de chargement, l'utilisateur recevra une [**demande de confirmation**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) et, si acceptée, l'ordinateur doit être **redémarré** pour le charger.

### Processus de chargement

Dans Catalina, c'était comme ça : Il est intéressant de noter que le processus de **vérification** se déroule en **userland**. Cependant, seules les applications avec l'octroi **`com.apple.private.security.kext-management`** peuvent **demander au noyau de charger une extension** : `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **démarre** le processus de **vérification** pour charger une extension
- Il communiquera avec **`kextd`** en utilisant un **service Mach**.
2. **`kextd`** vérifiera plusieurs choses, telles que la **signature**
- Il communiquera avec **`syspolicyd`** pour **vérifier** si l'extension peut être **chargée**.
3. **`syspolicyd`** **demande** à l'**utilisateur** si l'extension n'a pas été chargée précédemment.
- **`syspolicyd`** rapportera le résultat à **`kextd`**
4. **`kextd`** pourra enfin **dire au noyau de charger** l'extension

Si **`kextd`** n'est pas disponible, **`kextutil`** peut effectuer les mêmes vérifications.

### Énumération (kexts chargés)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

> [!CAUTION]
> Même si les extensions du noyau sont censées se trouver dans `/System/Library/Extensions/`, si vous allez dans ce dossier, vous **ne trouverez aucun binaire**. Cela est dû au **kernelcache** et pour inverser un `.kext`, vous devez trouver un moyen de l'obtenir.

Le **kernelcache** est une **version pré-compilée et pré-lien du noyau XNU**, ainsi que des **drivers** et des **extensions de noyau** essentiels. Il est stocké dans un format **compressé** et est décompressé en mémoire pendant le processus de démarrage. Le kernelcache facilite un **temps de démarrage plus rapide** en ayant une version prête à l'emploi du noyau et des drivers cruciaux disponibles, réduisant le temps et les ressources qui seraient autrement dépensés pour charger et lier dynamiquement ces composants au moment du démarrage.

### Local Kerlnelcache

Dans iOS, il est situé dans **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** dans macOS, vous pouvez le trouver avec : **`find / -name "kernelcache" 2>/dev/null`** \
Dans mon cas, dans macOS, je l'ai trouvé dans :

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

Le format de fichier IMG4 est un format de conteneur utilisé par Apple dans ses appareils iOS et macOS pour **stocker et vérifier en toute sécurité** les composants du firmware (comme le **kernelcache**). Le format IMG4 comprend un en-tête et plusieurs balises qui encapsulent différentes pièces de données, y compris la charge utile réelle (comme un noyau ou un chargeur de démarrage), une signature et un ensemble de propriétés de manifeste. Le format prend en charge la vérification cryptographique, permettant à l'appareil de confirmer l'authenticité et l'intégrité du composant du firmware avant de l'exécuter.

Il est généralement composé des composants suivants :

- **Payload (IM4P)** :
- Souvent compressé (LZFSE4, LZSS, …)
- Optionnellement chiffré
- **Manifest (IM4M)** :
- Contient la signature
- Dictionnaire clé/valeur supplémentaire
- **Restore Info (IM4R)** :
- Également connu sous le nom d'APNonce
- Empêche la répétition de certaines mises à jour
- OPTIONNEL : En général, cela n'est pas trouvé

Décompressez le Kernelcache :
```bash
# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Télécharger

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

Dans [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases), il est possible de trouver tous les kits de débogage du noyau. Vous pouvez le télécharger, le monter, l'ouvrir avec l'outil [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), accéder au dossier **`.kext`** et **l'extraire**.

Vérifiez-le pour les symboles avec :
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Parfois, Apple publie **kernelcache** avec des **symbols**. Vous pouvez télécharger certains firmwares avec des symbols en suivant les liens sur ces pages. Les firmwares contiendront le **kernelcache** parmi d'autres fichiers.

Pour **extract** les fichiers, commencez par changer l'extension de `.ipsw` à `.zip` et **unzip** le fichier.

Après avoir extrait le firmware, vous obtiendrez un fichier comme : **`kernelcache.release.iphone14`**. Il est au format **IMG4**, vous pouvez extraire les informations intéressantes avec :

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspection du kernelcache

Vérifiez si le kernelcache a des symboles avec
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Avec cela, nous pouvons maintenant **extraire toutes les extensions** ou **celle qui vous intéresse :**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Débogage

## Références

- [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
- [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{{#include ../../../banners/hacktricks-training.md}}
