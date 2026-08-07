# Extensions du kernel macOS & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Les extensions du kernel (Kexts) sont des **packages** portant l’extension **`.kext`** qui sont **chargés directement dans l’espace du kernel macOS**, fournissant des fonctionnalités supplémentaires au système d’exploitation principal.

### Statut de dépréciation & DriverKit / System Extensions
À partir de **macOS Catalina (10.15)**, Apple a marqué la plupart des KPI legacy comme étant *deprecated* et a introduit les frameworks **System Extensions & DriverKit**, qui s’exécutent dans l’**espace utilisateur**. Depuis **macOS Big Sur (11)**, le système d’exploitation *refuse de charger* les kexts tiers qui dépendent de KPI deprecated, sauf si la machine est démarrée en mode **Reduced Security**. Sur Apple Silicon, l’activation des kexts exige en outre que l’utilisateur :

1. Redémarre en **Recovery** → *Startup Security Utility*.
2. Sélectionne **Reduced Security** et coche **“Allow user management of kernel extensions from identified developers”**.
3. Redémarre et approuve le kext depuis **System Settings → Privacy & Security**.

Les drivers user-land écrits avec DriverKit/System Extensions **réduisent considérablement la attack surface**, car les crashs ou corruptions mémoire restent confinés à un processus sandboxé plutôt que dans l’espace du kernel.<sup>[[1]](#references)</sup>

> 📝 Depuis macOS Sequoia (15), Apple a supprimé plusieurs KPI legacy liés aux réseaux et à l’USB – la seule solution compatible avec les futures versions pour les vendors consiste à migrer vers les System Extensions.

### Prérequis

Évidemment, cette fonctionnalité est si puissante qu’il est **complexe de charger une kernel extension**. Voici les **prérequis** qu’une kernel extension doit respecter pour être chargée :

- Lors de l’**entrée en mode recovery**, les **extensions du kernel doivent être autorisées** à être chargées :

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- La kernel extension doit être **signée avec un certificat de signature de code du kernel**, qui ne peut être **accordé que par Apple**. Apple examinera en détail l’entreprise et les raisons pour lesquelles ce certificat est nécessaire.
- La kernel extension doit également être **notarisée** ; Apple pourra ainsi la vérifier pour détecter la présence de malware.
- Ensuite, l’utilisateur **root** est celui qui peut **charger la kernel extension**, et les fichiers contenus dans le package doivent **appartenir à root**.
- Pendant le processus d’upload, le package doit être préparé dans un **emplacement protégé non-root** : `/Library/StagedExtensions` (nécessite le grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Enfin, lors de la tentative de chargement, l’utilisateur [**recevra une demande de confirmation**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) et, si elle est acceptée, l’ordinateur devra être **redémarré** pour charger l’extension.

### Processus de chargement

Dans Catalina, le processus était le suivant : il est intéressant de noter que le processus de **vérification** s’effectue en userland. Cependant, seules les applications disposant du grant **`com.apple.private.security.kext-management`** peuvent **demander au kernel de charger une extension** : `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`**, le cli, **démarre** le processus de **vérification** pour charger une extension
- Il communiquera avec **`kextd`** en envoyant une requête via un **service Mach**.
2. **`kextd`** vérifiera plusieurs éléments, notamment la **signature**
- Il communiquera avec **`syspolicyd`** pour **vérifier** si l’extension peut être **chargée**.
3. **`syspolicyd`** demandera confirmation à l’**utilisateur** si l’extension n’a jamais été chargée auparavant.
- **`syspolicyd`** communiquera le résultat à **`kextd`**
4. **`kextd`** pourra finalement **indiquer au kernel de charger** l’extension

Si **`kextd`** n’est pas disponible, **`kextutil`** peut effectuer les mêmes vérifications.

### Énumération & gestion (kexts chargés)

`kextstat` était l’outil historique, mais il est **deprecated** dans les versions récentes de macOS. L’interface moderne est **`kmutil`** :
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
L’ancienne syntaxe est toujours disponible à titre de référence :
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` peut également être utilisé pour **extraire le contenu d’une Kernel Collection (KC)** ou vérifier qu’une kext résout toutes les dépendances de symboles :
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Même si les kernel extensions sont censées se trouver dans `/System/Library/Extensions/`, si vous ouvrez ce dossier, vous **ne trouverez aucun binaire**. Cela est dû au **kernelcache** et, pour reverse engineer un `.kext`, vous devez trouver un moyen de l'obtenir.

Le **kernelcache** est une version **précompilée et pré-liée du kernel XNU**, accompagnée des **drivers** de périphériques essentiels et des **kernel extensions**. Il est stocké dans un format **compressé** et décompressé en mémoire pendant le processus de démarrage. Le kernelcache permet un **démarrage plus rapide** en fournissant une version du kernel et des drivers essentiels prêts à être exécutés, ce qui réduit le temps et les ressources qui seraient autrement nécessaires au chargement et à l'édition de liens dynamiques de ces composants au démarrage.

Les principaux avantages du kernelcache sont la **rapidité de chargement** et le fait que tous les modules sont prelinked (aucun ralentissement lors du chargement). De plus, une fois tous les modules prelinked, KXLD peut être supprimé de la mémoire, ce qui signifie que **XNU ne peut pas charger de nouveaux KEXTs.**

> [!TIP]
> L'outil [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) déchiffre les conteneurs AEA (Apple Encrypted Archive / AEA asset) d'Apple — le format de conteneur chiffré utilisé par Apple pour les assets OTA et certaines parties des IPSW — et peut produire l'archive .dmg/asset sous-jacente que vous pouvez ensuite extraire avec les outils aastuff fournis.


### Kerlnelcache local

Dans iOS, il se trouve dans **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** ; dans macOS, vous pouvez le trouver avec : **`find / -name "kernelcache" 2>/dev/null`** \
Dans mon cas, sous macOS, je l'ai trouvé ici :

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Vous trouverez également ici le [**kernelcache de la version 14 avec symboles**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

Le format de fichier IMG4 est un format de conteneur utilisé par Apple sur ses appareils iOS et macOS pour **stocker et vérifier de manière sécurisée les composants du firmware** (comme le **kernelcache**). Le format IMG4 comprend un en-tête et plusieurs tags qui encapsulent différentes parties des données, notamment le payload réel (comme un kernel ou un bootloader), une signature et un ensemble de propriétés de manifeste. Le format prend en charge la vérification cryptographique, permettant à l'appareil de confirmer l'authenticité et l'intégrité du composant du firmware avant son exécution.

Il est généralement composé des composants suivants :

- **Payload (IM4P)** :
- Souvent compressé (LZFSE4, LZSS, …)
- Éventuellement chiffré
- **Manifest (IM4M)** :
- Contient une signature
- Dictionnaire Key/Value supplémentaire
- **Restore Info (IM4R)** :
- Également connu sous le nom d'APNonce
- Empêche la relecture de certaines updates
- OPTIONAL : Généralement, cet élément n'est pas présent

Décompressez le Kernelcache :
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# imjtool (https://newandroidbook.com/tools/imjtool.html)
imjtool _img_name_ [extract]

# disarm (you can use it directly on the IMG4 file) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -L kernelcache.release.v57 # From unzip ipsw

# disamer (extract specific parts, e.g. filesets) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -e filesets kernelcache.release.d23
```
#### Désactiver les symboles du kernel

**`Disarm`** permet de symboliser les fonctions du kernelcache à l’aide de matchers. Ces matchers sont simplement des règles de motif (lignes de texte) qui indiquent à disarm comment reconnaître et symboliser automatiquement les fonctions, les arguments ainsi que les chaînes de panic/log à l’intérieur d’un binaire.

En résumé, vous indiquez la chaîne utilisée par une fonction, et disarm la trouvera et la **symbolisera**.

Vous pouvez trouver certains `xnu.matchers` sur [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html), dans la section **`Matchers`**. Vous pouvez également créer vos propres matchers.
```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```
### Téléchargement

Un **IPSW (iPhone/iPad Software)** est le format de package de firmware d’Apple utilisé pour les restaurations et mises à jour des appareils, ainsi que pour les bundles de firmware complets. Il contient notamment le **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

Sur [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases), il est possible de trouver tous les kernel debug kits. Vous pouvez le télécharger, le monter, l’ouvrir avec l’outil [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), accéder au dossier **`.kext`** et **l’extraire**.

Vérifiez la présence de symbols avec :
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Il arrive qu'Apple publie un **kernelcache** avec des **symbols**. Vous pouvez télécharger certains firmwares avec des symbols en suivant les liens présents sur ces pages. Les firmwares contiendront le **kernelcache** parmi d'autres fichiers.

Pour **extract** le kernel cache, vous pouvez faire :
```bash
# Install ipsw tool
brew install blacktop/tap/ipsw

# Extract only the kernelcache from the IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# You should get something like:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# If you get an IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```
Une autre option pour **extraire** les fichiers consiste à commencer par remplacer l’extension `.ipsw` par `.zip`, puis à l’**unzip**.

Après avoir extrait le firmware, vous obtiendrez un fichier tel que : **`kernelcache.release.iphone14`**. Il est au format **IMG4**. Vous pouvez extraire les informations intéressantes avec :

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspection du kernelcache

Vérifiez si le kernelcache contient des symboles avec
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
## Vulnérabilités récentes & techniques d’exploitation

| Année | CVE | Résumé |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Une faille logique dans **`storagekitd`** permettait à un attaquant *root* d’enregistrer un bundle de système de fichiers malveillant qui chargeait finalement un **kext non signé**, **contournant System Integrity Protection (SIP)** et permettant l’installation de rootkits persistants. Corrigée dans macOS 14.2 / 15.2. <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Le daemon d’installation disposant de l’entitlement `com.apple.rootless.install` pouvait être exploité pour exécuter des scripts post-installation arbitraires, désactiver SIP et charger des kexts arbitraires. <sup>[[3]](#references)</sup> |

**Points à retenir pour les red-teamers**

1. **Recherchez les daemons disposant d’entitlements (`codesign -dvv /path/bin | grep entitlements`) qui interagissent avec Disk Arbitration, Installer ou Kext Management.**
2. **L’exploitation des contournements de SIP permet presque toujours de charger un kext → exécution de code dans le kernel**.

**Conseils défensifs**

*Gardez SIP activé*, surveillez les invocations de `kmutil load`/`kmutil create -n aux` provenant de binaires non Apple et déclenchez une alerte lors de toute écriture dans `/Library/Extensions`. Les événements Endpoint Security `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` offrent une visibilité quasi en temps réel.

## Débogage du kernel macOS & des kexts

Le workflow recommandé par Apple consiste à créer un **Kernel Debug Kit (KDK)** correspondant au build en cours d’exécution, puis à se connecter à **LLDB** via une session réseau **KDP (Kernel Debugging Protocol)**.

### Débogage local ponctuel d’un panic
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Débogage distant en direct depuis un autre Mac

1. Téléchargez et installez la version exacte du **KDK** pour la machine cible.
2. Connectez le Mac cible et le Mac hôte avec un **câble USB-C ou Thunderbolt**.
3. Sur le **cible** :
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. Sur l’**hôte** :
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### Attacher LLDB à une kext chargée spécifique
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP n’expose qu’une interface **en lecture seule**. Pour l’instrumentation dynamique, vous devrez patcher le binaire sur le disque, utiliser le **kernel function hooking** (par ex. `mach_override`) ou migrer le driver vers un **hypervisor** pour bénéficier d’un accès complet en lecture/écriture.

## Références

- [1] [Sécurité de DriverKit pour macOS - Guide de sécurité des plateformes Apple](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyse de CVE-2024-44243, un contournement de System Integrity Protection de macOS via les extensions du kernel - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Microsoft découvre une nouvelle vulnérabilité macOS, Shrootless, susceptible de contourner System Integrity Protection - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)

{{#include ../../../banners/hacktricks-training.md}}
