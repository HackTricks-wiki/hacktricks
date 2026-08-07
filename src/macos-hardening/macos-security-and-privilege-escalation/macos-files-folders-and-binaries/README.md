# Fichiers, dossiers, binaires et mémoire de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Organisation de la hiérarchie des fichiers

- **/Applications** : Les applications installées se trouvent ici. Tous les utilisateurs peuvent y accéder.
- **/bin** : Binaires en ligne de commande
- **/cores** : Si ce dossier existe, il est utilisé pour stocker les core dumps
- **/dev** : Tout est traité comme un fichier ; vous pouvez donc y voir les périphériques matériels stockés.
- **/etc** : Fichiers de configuration
- **/Library** : De nombreux sous-dossiers et fichiers liés aux préférences, aux caches et aux logs peuvent être trouvés ici. Un dossier Library existe à la racine et dans le répertoire de chaque utilisateur.
- **/private** : Non documenté, mais nombre des dossiers mentionnés sont des liens symboliques vers le répertoire private.
- **/sbin** : Binaires système essentiels (liés à l’administration)
- **/System** : Fichiers nécessaires au fonctionnement d’OS X. Vous devriez principalement y trouver des fichiers spécifiques à Apple (et non de tierces parties).
- **/tmp** : Les fichiers sont supprimés après 3 jours (il s’agit d’un lien symbolique vers /private/tmp)
- **/Users** : Répertoire personnel des utilisateurs.
- **/usr** : Binaires de configuration et du système
- **/var** : Fichiers de logs
- **/Volumes** : Les lecteurs montés apparaissent ici.
- **/.vol** : En exécutant `stat a.txt`, vous obtenez quelque chose comme `16777223 7545753 -rw-r--r-- 1 username wheel ...`, où le premier nombre est l’identifiant du volume sur lequel se trouve le fichier et le second est le numéro d’inode. Vous pouvez accéder au contenu de ce fichier via `/.vol/` avec ces informations en exécutant `cat /.vol/16777223/7545753`

### Dossiers d’applications

- Les **applications système** se trouvent sous `/System/Applications`
- Les applications **installées** sont généralement installées dans `/Applications` ou dans `~/Applications`
- Les données des applications peuvent se trouver dans `/Library/Application Support` pour les applications exécutées en tant que root et dans `~/Library/Application Support` pour les applications exécutées par l’utilisateur.
- Les **daemons** d’applications tierces qui **doivent être exécutés en tant que root** se trouvent généralement dans `/Library/PrivilegedHelperTools/`
- Les applications **sandboxed** sont mappées dans le dossier `~/Library/Containers`. Chaque application possède un dossier nommé selon l’identifiant de bundle de l’application (`com.apple.Safari`).
- Le **kernel** se trouve dans `/System/Library/Kernels/kernel`
- Les **extensions du kernel** d’**Apple** se trouvent dans `/System/Library/Extensions`
- Les **extensions du kernel** tierces sont stockées dans `/Library/Extensions`

### Fichiers contenant des informations sensibles

MacOS stocke des informations telles que les mots de passe à plusieurs endroits :


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Installateurs pkg vulnérables


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Extensions spécifiques à OS X

- **`.dmg`** : Les fichiers Apple Disk Image sont très fréquents pour les installateurs.
- **`.kext`** : Ils doivent suivre une structure spécifique et constituent la version OS X d’un driver. (Il s’agit d’un bundle.)
- **`.plist`** : Également appelé property list, ce format stocke des informations au format XML ou binaire.
- Peut être au format XML ou binaire. Les fichiers binaires peuvent être lus avec :
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`** : Applications Apple qui suivent une structure de répertoire (il s’agit d’un bundle).
- **`.dylib`** : Bibliothèques dynamiques (comme les fichiers DLL de Windows)
- **`.pkg`** : Elles sont identiques aux fichiers xar (format eXtensible Archive). La commande installer peut être utilisée pour installer le contenu de ces fichiers.
- **`.DS_Store`** : Ce fichier se trouve dans chaque répertoire et enregistre les attributs et personnalisations du répertoire.
- **`.Spotlight-V100`** : Ce dossier apparaît à la racine de chaque volume du système.
- **`.metadata_never_index`** : Si ce fichier se trouve à la racine d’un volume, Spotlight n’indexera pas ce volume.
- **`.noindex`** : Les fichiers et dossiers portant cette extension ne seront pas indexés par Spotlight.
- **`.sdef`** : Fichiers à l’intérieur des bundles qui spécifient comment il est possible d’interagir avec l’application depuis un AppleScript.

### Bundles macOS

Un bundle est un **répertoire** qui **ressemble à un objet dans le Finder** (un exemple de bundle sont les fichiers `*.app`).


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Sur macOS (et iOS), toutes les bibliothèques système partagées, comme les frameworks et les dylibs, sont **combinées dans un seul fichier**, appelé **dyld shared cache**. Cela améliore les performances, car le code peut être chargé plus rapidement.

Sous macOS, il se trouve dans `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` et, dans les anciennes versions, il est parfois possible de trouver le **shared cache** dans **`/System/Library/dyld/`**.\
Sous iOS, vous pouvez les trouver dans **`/System/Library/Caches/com.apple.dyld/`**.

Comme le dyld shared cache, le kernel et les extensions du kernel sont également compilés dans un kernel cache, qui est chargé au démarrage.

Pour extraire les bibliothèques du shared cache dylib contenu dans un seul fichier, il était possible d’utiliser le binaire [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip), qui pourrait ne plus fonctionner aujourd’hui, mais vous pouvez également utiliser [**dyldextractor**](https://github.com/arandomdev/dyldextractor) :
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Notez que même si l'outil `dyld_shared_cache_util` ne fonctionne pas, vous pouvez passer le **shared dyld binary à Hopper**, et Hopper sera capable d'identifier toutes les bibliothèques et de vous laisser **sélectionner celle** que vous souhaitez examiner :

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Certains extractors ne fonctionneront pas, car les dylibs sont préliées avec des adresses codées en dur et peuvent donc effectuer des sauts vers des adresses inconnues.

> [!TIP]
> Il est également possible de télécharger le Shared Library Cache d'autres appareils \*OS dans macos en utilisant un émulateur dans Xcode. Ils seront téléchargés dans : ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, comme :`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** utilise le syscall **`shared_region_check_np`** pour savoir si le SLC a été mappé (ce qui renvoie l'adresse) et **`shared_region_map_and_slide_np`** pour mapper le SLC.

Notez que même si le SLC est slid lors de la première utilisation, tous les **processus** utilisent la **même copie**, ce qui **éliminait la protection ASLR** si l'attaquant était capable d'exécuter des processus sur le système. Cette technique a effectivement été exploitée par le passé, puis corrigée avec shared region pager.

Les branch pools sont de petites dylibs Mach-O qui créent de petits espaces entre les mappings d'images, rendant impossible l'interposition des fonctions.

### Override SLCs

En utilisant les variables d'environnement :

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Cela permettra de charger un nouveau shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`** et en remplaçant manuellement les bibliothèques par des symlinks vers le shared cache contenant les bibliothèques réelles (vous devrez les extraire)

## Permissions spéciales des fichiers

### Permissions des dossiers

Dans un **dossier**, **read** permet de **le lister**, **write** permet de **supprimer** et d'**écrire** des fichiers dans celui-ci, et **execute** permet de **parcourir** le répertoire. Ainsi, par exemple, un utilisateur disposant de la **permission read sur un fichier** situé dans un répertoire sur lequel il **n'a pas la permission execute** **ne pourra pas lire** le fichier.

### Modificateurs de flags

Certains flags peuvent être définis sur les fichiers et modifier leur comportement. Vous pouvez **vérifier les flags** des fichiers d'un répertoire avec `ls -lO /path/directory`

- **`uchg`** : Aussi appelé flag **uchange**, il **empêchera toute action** modifiant ou supprimant le **fichier**. Pour le définir, utilisez : `chflags uchg file.txt`
- L'utilisateur root peut **supprimer le flag** et modifier le fichier
- **`restricted`** : Ce flag fait en sorte que le fichier soit **protégé par SIP** (vous ne pouvez pas ajouter ce flag à un fichier).
- **`Sticky bit`** : Si un répertoire possède le sticky bit, **seuls le propriétaire du répertoire ou root peuvent renommer ou supprimer** des fichiers. Il est généralement défini sur le répertoire /tmp afin d'empêcher les utilisateurs ordinaires de supprimer ou de déplacer les fichiers d'autres utilisateurs.

Tous les flags se trouvent dans le fichier `sys/stat.h` (trouvez-le avec `mdfind stat.h | grep stat.h`) et sont les suivants :

- `UF_SETTABLE` 0x0000ffff: Masque des flags modifiables par le propriétaire.
- `UF_NODUMP` 0x00000001: Ne pas dumper le fichier.
- `UF_IMMUTABLE` 0x00000002: Le fichier ne peut pas être modifié.
- `UF_APPEND` 0x00000004: Les écritures dans le fichier peuvent uniquement être ajoutées.
- `UF_OPAQUE` 0x00000008: Le répertoire est opaque par rapport à l'union.
- `UF_COMPRESSED` 0x00000020: Le fichier est compressé (certains systèmes de fichiers).
- `UF_TRACKED` 0x00000040: Aucune notification pour les suppressions/renommages des fichiers auxquels ce flag est appliqué.
- `UF_DATAVAULT` 0x00000080: Un entitlement est requis pour la lecture et l'écriture.
- `UF_HIDDEN` 0x00008000: Indique que cet élément ne doit pas être affiché dans une GUI.
- `SF_SUPPORTED` 0x009f0000: Masque des flags pris en charge par le superutilisateur.
- `SF_SETTABLE` 0x3fff0000: Masque des flags modifiables par le superutilisateur.
- `SF_SYNTHETIC` 0xc0000000: Masque des flags synthétiques en lecture seule du système.
- `SF_ARCHIVED` 0x00010000: Le fichier est archivé.
- `SF_IMMUTABLE` 0x00020000: Le fichier ne peut pas être modifié.
- `SF_APPEND` 0x00040000: Les écritures dans le fichier peuvent uniquement être ajoutées.
- `SF_RESTRICTED` 0x00080000: Un entitlement est requis pour l'écriture.
- `SF_NOUNLINK` 0x00100000: L'élément ne peut pas être supprimé, renommé ou monté.
- `SF_FIRMLINK` 0x00800000: Le fichier est un firmlink.
- `SF_DATALESS` 0x40000000: Le fichier est un objet dépourvu de données.

### **ACL des fichiers**

Les **ACL** des fichiers contiennent des **ACE** (Access Control Entries), qui permettent d'attribuer des **permissions plus granulaires** à différents utilisateurs.

Il est possible d'accorder à un **répertoire** les permissions suivantes : `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Et à un **fichier** : `read`, `write`, `append`, `execute`.

Lorsque le fichier contient des ACL, vous **trouverez un "+" lors de l'affichage des permissions, comme dans** :
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Vous pouvez **lire les ACLs** du fichier avec :
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Vous pouvez trouver **tous les fichiers avec des ACL** avec (c'est trèèès lent) :
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Attributs étendus

Les attributs étendus ont un nom et une valeur quelconque, et peuvent être affichés avec `ls -@` et manipulés à l'aide de la commande `xattr`. Voici quelques attributs étendus courants :

- `com.apple.resourceFork` : Compatibilité avec le resource fork. Également visible sous la forme `filename/..namedfork/rsrc`
- `com.apple.quarantine` : macOS : mécanisme de quarantaine de Gatekeeper (III/6)
- `metadata:*` : macOS : diverses métadonnées, telles que `_backup_excludeItem` ou `kMD*`
- `com.apple.lastuseddate` (#PS) : Date de dernière utilisation du fichier
- `com.apple.FinderInfo` : macOS : informations du Finder (par exemple, les Tags de couleur)
- `com.apple.TextEncoding` : Spécifie l'encodage du texte des fichiers texte ASCII
- `com.apple.logd.metadata` : Utilisé par logd sur les fichiers dans `/var/db/diagnostics`
- `com.apple.genstore.*` : Stockage générationnel (`/.DocumentRevisions-V100` à la racine du système de fichiers)
- `com.apple.rootless` : macOS : utilisé par System Integrity Protection pour étiqueter le fichier (III/10)
- `com.apple.uuidb.boot-uuid` : Marquages de logd des périodes de démarrage avec un UUID unique
- `com.apple.decmpfs` : macOS : compression transparente des fichiers (II/7)
- `com.apple.cprotect` : \*OS : données de chiffrement par fichier (III/11)
- `com.apple.installd.*` : \*OS : métadonnées utilisées par installd, par exemple `installType` et `uniqueInstallID`

### Resource Forks | macOS ADS

Il s'agit d'un moyen d'obtenir des **Alternate Data Streams sur les machines MacOS**. Vous pouvez enregistrer du contenu dans un attribut étendu appelé **com.apple.ResourceFork** à l'intérieur d'un fichier en l'enregistrant dans **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Vous pouvez **trouver tous les fichiers contenant cet attribut étendu** avec :
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

L’attribut étendu `com.apple.decmpfs` indique que le fichier est stocké de manière chiffrée, `ls -l` indiquera une **taille de 0** et les données compressées se trouvent dans cet attribut. Chaque fois que le fichier est consulté, il est déchiffré en mémoire.

Cet attribut peut être observé avec `ls -lO`, où il est indiqué comme compressé, car les fichiers compressés portent également le flag `UF_COMPRESSED`. Si le flag d’un fichier compressé est supprimé avec `chflags nocompressed </path/to/file>`, le système ne saura plus que le fichier était compressé et ne pourra donc pas décompresser ni accéder aux données (il considérera qu’il est réellement vide).

L’outil afscexpand peut être utilisé pour forcer la décompression d’un fichier.


### Emplacements de configuration intéressants (macOS)

| Chemin / Emplacement | Fonction / Ce qu’il configure | Sécurité / Potentiel d’attaque |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Stocke les fichiers plist de feature flags d’Apple qui contrôlent les comportements optionnels ou expérimentaux des daemons / frameworks système | Si un attaquant peut contourner SIP ou obtenir des privilèges, leur modification pourrait activer des chemins de code cachés ou désactiver des protections |
| `/System/Library/CoreServices/systemVersion.plist` | Contient les métadonnées de version de macOS (ProductVersion, BuildVersion) utilisées par les applications / installateurs pour contrôler leur comportement | Une modification peut tromper les applications ou les installateurs afin qu’ils acceptent des versions d’OS non prises en charge ou débloquent des fonctionnalités |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Préférences des applications / du système | S’ils sont accessibles en écriture, les attaquants peuvent injecter des paramètres pour orienter le comportement des applications, désactiver des protections ou provoquer une mauvaise configuration |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Définitions plist des daemons et agents en arrière-plan | L’insertion ou la manipulation de plist malveillants (si les permissions le permettent) permet la persistence ou des élévations de privilèges |
| `/etc/hosts` | Associations nom d’hôte ↔ adresse IP utilisées par le résolveur DNS du système | Redirection de noms de domaine, interception du trafic, usurpation de services sous contrôle local |
| `/etc/sudoers` | Définit qui peut exécuter des commandes avec `sudo` et sous quelles conditions | Un fichier sudoers corrompu peut accorder root ou des privilèges inappropriés à des comptes contrôlés par l’attaquant |
| `/private/var/db/dslocal/nodes/Default/users/` | Fichiers plist de définition des comptes utilisateur locaux | Une modification permet de créer ou modifier des comptes utilisateur, des hash de mots de passe ou des métadonnées utilisateur |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Extensions du kernel / drivers | L’installation ou la modification de kexts peut donner un contrôle au niveau du kernel ; ces éléments sont fortement protégés par SIP / les politiques de signature |
| `/private/var/db/SystemPolicyConfiguration/` | Stocke la configuration appliquée par les politiques système (par exemple Gatekeeper, notarization) | Leur modification peut permettre de contourner les vérifications de politique ou les règles de confiance |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Binaires auxiliaires et fichiers de configuration SSH | Une mauvaise configuration entraîne une sécurité SSH faible, un accès non autorisé ou l’utilisation d’algorithmes non sécurisés |
| `/System/Library/Sandbox/Profiles` | Profils de sandbox système (SBPL) utilisés pour restreindre les actions des processus | Le remplacement ou la modification des profils peut ouvrir des vecteurs de sandbox escape ou affaiblir le confinement |

> **Note** : Nombre de ces chemins se trouvent dans des répertoires protégés par SIP (par exemple `/System`) et sont protégés contre les écritures, sauf si SIP est désactivé ou contourné.


## **Universal binaries &** format Mach-o

Les binaires Mac OS sont généralement compilés en **universal binaries**. Un **universal binary** peut **prendre en charge plusieurs architectures dans le même fichier**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Dumping de la mémoire macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Catégories de risque des fichiers Mac OS

Le répertoire `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` contient les informations relatives au **risque associé aux différentes extensions de fichiers**. Ce répertoire classe les fichiers selon différents niveaux de risque, ce qui influence la manière dont Safari gère ces fichiers après leur téléchargement. Les catégories sont les suivantes :

- **LSRiskCategorySafe** : Les fichiers de cette catégorie sont considérés comme **totalement sûrs**. Safari ouvre automatiquement ces fichiers après leur téléchargement.
- **LSRiskCategoryNeutral** : Ces fichiers n’affichent aucun avertissement et ne sont **pas ouverts automatiquement** par Safari.
- **LSRiskCategoryUnsafeExecutable** : Les fichiers de cette catégorie **déclenchent un avertissement** indiquant que le fichier est une application. Il s’agit d’une mesure de sécurité visant à alerter l’utilisateur.
- **LSRiskCategoryMayContainUnsafeExecutable** : Cette catégorie concerne les fichiers, tels que les archives, qui peuvent contenir un exécutable. Safari **déclenche un avertissement**, sauf s’il peut vérifier que tout le contenu est sûr ou neutre.

## Fichiers journaux

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** : Contient des informations sur les fichiers téléchargés, comme l’URL depuis laquelle ils ont été téléchargés.
- **`/var/log/system.log`** : Journal principal des systèmes OSX. com.apple.syslogd.plist est responsable de l’exécution de syslogging (vous pouvez vérifier s’il est désactivé en recherchant "com.apple.syslogd" dans `launchctl list`.
- **`/private/var/log/asl/*.asl`** : Il s’agit des Apple System Logs, qui peuvent contenir des informations intéressantes.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`** : Stocke les fichiers et applications récemment consultés via "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`** : Stocke les éléments à lancer au démarrage du système
- **`$HOME/Library/Logs/DiskUtility.log`** : Fichier journal de l’application DiskUtility (informations sur les disques, y compris les périphériques USB)
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`** : Données relatives aux points d’accès sans fil.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`** : Liste des daemons désactivés.

{{#include ../../../banners/hacktricks-training.md}}
