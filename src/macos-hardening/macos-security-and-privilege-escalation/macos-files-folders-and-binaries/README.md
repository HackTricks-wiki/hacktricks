# macOS Fichiers, Dossiers, Binaires & Mémoire

{{#include ../../../banners/hacktricks-training.md}}

## Disposition de la hiérarchie des fichiers

- **/Applications** : Les applications installées devraient être ici. Tous les utilisateurs pourront y accéder.
- **/bin** : Binaires de ligne de commande
- **/cores** : S'il existe, il est utilisé pour stocker les dumps de noyau
- **/dev** : Tout est traité comme un fichier, donc vous pouvez voir des périphériques matériels stockés ici.
- **/etc** : Fichiers de configuration
- **/Library** : Beaucoup de sous-répertoires et de fichiers liés aux préférences, caches et journaux peuvent être trouvés ici. Un dossier Library existe à la racine et dans le répertoire de chaque utilisateur.
- **/private** : Non documenté mais beaucoup des dossiers mentionnés sont des liens symboliques vers le répertoire privé.
- **/sbin** : Binaires système essentiels (liés à l'administration)
- **/System** : Fichiers pour faire fonctionner OS X. Vous ne devriez trouver principalement que des fichiers spécifiques à Apple ici (pas de tiers).
- **/tmp** : Les fichiers sont supprimés après 3 jours (c'est un lien symbolique vers /private/tmp)
- **/Users** : Répertoire personnel pour les utilisateurs.
- **/usr** : Config et binaires système
- **/var** : Fichiers journaux
- **/Volumes** : Les disques montés apparaîtront ici.
- **/.vol** : En exécutant `stat a.txt`, vous obtenez quelque chose comme `16777223 7545753 -rw-r--r-- 1 username wheel ...` où le premier nombre est l'identifiant du volume où le fichier existe et le second est le numéro d'inode. Vous pouvez accéder au contenu de ce fichier via /.vol/ avec cette information en exécutant `cat /.vol/16777223/7545753`

### Dossiers d'applications

- **Les applications système** se trouvent sous `/System/Applications`
- **Les applications installées** sont généralement installées dans `/Applications` ou dans `~/Applications`
- **Les données d'application** peuvent être trouvées dans `/Library/Application Support` pour les applications s'exécutant en tant que root et `~/Library/Application Support` pour les applications s'exécutant en tant qu'utilisateur.
- Les **démons** d'applications tierces qui **doivent s'exécuter en tant que root** se trouvent généralement dans `/Library/PrivilegedHelperTools/`
- Les applications **sandboxées** sont mappées dans le dossier `~/Library/Containers`. Chaque application a un dossier nommé selon l'ID de bundle de l'application (`com.apple.Safari`).
- Le **noyau** se trouve dans `/System/Library/Kernels/kernel`
- **Les extensions de noyau d'Apple** se trouvent dans `/System/Library/Extensions`
- **Les extensions de noyau tierces** sont stockées dans `/Library/Extensions`

### Fichiers avec des informations sensibles

MacOS stocke des informations telles que des mots de passe à plusieurs endroits :

{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Installateurs pkg vulnérables

{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Extensions spécifiques à OS X

- **`.dmg`** : Les fichiers d'image disque Apple sont très fréquents pour les installateurs.
- **`.kext`** : Il doit suivre une structure spécifique et c'est la version OS X d'un pilote. (c'est un bundle)
- **`.plist`** : Également connu sous le nom de liste de propriétés, stocke des informations au format XML ou binaire.
- Peut être XML ou binaire. Les fichiers binaires peuvent être lus avec :
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`** : Applications Apple qui suivent une structure de répertoire (C'est un bundle).
- **`.dylib`** : Bibliothèques dynamiques (comme les fichiers DLL de Windows)
- **`.pkg`** : Sont les mêmes que xar (format d'archive extensible). La commande d'installation peut être utilisée pour installer le contenu de ces fichiers.
- **`.DS_Store`** : Ce fichier est présent dans chaque répertoire, il sauvegarde les attributs et personnalisations du répertoire.
- **`.Spotlight-V100`** : Ce dossier apparaît dans le répertoire racine de chaque volume du système.
- **`.metadata_never_index`** : Si ce fichier est à la racine d'un volume, Spotlight ne l'indexera pas.
- **`.noindex`** : Les fichiers et dossiers avec cette extension ne seront pas indexés par Spotlight.
- **`.sdef`** : Fichiers à l'intérieur des bundles spécifiant comment il est possible d'interagir avec l'application depuis un AppleScript.

### Bundles macOS

Un bundle est un **répertoire** qui **ressemble à un objet dans le Finder** (un exemple de bundle sont les fichiers `*.app`).

{{#ref}}
macos-bundles.md
{{#endref}}

## Cache de bibliothèque partagée Dyld (SLC)

Sur macOS (et iOS), toutes les bibliothèques partagées du système, comme les frameworks et les dylibs, sont **combinées en un seul fichier**, appelé le **cache partagé dyld**. Cela améliore les performances, car le code peut être chargé plus rapidement.

Cela se trouve sur macOS dans `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` et dans les versions plus anciennes, vous pourriez trouver le **cache partagé** dans **`/System/Library/dyld/`**.\
Dans iOS, vous pouvez les trouver dans **`/System/Library/Caches/com.apple.dyld/`**.

Semblable au cache partagé dyld, le noyau et les extensions de noyau sont également compilés dans un cache de noyau, qui est chargé au démarrage.

Pour extraire les bibliothèques du cache partagé de fichiers dylib, il était possible d'utiliser le binaire [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) qui pourrait ne plus fonctionner aujourd'hui, mais vous pouvez également utiliser [**dyldextractor**](https://github.com/arandomdev/dyldextractor) :
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Notez que même si l'outil `dyld_shared_cache_util` ne fonctionne pas, vous pouvez passer le **binaire dyld partagé à Hopper** et Hopper sera capable d'identifier toutes les bibliothèques et vous permettra de **sélectionner celle que vous** souhaitez enquêter :

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Certains extracteurs ne fonctionneront pas car les dylibs sont préliés avec des adresses codées en dur, donc ils pourraient sauter vers des adresses inconnues.

> [!TIP]
> Il est également possible de télécharger le cache de bibliothèque partagée d'autres appareils \*OS dans macos en utilisant un émulateur dans Xcode. Ils seront téléchargés dans : ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, comme : `$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** utilise l'appel système **`shared_region_check_np`** pour savoir si le SLC a été mappé (ce qui renvoie l'adresse) et **`shared_region_map_and_slide_np`** pour mapper le SLC.

Notez que même si le SLC est glissé lors de la première utilisation, tous les **processus** utilisent la **même copie**, ce qui **élimine la protection ASLR** si l'attaquant était capable d'exécuter des processus dans le système. Cela a en fait été exploité dans le passé et corrigé avec le pager de région partagée.

Les pools de branches sont de petits Mach-O dylibs qui créent de petits espaces entre les mappages d'images, rendant impossible l'interposition des fonctions.

### Override SLCs

En utilisant les variables d'environnement :

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Cela permettra de charger un nouveau cache de bibliothèque partagée.
- **`DYLD_SHARED_CACHE_DIR=avoid`** et remplacer manuellement les bibliothèques par des liens symboliques vers le cache partagé avec les réelles (vous devrez les extraire).

## Special File Permissions

### Folder permissions

Dans un **dossier**, **lire** permet de **lister**, **écrire** permet de **supprimer** et **écrire** des fichiers dessus, et **exécuter** permet de **traverser** le répertoire. Donc, par exemple, un utilisateur avec **la permission de lecture sur un fichier** à l'intérieur d'un répertoire où il **n'a pas la permission d'exécuter** **ne pourra pas lire** le fichier.

### Flag modifiers

Il existe certains drapeaux qui peuvent être définis dans les fichiers qui feront que le fichier se comportera différemment. Vous pouvez **vérifier les drapeaux** des fichiers à l'intérieur d'un répertoire avec `ls -lO /path/directory`

- **`uchg`** : Connu sous le nom de **drapeau uchange**, il **empêchera toute action** de modification ou de suppression du **fichier**. Pour le définir, faites : `chflags uchg file.txt`
- L'utilisateur root pourrait **supprimer le drapeau** et modifier le fichier.
- **`restricted`** : Ce drapeau rend le fichier **protégé par SIP** (vous ne pouvez pas ajouter ce drapeau à un fichier).
- **`Sticky bit`** : Si un répertoire a un bit collant, **seul** le **propriétaire du répertoire ou root peut renommer ou supprimer** des fichiers. En général, cela est défini sur le répertoire /tmp pour empêcher les utilisateurs ordinaires de supprimer ou de déplacer les fichiers d'autres utilisateurs.

Tous les drapeaux peuvent être trouvés dans le fichier `sys/stat.h` (trouvez-le en utilisant `mdfind stat.h | grep stat.h`) et sont :

- `UF_SETTABLE` 0x0000ffff : Masque des drapeaux modifiables par le propriétaire.
- `UF_NODUMP` 0x00000001 : Ne pas dumper le fichier.
- `UF_IMMUTABLE` 0x00000002 : Le fichier ne peut pas être modifié.
- `UF_APPEND` 0x00000004 : Les écritures dans le fichier ne peuvent qu'ajouter.
- `UF_OPAQUE` 0x00000008 : Le répertoire est opaque par rapport à l'union.
- `UF_COMPRESSED` 0x00000020 : Le fichier est compressé (certains systèmes de fichiers).
- `UF_TRACKED` 0x00000040 : Pas de notifications pour les suppressions/renommages pour les fichiers avec ce paramètre.
- `UF_DATAVAULT` 0x00000080 : Droit requis pour lire et écrire.
- `UF_HIDDEN` 0x00008000 : Indication que cet élément ne doit pas être affiché dans une interface graphique.
- `SF_SUPPORTED` 0x009f0000 : Masque des drapeaux pris en charge par le superutilisateur.
- `SF_SETTABLE` 0x3fff0000 : Masque des drapeaux modifiables par le superutilisateur.
- `SF_SYNTHETIC` 0xc0000000 : Masque des drapeaux synthétiques en lecture seule du système.
- `SF_ARCHIVED` 0x00010000 : Le fichier est archivé.
- `SF_IMMUTABLE` 0x00020000 : Le fichier ne peut pas être modifié.
- `SF_APPEND` 0x00040000 : Les écritures dans le fichier ne peuvent qu'ajouter.
- `SF_RESTRICTED` 0x00080000 : Droit requis pour écrire.
- `SF_NOUNLINK` 0x00100000 : L'élément ne peut pas être supprimé, renommé ou monté.
- `SF_FIRMLINK` 0x00800000 : Le fichier est un firmlink.
- `SF_DATALESS` 0x40000000 : Le fichier est un objet sans données.

### **File ACLs**

Les **ACLs** de fichier contiennent des **ACE** (Entrées de Contrôle d'Accès) où des **permissions plus granulaires** peuvent être attribuées à différents utilisateurs.

Il est possible d'accorder à un **répertoire** ces permissions : `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Et à un **fichier** : `read`, `write`, `append`, `execute`.

Lorsque le fichier contient des ACLs, vous trouverez **un "+" lors de la liste des permissions comme dans** :
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Vous pouvez **lire les ACL** du fichier avec :
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Vous pouvez trouver **tous les fichiers avec des ACL** avec (c'est très lent) :
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Attributs Étendus

Les attributs étendus ont un nom et une valeur souhaitée, et peuvent être vus en utilisant `ls -@` et manipulés avec la commande `xattr`. Certains attributs étendus courants sont :

- `com.apple.resourceFork`: Compatibilité avec le fork de ressources. Également visible comme `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS : Mécanisme de quarantaine de Gatekeeper (III/6)
- `metadata:*`: MacOS : diverses métadonnées, telles que `_backup_excludeItem`, ou `kMD*`
- `com.apple.lastuseddate` (#PS): Date de dernière utilisation du fichier
- `com.apple.FinderInfo`: MacOS : Informations sur le Finder (par exemple, étiquettes de couleur)
- `com.apple.TextEncoding`: Spécifie l'encodage de texte des fichiers texte ASCII
- `com.apple.logd.metadata`: Utilisé par logd sur les fichiers dans `/var/db/diagnostics`
- `com.apple.genstore.*`: Stockage générationnel (`/.DocumentRevisions-V100` à la racine du système de fichiers)
- `com.apple.rootless`: MacOS : Utilisé par la Protection de l'Intégrité du Système pour étiqueter le fichier (III/10)
- `com.apple.uuidb.boot-uuid`: Marquages logd des époques de démarrage avec UUID unique
- `com.apple.decmpfs`: MacOS : Compression de fichiers transparente (II/7)
- `com.apple.cprotect`: \*OS : Données de chiffrement par fichier (III/11)
- `com.apple.installd.*`: \*OS : Métadonnées utilisées par installd, par exemple, `installType`, `uniqueInstallID`

### Forks de Ressources | macOS ADS

C'est un moyen d'obtenir **Flux de Données Alternatifs dans MacOS**. Vous pouvez enregistrer du contenu à l'intérieur d'un attribut étendu appelé **com.apple.ResourceFork** à l'intérieur d'un fichier en le sauvegardant dans **file/..namedfork/rsrc**.
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

L'attribut étendu `com.apple.decmpfs` indique que le fichier est stocké de manière chiffrée, `ls -l` rapportera une **taille de 0** et les données compressées se trouvent à l'intérieur de cet attribut. Chaque fois que le fichier est accédé, il sera déchiffré en mémoire.

Cet attr peut être vu avec `ls -lO` indiqué comme compressé car les fichiers compressés sont également étiquetés avec le drapeau `UF_COMPRESSED`. Si un fichier compressé est supprimé avec ce drapeau via `chflags nocompressed </path/to/file>`, le système ne saura pas que le fichier était compressé et ne pourra donc pas décompresser et accéder aux données (il pensera qu'il est en fait vide).

L'outil afscexpand peut être utilisé pour forcer la décompression d'un fichier.

## **Universal binaries &** Mach-o Format

Les binaires Mac OS sont généralement compilés en tant que **binaires universels**. Un **binaire universel** peut **supporter plusieurs architectures dans le même fichier**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}

## macOS Process Memory

## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risk Category Files Mac OS

Le répertoire `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` est l'endroit où les informations sur le **risque associé à différentes extensions de fichiers sont stockées**. Ce répertoire catégorise les fichiers en divers niveaux de risque, influençant la manière dont Safari gère ces fichiers lors du téléchargement. Les catégories sont les suivantes :

- **LSRiskCategorySafe** : Les fichiers de cette catégorie sont considérés comme **complètement sûrs**. Safari ouvrira automatiquement ces fichiers après leur téléchargement.
- **LSRiskCategoryNeutral** : Ces fichiers ne comportent aucun avertissement et **ne sont pas ouverts automatiquement** par Safari.
- **LSRiskCategoryUnsafeExecutable** : Les fichiers de cette catégorie **déclenchent un avertissement** indiquant que le fichier est une application. Cela sert de mesure de sécurité pour alerter l'utilisateur.
- **LSRiskCategoryMayContainUnsafeExecutable** : Cette catégorie est pour les fichiers, tels que les archives, qui pourraient contenir un exécutable. Safari **déclenchera un avertissement** à moins qu'il ne puisse vérifier que tous les contenus sont sûrs ou neutres.

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** : Contient des informations sur les fichiers téléchargés, comme l'URL d'où ils ont été téléchargés.
- **`/var/log/system.log`** : Journal principal des systèmes OSX. com.apple.syslogd.plist est responsable de l'exécution de la journalisation système (vous pouvez vérifier s'il est désactivé en cherchant "com.apple.syslogd" dans `launchctl list`).
- **`/private/var/log/asl/*.asl`** : Ce sont les journaux système Apple qui peuvent contenir des informations intéressantes.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`** : Stocke les fichiers et applications récemment accédés via "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`** : Stocke les éléments à lancer au démarrage du système.
- **`$HOME/Library/Logs/DiskUtility.log`** : Fichier journal pour l'application DiskUtility (informations sur les disques, y compris les USB).
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`** : Données sur les points d'accès sans fil.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`** : Liste des démons désactivés.

{{#include ../../../banners/hacktricks-training.md}}
