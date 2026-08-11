# Fichiers, dossiers, binaires et mémoire macOS

{{#include ../../../banners/hacktricks-training.md}}

## Organisation de la hiérarchie des fichiers

Apple documente le système de fichiers macOS comme une hiérarchie de domaines système, local, réseau et utilisateur. Le contenu exact varie selon la version du système d'exploitation, et les emplacements système sont de plus en plus protégés ou synthétisés. <sup>[[1]](#references)</sup>

- **/Applications** : Les applications installées doivent se trouver ici. Tous les utilisateurs pourront y accéder.
- **/bin** : Binaires de ligne de commande
- **/cores** : Si ce dossier existe, il est utilisé pour stocker les core dumps
- **/dev** : Tout est traité comme un fichier ; vous pouvez donc voir les périphériques matériels stockés ici.
- **/etc** : Fichiers de configuration
- **/Library** : De nombreux sous-répertoires et fichiers liés aux préférences, aux caches et aux logs peuvent s'y trouver. Un dossier Library existe à la racine et dans le répertoire de chaque utilisateur.
- **/private** : Non documenté, mais de nombreux dossiers mentionnés sont des liens symboliques vers le répertoire private.
- **/sbin** : Binaires système essentiels (liés à l'administration)
- **/System** : Fichiers requis par macOS ; cette arborescence contient principalement des composants fournis par Apple.
- **/tmp** : Fichiers temporaires (lien symbolique vers `/private/tmp`). Les installations historiques nettoyaient généralement les anciens fichiers temporaires selon un calendrier périodique, parfois décrit comme étant de trois jours, mais le délai de nettoyage actuel dépend du système et de la stratégie appliquée ; ne comptez pas sur la persistance des données à cet emplacement.
- **/Users** : Répertoire personnel des utilisateurs.
- **/usr** : Configuration et binaires système
- **/var** : Fichiers de log
- **/Volumes** : Les volumes montés apparaissent ici.
- **/.vol** : En exécutant `stat a.txt`, vous obtenez quelque chose comme `16777223 7545753 -rw-r--r-- 1 username wheel ...`, où le premier nombre est l'identifiant du volume sur lequel se trouve le fichier et le second est le numéro d'inode. Vous pouvez accéder au contenu de ce fichier via /.vol/ avec ces informations en exécutant `cat /.vol/16777223/7545753`

### Dossiers d'applications

- Les **applications système** se trouvent sous `/System/Applications`
- Les applications **installées** sont généralement installées dans `/Applications` ou dans `~/Applications`
- Les données des applications peuvent se trouver dans `/Library/Application Support` pour les applications exécutées en tant que root et dans `~/Library/Application Support` pour les applications exécutées en tant qu'utilisateur.
- Les **daemons** d'applications tierces qui **doivent être exécutés en tant que root** se trouvent généralement dans `/Library/PrivilegedHelperTools/`.
- Les applications **Sandboxed** sont mappées dans le dossier `~/Library/Containers`. Chaque application possède un dossier nommé selon l'identifiant de bundle de l'application (`com.apple.Safari`).
- Le **kernel** se trouve dans `/System/Library/Kernels/kernel`
- Les extensions du **kernel d'Apple** se trouvent dans `/System/Library/Extensions`
- Les extensions du **kernel tierces** sont stockées dans `/Library/Extensions`

### Fichiers contenant des informations sensibles

macOS stocke des informations sensibles, notamment des credentials, à plusieurs emplacements :


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Installateurs pkg vulnérables


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Extensions spécifiques à OS X

- **`.dmg`** : Les fichiers Apple Disk Image sont très courants pour les installateurs.
- **`.kext`** : Il doit suivre une structure spécifique et constitue la version OS X d'un driver. (il s'agit d'un bundle)
- **`.plist`** : Une property list stocke des informations structurées au format XML ou binaire.
- Peut être au format XML ou binaire. Les fichiers binaires peuvent être lus avec :
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`** : Un bundle d'application qui suit la structure de répertoires standard de macOS.
- **`.dylib`** : Bibliothèques dynamiques (comme les fichiers DLL de Windows)
- **`.pkg`** : Sont identiques au format xar (eXtensible Archive format). La commande installer peut être utilisée pour installer le contenu de ces fichiers.
- **`.DS_Store`** : Ce fichier se trouve dans chaque répertoire ; il enregistre les attributs et personnalisations du répertoire.
- **`.Spotlight-V100`** : Ce dossier apparaît à la racine de chaque volume du système.
- **`.metadata_never_index`** : Si ce fichier se trouve à la racine d'un volume, Spotlight n'indexera pas ce volume.
- **`.noindex`** : Les fichiers et dossiers portant cette extension ne seront pas indexés par Spotlight.
- **`.sdef`** : Un fichier de définition de scripting qui décrit comment AppleScript peut interagir avec une application.

### Bundles macOS

Un bundle est un répertoire doté d'une hiérarchie standardisée que Finder peut présenter comme un objet unique ; les bundles d'applications utilisent l'extension `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Sur macOS et iOS, les bibliothèques système et frameworks couramment utilisés sont préliés dans le **dyld shared cache**, ce qui améliore les performances de démarrage des applications. Bien qu'il soit traité comme un cache logique unique, les versions actuelles peuvent le stocker sous la forme d'un cache principal accompagné de plusieurs fichiers subcache, plutôt que littéralement dans un seul fichier. Son format et son emplacement sont des détails d'implémentation qui évoluent selon les versions du système d'exploitation. <sup>[[3]](#references)</sup>

Sur macOS, il se trouve dans `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` et, dans les anciennes versions, vous pouviez trouver le **shared cache** dans **`/System/Library/dyld/`**.\
Sur iOS, vous pouvez les trouver dans **`/System/Library/Caches/com.apple.dyld/`**.

Comme le dyld shared cache, le kernel et les extensions du kernel sont également compilés dans un kernel cache, qui est chargé au démarrage.

Les anciennes versions pouvaient être extraites avec [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Cette version peut ne pas prendre en charge les formats de cache actuels ; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) constitue une autre option :
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Notez que même si l'outil `dyld_shared_cache_util` ne fonctionne pas, vous pouvez passer le **binaire dyld partagé à Hopper**, et Hopper sera capable d'identifier toutes les bibliothèques et de vous permettre de **sélectionner celle** que vous souhaitez examiner :

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Certains extractors ne fonctionneront pas, car les dylibs sont préliées avec des adresses codées en dur et peuvent donc effectuer des sauts vers des adresses inconnues.

> [!TIP]
> Il est également possible de télécharger le Shared Library Cache d'autres appareils \*OS dans macOS en utilisant un émulateur dans Xcode. Ils seront téléchargés dans : ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, comme :`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** utilise le syscall **`shared_region_check_np`** pour vérifier si le SLC a été mappé (ce qui renvoie l'adresse) et **`shared_region_map_and_slide_np`** pour mapper le SLC.

Notez que même si le SLC est slid lors de la première utilisation, tous les **processus** utilisent la **même copie**, ce qui **éliminait la protection ASLR** si l'attaquant était capable d'exécuter des processus sur le système. Cette vulnérabilité a effectivement été exploitée par le passé, puis corrigée avec shared region pager.

Les branch pools sont de petites dylibs Mach-O qui créent de petits espaces entre les mappings d'images, rendant impossible l'interposition des fonctions.

### Override SLCs

En utilisant les variables d'environnement :

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Cela permettra de charger un nouveau shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`** et en remplaçant manuellement les bibliothèques par des symlinks vers le shared cache contenant les bibliothèques réelles (vous devrez les extraire)

## Permissions spéciales des fichiers

### Permissions des dossiers

Pour un répertoire, **read** permet de lister les entrées, **write** permet de créer ou de supprimer des entrées, et **execute** permet de parcourir le répertoire. Par conséquent, un utilisateur qui peut lire un fichier, mais qui ne peut pas parcourir un répertoire parent, ne peut pas accéder à ce fichier par son chemin. <sup>[[4]](#references)</sup>

### Modificateurs de flags

Les fichiers peuvent contenir des flags qui modifient leur comportement. Inspectez les flags d'un répertoire avec `ls -lO /path/directory`.

- **`uchg`** : Connu sous le nom de flag **uchange**, il **empêchera toute action** de modifier ou de supprimer le **fichier**. Pour le définir, utilisez : `chflags uchg file.txt`
- L'utilisateur root peut **supprimer le flag** et modifier le fichier
- **`restricted`** : Ce flag fait en sorte que le fichier soit **protégé par SIP** (vous ne pouvez pas ajouter ce flag à un fichier).
- **`Sticky bit`** : Dans un répertoire où le sticky bit est défini, seul le propriétaire du fichier, le propriétaire du répertoire ou root peut renommer ou supprimer une entrée. Il est généralement activé sur `/tmp` afin d'empêcher les utilisateurs de supprimer ou de déplacer les fichiers d'autres utilisateurs.

Tous les flags se trouvent dans le fichier `sys/stat.h` (trouvez-le avec `mdfind stat.h | grep stat.h`) et sont :

- `UF_SETTABLE` 0x0000ffff : Masque des flags modifiables par le propriétaire.
- `UF_NODUMP` 0x00000001 : Ne pas dumper le fichier.
- `UF_IMMUTABLE` 0x00000002 : Le fichier ne peut pas être modifié.
- `UF_APPEND` 0x00000004 : Les écritures dans le fichier peuvent uniquement être ajoutées.
- `UF_OPAQUE` 0x00000008 : Le répertoire est opaque par rapport à l'union.
- `UF_COMPRESSED` 0x00000020 : Le fichier est compressé (certains file-systems).
- `UF_TRACKED` 0x00000040 : Aucune notification pour les suppressions/renommages des fichiers possédant ce flag.
- `UF_DATAVAULT` 0x00000080 : Un entitlement est requis pour la lecture et l'écriture.
- `UF_HIDDEN` 0x00008000 : Indique que cet élément ne doit pas être affiché dans une interface graphique.
- `SF_SUPPORTED` 0x009f0000 : Masque des flags pris en charge par le superutilisateur.
- `SF_SETTABLE` 0x3fff0000 : Masque des flags modifiables par le superutilisateur.
- `SF_SYNTHETIC` 0xc0000000 : Masque des flags synthétiques en lecture seule du système.
- `SF_ARCHIVED` 0x00010000 : Le fichier est archivé.
- `SF_IMMUTABLE` 0x00020000 : Le fichier ne peut pas être modifié.
- `SF_APPEND` 0x00040000 : Les écritures dans le fichier peuvent uniquement être ajoutées.
- `SF_RESTRICTED` 0x00080000 : Un entitlement est requis pour l'écriture.
- `SF_NOUNLINK` 0x00100000 : L'élément ne peut pas être supprimé, renommé ou monté.
- `SF_FIRMLINK` 0x00800000 : Le fichier est un firmlink.
- `SF_DATALESS` 0x40000000 : Le fichier est un objet sans données.

### **ACLs des fichiers**

Les **ACLs** des fichiers contiennent des **ACE** (Access Control Entries), au sein desquelles des **permissions plus granulaires** peuvent être attribuées à différents utilisateurs.

Il est possible d'accorder à un **répertoire** les permissions suivantes : `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Pour un **fichier** : `read`, `write`, `append` et `execute`.

Lorsque le fichier contient des ACLs, vous **trouverez un « + » lors de l'affichage des permissions, comme dans** :
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
Vous pouvez trouver **tous les fichiers avec des ACL** à l’aide de la commande suivante (c’est très lent) :
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Attributs étendus

Les attributs étendus sont des valeurs de métadonnées nommées stockées séparément des attributs ordinaires d'un fichier. Listez-les avec `ls -l@` et inspectez-les ou modifiez-les avec `xattr`. <sup>[[5]](#references)</sup> Voici quelques attributs étendus courants :

- `com.apple.resourceFork` : compatibilité avec le resource fork. Également visible sous `filename/..namedfork/rsrc`
- `com.apple.quarantine` : métadonnées de quarantaine de macOS Gatekeeper
- `metadata:*` : métadonnées macOS, telles que `_backup_excludeItem` ou `kMD*`
- `com.apple.lastuseddate` (#PS) : date de dernière utilisation du fichier
- `com.apple.FinderInfo` : informations du Finder macOS, telles que les balises de couleur
- `com.apple.TextEncoding` : spécifie l'encodage du texte des fichiers texte ASCII
- `com.apple.logd.metadata` : utilisé par logd pour les fichiers situés dans `/var/db/diagnostics`
- `com.apple.genstore.*` : stockage générationnel (`/.DocumentRevisions-V100` à la racine du système de fichiers)
- `com.apple.rootless` : métadonnées macOS associées à System Integrity Protection
- `com.apple.uuidb.boot-uuid` : marquages logd des périodes de démarrage avec un UUID unique
- `com.apple.decmpfs` : métadonnées de compression transparente des fichiers macOS
- `com.apple.cprotect` : \*OS : données de chiffrement par fichier (III/11)
- `com.apple.installd.*` : \*OS : métadonnées utilisées par installd, par exemple `installType` et `uniqueInstallID`

### Resource forks | macOS ADS

Les resource forks fournissent un flux de données alternatif sur macOS. Le contenu peut être stocké dans l'attribut étendu `com.apple.ResourceFork` et être accessible via `file/..namedfork/rsrc`.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Vous pouvez **trouver tous les fichiers contenant cet attribut étendu** avec :
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

L’attribut étendu `com.apple.decmpfs` stocke des métadonnées pour la compression transparente ; il n’indique pas un chiffrement. Selon le format de compression, les données compressées peuvent être stockées dans l’attribut ou dans un resource fork, puis décompressées de manière transparente lors de leur lecture.

Le flag `UF_COMPRESSED` apparaît sous la forme `compressed` dans `ls -lO`. Ne le supprimez pas manuellement : cela peut amener le système à interpréter incorrectement la représentation compressée.

La commande qui supprime le flag est présentée ici, car elle est utile lors d’un examen forensique, mais son exécution sur un fichier compressé peut rendre ce fichier vide ou inaccessible jusqu’à la réparation de ses métadonnées :
```bash
chflags nocompressed /path/to/file
```
L’utilitaire intégré `/usr/bin/afscexpand` peut forcer l’expansion des fichiers compressés de manière transparente. L’utilitaire tiers distinct `afsctool` peut également inspecter ou décompresser la compression du système de fichiers Apple, mais il ne doit pas être confondu avec la commande intégrée. <sup>[[8]](#references)</sup>


### Emplacements de configuration intéressants (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Stocke les fichiers plist des feature flags d’Apple qui contrôlent des comportements optionnels ou expérimentaux dans les daemons / frameworks système | Si un attaquant peut contourner SIP ou obtenir des privilèges, leur modification pourrait activer des chemins de code cachés ou désactiver des protections |
| `/System/Library/CoreServices/systemVersion.plist` | Contient les métadonnées de version de macOS (ProductVersion, BuildVersion) utilisées par les applications / installateurs pour conditionner leur comportement | Une modification peut tromper les applications ou les installateurs afin qu’ils acceptent des versions d’OS non prises en charge ou déverrouillent des fonctionnalités |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Préférences des applications / à l’échelle du système | Si ces fichiers sont accessibles en écriture, les attaquants peuvent injecter des paramètres pour orienter le comportement des applications, désactiver des protections ou provoquer une mauvaise configuration |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Définitions plist pour les daemons et agents en arrière-plan | L’insertion ou la manipulation de plist malveillants (si les permissions l’autorisent) permet la persistence ou des escalades de privilèges |
| `/etc/hosts` | Correspondances hostname ↔ IP utilisées par le résolveur DNS du système | Redirection de noms de domaine, interception du trafic, usurpation de services sous contrôle local |
| `/etc/sudoers` | Définit qui peut exécuter des commandes avec `sudo` et sous quelles conditions | Un fichier sudoers corrompu peut accorder root ou des privilèges inappropriés à des comptes contrôlés par l’attaquant |
| `/private/var/db/dslocal/nodes/Default/users/` | Fichiers plist de définition des comptes utilisateur locaux | Leur modification permet de créer ou modifier des comptes utilisateur, des hash de mots de passe ou des métadonnées utilisateur |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Extensions du kernel / drivers | L’installation ou la modification de kexts peut donner un contrôle au niveau du kernel ; ces éléments sont fortement protégés par SIP / les politiques de signature |
| `/private/var/db/SystemPolicyConfiguration/` | Stocke la configuration de l’application des politiques système (par exemple Gatekeeper, notarization) | Leur modification peut permettre de contourner les vérifications de politique ou les règles de confiance |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Binaires auxiliaires SSH et fichiers de configuration | Une mauvaise configuration peut entraîner une sécurité SSH faible, un accès non autorisé ou l’utilisation d’algorithmes non sécurisés |
| `/System/Library/Sandbox/Profiles` | Profils sandbox système (SBPL) utilisés pour restreindre les actions des processus | Le remplacement ou la modification des profils peut ouvrir des vecteurs d’évasion de sandbox ou affaiblir le confinement |

> **Remarque** : beaucoup de ces chemins se trouvent dans des répertoires protégés par SIP (par exemple `/System`) et sont protégés contre les écritures, sauf si SIP est désactivé ou contourné.


## Binaires universels et format Mach-O

Mach-O est le format d’exécutable natif de macOS. Un binaire universal, ou fat, regroupe plusieurs slices Mach-O spécifiques à une architecture dans un seul fichier ; la page dédiée explique les deux formats :

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Dumping de la mémoire macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risque des fichiers et métadonnées des handlers

LaunchServices, la quarantine des fichiers et Gatekeeper influencent collectivement la manière dont macOS traite les fichiers téléchargés et sélectionne les applications pour les extensions et les schémas URL. Leurs bases de données et fichiers de ressources internes changent selon les releases ; utilisez les pages dédiées plutôt que de considérer un chemin CoreTypes privé comme une interface de politique stable :

Sur les releases qui exposent les anciennes métadonnées de risque CoreTypes sous `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, les catégories couramment rencontrées sont les suivantes :<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`** : contenu considéré comme suffisamment sûr pour être ouvert automatiquement selon la politique applicable de l’application.
- **`LSRiskCategoryNeutral`** : contenu qui ne déclenche normalement pas d’avertissement et n’est pas ouvert automatiquement.
- **`LSRiskCategoryUnsafeExecutable`** : contenu exécutable pour lequel l’utilisateur doit recevoir un avertissement de l’application.
- **`LSRiskCategoryMayContainUnsafeExecutable`** : conteneurs tels que les archives pouvant contenir du contenu exécutable et nécessitant une inspection supplémentaire.

Il s’agit de détails d’implémentation, et non d’une API publique de politique stable ; vérifiez les métadonnées réelles ainsi que le comportement de Safari/Gatekeeper sur la version de macOS testée.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Fichiers de logs

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** : contient des informations sur les fichiers téléchargés, comme l’URL depuis laquelle ils ont été téléchargés.
- **Unified log** : sur les versions actuelles de macOS, interrogez les événements système et applicatifs avec `log show` et `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** et **`/private/var/log/asl/*.asl`** : artefacts de logging legacy qui peuvent encore être pertinents sur les anciens systèmes. Sur ces releases, `/System/Library/LaunchDaemons/com.apple.syslogd.plist` configure `syslogd` ; `launchctl list | grep com.apple.syslogd` peut aider à déterminer si le service est chargé.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`** : stocke les fichiers et applications récemment consultés via "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`** : ancien chemin de préférences associé aux login items ; les versions modernes de macOS utilisent des mécanismes supplémentaires.
- **`$HOME/Library/Logs/DiskUtility.log`** : ancien log de Disk Utility pouvant contenir des informations sur les disques, notamment les périphériques USB.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`** : données sur les points d’accès sans fil.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`** : anciennes données d’override de launchd.

## References

- [1] [Apple - Guide de programmation du système de fichiers](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Guide de programmation des bundles](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Forums Apple Developer - présentation du dyld shared cache](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Guide de programmation du système de fichiers : sécurité du système de fichiers macOS](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - page de manuel macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - page de manuel macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - page de manuel macOS](https://manp.gs/mac/1/afscexpand)
{{#include ../../../banners/hacktricks-training.md}}
