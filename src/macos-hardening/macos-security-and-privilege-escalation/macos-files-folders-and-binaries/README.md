# Fichiers, dossiers, binaires et mémoire sous macOS

{{#include ../../../banners/hacktricks-training.md}}

## Hiérarchie des fichiers

Apple documente le système de fichiers macOS comme une hiérarchie de domaines système, local, réseau et utilisateur. Le contenu exact varie selon la version du système d’exploitation, et les emplacements système sont de plus en plus protégés ou synthétisés. <sup>[[1]](#references)</sup>

- **/Applications** : Les applications installées doivent se trouver ici. Tous les utilisateurs pourront y accéder.
- **/bin** : Binaires en ligne de commande
- **/cores** : Si ce dossier existe, il sert à stocker les core dumps
- **/dev** : Tout est traité comme un fichier ; vous pouvez donc y voir des périphériques matériels.
- **/etc** : Fichiers de configuration
- **/Library** : On y trouve de nombreux sous-dossiers et fichiers liés aux préférences, aux caches et aux journaux. Un dossier Library existe à la racine et dans le répertoire de chaque utilisateur.
- **/private** : Non documenté, mais bon nombre des dossiers mentionnés sont des liens symboliques vers le répertoire private.
- **/sbin** : Binaires système essentiels (liés à l’administration)
- **/System** : Fichiers requis par macOS ; cette arborescence contient principalement des composants fournis par Apple.
- **/tmp** : Fichiers temporaires (lien symbolique vers `/private/tmp`). Les installations historiques supprimaient généralement les anciens fichiers temporaires selon une périodicité donnée, parfois décrite comme étant de trois jours, mais le calendrier de nettoyage actuel dépend du système et des règles en vigueur ; ne comptez pas sur la persistance des données qui s’y trouvent.
- **/Users** : Répertoire personnel des utilisateurs.
- **/usr** : Configuration et binaires système
- **/var** : Fichiers journaux
- **/Volumes** : Les volumes montés apparaissent ici.
- **/.vol** : En exécutant `stat a.txt`, vous obtenez quelque chose comme `16777223 7545753 -rw-r--r-- 1 username wheel ...`, où le premier nombre est l’identifiant du volume sur lequel se trouve le fichier et le second est son numéro d’inode. Vous pouvez accéder au contenu de ce fichier via /.vol/ à l’aide de ces informations, en exécutant `cat /.vol/16777223/7545753`

### Dossiers d’applications

- Les **applications système** se trouvent dans `/System/Applications`
- Les applications **installées** le sont généralement dans `/Applications` ou dans `~/Applications`
- Les **données des applications** se trouvent dans `/Library/Application Support` pour les applications exécutées en tant que root et dans `~/Library/Application Support` pour celles exécutées en tant qu’utilisateur.
- Les **daemons** d’applications tierces qui **doivent s’exécuter en tant que root** se trouvent généralement dans `/Library/PrivilegedHelperTools/`.
- Les applications **sandboxed** sont mappées dans le dossier `~/Library/Containers`. Chaque application possède un dossier nommé selon l’identifiant de bundle de l’application (`com.apple.Safari`).
- Le **kernel** se trouve dans `/System/Library/Kernels/kernel`
- Les **extensions de kernel d’Apple** se trouvent dans `/System/Library/Extensions`
- Les **extensions de kernel tierces** sont stockées dans `/Library/Extensions`

### Fichiers contenant des informations sensibles

macOS stocke des informations sensibles, notamment des identifiants, à plusieurs endroits :


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Installateurs pkg vulnérables


{{#ref}}
macos-installers-abuse.md
{{#endref}}

Pour distinguer le volume Data accessible en écriture du volume System scellé visibles dans cette hiérarchie, consultez [Volume système scellé et DataVault de macOS](../macos-security-protections/macos-sealed-system-volume-and-datavault.md).

## Extensions spécifiques à OS X

- **`.dmg`** : Les fichiers Apple Disk Image sont très courants pour les installateurs.
- **`.kext`** : Ce fichier doit suivre une structure spécifique et correspond à la version OS X d’un pilote. (c’est un bundle)
- **`.plist`** : Une property list stocke des informations structurées au format XML ou binaire.
  - Le format peut être XML ou binaire. Les fichiers binaires peuvent être lus avec :
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`** : Un bundle d’application qui respecte la structure standard des répertoires macOS.
- **`.dylib`** : Bibliothèques dynamiques (comme les fichiers DLL de Windows)
- **`.pkg`** : Les packages d’installation flat modernes sont des archives XAR, mais `.pkg` est un format d’installateur, pas un synonyme de XAR. Les anciens packages d’installation de type bundle sont des répertoires. Consultez [les installateurs macOS](macos-installers-abuse.md) pour en savoir plus sur la structure des packages et leur inspection. <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`** : Ce fichier se trouve dans chaque répertoire et enregistre ses attributs et personnalisations.
- **`.Spotlight-V100`** : Ce dossier apparaît à la racine de chaque volume du système.
- **`.metadata_never_index`** : Si ce fichier se trouve à la racine d’un volume, Spotlight n’indexera pas ce volume.
- **`.noindex`** : Les fichiers et dossiers portant cette extension ne seront pas indexés par Spotlight.
- **`.sdef`** : Un fichier de définition de script qui décrit la manière dont AppleScript peut interagir avec une application.

### Bundles macOS

Un bundle est un répertoire doté d’une hiérarchie standardisée que Finder peut présenter comme un seul objet ; les bundles d’applications utilisent l’extension `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Cache de bibliothèques partagées Dyld (SLC)

Sous macOS et iOS, les bibliothèques système et frameworks couramment utilisés sont préliés dans le **cache partagé dyld**, ce qui améliore les performances de démarrage des applications. Bien qu’il soit traité comme un cache logique unique, les versions actuelles peuvent le stocker sous la forme d’un cache principal accompagné de plusieurs fichiers de sous-cache, plutôt que dans un seul fichier au sens littéral. Son format et son emplacement sont des détails d’implémentation qui varient selon les versions du système d’exploitation. <sup>[[3]](#references)</sup>

Sous macOS, il se trouve dans `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` ; dans les versions plus anciennes, vous pouvez trouver le **cache partagé** dans **`/System/Library/dyld/`**.\
Sous iOS, vous pouvez le trouver dans **`/System/Library/Caches/com.apple.dyld/`**.

Comme le cache partagé dyld, le kernel et ses extensions sont également compilés dans un cache de kernel, qui est chargé au démarrage.

Les versions plus anciennes pouvaient être extraites avec [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Cette version peut ne pas prendre en charge les formats de cache actuels ; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) est une autre option :

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> Notez que même si l’outil `dyld_shared_cache_util` ne fonctionne pas, vous pouvez transmettre le **binaire dyld partagé à Hopper** : Hopper pourra identifier toutes les bibliothèques et vous laisser **sélectionner celle** que vous souhaitez examiner :

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Certains extracteurs ne fonctionneront pas, car les dylibs sont préliées avec des adresses codées en dur et peuvent donc effectuer des sauts vers des adresses inconnues.

> [!TIP]
> Il est également possible de télécharger le Shared Library Cache d’autres appareils \*OS dans macOS en utilisant un émulateur dans Xcode. Ils seront téléchargés dans : ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, par exemple :`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mappage du SLC

**`dyld`** utilise l’appel système **`shared_region_check_np`** pour savoir si le SLC a été mappé (celui-ci renvoie l’adresse) et **`shared_region_map_and_slide_np`** pour mapper le SLC.

Notez que même si le SLC est slid lors de la première utilisation, tous les **processus** utilisent la **même copie**, ce qui **éliminait la protection ASLR** si l’attaquant pouvait exécuter des processus sur le système. Cette vulnérabilité a été exploitée par le passé et corrigée avec le shared region pager.

Les Branch pools sont de petits dylibs Mach-O qui créent de petits espaces entre les mappages d’images, rendant impossible l’interposition des fonctions.

### Restrictions de l’environnement du shared cache

`DYLD_SHARED_CACHE_DIR` indique un répertoire de cache, tandis que `DYLD_SHARED_REGION` sélectionne un mode de shared region. L’ancienne orthographe `DYLD_DHARED_REGION` était invalide, et `avoid` n’est pas une valeur pour `DYLD_SHARED_CACHE_DIR`. Le dyld actuel n’autorise le mode `private` que si AMFI accorde la permission d’utiliser des shared caches personnalisés ; définir uniquement des variables d’environnement ne suffit donc pas à établir qu’un processus peut charger un cache de remplacement. <sup>[[10]](#references)</sup>

## Permissions spéciales des fichiers

### Permissions des dossiers

Pour un répertoire, **read** permet de lister les entrées, **write** permet de créer ou de supprimer des entrées, et **execute** permet de parcourir le répertoire. Par conséquent, un utilisateur qui peut lire un fichier, mais ne peut pas parcourir un répertoire parent, ne peut pas accéder à ce fichier par son chemin. <sup>[[4]](#references)</sup>

### Modificateurs d’attributs

Les fichiers peuvent avoir des attributs qui modifient leur comportement. Affichez les attributs d’un répertoire avec `ls -lO /path/directory`.

- **`uchg`** : connu sous le nom d’attribut **uchange**, il **empêche toute action** de modification ou de suppression du **fichier**. Pour le définir, exécutez : `chflags uchg file.txt`
  - Le propriétaire du fichier ou root peut supprimer cet attribut **utilisateur** avec `chflags nouchg file.txt` ; il ne les protège pas. L’attribut immuable **système** distinct (`schg`) est réservé à root. <sup>[[11]](#references)</sup>
- **`restricted`** : cet attribut signifie que le fichier est **protégé par SIP** (vous ne pouvez pas ajouter cet attribut à un fichier).
- **`Sticky bit`** : dans un répertoire où le sticky bit est défini, seul le propriétaire du fichier, le propriétaire du répertoire ou root peut renommer ou supprimer une entrée. Il est généralement activé sur `/tmp` pour empêcher les utilisateurs de supprimer ou de déplacer les fichiers des autres utilisateurs.

Tous les attributs sont répertoriés dans le fichier `sys/stat.h` (recherchez-le avec `mdfind stat.h | grep stat.h`) :

- `UF_SETTABLE` 0x0000ffff : masque des attributs modifiables par le propriétaire.
- `UF_NODUMP` 0x00000001 : ne pas vider le fichier.
- `UF_IMMUTABLE` 0x00000002 : le fichier ne peut pas être modifié.
- `UF_APPEND` 0x00000004 : seules des données peuvent être ajoutées au fichier.
- `UF_OPAQUE` 0x00000008 : le répertoire est opaque par rapport à l’union.
- `UF_COMPRESSED` 0x00000020 : le fichier est compressé (certains systèmes de fichiers).
- `UF_TRACKED` 0x00000040 : aucune notification de suppression ou de renommage pour les fichiers ayant cet attribut.
- `UF_DATAVAULT` 0x00000080 : une entitlement est requise pour la lecture et l’écriture.
- `UF_HIDDEN` 0x00008000 : indique que cet élément ne doit pas être affiché dans une interface graphique.
- `SF_SUPPORTED` 0x009f0000 : masque des attributs pris en charge par le superutilisateur.
- `SF_SETTABLE` 0x3fff0000 : masque des attributs modifiables par le superutilisateur.
- `SF_SYNTHETIC` 0xc0000000 : masque des attributs synthétiques en lecture seule du système.
- `SF_ARCHIVED` 0x00010000 : le fichier est archivé.
- `SF_IMMUTABLE` 0x00020000 : le fichier ne peut pas être modifié.
- `SF_APPEND` 0x00040000 : seules des données peuvent être ajoutées au fichier.
- `SF_RESTRICTED` 0x00080000 : une entitlement est requise pour l’écriture.
- `SF_NOUNLINK` 0x00100000 : l’élément ne peut pas être supprimé, renommé ou monté sur.
- `SF_FIRMLINK` 0x00800000 : le fichier est un firmlink.
- `SF_DATALESS` 0x40000000 : le fichier est un objet sans données.

### **ACL de fichiers**

Les **ACL** des fichiers contiennent des **ACE** (Access Control Entries), qui permettent d’attribuer des **permissions plus granulaires** à différents utilisateurs.

Il est possible d’accorder à un **répertoire** les permissions suivantes : `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Pour un **fichier** : `read`, `write`, `append` et `execute`.

Lorsque le fichier contient des ACL, vous **verrez un « + » lors de l’affichage des permissions, comme dans** :

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

Vous pouvez trouver **tous les fichiers avec des ACL** à l'aide de la commande suivante (c'est très lent) :

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### Attributs étendus

Les attributs étendus sont des valeurs de métadonnées nommées, stockées séparément des attributs ordinaires d’un fichier. Listez-les avec `ls -l@` et inspectez-les ou modifiez-les avec `xattr`. <sup>[[5]](#references)</sup> Voici quelques attributs étendus courants :

- `com.apple.resourceFork` : compatibilité avec les forks de ressources. Également visible sous `filename/..namedfork/rsrc`
- `com.apple.quarantine` : métadonnées de quarantaine de macOS Gatekeeper
- `metadata:*` : métadonnées macOS, telles que `_backup_excludeItem` ou `kMD*`
- `com.apple.lastuseddate` (#PS) : date de dernière utilisation du fichier
- `com.apple.FinderInfo` : informations du Finder macOS, telles que les étiquettes de couleur
- `com.apple.TextEncoding` : spécifie l’encodage du texte des fichiers texte ASCII
- `com.apple.logd.metadata` : utilisé par logd sur les fichiers dans `/var/db/diagnostics`
- `com.apple.genstore.*` : stockage générationnel (`/.DocumentRevisions-V100` à la racine du système de fichiers)
- `com.apple.rootless` : métadonnées macOS associées à System Integrity Protection
- `com.apple.uuidb.boot-uuid` : marqueurs de logd indiquant les époques de démarrage au moyen d’UUID uniques
- `com.apple.decmpfs` : métadonnées de compression transparente des fichiers macOS
- `com.apple.cprotect` : \*OS : données de chiffrement par fichier (III/11)
- `com.apple.installd.*` : \*OS : métadonnées utilisées par installd, par exemple `installType` et `uniqueInstallID`

### Resource Forks | macOS ADS

Les forks de ressources fournissent un flux de données alternatif sur macOS. Le contenu peut être stocké dans l’attribut étendu `com.apple.ResourceFork` et consulté via `file/..namedfork/rsrc`.

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

L’attribut étendu `com.apple.decmpfs` stocke des métadonnées pour la compression transparente ; il n’indique pas un chiffrement. Selon le format de compression, les données compressées peuvent être stockées dans l’attribut ou dans un fork de ressources, puis décompressées de manière transparente lors de la lecture.

L’indicateur `UF_COMPRESSED` apparaît sous la forme `compressed` dans `ls -lO`. Ne le supprimez pas manuellement : le système pourrait alors interpréter incorrectement la représentation compressée.

La commande qui efface l’indicateur est présentée ici car elle peut être utile lors d’un examen forensique, mais son exécution sur un fichier compressé peut donner l’impression que celui-ci est vide ou inaccessible jusqu’à la réparation de ses métadonnées :

```bash
chflags nocompressed /path/to/file
```

L’utilitaire intégré `/usr/bin/afscexpand` peut forcer la décompression de fichiers compressés de manière transparente. L’utilitaire tiers distinct `afsctool` peut également inspecter ou décompresser la compression du système de fichiers Apple, mais il ne faut pas le confondre avec la commande intégrée. <sup>[[8]](#references)</sup>


### Emplacements de configuration intéressants (macOS)

| Chemin / Emplacement | Rôle / Éléments configurés | Sécurité / Potentiel d’attaque |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Contient les fichiers plist des indicateurs de fonctionnalité d’Apple, qui contrôlent les comportements optionnels ou expérimentaux des daemons / frameworks système | Si un attaquant peut contourner SIP ou obtenir des privilèges, leur modification pourrait activer des chemins de code cachés ou désactiver des protections |
| `/System/Library/CoreServices/systemVersion.plist` | Contient les métadonnées de version de macOS (ProductVersion, BuildVersion) utilisées par les apps / installateurs pour conditionner leur comportement | Une modification peut tromper les apps ou les installateurs et leur faire accepter des versions non prises en charge de l’OS ou déverrouiller des fonctionnalités |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Préférences des applications / du système | Si ces fichiers sont accessibles en écriture, des attaquants peuvent injecter des paramètres pour orienter le comportement des apps, désactiver des protections ou provoquer une mauvaise configuration |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Définitions plist des daemons et agents en arrière-plan | L’insertion ou la manipulation de plist (si les permissions le permettent) peut assurer la persistance ou permettre des escalades de privilèges |
| `/etc/hosts` | Associations nom d’hôte ↔ IP utilisées par le résolveur DNS du système | Redirection de noms de domaine, interception du trafic, usurpation de services sous contrôle local |
| `/etc/sudoers` | Définit qui peut exécuter des commandes avec `sudo` et sous quelles conditions | Un fichier sudoers corrompu peut accorder l’accès root ou des privilèges inappropriés aux comptes d’attaquants |
| `/private/var/db/dslocal/nodes/Default/users/` | Fichiers plist de définition des comptes utilisateur locaux | Une manipulation permet de créer ou de modifier des comptes utilisateur, des hashes de mots de passe ou des métadonnées utilisateur |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Extensions du noyau / pilotes | L’installation ou la modification de kexts peut donner un contrôle au niveau du noyau ; ces éléments sont fortement protégés par SIP / les politiques de signature |
| `/private/var/db/SystemPolicyConfiguration/` | Contient la configuration de l’application des politiques système (par exemple Gatekeeper, notarisation) | Leur manipulation peut permettre de contourner les vérifications de politique ou les règles de confiance |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Binaires auxiliaires et fichiers de configuration SSH | Une mauvaise configuration peut entraîner une sécurité SSH faible, un accès non autorisé ou l’utilisation d’algorithmes non sécurisés |
| `/System/Library/Sandbox/Profiles` | Profils sandbox système (SBPL) utilisés pour restreindre les actions des processus | Le remplacement ou la modification des profils peut ouvrir des vecteurs d’évasion de sandbox ou affaiblir le confinement |

> **Remarque** : Beaucoup de ces chemins se trouvent dans des répertoires protégés par SIP (par exemple `/System`) et ne sont pas accessibles en écriture, sauf si SIP est désactivé ou contourné.  


## Binaires universels et format Mach-O

Mach-O est le format exécutable natif de macOS. Un binaire universel, ou fat, regroupe dans un seul fichier plusieurs tranches Mach-O propres à différentes architectures ; la page dédiée explique les deux formats :

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Extraction de la mémoire macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risque des fichiers et métadonnées des gestionnaires

LaunchServices, la quarantaine des fichiers et Gatekeeper influencent ensemble la façon dont macOS traite les fichiers téléchargés et choisit les applications pour les extensions et les schémas d’URL. Leurs bases de données et fichiers de ressources internes évoluent selon les versions ; consultez les pages dédiées plutôt que de considérer un chemin privé de CoreTypes comme une interface de politique stable :

Dans les versions où les métadonnées de risque CoreTypes historiques sont exposées sous `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, les catégories couramment rencontrées sont :<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`** : contenu considéré comme suffisamment sûr pour être ouvert automatiquement selon la politique applicable à l’application.
- **`LSRiskCategoryNeutral`** : contenu qui ne déclenche généralement pas d’avertissement et n’est pas ouvert automatiquement.
- **`LSRiskCategoryUnsafeExecutable`** : contenu exécutable pour lequel l’utilisateur doit recevoir un avertissement de l’application.
- **`LSRiskCategoryMayContainUnsafeExecutable`** : conteneurs, comme les archives, susceptibles de contenir du contenu exécutable et nécessitant une inspection plus approfondie.

Il s’agit de détails d’implémentation, et non d’une API publique de politique stable ; vérifiez les métadonnées réelles et le comportement de Safari/Gatekeeper sur la version de macOS testée.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Fichiers journaux

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** : contient des informations sur les fichiers téléchargés, comme l’URL depuis laquelle ils ont été téléchargés.
- **Journal unifié** : sur les versions actuelles de macOS, consultez les événements système et applicatifs avec `log show` et `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** et **`/private/var/log/asl/*.asl`** : anciens artefacts de journalisation qui peuvent encore être pertinents sur les systèmes plus anciens. Sur ces versions, `/System/Library/LaunchDaemons/com.apple.syslogd.plist` configure `syslogd` ; `launchctl list | grep com.apple.syslogd` peut aider à déterminer si le service est chargé.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`** : stocke les fichiers et applications récemment consultés via "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`** : ancien chemin de préférences associé aux éléments d’ouverture de session ; les versions modernes de macOS utilisent des mécanismes supplémentaires.
- **`$HOME/Library/Logs/DiskUtility.log`** : ancien journal d’Utilitaire de disque pouvant contenir des informations sur les lecteurs, notamment les périphériques USB.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`** : données sur les points d’accès sans fil.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`** : anciennes données de dérogation launchd.



## References

- [1] [Apple - Guide de programmation du système de fichiers](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Guide de programmation des bundles](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Forums Apple Developer - Aperçu du cache partagé dyld](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Guide de programmation du système de fichiers : sécurité du système de fichiers macOS](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - Page de manuel macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - Page de manuel macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Services de lancement](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - Page de manuel macOS](https://manp.gs/mac/1/afscexpand)
- [9] [Forums Apple Developer - Dépaquetage des archives Apple](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld - DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple - Sécurité des scripts shell : indicateurs spéciaux de permission de fichier](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple - Tâches de signature de code : packages d’installation](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
