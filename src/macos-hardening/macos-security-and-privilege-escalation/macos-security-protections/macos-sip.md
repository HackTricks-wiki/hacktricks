# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Informations de base**

**System Integrity Protection (SIP)** dans macOS est un mécanisme conçu pour empêcher même les utilisateurs les plus privilégiés d’apporter des modifications non autorisées aux dossiers système essentiels. Cette fonctionnalité joue un rôle crucial dans le maintien de l’intégrité du système en restreignant les actions telles que l’ajout, la modification ou la suppression de fichiers dans les zones protégées. Les principaux dossiers protégés par SIP sont les suivants :

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Les règles qui régissent le fonctionnement de SIP sont définies dans le fichier de configuration situé à **`/System/Library/Sandbox/rootless.conf`**. Dans ce fichier, les chemins précédés d’un astérisque (\*) sont désignés comme des exceptions aux restrictions SIP normalement strictes.

Prenons l’exemple ci-dessous :
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Cet extrait indique que, bien que SIP protège généralement le répertoire **`/usr`**, certaines sous-répertoires (`/usr/libexec/cups`, `/usr/local` et `/usr/share/man`) peuvent être modifiés, comme l’indique l’astérisque (\*) précédant leurs chemins.

Pour vérifier si un répertoire ou un fichier est protégé par SIP, vous pouvez utiliser la commande **`ls -lOd`** afin de rechercher la présence de l’attribut **`restricted`** ou **`sunlnk`**. Par exemple :
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Dans ce cas, le flag **`sunlnk`** signifie que le répertoire `/usr/libexec/cups` lui-même **ne peut pas être supprimé**, bien que des fichiers puissent y être créés, modifiés ou supprimés.

En revanche :
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Ici, le flag **`restricted`** indique que le répertoire `/usr/libexec` est protégé par SIP. Dans un répertoire protégé par SIP, les fichiers ne peuvent pas être créés, modifiés ou supprimés.

De plus, si un fichier contient l’**attribut** étendu **`com.apple.rootless`**, ce fichier sera également **protégé par SIP**.

> [!TIP]
> Notez que le hook **`hook_vnode_check_setextattr`** de **Sandbox** empêche toute tentative de modification de l’attribut étendu **`com.apple.rootless`.**

**SIP limite également d’autres actions root**, notamment :

- Le chargement d’extensions kernel non approuvées
- L’obtention de task-ports pour les processus signés par Apple
- La modification des variables NVRAM
- L’autorisation du kernel debugging

Les options sont conservées dans une variable nvram sous forme de bitflag (`csr-active-config` sur Intel et `lp-sip0` est lu depuis le Device Tree démarré sur ARM). Vous pouvez trouver les flags dans le code source de XNU, dans `csr.sh` :

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Statut de SIP

Vous pouvez vérifier si SIP est activé sur votre système avec la commande suivante :
```bash
csrutil status
```
Si vous devez désactiver SIP, vous devez redémarrer votre ordinateur en mode récupération (en appuyant sur Command+R pendant le démarrage), puis exécuter la commande suivante :
```bash
csrutil disable
```
Si vous souhaitez conserver SIP activé tout en supprimant les protections de debugging, vous pouvez le faire avec :
```bash
csrutil enable --without debug
```
### Autres restrictions

- **Interdit le chargement des extensions kernel non signées** (kexts), garantissant que seules les extensions vérifiées interagissent avec le kernel du système.
- **Empêche le debugging** des processus système de macOS, protégeant les composants essentiels du système contre tout accès et toute modification non autorisés.
- **Empêche les outils** tels que dtrace d'inspecter les processus système, protégeant davantage l'intégrité du fonctionnement du système.

[**En savoir plus sur SIP dans cette présentation**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[1]</sup>

### **Entitlements liés à SIP**

- `com.apple.rootless.xpc.bootstrap` : Contrôler launchd
- `com.apple.rootless.install[.heritable]` : Accéder au file system
- `com.apple.rootless.kext-management` : `kext_request`
- `com.apple.rootless.datavault.controller` : Gérer UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap` : Capacités de configuration XPC
- `com.apple.rootless.xpc.effective-root` : Obtenir root via launchd XPC
- `com.apple.rootless.restricted-block-devices` : Accéder aux périphériques block bruts
- `com.apple.rootless.internal.installer-equivalent` : Accès sans restriction au file system
- `com.apple.rootless.restricted-nvram-variables[.heritable]` : Accès complet à la NVRAM
- `com.apple.rootless.storage.label` : Modifier les fichiers restreints par l'xattr com.apple.rootless avec le label correspondant
- `com.apple.rootless.volume.VM.label` : Maintenir le swap VM sur le volume

## SIP Bypasses

Le bypass de SIP permet à un attaquant de :

- **Accéder aux données utilisateur** : Lire des données utilisateur sensibles telles que les e-mails, les messages et l'historique Safari de tous les comptes utilisateur.
- **TCC Bypass** : Manipuler directement la base de données TCC (Transparency, Consent, and Control) afin d'accorder un accès non autorisé à la webcam, au microphone et à d'autres ressources.
- **Établir une persistence** : Placer des malwares dans des emplacements protégés par SIP, les rendant résistants à la suppression, même avec les privilèges root. Cela inclut également la possibilité de modifier le Malware Removal Tool (MRT).
- **Charger des extensions kernel** : Bien qu'il existe des protections supplémentaires, le bypass de SIP simplifie le chargement d'extensions kernel non signées.

### Packages Installer

**Les packages Installer signés avec le certificat d'Apple** peuvent bypass ses protections. Cela signifie que même les packages signés par des développeurs standards seront bloqués s'ils tentent de modifier des répertoires protégés par SIP.

### Fichier SIP inexistant

Une faille potentielle existe lorsqu'un fichier spécifié dans **`rootless.conf` mais qui n'existe pas actuellement** peut être créé. Un malware pourrait exploiter cela pour **établir une persistence** sur le système. Par exemple, un programme malveillant pourrait créer un fichier .plist dans `/System/Library/LaunchDaemons` s'il est listé dans `rootless.conf` mais absent.

### com.apple.rootless.install.heritable

> [!CAUTION]
> L'entitlement **`com.apple.rootless.install.heritable`** permet de bypass SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Il a été découvert qu'il était possible de **remplacer le package Installer après que le système avait vérifié la signature** de son code, puis le système installait le package malveillant à la place de l'original. Comme ces actions étaient effectuées par **`system_installd`**, cela permettait de bypass SIP.<sup>[2]</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Si un package était installé depuis une image montée ou un disque externe, **l'Installer** **exécutait** le binaire depuis **ce file system** (au lieu d'un emplacement protégé par SIP), ce qui permettait à **`system_installd`** d'exécuter un binaire arbitraire.<sup>[3]</sup>

#### CVE-2021-30892 - Shrootless

[**Les chercheurs de cet article de blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) ont découvert une vulnérabilité dans le mécanisme System Integrity Protection (SIP) de macOS, surnommée la vulnérabilité « Shrootless ». Cette vulnérabilité concerne le daemon **`system_installd`**, qui possède un entitlement, **`com.apple.rootless.install.heritable`**, permettant à tous ses processus enfants de bypass les restrictions SIP du file system.<sup>[4]</sup>

Le daemon **`system_installd`** installe les packages signés par **Apple**.

Les chercheurs ont découvert que lors de l'installation d'un package signé par Apple (fichier .pkg), **`system_installd`** **exécute** tous les scripts **post-installation** inclus dans le package. Ces scripts sont exécutés par le shell par défaut, **`zsh`**, qui **exécute** automatiquement les commandes du fichier **`/etc/zshenv`**, s'il existe, même en mode non interactif. Ce comportement pouvait être exploité par des attaquants : en créant un fichier `/etc/zshenv` malveillant et en attendant que **`system_installd` invoque `zsh`**, ils pouvaient effectuer des opérations arbitraires sur l'appareil.<sup>[4]</sup>

En outre, il a été découvert que **`/etc/zshenv` pouvait être utilisé comme technique d'attaque générale**, et pas uniquement pour bypass SIP. Chaque profil utilisateur possède un fichier `~/.zshenv`, qui se comporte de la même manière que `/etc/zshenv`, mais ne nécessite pas les permissions root. Ce fichier pouvait être utilisé comme mécanisme de persistence, en se déclenchant à chaque démarrage de `zsh`, ou comme mécanisme d'élévation de privilèges. Si un utilisateur admin élève ses privilèges vers root à l'aide de `sudo -s` ou `sudo <command>`, le fichier `~/.zshenv` serait déclenché, permettant effectivement d'obtenir les privilèges root.<sup>[4]</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

Dans [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/), il a été découvert que le même processus **`system_installd`** pouvait toujours être exploité, car il plaçait le **script post-installation dans un dossier au nom aléatoire protégé par SIP dans `/tmp`**. Le problème est que **`/tmp` lui-même n'est pas protégé par SIP** ; il était donc possible d'y **monter** une **image virtuelle**, puis l'**Installer** y plaçait le **script post-installation**, **démontait** l'image virtuelle, **recréait** tous les **dossiers** et **ajoutait** le script de **post-installation** contenant le **payload** à exécuter.<sup>[5]</sup>

#### [Utilitaire fsck_cs](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Une vulnérabilité a été identifiée : **`fsck_cs`** était amené à corrompre un fichier essentiel en raison de sa capacité à suivre les **symbolic links**. Plus précisément, les attaquants créaient un lien de _`/dev/diskX`_ vers le fichier `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. L'exécution de **`fsck_cs`** sur _`/dev/diskX`_ entraînait la corruption de `Info.plist`. L'intégrité de ce fichier est essentielle pour le SIP (System Integrity Protection) du système d'exploitation, qui contrôle le chargement des extensions kernel. Une fois corrompue, la capacité de SIP à gérer les exclusions kernel est compromise.<sup>[6]</sup>

Les commandes permettant d'exploiter cette vulnérabilité sont :
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
L'exploitation de cette vulnérabilité a de graves implications. Le fichier `Info.plist`, normalement chargé de gérer les permissions des extensions du kernel, devient inefficace. Cela inclut l'impossibilité de blacklister certaines extensions, telles que `AppleHWAccess.kext`. Par conséquent, le mécanisme de contrôle de SIP étant hors service, cette extension peut être chargée, accordant un accès non autorisé en lecture et en écriture à la RAM du système.<sup>[6]</sup>

#### [Monter un système de fichiers par-dessus les dossiers protégés par SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Il était possible de monter un nouveau système de fichiers par-dessus les **dossiers protégés par SIP afin de contourner la protection**.<sup>[1]</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Le système est configuré pour démarrer depuis une image disque d’installation intégrée à `Install macOS Sierra.app` afin de mettre à niveau l’OS, en utilisant l’utilitaire `bless`. La commande utilisée est la suivante :<sup>[7]</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
La sécurité de ce processus peut être compromise si un attaquant modifie l’image de mise à niveau (`InstallESD.dmg`) avant le démarrage. La stratégie consiste à remplacer un dynamic loader (dyld) par une version malveillante (`libBaseIA.dylib`). Ce remplacement entraîne l’exécution du code de l’attaquant lorsque l’installateur est lancé.<sup>[7]</sup>

Le code de l’attaquant prend le contrôle pendant le processus de mise à niveau en exploitant la confiance du système envers l’installateur. L’attaque consiste à modifier l’image `InstallESD.dmg` via le method swizzling, en ciblant notamment la méthode `extractBootBits`. Cela permet d’injecter du code malveillant avant l’utilisation de l’image disque.<sup>[7]</sup>

De plus, `InstallESD.dmg` contient un fichier `BaseSystem.dmg`, qui sert de système de fichiers racine au code de mise à niveau. L’injection d’une dynamic library dans celui-ci permet au code malveillant de s’exécuter au sein d’un processus capable de modifier des fichiers au niveau du système d’exploitation, ce qui augmente considérablement le potentiel de compromission du système.<sup>[7]</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Dans cette présentation de la [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), il est montré comment **`systemmigrationd`** (qui peut contourner SIP) exécute un script **bash** et un script **perl**, lesquels peuvent être exploités via les variables d’environnement **`BASH_ENV`** et **`PERL5OPT`**.<sup>[8]</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Comme [**expliqué en détail dans cet article de blog**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), un script `postinstall` de packages `InstallAssistant.pkg` autorisés était exécuté :<sup>[9]</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
et il était possible de créer un lien symbolique dans `${SHARED_SUPPORT_PATH}/SharedSupport.dmg`, ce qui permettait à un utilisateur de **supprimer les restrictions de n’importe quel fichier, en contournant la protection SIP**.<sup>[9]</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> L’entitlement **`com.apple.rootless.install`** permet de contourner SIP

L’entitlement `com.apple.rootless.install` est connu pour permettre de contourner System Integrity Protection (SIP) sur macOS. Cela a notamment été mentionné en lien avec [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).<sup>[10]</sup>

Dans ce cas précis, le service XPC système situé à `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possède cet entitlement. Cela permet au processus associé de contourner les restrictions de SIP. De plus, ce service présente notamment une méthode qui permet de déplacer des fichiers sans appliquer de mesures de sécurité.<sup>[10]</sup>

## Instantanés système scellés

Les instantanés système scellés sont une fonctionnalité introduite par Apple dans **macOS Big Sur (macOS 11)** dans le cadre de son mécanisme **System Integrity Protection (SIP)**, afin de fournir une couche supplémentaire de sécurité et de stabilité au système. Il s’agit essentiellement de versions en lecture seule du volume système.

Voici un aperçu plus détaillé :

1. **Système immuable** : les instantanés système scellés rendent le volume système de macOS « immuable », ce qui signifie qu’il ne peut pas être modifié. Cela empêche les modifications non autorisées ou accidentelles du système susceptibles de compromettre la sécurité ou la stabilité du système.
2. **Mises à jour logicielles du système** : lorsque vous installez des mises à jour ou des upgrades de macOS, macOS crée un nouvel instantané système. Le volume de démarrage de macOS utilise alors **APFS (Apple File System)** pour basculer vers ce nouvel instantané. L’ensemble du processus d’application des mises à jour devient plus sûr et plus fiable, car le système peut toujours revenir à l’instantané précédent en cas de problème pendant la mise à jour.
3. **Séparation des données** : conjointement avec le concept de séparation des volumes Data et System introduit dans macOS Catalina, la fonctionnalité d’instantané système scellé garantit que toutes vos données et tous vos réglages sont stockés sur un volume "**Data**" distinct. Cette séparation rend vos données indépendantes du système, ce qui simplifie le processus de mise à jour du système et renforce la sécurité du système.

N’oubliez pas que ces instantanés sont gérés automatiquement par macOS et n’occupent pas d’espace supplémentaire sur votre disque grâce aux fonctionnalités de partage d’espace d’APFS. Il est également important de noter que ces instantanés sont différents des **instantanés Time Machine**, qui sont des sauvegardes accessibles à l’utilisateur de l’intégralité du système.

### Vérifier les instantanés

La commande **`diskutil apfs list`** affiche les **détails des volumes APFS** et leur disposition :

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-< Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

Dans la sortie précédente, il est possible de voir que les **emplacements accessibles à l’utilisateur** sont montés sous `/System/Volumes/Data`.

De plus, **l’instantané du volume système de macOS** est monté dans `/` et il est **scellé** (signé cryptographiquement par l’OS). Ainsi, si SIP est contourné et qu’il est modifié, **l’OS ne démarrera plus**.

Il est également possible de **vérifier que le scellage est activé** en exécutant :
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
De plus, le disque snapshot est également monté en **lecture seule** :
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Références

- [1] [SyScan360 - Stefan Esser - OS X El Capitan fait sombrer le S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Blog Objective-See](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854 : « Unauthd » (trois) bugs logiques ftw ! - Blog Objective-See](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft découvre une nouvelle vulnérabilité macOS, Shrootless, qui pourrait contourner la System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Analyse technique : CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [La sécurité rootless sans root d’Apple, privée de fruits, cassée par du code tenant dans un tweet - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Contourner la System Integrity Protection d’Apple - Blog Objective-See](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - Contournement unique de SIP sur MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple atténue les vulnérabilités dans les scripts d’installation - Blog Kandji](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712 : la POC pour le contournement de SIP tient même dans un tweet](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
