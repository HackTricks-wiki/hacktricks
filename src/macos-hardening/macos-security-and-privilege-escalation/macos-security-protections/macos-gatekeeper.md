# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** est une fonctionnalité de sécurité développée pour les systèmes d’exploitation Mac, conçue pour garantir que les utilisateurs **n’exécutent que des logiciels fiables** sur leurs systèmes. Elle fonctionne en **validant les logiciels** qu’un utilisateur télécharge et tente d’ouvrir depuis des **sources externes à l’App Store**, comme une application, un plug-in ou un package d’installation.

Le mécanisme clé de Gatekeeper repose sur son processus de **vérification**. Il vérifie si le logiciel est **signé par un développeur reconnu**, afin de garantir son authenticité. Il détermine également si le logiciel est **notarisé par Apple**, confirmant ainsi qu’il ne contient aucun contenu malveillant connu et qu’il n’a pas été altéré après sa notarisation.

De plus, Gatekeeper renforce le contrôle et la sécurité de l’utilisateur en **lui demandant d’approuver l’ouverture** d’un logiciel téléchargé lors de sa première exécution. Cette protection permet d’éviter que les utilisateurs n’exécutent involontairement du code exécutable potentiellement dangereux qu’ils auraient pu prendre pour un fichier de données inoffensif.

### Signatures des applications

Les signatures d’application, également appelées signatures de code, constituent un élément essentiel de l’infrastructure de sécurité d’Apple. Elles servent à **vérifier l’identité de l’auteur du logiciel** (le développeur) et à garantir que le code n’a pas été altéré depuis sa dernière signature.

Voici comment cela fonctionne :

1. **Signature de l’application :** lorsqu’un développeur est prêt à distribuer son application, il **signe l’application à l’aide d’une clé privée**. Cette clé privée est associée à un **certificat délivré par Apple au développeur** lorsqu’il s’inscrit à l’Apple Developer Program. Le processus de signature consiste à créer un hash cryptographique de toutes les parties de l’application, puis à chiffrer ce hash avec la clé privée du développeur.
2. **Distribution de l’application :** l’application signée est ensuite distribuée aux utilisateurs avec le certificat du développeur, qui contient la clé publique correspondante.
3. **Vérification de l’application :** lorsqu’un utilisateur télécharge et tente d’exécuter l’application, le système d’exploitation de son Mac utilise la clé publique du certificat du développeur pour déchiffrer le hash. Il recalcule ensuite le hash en fonction de l’état actuel de l’application et le compare au hash déchiffré. S’ils correspondent, cela signifie que **l’application n’a pas été modifiée** depuis sa signature par le développeur, et le système autorise son exécution.

Les signatures d’application constituent un élément essentiel de la technologie Gatekeeper d’Apple. Lorsqu’un utilisateur tente **d’ouvrir une application téléchargée depuis Internet**, Gatekeeper vérifie la signature de l’application. Si celle-ci est signée avec un certificat délivré par Apple à un développeur connu et que le code n’a pas été altéré, Gatekeeper autorise l’exécution de l’application. Dans le cas contraire, il bloque l’application et en informe l’utilisateur.

Depuis macOS Catalina, **Gatekeeper vérifie également si l’application a été notarisée** par Apple, ajoutant ainsi une couche de sécurité supplémentaire. Le processus de notarisation vérifie que l’application ne présente aucun problème de sécurité connu ni code malveillant. Si ces vérifications sont concluantes, Apple ajoute un ticket à l’application que Gatekeeper peut vérifier.

#### Vérifier les signatures

Lors de l’analyse d’un **échantillon de malware**, vous devez toujours **vérifier la signature** du binaire, car le **développeur** qui l’a signé peut déjà être **lié** à des **malwares**.
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarisation

Le processus de notarisation d'Apple constitue une protection supplémentaire destinée à protéger les utilisateurs contre les logiciels potentiellement malveillants. Il consiste à **soumettre l'application du développeur pour examen** par le **Notary Service d'Apple**, qui ne doit pas être confondu avec l'App Review. Ce service est un **système automatisé** qui examine le logiciel soumis afin de détecter la présence de **contenu malveillant** et tout problème potentiel lié à la signature du code.

Si le logiciel **réussit** cette inspection sans soulever de problème, le Notary Service génère un ticket de notarisation. Le développeur doit ensuite **attacher ce ticket à son logiciel**, un processus appelé « stapling ». En outre, le ticket de notarisation est également publié en ligne, où Gatekeeper, la technologie de sécurité d'Apple, peut y accéder.

Lors de la première installation ou exécution du logiciel par l'utilisateur, l'existence du ticket de notarisation - qu'il soit attaché à l'exécutable ou trouvé en ligne - **informe Gatekeeper que le logiciel a été notarisé par Apple**. Gatekeeper affiche alors un message descriptif dans la boîte de dialogue du premier lancement, indiquant que le logiciel a été vérifié par Apple afin d'y détecter tout contenu malveillant. Ce processus renforce ainsi la confiance des utilisateurs dans la sécurité des logiciels qu'ils installent ou exécutent sur leurs systèmes.

### spctl & syspolicyd

> [!CAUTION]
> Notez qu'à partir de la version Sequoia, **`spctl`** ne permet plus de modifier la configuration de Gatekeeper.

**`spctl`** est l'outil CLI permettant d'énumérer et d'interagir avec Gatekeeper (avec le daemon `syspolicyd` via des messages XPC). Par exemple, il est possible d'afficher le **status** de GateKeeper avec :
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Notez que les vérifications de signature de GateKeeper sont effectuées uniquement sur les **fichiers possédant l'attribut Quarantine**, et non sur tous les fichiers.

GateKeeper vérifiera, conformément aux **préférences et à la signature**, si un binaire peut être exécuté :

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** est le daemon principal responsable de l'application de Gatekeeper. Il maintient une base de données située dans `/var/db/SystemPolicy`, et il est possible de trouver le code prenant en charge la [base de données ici](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), ainsi que le [modèle SQL ici](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Notez que la base de données n'est pas restreinte par SIP et est accessible en écriture par root, et que la base de données `/var/db/.SystemPolicy-default` est utilisée comme sauvegarde originale au cas où l'autre serait corrompue.

De plus, les bundles **`/var/db/gke.bundle`** et **`/var/db/gkopaque.bundle`** contiennent des fichiers avec des règles qui sont insérées dans la base de données. Vous pouvez consulter cette base de données en tant que root avec :
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
**`syspolicyd`** expose également un serveur XPC avec différentes opérations telles que `assess`, `update`, `record` et `cancel`, qui sont aussi accessibles via les API **`SecAssessment*`** de **`Security.framework`**, et **`spctl`** communique en réalité avec **`syspolicyd`** via XPC.

Notez que la première règle se terminait par "**App Store**" et la seconde par "**Developer ID**", et que dans l’image précédente, il était **possible d’exécuter des apps provenant de l’App Store et de développeurs identifiés**.\
Si vous **modifiez** ce réglage sur App Store, les règles "**Notarized Developer ID" disparaîtront**.

Il existe également des milliers de règles de **type GKE** :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Voici les hashes provenant de :

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Vous pouvez également afficher les informations précédentes avec :
```bash
sudo spctl --list
```
Les options **`--master-disable`** et **`--global-disable`** de **`spctl`** **désactiveront complètement** ces vérifications de signature :
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Lorsqu’elle est complètement activée, une nouvelle option apparaît :

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Il est possible de **vérifier si une App sera autorisée par GateKeeper** avec :
```bash
spctl --assess -v /Applications/App.app
```
Il est possible d’ajouter de nouvelles règles dans GateKeeper pour autoriser l’exécution de certaines applications avec :
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
Concernant les **kernel extensions**, le dossier `/var/db/SystemPolicyConfiguration` contient des fichiers avec des listes de kexts autorisés à être chargés. De plus, `spctl` dispose de l’entitlement `com.apple.private.iokit.nvram-csr`, car il est capable d’ajouter de nouvelles kernel extensions pré-approuvées, qui doivent également être enregistrées dans la NVRAM sous une clé `kext-allowed-teams`.

#### Gestion de Gatekeeper sur macOS 15 (Sequoia) et versions ultérieures

- Le contournement Finder **Ctrl+Open / clic droit → Open**, utilisé depuis longtemps, a été supprimé ; les utilisateurs doivent explicitement autoriser une application bloquée via **System Settings → Privacy & Security → Open Anyway** après la première boîte de dialogue de blocage.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` ne sont plus acceptés ; `spctl` est désormais essentiellement en lecture seule pour l’évaluation et la gestion des labels, tandis que l’application des politiques est configurée via l’interface ou MDM.

Depuis macOS 15 Sequoia, les utilisateurs finaux ne peuvent plus basculer la politique de Gatekeeper depuis `spctl`. La gestion s’effectue via System Settings ou en déployant un profil de configuration MDM avec le payload `com.apple.systempolicy.control`. Exemple de fragment de profil autorisant l’App Store et les développeurs identifiés (mais pas « Anywhere ») :

<details>
<summary>Profil MDM autorisant l’App Store et les développeurs identifiés</summary>
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>PayloadContent</key>
<array>
<dict>
<key>PayloadType</key>
<string>com.apple.systempolicy.control</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadIdentifier</key>
<string>com.example.gatekeeper</string>
<key>EnableAssessment</key>
<true/>
<key>AllowIdentifiedDevelopers</key>
<true/>
</dict>
</array>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadIdentifier</key>
<string>com.example.profile.gatekeeper</string>
<key>PayloadUUID</key>
<string>00000000-0000-0000-0000-000000000000</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadDisplayName</key>
<string>Gatekeeper</string>
</dict>
</plist>
```
</details>

### Fichiers en quarantaine

Lors du **téléchargement** d'une application ou d'un fichier, certaines **applications** macOS, telles que les navigateurs web ou les clients de messagerie, **attachent un attribut de fichier étendu**, communément appelé "**quarantine flag**", au fichier téléchargé. Cet attribut agit comme une mesure de sécurité pour **marquer le fichier** comme provenant d'une source non fiable (Internet) et pouvant présenter des risques. Cependant, toutes les applications n'attachent pas cet attribut ; par exemple, les logiciels clients BitTorrent courants contournent généralement ce processus.

**La présence d'un quarantine flag signale la fonctionnalité de sécurité Gatekeeper de macOS lorsqu'un utilisateur tente d'exécuter le fichier**.

Lorsque le **quarantine flag est absent** (comme pour les fichiers téléchargés via certains clients BitTorrent), les **vérifications de Gatekeeper peuvent ne pas être effectuées**. Les utilisateurs doivent donc faire preuve de prudence lorsqu'ils ouvrent des fichiers téléchargés depuis des sources moins sûres ou inconnues.

> [!NOTE] > **Vérifier** la **validité** des signatures de code est un processus **intensif en ressources** qui comprend la génération de **hashes cryptographiques** du code et de toutes ses ressources intégrées. De plus, la vérification de la validité du certificat implique d'effectuer une **vérification en ligne** auprès des serveurs d'Apple afin de déterminer s'il a été révoqué après son émission. Pour ces raisons, une vérification complète de la signature du code et de la notarisation est **impossible à effectuer à chaque lancement d'une application**.
>
> Par conséquent, ces vérifications sont **uniquement effectuées lors de l'exécution d'applications possédant l'attribut quarantine**.

> [!WARNING]
> Cet attribut doit être **défini par l'application qui crée ou télécharge** le fichier.
>
> Cependant, les fichiers créés dans une sandbox auront cet attribut défini pour chaque fichier qu'ils créent. Les applications qui ne sont pas dans une sandbox peuvent le définir elles-mêmes ou spécifier la clé [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) dans le fichier **Info.plist**, ce qui amènera le système à définir l'attribut étendu `com.apple.quarantine` sur les fichiers créés,

De plus, tous les fichiers créés par un processus appelant **`qtn_proc_apply_to_self`** sont mis en quarantaine. L'API **`qtn_file_apply_to_path`** ajoute également l'attribut de quarantaine à un chemin de fichier spécifié.

Il est possible de **vérifier son état et de l'activer ou le désactiver** (root requis) avec :
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Vous pouvez également **vérifier si un fichier possède l’attribut étendu de quarantaine** avec :
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Vérifiez la **valeur** des **attributs** **étendus** et identifiez l’application qui a écrit l’attribut quarantine avec :
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
En fait, un processus « pourrait définir des indicateurs de quarantaine sur les fichiers qu’il crée » (j’ai déjà essayé d’appliquer l’indicateur `USER_APPROVED` à un fichier créé, mais cela ne fonctionne pas) :

<details>

<summary>Code source pour appliquer les indicateurs de quarantaine</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

Et **supprimez** cet attribut avec :
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Et trouvez tous les fichiers mis en quarantaine avec :
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Les informations de Quarantine sont également stockées dans une base de données centrale gérée par LaunchServices dans **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, ce qui permet à l'interface graphique d'obtenir des données sur l'origine des fichiers. De plus, ces informations peuvent être écrasées par des applications qui pourraient vouloir masquer leur origine. Cela peut également être effectué depuis les LaunchServices APIS.

#### **libquarantine.dylib**

Cette bibliothèque exporte plusieurs fonctions permettant de manipuler les champs des attributs étendus.

Les APIs `qtn_file_*` traitent les politiques de file quarantine, tandis que les APIs `qtn_proc_*` s'appliquent aux processus (fichiers créés par le processus). Les fonctions non exportées `__qtn_syscall_quarantine*` sont celles qui appliquent les politiques et appellent `mac_syscall` avec « Quarantine » comme premier argument, ce qui envoie les requêtes à `Quarantine.kext`.

#### **Quarantine.kext**

L'extension kernel est uniquement disponible dans le **kernel cache du système** ; cependant, vous _pouvez télécharger le **Kernel Debug Kit depuis** [**https://developer.apple.com/**](https://developer.apple.com/), qui contiendra une version symbolicated de l'extension.

Ce Kext utilise MACF pour intercepter plusieurs appels afin de capturer tous les événements du cycle de vie des fichiers : création, ouverture, renommage, hard-linkning... et même `setxattr`, afin d'empêcher la définition de l'attribut étendu `com.apple.quarantine`.

Il utilise également quelques MIBs :

- `security.mac.qtn.sandbox_enforce` : applique Quarantine avec Sandbox
- `security.mac.qtn.user_approved_exec` : les procs en Quarantine peuvent uniquement exécuter des fichiers approuvés

#### Provenance xattr (Ventura et versions ultérieures)

macOS 13 Ventura a introduit un mécanisme de provenance distinct, qui est alimenté la première fois qu'une app en Quarantine est autorisée à s'exécuter.<sup>[[2]](#references)</sup> Deux artefacts sont créés :

- L'xattr `com.apple.provenance` sur le répertoire du bundle `.app` (valeur binaire de taille fixe contenant une clé primaire et des flags).
- Une ligne dans la table `provenance_tracking` de la base de données ExecPolicy située dans `/var/db/SystemPolicyConfiguration/ExecPolicy/`, qui stocke le cdhash et les métadonnées de l'app.

Utilisation pratique :
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect est une fonctionnalité **anti-malware** intégrée à macOS. XProtect **vérifie chaque application lors de son premier lancement ou de sa modification par rapport à sa base de données** de malware connus et de types de fichiers dangereux. Lorsque vous téléchargez un fichier via certaines apps, comme Safari, Mail ou Messages, XProtect analyse automatiquement le fichier. S'il correspond à un malware connu dans sa base de données, XProtect **empêche l'exécution du fichier** et vous alerte de la menace.

La base de données de XProtect est **régulièrement mise à jour** par Apple avec de nouvelles définitions de malware, et ces mises à jour sont automatiquement téléchargées et installées sur votre Mac. Cela garantit que XProtect est toujours à jour face aux dernières menaces connues.

Cependant, il convient de noter que **XProtect n'est pas une solution antivirus complète**. Il vérifie uniquement une liste spécifique de menaces connues et n'effectue pas d'analyse à l'accès comme la plupart des logiciels antivirus.

Vous pouvez obtenir des informations sur la dernière mise à jour de XProtect en exécutant :
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect se trouve dans un emplacement protégé par SIP à **/Library/Apple/System/Library/CoreServices/XProtect.bundle** et, à l'intérieur du bundle, vous pouvez trouver les informations utilisées par XProtect :

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`** : Autorise le code correspondant à ces cdhashes à utiliser les entitlements legacy.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`** : Liste des plugins et extensions dont le chargement est interdit via leur BundleID et TeamID, ou indiquant une version minimale.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`** : Règles Yara permettant de détecter les malware.
- **`XProtect.bundle/Contents/Resources/gk.db`** : Base de données SQLite3 contenant les hashes des applications bloquées et des TeamIDs.

Notez qu'il existe une autre App dans **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, liée à XProtect, qui n'intervient pas dans le processus Gatekeeper.

> XProtect Remediator : Sur les versions modernes de macOS, Apple fournit des scanners à la demande (XProtect Remediator) qui s'exécutent périodiquement via launchd afin de détecter et de remédier aux familles de malware. Vous pouvez observer ces scans dans les unified logs :
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Pas Gatekeeper

> [!CAUTION]
> Notez que Gatekeeper **n'est pas exécuté à chaque fois** que vous exécutez une application ; seul _**AppleMobileFileIntegrity**_ **vérifiera les signatures du code exécutable** lorsque vous exécutez une app qui a déjà été exécutée et vérifiée par Gatekeeper.

Par conséquent, il était auparavant possible d'exécuter une app afin de la mettre en cache avec Gatekeeper, puis de **modifier les fichiers non exécutables de l'application** (comme les fichiers Electron asar ou NIB) ; si aucune autre protection n'était en place, l'application était **exécutée** avec les ajouts **malicious**.

Cependant, cela n'est désormais plus possible, car macOS **empêche la modification des fichiers** à l'intérieur des applications bundles. Ainsi, si vous essayez l'attaque [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), vous constaterez qu'il n'est plus possible de l'exploiter, car après avoir exécuté l'app pour la mettre en cache avec Gatekeeper, vous ne pourrez pas modifier le bundle. Et si vous changez, par exemple, le nom du répertoire Contents en NotCon (comme indiqué dans l'exploit), puis exécutez le binaire principal de l'app pour la mettre en cache avec Gatekeeper, cela déclenchera une erreur et l'app ne s'exécutera pas.

## Gatekeeper Bypasses

Tout moyen de bypass Gatekeeper (parvenir à faire télécharger quelque chose à l'utilisateur et à lui faire exécuter ce contenu alors que Gatekeeper devrait l'interdire) est considéré comme une vulnérabilité dans macOS. Voici quelques CVE attribués à des techniques qui permettaient de bypass Gatekeeper par le passé :

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Il a été observé que si l'**Archive Utility** est utilisée pour l'extraction, les fichiers dont les **paths dépassent 886 caractères** ne reçoivent pas l'attribut étendu com.apple.quarantine. Cette situation permet involontairement à ces fichiers de **contourner les** contrôles de sécurité de Gatekeeper.<sup>[[5]](#references)</sup>

Consultez le [**rapport original**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) pour plus d'informations.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Lorsqu'une application est créée avec **Automator**, les informations concernant ce dont elle a besoin pour s'exécuter se trouvent dans `application.app/Contents/document.wflow`, et non dans l'exécutable. L'exécutable est simplement un binaire Automator générique appelé **Automator Application Stub**.

Par conséquent, vous pouviez faire pointer `application.app/Contents/MacOS/Automator\ Application\ Stub` **vers un autre Automator Application Stub du système à l'aide d'un lien symbolique**, et il exécuterait le contenu de `document.wflow` (votre script) **sans déclencher Gatekeeper**, car l'exécutable réel ne possède pas l'xattr quarantine.<sup>[[6]](#references)</sup>

Exemple d'emplacement attendu : `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consultez le [**rapport original**](https://ronmasas.com/posts/bypass-macos-gatekeeper) pour plus d'informations.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Dans ce bypass, un fichier zip était créé avec une application dont la compression commençait à partir de `application.app/Contents` au lieu de `application.app`. Par conséquent, l'**attribut quarantine** était appliqué à tous les **fichiers de `application.app/Contents`**, mais pas à **`application.app`**, qui est l'élément vérifié par Gatekeeper. Gatekeeper était donc bypassé, car lorsque `application.app` était déclenchée, elle **ne possédait pas l'attribut quarantine.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Consultez le [**rapport original**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) pour plus d’informations.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Même si les composants sont différents, l’exploitation de cette vulnérabilité est très similaire à la précédente. Dans ce cas, nous allons générer une Apple Archive à partir de **`application.app/Contents`**, de sorte que **`application.app` ne recevra pas l’attribut de quarantaine** lors de sa décompression par **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Consultez le [**rapport original**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) pour plus d’informations.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

L’ACL **`writeextattr`** peut être utilisée pour empêcher quiconque d’écrire un attribut dans un fichier :
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
De plus, le format de fichier **AppleDouble** copie un fichier, y compris ses ACEs.<sup>[[9]](#references)</sup>

Dans le [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), il est possible de voir que la représentation textuelle de l'ACL stockée dans l'xattr appelé **`com.apple.acl.text`** va être définie comme ACL dans le fichier décompressé. Ainsi, si vous avez compressé une application dans un fichier zip au format **AppleDouble** avec une ACL qui empêche l'écriture d'autres xattrs... l'xattr de quarantine n'était pas défini sur l'application :
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Consultez le [**rapport original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) pour plus d’informations.<sup>[[9]](#references)</sup>

Notez que cela pourrait également être exploité avec AppleArchives :
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Il a été découvert que **Google Chrome ne définissait pas l’attribut quarantine** pour les fichiers téléchargés en raison de certains problèmes internes à macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble stocke les attributs d’un fichier dans un fichier distinct dont le nom commence par `._` ; cela permet de copier les attributs des fichiers **entre des machines macOS**. Cependant, après la décompression d’un fichier AppleDouble, le fichier commençant par `._` **ne recevait pas l’attribut quarantine**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
Pouvoir créer un fichier qui n’aurait pas l’attribut quarantine défini, il était **possible de contourner Gatekeeper.** L’astuce consistait à **créer une application dans un fichier DMG** en utilisant la convention de nommage AppleDouble (commencer par `._`) et à créer un **fichier visible sous forme de lien symbolique vers ce fichier caché** sans attribut quarantine.\
Lorsque le **fichier DMG est exécuté**, comme il ne possède pas d’attribut quarantine, il **contournera Gatekeeper**.
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### [CVE-2023-41067]

Un bypass de Gatekeeper corrigé dans macOS Sonoma 14.0 permettait à des apps conçues à cet effet de s’exécuter sans afficher de demande. Les détails ont été divulgués publiquement après le correctif, et le problème était activement exploité dans la nature avant sa correction. Assurez-vous que Sonoma 14.0 ou une version ultérieure est installée.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Un bypass de Gatekeeper dans macOS 14.4 (sorti en mars 2024), dû au traitement des ZIP malveillants par `libarchive`, permettait à des apps d’échapper à l’évaluation. Effectuez la mise à jour vers la version 14.4 ou une version ultérieure, dans laquelle Apple a corrigé le problème.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Un **Automator Quick Action workflow** intégré dans une app téléchargée pouvait se déclencher sans évaluation par Gatekeeper, car les workflows étaient traités comme des données et exécutés par l’assistant Automator en dehors du chemin normal de demande de notarization. Une `.app` conçue à cet effet et contenant une Quick Action qui exécute un shell script (par exemple dans `Contents/PlugIns/*.workflow/Contents/document.wflow`) pouvait donc s’exécuter immédiatement au lancement. Apple a ajouté une boîte de dialogue de consentement supplémentaire et corrigé le chemin d’évaluation dans Ventura **13.7**, Sonoma **14.7** et Sequoia **15**.<sup>[[3]](#references)</sup>

### Outils de décompression tiers propageant mal la quarantine (2023–2024)

Plusieurs vulnérabilités dans des outils d’extraction populaires (par exemple The Unarchiver) empêchaient les fichiers extraits d’archives de recevoir l’attribut étendu `com.apple.quarantine`, ce qui permettait des opportunités de bypass de Gatekeeper. Utilisez toujours macOS Archive Utility ou des outils corrigés lors des tests, et validez les attributs étendus après l’extraction.

### uchg (d’après ce [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Créez un répertoire contenant une app.
- Ajoutez uchg à l’app.
- Compressez l’app dans un fichier tar.gz.
- Envoyez le fichier tar.gz à une victime.
- La victime ouvre le fichier tar.gz et exécute l’app.
- Gatekeeper ne vérifie pas l’app.<sup>[[12]](#references)</sup>

### Empêcher l’attribut étendu Quarantine

Dans un bundle ".app", si l’attribut étendu quarantine ne lui est pas ajouté, **Gatekeeper ne sera pas déclenché** lors de son exécution.

## References

- [1] [Apple Platform Security : À propos du contenu de sécurité de macOS Sonoma 14.4 (inclut CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light : Comment macOS suit désormais la provenance des apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple : À propos du contenu de sécurité de macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors : macOS 15 Sequoia supprime le bypass Gatekeeper « Ouvrir » avec un clic de contrôle](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs : La découverte de CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Bypassing The macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifie une vulnérabilité de Safari permettant un bypass de Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifie une vulnérabilité de macOS Archive Utility permettant un bypass de Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Le talon d’Achille de Gatekeeper : découverte d’une vulnérabilité macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure : Découverte d’un bypass de Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Trouver et signaler un exploit de bypass de Gatekeeper avec l’aide de Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023 : Bypassing macOS Security and Privacy Mechanisms — From Gatekeeper to System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple : À propos du contenu de sécurité de macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
{{#include ../../../banners/hacktricks-training.md}}
