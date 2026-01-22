# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** est une fonctionnalité de sécurité développée pour les systèmes d'exploitation Mac, conçue pour s'assurer que les utilisateurs **exécutent uniquement des logiciels de confiance** sur leurs systèmes. Elle fonctionne en **validant les logiciels** qu'un utilisateur télécharge et tente d'ouvrir depuis des **sources en dehors de l'App Store**, comme une application, un plug-in ou un paquet d'installation.

Le mécanisme clé de Gatekeeper réside dans son processus de **vérification**. Il vérifie si le logiciel téléchargé est **signé par un développeur reconnu**, garantissant l'authenticité du logiciel. De plus, il s'assure que le logiciel est **notarisé par Apple**, confirmant qu'il est dépourvu de contenu malveillant connu et qu'il n'a pas été altéré après la notarisation.

En outre, Gatekeeper renforce le contrôle et la sécurité de l'utilisateur en **demandant aux utilisateurs d'approuver l'ouverture** du logiciel téléchargé lors de la première fois. Cette protection aide à empêcher les utilisateurs d'exécuter involontairement du code exécutable potentiellement dangereux qu'ils auraient pu confondre avec un fichier de données inoffensif.

### Signatures d'application

Les signatures d'application, aussi appelées code signatures, sont un composant critique de l'infrastructure de sécurité d'Apple. Elles sont utilisées pour **vérifier l'identité de l'auteur du logiciel** (le développeur) et pour s'assurer que le code n'a pas été altéré depuis sa dernière signature.

Voici comment cela fonctionne :

1. **Signing the Application :** Lorsqu'un développeur est prêt à distribuer son application, il **signe l'application en utilisant une clé privée**. Cette clé privée est associée à un **certificat qu'Apple délivre au développeur** lorsqu'il s'inscrit au Apple Developer Program. Le processus de signature implique la création d'un hash cryptographique de toutes les parties de l'application et le chiffrement de ce hash avec la clé privée du développeur.
2. **Distributing the Application :** L'application signée est ensuite distribuée aux utilisateurs accompagnée du certificat du développeur, qui contient la clé publique correspondante.
3. **Verifying the Application :** Lorsqu'un utilisateur télécharge et tente d'exécuter l'application, son système macOS utilise la clé publique du certificat du développeur pour déchiffrer le hash. Il recalcule ensuite le hash en fonction de l'état actuel de l'application et le compare avec le hash déchiffré. S'ils correspondent, cela signifie que **l'application n'a pas été modifiée** depuis que le développeur l'a signée, et le système autorise l'exécution de l'application.

Les signatures d'application sont une partie essentielle de la technologie Gatekeeper d'Apple. Lorsqu'un utilisateur tente **d'ouvrir une application téléchargée depuis Internet**, Gatekeeper vérifie la signature de l'application. Si elle est signée avec un certificat délivré par Apple à un développeur connu et que le code n'a pas été altéré, Gatekeeper autorise l'exécution de l'application. Sinon, il bloque l'application et avertit l'utilisateur.

À partir de macOS Catalina, **Gatekeeper vérifie également si l'application a été notarisée** par Apple, ajoutant une couche de sécurité supplémentaire. Le processus de notarisation vérifie l'application pour des problèmes de sécurité connus et du code malveillant, et si ces vérifications sont concluantes, Apple ajoute un ticket à l'application que Gatekeeper peut vérifier.

#### Vérifier les signatures

Lors de l'examen d'un **malware sample**, vous devriez toujours **vérifier la signature** du binaire car le **développeur** qui l'a signé peut déjà être **lié** au **malware.**
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

Le processus de notarisation d'Apple sert de garde-fou supplémentaire pour protéger les utilisateurs contre des logiciels potentiellement nuisibles. Il implique que le **développeur soumette son application pour examen** par **Apple's Notary Service**, qui ne doit pas être confondu avec App Review. Ce service est un **système automatisé** qui examine le logiciel soumis à la recherche de **contenu malveillant** et de tout problème potentiel lié à la signature du code.

Si le logiciel **passe** cette inspection sans soulever de préoccupations, le Notary Service génère un ticket de notarisation. Le développeur doit alors **attacher ce ticket à son logiciel**, un processus connu sous le nom de 'stapling'. De plus, le ticket de notarisation est également publié en ligne où Gatekeeper, la technologie de sécurité d'Apple, peut y accéder.

Lors de la première installation ou exécution du logiciel par l'utilisateur, la présence du ticket de notarisation — qu'il soit 'stapled' à l'exécutable ou accessible en ligne — **informe Gatekeeper que le logiciel a été notarisé par Apple**. En conséquence, Gatekeeper affiche un message descriptif dans la boîte de dialogue de lancement initiale, indiquant que le logiciel a été vérifié par Apple pour la présence de contenu malveillant. Ce processus renforce ainsi la confiance des utilisateurs dans la sécurité des logiciels qu'ils installent ou exécutent sur leurs systèmes.

### spctl & syspolicyd

> [!CAUTION]
> Notez que depuis la version Sequoia, **`spctl`** ne permet plus de modifier la configuration de Gatekeeper.

**`spctl`** est l'outil CLI pour énumérer et interagir avec Gatekeeper (avec le démon `syspolicyd` via des messages XPC). Par exemple, il est possible de voir le **statut** de GateKeeper avec :
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Notez que les vérifications de signature de GateKeeper ne sont effectuées que sur les **fichiers avec l'attribut Quarantine**, pas sur tous les fichiers.

GateKeeper vérifiera si, selon les **préférences & la signature**, un binaire peut être exécuté :

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** est le daemon principal chargé d'appliquer GateKeeper. Il maintient une base de données située dans `/var/db/SystemPolicy` et il est possible de trouver le code pour supporter la [database here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) et le [SQL template here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Notez que la base de données n'est pas restreinte par SIP et est inscriptible par root, et que la base de données `/var/db/.SystemPolicy-default` est utilisée comme sauvegarde originale au cas où l'autre serait corrompue.

De plus, les bundles **`/var/db/gke.bundle`** et **`/var/db/gkopaque.bundle`** contiennent des fichiers avec des règles qui sont insérées dans la base de données. Vous pouvez vérifier cette base de données en tant que root avec :
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
**`syspolicyd`** expose également un serveur XPC avec différentes opérations comme `assess`, `update`, `record` et `cancel` qui sont aussi accessibles en utilisant les APIs **`Security.framework`'s `SecAssessment*`** et **`spctl`** communique en fait avec **`syspolicyd`** via XPC.

Remarquez que la première règle se terminait par "**App Store**" et la deuxième par "**Developer ID**" et que, dans l'image précédente, elle était **activée pour exécuter des apps provenant de l'App Store et des développeurs identifiés**.\
Si vous **modifiez** ce paramètre sur App Store, les **"Notarized Developer ID" règles disparaîtront**.

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

Ou vous pouvez lister les informations précédentes avec :
```bash
sudo spctl --list
```
Les options **`--master-disable`** et **`--global-disable`** de **`spctl`** désactiveront complètement ces vérifications de signature :
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Lorsque l'option est complètement activée, une nouvelle option apparaîtra :

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Il est possible de **vérifier si une App sera autorisée par GateKeeper** avec :
```bash
spctl --assess -v /Applications/App.app
```
Il est possible d'ajouter de nouvelles règles dans GateKeeper pour autoriser l'exécution de certaines applications avec :
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
Concernant les **kernel extensions**, le dossier `/var/db/SystemPolicyConfiguration` contient des fichiers avec des listes de kexts autorisés à être chargés. De plus, `spctl` possède l'entitlement `com.apple.private.iokit.nvram-csr` car il est capable d'ajouter de nouvelles kernel extensions préapprouvées qui doivent également être enregistrées dans la NVRAM sous la clé `kext-allowed-teams`.

#### Gestion de Gatekeeper sur macOS 15 (Sequoia) et versions ultérieures

- Le contournement historique du Finder **Ctrl+Open / Right‑click → Open** a été supprimé ; les utilisateurs doivent explicitement autoriser une app bloquée depuis **System Settings → Privacy & Security → Open Anyway** après la première boîte de dialogue de blocage.
- `spctl --master-disable/--global-disable` ne sont plus acceptées ; `spctl` est en pratique en lecture seule pour l'évaluation et la gestion des labels, tandis que l'application de la politique se configure via l'UI ou MDM.

À partir de macOS 15 Sequoia, les utilisateurs finaux ne peuvent plus basculer la politique de Gatekeeper depuis `spctl`. La gestion s'effectue via System Settings ou en déployant un profil de configuration MDM avec la payload `com.apple.systempolicy.control`. Extrait d'exemple de profil pour autoriser l'App Store et les développeurs identifiés (mais pas "Anywhere") :

<details>
<summary>MDM profile to allow App Store and identified developers</summary>
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

Lors du **téléchargement** d'une application ou d'un fichier, certaines **applications** macOS telles que les navigateurs web ou les clients mail **ajoutent un attribut de fichier étendu**, couramment appelé le "**quarantine flag**", au fichier téléchargé. Cet attribut sert de mesure de sécurité pour **marquer le fichier** comme provenant d'une source non fiable (internet) et pouvant présenter des risques. Cependant, toutes les applications n'ajoutent pas cet attribut ; par exemple, certains clients BitTorrent contournent généralement ce processus.

**La présence d'un quarantine flag signale la fonctionnalité de sécurité Gatekeeper de macOS lorsqu'un utilisateur tente d'exécuter le fichier**.

Dans le cas où le **quarantine flag n'est pas présent** (comme pour des fichiers téléchargés via certains clients BitTorrent), les **vérifications de Gatekeeper peuvent ne pas être effectuées**. Ainsi, les utilisateurs doivent faire preuve de prudence lorsqu'ils ouvrent des fichiers téléchargés depuis des sources moins sûres ou inconnues.

> [!NOTE] > **Vérifier** la **validité** des signatures de code est un processus **consommateur de ressources** qui inclut la génération de **hashes** cryptographiques du code et de toutes ses ressources intégrées. De plus, vérifier la validité d'un certificat implique une **vérification en ligne** auprès des serveurs d'Apple pour déterminer s'il a été révoqué après émission. Pour ces raisons, une vérification complète de la signature de code et de la notarisation est **peu pratique à exécuter à chaque lancement d'une app**.
>
> Par conséquent, ces vérifications ne sont **exécutées que lors de l'exécution d'apps présentant l'attribut de quarantaine.**

> [!WARNING]
> Cet attribut doit être **défini par l'application créant/téléchargeant** le fichier.
>
> Toutefois, les fichiers créés par des applications sandboxées auront cet attribut défini pour chaque fichier qu'elles créent. Les applications non sandboxées peuvent le définir elles-mêmes, ou spécifier la clé [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) dans le **Info.plist**, ce qui fera que le système définira l'attribut étendu `com.apple.quarantine` sur les fichiers créés,

De plus, tous les fichiers créés par un processus appelant **`qtn_proc_apply_to_self`** sont mis en quarantaine. L'API **`qtn_file_apply_to_path`** ajoute quant à elle l'attribut de quarantaine à un chemin de fichier spécifié.

Il est possible de **vérifier son statut et de l'activer/désactiver** (root requis) avec :
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Vous pouvez également **vérifier si un fichier possède l'attribut étendu quarantine** avec :
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Vérifiez la **valeur** des **attributs** **étendus** et découvrez l'application qui a écrit l'attribut de quarantaine avec :
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
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
En fait, un processus "peut définir des drapeaux de quarantaine sur les fichiers qu'il crée" (j'ai déjà essayé d'appliquer le drapeau USER_APPROVED sur un fichier créé mais il ne s'applique pas) :

<details>

<summary>Code source : appliquer les drapeaux de quarantaine</summary>
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
Les informations de quarantaine sont également stockées dans une base de données centrale gérée par LaunchServices dans **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, ce qui permet à la GUI d'obtenir des données sur l'origine des fichiers. De plus, cela peut être écrasé par des applications qui pourraient être intéressées à masquer leur origine. De plus, cela peut être fait depuis les LaunchServices APIS.

#### **libquarantine.dylib**

Cette bibliothèque exporte plusieurs fonctions qui permettent de manipuler les champs d'attributs étendus.

Les APIs `qtn_file_*` gèrent les politiques de quarantaine des fichiers, les APIs `qtn_proc_*` s'appliquent aux processus (fichiers créés par le processus). Les fonctions non exportées `__qtn_syscall_quarantine*` sont celles qui appliquent les politiques : elles appellent `mac_syscall` avec "Quarantine" comme premier argument, ce qui envoie les requêtes à `Quarantine.kext`.

#### **Quarantine.kext**

L'extension kernel n'est disponible que via le **kernel cache sur le système** ; toutefois, vous _pouvez_ télécharger le **Kernel Debug Kit depuis** [**https://developer.apple.com/**](https://developer.apple.com/), qui contiendra une version symboliquée de l'extension.

Ce Kext interceptera via MACF plusieurs appels afin de piéger tous les événements du cycle de vie des fichiers : création, ouverture, renommage, création de hard-links... même `setxattr` pour l'empêcher de définir l'attribut étendu `com.apple.quarantine`.

Il utilise également quelques MIBs :

- `security.mac.qtn.sandbox_enforce`: Enforce quarantine along Sandbox
- `security.mac.qtn.user_approved_exec`: Querantined procs can only execute approved files

#### Provenance xattr (Ventura and later)

macOS 13 Ventura a introduit un mécanisme de provenance distinct qui est rempli la première fois qu'une app en quarantaine est autorisée à s'exécuter. Deux artefacts sont créés :

- The `com.apple.provenance` xattr on the `.app` bundle directory (fixed-size binary value containing a primary key and flags).
- A row in the `provenance_tracking` table inside the ExecPolicy database at `/var/db/SystemPolicyConfiguration/ExecPolicy/` storing the app’s cdhash and metadata.

Practical usage:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect est une fonctionnalité intégrée de **anti-malware** dans macOS. XProtect **vérifie toute application lorsqu'elle est lancée pour la première fois ou modifiée par rapport à sa base de données** de malware connus et de types de fichiers dangereux. Lorsque vous téléchargez un fichier via certaines apps, telles que Safari, Mail ou Messages, XProtect scanne automatiquement le fichier. Si celui-ci correspond à un malware connu dans sa base de données, XProtect **empêchera l'exécution du fichier** et vous avertira de la menace.

La base de données XProtect est **mise à jour régulièrement** par Apple avec de nouvelles définitions de malware, et ces mises à jour sont automatiquement téléchargées et installées sur votre Mac. Cela garantit que XProtect est toujours à jour avec les dernières menaces connues.

Cependant, il convient de noter que **XProtect n'est pas une solution antivirus complète**. Il ne vérifie qu'une liste spécifique de menaces connues et n'effectue pas de on-access scanning comme la plupart des antivirus.

Vous pouvez obtenir des informations sur la dernière mise à jour XProtect en exécutant :
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect is located on. SIP protected location at **/Library/Apple/System/Library/CoreServices/XProtect.bundle** and inside the bundle you can find information XProtect uses:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Allows code with those cdhashes to use legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: List of plugins and extensions that are disallowed to load via BundleID and TeamID or indicating a minimum version.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara rules to detect malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3 database with hashes of blocked applications and TeamIDs.

Note that there is another App in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** related to XProtect that isn't involved with the Gatekeeper process.

> XProtect Remediator: On modern macOS, Apple ships on-demand scanners (XProtect Remediator) that run periodically via launchd to detect and remediate families of malware. You can observe these scans in unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Ce n'est pas Gatekeeper

> [!CAUTION]
> Notez que Gatekeeper **n'est pas exécuté à chaque fois** que vous lancez une application : seule _**AppleMobileFileIntegrity**_ (AMFI) **vérifie les signatures du code exécutable** lorsque vous exécutez une app qui a déjà été exécutée et vérifiée par Gatekeeper.

Par conséquent, auparavant il était possible d'exécuter une application pour la mettre en cache via Gatekeeper, puis de **modifier des fichiers non exécutables de l'application** (comme les asar d'Electron ou les fichiers NIB) et si aucune autre protection n'était en place, l'application était **exécutée** avec les ajouts **malveillants**.

Cependant, maintenant ce n'est plus possible car macOS **empêche la modification des fichiers** à l'intérieur des bundles d'applications. Ainsi, si vous essayez l'attaque [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), vous constaterez qu'il n'est plus possible d'en abuser car après avoir exécuté l'app pour la mettre en cache via Gatekeeper, vous ne pourrez pas modifier le bundle. Et si vous changez par exemple le nom du répertoire Contents en NotCon (comme indiqué dans l'exploit), puis exécutez le binaire principal de l'application pour la mettre en cache via Gatekeeper, cela déclenchera une erreur et ne s'exécutera pas.

## Contournements de Gatekeeper

Toute méthode permettant de contourner Gatekeeper (réussir à faire télécharger quelque chose à l'utilisateur et l'exécuter alors que Gatekeeper devrait l'interdire) est considérée comme une vulnérabilité dans macOS. Voici quelques CVE attribuées à des techniques ayant permis de contourner Gatekeeper par le passé :

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Il a été observé que si l'Archive Utility est utilisé pour l'extraction, les fichiers avec des **chemins dépassant 886 caractères** ne reçoivent pas l'attribut étendu com.apple.quarantine. Cette situation permet involontairement à ces fichiers de **contourner les contrôles de sécurité de Gatekeeper**.

Consultez le [**rapport original**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) pour plus d'informations.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Lorsqu'une application est créée avec **Automator**, les informations sur ce dont elle a besoin pour s'exécuter se trouvent dans `application.app/Contents/document.wflow` et non dans l'exécutable. L'exécutable n'est qu'un binaire Automator générique appelé **Automator Application Stub**.

Par conséquent, vous pouviez faire en sorte que `application.app/Contents/MacOS/Automator\ Application\ Stub` **pointe avec un lien symbolique vers un autre Automator Application Stub dans le système** et il exécutera ce qui est dans `document.wflow` (votre script) **sans déclencher Gatekeeper** parce que l'exécutable réel n'a pas l'xattr de quarantaine.

Exemple d'emplacement attendu : `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consultez le [**rapport original**](https://ronmasas.com/posts/bypass-macos-gatekeeper) pour plus d'informations.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Dans ce contournement, un fichier zip a été créé en commençant la compression à partir de `application.app/Contents` au lieu de `application.app`. Par conséquent, l'**attribut de quarantaine** a été appliqué à tous les **fichiers de `application.app/Contents`** mais **pas à `application.app`**, qui est ce que Gatekeeper vérifiait, si bien que Gatekeeper était contourné parce que lorsque `application.app` était lancé il **n'avait pas l'attribut de quarantaine.**
```bash
zip -r test.app/Contents test.zip
```
Consultez le [**rapport original**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) pour plus d'informations.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Même si les composants sont différents, l'exploitation de cette vulnérabilité est très similaire à la précédente. Dans ce cas, on va générer un Apple Archive à partir de **`application.app/Contents`**, donc **`application.app` won't get the quarantine attr** lorsqu'il est décompressé par **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Consultez le [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) pour plus d'informations.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

L'ACL **`writeextattr`** peut être utilisée pour empêcher quiconque d'écrire un attribut dans un fichier :
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
De plus, le format de fichier **AppleDouble** copie un fichier en incluant ses ACEs.

Dans le [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) on peut voir que la représentation texte de l'ACL stockée dans l'xattr appelé **`com.apple.acl.text`** sera appliquée comme ACL dans le fichier décompressé. Donc, si vous avez compressé une application dans un fichier zip avec le format **AppleDouble** et avec une ACL qui empêche l'écriture d'autres xattrs... le quarantine xattr n'a pas été défini dans l'application :
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Consultez le [**rapport original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) pour plus d'informations.

Notez que cela pourrait également être exploité avec AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

On a découvert que **Google Chrome n'ajoutait pas l'attribut de quarantaine** aux fichiers téléchargés en raison de problèmes internes à macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Les formats AppleDouble stockent les attributs d'un fichier dans un fichier séparé commençant par `._`, ce qui permet de copier les attributs de fichier **entre des machines macOS**. Cependant, on a constaté qu'après la décompression d'un fichier AppleDouble, le fichier commençant par `._` **n'obtenait pas l'attribut de quarantaine**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
En étant capable de créer un fichier qui n'aura pas le quarantine attribute défini, il était **possible de bypass Gatekeeper.** Le truc consistait à **créer une application DMG** en utilisant la convention de nommage AppleDouble (start it with `._`) et à créer un **fichier visible comme un sym link vers ce fichier caché** sans le quarantine attribute.\
Lorsque le **dmg file est exécuté**, comme il n'a pas de quarantine attribute il va **bypass Gatekeeper**.
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

Un contournement de Gatekeeper corrigé dans macOS Sonoma 14.0 permettait à des apps spécialement conçues de s'exécuter sans demande de confirmation. Les détails ont été rendus publics après le patch et le problème a été activement exploité dans la nature avant la correction. Assurez-vous que Sonoma 14.0 ou une version ultérieure est installée.

### [CVE-2024-27853]

Un contournement de Gatekeeper dans macOS 14.4 (publié en mars 2024) dû au comportement de `libarchive` face à des ZIP malveillants permettait à des apps d'échapper à l'évaluation. Mettez à jour vers 14.4 ou une version ultérieure où Apple a corrigé le problème.

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Un **Automator Quick Action workflow** intégré dans une app téléchargée pouvait se déclencher sans l'évaluation de Gatekeeper, car les workflows étaient traités comme des données et exécutés par le helper Automator en dehors du chemin normal de l'invite de notarisation. Une `.app` spécialement conçue emballant une Quick Action qui exécute un script shell (par ex. dans `Contents/PlugIns/*.workflow/Contents/document.wflow`) pouvait donc s'exécuter immédiatement au lancement. Apple a ajouté une boîte de dialogue de consentement supplémentaire et corrigé le chemin d'évaluation dans Ventura **13.7**, Sonoma **14.7**, et Sequoia **15**.

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

Plusieurs vulnérabilités dans des outils d'extraction populaires (p.ex. The Unarchiver) faisaient que les fichiers extraits d'archives n'avaient pas l'xattr `com.apple.quarantine`, permettant des opportunités de contournement de Gatekeeper. Utilisez toujours macOS Archive Utility ou des outils patchés lors des tests, et validez les xattrs après extraction.

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Créez un répertoire contenant une app.
- Ajoutez uchg à l'app.
- Compressez l'app en un fichier tar.gz.
- Envoyez le fichier tar.gz à une victime.
- La victime ouvre le tar.gz et exécute l'app.
- Gatekeeper ne vérifie pas l'app.

### Prevent Quarantine xattr

Dans un bundle ".app", si l'xattr de quarantine n'est pas ajouté, lors de son exécution **Gatekeeper ne sera pas déclenché**.


## References

- Apple Platform Security: À propos du contenu de sécurité de macOS Sonoma 14.4 (inclut CVE-2024-27853) – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: Comment macOS suit maintenant la provenance des apps – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- Apple: À propos du contenu de sécurité de macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128) – [https://support.apple.com/en-us/121234](https://support.apple.com/en-us/121234)
- MacRumors: macOS 15 Sequoia supprime le contournement Gatekeeper via le Control‑click “Open” – [https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)

{{#include ../../../banners/hacktricks-training.md}}
