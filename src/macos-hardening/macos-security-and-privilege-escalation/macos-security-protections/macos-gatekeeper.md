# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** est une fonctionnalité de sécurité développée pour les systèmes d’exploitation Mac, conçue pour garantir que les utilisateurs **n’exécutent que des logiciels de confiance** sur leurs systèmes. Elle fonctionne en **validant les logiciels** qu’un utilisateur télécharge et tente d’ouvrir depuis des **sources extérieures à l’App Store**, comme une application, un plug-in ou un package d’installation.

Le mécanisme clé de Gatekeeper repose sur son processus de **vérification**. Il vérifie si le logiciel téléchargé est **signé par un développeur reconnu**, afin d’en garantir l’authenticité. Il vérifie également si le logiciel est **notarisé par Apple**, ce qui confirme qu’il ne contient aucun contenu malveillant connu et qu’il n’a pas été modifié après sa notarisation.

De plus, Gatekeeper renforce le contrôle et la sécurité des utilisateurs en **leur demandant d’autoriser l’ouverture** d’un logiciel téléchargé lors de sa première exécution. Cette protection aide à empêcher les utilisateurs d’exécuter par inadvertance du code exécutable potentiellement dangereux qu’ils auraient pu prendre pour un fichier de données inoffensif.

### Signatures des applications

Les signatures d’application, également appelées signatures de code, sont un élément essentiel de l’infrastructure de sécurité d’Apple. Elles servent à **vérifier l’identité de l’auteur du logiciel** (le développeur) et à garantir que le code n’a pas été modifié depuis sa dernière signature.

Voici comment cela fonctionne :

1. **Signature de l’application :** Lorsqu’un développeur est prêt à distribuer son application, il **signe l’application à l’aide d’une clé privée**. Cette clé privée est associée à un **certificat qu’Apple délivre au développeur** lorsqu’il s’inscrit à l’Apple Developer Program. Le processus de signature consiste à créer un hash cryptographique de toutes les parties de l’application, puis à chiffrer ce hash avec la clé privée du développeur.
2. **Distribution de l’application :** L’application signée est ensuite distribuée aux utilisateurs avec le certificat du développeur, qui contient la clé publique correspondante.
3. **Vérification de l’application :** Lorsqu’un utilisateur télécharge l’application et tente de l’exécuter, le système d’exploitation de son Mac utilise la clé publique du certificat du développeur pour déchiffrer le hash. Il recalcule ensuite le hash à partir de l’état actuel de l’application et le compare au hash déchiffré. S’ils correspondent, cela signifie que **l’application n’a pas été modifiée** depuis sa signature par le développeur, et le système autorise son exécution.

Les signatures d’application sont un élément essentiel de la technologie Gatekeeper d’Apple. Lorsqu’un utilisateur tente **d’ouvrir une application téléchargée depuis Internet**, Gatekeeper vérifie sa signature. Si elle est signée avec un certificat délivré par Apple à un développeur connu et que le code n’a pas été modifié, Gatekeeper autorise son exécution. Sinon, il la bloque et avertit l’utilisateur.

À partir de macOS Catalina, **Gatekeeper vérifie également si l’application a été notarisée** par Apple, ajoutant ainsi une couche de sécurité supplémentaire. Le processus de notarisation vérifie si l’application présente des problèmes de sécurité connus ou du code malveillant. Si elle passe ces vérifications, Apple lui ajoute un ticket que Gatekeeper peut vérifier.

#### Vérifier les signatures

Lorsque vous examinez un **échantillon de malware**, vous devriez toujours **vérifier la signature** du binaire, car le **développeur** qui l’a signé peut déjà être **lié** à des **malwares**.

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

Le processus de notarisation d’Apple constitue une protection supplémentaire contre les logiciels potentiellement dangereux. Il consiste à **soumettre l’application du développeur à l’examen** du **Notary Service d’Apple**, à ne pas confondre avec App Review. Ce service est un **système automatisé** qui analyse le logiciel soumis à la recherche de **contenu malveillant** et de problèmes potentiels liés à la signature de code.

Si le logiciel **réussit** cette inspection sans soulever de problème, le Notary Service génère un ticket de notarisation. Le développeur doit alors **joindre ce ticket à son logiciel**, un processus appelé « stapling ». De plus, le ticket de notarisation est également publié en ligne, où Gatekeeper, la technologie de sécurité d’Apple, peut y accéder.

Lors de la première installation ou exécution du logiciel par l’utilisateur, la présence du ticket de notarisation — qu’il soit joint à l’exécutable ou trouvé en ligne — **indique à Gatekeeper que le logiciel a été notarisé par Apple**. Gatekeeper affiche alors un message descriptif dans la boîte de dialogue de lancement initiale, indiquant que le logiciel a été vérifié par Apple pour détecter tout contenu malveillant. Ce processus renforce ainsi la confiance des utilisateurs dans la sécurité des logiciels qu’ils installent ou exécutent sur leurs systèmes.

### spctl & syspolicyd

> [!CAUTION]
> Notez qu’à partir de Sequoia, **`spctl`** ne permet plus de modifier la configuration de Gatekeeper.

**`spctl`** est l’outil CLI permettant d’énumérer Gatekeeper et d’interagir avec lui (via des messages XPC envoyés au daemon `syspolicyd`). Par exemple, il est possible de voir l’**état** de GateKeeper avec :

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> Notez que les vérifications de signature de GateKeeper s'appliquent uniquement aux **fichiers dotés de l'attribut Quarantine**, et non à tous les fichiers.

GateKeeper vérifie si, selon les **préférences et la signature**, un binaire peut être exécuté :

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** est le principal daemon chargé d'appliquer Gatekeeper. Il gère une base de données située dans `/var/db/SystemPolicy`. Le code permettant de gérer cette [base de données](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) et le [modèle SQL](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) sont disponibles. Notez que SIP ne restreint pas l'accès à la base de données, qui est accessible en écriture par root. La base de données `/var/db/.SystemPolicy-default` sert de copie de sauvegarde d'origine au cas où l'autre serait corrompue.

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

**`syspolicyd`** expose également un serveur XPC proposant différentes opérations comme `assess`, `update`, `record` et `cancel`, qui sont aussi accessibles via les API **`SecAssessment*`** de **`Security.framework`**. **`spctl`** communique en fait avec **`syspolicyd`** via XPC.

Notez que la première règle se terminait par "**App Store**" et la deuxième par "**Developer ID**", et que sur l’image précédente, l’exécution des apps de l’App Store et des développeurs identifiés était **autorisée**.\
Si vous **modifiez** ce réglage pour le limiter à l’App Store, les règles "**Notarized Developer ID" disparaîtront**.

Il existe également des milliers de règles de **type GKE** :

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

Il s’agit de hachages provenant de :

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Vous pouvez aussi afficher les informations précédentes avec :

```bash
sudo spctl --list
```

Les options **`--master-disable`** et **`--global-disable`** de **`spctl`** **désactivent** complètement ces vérifications de signature :

```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```

Lorsqu’elle est entièrement activée, une nouvelle option apparaît :

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Il est possible de **vérifier si une app sera autorisée par GateKeeper** avec :

```bash
spctl --assess -v /Applications/App.app
```

Sur macOS 14 et les versions ultérieures, **`syspolicy_check`** est un outil de vérification préalable à la distribution utile pour un bundle d’application. Il fournit des diagnostics plus exploitables sur l’exécution de confiance qu’un simple résultat de `spctl`, même si Apple recommande toujours de tester le parcours réel de téléchargement, d’extraction et de premier lancement, car cela permet aussi de vérifier la propagation de la quarantaine.<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
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

Concernant les **extensions du noyau**, le dossier `/var/db/SystemPolicyConfiguration` contient des fichiers répertoriant les kexts autorisés à être chargés. De plus, `spctl` possède l’entitlement `com.apple.private.iokit.nvram-csr`, car il peut ajouter de nouvelles extensions du noyau préapprouvées, qui doivent également être enregistrées dans la NVRAM sous la clé `kext-allowed-teams`.

#### Gestion de Gatekeeper sur macOS 15 (Sequoia) et les versions ultérieures

- Le contournement Finder **Ctrl+Open / Right-click → Open** qui existait depuis longtemps a été supprimé ; après le premier avertissement de blocage, les utilisateurs doivent explicitement autoriser une app bloquée dans **System Settings → Privacy & Security → Open Anyway**.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` ne sont plus acceptées pour modifier la stratégie sans intervention. Les opérations qui modifient la base de règles ou l’état global d’évaluation sont obsolètes ; utilisez donc `spctl` pour l’évaluation et configurez l’application des règles via l’interface ou un MDM.

À partir de macOS 15 Sequoia, les utilisateurs finaux ne peuvent plus modifier la stratégie de Gatekeeper avec `spctl`. La gestion s’effectue via System Settings ou en déployant un profil de configuration MDM avec la charge utile `com.apple.systempolicy.control`. Exemple d’extrait de profil autorisant l’App Store et les développeurs identifiés (mais pas « Anywhere ») :

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

Lors du **téléchargement** d’une application ou d’un fichier, certaines **applications** macOS, comme les navigateurs Web ou les clients de messagerie, **ajoutent un attribut de fichier étendu**, communément appelé « **indicateur de quarantaine** », au fichier téléchargé. Cet attribut constitue une mesure de sécurité qui **marque le fichier** comme provenant d’une source non fiable (Internet) et comme présentant potentiellement des risques. Cependant, toutes les applications n’ajoutent pas cet attribut ; par exemple, les logiciels clients BitTorrent courants contournent généralement ce processus.

**La présence d’un indicateur de quarantaine signale la fonctionnalité de sécurité Gatekeeper de macOS lorsqu’un utilisateur tente d’exécuter le fichier**.

Si l’**indicateur de quarantaine est absent** (comme pour les fichiers téléchargés à l’aide de certains clients BitTorrent), les **vérifications** de Gatekeeper **peuvent ne pas être effectuées**. Les utilisateurs doivent donc faire preuve de prudence lorsqu’ils ouvrent des fichiers téléchargés depuis des sources moins sûres ou inconnues.

> [!NOTE] > **Vérifier** la **validité** des signatures de code est un processus **gourmand en ressources** qui comprend le calcul d’**empreintes** cryptographiques du code et de toutes ses ressources intégrées. De plus, vérifier la validité des certificats implique de procéder à une **vérification en ligne** auprès des serveurs d’Apple pour savoir si le certificat a été révoqué depuis sa délivrance. Pour ces raisons, il est **impraticable d’effectuer une vérification complète de la signature du code et de la notarisation à chaque lancement d’une application**.
>
> Par conséquent, ces vérifications sont **effectuées uniquement lors de l’exécution d’applications dotées de l’attribut de quarantaine**.

> [!WARNING]
> Cet attribut doit être **défini par l’application qui crée/télécharge** le fichier.
>
> Cependant, les fichiers créés dans un bac à sable auront cet attribut. Les applications hors bac à sable peuvent le définir elles-mêmes ou spécifier la clé [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) dans **Info.plist**, ce qui entraînera la définition par le système de l’attribut étendu `com.apple.quarantine` sur les fichiers créés.

De plus, tous les fichiers créés par un processus appelant **`qtn_proc_apply_to_self`** sont mis en quarantaine. L’API **`qtn_file_apply_to_path`** ajoute quant à elle l’attribut de quarantaine au chemin d’un fichier spécifié.

Il est possible de **vérifier son état et de l’activer/la désactiver** (droits root requis) avec :

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

Vérifiez la **valeur** des **attributs** **étendus** et découvrez quelle application a écrit l’attribut de quarantaine avec :

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

En réalité, un processus « pourrait définir des indicateurs de quarantaine sur les fichiers qu’il crée » (j’ai déjà essayé d’appliquer l’indicateur USER_APPROVED à un fichier créé, mais cela ne fonctionne pas) :

<details>

<summary>Code source : appliquer des indicateurs de quarantaine</summary>

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

Les informations de quarantaine sont également stockées dans une base de données centralisée gérée par LaunchServices dans **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, ce qui permet à l’interface graphique d’obtenir des données sur la provenance des fichiers. De plus, les applications qui souhaitent masquer leur provenance peuvent écraser ces informations. Cela peut également être fait à l’aide des API de LaunchServices.

#### **libquarantine.dylib**

Cette bibliothèque exporte plusieurs fonctions permettant de manipuler les champs des attributs étendus.

Les API `qtn_file_*` gèrent les politiques de quarantaine des fichiers, tandis que les API `qtn_proc_*` s’appliquent aux processus (aux fichiers créés par le processus). Les fonctions non exportées `__qtn_syscall_quarantine*` appliquent les politiques en appelant `mac_syscall` avec « Quarantine » comme premier argument, ce qui transmet les requêtes à `Quarantine.kext`.

#### **Quarantine.kext**

Cette extension du noyau est uniquement disponible dans le **cache du noyau du système** ; toutefois, vous _pouvez_ télécharger le **Kernel Debug Kit depuis** [**https://developer.apple.com/**](https://developer.apple.com/), qui contient une version de l’extension avec les symboles.

Cette Kext utilise MACF pour intercepter plusieurs appels afin de surveiller tous les événements du cycle de vie des fichiers : création, ouverture, renommage, création de liens physiques... et même `setxattr`, pour empêcher la définition de l’attribut étendu `com.apple.quarantine`.

Elle utilise également deux MIB :

- `security.mac.qtn.sandbox_enforce` : impose la quarantaine dans le Sandbox
- `security.mac.qtn.user_approved_exec` : les processus en quarantaine ne peuvent exécuter que des fichiers approuvés

#### Attribut xattr de provenance (Ventura et versions ultérieures)

macOS 13 Ventura a introduit un mécanisme de provenance distinct, renseigné la première fois qu’une app en quarantaine est autorisée à s’exécuter.<sup>[[2]](#references)</sup> Deux artefacts sont créés :

- L’attribut xattr `com.apple.provenance` sur le répertoire du bundle `.app` (valeur binaire de taille fixe contenant une clé primaire et des indicateurs).
- Une ligne dans la table `provenance_tracking` de la base de données ExecPolicy située dans `/var/db/SystemPolicyConfiguration/ExecPolicy/`, qui stocke le cdhash de l’app et ses métadonnées.

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

XProtect est une fonctionnalité **anti-malware** intégrée à macOS. XProtect **vérifie chaque application lors de son premier lancement ou après sa modification en la comparant à sa base de données** de malwares connus et de types de fichiers dangereux. Lorsque vous téléchargez un fichier avec certaines applications, comme Safari, Mail ou Messages, XProtect analyse automatiquement le fichier. S'il correspond à un malware connu dans sa base de données, XProtect **empêche l'exécution du fichier** et vous alerte de la menace.

Apple **met régulièrement à jour** la base de données XProtect avec de nouvelles définitions de malwares. Ces mises à jour sont téléchargées et installées automatiquement sur votre Mac. XProtect reste ainsi à jour face aux dernières menaces connues.

Il convient toutefois de noter que **XProtect n'est pas une solution antivirus complète**. Il vérifie uniquement une liste spécifique de menaces connues et n'effectue pas d'analyse à l'accès comme la plupart des logiciels antivirus.

Vous pouvez obtenir des informations sur la dernière mise à jour de XProtect en exécutant :

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect se trouve dans un emplacement protégé par SIP : **/Library/Apple/System/Library/CoreServices/XProtect.bundle**. Dans le bundle, vous trouverez des informations utilisées par XProtect :

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`** : autorise le code ayant ces cdhashes à utiliser des entitlements hérités.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`** : liste les plugins et extensions dont le chargement est interdit selon leur BundleID et leur TeamID, ou indique une version minimale.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`** : règles Yara permettant de détecter les malwares.
- **`XProtect.bundle/Contents/Resources/gk.db`** : base de données SQLite3 contenant les hashes des applications bloquées et les TeamIDs correspondants.

Notez qu’une autre app, **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, est liée à XProtect, mais n’intervient pas dans le processus Gatekeeper.

> XProtect Remediator : Sur les versions récentes de macOS, Apple fournit des scanners à la demande (XProtect Remediator) qui s’exécutent périodiquement via launchd pour détecter et éliminer certaines familles de malwares. Vous pouvez observer ces scans dans les journaux unifiés :
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Pas Gatekeeper

> [!CAUTION]
> Notez que Gatekeeper **n'est pas exécuté à chaque fois** que vous lancez une application ; seul _**AppleMobileFileIntegrity**_ (AMFI) **vérifie les signatures du code exécutable** lorsque vous lancez une app qui a déjà été lancée et vérifiée par Gatekeeper.

Par conséquent, il était auparavant possible de lancer une app pour la mettre en cache avec Gatekeeper, puis de **modifier les fichiers non exécutables de l'application** (comme les fichiers asar ou NIB d'Electron) et, en l'absence d'autres protections, l'application était **exécutée** avec les ajouts **malveillants**.

Cependant, ce n'est désormais plus possible, car macOS **empêche la modification des fichiers** à l'intérieur des bundles d'applications. Ainsi, si vous essayez l'attaque [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), vous constaterez qu'il n'est plus possible de l'exploiter : après avoir lancé l'app pour la mettre en cache avec Gatekeeper, vous ne pourrez pas modifier le bundle. Et si vous changez, par exemple, le nom du répertoire Contents en NotCon (comme indiqué dans l'exploit), puis lancez le binaire principal de l'app pour la mettre en cache avec Gatekeeper, cela déclenchera une erreur et l'app ne s'exécutera pas.

## Gatekeeper Bypasses

Toute méthode permettant de contourner Gatekeeper (parvenir à faire télécharger un fichier à l'utilisateur et à le faire exécuter alors que Gatekeeper devrait l'interdire) est considérée comme une vulnérabilité dans macOS. Voici quelques CVE attribuées à des techniques qui ont permis de contourner Gatekeeper par le passé :

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Il a été constaté que lorsque l'**Archive Utility** est utilisé pour extraire des fichiers, ceux dont le **chemin dépasse 886 caractères** ne reçoivent pas l'attribut étendu com.apple.quarantine. Cette situation permet involontairement à ces fichiers de **contourner** les contrôles de sécurité de Gatekeeper.<sup>[[5]](#references)</sup>

Consultez le [**rapport original**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) pour plus d'informations.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Lorsqu'une application est créée avec **Automator**, les informations sur ce qu'elle doit exécuter se trouvent dans `application.app/Contents/document.wflow`, et non dans l'exécutable. L'exécutable est simplement un binaire Automator générique appelé **Automator Application Stub**.

Vous pouviez donc faire pointer `application.app/Contents/MacOS/Automator\ Application\ Stub` **vers un autre Automator Application Stub du système à l'aide d'un lien symbolique** ; il exécuterait alors le contenu de `document.wflow` (votre script) **sans déclencher Gatekeeper**, car l'exécutable réel ne possède pas l'xattr quarantine.<sup>[[6]](#references)</sup>

Exemple d'emplacement attendu : `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consultez le [**rapport original**](https://ronmasas.com/posts/bypass-macos-gatekeeper) pour plus d'informations.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Dans ce bypass, un fichier zip était créé en commençant la compression à partir de `application.app/Contents` plutôt que de `application.app`. L'**attribut quarantine** était donc appliqué à tous les **fichiers de `application.app/Contents`**, mais **pas à `application.app`**, que Gatekeeper vérifiait. Gatekeeper était donc contourné, car lorsque `application.app` était lancé, il **ne possédait pas l'attribut quarantine.**<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

Consultez le [**rapport original**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) pour plus d’informations.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Même si les composants sont différents, l’exploitation de cette vulnérabilité est très similaire à la précédente. Dans ce cas, nous allons générer une Apple Archive à partir de **`application.app/Contents`** afin que **`application.app`** ne reçoive pas l’attribut quarantine lors de sa décompression par **Archive Utility**.<sup>[[8]](#references)</sup>

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

De plus, le format de fichier **AppleDouble** copie un fichier avec ses ACE.<sup>[[9]](#references)</sup>

Dans le [**code source**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), on peut voir que la représentation textuelle de l’ACL stockée dans l’attribut étendu appelé **`com.apple.acl.text`** est définie comme ACL du fichier décompressé. Ainsi, si vous compressez une application dans un fichier zip au format **AppleDouble** avec une ACL empêchant l’écriture d’autres attributs étendus... l’attribut étendu quarantine n’est pas défini sur l’application :

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

Consultez le [**rapport original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) pour en savoir plus.<sup>[[9]](#references)</sup> Consultez la [reproduction AppleDouble/ACL](macos-fs-tricks/macos-xattr-acls-extra-stuff.md) pour connaître les étapes de création et de validation du fichier sidecar.

Notez que cette méthode pourrait également être exploitée avec AppleArchives :

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Il a été découvert que **Google Chrome ne définissait pas l’attribut de quarantaine** des fichiers téléchargés en raison de certains problèmes internes à macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble stocke les attributs d’un fichier dans un fichier distinct dont le nom commence par `._` ; cela permet de copier les attributs de fichiers **entre des machines macOS**. Cependant, après la décompression d’un fichier AppleDouble, le fichier commençant par `._` **ne recevait pas l’attribut de quarantaine**.<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

En pouvant créer un fichier auquel l’attribut de quarantaine ne serait pas défini, il était **possible de contourner Gatekeeper**. L’astuce consistait à **créer un fichier d’application DMG** en utilisant la convention de nommage AppleDouble (en le faisant commencer par `._`), puis à créer un **fichier visible sous forme de lien symbolique vers ce fichier caché**, auquel l’attribut de quarantaine n’était pas défini.\
Lorsque le **fichier DMG est exécuté**, comme il ne possède pas d’attribut de quarantaine, il **contourne Gatekeeper**.

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

Apple a corrigé une erreur de logique de LaunchServices dans macOS Sonoma 14.0 en renforçant les vérifications. L’avis public indique uniquement qu’une app pouvait contourner Gatekeeper ; ne déduisez donc pas un format de fichier porteur ou une chaîne d’exploitation spécifique à partir de la seule entrée CVE.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Un contournement de Gatekeeper dans macOS 14.4 (publié en mars 2024), dû à la gestion des ZIP malveillants par `libarchive`, permettait aux apps d’échapper à l’évaluation. Effectuez la mise à jour vers la version 14.4 ou ultérieure, dans laquelle Apple a corrigé le problème.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Un **workflow Automator Quick Action** intégré à une app téléchargée pouvait se déclencher sans évaluation de Gatekeeper, car les workflows étaient traités comme des données et exécutés par l’assistant Automator en dehors du parcours normal d’invite de notarisation. Une app `.app` conçue spécialement, contenant une Quick Action qui exécute un script shell (par exemple dans `Contents/PlugIns/*.workflow/Contents/document.wflow`), pouvait donc s’exécuter immédiatement au lancement. Apple a ajouté une boîte de dialogue de consentement supplémentaire et corrigé le parcours d’évaluation dans Ventura **13.7**, Sonoma **14.7** et Sequoia **15**.<sup>[[3]](#references)</sup>

### Échecs de propagation de la quarantaine lors de l’extraction et de la copie

Une étude de 2024 a relevé des lacunes de propagation dans les versions testées d’iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) et 7z Utility (DMG/ZIP/7Z) ; elle a également observé la perte de l’attribut lors de copies de l’hôte vers l’invité avec VMware Tools. Plusieurs fournisseurs ont ensuite annoncé des correctifs : considérez donc ces noms comme des pistes pour des **tests à refaire selon la version**, et non comme une liste permanente de logiciels vulnérables. Le même problème de frontière de confiance concerne les workflows Unix natifs : `curl`/`scp` n’ajoutent pas la quarantaine, et `tar`/`unzip` en ligne de commande ne l’héritent pas automatiquement d’une archive porteuse.<sup>[[15]](#references)</sup>

Pour les tests offensifs, comparez l’archive porteuse et l’app finale après **chaque** transition impliquant un navigateur, un client de messagerie, une archive, une image disque, une synchronisation cloud, un dossier partagé ou une copie de machine virtuelle. Un rejet explicite par `spctl` ne corrige pas l’absence de xattr : sans quarantaine, le parcours normal de Gatekeeper à la première ouverture peut ne jamais demander cette évaluation.<sup>[[15]](#references)</sup>

```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
  'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Créez un répertoire contenant une app.
- Ajoutez uchg à l’app.
- Compressez l’app dans un fichier tar.gz.
- Envoyez le fichier tar.gz à une victime.
- La victime ouvre le fichier tar.gz et exécute l’app.
- Gatekeeper ne vérifie pas l’app.<sup>[[12]](#references)</sup>

### Empêcher l’ajout de l’attribut étendu Quarantine

Dans un bundle « .app », si l’attribut étendu Quarantine n’est pas ajouté, **Gatekeeper ne se déclenche pas** lors de son exécution.

Consultez [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) pour découvrir des primitives basées sur le système de fichiers, les flags, les ACL et AppleDouble qui peuvent empêcher ou supprimer les attributs étendus.





## References

- [1] [Sécurité des plateformes Apple : À propos du contenu de sécurité de macOS Sonoma 14.4 (inclut CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light : Comment macOS suit désormais la provenance des apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple : À propos du contenu de sécurité de macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors : macOS 15 Sequoia supprime le contournement de Gatekeeper par clic avec la touche Contrôle et sélection de « Ouvrir »](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs : La découverte de CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, contournement de macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs découvre une vulnérabilité de Safari permettant de contourner Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs découvre une vulnérabilité de l’utilitaire d’archivage macOS permettant de contourner Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Le talon d’Achille de Gatekeeper : découverte d’une vulnérabilité macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure : Découverte d’un contournement de Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Découverte et signalement d’un exploit de contournement de Gatekeeper avec l’aide de Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023 : Contourner les mécanismes de sécurité et de confidentialité de macOS — de Gatekeeper à System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple : À propos du contenu de sécurité de macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Forums des développeurs Apple : Tester un produit notarié](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42 : Contournement de Gatekeeper — Découverte des faiblesses d’un mécanisme de sécurité macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
