# macOS Code Signing

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Les binaires Mach-o contiennent une commande de chargement appelée **`LC_CODE_SIGNATURE`** qui indique le **décalage** et la **taille** des signatures à l'intérieur du binaire. En fait, en utilisant l'outil GUI MachOView, il est possible de trouver à la fin du binaire une section appelée **Code Signature** avec ces informations :

<figure><img src="../../../images/image (1) (1) (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

L'en-tête magique de la Code Signature est **`0xFADE0CC0`**. Ensuite, vous avez des informations telles que la longueur et le nombre de blobs du superBlob qui les contient.\
Il est possible de trouver ces informations dans le [code source ici](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L276) :
```c
/*
* Structure of an embedded-signature SuperBlob
*/

typedef struct __BlobIndex {
uint32_t type;                                  /* type of entry */
uint32_t offset;                                /* offset of entry */
} CS_BlobIndex
__attribute__ ((aligned(1)));

typedef struct __SC_SuperBlob {
uint32_t magic;                                 /* magic number */
uint32_t length;                                /* total length of SuperBlob */
uint32_t count;                                 /* number of index entries following */
CS_BlobIndex index[];                   /* (count) entries */
/* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob
__attribute__ ((aligned(1)));

#define KERNEL_HAVE_CS_GENERICBLOB 1
typedef struct __SC_GenericBlob {
uint32_t magic;                                 /* magic number */
uint32_t length;                                /* total length of blob */
char data[];
} CS_GenericBlob
__attribute__ ((aligned(1)));
```
Les blobs courants contenus sont le Code Directory, les Requirements et les Entitlements, ainsi qu'un Cryptographic Message Syntax (CMS).\
De plus, notez comment les données encodées dans les blobs sont encodées en **Big Endian.**

De plus, les signatures peuvent être détachées des binaires et stockées dans `/var/db/DetachedSignatures` (utilisé par iOS).

## Code Directory Blob

Il est possible de trouver la déclaration du [Code Directory Blob dans le code](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L104):
```c
typedef struct __CodeDirectory {
uint32_t magic;                                 /* magic number (CSMAGIC_CODEDIRECTORY) */
uint32_t length;                                /* total length of CodeDirectory blob */
uint32_t version;                               /* compatibility version */
uint32_t flags;                                 /* setup and mode flags */
uint32_t hashOffset;                    /* offset of hash slot element at index zero */
uint32_t identOffset;                   /* offset of identifier string */
uint32_t nSpecialSlots;                 /* number of special hash slots */
uint32_t nCodeSlots;                    /* number of ordinary (code) hash slots */
uint32_t codeLimit;                             /* limit to main image signature range */
uint8_t hashSize;                               /* size of each hash in bytes */
uint8_t hashType;                               /* type of hash (cdHashType* constants) */
uint8_t platform;                               /* platform identifier; zero if not platform binary */
uint8_t pageSize;                               /* log2(page size in bytes); 0 => infinite */
uint32_t spare2;                                /* unused (must be zero) */

char end_earliest[0];

/* Version 0x20100 */
uint32_t scatterOffset;                 /* offset of optional scatter vector */
char end_withScatter[0];

/* Version 0x20200 */
uint32_t teamOffset;                    /* offset of optional team identifier */
char end_withTeam[0];

/* Version 0x20300 */
uint32_t spare3;                                /* unused (must be zero) */
uint64_t codeLimit64;                   /* limit to main image signature range, 64 bits */
char end_withCodeLimit64[0];

/* Version 0x20400 */
uint64_t execSegBase;                   /* offset of executable segment */
uint64_t execSegLimit;                  /* limit of executable segment */
uint64_t execSegFlags;                  /* executable segment flags */
char end_withExecSeg[0];

/* Version 0x20500 */
uint32_t runtime;
uint32_t preEncryptOffset;
char end_withPreEncryptOffset[0];

/* Version 0x20600 */
uint8_t linkageHashType;
uint8_t linkageApplicationType;
uint16_t linkageApplicationSubType;
uint32_t linkageOffset;
uint32_t linkageSize;
char end_withLinkage[0];

/* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory
__attribute__ ((aligned(1)));
```
Notez qu'il existe différentes versions de cette structure où les anciennes peuvent contenir moins d'informations.

## Pages de signature de code

Hacher le binaire complet serait inefficace et même inutile s'il n'est chargé en mémoire que partiellement. Par conséquent, la signature de code est en réalité un hachage de hachages où chaque page binaire est hachée individuellement.\
En fait, dans le code du **répertoire de code** précédent, vous pouvez voir que la **taille de la page est spécifiée** dans l'un de ses champs. De plus, si la taille du binaire n'est pas un multiple de la taille d'une page, le champ **CodeLimit** spécifie où se termine la signature.
```bash
# Get all hashes of /bin/ps
codesign -d -vvvvvv /bin/ps
[...]
CandidateCDHash sha256=c46e56e9490d93fe35a76199bdb367b3463c91dc
CandidateCDHashFull sha256=c46e56e9490d93fe35a76199bdb367b3463c91dcdb3c46403ab8ba1c2d13fd86
Hash choices=sha256
CMSDigest=c46e56e9490d93fe35a76199bdb367b3463c91dcdb3c46403ab8ba1c2d13fd86
CMSDigestType=2
Executable Segment base=0
Executable Segment limit=32768
Executable Segment flags=0x1
Page size=4096
-7=a542b4dcbc134fbd950c230ed9ddb99a343262a2df8e0c847caee2b6d3b41cc8
-6=0000000000000000000000000000000000000000000000000000000000000000
-5=2bb2de519f43b8e116c7eeea8adc6811a276fb134c55c9c2e9dcbd3047f80c7d
-4=0000000000000000000000000000000000000000000000000000000000000000
-3=0000000000000000000000000000000000000000000000000000000000000000
-2=4ca453dc8908dc7f6e637d6159c8761124ae56d080a4a550ad050c27ead273b3
-1=0000000000000000000000000000000000000000000000000000000000000000
0=a5e6478f89812c0c09f123524cad560a9bf758d16014b586089ddc93f004e39c
1=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
2=93d476eeace15a5ad14c0fb56169fd080a04b99582b4c7a01e1afcbc58688f
[...]

# Calculate the hasehs of each page manually
BINARY=/bin/ps
SIZE=`stat -f "%Z" $BINARY`
PAGESIZE=4096 # From the previous output
PAGES=`expr $SIZE / $PAGESIZE`
for i in `seq 0 $PAGES`; do
dd if=$BINARY of=/tmp/`basename $BINARY`.page.$i bs=$PAGESIZE skip=$i count=1
done
openssl sha256 /tmp/*.page.*
```
## Entitlements Blob

Notez que les applications peuvent également contenir un **entitlement blob** où tous les droits sont définis. De plus, certains binaires iOS peuvent avoir leurs droits spécifiques dans l'emplacement spécial -7 (au lieu de l'emplacement spécial -5 des droits).

## Special Slots

Les applications MacOS n'ont pas tout ce dont elles ont besoin pour s'exécuter à l'intérieur du binaire, mais elles utilisent également des **ressources externes** (généralement à l'intérieur du **bundle** des applications). Par conséquent, il y a des emplacements à l'intérieur du binaire qui contiendront les hachages de certaines ressources externes intéressantes pour vérifier qu'elles n'ont pas été modifiées.

En fait, il est possible de voir dans les structures du Code Directory un paramètre appelé **`nSpecialSlots`** indiquant le nombre d'emplacements spéciaux. Il n'y a pas d'emplacement spécial 0 et les plus courants (de -1 à -6) sont :

- Hachage de `info.plist` (ou celui à l'intérieur de `__TEXT.__info__plist`).
- Hachage des Exigences
- Hachage du Répertoire de Ressources (hachage du fichier `_CodeSignature/CodeResources` à l'intérieur du bundle).
- Spécifique à l'application (non utilisé)
- Hachage des droits
- Signatures de code DMG uniquement
- Droits DER

## Code Signing Flags

Chaque processus a un bitmask associé connu sous le nom de `status` qui est initialisé par le noyau et certains d'entre eux peuvent être remplacés par la **signature de code**. Ces drapeaux qui peuvent être inclus dans la signature de code sont [définis dans le code](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36) :
```c
/* code signing attributes of a process */
#define CS_VALID                    0x00000001  /* dynamically valid */
#define CS_ADHOC                    0x00000002  /* ad hoc signed */
#define CS_GET_TASK_ALLOW           0x00000004  /* has get-task-allow entitlement */
#define CS_INSTALLER                0x00000008  /* has installer entitlement */

#define CS_FORCED_LV                0x00000010  /* Library Validation required by Hardened System Policy */
#define CS_INVALID_ALLOWED          0x00000020  /* (macOS Only) Page invalidation allowed by task port policy */

#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION         0x00000400  /* force expiration checking */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */

#define CS_ENFORCEMENT              0x00001000  /* require enforcement */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_ENTITLEMENTS_VALIDATED   0x00004000  /* code signature permits restricted entitlements */
#define CS_NVRAM_UNRESTRICTED       0x00008000  /* has com.apple.rootless.restricted-nvram-variables.heritable entitlement */

#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
#define CS_LINKER_SIGNED            0x00020000  /* Automatically signed by the linker */

#define CS_ALLOWED_MACHO            (CS_ADHOC | CS_HARD | CS_KILL | CS_CHECK_EXPIRATION | \
CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV | CS_RUNTIME | CS_LINKER_SIGNED)

#define CS_EXEC_SET_HARD            0x00100000  /* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL            0x00200000  /* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT     0x00400000  /* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_INHERIT_SIP         0x00800000  /* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED                   0x01000000  /* was killed by kernel for invalidity */
#define CS_NO_UNTRUSTED_HELPERS     0x02000000  /* kernel did not load a non-platform-binary dyld or Rosetta runtime */
#define CS_DYLD_PLATFORM            CS_NO_UNTRUSTED_HELPERS /* old name */
#define CS_PLATFORM_BINARY          0x04000000  /* this is a platform binary */
#define CS_PLATFORM_PATH            0x08000000  /* platform binary by the fact of path (osx only) */

#define CS_DEBUGGED                 0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */
#define CS_SIGNED                   0x20000000  /* process has a signature (may have gone invalid) */
#define CS_DEV_CODE                 0x40000000  /* code is dev signed, cannot be loaded into prod signed code (will go away with rdar://problem/28322552) */
#define CS_DATAVAULT_CONTROLLER     0x80000000  /* has Data Vault controller entitlement */

#define CS_ENTITLEMENT_FLAGS        (CS_GET_TASK_ALLOW | CS_INSTALLER | CS_DATAVAULT_CONTROLLER | CS_NVRAM_UNRESTRICTED)
```
Notez que la fonction [**exec_mach_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_exec.c#L1420) peut également ajouter dynamiquement les drapeaux `CS_EXEC_*` lors du démarrage de l'exécution.

## Exigences de signature de code

Chaque application stocke des **exigences** qu'elle doit **satisfaire** pour pouvoir être exécutée. Si les **exigences de l'application ne sont pas satisfaites**, elle ne sera pas exécutée (car elle a probablement été modifiée).

Les exigences d'un binaire utilisent une **grammaire spéciale** qui est un flux d'**expressions** et sont encodées sous forme de blobs en utilisant `0xfade0c00` comme magie dont le **hash est stocké dans un emplacement de code spécial**.

Les exigences d'un binaire peuvent être consultées en exécutant :
```bash
codesign -d -r- /bin/ls
Executable=/bin/ls
designated => identifier "com.apple.ls" and anchor apple

codesign -d -r- /Applications/Signal.app/
Executable=/Applications/Signal.app/Contents/MacOS/Signal
designated => identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR
```
> [!NOTE]
> Notez comment ces signatures peuvent vérifier des éléments tels que les informations de certification, TeamID, IDs, droits et de nombreuses autres données.

De plus, il est possible de générer des exigences compilées en utilisant l'outil `csreq` :
```bash
# Generate compiled requirements
csreq -b /tmp/output.csreq -r='identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR'

# Get the compiled bytes
od -A x -t x1 /tmp/output.csreq
0000000    fa  de  0c  00  00  00  00  b0  00  00  00  01  00  00  00  06
0000010    00  00  00  06  00  00  00  06  00  00  00  06  00  00  00  02
0000020    00  00  00  21  6f  72  67  2e  77  68  69  73  70  65  72  73
[...]
```
Il est possible d'accéder à ces informations et de créer ou modifier des exigences avec certaines API du `Security.framework` comme :

#### **Vérification de Validité**

- **`Sec[Static]CodeCheckValidity`** : Vérifie la validité de SecCodeRef par exigence.
- **`SecRequirementEvaluate`** : Valide l'exigence dans le contexte du certificat.
- **`SecTaskValidateForRequirement`** : Valide un SecTask en cours par rapport à l'exigence `CFString`.

#### **Création et Gestion des Exigences de Code**

- **`SecRequirementCreateWithData` :** Crée un `SecRequirementRef` à partir de données binaires représentant l'exigence.
- **`SecRequirementCreateWithString` :** Crée un `SecRequirementRef` à partir d'une expression de chaîne de l'exigence.
- **`SecRequirementCopy[Data/String]`** : Récupère la représentation des données binaires d'un `SecRequirementRef`.
- **`SecRequirementCreateGroup`** : Crée une exigence pour l'appartenance à un groupe d'applications.

#### **Accès aux Informations de Signature de Code**

- **`SecStaticCodeCreateWithPath`** : Initialise un objet `SecStaticCodeRef` à partir d'un chemin de système de fichiers pour inspecter les signatures de code.
- **`SecCodeCopySigningInformation`** : Obtient des informations de signature à partir d'un `SecCodeRef` ou `SecStaticCodeRef`.

#### **Modification des Exigences de Code**

- **`SecCodeSignerCreate`** : Crée un objet `SecCodeSignerRef` pour effectuer des opérations de signature de code.
- **`SecCodeSignerSetRequirement`** : Définit une nouvelle exigence que le signataire de code doit appliquer lors de la signature.
- **`SecCodeSignerAddSignature`** : Ajoute une signature au code en cours de signature avec le signataire spécifié.

#### **Validation du Code avec des Exigences**

- **`SecStaticCodeCheckValidity`** : Valide un objet de code statique par rapport aux exigences spécifiées.

#### **API Utiles Supplémentaires**

- **`SecCodeCopy[Internal/Designated]Requirement` : Obtenir SecRequirementRef à partir de SecCodeRef**
- **`SecCodeCopyGuestWithAttributes`** : Crée un `SecCodeRef` représentant un objet de code basé sur des attributs spécifiques, utile pour le sandboxing.
- **`SecCodeCopyPath`** : Récupère le chemin du système de fichiers associé à un `SecCodeRef`.
- **`SecCodeCopySigningIdentifier`** : Obtient l'identifiant de signature (par exemple, Team ID) à partir d'un `SecCodeRef`.
- **`SecCodeGetTypeID`** : Renvoie l'identifiant de type pour les objets `SecCodeRef`.
- **`SecRequirementGetTypeID`** : Obtient un CFTypeID d'un `SecRequirementRef`.

#### **Drapeaux et Constantes de Signature de Code**

- **`kSecCSDefaultFlags`** : Drapeaux par défaut utilisés dans de nombreuses fonctions du Security.framework pour les opérations de signature de code.
- **`kSecCSSigningInformation`** : Drapeau utilisé pour spécifier que les informations de signature doivent être récupérées.

## Application de la Signature de Code

Le **noyau** est celui qui **vérifie la signature de code** avant de permettre l'exécution du code de l'application. De plus, une façon de pouvoir écrire et exécuter un nouveau code en mémoire est d'abuser de JIT si `mprotect` est appelé avec le drapeau `MAP_JIT`. Notez que l'application a besoin d'un droit spécial pour pouvoir faire cela.

## `cs_blobs` & `cs_blob`

[**cs_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc_internal.h#L106) la structure contient des informations sur le droit du processus en cours. `csb_platform_binary` informe également si l'application est un binaire de plateforme (ce qui est vérifié à différents moments par le système d'exploitation pour appliquer des mécanismes de sécurité comme protéger les droits SEND aux ports de tâche de ces processus).
```c
struct cs_blob {
struct cs_blob  *csb_next;
vnode_t         csb_vnode;
void            *csb_ro_addr;
__xnu_struct_group(cs_cpu_info, csb_cpu_info, {
cpu_type_t      csb_cpu_type;
cpu_subtype_t   csb_cpu_subtype;
});
__xnu_struct_group(cs_signer_info, csb_signer_info, {
unsigned int    csb_flags;
unsigned int    csb_signer_type;
});
off_t           csb_base_offset;        /* Offset of Mach-O binary in fat binary */
off_t           csb_start_offset;       /* Blob coverage area start, from csb_base_offset */
off_t           csb_end_offset;         /* Blob coverage area end, from csb_base_offset */
vm_size_t       csb_mem_size;
vm_offset_t     csb_mem_offset;
void            *csb_mem_kaddr;
unsigned char   csb_cdhash[CS_CDHASH_LEN];
const struct cs_hash  *csb_hashtype;
#if CONFIG_SUPPLEMENTAL_SIGNATURES
unsigned char   csb_linkage[CS_CDHASH_LEN];
const struct cs_hash  *csb_linkage_hashtype;
#endif
int             csb_hash_pageshift;
int             csb_hash_firstlevel_pageshift;   /* First hash this many bytes, then hash the hashes together */
const CS_CodeDirectory *csb_cd;
const char      *csb_teamid;
#if CONFIG_SUPPLEMENTAL_SIGNATURES
char            *csb_supplement_teamid;
#endif
const CS_GenericBlob *csb_entitlements_blob;    /* raw blob, subrange of csb_mem_kaddr */
const CS_GenericBlob *csb_der_entitlements_blob;    /* raw blob, subrange of csb_mem_kaddr */

/*
* OSEntitlements pointer setup by AMFI. This is PAC signed in addition to the
* cs_blob being within RO-memory to prevent modifications on the temporary stack
* variable used to setup the blob.
*/
void *XNU_PTRAUTH_SIGNED_PTR("cs_blob.csb_entitlements") csb_entitlements;

unsigned int    csb_reconstituted;      /* signature has potentially been modified after validation */
__xnu_struct_group(cs_blob_platform_flags, csb_platform_flags, {
/* The following two will be replaced by the csb_signer_type. */
unsigned int    csb_platform_binary:1;
unsigned int    csb_platform_path:1;
});

/* Validation category used for TLE */
unsigned int    csb_validation_category;

#if CODE_SIGNING_MONITOR
void *XNU_PTRAUTH_SIGNED_PTR("cs_blob.csb_csm_obj") csb_csm_obj;
bool csb_csm_managed;
#endif
};
```
## Références

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
