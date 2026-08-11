# macOS Code Signing

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

{{#ref}}
../../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/mach-o-entitlements-and-ipsw-indexing.md
{{#endref}}


Les binaires Mach-o contiennent une commande de chargement appelée **`LC_CODE_SIGNATURE`** qui indique l'**offset** et la **taille** des signatures à l'intérieur du binaire. En fait, avec l'outil GUI MachOView, il est possible de trouver à la fin du binaire une section appelée **Code Signature** contenant ces informations :

<figure><img src="../../../images/image (1) (1) (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

Le magic header de la Code Signature est **`0xFADE0CC0`** (embedded code signature) ou **`0xFADE0CC1`** (detached code signature). Vous disposez ensuite d'informations telles que la longueur et le nombre de blobs du superBlob qui les contient.\
Il est possible de trouver ces informations dans le [source code ici](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L276):<sup>[[1]](#references)</sup>
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
Les blobs couramment contenus sont Code Directory, Requirements et Entitlements, ainsi qu'un Cryptographic Message Syntax (CMS).\
Par ailleurs, notez que les données encodées dans les blobs le sont en **Big Endian.**

De plus, les signatures peuvent être détachées des binaires et stockées dans `/var/db/DetachedSignatures` (utilisé par iOS).

## Code Directory Blob

Il est possible de trouver la déclaration du [Code Directory Blob dans le code](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L104):<sup>[[1]](#references)</sup>
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
Notez qu’il existe différentes versions de cette struct, dont les plus anciennes peuvent contenir moins d’informations.

Notez que le répertoire Code peut utiliser n’importe quel algorithme de hachage. Actuellement, le plus courant est **SHA256** (indiqué par la valeur 2 dans le champ `hashType`), mais à l’avenir, si ce hash est compromis, Apple pourrait commencer à en utiliser un autre.

## Signature des pages de code

Hacher l’intégralité du binaire serait inefficace et même inutile s’il n’est chargé que partiellement en mémoire. Par conséquent, la signature du code est en réalité un hash de hashes, où chaque page du binaire est hashée individuellement.\
En fait, dans le code **Code Directory** précédent, vous pouvez voir que la **taille des pages est spécifiée** dans l’un de ses champs. De plus, si la taille du binaire n’est pas un multiple de la taille d’une page, le champ **CodeLimit** indique où se termine la signature.
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

# get them with disarm
disarm -vv --sig /bin/ps # Get all the hashes of the binary
An embedded signature of 5824 bytes, with 5 blobs:
Code Directory (869 bytes)
Version:     20400
Flags:       none
Platform Binary
CodeLimit:   0x10f80
Identifier:  com.apple.ps (@0x58)
Executable Segment: Base 0x0 Limit: 0x00008000 Flags: 0x00000001
CDHash:	     ba668da43c001d101f02ffd9c915b8d4b88e3a7ad5333acd58499189a22a16a2 (computed)
# of hashes: 17 code (4K pages) + 7 special
Hashes @325 size: 32 Type: SHA-256
Special Slot   7 Entitlements ASN1/DER:	a542b4dcbc134fbd950c230ed9ddb99a343262a2df8e0c847caee2b6d3b41cc8 (OK)
Special Slot   6 DMG:	Not Bound
Special Slot   5 Entitlements blob:	2bb2de519f43b8e116c7eeea8adc6811a276fb134c55c9c2e9dcbd3047f80c7d (OK)
Special Slot   4 Application Specific:	Not Bound
Special Slot   3 Resource Directory:	Not Bound
Special Slot   2 Requirements blob:	4ca453dc8908dc7f6e637d6159c8761124ae56d080a4a550ad050c27ead273b3 (OK)
Special Slot   1 Bound Info.plist:	Not Bound
Slot   0 (File page @0x0000):	68eb381817e783faf97d5bf64ca066e6f3867a1ef16c145b32ad282cd550cabd (OK)
Slot   1 (File page @0x1000):	4c0714307c8ffbabe003573bc45d5a5690256ecc52c39250cae211f3ecafd507 (OK)
Slot   2 (File page @0x2000):	6e291b8260de343ef8fb984b88eac08d55f473870f5a612c71f7538a9c846beb (OK)
Slot   3 (File page @0x3000):	7a735f6a34a3544ca716cf2ab7ddf0dbd499aba1c279268de7c86626f4d320d9 (OK)
Slot   4 (File page @0x4000):	d01f0d2ddca0b0dc07269349add7320fbc277a7ad629c00f25fe59b926d9ca5f (OK)
Slot   5 (File page @0x5000):	7f282101b9601946b573303e3a6adbbc855768a15784d1c25e217b4fdea4da7e (OK)
Slot   6 (File page @0x6000):	NULL PAGE HASH (OK)
Slot   7 (File page @0x7000):	NULL PAGE HASH (OK)
Slot   8 (File page @0x8000):	b90a5987d6daa560ef3013c3626d23133e1dfad33499ae27ba1bd7c40b321347 (OK)
[...]

# Calculate the hashes of each page manually
BINARY=/bin/ps
SIZE=`stat -f "%Z" $BINARY`
PAGESIZE=4096 # From the previous output
PAGES=`expr $SIZE / $PAGESIZE`
for i in `seq 0 $PAGES`; do
dd if=$BINARY of=/tmp/`basename $BINARY`.page.$i bs=$PAGESIZE skip=$i count=1
done
openssl sha256 /tmp/*.page.*

#Note that the last pages might not coincide because the binary didn't signed the signatura that it was calculating but the real size of the binary.
```
## Entitlements Blob

Notez que les applications peuvent également contenir un **entitlement blob** où tous les entitlements sont définis. De plus, certains binaires iOS peuvent avoir leurs entitlements spécifiés dans le slot spécial -7 (au lieu du slot spécial -5 des entitlements).

## Special Slots

Les applications macOS ne contiennent pas tout ce dont elles ont besoin pour s'exécuter à l'intérieur du binaire, mais utilisent également des **ressources externes** (généralement à l'intérieur du **bundle** de l'application). Par conséquent, certains slots du binaire contiennent les hashes de ressources externes intéressantes afin de vérifier qu'elles n'ont pas été modifiées.

En réalité, il est possible de voir dans les structures Code Directory un paramètre appelé **`nSpecialSlots`**, indiquant le nombre de slots spéciaux. Il n'existe pas de slot spécial 0, et les plus courants (de -1 à -6) sont :

- Hash de `info.plist` (ou de celui présent dans `__TEXT.__info__plist`).
- Hash des Requirements
- Hash du Resource Directory (hash du fichier `_CodeSignature/CodeResources` à l'intérieur du bundle).
- Spécifique à l'application (non utilisé)
- Hash des entitlements
- Uniquement pour les code signatures DMG
- DER Entitlements

## Code Signing Flags

Chaque processus possède un bitmask associé, appelé `status`, qui est initialisé par le kernel et dont certaines valeurs peuvent être remplacées par la **code signature**. Ces flags pouvant être inclus dans la code signing sont [définis dans le code](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36):<sup>[[1]](#references)</sup>

L'espace utilisateur peut interroger ou mettre à jour les parties autorisées de cet état via les opérations `csops` et `csops_audittoken` définies par XNU.<sup>[[5]](#references)</sup>
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
Notez que la fonction [**exec_mach_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_exec.c#L1420) peut également ajouter dynamiquement les flags `CS_EXEC_*` lors du démarrage de l’exécution.

## Exigences de Code Signature

Chaque application stocke certaines **exigences** auxquelles elle doit **satisfaire** pour pouvoir être exécutée. Si **l’application contient des exigences qui ne sont pas satisfaites par l’application**, elle ne sera pas exécutée (car elle a probablement été modifiée).

Les exigences d’un binaire utilisent une **grammaire spéciale** qui est un flux d’**expressions** et sont encodées sous forme de blobs en utilisant `0xfade0c00` comme valeur magique, dont le **hash est stocké dans un slot de code spécial**.<sup>[[4]](#references)</sup>

Les exigences d’un binaire peuvent être affichées en exécutant :
```bash
codesign -d -r- /bin/ls
Executable=/bin/ls
designated => identifier "com.apple.ls" and anchor apple

codesign -d -r- /Applications/Signal.app/
Executable=/Applications/Signal.app/Contents/MacOS/Signal
designated => identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR
```
> [!TIP]
> Notez que ces signatures peuvent vérifier des éléments tels que les informations de certification, le TeamID, les IDs, les entitlements et bien d'autres données.

De plus, il est possible de générer certaines exigences compilées à l'aide de l'outil `csreq` :
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
Il est possible d’accéder à ces informations et de créer ou modifier des requirements avec certaines APIs de `Security.framework` comme :<sup>[[3]](#references)</sup>

#### **Vérification de la validité**

- **`Sec[Static]CodeCheckValidity`** : Vérifie la validité de SecCodeRef selon le Requirement.
- **`SecRequirementEvaluate`** : Valide un requirement dans le contexte d’un certificat.
- **`SecTaskValidateForRequirement`** : Valide un SecTask en cours d’exécution par rapport à un requirement `CFString`.

#### **Création et gestion des Code Requirements**

- **`SecRequirementCreateWithData` :** Crée un `SecRequirementRef` à partir de données binaires représentant le requirement.
- **`SecRequirementCreateWithString` :** Crée un `SecRequirementRef` à partir d’une expression textuelle du requirement.
- **`SecRequirementCopy[Data/String]`** : Récupère la représentation en données binaires d’un `SecRequirementRef`.
- **`SecRequirementCreateGroup`** : Crée un requirement pour l’appartenance à un app-group.

#### **Accès aux informations de Code Signing**

- **`SecStaticCodeCreateWithPath`** : Initialise un objet `SecStaticCodeRef` à partir d’un chemin du système de fichiers afin d’inspecter les signatures de code.
- **`SecCodeCopySigningInformation`** : Obtient les informations de signature à partir d’un `SecCodeRef` ou d’un `SecStaticCodeRef`.

#### **Modification des Code Requirements**

- **`SecCodeSignerCreate`** : Crée un objet `SecCodeSignerRef` pour effectuer des opérations de code signing.
- **`SecCodeSignerSetRequirement`** : Définit un nouveau requirement que le code signer doit appliquer lors de la signature.
- **`SecCodeSignerAddSignature`** : Ajoute une signature au code signé avec le signer spécifié.

#### **Validation du code avec des requirements**

- **`SecStaticCodeCheckValidity`** : Valide un objet de code statique par rapport aux requirements spécifiés.

#### **APIs supplémentaires utiles**

- **`SecCodeCopy[Internal/Designated]Requirement`** : Récupère un SecRequirementRef depuis un SecCodeRef.
- **`SecCodeCopyGuestWithAttributes`** : Crée un `SecCodeRef` représentant un objet de code selon des attributs spécifiques, ce qui est utile pour le sandboxing.
- **`SecCodeCopyPath`** : Récupère le chemin du système de fichiers associé à un `SecCodeRef`.
- **`SecCodeCopySigningIdentifier`** : Obtient l’identifiant de signature (par exemple, le Team ID) depuis un `SecCodeRef`.
- **`SecCodeGetTypeID`** : Renvoie l’identifiant de type des objets `SecCodeRef`.
- **`SecRequirementGetTypeID`** : Obtient un CFTypeID d’un `SecRequirementRef`.

#### **Flags et constantes de Code Signing**

- **`kSecCSDefaultFlags`** : Flags par défaut utilisés par de nombreuses fonctions de `Security.framework` pour les opérations de code signing.
- **`kSecCSSigningInformation`** : Flag utilisé pour indiquer que les informations de signature doivent être récupérées.

## Application des signatures de code

Le **kernel** est celui qui **vérifie la signature du code** avant d’autoriser l’exécution du code de l’application. De plus, une façon de pouvoir écrire et exécuter du nouveau code en mémoire consiste à abuser de JIT si `mprotect` est appelé avec le flag `MAP_JIT`. Notez que l’application doit disposer d’un entitlement spécial pour pouvoir le faire.

## `cs_blobs` & `cs_blob`

La structure [**cs_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc_internal.h#L106) contient les informations relatives à l’entitlement du processus en cours d’exécution. `csb_platform_binary` indique également si l’application est un **platform binary** (ce qui est vérifié à différents moments par l’OS afin d’appliquer des mécanismes de sécurité, comme la protection des droits SEND sur les task ports de ces processus).<sup>[[2]](#references)</sup>

> [!WARNING]
> Notez que plusieurs mesures de sécurité dépendent du fait que le binaire soit un platform binary. Ainsi, une manière d’escalader les privilèges consiste à **transformer le binaire en platform binary** (par exemple, en le re-signant avec un certificat qui l’autorise).
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
## References

- [1] [XNU — `osfmk/kern/cs_blobs.h` (`CodeDirectory`, `CS_*` flags, blob magic values)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [2] [XNU — `bsd/kern/ubc_subr.c` (`cs_blob` handling and signature validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [3] [Source du framework Security d’Apple — `libsecurity_codesigning`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/libsecurity_codesigning)
- [4] [Apple Developer — Guide de Code Signing](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Introduction/Introduction.html)
- [5] [XNU — `bsd/sys/codesign.h` (`csops`/`csops_audittoken` operations)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
{{#include ../../../banners/hacktricks-training.md}}
