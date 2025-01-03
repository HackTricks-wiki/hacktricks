# macOS Code Signing

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Mach-o binaries bevat 'n laaiopdrag genaamd **`LC_CODE_SIGNATURE`** wat die **offset** en **grootte** van die handtekeninge binne die binêre aandui. Trouens, deur die GUI-gereedskap MachOView te gebruik, is dit moontlik om aan die einde van die binêre 'n afdeling genaamd **Code Signature** met hierdie inligting te vind:

<figure><img src="../../../images/image (1) (1) (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

Die magiese kop van die Code Signature is **`0xFADE0CC0`**. Dan het jy inligting soos die lengte en die aantal blobs van die superBlob wat hulle bevat.\
Dit is moontlik om hierdie inligting in die [bron kode hier](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L276) te vind:
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
Gewone blobs wat bevat word, is Code Directory, Requirements en Entitlements en 'n Cryptographic Message Syntax (CMS).\
Boonop, let op hoe die data wat in die blobs gekodeer is, in **Big Endian** gekodeer is.

Boonop kan handtekeninge van die binaries losgemaak word en gestoor word in `/var/db/DetachedSignatures` (gebruik deur iOS).

## Code Directory Blob

Dit is moontlik om die verklaring van die [Code Directory Blob in die kode](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L104) te vind:
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
Let wel dat daar verskillende weergawes van hierdie struktuur is waar oues minder inligting mag bevat.

## Ondertekening van Kode Bladsye

Hashing van die volle binêre sou ondoeltreffend en selfs nutteloos wees as dit net gedeeltelik in geheue gelaai word. Daarom is die kodehandtekening eintlik 'n hash van hashes waar elke binêre bladsy individueel gehasht word.\
Eintlik kan jy in die vorige **Kode Gids** kode sien dat die **bladgrootte gespesifiseer is** in een van sy velde. Boonop, as die grootte van die binêre nie 'n veelvoud van die grootte van 'n bladsy is nie, spesifiseer die veld **CodeLimit** waar die einde van die handtekening is.
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
## Toelaag Blob

Let daarop dat toepassings ook 'n **toelaag blob** kan bevat waar al die toelaes gedefinieer is. Boonop mag sommige iOS binêre hul toelaes spesifiek in die spesiale slot -7 hê (in plaas van in die -5 toelaes spesiale slot).

## Spesiale Slots

MacOS toepassings het nie alles wat hulle nodig het om binne die binêre uit te voer nie, maar hulle gebruik ook **buitelandse hulpbronne** (gewoonlik binne die toepassings **bundel**). Daarom is daar 'n paar slots binne die binêre wat die hashes van 'n paar interessante buitelandse hulpbronne sal bevat om te kontroleer dat hulle nie gewysig is nie.

Werklik, dit is moontlik om in die Code Directory strukture 'n parameter genaamd **`nSpecialSlots`** te sien wat die aantal spesiale slots aandui. Daar is nie 'n spesiale slot 0 nie en die mees algemene (van -1 tot -6) is:

- Hash van `info.plist` (of die een binne `__TEXT.__info__plist`).
- Hash van die Vereistes
- Hash van die Hulpbron Gids (hash van `_CodeSignature/CodeResources` lêer binne die bundel).
- Toepassing spesifiek (onbenut)
- Hash van die toelaes
- DMG kode handtekeninge slegs
- DER Toelaes

## Kode Handtekening Vlaggies

Elke proses het 'n bitmasker wat bekend staan as die `status` wat deur die kernel begin word en sommige daarvan kan oorgeskryf word deur die **kode handtekening**. Hierdie vlaggies wat in die kode handtekening ingesluit kan word, is [gedefinieer in die kode](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36):
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
Let wel, die funksie [**exec_mach_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_exec.c#L1420) kan ook die `CS_EXEC_*` vlae dinamies byvoeg wanneer die uitvoering begin.

## Kode Handtekening Vereistes

Elke toepassing stoor **vereistes** wat dit moet **tevrede stel** om uitgevoer te kan word. As die **toepassing vereistes bevat wat nie deur die toepassing tevrede gestel word nie**, sal dit nie uitgevoer word nie (soos dit waarskynlik verander is).

Die vereistes van 'n binêre gebruik 'n **spesiale grammatika** wat 'n stroom van **uitdrukkings** is en word as blobs gekodeer met `0xfade0c00` as die magie waarvan die **hash in 'n spesiale kode-slot gestoor word**.

Die vereistes van 'n binêre kan gesien word deur te loop:
```bash
codesign -d -r- /bin/ls
Executable=/bin/ls
designated => identifier "com.apple.ls" and anchor apple

codesign -d -r- /Applications/Signal.app/
Executable=/Applications/Signal.app/Contents/MacOS/Signal
designated => identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR
```
> [!NOTE]
> Let op hoe hierdie handtekeninge dinge soos sertifiseringsinligting, TeamID, ID's, regte en baie ander data kan nagaan.

Boonop is dit moontlik om 'n paar saamgestelde vereistes te genereer met die `csreq` hulpmiddel:
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
It's possible to access this information and create or modify requirements with some APIs from the `Security.framework` like:

#### **Kontroleer Geldigheid**

- **`Sec[Static]CodeCheckValidity`**: Kontroleer die geldigheid van SecCodeRef per Vereiste.
- **`SecRequirementEvaluate`**: Valideer vereiste in sertifikaat konteks
- **`SecTaskValidateForRequirement`**: Valideer 'n lopende SecTask teen `CFString` vereiste.

#### **Skep en Bestuur Kode Vereistes**

- **`SecRequirementCreateWithData`:** Skep 'n `SecRequirementRef` uit binêre data wat die vereiste verteenwoordig.
- **`SecRequirementCreateWithString`:** Skep 'n `SecRequirementRef` uit 'n stringuitdrukking van die vereiste.
- **`SecRequirementCopy[Data/String]`**: Verkry die binêre data voorstelling van 'n `SecRequirementRef`.
- **`SecRequirementCreateGroup`**: Skep 'n vereiste vir app-groep lidmaatskap

#### **Toegang tot Kode Handtekening Inligting**

- **`SecStaticCodeCreateWithPath`**: Inisialiseer 'n `SecStaticCodeRef` objek vanaf 'n lêerstelsel pad vir die inspeksie van kode handtekeninge.
- **`SecCodeCopySigningInformation`**: Verkry handtekening inligting van 'n `SecCodeRef` of `SecStaticCodeRef`.

#### **Wysig Kode Vereistes**

- **`SecCodeSignerCreate`**: Skep 'n `SecCodeSignerRef` objek vir die uitvoering van kode handtekening operasies.
- **`SecCodeSignerSetRequirement`**: Stel 'n nuwe vereiste vir die kode ondertekenaar in om tydens ondertekening toe te pas.
- **`SecCodeSignerAddSignature`**: Voeg 'n handtekening by die kode wat onderteken word met die gespesifiseerde ondertekenaar.

#### **Valideer Kode met Vereistes**

- **`SecStaticCodeCheckValidity`**: Valideer 'n statiese kode objek teen gespesifiseerde vereistes.

#### **Addisionele Nuttige APIs**

- **`SecCodeCopy[Internal/Designated]Requirement`: Kry SecRequirementRef van SecCodeRef**
- **`SecCodeCopyGuestWithAttributes`**: Skep 'n `SecCodeRef` wat 'n kode objek verteenwoordig gebaseer op spesifieke eienskappe, nuttig vir sandboxing.
- **`SecCodeCopyPath`**: Verkry die lêerstelsel pad geassosieer met 'n `SecCodeRef`.
- **`SecCodeCopySigningIdentifier`**: Verkry die handtekening identifiseerder (bv. Span ID) van 'n `SecCodeRef`.
- **`SecCodeGetTypeID`**: Gee die tipe identifiseerder vir `SecCodeRef` objek.
- **`SecRequirementGetTypeID`**: Kry 'n CFTypeID van 'n `SecRequirementRef`

#### **Kode Handtekening Vlaggies en Konstanten**

- **`kSecCSDefaultFlags`**: Standaard vlaggies wat in baie Security.framework funksies vir kode handtekening operasies gebruik word.
- **`kSecCSSigningInformation`**: Vlag wat gebruik word om aan te dui dat handtekening inligting verkry moet word.

## Kode Handtekening Afforcing

Die **kernel** is die een wat **die kode handtekening kontroleer** voordat dit die kode van die app toelaat om uit te voer. Boonop, een manier om in geheue nuwe kode te kan skryf en uitvoer is om JIT te misbruik as `mprotect` met `MAP_JIT` vlag aangeroep word. Let daarop dat die toepassing 'n spesiale regte benodig om dit te kan doen.

## `cs_blobs` & `cs_blob`

[**cs_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc_internal.h#L106) struktuur bevat die inligting oor die regte van die lopende proses daarop. `csb_platform_binary` dui ook aan of die toepassing 'n platform binêre is (wat op verskillende tye deur die OS gekontroleer word om sekuriteitsmeganismes toe te pas soos om die SEND regte na die taak poorte van hierdie prosesse te beskerm).
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
## Verwysings

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
