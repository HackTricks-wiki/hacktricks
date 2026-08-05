# Code Signing ya macOS

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

{{#ref}}
../../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/mach-o-entitlements-and-ipsw-indexing.md
{{#endref}}


Binaries za Mach-o zina load command inayoitwa **`LC_CODE_SIGNATURE`**, ambayo inaonyesha **offset** na **size** ya signatures zilizo ndani ya binary. Kwa kweli, kwa kutumia zana ya GUI MachOView, inawezekana kupata mwishoni mwa binary sehemu inayoitwa **Code Signature** yenye taarifa hizi:

<figure><img src="../../../images/image (1) (1) (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

Magic header ya Code Signature ni **`0xFADE0CC0`** (embedded code signature) au **`0xFADE0CC1`** (detached code signature). Kisha kuna taarifa kama vile urefu na idadi ya blobs za superBlob inayozihifadhi.\
Inawezekana kupata taarifa hii katika [source code hapa](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L276):<sup>[[1]](#references)</sup>】【。
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
Blob zinazopatikana kwa kawaida ni Code Directory, Requirements na Entitlements, pamoja na Cryptographic Message Syntax (CMS).\
Aidha, zingatia kwamba data iliyosimbwa katika blobs imesimbwa kwa **Big Endian.**

Aidha, kumbuka kwamba signatures zinaweza kutenganishwa kutoka kwenye binaries na kuhifadhiwa katika `/var/db/DetachedSignatures` (inayotumiwa na iOS).

## Code Directory Blob

Inawezekana kupata declaration ya [Code Directory Blob kwenye code](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L104):<sup>[[1]](#references)</sup>
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
Note kwamba kuna matoleo tofauti ya struct hii ambapo ya zamani yanaweza kuwa na taarifa chache.

Note kwamba Code directory inaweza kutumia hashing algorithm yoyote. Kwa sasa, inayotumika zaidi ni **SHA256** (inayoonyeshwa na thamani 2 katika field ya `hashType`), lakini baadaye hash hii ikivunjwa, Apple inaweza kuanza kutumia nyingine.

## Kusaini Code Pages

Kuhash binary nzima kungekuwa hakufai na hata hakuna maana ikiwa inapakiwa kwenye memory kwa sehemu tu. Kwa hiyo, code signature kwa kweli ni hash ya hashes ambapo kila binary page inahashwa kivyake.\
Kwa kweli, katika code ya awali ya **Code Directory** unaweza kuona kwamba **page size imeainishwa** katika mojawapo ya fields zake. Zaidi ya hayo, ikiwa size ya binary si multiple ya size ya page, field ya **CodeLimit** huainisha mahali ambapo signature inaishia.
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

Kumbuka kwamba applications huenda pia zikawa na **entitlement blob** ambapo entitlements zote zimefafanuliwa. Zaidi ya hayo, baadhi ya iOS binaries zinaweza kuwa na entitlements zake katika special slot -7 (badala ya special slot -5 ya entitlements).

## Special Slots

Applications za MacOS hazina kila kitu zinachohitaji ili kutekelezwa ndani ya binary, bali pia hutumia **external resources** (kwa kawaida zilizo ndani ya **bundle** ya application). Kwa hiyo, kuna slots kadhaa ndani ya binary ambazo huwa na hashes za baadhi ya external resources muhimu, ili kuthibitisha kwamba hazijabadilishwa.

Kwa kweli, inawezekana kuona katika Code Directory structs parameter inayoitwa **`nSpecialSlots`**, inayobainisha idadi ya special slots. Hakuna special slot 0, na zinazotumika zaidi (kutoka -1 hadi -6) ni:

- Hash ya `info.plist` (au ile iliyo ndani ya `__TEXT.__info__plist`).
- Hash ya Requirements
- Hash ya Resource Directory (hash ya faili `_CodeSignature/CodeResources` ndani ya bundle).
- Application-specific (haitumiki)
- Hash ya entitlements
- DMG code signatures pekee
- DER Entitlements

## Code Signing Flags

Kila process ina bitmask inayohusiana nayo, inayojulikana kama `status`, ambayo huanzishwa na kernel, na baadhi ya flags zake zinaweza kubatilishwa na **code signature**. Flags hizi zinazoweza kujumuishwa katika code signing [zimefafanuliwa kwenye code](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36):<sup>[[1]](#references)</sup>
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
Kumbuka kwamba function [**exec_mach_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_exec.c#L1420) pia inaweza kuongeza flags za `CS_EXEC_*` dynamically wakati wa kuanzisha execution.

## Mahitaji ya Code Signature

Kila application huhifadhi **requirements** ambazo lazima **itimie** ili iweze ku-execute. Ikiwa **application ina requirements ambazo hazijatimizwa na application hiyo**, haitatekelezwa (kwa kuwa huenda imebadilishwa).

Requirements za binary hutumia **grammar maalum** ambayo ni stream ya **expressions**, na hu-encodewa kama blobs kwa kutumia `0xfade0c00` kama magic, ambao **hash** yake huhifadhiwa katika code slot maalum.

Requirements za binary zinaweza kuonekana kwa ku-run:
```bash
codesign -d -r- /bin/ls
Executable=/bin/ls
designated => identifier "com.apple.ls" and anchor apple

codesign -d -r- /Applications/Signal.app/
Executable=/Applications/Signal.app/Contents/MacOS/Signal
designated => identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR
```
> [!TIP]
> Zingatia jinsi signatures hizi zinavyoweza kukagua vitu kama certification information, TeamID, IDs, entitlements na data nyingine nyingi.

Zaidi ya hayo, inawezekana kutengeneza requirements zilizocompile kwa kutumia tool ya `csreq`:
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
Inawezekana kufikia taarifa hizi na kuunda au kurekebisha requirements kwa kutumia baadhi ya APIs kutoka `Security.framework` kama vile:<sup>[[4]](#references)</sup>

#### **Kukagua Uhalali**

- **`Sec[Static]CodeCheckValidity`**: Hukagua uhalali wa SecCodeRef kulingana na Requirement.
- **`SecRequirementEvaluate`**: Huthibitisha requirement katika muktadha wa certificate.
- **`SecTaskValidateForRequirement`**: Huthibitisha SecTask inayoendesha dhidi ya requirement ya `CFString`.

#### **Kuunda na Kusimamia Code Requirements**

- **`SecRequirementCreateWithData`:** Huunda `SecRequirementRef` kutoka kwenye binary data inayowakilisha requirement.
- **`SecRequirementCreateWithString`:** Huunda `SecRequirementRef` kutoka kwenye string expression ya requirement.
- **`SecRequirementCopy[Data/String]`**: Hupata uwakilishi wa binary data wa `SecRequirementRef`.
- **`SecRequirementCreateGroup`**: Huunda requirement kwa ajili ya uanachama wa app-group.

#### **Kufikia Taarifa za Code Signing**

- **`SecStaticCodeCreateWithPath`**: Huanzisha object ya `SecStaticCodeRef` kutoka kwenye file system path kwa ajili ya kukagua code signatures.
- **`SecCodeCopySigningInformation`**: Hupata taarifa za signing kutoka kwenye `SecCodeRef` au `SecStaticCodeRef`.

#### **Kurekebisha Code Requirements**

- **`SecCodeSignerCreate`**: Huunda object ya `SecCodeSignerRef` kwa ajili ya kutekeleza shughuli za code signing.
- **`SecCodeSignerSetRequirement`**: Huweka requirement mpya kwa code signer ili itumike wakati wa signing.
- **`SecCodeSignerAddSignature`**: Huongeza signature kwenye code inayosainiwa kwa kutumia signer maalum.

#### **Kuthibitisha Code kwa kutumia Requirements**

- **`SecStaticCodeCheckValidity`**: Huthibitisha static code object dhidi ya requirements zilizobainishwa.

#### **APIs Nyingine Muhimu**

- **`SecCodeCopy[Internal/Designated]Requirement`:** Hupata SecRequirementRef kutoka kwenye SecCodeRef.
- **`SecCodeCopyGuestWithAttributes`**: Huunda `SecCodeRef` inayowakilisha code object kulingana na attributes maalum, ambayo ni muhimu kwa sandboxing.
- **`SecCodeCopyPath`**: Hupata file system path inayohusishwa na `SecCodeRef`.
- **`SecCodeCopySigningIdentifier`**: Hupata signing identifier (kwa mfano, Team ID) kutoka kwenye `SecCodeRef`.
- **`SecCodeGetTypeID`**: Hurejesha type identifier ya objects za `SecCodeRef`.
- **`SecRequirementGetTypeID`**: Hupata CFTypeID ya `SecRequirementRef`.

#### **Code Signing Flags na Constants**

- **`kSecCSDefaultFlags`**: Flags chaguomsingi zinazotumiwa na functions nyingi za `Security.framework` kwa shughuli za code signing.
- **`kSecCSSigningInformation`**: Flag inayotumiwa kubainisha kwamba taarifa za signing zinapaswa kupatikana.

## Utekelezaji wa Code Signature

**kernel** ndiyo **hukagua code signature** kabla ya kuruhusu code ya app kutekelezwa. Zaidi ya hayo, njia mojawapo ya kuweza kuandika na kutekeleza code mpya kwenye memory ni kutumia vibaya JIT ikiwa `mprotect` itaitwa kwa flag ya `MAP_JIT`. Kumbuka kwamba application inahitaji entitlement maalum ili kuweza kufanya hivyo.

## `cs_blobs` & `cs_blob`

Struct ya [**cs_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc_internal.h#L106) ina taarifa kuhusu entitlement ya running process inayohusishwa nayo. `csb_platform_binary` pia huonyesha ikiwa application ni **platform binary** (ambayo hukaguliwa katika nyakati tofauti na OS ili kutumia security mechanisms kama kulinda SEND rights za task ports za processes hizi).

> [!WARNING]
> Kumbuka kwamba hatua kadhaa za usalama zinategemea binary kuwa platform binary, kwa hiyo njia moja ya ku-escalate privileges ni **kuifanya binary kuwa platform binary** (kwa mfano, kwa kuisaini tena kwa certificate inayoruhusu hilo).
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
## Marejeo

- [1] [XNU — `osfmk/kern/cs_blobs.h` (`CodeDirectory`, `CS_*` flags, blob magic values)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [2] [XNU — `bsd/kern/ubc_subr.c` (`cs_blob` handling and signature validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [3] [XNU — `bsd/sys/codesign.h` (`csops`/`csops_audittoken` operations)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [4] [Apple Security framework source — `libsecurity_codesigning`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/libsecurity_codesigning)
- [5] [Apple Developer — Code Signing Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Introduction/Introduction.html)

{{#include ../../../banners/hacktricks-training.md}}
