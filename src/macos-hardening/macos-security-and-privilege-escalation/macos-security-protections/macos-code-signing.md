# macOS Code Signing

{{#include ../../../banners/hacktricks-training.md}}

## बेसिक जानकारी

{{#ref}}
../../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/mach-o-entitlements-and-ipsw-indexing.md
{{#endref}}


Mach-o binaries में एक load command होता है जिसका नाम **`LC_CODE_SIGNATURE`** है जो बाइनरी के अंदर signatures के **offset** और **size** को दर्शाता है। दरअसल, GUI tool MachOView का उपयोग करके, बाइनरी के अंत में **Code Signature** नामक एक section पाया जा सकता है जिसमें यह जानकारी रहती है:

<figure><img src="../../../images/image (1) (1) (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

Code Signature का magic header **`0xFADE0CC0`** है। फिर आपको उन blobs को contain करने वाले superBlob की length और number of blobs जैसी जानकारी मिलती है।\
यह जानकारी आप [source code here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L276):
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
सामान्य रूप से मौजूद blobs में Code Directory, Requirements और Entitlements तथा एक Cryptographic Message Syntax (CMS) शामिल होते हैं।\
साथ ही ध्यान दें कि blobs में एन्कोड किया गया डेटा **Big Endian.**

साथ ही, signatures बाइनरी से अलग करके `/var/db/DetachedSignatures` में स्टोर की जा सकती हैं (iOS द्वारा उपयोग)।

## Code Directory Blob

कोड में [Code Directory Blob in the code](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L104) की घोषणा देखी जा सकती है:
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
ध्यान दें कि इस struct के अलग-अलग संस्करण हैं जहाँ पुराने वाले कम जानकारी रख सकते हैं।

## Signing Code Pages

यदि पूरा binary हैश किया जाए तो यह अप्रभावी और बेकार होगा जब वह केवल memory में आंशिक रूप से लोड हो। इसलिए, code signature वास्तव में एक hash of hashes है जहाँ प्रत्येक binary page को अलग-अलग hashed किया जाता है।\
वास्तव में, पिछले **Code Directory** code में आप देख सकते हैं कि उसके एक field में **page size is specified**। इसके अलावा, यदि binary का size किसी page के size का multiple नहीं है, तो field **CodeLimit** यह निर्दिष्ट करता है कि signature का अंत कहाँ है।
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

ध्यान दें कि applications में एक **entitlement blob** भी हो सकता है जहाँ सभी entitlements परिभाषित होते हैं। इसके अलावा, कुछ iOS binaries में उनके entitlements विशेष स्लॉट -7 में हो सकते हैं (बज़ाय -5 entitlements विशेष स्लॉट के)।

## Special Slots

MacOS applications के पास binary के अंदर चलने के लिए सब कुछ नहीं होता, बल्कि वे **external resources** का भी उपयोग करते हैं (आम तौर पर applications के **bundle** के भीतर)। इसलिए, binary के अंदर कुछ ऐसे स्लॉट होते हैं जो कुछ महत्वपूर्ण external resources के hashes रखेंगे ताकि यह जांचा जा सके कि उन्हें modify नहीं किया गया है।

वास्तव में, Code Directory structs में **`nSpecialSlots`** नाम का एक parameter देखा जा सकता है जो special slots की संख्या दर्शाता है। यहाँ कोई special slot 0 नहीं होता और सबसे आम ones (from -1 to -6) हैं:

- `info.plist` का Hash (या जो `__TEXT.__info__plist` के अंदर है)।
- Requirements का Hash
- Resource Directory का Hash (`_CodeSignature/CodeResources` फ़ाइल का bundle के अंदर hash)।
- Application specific (unused)
- Entitlements का Hash
- केवल DMG code signatures
- DER Entitlements

## Code Signing Flags

हर process से संबंधित एक bitmask होता है जिसे `status` कहा जाता है, जिसे kernel द्वारा सेट किया जाता है और जिनमें से कुछ को **code signature** द्वारा override किया जा सकता है। ये flags जो code signing में शामिल किए जा सकते हैं [defined in the code](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36):
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
ध्यान दें कि फ़ंक्शन [**exec_mach_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_exec.c#L1420) निष्पादन शुरू करते समय डायनामिक रूप से `CS_EXEC_*` फ्लैग भी जोड़ सकता है।

## कोड सिग्नेचर आवश्यकताएँ

प्रत्येक एप्लिकेशन कुछ **आवश्यकताएँ** संग्रहीत करता है जिन्हें निष्पादन योग्य होने के लिए **संतुष्ट** होना आवश्यक है। यदि एप्लिकेशन में मौजूद **आवश्यकताएँ** संतुष्ट नहीं होतीं, तो इसे निष्पादित नहीं किया जाएगा (क्योंकि संभवतः इसे बदल दिया गया है)।

किसी बाइनरी की आवश्यकताएँ एक **विशेष व्याकरण** का उपयोग करती हैं जो **अभिव्यक्तियों** की एक धारा है और इन्हें ब्लॉब्स के रूप में एन्कोड किया जाता है जो `0xfade0c00` को magic के रूप में उपयोग करते हैं, जिसका **हैश एक विशेष कोड स्लॉट में संग्रहीत** होता है।

किसी बाइनरी की आवश्यकताओं को निष्पादन के समय देखा जा सकता है:
```bash
codesign -d -r- /bin/ls
Executable=/bin/ls
designated => identifier "com.apple.ls" and anchor apple

codesign -d -r- /Applications/Signal.app/
Executable=/Applications/Signal.app/Contents/MacOS/Signal
designated => identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR
```
> [!TIP]
> ध्यान दें कि ये signatures प्रमाणपत्र जानकारी, TeamID, IDs, entitlements और कई अन्य डेटा जैसी चीज़ों की जाँच कर सकते हैं।

इसके अलावा, `csreq` टूल का उपयोग करके कुछ compiled requirements बनाना संभव है:
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
यह जानकारी एक्सेस करना और `Security.framework` के कुछ APIs के माध्यम से requirements बनाना या संशोधित करना संभव है, जैसे:

#### **वैधता की जाँच**

- **`Sec[Static]CodeCheckValidity`**: SecCodeRef की वैधता Requirement के अनुसार जाँचें।
- **`SecRequirementEvaluate`**: प्रमाणपत्र संदर्भ (certificate context) में Requirement को मान्य करें।
- **`SecTaskValidateForRequirement`**: चल रहे SecTask को `CFString` requirement के विरुद्ध मान्य करें।

#### **Code Requirements बनाना और प्रबंधित करना**

- **`SecRequirementCreateWithData`:** Requirement का प्रतिनिधित्व करने वाले बाइनरी डेटा से `SecRequirementRef` बनाता है।
- **`SecRequirementCreateWithString`:** Requirement के स्ट्रिंग एक्सप्रेशन से `SecRequirementRef` बनाता है।
- **`SecRequirementCopy[Data/String]`**: `SecRequirementRef` का बाइनरी डेटा प्रतिनिधित्व प्राप्त करता है।
- **`SecRequirementCreateGroup`**: app-group सदस्यता के लिए requirement बनाता है।

#### **Code Signing जानकारी तक पहुँच**

- **`SecStaticCodeCreateWithPath`**: कोड सिग्नेचर inspect करने के लिए फाइल सिस्टम पाथ से `SecStaticCodeRef` ऑब्जेक्ट इनिशियलाइज़ करता है।
- **`SecCodeCopySigningInformation`**: `SecCodeRef` या `SecStaticCodeRef` से साइनिंग जानकारी प्राप्त करता है।

#### **Code Requirements संशोधित करना**

- **`SecCodeSignerCreate`**: कोड साइनिंग ऑपरेशन के लिए `SecCodeSignerRef` ऑब्जेक्ट बनाता है।
- **`SecCodeSignerSetRequirement`**: साइनिंग के दौरान लागू करने के लिए कोड साइनर के लिए नया requirement सेट करता है।
- **`SecCodeSignerAddSignature`**: निर्दिष्ट signer के साथ साइन किए जा रहे कोड में सिग्नेचर जोड़ता है।

#### **Requirements के साथ कोड को मान्य करना**

- **`SecStaticCodeCheckValidity`**: निर्दिष्ट requirements के खिलाफ static code ऑब्जेक्ट को मान्य करता है।

#### **अन्य उपयोगी APIs**

- **`SecCodeCopy[Internal/Designated]Requirement`: Get SecRequirementRef from SecCodeRef**
- **`SecCodeCopyGuestWithAttributes`**: विशिष्ट attributes के आधार पर कोड ऑब्जेक्ट को दर्शाने वाला `SecCodeRef` बनाता है, sandboxing के लिए उपयोगी।
- **`SecCodeCopyPath`**: `SecCodeRef` से संबंधित फाइल सिस्टम पाथ प्राप्त करता है।
- **`SecCodeCopySigningIdentifier`**: `SecCodeRef` से signing identifier (उदा., Team ID) प्राप्त करता है।
- **`SecCodeGetTypeID`**: `SecCodeRef` ऑब्जेक्ट्स के लिए type identifier लौटाता है।
- **`SecRequirementGetTypeID`**: `SecRequirementRef` का CFTypeID प्राप्त करता है।

#### **Code Signing फ्लैग्स और कॉन्स्टैंट्स**

- **`kSecCSDefaultFlags`**: कोड साइनिंग ऑपरेशनों के लिए कई Security.framework फंक्शन्स में उपयोग होने वाले डिफ़ॉल्ट फ्लैग्स।
- **`kSecCSSigningInformation`**: यह फ्लैग यह निर्दिष्ट करने के लिए उपयोग होता है कि साइनिंग जानकारी प्राप्त की जानी चाहिए।

## कोड सिग्नेचर लागू करना (Code Signature Enforcement)

**कर्नेल** वह घटक है जो ऐप के कोड को निष्पादित करने की अनुमति देने से पहले **कोड सिग्नेचर की जाँच** करता है। इसके अलावा, मेमोरी में नया कोड लिखने और निष्पादित करने में सक्षम होने का एक तरीका JIT का दुरुपयोग करना है यदि `mprotect` को `MAP_JIT` फ्लैग के साथ कॉल किया जाए। ध्यान दें कि इसको करने के लिए एप्लिकेशन को एक विशेष entitlement की आवश्यकता होती है।

## `cs_blobs` & `cs_blob`

[**cs_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc_internal.h#L106) struct उस पर चल रहे प्रोसेस के entitlement के बारे में जानकारी रखता है। `csb_platform_binary` यह भी बताता है कि एप्लिकेशन एक platform binary है या नहीं (जिसे OS विभिन्न समयों पर जाँचता है ताकि सुरक्षा तंत्र लागू किये जा सकें, जैसे इन प्रोसेसेस के task ports के SEND rights की रक्षा करना)।
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
## संदर्भ

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
