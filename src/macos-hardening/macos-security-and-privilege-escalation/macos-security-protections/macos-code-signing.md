# macOS कोड साइनिंग

{{#include ../../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

Mach-o बाइनरी में एक लोड कमांड होता है जिसे **`LC_CODE_SIGNATURE`** कहा जाता है, जो बाइनरी के अंदर सिग्नेचर के **ऑफसेट** और **आकार** को इंगित करता है। वास्तव में, GUI टूल MachOView का उपयोग करके, बाइनरी के अंत में **कोड सिग्नेचर** नामक एक अनुभाग पाया जा सकता है जिसमें यह जानकारी होती है:

<figure><img src="../../../images/image (1) (1) (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

कोड सिग्नेचर का जादुई हेडर **`0xFADE0CC0`** है। फिर आपके पास सुपरब्लॉब के ब्लॉब की लंबाई और संख्या जैसी जानकारी होती है जो उन्हें शामिल करती है।\
यह जानकारी [स्रोत कोड यहाँ](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L276) पर पाई जा सकती है:
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
सामान्य ब्लॉब में कोड निर्देशिका, आवश्यकताएँ और अधिकार और एक क्रिप्टोग्राफिक संदेश सिंटैक्स (CMS) शामिल होते हैं।\
इसके अलावा, ध्यान दें कि ब्लॉब में एन्कोड किया गया डेटा **बिग एंडियन** में एन्कोड किया गया है।

इसके अलावा, हस्ताक्षर बाइनरी से अलग किए जा सकते हैं और `/var/db/DetachedSignatures` में संग्रहीत किए जा सकते हैं (जो iOS द्वारा उपयोग किया जाता है)।

## कोड निर्देशिका ब्लॉब

[कोड निर्देशिका ब्लॉब की घोषणा कोड में पाई जा सकती है](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L104):
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
ध्यान दें कि इस संरचना के विभिन्न संस्करण हैं जहाँ पुराने संस्करणों में कम जानकारी हो सकती है।

## कोड साइनिंग पृष्ठ

पूर्ण बाइनरी का हैशिंग अप्रभावी और यहां तक कि बेकार होगा यदि इसे केवल आंशिक रूप से मेमोरी में लोड किया गया हो। इसलिए, कोड सिग्नेचर वास्तव में हैश का हैश है जहाँ प्रत्येक बाइनरी पृष्ठ को व्यक्तिगत रूप से हैश किया जाता है।\
वास्तव में, पिछले **कोड निर्देशिका** कोड में आप देख सकते हैं कि **पृष्ठ का आकार निर्दिष्ट है** इसके एक क्षेत्र में। इसके अलावा, यदि बाइनरी का आकार पृष्ठ के आकार का गुणांक नहीं है, तो क्षेत्र **CodeLimit** यह निर्दिष्ट करता है कि सिग्नेचर का अंत कहाँ है।
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

ध्यान दें कि अनुप्रयोगों में एक **entitlement blob** भी हो सकता है जहाँ सभी अधिकार परिभाषित होते हैं। इसके अलावा, कुछ iOS बाइनरी में उनके अधिकार विशेष स्लॉट -7 में विशिष्ट हो सकते हैं (बजाय -5 अधिकार विशेष स्लॉट में)।

## Special Slots

MacOS अनुप्रयोगों को बाइनरी के अंदर निष्पादित करने के लिए उन्हें जो कुछ भी चाहिए वह नहीं होता है, बल्कि वे **external resources** (आमतौर पर अनुप्रयोगों के **bundle** के अंदर) का भी उपयोग करते हैं। इसलिए, बाइनरी के अंदर कुछ स्लॉट होते हैं जो कुछ दिलचस्प बाहरी संसाधनों के हैश को रखेंगे ताकि यह जांचा जा सके कि उन्हें संशोधित नहीं किया गया है।

वास्तव में, कोड निर्देशिका संरचनाओं में एक पैरामीटर है जिसे **`nSpecialSlots`** कहा जाता है, जो विशेष स्लॉट की संख्या को इंगित करता है। वहाँ विशेष स्लॉट 0 नहीं है और सबसे सामान्य ( -1 से -6 तक) हैं:

- `info.plist` का हैश (या वह जो `__TEXT.__info__plist` के अंदर है)।
- आवश्यकताओं का हैश
- संसाधन निर्देशिका का हैश (बंडल के अंदर `_CodeSignature/CodeResources` फ़ाइल का हैश)।
- अनुप्रयोग विशिष्ट (अप्रयुक्त)
- अधिकारों का हैश
- केवल DMG कोड हस्ताक्षर
- DER अधिकार

## Code Signing Flags

हर प्रक्रिया से संबंधित एक बिटमास्क होता है जिसे `status` के रूप में जाना जाता है जिसे कर्नेल द्वारा शुरू किया जाता है और इनमें से कुछ को **कोड हस्ताक्षर** द्वारा ओवरराइड किया जा सकता है। कोड हस्ताक्षर में शामिल किए जा सकने वाले ये ध्वज [कोड में परिभाषित हैं](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36):
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
ध्यान दें कि फ़ंक्शन [**exec_mach_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_exec.c#L1420) कार्यान्वयन शुरू करते समय `CS_EXEC_*` फ़्लैग को गतिशील रूप से जोड़ सकता है।

## कोड सिग्नेचर आवश्यकताएँ

प्रत्येक एप्लिकेशन कुछ **आवश्यकताएँ** संग्रहीत करता है जिन्हें इसे कार्यान्वित करने के लिए **पूरा करना** आवश्यक है। यदि **एप्लिकेशन में ऐसी आवश्यकताएँ हैं जो एप्लिकेशन द्वारा पूरी नहीं की गई हैं**, तो इसे कार्यान्वित नहीं किया जाएगा (क्योंकि इसे शायद संशोधित किया गया है)।

एक बाइनरी की आवश्यकताएँ एक **विशेष व्याकरण** का उपयोग करती हैं जो **व्यक्तियों** की एक धारा होती है और इन्हें `0xfade0c00` को जादू के रूप में उपयोग करके ब्लॉब के रूप में एन्कोड किया जाता है, जिसका **हैश एक विशेष कोड स्लॉट में संग्रहीत होता है**।

एक बाइनरी की आवश्यकताएँ चलाते समय देखी जा सकती हैं:
```bash
codesign -d -r- /bin/ls
Executable=/bin/ls
designated => identifier "com.apple.ls" and anchor apple

codesign -d -r- /Applications/Signal.app/
Executable=/Applications/Signal.app/Contents/MacOS/Signal
designated => identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR
```
> [!NOTE]
> ध्यान दें कि ये सिग्नेचर चीजों की जांच कर सकते हैं जैसे प्रमाणन जानकारी, TeamID, IDs, अधिकार और कई अन्य डेटा।

इसके अलावा, `csreq` टूल का उपयोग करके कुछ संकलित आवश्यकताएँ उत्पन्न करना संभव है:
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
यह जानकारी प्राप्त करना और `Security.framework` के कुछ APIs के साथ आवश्यकताओं को बनाना या संशोधित करना संभव है जैसे:

#### **वैधता की जांच करना**

- **`Sec[Static]CodeCheckValidity`**: आवश्यकता के अनुसार SecCodeRef की वैधता की जांच करें।
- **`SecRequirementEvaluate`**: प्रमाणपत्र संदर्भ में आवश्यकता को मान्य करें।
- **`SecTaskValidateForRequirement`**: `CFString` आवश्यकता के खिलाफ चल रहे SecTask को मान्य करें।

#### **कोड आवश्यकताओं का निर्माण और प्रबंधन**

- **`SecRequirementCreateWithData`:** आवश्यकता का प्रतिनिधित्व करने वाले बाइनरी डेटा से `SecRequirementRef` बनाता है।
- **`SecRequirementCreateWithString`:** आवश्यकता के स्ट्रिंग अभिव्यक्ति से `SecRequirementRef` बनाता है।
- **`SecRequirementCopy[Data/String]`**: `SecRequirementRef` का बाइनरी डेटा प्रतिनिधित्व प्राप्त करता है।
- **`SecRequirementCreateGroup`**: ऐप-ग्रुप सदस्यता के लिए एक आवश्यकता बनाएं।

#### **कोड साइनिंग जानकारी तक पहुंचना**

- **`SecStaticCodeCreateWithPath`**: कोड सिग्नेचर का निरीक्षण करने के लिए फ़ाइल सिस्टम पथ से `SecStaticCodeRef` ऑब्जेक्ट को प्रारंभ करता है।
- **`SecCodeCopySigningInformation`**: `SecCodeRef` या `SecStaticCodeRef` से साइनिंग जानकारी प्राप्त करता है।

#### **कोड आवश्यकताओं को संशोधित करना**

- **`SecCodeSignerCreate`**: कोड साइनिंग संचालन करने के लिए `SecCodeSignerRef` ऑब्जेक्ट बनाता है।
- **`SecCodeSignerSetRequirement`**: साइनिंग के दौरान लागू करने के लिए कोड साइनर के लिए एक नई आवश्यकता सेट करता है।
- **`SecCodeSignerAddSignature`**: निर्दिष्ट साइनर के साथ साइन किए जा रहे कोड में एक सिग्नेचर जोड़ता है।

#### **आवश्यकताओं के साथ कोड को मान्य करना**

- **`SecStaticCodeCheckValidity`**: निर्दिष्ट आवश्यकताओं के खिलाफ एक स्थिर कोड ऑब्जेक्ट को मान्य करता है।

#### **अतिरिक्त उपयोगी APIs**

- **`SecCodeCopy[Internal/Designated]Requirement`: SecCodeRef से SecRequirementRef प्राप्त करें**
- **`SecCodeCopyGuestWithAttributes`**: विशिष्ट विशेषताओं के आधार पर कोड ऑब्जेक्ट का प्रतिनिधित्व करने वाला `SecCodeRef` बनाता है, जो सैंडबॉक्सिंग के लिए उपयोगी है।
- **`SecCodeCopyPath`**: `SecCodeRef` से संबंधित फ़ाइल सिस्टम पथ प्राप्त करता है।
- **`SecCodeCopySigningIdentifier`**: `SecCodeRef` से साइनिंग पहचानकर्ता (जैसे, टीम आईडी) प्राप्त करता है।
- **`SecCodeGetTypeID`**: `SecCodeRef` ऑब्जेक्ट के लिए प्रकार पहचानकर्ता लौटाता है।
- **`SecRequirementGetTypeID`**: `SecRequirementRef` का CFTypeID प्राप्त करता है।

#### **कोड साइनिंग फ्लैग और स्थिरांक**

- **`kSecCSDefaultFlags`**: कोड साइनिंग संचालन के लिए कई Security.framework कार्यों में उपयोग किए जाने वाले डिफ़ॉल्ट फ्लैग।
- **`kSecCSSigningInformation`**: फ्लैग जो यह निर्दिष्ट करने के लिए उपयोग किया जाता है कि साइनिंग जानकारी प्राप्त की जानी चाहिए।

## कोड सिग्नेचर प्रवर्तन

**कर्नेल** वह है जो **कोड सिग्नेचर की जांच करता है** इससे पहले कि ऐप का कोड निष्पादित हो सके। इसके अलावा, मेमोरी में नए कोड को लिखने और निष्पादित करने के लिए एक तरीका JIT का दुरुपयोग करना है यदि `mprotect` को `MAP_JIT` फ्लैग के साथ कॉल किया जाता है। ध्यान दें कि एप्लिकेशन को ऐसा करने के लिए एक विशेष अधिकार की आवश्यकता होती है।

## `cs_blobs` & `cs_blob`

[**cs_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc_internal.h#L106) संरचना में चल रहे प्रक्रिया के अधिकार के बारे में जानकारी होती है। `csb_platform_binary` यह भी सूचित करता है कि क्या एप्लिकेशन एक प्लेटफ़ॉर्म बाइनरी है (जिसकी जांच OS द्वारा विभिन्न क्षणों में सुरक्षा तंत्र लागू करने के लिए की जाती है जैसे कि इन प्रक्रियाओं के कार्य पोर्ट के लिए SEND अधिकारों की रक्षा करना)।
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
