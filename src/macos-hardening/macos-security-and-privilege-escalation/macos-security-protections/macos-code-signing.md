# macOS Code Signing

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

{{#ref}}
../../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/mach-o-entitlements-and-ipsw-indexing.md
{{#endref}}


Mach-o 바이너리에는 바이너리 내부 signature의 **`offset`**과 **`size`**를 나타내는 **`LC_CODE_SIGNATURE`**라는 load command가 포함되어 있습니다. 실제로 GUI tool인 MachOView를 사용하면 바이너리의 끝부분에서 다음 정보가 포함된 **Code Signature**라는 section을 확인할 수 있습니다:

<figure><img src="../../../images/image (1) (1) (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

Code Signature의 magic header는 **`0xFADE0CC0`**(embedded code signature) 또는 **`0xFADE0CC1`**(detached code signature)입니다. 그런 다음 해당 signature를 포함하는 superBlob의 length 및 blob 개수와 같은 정보를 확인할 수 있습니다.\
이 정보는 [source code here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L276)에서 확인할 수 있습니다:<sup>[[1]](#references)</sup>
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
일반적으로 포함되는 blob은 Code Directory, Requirements 및 Entitlements, 그리고 Cryptographic Message Syntax(CMS)입니다.\
또한 blob에 인코딩된 데이터가 **Big Endian**으로 인코딩된다는 점에 유의하세요.

또한 signatures는 바이너리에서 분리되어 `/var/db/DetachedSignatures`에 저장될 수 있습니다(iOS에서 사용됨).

## Code Directory Blob

[Code Directory Blob의 선언은 code에서 확인할 수 있습니다](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L104):<sup>[[1]](#references)</sup>
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
이 struct에는 여러 버전이 있으며, 이전 버전에는 정보가 더 적을 수 있다는 점에 유의하세요.

Code directory에서는 어떤 hashing algorithm이든 사용할 수 있습니다. 현재 가장 일반적인 것은 **SHA256**이며, 이는 `hashType` 필드의 값 2로 표시됩니다. 하지만 향후 이 hash가 깨질 경우 Apple은 다른 hash를 사용하기 시작할 수 있습니다.

## Signing Code Pages

전체 binary를 hashing하는 것은 비효율적이며, binary가 메모리에 부분적으로만 로드되는 경우에는 쓸모가 없습니다. 따라서 code signature는 실제로 각 binary page를 개별적으로 hashing한 hash들의 hash입니다.\
실제로 앞의 **Code Directory** code에서 **page size가 지정되어 있음**을 해당 필드 중 하나에서 확인할 수 있습니다. 또한 binary의 크기가 page 크기의 배수가 아닌 경우, **CodeLimit** 필드가 signature의 끝나는 위치를 지정합니다.
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

애플리케이션에는 모든 entitlements가 정의된 **entitlement blob**도 포함될 수 있습니다. 또한 일부 iOS 바이너리는 entitlements를 -5 entitlements special slot이 아니라 특수 슬롯 -7에 지정할 수 있습니다.

## Special Slots

MacOS 애플리케이션은 실행에 필요한 모든 항목을 바이너리 내부에 포함하지 않으며, **외부 리소스**(일반적으로 애플리케이션 **bundle** 내부)도 사용합니다. 따라서 바이너리 내부에는 일부 중요한 외부 리소스의 해시를 포함하는 슬롯이 있으며, 이를 통해 해당 리소스가 수정되지 않았는지 확인합니다.

실제로 Code Directory structs에서 특수 슬롯의 개수를 나타내는 **`nSpecialSlots`**라는 parameter를 확인할 수 있습니다. 특수 슬롯 0은 존재하지 않으며, 가장 일반적인 슬롯(-1부터 -6까지)은 다음과 같습니다.

- `info.plist`의 해시(또는 `__TEXT.__info__plist` 내부에 있는 plist의 해시)
- Requirements의 해시
- Resource Directory의 해시(bundle 내부 `_CodeSignature/CodeResources` 파일의 해시)
- Application specific (unused)
- entitlements의 해시
- DMG code signatures only
- DER Entitlements

## Code Signing Flags

모든 process에는 `status`라는 bitmask가 연결되어 있으며, 이 값은 kernel에 의해 설정되고 일부는 **code signature**로 재정의될 수 있습니다. Code signing에 포함할 수 있는 이러한 flags는 [code에 정의되어 있습니다](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36):<sup>[[1]](#references)</sup>

User space는 XNU에 정의된 `csops` 및 `csops_audittoken` operations를 통해 이 state에서 허용된 부분을 조회하거나 업데이트할 수 있습니다.<sup>[[5]](#references)</sup>
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
참고로 [**exec_mach_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_exec.c#L1420) 함수는 실행을 시작할 때 `CS_EXEC_*` flags를 동적으로 추가할 수도 있습니다.

## Code Signature Requirements

각 application은 실행될 수 있으려면 **충족해야 하는 requirements**를 저장합니다. **application에 포함된 requirements가 application에 의해 충족되지 않으면**, 해당 application은 실행되지 않습니다(변조되었을 가능성이 높기 때문입니다).

바이너리의 requirements는 **expressions**의 stream으로 구성된 **특수 grammar**를 사용하며, `0xfade0c00`을 magic으로 사용해 blobs로 인코딩되고, 해당 **hash는 특수 code slot에 저장됩니다**.<sup>[[4]](#references)</sup>

바이너리의 requirements는 다음 명령을 실행하여 확인할 수 있습니다:
```bash
codesign -d -r- /bin/ls
Executable=/bin/ls
designated => identifier "com.apple.ls" and anchor apple

codesign -d -r- /Applications/Signal.app/
Executable=/Applications/Signal.app/Contents/MacOS/Signal
designated => identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR
```
> [!TIP]
> 이러한 signature는 인증서 정보, TeamID, ID, entitlements 및 기타 여러 데이터와 같은 항목을 확인할 수 있다는 점에 유의하세요.

또한 `csreq` tool을 사용하여 일부 compiled requirements를 생성할 수 있습니다:
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
이 정보에 액세스하고 다음과 같은 `Security.framework`의 일부 API를 사용하여 requirements를 생성하거나 수정할 수 있습니다:<sup>[[3]](#references)</sup>

#### **Validity 확인**

- **`Sec[Static]CodeCheckValidity`**: Requirement에 따라 SecCodeRef의 validity를 확인합니다.
- **`SecRequirementEvaluate`**: certificate context에서 requirement를 검증합니다.
- **`SecTaskValidateForRequirement`**: 실행 중인 SecTask를 `CFString` requirement에 대해 검증합니다.

#### **Code Requirements 생성 및 관리**

- **`SecRequirementCreateWithData`:** requirement를 나타내는 binary data에서 `SecRequirementRef`를 생성합니다.
- **`SecRequirementCreateWithString`:** requirement의 string expression에서 `SecRequirementRef`를 생성합니다.
- **`SecRequirementCopy[Data/String]`**: `SecRequirementRef`의 binary data representation을 가져옵니다.
- **`SecRequirementCreateGroup`**: app-group membership를 위한 requirement를 생성합니다.

#### **Code Signing 정보 액세스**

- **`SecStaticCodeCreateWithPath`**: code signature를 검사하기 위해 file system path에서 `SecStaticCodeRef` object를 초기화합니다.
- **`SecCodeCopySigningInformation`**: `SecCodeRef` 또는 `SecStaticCodeRef`에서 signing 정보를 가져옵니다.

#### **Code Requirements 수정**

- **`SecCodeSignerCreate`**: code signing 작업을 수행하기 위한 `SecCodeSignerRef` object를 생성합니다.
- **`SecCodeSignerSetRequirement`**: signing 중 code signer가 적용할 새 requirement를 설정합니다.
- **`SecCodeSignerAddSignature`**: 지정된 signer를 사용하여 signing 중인 code에 signature를 추가합니다.

#### **Requirements를 사용한 Code 검증**

- **`SecStaticCodeCheckValidity`**: static code object를 지정된 requirements에 대해 검증합니다.

#### **추가로 유용한 API**

- **`SecCodeCopy[Internal/Designated]Requirement`:** SecCodeRef에서 SecRequirementRef를 가져옵니다.
- **`SecCodeCopyGuestWithAttributes`**: 특정 attributes를 기반으로 code object를 나타내는 `SecCodeRef`를 생성하며, sandboxing에 유용합니다.
- **`SecCodeCopyPath`**: `SecCodeRef`와 연결된 file system path를 가져옵니다.
- **`SecCodeCopySigningIdentifier`**: `SecCodeRef`에서 signing identifier(예: Team ID)를 가져옵니다.
- **`SecCodeGetTypeID`**: `SecCodeRef` object의 type identifier를 반환합니다.
- **`SecRequirementGetTypeID`**: `SecRequirementRef`의 CFTypeID를 가져옵니다.

#### **Code Signing Flags 및 Constants**

- **`kSecCSDefaultFlags`**: code signing 작업을 위한 여러 Security.framework 함수에서 사용되는 기본 flags입니다.
- **`kSecCSSigningInformation`**: signing 정보를 가져와야 함을 지정하는 flag입니다.

## Code Signature Enforcement

**kernel**은 app의 code가 실행되도록 허용하기 전에 **code signature를 확인**합니다. 또한 memory에 새로운 code를 작성하고 실행할 수 있는 한 가지 방법은 `mprotect`가 `MAP_JIT` flag와 함께 호출될 때 JIT를 abuse하는 것입니다. 이를 수행하려면 application에 특별한 entitlement가 필요합니다.

## `cs_blobs` & `cs_blob`

[**cs_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc_internal.h#L106) struct에는 실행 중인 process의 entitlement 정보가 포함되어 있습니다. `csb_platform_binary`는 application이 **platform binary**인지도 알려줍니다. 이는 OS가 이러한 process의 task port에 대한 SEND rights를 보호하는 등의 security mechanisms를 적용하기 위해 여러 시점에 확인합니다.<sup>[[2]](#references)</sup>

> [!WARNING]
> 여러 security measures는 binary가 platform binary인지에 따라 달라집니다. 따라서 privileges를 escalate하는 한 가지 방법은 **binary를 platform binary로 만드는 것**입니다(예: 이를 허용하는 certificate로 re-signing하는 방법).
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

- [1] [XNU — `osfmk/kern/cs_blobs.h` (`CodeDirectory`, `CS_*` 플래그, blob 매직 값)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [2] [XNU — `bsd/kern/ubc_subr.c` (`cs_blob` 처리 및 서명 검증)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [3] [Apple Security framework 소스 — `libsecurity_codesigning`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/libsecurity_codesigning)
- [4] [Apple Developer — 코드 서명 가이드](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Introduction/Introduction.html)
- [5] [XNU — `bsd/sys/codesign.h` (`csops`/`csops_audittoken` 작업)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
{{#include ../../../banners/hacktricks-training.md}}
