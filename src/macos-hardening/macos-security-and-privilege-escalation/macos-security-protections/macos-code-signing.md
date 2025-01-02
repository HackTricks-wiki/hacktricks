# macOS 코드 서명

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

Mach-o 바이너리는 바이너리 내부의 서명의 **오프셋**과 **크기**를 나타내는 **`LC_CODE_SIGNATURE`**라는 로드 명령을 포함합니다. 실제로 GUI 도구인 MachOView를 사용하면 바이너리의 끝에서 이 정보를 포함하는 **Code Signature**라는 섹션을 찾을 수 있습니다:

<figure><img src="../../../images/image (1) (1) (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

코드 서명의 매직 헤더는 **`0xFADE0CC0`**입니다. 그런 다음 이들을 포함하는 superBlob의 길이와 블롭 수와 같은 정보가 있습니다.\
이 정보는 [소스 코드 여기](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L276)에서 찾을 수 있습니다:
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
일반적으로 포함된 블롭은 Code Directory, Requirements 및 Entitlements와 Cryptographic Message Syntax (CMS)입니다.\
또한, 블롭에 인코딩된 데이터가 **Big Endian**으로 인코딩되어 있음을 주목하십시오.

또한, 서명은 이진 파일에서 분리되어 `/var/db/DetachedSignatures`에 저장될 수 있습니다 (iOS에서 사용됨).

## Code Directory Blob

[Code Directory Blob의 선언을 코드에서 찾는 것이 가능합니다](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L104):
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
다양한 버전의 이 구조체가 있으며, 이전 버전은 정보가 적을 수 있습니다.

## 코드 서명 페이지

전체 바이너리를 해싱하는 것은 비효율적이며, 메모리에 부분적으로만 로드될 경우에는 심지어 쓸모가 없습니다. 따라서 코드 서명은 실제로 각 바이너리 페이지가 개별적으로 해싱된 해시의 해시입니다.\
실제로 이전 **코드 디렉토리** 코드에서 **페이지 크기가 지정되어** 있는 것을 볼 수 있습니다. 또한, 바이너리의 크기가 페이지 크기의 배수가 아닌 경우, 필드 **CodeLimit**는 서명의 끝이 어디인지 지정합니다.
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

응용 프로그램에는 모든 권한이 정의된 **entitlement blob**이 포함될 수 있습니다. 또한 일부 iOS 바이너리는 특별 슬롯 -7에 권한이 특정되어 있을 수 있습니다(대신 -5 권한 특별 슬롯에).

## Special Slots

MacOS 응용 프로그램은 바이너리 내에서 실행하는 데 필요한 모든 것을 갖추고 있지 않지만 **외부 리소스**(일반적으로 응용 프로그램의 **bundle** 내)에 의존합니다. 따라서 바이너리 내에는 수정되지 않았는지 확인하기 위해 일부 흥미로운 외부 리소스의 해시를 포함하는 슬롯이 있습니다.

실제로, Code Directory 구조체에서 **`nSpecialSlots`**라는 매개변수를 볼 수 있으며, 이는 특별 슬롯의 수를 나타냅니다. 특별 슬롯 0은 없으며 가장 일반적인 슬롯( -1에서 -6까지)은 다음과 같습니다:

- `info.plist`의 해시(또는 `__TEXT.__info__plist` 내의 것).
- 요구 사항의 해시
- 리소스 디렉토리의 해시(번들 내의 `_CodeSignature/CodeResources` 파일의 해시).
- 응용 프로그램 특정(사용되지 않음)
- 권한의 해시
- DMG 코드 서명 전용
- DER 권한

## Code Signing Flags

모든 프로세스에는 `status`로 알려진 비트마스크가 관련되어 있으며, 이는 커널에 의해 시작되며 일부는 **코드 서명**에 의해 재정의될 수 있습니다. 코드 서명에 포함될 수 있는 이러한 플래그는 [코드에서 정의되어 있습니다](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36):
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
Note that the function [**exec_mach_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_exec.c#L1420) can also add the `CS_EXEC_*` flags dynamically when starting the execution.

## 코드 서명 요구 사항

각 애플리케이션은 실행될 수 있도록 **충족해야 하는** **요구 사항**을 저장합니다. **애플리케이션이 충족하지 않는 요구 사항을 포함하는 경우**, 애플리케이션은 실행되지 않습니다(변경되었을 가능성이 높기 때문입니다).

바이너리의 요구 사항은 **특별한 문법**을 사용하며, 이는 **표현식**의 흐름으로 `0xfade0c00`을 매직으로 사용하여 블롭으로 인코딩됩니다. 이 **해시는 특별한 코드 슬롯에 저장됩니다**.

바이너리의 요구 사항은 다음을 실행하여 확인할 수 있습니다:
```bash
codesign -d -r- /bin/ls
Executable=/bin/ls
designated => identifier "com.apple.ls" and anchor apple

codesign -d -r- /Applications/Signal.app/
Executable=/Applications/Signal.app/Contents/MacOS/Signal
designated => identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR
```
> [!NOTE]
> 이 서명이 인증 정보, TeamID, ID, 권한 및 기타 많은 데이터를 확인할 수 있는 방법에 주목하세요.

또한, `csreq` 도구를 사용하여 일부 컴파일된 요구 사항을 생성하는 것이 가능합니다:
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

#### **유효성 검사**

- **`Sec[Static]CodeCheckValidity`**: 요구 사항에 따라 SecCodeRef의 유효성을 검사합니다.
- **`SecRequirementEvaluate`**: 인증서 컨텍스트에서 요구 사항을 검증합니다.
- **`SecTaskValidateForRequirement`**: `CFString` 요구 사항에 대해 실행 중인 SecTask를 검증합니다.

#### **코드 요구 사항 생성 및 관리**

- **`SecRequirementCreateWithData`:** 요구 사항을 나타내는 이진 데이터에서 `SecRequirementRef`를 생성합니다.
- **`SecRequirementCreateWithString`:** 요구 사항의 문자열 표현에서 `SecRequirementRef`를 생성합니다.
- **`SecRequirementCopy[Data/String]`**: `SecRequirementRef`의 이진 데이터 표현을 검색합니다.
- **`SecRequirementCreateGroup`**: 앱 그룹 멤버십에 대한 요구 사항을 생성합니다.

#### **코드 서명 정보 접근**

- **`SecStaticCodeCreateWithPath`**: 코드 서명을 검사하기 위해 파일 시스템 경로에서 `SecStaticCodeRef` 객체를 초기화합니다.
- **`SecCodeCopySigningInformation`**: `SecCodeRef` 또는 `SecStaticCodeRef`에서 서명 정보를 얻습니다.

#### **코드 요구 사항 수정**

- **`SecCodeSignerCreate`**: 코드 서명 작업을 수행하기 위한 `SecCodeSignerRef` 객체를 생성합니다.
- **`SecCodeSignerSetRequirement`**: 서명 중에 적용할 코드 서명자에 대한 새로운 요구 사항을 설정합니다.
- **`SecCodeSignerAddSignature`**: 지정된 서명자로 서명되는 코드에 서명을 추가합니다.

#### **요구 사항으로 코드 검증**

- **`SecStaticCodeCheckValidity`**: 지정된 요구 사항에 대해 정적 코드 객체를 검증합니다.

#### **추가 유용한 API**

- **`SecCodeCopy[Internal/Designated]Requirement`: SecCodeRef에서 SecRequirementRef 가져오기**
- **`SecCodeCopyGuestWithAttributes`**: 특정 속성을 기반으로 하는 코드 객체를 나타내는 `SecCodeRef`를 생성하며, 샌드박싱에 유용합니다.
- **`SecCodeCopyPath`**: `SecCodeRef`와 관련된 파일 시스템 경로를 검색합니다.
- **`SecCodeCopySigningIdentifier`**: `SecCodeRef`에서 서명 식별자(예: 팀 ID)를 얻습니다.
- **`SecCodeGetTypeID`**: `SecCodeRef` 객체에 대한 유형 식별자를 반환합니다.
- **`SecRequirementGetTypeID`**: `SecRequirementRef`의 CFTypeID를 가져옵니다.

#### **코드 서명 플래그 및 상수**

- **`kSecCSDefaultFlags`**: 코드 서명 작업을 위한 많은 Security.framework 함수에서 사용되는 기본 플래그입니다.
- **`kSecCSSigningInformation`**: 서명 정보를 검색해야 함을 지정하는 데 사용되는 플래그입니다.

## 코드 서명 강제 적용

**커널**은 앱의 코드가 실행되기 전에 **코드 서명**을 **검사**합니다. 또한, 메모리에 새로운 코드를 작성하고 실행할 수 있는 한 가지 방법은 `mprotect`가 `MAP_JIT` 플래그와 함께 호출될 때 JIT를 악용하는 것입니다. 이 작업을 수행하려면 애플리케이션에 특별한 권한이 필요합니다.

## `cs_blobs` & `cs_blob`

[**cs_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc_internal.h#L106) 구조체는 실행 중인 프로세스의 권한에 대한 정보를 포함합니다. `csb_platform_binary`는 애플리케이션이 플랫폼 이진 파일인지 여부도 알려줍니다(이는 보안 메커니즘을 적용하기 위해 OS에 의해 여러 순간에 확인됩니다. 예를 들어 이러한 프로세스의 작업 포트에 대한 SEND 권한을 보호하는 것입니다).
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

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
