# macOS Code Signing

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

{{#ref}}
../../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/mach-o-entitlements-and-ipsw-indexing.md
{{#endref}}


Mach-o 二进制文件包含一个名为 **`LC_CODE_SIGNATURE`** 的加载命令，用于指示二进制文件中签名的**偏移量**和**大小**。实际上，使用 GUI 工具 MachOView，可以在二进制文件末尾找到一个名为 **Code Signature** 的 section，其中包含这些信息：

<figure><img src="../../../images/image (1) (1) (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

Code Signature 的 magic header 是 **`0xFADE0CC0`**（embedded code signature）或 **`0xFADE0CC1`**（detached code signature）。随后可以看到包含这些 blob 的 superBlob 的长度、blob 数量等信息。\
可以在[此处的源代码](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L276)中找到这些信息：<sup>[[1]](#references)</sup>
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
常见的 blob 包含 Code Directory、Requirements 和 Entitlements，以及 Cryptographic Message Syntax (CMS)。\
此外，请注意，blob 中编码的数据采用 **Big Endian** 编码。

此外，签名可以从二进制文件中分离出来，并存储在 `/var/db/DetachedSignatures` 中（iOS 使用）。

## Code Directory Blob

可以在[代码](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L104)中找到 Code Directory Blob 的声明：<sup>[[1]](#references)</sup>
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
请注意，这个 struct 存在不同版本，旧版本可能包含较少的信息。

请注意，Code directory 可以使用任何 hashing algorithm。目前最常见的是 **SHA256**（由字段 `hashType` 中的值 2 表示），但未来如果该 hash 被破解，Apple 可能会开始使用其他 hash。

## Signing Code Pages

对完整 binary 进行 hashing 效率很低；如果 binary 只被部分加载到内存中，这样做甚至没有意义。因此，code signature 实际上是一个 hash 的 hash，其中每个 binary page 都会单独进行 hashing。\
实际上，在前面的 **Code Directory** 代码中可以看到，**page size 已在其中一个字段中指定**。此外，如果 binary 的大小不是 page size 的整数倍，字段 **CodeLimit** 会指定 signature 的结束位置。
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

请注意，应用程序还可能包含一个 **entitlement blob**，其中定义了所有 entitlements。此外，某些 iOS 二进制文件可能会将其 entitlements 存放在特殊槽位 -7 中，而不是 -5 entitlements 特殊槽位中。

## Special Slots

MacOS 应用程序并不会将执行所需的全部内容都包含在二进制文件中，它们还会使用**外部资源**（通常位于应用程序的 **bundle** 内）。因此，二进制文件中存在一些槽位，用于存放某些重要外部资源的哈希值，以检查这些资源是否被修改。

实际上，可以在 Code Directory 结构中看到一个名为 **`nSpecialSlots`** 的参数，它表示特殊槽位的数量。其中不存在特殊槽位 0，最常见的槽位（-1 至 -6）包括：

- `info.plist` 的哈希值（或 `__TEXT.__info__plist` 内部文件的哈希值）。
- Requirements 的哈希值。
- Resource Directory 的哈希值（bundle 内 `_CodeSignature/CodeResources` 文件的哈希值）。
- 应用程序特定内容（未使用）。
- entitlements 的哈希值。
- 仅用于 DMG code signatures。
- DER Entitlements。

## Code Signing Flags

每个进程都有一个相关的位掩码，称为 `status`。该状态由 kernel 设置，其中一些状态可以被 **code signature** 覆盖。这些可包含在 code signing 中的 flags 在[代码](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36)中定义：<sup>[[1]](#references)</sup>

User space 可以通过 XNU 定义的 `csops` 和 `csops_audittoken` 操作，查询或更新该状态中允许修改的部分。<sup>[[5]](#references)</sup>
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
请注意，函数 [**exec_mach_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_exec.c#L1420) 还可以在开始执行时动态添加 `CS_EXEC_*` 标志。

## Code Signature Requirements

每个应用程序都会存储一些 **requirements**，必须 **满足** 这些 requirements 才能执行。如果 **应用程序包含的 requirements 未被应用程序满足**，则不会执行该应用程序（因为它很可能已被篡改）。

二进制文件的 requirements 使用一种**特殊语法**，由一系列**表达式**组成，并被编码为 blobs，使用 `0xfade0c00` 作为 magic，其 **hash 存储在一个特殊的 code slot 中**。<sup>[[4]](#references)</sup>

可以通过运行以下命令查看二进制文件的 requirements：
```bash
codesign -d -r- /bin/ls
Executable=/bin/ls
designated => identifier "com.apple.ls" and anchor apple

codesign -d -r- /Applications/Signal.app/
Executable=/Applications/Signal.app/Contents/MacOS/Signal
designated => identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR
```
> [!TIP]
> 注意，这些签名可以检查证书信息、TeamID、ID、entitlements 以及许多其他数据。

此外，还可以使用 `csreq` 工具生成一些已编译的 requirements：
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
可以通过 `Security.framework` 中的一些 API 访问这些信息，并创建或修改 requirements，例如：<sup>[[3]](#references)</sup>

#### **检查有效性**

- **`Sec[Static]CodeCheckValidity`**：根据 Requirement 检查 SecCodeRef 的有效性。
- **`SecRequirementEvaluate`**：在证书上下文中验证 requirement。
- **`SecTaskValidateForRequirement`**：根据 `CFString` requirement 验证正在运行的 SecTask。

#### **创建和管理 Code Requirements**

- **`SecRequirementCreateWithData`：**从表示 requirement 的二进制数据创建 `SecRequirementRef`。
- **`SecRequirementCreateWithString`：**从 requirement 的字符串表达式创建 `SecRequirementRef`。
- **`SecRequirementCopy[Data/String]`**：获取 `SecRequirementRef` 的二进制数据表示。
- **`SecRequirementCreateGroup`**：为 app-group membership 创建 requirement。

#### **访问 Code Signing 信息**

- **`SecStaticCodeCreateWithPath`**：根据文件系统路径初始化 `SecStaticCodeRef` 对象，用于检查 code signatures。
- **`SecCodeCopySigningInformation`**：从 `SecCodeRef` 或 `SecStaticCodeRef` 获取 signing 信息。

#### **修改 Code Requirements**

- **`SecCodeSignerCreate`**：创建用于执行 code signing 操作的 `SecCodeSignerRef` 对象。
- **`SecCodeSignerSetRequirement`**：为 code signer 设置新的 requirement，以便在 signing 期间应用。
- **`SecCodeSignerAddSignature`**：使用指定的 signer 为正在签名的 code 添加 signature。

#### **使用 Requirements 验证 Code**

- **`SecStaticCodeCheckValidity`**：根据指定的 requirements 验证 static code 对象。

#### **其他有用的 API**

- **`SecCodeCopy[Internal/Designated]Requirement`**：从 SecCodeRef 获取 SecRequirementRef。
- **`SecCodeCopyGuestWithAttributes`**：根据特定 attributes 创建表示 code 对象的 `SecCodeRef`，对 sandboxing 很有用。
- **`SecCodeCopyPath`**：获取与 `SecCodeRef` 关联的文件系统路径。
- **`SecCodeCopySigningIdentifier`**：从 `SecCodeRef` 获取 signing identifier（例如 Team ID）。
- **`SecCodeGetTypeID`**：返回 `SecCodeRef` 对象的类型标识符。
- **`SecRequirementGetTypeID`**：获取 `SecRequirementRef` 的 CFTypeID。

#### **Code Signing Flags 和 Constants**

- **`kSecCSDefaultFlags`**：许多用于 code signing 操作的 Security.framework 函数所使用的默认 flags。
- **`kSecCSSigningInformation`**：用于指定应获取 signing 信息的 flag。

## Code Signature Enforcement

**kernel** 会在允许 app 的 code 执行前**检查 code signature**。此外，如果使用 `MAP_JIT` flag 调用 `mprotect`，abusing JIT 是一种能够在内存中写入并执行新 code 的方式。请注意，application 需要特殊的 entitlement 才能执行此操作。

## `cs_blobs` & `cs_blob`

[**cs_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc_internal.h#L106) struct 包含运行中 process 的 entitlement 信息。`csb_platform_binary` 还会说明 application 是否为 **platform binary**（OS 会在不同时间检查这一点，以应用各种 security mechanisms，例如保护这些 process 的 task ports 的 SEND rights）。<sup>[[2]](#references)</sup>

> [!WARNING]
> 请注意，多项 security measures 取决于 binary 是否为 platform binary，因此一种 privilege escalation 方法是**让 binary 成为 platform binary**（例如，使用允许这样做的 certificate 对其重新 signing）。
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

- [1] [XNU — `osfmk/kern/cs_blobs.h`（`CodeDirectory`、`CS_*` 标志、blob magic 值）](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [2] [XNU — `bsd/kern/ubc_subr.c`（`cs_blob` 处理和签名验证）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [3] [Apple Security framework 源码 — `libsecurity_codesigning`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/libsecurity_codesigning)
- [4] [Apple Developer — 代码签名指南](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Introduction/Introduction.html)
- [5] [XNU — `bsd/sys/codesign.h`（`csops`/`csops_audittoken` 操作）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
{{#include ../../../banners/hacktricks-training.md}}
