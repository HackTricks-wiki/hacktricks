# macOS 代码签名

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

{{#ref}}
../../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/mach-o-entitlements-and-ipsw-indexing.md
{{#endref}}


Mach-o 二进制包含一个名为 **`LC_CODE_SIGNATURE`** 的 load command，指示二进制中签名的 **offset** 和 **size**。事实上，使用 GUI 工具 MachOView，可以在二进制末尾找到一个名为 **Code Signature** 的区段，其中包含这些信息：

<figure><img src="../../../images/image (1) (1) (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

Code Signature 的 magic header 是 **`0xFADE0CC0`**。然后你会看到诸如 length 和 superBlob 中包含它们的 blobs 数量等信息。\
可以在 [source code here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L276) 中找到这些信息：
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
常见的 blobs 包括 Code Directory、Requirements 和 Entitlements，以及 Cryptographic Message Syntax (CMS).\
此外，请注意 blobs 中的数据是以 **Big Endian.** 编码的。

此外，签名可以从二进制文件中分离并存储在 `/var/db/DetachedSignatures`（iOS 使用）。

## Code Directory Blob

可以在代码中找到 [Code Directory Blob in the code](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L104):
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
注意该 struct 有不同版本，旧版本可能包含较少信息。

## 签名代码页

对整个二进制文件进行哈希既低效，在只部分加载到内存时甚至无用。因此，代码签名实际上是哈希的哈希，每个二进制页面分别进行哈希。\  
实际上，在前面的 **Code Directory** 代码中，你可以看到 **页面大小在其字段之一中指定**。此外，如果二进制的大小不是页面大小的整数倍，字段 **CodeLimit** 指定了签名的结束位置。
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
## 权限 blob

注意，应用程序可能还包含一个定义了所有权限的**权限 blob**。此外，一些 iOS 二进制文件可能会把它们的权限放在特殊槽位 -7（而不是常见的 -5 entitlements 特殊槽位）。

## 特殊槽位

MacOS 应用并非把执行所需的所有内容都包含在二进制内，它们也使用 **external resources**（通常位于应用的 **bundle** 内）。因此，二进制中存在一些槽位，用于存放某些重要外部资源的哈希，以便验证它们未被修改。

事实上，可以在 Code Directory 结构体中看到一个名为 **`nSpecialSlots`** 的参数，用来指示特殊槽位的数量。注意没有特殊槽位 0，最常见的槽位是（从 -1 到 -6）：

- `info.plist` 的哈希（或位于 `__TEXT.__info__plist` 中的那个）。
- Requirements 的哈希
- 资源目录的哈希（位于 bundle 内的 `_CodeSignature/CodeResources` 文件的哈希）。
- 应用程序特定（未使用）
- 权限的哈希
- 仅针对 DMG 的代码签名
- DER 权限

## 代码签名标志

每个进程都有一个关联的位掩码，称为 `status`，由内核设置，其中一些位可以被**代码签名**覆盖。这些可以包含在代码签名中的标志在代码中有定义： [defined in the code](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36):
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
注意函数 [**exec_mach_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_exec.c#L1420) 在启动执行时也可以动态添加 `CS_EXEC_*` 标志。

## 代码签名要求

每个应用会存储一些必须**满足**的**要求**，以便能够被执行。如果应用包含的这些**要求**没有被满足，应用将不会被执行（因为它可能已被篡改）。

二进制的这些要求使用一种**特殊语法**，是由一系列**表达式**组成，并以 blob 的形式编码，使用 `0xfade0c00` 作为魔数，其**哈希存储在一个特殊的 code slot 中**。

可以通过运行以下命令查看二进制的要求：
```bash
codesign -d -r- /bin/ls
Executable=/bin/ls
designated => identifier "com.apple.ls" and anchor apple

codesign -d -r- /Applications/Signal.app/
Executable=/Applications/Signal.app/Contents/MacOS/Signal
designated => identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR
```
> [!TIP]
> 注意这些签名如何检查诸如证书信息、TeamID、IDs、entitlements 等多种数据。

此外，可以使用 `csreq` 工具生成一些已编译的 requirements：
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
可以通过 `Security.framework` 的一些 API 访问这些信息并创建或修改要求，如：

#### **检查有效性**

- **`Sec[Static]CodeCheckValidity`**：根据要求检查 SecCodeRef 的有效性。
- **`SecRequirementEvaluate`**：在证书上下文中验证要求。
- **`SecTaskValidateForRequirement`**：根据 `CFString` 要求验证正在运行的 SecTask。

#### **创建和管理代码要求**

- **`SecRequirementCreateWithData`:** 从表示要求的二进制数据创建 `SecRequirementRef`。
- **`SecRequirementCreateWithString`:** 从要求的字符串表达式创建 `SecRequirementRef`。
- **`SecRequirementCopy[Data/String]`**: 检索 `SecRequirementRef` 的二进制数据表示。
- **`SecRequirementCreateGroup`**: 为 app-group 成员资格创建要求

#### **访问代码签名信息**

- **`SecStaticCodeCreateWithPath`**: 从文件系统路径初始化 `SecStaticCodeRef` 对象以检查代码签名。
- **`SecCodeCopySigningInformation`**: 从 `SecCodeRef` 或 `SecStaticCodeRef` 获取签名信息。

#### **修改代码要求**

- **`SecCodeSignerCreate`**: 创建用于执行代码签名操作的 `SecCodeSignerRef` 对象。
- **`SecCodeSignerSetRequirement`**: 为签名器设置在签名期间应用的新要求。
- **`SecCodeSignerAddSignature`**: 使用指定签名器向正在签名的代码添加签名。

#### **使用要求验证代码**

- **`SecStaticCodeCheckValidity`**: 根据指定要求验证静态代码对象。

#### **其他有用的 APIs**

- **`SecCodeCopy[Internal/Designated]Requirement`: Get SecRequirementRef from SecCodeRef**
- **`SecCodeCopyGuestWithAttributes`**: 基于特定属性创建表示代码对象的 `SecCodeRef`，可用于沙箱化。
- **`SecCodeCopyPath`**: 检索与 `SecCodeRef` 关联的文件系统路径。
- **`SecCodeCopySigningIdentifier`**: 从 `SecCodeRef` 获取签名标识符（例如 Team ID）。
- **`SecCodeGetTypeID`**: 返回 `SecCodeRef` 对象的类型标识符。
- **`SecRequirementGetTypeID`**: 获取 `SecRequirementRef` 的 CFTypeID

#### **代码签名标志和常量**

- **`kSecCSDefaultFlags`**: 在许多 `Security.framework` 函数中用于代码签名操作的默认标志。
- **`kSecCSSigningInformation`**: 用于指定应检索签名信息的标志。

## 代码签名强制

内核负责在允许应用代码执行之前检查代码签名。此外，如果 `mprotect` 使用 `MAP_JIT` 标志被调用，滥用 JIT 是在内存中写入并执行新代码的一种方式。注意，应用需要特殊的 entitlement 才能这样做。

## `cs_blobs` & `cs_blob`

[**cs_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc_internal.h#L106) 结构包含关于运行进程 entitlement 的信息。`csb_platform_binary` 还表明应用是否为 platform binary（操作系统在不同阶段检查该标志以应用安全机制，例如保护这些进程的任务端口的 SEND 权限）。
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
## 参考资料

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
