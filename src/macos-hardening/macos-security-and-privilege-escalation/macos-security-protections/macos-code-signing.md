# Ký mã macOS

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

{{#ref}}
../../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/mach-o-entitlements-and-ipsw-indexing.md
{{#endref}}


Các binary Mach-o chứa một lệnh nạp có tên **`LC_CODE_SIGNATURE`**, cho biết **offset** và **kích thước** của chữ ký bên trong binary. Thực tế, bằng công cụ GUI MachOView, bạn có thể tìm thấy một phần có tên **Code Signature** ở cuối binary, chứa thông tin này:

<figure><img src="../../../images/image (1) (1) (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

Magic header của Code Signature là **`0xFADE0CC0`** (chữ ký mã nhúng) hoặc **`0xFADE0CC1`** (chữ ký mã tách rời). Sau đó là các thông tin như độ dài và số lượng blob trong superBlob chứa chúng.\
Bạn có thể tìm thấy thông tin này trong [mã nguồn tại đây](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L276):<sup>[[1]](#references)</sup>

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

Các blob thường chứa Code Directory, Requirements và Entitlements, cùng với Cryptographic Message Syntax (CMS).\
Ngoài ra, lưu ý rằng dữ liệu được mã hóa trong các blob được mã hóa theo thứ tự **Big Endian.**

Ngoài ra, chữ ký có thể được tách khỏi các tệp nhị phân và lưu trữ trong `/var/db/DetachedSignatures` (được iOS sử dụng).

## Code Directory Blob

Có thể tìm thấy khai báo của [Code Directory Blob trong mã nguồn](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L104):<sup>[[1]](#references)</sup>

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

Lưu ý rằng có nhiều phiên bản khác nhau của struct này, trong đó các phiên bản cũ có thể chứa ít thông tin hơn.

Lưu ý rằng thư mục Code có thể sử dụng bất kỳ thuật toán hashing nào. Hiện tại, thuật toán phổ biến nhất là **SHA256** (được biểu thị bằng giá trị 2 trong trường `hashType`), nhưng trong tương lai, nếu hash này bị phá vỡ, Apple có thể bắt đầu sử dụng thuật toán khác.

## Signing Code Pages

Hashing toàn bộ binary sẽ không hiệu quả, thậm chí vô ích nếu binary chỉ được tải một phần vào bộ nhớ. Vì vậy, code signature thực chất là một hash của các hash, trong đó từng page của binary được hash riêng.\
Trên thực tế, trong đoạn code **Code Directory** ở trên, bạn có thể thấy **kích thước page được chỉ định** trong một trường. Hơn nữa, nếu kích thước của binary không phải là bội số của kích thước page, trường **CodeLimit** sẽ chỉ định điểm kết thúc của signature.

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

Lưu ý rằng các ứng dụng cũng có thể chứa **entitlement blob**, nơi định nghĩa tất cả các entitlements. Ngoài ra, một số binary iOS có thể lưu entitlements trong slot đặc biệt -7 (thay vì slot đặc biệt -5 dành cho entitlements).

## Special Slots

Ứng dụng macOS không chứa mọi thứ cần thiết để thực thi bên trong binary mà còn sử dụng **external resources** (thường nằm trong **bundle** của ứng dụng). Vì vậy, trong binary có một số slot chứa hash của các external resources quan trọng để kiểm tra xem chúng có bị sửa đổi hay không.

Thực tế, trong các struct Code Directory có thể thấy một tham số tên là **`nSpecialSlots`**, cho biết số lượng special slot. Không có special slot 0, và các slot phổ biến nhất (từ -1 đến -6) là:

- Hash của `info.plist` (hoặc tệp nằm trong `__TEXT.__info__plist`).
- Hash của Requirements
- Hash của Resource Directory (hash của tệp `_CodeSignature/CodeResources` bên trong bundle).
- Dành riêng cho ứng dụng (không sử dụng)
- Hash của entitlements
- Chỉ dùng cho chữ ký code của DMG
- DER Entitlements

## Code Signing Flags

Mỗi process có một bitmask liên quan gọi là `status`, được kernel khởi tạo và một số giá trị có thể được **code signature** ghi đè. Các flags có thể được đưa vào code signing này được [định nghĩa trong mã nguồn](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36):<sup>[[1]](#references)</sup>

User space có thể truy vấn hoặc cập nhật các phần được phép của trạng thái này thông qua các thao tác `csops` và `csops_audittoken` do XNU định nghĩa.<sup>[[5]](#references)</sup>

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

Lưu ý rằng hàm [**exec_mach_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_exec.c#L1420) cũng có thể thêm các flag `CS_EXEC_*` một cách động khi bắt đầu thực thi.

## Yêu cầu về chữ ký mã

Mỗi ứng dụng lưu trữ một số **yêu cầu** mà nó phải **đáp ứng** để có thể được thực thi. Nếu **ứng dụng chứa các yêu cầu mà chính nó không đáp ứng**, ứng dụng sẽ không được thực thi (vì có thể nó đã bị chỉnh sửa).

Các yêu cầu của một binary sử dụng **ngữ pháp đặc biệt**, gồm một chuỗi các **biểu thức** và được mã hóa thành các blob bằng cách dùng `0xfade0c00` làm magic; **hash** của giá trị này được lưu trong một code slot đặc biệt.<sup>[[4]](#references)</sup>

Có thể xem các yêu cầu của một binary bằng cách chạy:

```bash
codesign -d -r- /bin/ls
Executable=/bin/ls
designated => identifier "com.apple.ls" and anchor apple

codesign -d -r- /Applications/Signal.app/
Executable=/Applications/Signal.app/Contents/MacOS/Signal
designated => identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR
```

> [!TIP]
> Lưu ý rằng các chữ ký này có thể kiểm tra những thông tin như thông tin chứng chỉ, TeamID, ID, entitlements và nhiều dữ liệu khác.

Ngoài ra, có thể tạo một số compiled requirements bằng công cụ `csreq`:

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

Có thể truy cập thông tin này và tạo hoặc sửa đổi requirement bằng một số API trong `Security.framework` như sau:<sup>[[3]](#references)</sup>

#### **Kiểm tra tính hợp lệ**

- **`Sec[Static]CodeCheckValidity`**: Kiểm tra tính hợp lệ của SecCodeRef theo Requirement.
- **`SecRequirementEvaluate`**: Xác thực requirement trong ngữ cảnh certificate
- **`SecTaskValidateForRequirement`**: Xác thực một SecTask đang chạy theo requirement `CFString`.

#### **Tạo và quản lý Code Requirement**

- **`SecRequirementCreateWithData`:** Tạo `SecRequirementRef` từ dữ liệu nhị phân biểu diễn requirement.
- **`SecRequirementCreateWithString`:** Tạo `SecRequirementRef` từ biểu thức chuỗi của requirement.
- **`SecRequirementCopy[Data/String]`**: Lấy biểu diễn dữ liệu nhị phân của `SecRequirementRef`.
- **`SecRequirementCreateGroup`**: Tạo requirement cho tư cách thành viên app-group

#### **Truy cập thông tin Code Signing**

- **`SecStaticCodeCreateWithPath`**: Khởi tạo đối tượng `SecStaticCodeRef` từ đường dẫn hệ thống tệp để kiểm tra chữ ký mã.
- **`SecCodeCopySigningInformation`**: Lấy thông tin signing từ `SecCodeRef` hoặc `SecStaticCodeRef`.

#### **Sửa đổi Code Requirement**

- **`SecCodeSignerCreate`**: Tạo đối tượng `SecCodeSignerRef` để thực hiện các thao tác code signing.
- **`SecCodeSignerSetRequirement`**: Đặt requirement mới để code signer áp dụng trong quá trình signing.
- **`SecCodeSignerAddSignature`**: Thêm chữ ký vào mã đang được ký bằng signer được chỉ định.

#### **Xác thực mã bằng Requirement**

- **`SecStaticCodeCheckValidity`**: Xác thực đối tượng mã tĩnh theo các requirement được chỉ định.

#### **Các API hữu ích khác**

- **`SecCodeCopy[Internal/Designated]Requirement`: Lấy SecRequirementRef từ SecCodeRef**
- **`SecCodeCopyGuestWithAttributes`**: Tạo `SecCodeRef` đại diện cho một đối tượng mã dựa trên các thuộc tính cụ thể, hữu ích cho sandboxing.
- **`SecCodeCopyPath`**: Lấy đường dẫn hệ thống tệp được liên kết với `SecCodeRef`.
- **`SecCodeCopySigningIdentifier`**: Lấy signing identifier (ví dụ: Team ID) từ `SecCodeRef`.
- **`SecCodeGetTypeID`**: Trả về type identifier cho các đối tượng `SecCodeRef`.
- **`SecRequirementGetTypeID`**: Lấy CFTypeID của `SecRequirementRef`

#### **Các cờ và hằng số Code Signing**

- **`kSecCSDefaultFlags`**: Các cờ mặc định được nhiều hàm `Security.framework` sử dụng cho thao tác code signing.
- **`kSecCSSigningInformation`**: Cờ dùng để chỉ định rằng cần lấy thông tin signing.

## Thực thi Code Signature

**Kernel** là thành phần **kiểm tra code signature** trước khi cho phép mã của ứng dụng thực thi. Ngoài ra, một cách để ghi và thực thi mã mới trong bộ nhớ là lạm dụng JIT nếu `mprotect` được gọi với cờ `MAP_JIT`. Lưu ý rằng ứng dụng cần có entitlement đặc biệt mới làm được điều này.

## `cs_blobs` & `cs_blob`

Struct [**cs_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc_internal.h#L106) chứa thông tin về entitlement của tiến trình đang chạy trên đó. `csb_platform_binary` cũng cho biết ứng dụng có phải là **platform binary** hay không (điều này được OS kiểm tra ở nhiều thời điểm khác nhau để áp dụng các cơ chế bảo mật, chẳng hạn như bảo vệ quyền SEND đối với task port của những tiến trình này).<sup>[[2]](#references)</sup>

> [!WARNING]
> Lưu ý rằng một số biện pháp bảo mật phụ thuộc vào việc binary có phải là platform binary hay không, vì vậy một cách để leo thang đặc quyền là **biến binary thành platform binary** (ví dụ: ký lại nó bằng certificate cho phép điều này).

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

- [1] [XNU — `osfmk/kern/cs_blobs.h` (`CodeDirectory`, cờ `CS_*`, các giá trị magic của blob)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [2] [XNU — `bsd/kern/ubc_subr.c` (xử lý `cs_blob` và xác thực chữ ký)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [3] [Mã nguồn Apple Security framework — `libsecurity_codesigning`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/libsecurity_codesigning)
- [4] [Apple Developer — Hướng dẫn Code Signing](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Introduction/Introduction.html)
- [5] [XNU — `bsd/sys/codesign.h` (các thao tác `csops`/`csops_audittoken`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
{{#include ../../../banners/hacktricks-training.md}}
