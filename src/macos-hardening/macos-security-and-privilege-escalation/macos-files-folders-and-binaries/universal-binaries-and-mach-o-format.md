# Binary universal macOS & định dạng Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

macOS sử dụng định dạng executable **Mach-O**. Một binary **universal**, hay binary fat, chứa nhiều slice Mach-O dành riêng cho từng kiến trúc trong cùng một file. Các header mã nguồn mở `fat.h` và `loader.h` của Apple định nghĩa các cấu trúc và hằng số được mô tả trên trang này. <sup>[[5]](#references)</sup>

Một Mach-O image gồm:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Tìm file bằng lệnh: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* number of structs that follow */
</strong>};

struct fat_arch {
	cpu_type_t	cputype;	/* cpu specifier (int) */
	cpu_subtype_t	cpusubtype;	/* machine specifier (int) */
	uint32_t	offset;		/* file offset to this object file */
	uint32_t	size;		/* size of this object file */
	uint32_t	align;		/* alignment as a power of 2 */
};
</code></pre>

Header có các byte **magic**, theo sau là **số lượng** **kiến trúc** mà file **chứa** (`nfat_arch`); mỗi kiến trúc sẽ có một struct `fat_arch`.

Kiểm tra bằng lệnh:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (for architecture x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (for architecture arm64e):	Mach-O 64-bit executable arm64e

% otool -f -v /bin/ls
Fat headers
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>architecture x86_64
</strong>    cputype CPU_TYPE_X86_64
    cpusubtype CPU_SUBTYPE_X86_64_ALL
    capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>architecture arm64e
</strong>    cputype CPU_TYPE_ARM64
    cpusubtype CPU_SUBTYPE_ARM64E
    capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

hoặc dùng công cụ [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Như bạn có thể đoán, binary universal được biên dịch cho 2 kiến trúc thường có **kích thước gấp đôi** binary chỉ được biên dịch cho 1 kiến trúc.

> [!TIP]
> Khi phân loại malware hoặc ứng dụng đáng ngờ, đừng dừng lại sau khi `file` báo kiến trúc "phù hợp nhất". Binary universal có thể ẩn các imports, load commands hoặc metadata của compiler khác nhau trong từng slice; vì vậy, trước tiên hãy liệt kê **tất cả** các slice, sau đó kiểm tra từng slice riêng biệt:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Các macOS SDK gần đây cũng cung cấp các helper như `macho_for_each_slice()` và `macho_best_slice()` trong `<mach-o/utils.h>`. Hàm thứ hai hữu ích để mô phỏng những gì dyld/kernel sẽ tải, nhưng các scanner vẫn nên duyệt qua mọi slice để tránh bỏ sót nội dung đặc thù theo kiến trúc.<sup>[[1]](#references)</sup>

## **Header Mach-O**

Header chứa thông tin cơ bản về tệp, chẳng hạn như các byte magic để nhận diện đây là tệp Mach-O và thông tin về kiến trúc đích. Bạn có thể tìm thấy nó bằng lệnh: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

```c
#define	MH_MAGIC	0xfeedface	/* the mach magic number */
#define MH_CIGAM	0xcefaedfe	/* NXSwapInt(MH_MAGIC) */
struct mach_header {
	uint32_t	magic;		/* mach magic number identifier */
	cpu_type_t	cputype;	/* cpu specifier (e.g. I386) */
	cpu_subtype_t	cpusubtype;	/* machine specifier */
	uint32_t	filetype;	/* type of file (usage and alignment for the file) */
	uint32_t	ncmds;		/* number of load commands */
	uint32_t	sizeofcmds;	/* the size of all the load commands */
	uint32_t	flags;		/* flags */
};

#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */
struct mach_header_64 {
	uint32_t	magic;		/* mach magic number identifier */
	int32_t		cputype;	/* cpu specifier */
	int32_t		cpusubtype;	/* machine specifier */
	uint32_t	filetype;	/* type of file */
	uint32_t	ncmds;		/* number of load commands */
	uint32_t	sizeofcmds;	/* the size of all the load commands */
	uint32_t	flags;		/* flags */
	uint32_t	reserved;	/* reserved */
};
```

### Các loại tệp Mach-O

Có nhiều loại tệp khác nhau, bạn có thể tìm thấy chúng được định nghĩa trong [**mã nguồn, ví dụ tại đây**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Các loại quan trọng nhất là:

- `MH_OBJECT`: Tệp object có thể tái định vị (sản phẩm trung gian của quá trình biên dịch, chưa phải tệp thực thi).
- `MH_EXECUTE`: Tệp thực thi.
- `MH_FVMLIB`: Tệp thư viện VM cố định.
- `MH_CORE`: Bản dump mã.
- `MH_PRELOAD`: Tệp thực thi được tải trước (không còn được XNU hỗ trợ).
- `MH_DYLIB`: Thư viện động.
- `MH_DYLINKER`: Trình liên kết động.
- `MH_BUNDLE`: "Tệp plugin". Được tạo bằng tùy chọn -bundle trong gcc và được tải rõ ràng bằng `NSBundle` hoặc `dlopen`.
- `MH_DYSM`: Tệp `.dSym` đi kèm (tệp chứa các symbol dùng để debug).
- `MH_KEXT_BUNDLE`: Kernel Extension.

```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

Hoặc sử dụng [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Cờ Mach-O**

Mã nguồn cũng định nghĩa một số cờ hữu ích cho việc tải thư viện:

- `MH_NOUNDEFS`: Không có tham chiếu chưa được định nghĩa (liên kết hoàn chỉnh)
- `MH_DYLDLINK`: Liên kết bằng Dyld
- `MH_PREBOUND`: Các tham chiếu động được liên kết trước.
- `MH_SPLIT_SEGS`: Tệp chia các segment chỉ đọc và đọc/ghi.
- `MH_WEAK_DEFINES`: Binary có các symbol được định nghĩa yếu
- `MH_BINDS_TO_WEAK`: Binary sử dụng các symbol yếu
- `MH_ALLOW_STACK_EXECUTION`: Cho phép stack thực thi
- `MH_NO_REEXPORTED_DYLIBS`: Thư viện không có lệnh LC_REEXPORT
- `MH_PIE`: Executable độc lập vị trí
- `MH_HAS_TLV_DESCRIPTORS`: Có một section chứa các biến cục bộ của thread
- `MH_NO_HEAP_EXECUTION`: Không thực thi các trang heap/data
- `MH_HAS_OBJC`: Binary có các section Objective-C
- `MH_SIM_SUPPORT`: Hỗ trợ trình mô phỏng
- `MH_DYLIB_IN_CACHE`: Được dùng cho dylib/framework trong shared library cache.

## **Các lệnh tải Mach-O**

**Bố cục của tệp trong bộ nhớ** được chỉ định tại đây, nêu rõ **vị trí của bảng symbol**, ngữ cảnh của main thread khi bắt đầu thực thi và các **shared library** cần thiết. Các chỉ dẫn được cung cấp cho dynamic loader **(dyld)** về quy trình tải binary vào bộ nhớ.

Nó sử dụng cấu trúc **load_command**, được định nghĩa trong **`loader.h`** đã đề cập:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

There are about **50 loại load command khác nhau** được hệ thống xử lý theo những cách khác nhau. Các loại phổ biến nhất là: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` và `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Về cơ bản, loại Load Command này xác định **cách tải các segment \_\_TEXT** (mã thực thi) **và \_\_DATA** (dữ liệu của process) **theo các offset được chỉ định trong phần Data** khi binary được thực thi.

Các lệnh này **xác định những segment** được **ánh xạ** vào **không gian bộ nhớ ảo** của một process khi process đó được thực thi.

Có **nhiều loại** segment khác nhau, chẳng hạn như segment **\_\_TEXT**, chứa mã thực thi của chương trình, và segment **\_\_DATA**, chứa dữ liệu mà process sử dụng. Các **segment này nằm trong phần data** của file Mach-O.

**Mỗi segment** có thể được **chia nhỏ** thành nhiều **section**. **Cấu trúc load command** chứa **thông tin** về **các section này** bên trong segment tương ứng.

Trong header, trước tiên bạn sẽ thấy **segment header**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* for 64-bit architectures */
	uint32_t	cmd;		/* LC_SEGMENT_64 */
	uint32_t	cmdsize;	/* includes sizeof section_64 structs */
	char		segname[16];	/* segment name */
	uint64_t	vmaddr;		/* memory address of this segment */
	uint64_t	vmsize;		/* memory size of this segment */
	uint64_t	fileoff;	/* file offset of this segment */
	uint64_t	filesize;	/* amount to map from the file */
	int32_t		maxprot;	/* maximum VM protection */
	int32_t		initprot;	/* initial VM protection */
<strong>	uint32_t	nsects;		/* number of sections in segment */
</strong>	uint32_t	flags;		/* flags */
};
</code></pre>

Ví dụ về segment header:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Header này xác định **số lượng section có header xuất hiện ngay sau nó**:

```c
struct section_64 { /* for 64-bit architectures */
	char		sectname[16];	/* name of this section */
	char		segname[16];	/* segment this section goes in */
	uint64_t	addr;		/* memory address of this section */
	uint64_t	size;		/* size in bytes of this section */
	uint32_t	offset;		/* file offset of this section */
	uint32_t	align;		/* section alignment (power of 2) */
	uint32_t	reloff;		/* file offset of relocation entries */
	uint32_t	nreloc;		/* number of relocation entries */
	uint32_t	flags;		/* flags (section type and attributes)*/
	uint32_t	reserved1;	/* reserved (for offset or index) */
	uint32_t	reserved2;	/* reserved (for count or sizeof) */
	uint32_t	reserved3;	/* reserved */
};
```

Ví dụ về **header của section**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Nếu bạn **cộng** **offset của section** (0x37DC) với **offset** nơi **arch bắt đầu**, trong trường hợp này là `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Bạn cũng có thể lấy **thông tin về header** từ **command line** bằng cách:

```bash
otool -lv /bin/ls
```

Các segment phổ biến được nạp bởi lệnh này:

- **`__PAGEZERO`:** Hướng dẫn kernel **map** **địa chỉ zero** để địa chỉ này **không thể bị đọc, ghi hoặc thực thi**. Các biến maxprot và minprot trong cấu trúc được đặt thành zero để biểu thị rằng **trang này không có quyền đọc-ghi-thực thi**.
  - Việc cấp phát này rất quan trọng để **giảm thiểu các lỗ hổng NULL pointer dereference**. Lý do là XNU áp dụng hard page zero, đảm bảo trang bộ nhớ đầu tiên (chỉ trang đầu tiên) không thể truy cập được (trừ trên i386). Một binary có thể đáp ứng yêu cầu này bằng cách tạo một \_\_PAGEZERO nhỏ (dùng `-pagezero_size`) để bao phủ 4k đầu tiên, đồng thời cho phép phần còn lại của bộ nhớ 32bit truy cập được ở cả user mode lẫn kernel mode.
- **`__TEXT`**: Chứa **code** **thực thi được** với quyền **đọc** và **thực thi** (không có quyền ghi)**.** Các section phổ biến của segment này:
  - `__text`: Code binary đã biên dịch
  - `__const`: Dữ liệu hằng (chỉ đọc)
  - `__[c/u/os_log]string`: Các hằng chuỗi C, Unicode hoặc os log
  - `__stubs` và `__stubs_helper`: Được dùng trong quá trình nạp dynamic library
  - `__unwind_info`: Dữ liệu unwind của stack.
  - Lưu ý rằng toàn bộ nội dung này được ký nhưng cũng được đánh dấu là có thể thực thi (tạo thêm nhiều lựa chọn để khai thác các section không nhất thiết cần quyền này, chẳng hạn như các section dành riêng cho chuỗi).
- **`__DATA`**: Chứa dữ liệu **có thể đọc** và **ghi được** (không thể thực thi)**.**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Con trỏ symbol không lazy (bind khi nạp)
  - `__la_symbol_ptr`: Con trỏ symbol lazy (bind khi sử dụng)
  - `__const`: Đáng lẽ là dữ liệu chỉ đọc (nhưng thực tế không phải vậy)
  - `__cfstring`: Các chuỗi CoreFoundation
  - `__data`: Các biến toàn cục (đã được khởi tạo)
  - `__bss`: Các biến static (chưa được khởi tạo)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, v.v.): Thông tin được Objective-C runtime sử dụng
- **`__DATA_CONST`**: \_\_DATA.\_\_const không được đảm bảo là hằng (có quyền ghi), và các con trỏ khác cùng GOT cũng vậy. Section này dùng `mprotect` để đặt `__const`, một số initializer và bảng GOT (sau khi được phân giải) thành **chỉ đọc**.
- **`__AUTH` / `__AUTH_CONST`**: Thường gặp trong các binary Apple Silicon gần đây. Các segment này chứa những con trỏ cần được xác thực khi nạp hoặc khi sử dụng (ví dụ `__auth_got`). Nếu một thủ thuật rebinding, hook hoặc import-patching chỉ kiểm tra các section `__got` / `__la_symbol_ptr` cũ, nó có thể bỏ sót các call site thực tế trong binary `arm64e` hiện đại. Để biết thêm chi tiết về các section này, xem [trang này](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Chứa thông tin dành cho linker (dyld), chẳng hạn như các mục trong bảng symbol, string và relocation. Đây là container tổng quát cho nội dung không nằm trong `__TEXT` hoặc `__DATA`; nội dung của nó được mô tả trong các load command khác.
  - Thông tin dyld: Các opcode rebase, binding non-lazy/lazy/weak và thông tin export
  - Function starts: Bảng địa chỉ bắt đầu của các function
  - Data In Code: Các vùng dữ liệu trong \_\_text
  - SYmbol Table: Các symbol trong binary
  - Indirect Symbol Table: Các symbol con trỏ/stub
  - String Table
  - Code Signature
- **`__OBJC`**: Chứa thông tin được Objective-C runtime sử dụng. Tuy nhiên, thông tin này cũng có thể nằm trong segment \_\_DATA, bên trong nhiều section \_\_objc\_\*.
- **`__RESTRICT`**: Segment không chứa nội dung, với một section duy nhất tên là **`__restrict`** (cũng trống), đảm bảo rằng khi chạy binary, các biến môi trường DYLD sẽ bị bỏ qua.

Như có thể thấy trong code, **các segment cũng hỗ trợ flags** (dù chúng không được dùng nhiều):

- `SG_HIGHVM`: Chỉ dành cho Core (không được dùng)
- `SG_FVMLIB`: Không được dùng
- `SG_NORELOC`: Segment không có relocation
- `SG_PROTECTED_VERSION_1`: Mã hóa. Ví dụ, Finder dùng flag này để mã hóa segment `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** chứa entrypoint trong thuộc tính **entryoff**. Khi nạp, **dyld** chỉ cần **cộng** giá trị này với **địa chỉ cơ sở** của binary (trong bộ nhớ), sau đó **nhảy** đến instruction này để bắt đầu thực thi code của binary.

**`LC_UNIXTHREAD`** chứa các giá trị mà register phải có khi khởi chạy main thread. Cách này đã bị deprecated, nhưng **`dyld`** vẫn sử dụng. Có thể xem các giá trị register được thiết lập bằng cách dùng lệnh sau:

```bash
otool -l /usr/lib/dyld
[...]
Load command 13
        cmd LC_UNIXTHREAD
    cmdsize 288
     flavor ARM_THREAD_STATE64
      count ARM_THREAD_STATE64_COUNT
	    x0  0x0000000000000000 x1  0x0000000000000000 x2  0x0000000000000000
	    x3  0x0000000000000000 x4  0x0000000000000000 x5  0x0000000000000000
	    x6  0x0000000000000000 x7  0x0000000000000000 x8  0x0000000000000000
	    x9  0x0000000000000000 x10 0x0000000000000000 x11 0x0000000000000000
	    x12 0x0000000000000000 x13 0x0000000000000000 x14 0x0000000000000000
	    x15 0x0000000000000000 x16 0x0000000000000000 x17 0x0000000000000000
	    x18 0x0000000000000000 x19 0x0000000000000000 x20 0x0000000000000000
	    x21 0x0000000000000000 x22 0x0000000000000000 x23 0x0000000000000000
	    x24 0x0000000000000000 x25 0x0000000000000000 x26 0x0000000000000000
	    x27 0x0000000000000000 x28 0x0000000000000000  fp 0x0000000000000000
	     lr 0x0000000000000000 sp  0x0000000000000000  pc 0x0000000000004b70
	   cpsr 0x00000000

[...]
```

### **`LC_CODE_SIGNATURE`**

{{#ref}}
../../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/mach-o-entitlements-and-ipsw-indexing.md
{{#endref}}


Chứa thông tin về **chữ ký code của file Mach-O**. Nó chỉ chứa một **offset** **trỏ đến** **signature blob**. Thông thường, phần này nằm ở cuối file.\
Bạn có thể tìm thêm thông tin về section này trong [**bài blog này**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) và [**gist này**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Hỗ trợ mã hóa binary. Tuy nhiên, tất nhiên, nếu attacker xâm nhập được process, họ vẫn có thể dump memory ở dạng không mã hóa.

### **`LC_LOAD_DYLINKER`**

Chứa **đường dẫn đến executable dynamic linker**, chương trình ánh xạ shared libraries vào không gian địa chỉ của process. **Giá trị luôn được đặt là `/usr/lib/dyld`**. Cần lưu ý rằng trong macOS, việc ánh xạ dylib diễn ra ở **user mode**, không phải kernel mode.

### **`LC_IDENT`**

Đã lỗi thời, nhưng khi được cấu hình để tạo dump khi xảy ra panic, một Mach-O core dump sẽ được tạo và phiên bản kernel được đặt trong command `LC_IDENT`.

### **`LC_UUID`**

UUID ngẫu nhiên. Nó không hữu ích trực tiếp cho việc gì, nhưng XNU lưu cache UUID này cùng với phần thông tin còn lại của process. UUID có thể được dùng trong crash report.

### **`LC_BUILD_VERSION`**

Các binary hiện đại thường có command này để khai báo **platform mục tiêu**, **phiên bản OS tối thiểu**, **phiên bản SDK** và tùy chọn **các phiên bản tool** được dùng để build slice đó. Từ góc độ offensive/reversing, thông tin này rất hữu ích để xác định cách một sample được build và nhanh chóng phát hiện các universal binary bất thường, trong đó một slice được compile bằng SDK hoặc deployment target khác. Các binary cũ hơn có thể vẫn dùng `LC_VERSION_MIN_*`.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Cho phép chỉ định các biến môi trường cho dyld trước khi tiến trình được thực thi. Điều này có thể rất nguy hiểm vì có thể cho phép thực thi mã tùy ý bên trong tiến trình. Vì vậy, lệnh tải này chỉ được sử dụng trong bản dựng dyld có `#define SUPPORT_LC_DYLD_ENVIRONMENT` và còn giới hạn việc xử lý chỉ ở các biến có dạng `DYLD_..._PATH` chỉ định đường dẫn tải.

### **`LC_DYLD_EXPORTS_TRIE` và `LC_DYLD_CHAINED_FIXUPS`**

Các toolchain gần đây thường lưu metadata export/bind/rebase trong các lệnh này thay vì chỉ dựa vào các opcode `LC_DYLD_INFO[_ONLY]` cũ hơn. Cả hai đều là các mục `linkedit_data_command` trỏ đến **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Trie gọn chứa các symbol được image export.
- **`LC_DYLD_CHAINED_FIXUPS`**: Các chuỗi fixup theo từng segment, được dyld dùng để áp dụng rebase và bind. Trên Apple Silicon, đây cũng là nơi bạn sẽ gặp nhiều fixup con trỏ có xác thực hiện đại.

Metadata này rất hữu ích khi tái dựng imports/exports, tìm hiểu vì sao một dependency được tải bằng `@rpath` lại được phân giải theo cách đó, hoặc xác định lý do một nỗ lực hook/rebinding thất bại trên mục tiêu `arm64e` hiện đại. `dyld_info` cũng có thể được dùng với **các đường dẫn dylib chỉ có trong cache** và không tồn tại dưới dạng tệp độc lập trên ổ đĩa. Điều này rất hữu ích trên macOS hiện đại, nơi nhiều thư viện hệ thống chỉ nằm trong shared cache.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Lệnh tải hiện đại này chủ yếu hữu ích khi kiểm tra **kernel collections / kernelcache-style filesets**. Thay vì biểu diễn một image độc lập, Mach-O bên ngoài đóng vai trò như một container và mỗi `LC_FILESET_ENTRY` trỏ đến một Mach-O được nhúng, với **entry id** dạng đường dẫn riêng, địa chỉ VM và offset trong file. Khi reverse các thành phần kernel hiện đại của macOS/iOS, lệnh này thường là cầu nối giữa container cấp cao nhất và image thực tế mà bạn muốn trích xuất hoặc disassemble.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

For practical extraction workflows, xem [trang khác này về macOS kernel extensions và kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Lệnh tải này mô tả một dependency **thư viện** **động**, **chỉ thị** cho **loader** (dyld) **tải và liên kết thư viện đó**. Có một lệnh tải `LC_LOAD_DYLIB` **cho mỗi thư viện** mà binary Mach-O yêu cầu.

- Lệnh tải này là một cấu trúc kiểu **`dylib_command`** (chứa một struct dylib, mô tả thư viện động phụ thuộc thực tế):

```objectivec
struct dylib_command {
        uint32_t        cmd;            /* LC_LOAD_{,WEAK_}DYLIB */
        uint32_t        cmdsize;        /* includes pathname string */
        struct dylib    dylib;          /* the library identification */
};

struct dylib {
    union lc_str  name;                 /* library's path name */
    uint32_t timestamp;                 /* library's build time stamp */
    uint32_t current_version;           /* library's current version number */
    uint32_t compatibility_version;     /* library's compatibility vers number*/
};
```

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t phiên bản tương thích; / số phiên bản tương thích của thư viện /](<../../../images/image (486).png>)

Bạn cũng có thể lấy thông tin này từ cli bằng lệnh:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Một số thư viện có thể liên quan đến malware:

- **DiskArbitration**: Giám sát ổ USB
- **AVFoundation:** Thu âm thanh và video
- **CoreWLAN**: Quét Wi-Fi.

> [!TIP]
> Một binary Mach-O có thể chứa một hoặc **nhiều** **constructor**, sẽ được **thực thi** **trước** địa chỉ được chỉ định trong **LC_MAIN**.\
> Offset của mọi constructor được lưu trong section **\_\_mod_init_func** của segment **\_\_DATA_CONST**.

## **Dữ liệu Mach-O**

Cốt lõi của tệp là vùng dữ liệu, gồm nhiều segment được định nghĩa trong vùng load command. **Mỗi segment có thể chứa nhiều section dữ liệu**, và mỗi section **chứa code hoặc dữ liệu** dành riêng cho một loại.

> [!TIP]
> Về cơ bản, dữ liệu là phần chứa toàn bộ **thông tin** được load command **LC_SEGMENTS_64** tải vào.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Nội dung này bao gồm:

- **Bảng hàm:** Chứa thông tin về các hàm của chương trình.
- **Bảng symbol**: Chứa thông tin về các hàm bên ngoài được binary sử dụng.
- Nó cũng có thể chứa tên của các hàm nội bộ, biến, v.v.

Để kiểm tra, bạn có thể dùng công cụ [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Hoặc dùng CLI:

```bash
size -m /bin/ls
```

### Dữ liệu nối thêm và overlay được phân tích ngược

Một loader có thể lưu cấu hình trong dữ liệu nối thêm thay vì trong một section Mach-O có tên. Sau đó, trình phân tích ngược dựa vào một dấu đánh dấu ở cuối, đọc kích thước được lưu ngay trước dấu đó, rồi dùng giá trị này để định vị và giải mã blob đứng trước. Một loader universal được quan sát thấy sử dụng bố cục này cho URL downloader được mã hóa XOR:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Khi reverse một binary chưa quen thuộc, hãy kiểm tra các byte xung quanh những dấu kết thúc dễ nhận biết và lần theo mọi phép tính kích thước ngược trước khi cho rằng các chuỗi hoặc cấu hình nhất thiết phải thuộc về một section của load command. Dấu đánh dấu và khóa XOR chỉ dùng cho mẫu cụ thể; kỹ thuật có thể tái sử dụng là trailer tự mô tả.

## Các section phổ biến của Objective-C

Trong segment `__TEXT` (r-x):

- `__objc_classname`: Tên class (chuỗi)
- `__objc_methname`: Tên method (chuỗi)
- `__objc_methtype`: Kiểu method (chuỗi)

Trong segment `__DATA` (rw-):

- `__objc_classlist`: Con trỏ đến tất cả class Objective-C
- `__objc_nlclslist`: Con trỏ đến các class Objective-C Non-Lazy
- `__objc_catlist`: Con trỏ đến Categories
- `__objc_nlcatlist`: Con trỏ đến Categories Non-Lazy
- `__objc_protolist`: Danh sách Protocol
- `__objc_const`: Dữ liệu hằng
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

Xem thêm: [Reflective Mach-O Loading](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Các slice Mach-O không đơn giản như bạn nghĩ](https://objective-see.org/blog/blog_0x80.html)
- [2] [Trang man dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Đọc Entitlements của chính bạn](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Mã nguồn mở Apple - Mach-O `fat.h` và `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - Phiên bản mới của mã độc đánh cắp macOS MacSync nhắm vào những người đam mê tiền mã hóa và nhà phát triển](https://securelist.com/macsync-new-version/121383/)
