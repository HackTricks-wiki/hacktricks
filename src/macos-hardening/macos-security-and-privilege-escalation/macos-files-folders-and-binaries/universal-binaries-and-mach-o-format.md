# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Mac OS binary'leri genellikle **universal binaries** olarak derlenir. Bir **universal binary**, **aynı dosya içinde birden fazla mimariyi destekleyebilir**.

Bu binary'ler temel olarak şu bölümlerden oluşan **Mach-O yapısını** izler:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Dosyayı şu komutla arayın: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Header, **magic** byte'larını ve ardından dosyanın **içerdiği** **arch** sayısını (`nfat_arch`) barındırır; her arch bir `fat_arch` struct'ına sahip olacaktır.

Şu komutla kontrol edin:

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

veya [Mach-O View](https://sourceforge.net/projects/machoview/) aracını kullanarak:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Tahmin edebileceğiniz gibi, genellikle 2 mimari için derlenen bir universal binary, yalnızca 1 arch için derlenen binary'nin **boyutunu iki katına çıkarır**.

> [!TIP]
> Malware veya şüpheli uygulamaları triage ederken, `file` komutunun "en iyi" mimariyi bildirmesiyle yetinmeyin. Bir universal binary, her slice içinde farklı import'ları, load command'ları veya compiler metadata'sını gizleyebilir; bu nedenle önce **tüm** slice'ları enumerate edin, ardından bunları bağımsız olarak inceleyin:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Recent macOS SDK'leri ayrıca `<mach-o/utils.h>` içinde `macho_for_each_slice()` ve `macho_best_slice()` gibi yardımcılar sunar. İkincisi, dyld/kernel'in yükleyeceği şeyi taklit etmek için kullanışlıdır; ancak scanner'lar arch-specific içeriği kaçırmamak için yine de her slice'ı taramalıdır.<sup>[[1]](#references)</sup>

## **Mach-O Header**

Header, dosya hakkında Mach-O dosyası olduğunu belirlemek için magic byte'lar ve hedef mimari hakkında bilgiler gibi temel bilgileri içerir. Şu komutla bulabilirsiniz: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O Dosya Türleri

Farklı dosya türleri vardır; bunları [**örneğin burada kaynak kodunda bulabilirsiniz**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). En önemlileri şunlardır:

- `MH_OBJECT`: Relocatable object file (derlemenin ara ürünleri; henüz executable değildir).
- `MH_EXECUTE`: Executable dosyaları.
- `MH_FVMLIB`: Sabit VM library dosyası.
- `MH_CORE`: Kod dökümleri.
- `MH_PRELOAD`: Preloaded executable dosyası (XNU'da artık desteklenmiyor).
- `MH_DYLIB`: Dynamic Libraries.
- `MH_DYLINKER`: Dynamic Linker.
- `MH_BUNDLE`: "Plugin dosyaları". gcc'de `-bundle` kullanılarak oluşturulur ve `NSBundle` veya `dlopen` tarafından açıkça yüklenir.
- `MH_DYSM`: Companion `.dSym` dosyası (debugging için semboller içeren dosya).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Ya da [Mach-O View](https://sourceforge.net/projects/machoview/) kullanarak:

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

Kaynak kod ayrıca libraries yüklemek için yararlı olan çeşitli flags tanımlar:

- `MH_NOUNDEFS`: Undefined references yok (fully linked)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamic references prebound.
- `MH_SPLIT_SEGS`: File, r/o ve r/w segments olarak ayrılır.
- `MH_WEAK_DEFINES`: Binary, weak defined symbols içerir
- `MH_BINDS_TO_WEAK`: Binary, weak symbols kullanır
- `MH_ALLOW_STACK_EXECUTION`: Stack'i executable yapar
- `MH_NO_REEXPORTED_DYLIBS`: Library'de LC_REEXPORT commands yok
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Thread local variables içeren bir section vardır
- `MH_NO_HEAP_EXECUTION`: Heap/data pages için execution yok
- `MH_HAS_OBJC`: Binary, oBject-C sections içerir
- `MH_SIM_SUPPORT`: Simulator desteği
- `MH_DYLIB_IN_CACHE`: Shared library cache içindeki dylibs/frameworks üzerinde kullanılır.

## **Mach-O Load commands**

**Dosyanın memory içindeki yerleşimi** burada belirtilir; **symbol table'ın konumu**, execution başlangıcında ana thread'in context'i ve gerekli **shared libraries** ayrıntılı olarak açıklanır. Dynamic loader'a **(dyld)** binary'nin memory'ye yüklenme süreciyle ilgili talimatlar sağlanır.

Bu, bahsedilen **`loader.h`** içinde tanımlanan **load_command** structure'ını kullanır:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Sistemin farklı şekilde işlediği yaklaşık **50 farklı load command türü** vardır. En yaygın olanlar: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` ve `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Temel olarak bu Load Command türü, binary çalıştırıldığında **Data bölümünde belirtilen offset'lere** göre **\_\_TEXT** (çalıştırılabilir kod) ve **\_\_DATA** (process için veriler) **segment'lerinin nasıl yükleneceğini tanımlar**.

Bu command'ler, çalıştırıldığında bir process'in **virtual memory space** alanına **map edilen** **segment'leri tanımlar**.

Programın çalıştırılabilir kodunu tutan **\_\_TEXT** segment'i ve process tarafından kullanılan verileri içeren **\_\_DATA** segment'i gibi **farklı segment türleri** vardır. Bu **segment'ler Mach-O dosyasının data bölümünde bulunur**.

**Her segment** birden fazla **section'a** ayrılabilir. **Load command yapısı**, ilgili segment içindeki **bu section'lar hakkında bilgi** içerir.

Header'da ilk olarak **segment header'ını** bulursunuz:

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

Segment header örneği:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Bu header, kendisinden sonra header'ları görünen **section'ların sayısını tanımlar**:
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
**section header** örneği:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

**section offset** (0x37DC) ile **arch starts** konumundaki **offset** değerini, bu durumda `0x18000`, **toplarsanız** --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

**headers information** bilgilerini **command line** üzerinden şu komutla almak da mümkündür:
```bash
otool -lv /bin/ls
```
Bu cmd tarafından yüklenen yaygın segmentler:

- **`__PAGEZERO`:** Kernel'e **address zero** değerini **map** etmesini ve bu adresin **read**, **write** veya **execute** edilememesini bildirir. Yapıdaki maxprot ve minprot değişkenleri, **bu page üzerinde read-write-execute hakları olmadığını** belirtmek için sıfıra ayarlanır.
- Bu allocation, **NULL pointer dereference vulnerabilities** riskini azaltmak için önemlidir. Bunun nedeni, XNU'nun belleğin ilk page'inin (yalnızca ilkinin) erişilemez olmasını sağlayan hard page zero uygulamasıdır (i386 hariç). Bir binary, ilk 4k'yı kapsayacak küçük bir \_\_PAGEZERO oluşturarak ( `-pagezero_size` kullanarak) ve 32bit belleğin geri kalanını hem user hem de kernel mode'da erişilebilir hâle getirerek bu gereksinimi karşılayabilir.
- **`__TEXT`**: **read** ve **execute** izinlerine sahip **executable** **code** içerir (**writable değildir)**.** Bu segmentin yaygın sections'ları:
- `__text`: Derlenmiş binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode veya os logs string constants
- `__stubs` ve `__stubs_helper`: Dynamic library loading işlemi sırasında kullanılır
- `__unwind_info`: Stack unwind data.
- Tüm bu içeriğin signed olduğunu, ancak executable olarak da işaretlendiğini unutmayın (bu ayrıcalığa mutlaka ihtiyaç duymayan sections'ların, örneğin string'e ayrılmış sections'ların exploitation'ı için daha fazla seçenek oluşturur).
- **`__DATA`**: **readable** ve **writable** data içerir (**executable değildir)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (load sırasında bind edilen) symbol pointer
- `__la_symbol_ptr`: Lazy (use sırasında bind edilen) symbol pointer
- `__const`: Read-only data olmalıdır (aslında değil)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (initialized olanlar)
- `__bss`: Static variables (initialized olmayanlar)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist vb.): Objective-C runtime tarafından kullanılan bilgiler
- **`__DATA_CONST`**: \_\_DATA.\_\_const'ın constant olması (write permissions) garanti edilmez; diğer pointers ve GOT için de aynı durum geçerlidir. Bu section, `mprotect` kullanarak `__const`, bazı initializers'ları ve GOT table'ı (resolved olduktan sonra) **read only** hâle getirir.
- **`__AUTH` / `__AUTH_CONST`**: Recent Apple Silicon binaries içinde yaygındır. Bu segments, load veya use time sırasında authenticate edilmesi gereken pointers'ları (örneğin `__auth_got`) barındırır. Bir rebinding, hook veya import-patching trick yalnızca legacy `__got` / `__la_symbol_ptr` sections'larını kontrol ederse modern `arm64e` binaries içindeki gerçek call sites'larını gözden kaçırabilir. Bu sections hakkında daha fazla bilgi için [bu sayfaya](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) bakın.
- **`__LINKEDIT`**: Symbol, string ve relocation table entries gibi linker (dyld) bilgilerini içerir. `__TEXT` veya `__DATA` içinde bulunmayan contents için generic bir container'dır ve içeriği diğer load commands içinde açıklanır.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes ve export info
- Functions starts: Functions'ların start addresses table'ı
- Data In Code: \_\_text içindeki data islands
- SYmbol Table: Binary içindeki symbols
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Objective-C runtime tarafından kullanılan bilgileri içerir. Ancak bu bilgiler \_\_DATA segmenti içinde, çeşitli \_\_objc\_\* sections'larında da bulunabilir.
- **`__RESTRICT`**: `__restrict` adlı tek bir section içeren (o da empty'dir) contents'siz bir segment'tir; binary çalıştırılırken DYLD environmental variables'ın ignore edilmesini sağlar.

Code içinde görülebileceği üzere, **segments flags'ları da destekler** (çok fazla kullanılmasalar da):

- `SG_HIGHVM`: Core only (kullanılmıyor)
- `SG_FVMLIB`: Kullanılmıyor
- `SG_NORELOC`: Segment'te relocation yok
- `SG_PROTECTED_VERSION_1`: Encryption. Örneğin Finder tarafından text `__TEXT` segmentini encrypt etmek için kullanılır.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`**, **entrypoint'i `entryoff` attribute'unda** içerir. Load time sırasında **dyld**, bu değeri (in-memory) **binary'nin base'ine** ekler ve ardından binary'nin code'unun execution'ını başlatmak için bu instruction'a **jump** eder.

**`LC_UNIXTHREAD`**, main thread başlatılırken register'ın sahip olması gereken değerleri içerir. Bu özellik artık deprecated durumdadır, ancak **`dyld`** hâlâ bunu kullanır. Bununla ayarlanan register değerlerini şu komutla görmek mümkündür:
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


**Mach-O file'ın code signature'ı** hakkında bilgi içerir. Yalnızca **signature blob'a işaret eden** bir **offset** içerir. Bu genellikle dosyanın en sonunda bulunur.\
Ancak bu section hakkında bazı bilgileri [**bu blog yazısında**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) ve bu [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) içinde bulabilirsiniz.<sup>[[3]](#references)[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Binary encryption desteği sağlar. Ancak elbette bir attacker process'i compromise etmeyi başarırsa memory'yi unencrypted olarak dump edebilir.

### **`LC_LOAD_DYLINKER`**

Shared libraries'yi process address space'e map eden **dynamic linker executable'ın path'ini** içerir. **Değer her zaman `/usr/lib/dyld` olarak ayarlanır**. macOS'ta dylib mapping işleminin kernel mode'da değil, **user mode'da** gerçekleştiğini belirtmek önemlidir.

### **`LC_IDENT`**

Obsolete bir komuttur; ancak panic durumunda dump oluşturacak şekilde yapılandırıldığında bir Mach-O core dump oluşturulur ve kernel version `LC_IDENT` command'ında ayarlanır.

### **`LC_UUID`**

Random UUID. Herhangi bir şey için doğrudan kullanışlı değildir; ancak XNU bunu process info'nun geri kalanıyla birlikte cache'ler. Crash report'larda kullanılabilir.

### **`LC_BUILD_VERSION`**

Modern binary'ler genellikle **target platform'u**, **minimum OS version'ı**, **SDK version'ı** ve isteğe bağlı olarak ilgili slice'ı build etmek için kullanılan **tool version'larını** belirtmek üzere bu command'ı içerir. Offensive/reversing açısından bu, bir sample'ın nasıl build edildiğini fingerprint etmek ve bir slice'ın farklı bir SDK veya deployment target ile compile edildiği şüpheli universal binary'leri hızlıca tespit etmek için oldukça kullanışlıdır. Daha eski binary'ler bunun yerine hâlâ `LC_VERSION_MIN_*` kullanabilir.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

İşlem yürütülmeden önce dyld'ye environment variables belirtmeye olanak tanır. Bu, işlem içinde arbitrary code execute edilmesine izin verebileceğinden oldukça tehlikeli olabilir; bu nedenle bu load command yalnızca `#define SUPPORT_LC_DYLD_ENVIRONMENT` ile derlenen dyld sürümlerinde kullanılır ve işleme, yalnızca load paths belirten `DYLD_..._PATH` biçimindeki variables ile daha da sınırlandırılır.

### **`LC_DYLD_EXPORTS_TRIE` ve `LC_DYLD_CHAINED_FIXUPS`**

Recent toolchains, export/bind/rebase metadata'sını yalnızca eski `LC_DYLD_INFO[_ONLY]` opcodes'larına güvenmek yerine sıklıkla bu commands içinde depolar. Her ikisi de **`__LINKEDIT`** içindeki bir konuma işaret eden `linkedit_data_command` entries'idir:

- **`LC_DYLD_EXPORTS_TRIE`**: Image tarafından export edilen symbols'leri içeren compact trie.
- **`LC_DYLD_CHAINED_FIXUPS`**: Rebases ve binds uygulamak için dyld tarafından kullanılan, segment başına fixup chains. Apple Silicon üzerinde birçok modern authenticated pointer fixup ile karşılaşacağınız yer de burasıdır.

Bu metadata; imports/exports yeniden oluşturulurken, `@rpath` ile yüklenen bir dependency'nin neden bu şekilde resolve edildiğini anlaşılırken veya bir hook/rebinding girişiminin modern bir `arm64e` target üzerinde neden başarısız olduğunu belirlerken oldukça kullanışlıdır. `dyld_info`, standalone file olarak diskte bulunmayan **cache-only dylib paths** üzerinde de kullanılabilir; bu, birçok system library'nin yalnızca shared cache içinde bulunduğu modern macOS'ta oldukça kullanışlıdır.<sup>[[2]](#references)</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Bu modern load command, çoğunlukla **kernel collections / kernelcache-style fileset** dosyalarını incelerken önem taşır. Tek bir bağımsız image'ı temsil etmek yerine, dıştaki Mach-O bir container görevi görür ve her `LC_FILESET_ENTRY`, kendisine ait path benzeri bir **entry id**, VM address ve file offset ile gömülü bir Mach-O'yu işaret eder. Modern macOS/iOS kernel bileşenlerini reverse ediyorsanız bu command, üst düzey container ile extract etmek veya disassemble etmek istediğiniz gerçek image arasındaki bağlantıyı çoğu zaman sağlar.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Pratik çıkarma iş akışları için [macOS kernel extensions ve kernelcache hakkındaki bu diğer sayfaya](../mac-os-architecture/macos-kernel-extensions.md) bakın.

### **`LC_LOAD_DYLIB`**

Bu load command, **loader**'a (dyld) ilgili **library'yi yükleyip linklemesini** bildiren bir **dynamic** **library** bağımlılığını açıklar. Mach-O binary'nin gerektirdiği **her library** için bir `LC_LOAD_DYLIB` load command bulunur.

- Bu load command, **`dylib_command`** türünde bir yapıdır (gerçek bağımlı dynamic library'yi açıklayan bir struct dylib içerir):
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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t uyumluluk sürümü; / library's uyumluluk sürüm numarası /](<../../../images/image (486).png>)

Bu bilgiyi CLI kullanarak da edinebilirsiniz:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Bazı potansiyel malware ile ilgili kütüphaneler şunlardır:

- **DiskArbitration**: USB sürücülerini izleme
- **AVFoundation:** Ses ve video yakalama
- **CoreWLAN**: WiFi taramaları.

> [!TIP]
> Bir Mach-O binary'si bir veya **daha fazla** **constructor** içerebilir ve bunlar **LC_MAIN** içinde belirtilen adresten **önce çalıştırılır**.\
> Herhangi bir constructor'ın offset'leri, **\_\_DATA_CONST** segmentinin **\_\_mod_init_func** section'ında tutulur.

## **Mach-O Verileri**

Dosyanın temelinde, load-commands bölgesinde tanımlandığı şekilde birkaç segmentten oluşan veri bölgesi bulunur. **Her segment içinde çeşitli veri section'ları barındırılabilir** ve her section bir türe özgü **code veya data** içerir.

> [!TIP]
> Veriler temel olarak, load commands **LC_SEGMENTS_64** tarafından yüklenen tüm **bilgileri** içeren kısımdır.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Bunlar şunları içerir:

- **Function table:** Program function'ları hakkındaki bilgileri tutar.
- **Symbol table**: Binary tarafından kullanılan external function hakkındaki bilgileri içerir.
- Ayrıca internal function ve variable adlarını da içerebilir.

Kontrol etmek için [**Mach-O View**](https://sourceforge.net/projects/machoview/) aracını kullanabilirsiniz:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Veya CLI üzerinden:
```bash
size -m /bin/ls
```
## Objective-C Yaygın Bölümleri

`__TEXT` segmentinde (r-x):

- `__objc_classname`: Sınıf adları (string'ler)
- `__objc_methname`: Method adları (string'ler)
- `__objc_methtype`: Method türleri (string'ler)

`__DATA` segmentinde (rw-):

- `__objc_classlist`: Tüm Objective-C sınıflarına işaretçiler
- `__objc_nlclslist`: Non-Lazy Objective-C sınıflarına işaretçiler
- `__objc_catlist`: Category'lere işaretçi
- `__objc_nlcatlist`: Non-Lazy Category'lere işaretçi
- `__objc_protolist`: Protocol listesi
- `__objc_const`: Sabit veriler
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## Referanslar

- [1] [Mach-O dilimleri düşündüğünüz kadar basit değildir](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) man sayfası](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Kendi Entitlements'larınızı Okuma](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
