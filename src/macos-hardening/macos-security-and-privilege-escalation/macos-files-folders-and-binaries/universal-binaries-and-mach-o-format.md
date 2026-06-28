# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Mac OS binaries usually are compiled as **universal binaries**. A **universal binary** can **support multiple architectures in the same file**.

These binaries follows the **Mach-O structure** which is basically compased of:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Şu dosyayı arayın: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Başlık, **magic** baytlarını ve ardından dosyanın **içerdiği** **arch sayısını** (`nfat_arch`) içerir ve her arch bir `fat_arch` struct'ına sahip olacaktır.

Şununla kontrol edin:

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

veya [Mach-O View](https://sourceforge.net/projects/machoview/) aracıyla:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Düşünüyor olabileceğiniz gibi, genellikle 2 mimari için derlenmiş bir universal binary, yalnızca 1 arch için derlenmiş olana göre **boyutu iki katına çıkarır**.

> [!TIP]
> Malware veya suspicious app'leri incelerken, `file` "en iyi" mimariyi rapor ettikten sonra durmayın. Bir universal binary, her slice'ta farklı imports, load commands veya compiler metadata gizleyebilir; bu yüzden önce **tüm** slice'ları enumerate edin ve sonra her birini bağımsız olarak inceleyin:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Son macOS SDK'leri ayrıca `<mach-o/utils.h>` içinde `macho_for_each_slice()` ve `macho_best_slice()` gibi yardımcılar da sunar. İkincisi, dyld/kernel'in neyi yükleyeceğini taklit etmek için kullanışlıdır, ancak scanner'lar yine de arch-specific content'i kaçırmamak için her slice'ı tek tek dolaşmalıdır.

## **Mach-O Header**

Header, dosya hakkında Mach-O file olarak tanımlamak için magic bytes ve target architecture hakkında bilgi gibi temel bilgileri içerir. Şurada bulunabilir: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O File Türleri

Farklı file type'lar vardır, bunları [**örnek olarak source code burada**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) tanımlı halde bulabilirsiniz. En önemlileri şunlardır:

- `MH_OBJECT`: Relocatable object file (derleme ara ürünleri, henüz executable değil).
- `MH_EXECUTE`: Executable dosyalar.
- `MH_FVMLIB`: Fixed VM library dosyası.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Preloaded executable dosya (XNU içinde artık desteklenmiyor)
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin files". gcc'de -bundle kullanılarak üretilir ve `NSBundle` ya da `dlopen` ile açıkça yüklenir.
- `MH_DYSM`: Companion `.dSym` dosyası (debugging için symbols içeren dosya).
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

Kaynak kod ayrıca kütüphanelerin yüklenmesi için yararlı birkaç flag tanımlar:

- `MH_NOUNDEFS`: Undefined reference yok (tamamen linked)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamic reference'lar prebound.
- `MH_SPLIT_SEGS`: File r/o ve r/w segmentlere ayrılır.
- `MH_WEAK_DEFINES`: Binary weak defined symbols içerir
- `MH_BINDS_TO_WEAK`: Binary weak symbols kullanır
- `MH_ALLOW_STACK_EXECUTION`: Stack'i executable yapar
- `MH_NO_REEXPORTED_DYLIBS`: Library'de LC_REEXPORT komutları yok
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Thread local variables içeren bir section vardır
- `MH_NO_HEAP_EXECUTION`: Heap/data pages için execution yok
- `MH_HAS_OBJC`: Binary oBject-C sections içerir
- `MH_SIM_SUPPORT`: Simulator desteği
- `MH_DYLIB_IN_CACHE`: Shared library cache içindeki dylibs/frameworks üzerinde kullanılır.

## **Mach-O Load commands**

**Dosyanın bellek içindeki düzeni** burada belirtilir; **symbol table'ın konumu**, yürütme başlangıcında ana thread'in durumu ve gerekli **shared libraries** detaylandırılır. Dynamic loader **(dyld)**'a binary'nin belleğe yüklenme süreci için talimatlar verilir.

Bunun için belirtilen **`loader.h`** içindeki **load_command** yapısı kullanılır:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Yaklaşık **50 farklı türde load command** vardır ve sistem bunları farklı şekilde işler. En yaygın olanlar: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` ve `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Temel olarak, bu tür Load Command, binary çalıştırıldığında **Data section** içinde belirtilen **offsets**’lere göre **\_\_TEXT** (çalıştırılabilir kod) ve **\_\_DATA** (process için veri) **segmentlerinin** nasıl yükleneceğini **tanımlar**.

Bu komutlar, çalıştırıldığında bir process’in **virtual memory space**’ine **mapped** edilen **segmentleri tanımlar**.

**\_\_TEXT** segmenti gibi, bir programın çalıştırılabilir kodunu tutan ve **\_\_DATA** segmenti gibi process tarafından kullanılan verileri içeren **farklı segment türleri** vardır. Bu **segmentler Mach-O dosyasının data section**’ında bulunur.

**Her segment**, birden fazla **section**’a daha da **bölünebilir**. **Load command structure**, ilgili segment içindeki **bu section’lar** hakkında **bilgi** içerir.

Header’da önce **segment header**’ı bulursunuz:

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

Bu header, ardından gelen **header’ların sayısını** tanımlar:
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
**bölüm başlığı** örneği:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

**bölüm ofseti** (0x37DC) + **arch'in başladığı** **ofset**i, bu durumda `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

**header** bilgilerini **komut satırından** şu şekilde almak da mümkündür:
```bash
otool -lv /bin/ls
```
Ortak segmentler bu cmd tarafından yüklenir:

- **`__PAGEZERO`:** Kernel'e **address zero**'ı **map** etmesini söyler, böylece **okunamaz, yazılamaz veya çalıştırılamaz**. Yapı içindeki maxprot ve minprot değişkenleri, bu sayfada **read-write-execute yetkisi olmadığını** belirtmek için sıfıra ayarlanır.
- Bu allocation, **NULL pointer dereference vulnerabilities** azaltmak için önemlidir. Çünkü XNU, ilk sayfanın (yalnızca ilki) belleğe erişilemez olmasını sağlayan sabit bir page zero uygular (i386 hariç). Bir binary, ilk 4k'yı kapsayacak küçük bir \_\_PAGEZERO (`-pagezero_size` kullanarak) oluşturarak ve 32bit memory'nin geri kalanını hem user hem de kernel mode'da erişilebilir bırakarak bu gereksinimi karşılayabilir.
- **`__TEXT`**: **read** ve **execute** izinlerine sahip **executable** **code** içerir (writable değil)**.** Bu segmentin yaygın section'ları:
- `__text`: Derlenmiş binary code
- `__const`: Sabit data (yalnızca okunur)
- `__[c/u/os_log]string`: C, Unicode veya os logs string sabitleri
- `__stubs` ve `__stubs_helper`: dynamic library loading sürecinde yer alır
- `__unwind_info`: Stack unwind data.
- Bu içeriğin tamamının imzalı olduğunu, ancak aynı zamanda executable olarak işaretlendiğini unutmayın (bu da string'e ayrılmış section'lar gibi normalde bu yetkiye ihtiyaç duymayan section'ların exploitation'ı için daha fazla seçenek oluşturur).
- **`__DATA`**: **readable** ve **writable** data içerir (executable değil)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Read-only data olmalı (gerçekte değil)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (initialize edilmiş olanlar)
- `__bss`: Static variables (initialize edilmemiş olanlar)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, vb): Objective-C runtime tarafından kullanılan bilgi
- **`__DATA_CONST`**: \_\_DATA.\_\_const'un constant olduğu garanti edilmez (write permissions vardır), diğer pointers ve GOT da öyle. Bu section, `mprotect` kullanarak `__const`, bazı initializers ve GOT table'ı (bir kez çözümlendiğinde) **read only** yapar.
- **`__AUTH` / `__AUTH_CONST`**: Son Apple Silicon binary'lerinde yaygındır. Bu segmentler, load veya use zamanında authenticate edilmesi gereken pointers'ı tutar (örneğin `__auth_got`). Bir rebinding, hook veya import-patching tekniği yalnızca eski `__got` / `__la_symbol_ptr` section'larını kontrol ediyorsa, modern `arm64e` binary'lerdeki gerçek call site'ları kaçırabilir. Bu section'lar hakkında daha fazla detay için [bu sayfaya](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) bakın.
- **`__LINKEDIT`**: Linker (`dyld`) için symbol, string ve relocation table entries gibi bilgileri içerir. `__TEXT` veya `__DATA` içinde olmayan içerikler için genel bir container'dır ve içeriği diğer load commands içinde tanımlanır.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes ve export info
- Functions starts: Functions'ın başlangıç adresleri tablosu
- Data In Code: `__text` içindeki data islands
- SYmbol Table: Binary içindeki symbols
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Objective-C runtime tarafından kullanılan bilgi içerir. Bu bilgi `__DATA` segmentinde, çeşitli \_\_objc\_\* section'ları içinde de bulunabilir.
- **`__RESTRICT`**: İçerik içermeyen, tek section'ı **`__restrict`** olan (o da boş) bir segmenttir; binary çalıştırıldığında DYLD environmental variables'ı yok saymasını sağlar.

Kodda görülebileceği gibi, **segmentler flags de destekler** (her ne kadar pek kullanılmasalar da):

- `SG_HIGHVM`: Sadece core (kullanılmaz)
- `SG_FVMLIB`: Kullanılmaz
- `SG_NORELOC`: Segment relocation içermez
- `SG_PROTECTED_VERSION_1`: Encryption. Örneğin Finder tarafından text `__TEXT` segmentini encrypt etmek için kullanılır.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** **entryoff attribute** içinde entrypoint'i içerir. Load zamanında, **dyld** bu değeri basitçe binary'nin (memory içindeki) **base**'ine **ekler**, ardından binary’nin code'unu çalıştırmak için bu instruction'a **jump** eder.

**`LC_UNIXTHREAD`** ana thread başlarken register'ların sahip olması gereken değerleri içerir. Bu zaten deprecated oldu ancak **`dyld`** hâlâ kullanır. Bunun ayarladığı register değerlerini şununla görmek mümkündür:
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


**Mach-O dosyasının code signature’ı** hakkında bilgi içerir. Yalnızca **signature blob**’a **işaret eden** bir **offset** içerir. Bu genellikle dosyanın en sonunda bulunur.\
Ancak, bu bölüm hakkında bazı bilgileri [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) ve [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) içinde bulabilirsiniz.

### **`LC_ENCRYPTION_INFO[_64]`**

Binary encryption desteği. Ancak elbette, bir saldırgan süreci ele geçirmeyi başarırsa, memory’yi şifrelenmemiş olarak dump edebilir.

### **`LC_LOAD_DYLINKER`**

Shared libraries’i process address space içine map eden **dynamic linker executable**’ın **path**’ini içerir. **Değer her zaman `/usr/lib/dyld` olarak ayarlanır**. macOS’ta dylib mapping’in **user mode**’da, kernel mode’da değil, gerçekleştiğini not etmek önemlidir.

### **`LC_IDENT`**

Kullanım dışıdır, ancak panic sırasında dump oluşturacak şekilde ayarlandığında, bir Mach-O core dump oluşturulur ve kernel version `LC_IDENT` komutunda ayarlanır.

### **`LC_UUID`**

Rastgele UUID. Tek başına doğrudan hiçbir şey için çok faydalı değildir, ancak XNU bunu process bilgileriyle birlikte cache’ler. crash reports içinde kullanılabilir.

### **`LC_BUILD_VERSION`**

Modern binary’ler genellikle bu komutu kullanarak **target platform**’u, **minimum OS version**’ı, **SDK version**’ı ve isteğe bağlı olarak o slice’ı build etmek için kullanılan **tool versions**’ı bildirir. Offensive/reversing açısından bu, bir sample’ın nasıl build edildiğini fingerprint etmek ve bir slice’ın farklı bir SDK ya da deployment target ile compile edildiği tuhaf universal binaries’yi hızlıca fark etmek için çok faydalıdır. Eski binary’ler bunun yerine hâlâ `LC_VERSION_MIN_*` kullanabilir.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

dyld'a işlem yürütülmeden önce environment variables belirtmeye izin verir. Bu, çok tehlikeli olabilir; çünkü process içinde arbitrary code execute edilmesine izin verebilir. Bu nedenle bu load command yalnızca `#define SUPPORT_LC_DYLD_ENVIRONMENT` ile build edilmiş dyld içinde kullanılır ve ayrıca processing'i sadece yükleme path'lerini belirten `DYLD_..._PATH` formundaki variables ile sınırlar.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Recent toolchains sıklıkla export/bind/rebase metadata'sını yalnızca eski `LC_DYLD_INFO[_ONLY]` opcodes'a güvenmek yerine bu commands içinde saklar. İkisi de **`__LINKEDIT`** içine işaret eden `linkedit_data_command` entries'dir:

- **`LC_DYLD_EXPORTS_TRIE`**: Image tarafından export edilen symbols ile compact trie.
- **`LC_DYLD_CHAINED_FIXUPS`**: dyld'nin rebases ve binds uygulamak için kullandığı per-segment fixup chains. Apple Silicon üzerinde bu aynı zamanda birçok modern authenticated pointer fixup ile karşılaşacağınız yerdir.

Bu metadata, imports/exports'u yeniden oluştururken, bir `@rpath`-loaded dependency'nin neden o şekilde resolve edildiğini anlamada ya da modern bir `arm64e` target'ta bir hook/rebinding denemesinin neden başarısız olduğunu bulmada çok kullanışlıdır. `dyld_info`, disk üzerinde bağımsız dosyalar olarak bulunmayan **cache-only dylib paths** üzerinde de kullanılabilir; bu da modern macOS'ta birçok system library'nin yalnızca shared cache içinde yaşaması nedeniyle oldukça faydalıdır.
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Bu modern load command, çoğunlukla **kernel collections / kernelcache-style filesets** incelerken önemlidir. Tek başına bağımsız bir image temsil etmek yerine, dıştaki Mach-O bir container gibi davranır ve her `LC_FILESET_ENTRY`, kendi path-like **entry id**'si, VM address'i ve file offset'i olan gömülü bir Mach-O'ya işaret eder. Modern macOS/iOS kernel bileşenlerini reverse ederken, bu command genellikle üst seviye container ile çıkarmak veya disassemble etmek istediğiniz gerçek image arasındaki köprüdür.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Pratik extraction iş akışları için, [macOS kernel extensions and kernelcache hakkında bu diğer sayfaya](../mac-os-architecture/macos-kernel-extensions.md) bakın.

### **`LC_LOAD_DYLIB`**

Bu load command, **loader**’a (dyld) belirtilen library’yi **yüklemesi ve linklemesi** için talimat veren bir **dynamic** **library** bağımlılığını açıklar. Mach-O binary’nin ihtiyaç duyduğu **her library için** bir `LC_LOAD_DYLIB` load command vardır.

- Bu load command, **`dylib_command`** türünde bir yapıdır (bu yapı, gerçek bağımlı dynamic library’yi tanımlayan bir struct dylib içerir):
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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t compatibility version; / library's compatibility vers number /](<../../../images/image (486).png>)

Bu bilgiyi ayrıca cli üzerinden şununla da alabilirsiniz:
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
- **CoreWLAN**: Wifi taramaları.

> [!TIP]
> Bir Mach-O binary, **LC_MAIN** içinde belirtilen adresin **öncesinde** **çalıştırılacak** bir veya **birden fazla** **constructor** içerebilir.\
> Herhangi bir constructor’ın offset’leri, **\_\_DATA_CONST** segmentindeki **\_\_mod_init_func** section’ında tutulur.

## **Mach-O Data**

Dosyanın merkezinde, load-commands region’da tanımlandığı şekilde birkaç segmentten oluşan data region yer alır. **Her segment içinde çeşitli data section’ları bulunabilir** ve her section türüne özgü code veya data **tutar**.

> [!TIP]
> Data, temelde load commands **LC_SEGMENTS_64** tarafından yüklenen tüm **bilgileri** içeren kısımdır

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Buna şunlar dahildir:

- **Function table:** Program function’ları hakkında bilgi tutar.
- **Symbol table**: Binary tarafından kullanılan external function hakkında bilgi içerir
- Ayrıca internal function, variable names ve daha fazlasını da içerebilir.

Bunu kontrol etmek için [**Mach-O View**](https://sourceforge.net/projects/machoview/) aracını kullanabilirsiniz:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Ya da cli’dan:
```bash
size -m /bin/ls
```
## Objetive-C Common Sections

`__TEXT` segmentinde (r-x):

- `__objc_classname`: Sınıf adları (strings)
- `__objc_methname`: Method adları (strings)
- `__objc_methtype`: Method türleri (strings)

`__DATA` segmentinde (rw-):

- `__objc_classlist`: Tüm Objetive-C sınıflarına işaretçiler
- `__objc_nlclslist`: Non-Lazy Objective-C sınıflarına işaretçiler
- `__objc_catlist`: Categories için pointer
- `__objc_nlcatlist`: Non-Lazy Categories için pointer
- `__objc_protolist`: Protocols listesi
- `__objc_const`: Sabit data
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
{{#include ../../../banners/hacktricks-training.md}}
