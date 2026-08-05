# macOS Universal binaries ve Mach-O Biçimi

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Mac OS binary'leri genellikle **universal binary** olarak derlenir. Bir **universal binary**, **aynı dosya içinde birden fazla architecture'ı destekleyebilir**.

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

Header, **magic** byte'larını ve ardından dosyanın **içerdiği** **arch** sayısını (`nfat_arch`) barındırır; her arch bir `fat_arch` struct'ına sahip olur.

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

Tahmin edebileceğiniz gibi, 2 architecture için derlenen bir universal binary genellikle yalnızca 1 arch için derlenen binary'nin **boyutunu iki katına çıkarır**.

> [!TIP]
> Malware veya şüpheli uygulamaları triage ederken `file` komutunun "en uygun" architecture'ı bildirmesiyle yetinmeyin. Bir universal binary, her slice içinde farklı import'ları, load command'ları veya compiler metadata'sını gizleyebilir. Bu nedenle önce **tüm** slice'ları enumerate edin, ardından her birini bağımsız olarak inceleyin:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Güncel macOS SDK'ları ayrıca `<mach-o/utils.h>` içinde `macho_for_each_slice()` ve `macho_best_slice()` gibi yardımcılar da sunar. İkincisi, dyld/kernel'in yükleyeceği şeyi taklit etmek için kullanışlıdır; ancak scanner'lar arch-specific içerikleri gözden kaçırmamak için yine de her slice'ı taramalıdır.<sup>[1]</sup>

## **Mach-O Header**

Header, dosyayı Mach-O dosyası olarak tanımlayan magic bytes ve hedef mimari hakkındaki bilgiler gibi dosyaya ilişkin temel bilgileri içerir. Şu komutla bulabilirsiniz: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Farklı dosya türleri vardır; bunların tanımlarını [**örneğin buradaki kaynak kodunda bulabilirsiniz**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). En önemlileri şunlardır:

- `MH_OBJECT`: Relocatable object file (derlemenin ara ürünleri, henüz executable değildir).
- `MH_EXECUTE`: Executable files.
- `MH_FVMLIB`: Fixed VM library file.
- `MH_CORE`: Kod dökümleri.
- `MH_PRELOAD`: Preloaded executable file (artık XNU tarafından desteklenmiyor).
- `MH_DYLIB`: Dynamic Libraries.
- `MH_DYLINKER`: Dynamic Linker.
- `MH_BUNDLE`: "Plugin files". gcc'de -bundle kullanılarak oluşturulur ve `NSBundle` veya `dlopen` tarafından açıkça yüklenir.
- `MH_DYSM`: Companion `.dSym` file (debugging için semboller içeren dosya).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Veya [Mach-O View](https://sourceforge.net/projects/machoview/) kullanarak:

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

Kaynak kod ayrıca library'leri yüklemek için kullanışlı birkaç flag tanımlar:

- `MH_NOUNDEFS`: Undefined reference yok (fully linked)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamic reference'lar prebound.
- `MH_SPLIT_SEGS`: Dosya r/o ve r/w segment'lerine ayrılır.
- `MH_WEAK_DEFINES`: Binary, weak olarak tanımlanmış symbol'lere sahip
- `MH_BINDS_TO_WEAK`: Binary, weak symbol'ler kullanır
- `MH_ALLOW_STACK_EXECUTION`: Stack'i executable yapar
- `MH_NO_REEXPORTED_DYLIBS`: Library'de LC_REEXPORT command'ları yok
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Thread-local variable'ların bulunduğu bir section vardır
- `MH_NO_HEAP_EXECUTION`: Heap/data page'leri için execution yok
- `MH_HAS_OBJC`: Binary, Objective-C section'larına sahip
- `MH_SIM_SUPPORT`: Simulator desteği
- `MH_DYLIB_IN_CACHE`: Shared library cache içindeki dylib/framework'lerde kullanılır.

## **Mach-O Load commands**

**Dosyanın memory'deki yerleşimi** burada belirtilir; **symbol table'ın konumu**, execution başlangıcında main thread'in context'i ve gerekli **shared library**'ler ayrıntılandırılır. Dynamic loader'a **(dyld)** binary'nin memory'ye yüklenme süreciyle ilgili talimatlar sağlanır.

Bu işlem, bahsedilen **`loader.h`** içinde tanımlanan **load_command** structure'ını kullanır:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Sistemin farklı şekilde işlediği yaklaşık **50 farklı load command türü** vardır. En yaygın olanlar şunlardır: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` ve `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Temel olarak bu Load Command türü, binary çalıştırıldığında **Data bölümünde belirtilen offset'lere** göre **\_\_TEXT** (çalıştırılabilir kod) ve **\_\_DATA** (process için veriler) **segment'lerinin nasıl yükleneceğini tanımlar**.

Bu komutlar, çalıştırıldığında bir process'in **virtual memory space**'ine **map edilen** **segment'leri tanımlar**.

Programın çalıştırılabilir kodunu tutan **\_\_TEXT** segment'i ve process tarafından kullanılan verileri içeren **\_\_DATA** segment'i gibi **farklı segment türleri** vardır. Bu **segment'ler Mach-O dosyasının data bölümünde bulunur**.

**Her segment** birden fazla **section'a** ayrılabilir. **Load command yapısı**, ilgili segment içindeki **bu section'lar hakkında bilgi** içerir.

Header'da önce **segment header'ı** bulursunuz:

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

Bu header, **header'ları kendisinden sonra gelen section'ların sayısını tanımlar**:
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

**section offset** değerini (0x37DC) bu durumda `0x18000` olan **arch starts** offsetine **eklerseniz** --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Ayrıca **headers bilgilerini** şu komut satırıyla elde etmek de mümkündür:
```bash
otool -lv /bin/ls
```
Bu cmd tarafından yüklenen yaygın segmentler:

- **`__PAGEZERO`:** Kernel'e **address zero** değerini **map** etmesini ve bu değerin **okunamamasını, yazılamamasını veya çalıştırılamamasını** bildirir. Yapıdaki maxprot ve minprot değişkenleri, **bu sayfada read-write-execute haklarının bulunmadığını** belirtmek için sıfıra ayarlanır.
- Bu allocation, **NULL pointer dereference vulnerabilities** riskini azaltmak için önemlidir. Bunun nedeni, XNU'nun ilk memory sayfasının (yalnızca ilk sayfa) erişilemez olmasını sağlayan hard page zero uygulamasıdır (i386 hariç). Bir binary, ilk 4k'yı kapsayacak küçük bir \_\_PAGEZERO oluşturarak ( `-pagezero_size` kullanarak) ve 32bit memory'nin geri kalanını hem user hem de kernel mode'da erişilebilir hâle getirerek bu gereksinimi karşılayabilir.
- **`__TEXT`**: **read** ve **execute** izinlerine sahip **executable** **code** içerir (writable değildir)**.** Bu segmentin yaygın section'ları:
- `__text`: Derlenmiş binary code
- `__const`: Sabit data (read only)
- `__[c/u/os_log]string`: C, Unicode veya os logs string sabitleri
- `__stubs` ve `__stubs_helper`: Dynamic library loading sürecinde kullanılır
- `__unwind_info`: Stack unwind data'sı.
- Tüm bu içeriğin signed olduğunu, ancak aynı zamanda executable olarak işaretlendiğini unutmayın (string dedicated sections gibi bu ayrıcalığa mutlaka ihtiyaç duymayan section'ların exploitation'ı için daha fazla seçenek oluşturur).
- **`__DATA`**: **readable** ve **writable** olan (executable olmayan) data içerir)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (load sırasında bind edilen) symbol pointer
- `__la_symbol_ptr`: Lazy (kullanım sırasında bind edilen) symbol pointer
- `__const`: Read-only data olması gerekir (aslında değil)
- `__cfstring`: CoreFoundation string'leri
- `__data`: Global variables (initialize edilmiş)
- `__bss`: Static variables (initialize edilmemiş)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, vb.): Objective-C runtime tarafından kullanılan bilgiler
- **`__DATA_CONST`**: \_\_DATA.\_\_const değerinin constant olması (write permissions) garanti edilmez; diğer pointer'lar ve GOT için de aynı durum geçerlidir. Bu section, `mprotect` kullanarak `__const` değerini, bazı initializer'ları ve GOT table'ı (resolved olduktan sonra) **read only** hâle getirir.
- **`__AUTH` / `__AUTH_CONST`**: Recent Apple Silicon binaries içinde yaygındır. Bu segment'ler, load veya kullanım sırasında authenticate edilmesi gereken pointer'ları barındırır (örneğin `__auth_got`). Bir rebinding, hook veya import-patching trick'i yalnızca legacy `__got` / `__la_symbol_ptr` section'larını kontrol ederse modern `arm64e` binaries içindeki gerçek call site'larını gözden kaçırabilir. Bu section'lar hakkında daha fazla detay için [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) sayfasına bakın.
- **`__LINKEDIT`**: Symbol, string ve relocation table entry'leri gibi linker (dyld) için gerekli bilgileri içerir. `__TEXT` veya `__DATA` içinde bulunmayan içerikler için generic bir container'dır ve içeriği diğer load command'lerde açıklanır.
- dyld bilgileri: Rebase, Non-lazy/lazy/weak binding opcode'ları ve export bilgileri
- Functions starts: Function'ların başlangıç address'lerinin table'ı
- Data In Code: \_\_text içindeki data island'ları
- SYmbol Table: Binary içindeki symbol'ler
- Indirect Symbol Table: Pointer/stub symbol'leri
- String Table
- Code Signature
- **`__OBJC`**: Objective-C runtime tarafından kullanılan bilgileri içerir. Bu bilgiler \_\_DATA segment'inde, çeşitli \_\_objc\_\* section'ları içinde de bulunabilir.
- **`__RESTRICT`**: `__restrict` adlı tek bir section içeren (bu section da boştur) içeriksiz bir segment'tir; binary çalıştırılırken DYLD environmental variable'larını yok saymasını sağlar.

Kodda görülebileceği üzere, **segment'ler flag'leri de destekler** (her ne kadar çok fazla kullanılmasalar da):

- `SG_HIGHVM`: Yalnızca Core (kullanılmıyor)
- `SG_FVMLIB`: Kullanılmıyor
- `SG_NORELOC`: Segment'te relocation yok
- `SG_PROTECTED_VERSION_1`: Encryption. Örneğin Finder tarafından `__TEXT` segment'ini encrypt etmek için kullanılır.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`**, **entrypoint'i `entryoff` attribute'unda** barındırır. Load sırasında **dyld**, bu değeri (memory içindeki) **binary'nin base** değerine ekler ve ardından binary'nin code'unun execution'ını başlatmak için bu instruction'a **jump** eder.

**`LC_UNIXTHREAD`**, main thread başlatılırken register'ların sahip olması gereken değerleri içerir. Bu özellik artık deprecated olmasına rağmen **`dyld`** hâlâ bunu kullanır. Bununla ayarlanan register değerlerini şu komutla görmek mümkündür:
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


**Macho-O dosyasının code signature bilgilerini** içerir. Yalnızca **signature blob'a işaret eden** bir **offset** içerir. Bu genellikle dosyanın en sonunda bulunur.\
Ancak bu bölüm hakkında bazı bilgileri [**bu blog yazısında**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) ve şu [**gist'lerde**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) bulabilirsiniz.<sup>[3][4]</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Binary encryption desteği sağlar. Ancak elbette bir attacker process'i compromise etmeyi başarırsa, memory'yi unencrypted olarak dump edebilir.

### **`LC_LOAD_DYLINKER`**

Shared libraries'leri process address space'ine map eden **dynamic linker executable'ın path'ini** içerir. **Değer her zaman `/usr/lib/dyld` olarak ayarlanır**. macOS'ta dylib mapping işleminin kernel mode'da değil, **user mode'da** gerçekleştiğini belirtmek önemlidir.

### **`LC_IDENT`**

Obsolete olmasına rağmen panic durumunda dump'lar oluşturacak şekilde yapılandırıldığında bir Mach-O core dump oluşturulur ve kernel version `LC_IDENT` command'ında ayarlanır.

### **`LC_UUID`**

Random UUID. Doğrudan herhangi bir şey için kullanışlı değildir, ancak XNU bunu process info'nun geri kalanıyla birlikte cache'ler. Crash report'larda kullanılabilir.

### **`LC_BUILD_VERSION`**

Modern binary'ler genellikle **target platform'u**, **minimum OS version'ı**, **SDK version'ı** ve isteğe bağlı olarak ilgili slice'ı oluşturmak için kullanılan **tool version'larını** belirtmek üzere bu command'ı içerir. Offensive/reversing açısından bu, bir sample'ın nasıl build edildiğini fingerprint etmek ve bir slice'ın farklı bir SDK veya deployment target ile compile edildiği garip universal binary'leri hızlıca tespit etmek için oldukça kullanışlıdır. Daha eski binary'ler bunun yerine hâlâ `LC_VERSION_MIN_*` kullanabilir.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Process yürütülmeden önce dyld'e environment variables belirtmeye olanak tanır. Bu, process içinde arbitrary code yürütülmesine izin verebildiğinden oldukça dangerous olabilir. Bu nedenle bu load command yalnızca `#define SUPPORT_LC_DYLD_ENVIRONMENT` ile derlenen dyld sürümlerinde kullanılır ve işleme, yalnızca load paths belirten `DYLD_..._PATH` biçimindeki variables ile further sınırlandırılır.

### **`LC_DYLD_EXPORTS_TRIE` ve `LC_DYLD_CHAINED_FIXUPS`**

Recent toolchains, export/bind/rebase metadata'sını yalnızca eski `LC_DYLD_INFO[_ONLY]` opcodes'larına güvenmek yerine sıklıkla bu commands içinde depolar. Her ikisi de **`__LINKEDIT`** içine işaret eden `linkedit_data_command` entries'idir:

- **`LC_DYLD_EXPORTS_TRIE`**: Image tarafından exported edilen symbols'ları içeren compact trie.
- **`LC_DYLD_CHAINED_FIXUPS`**: dyld tarafından rebases ve binds uygulamak için kullanılan, segment başına fixup chains. Apple Silicon üzerinde birçok modern authenticated pointer fixup'ı da burada bulabilirsiniz.

Bu metadata, imports/exports yeniden oluşturulurken, `@rpath` ile yüklenen bir dependency'nin neden bu şekilde resolve edildiğini anlamada veya modern bir `arm64e` target'ında hook/rebinding attempt'inin neden başarısız olduğunu belirlemede oldukça kullanışlıdır. `dyld_info`, diskte standalone files olarak bulunmayan **cache-only dylib paths** üzerinde de kullanılabilir. Bu, birçok system library'nin yalnızca shared cache içinde bulunduğu modern macOS'ta oldukça kullanışlıdır.<sup>[2]</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Bu modern load command, çoğunlukla **kernel collections / kernelcache-style filesets** incelenirken önem taşır. Tek başına bir image'i temsil etmek yerine, dış Mach-O bir container görevi görür ve her `LC_FILESET_ENTRY`, kendine ait yol benzeri bir **entry id**, VM adresi ve dosya offset'i bulunan gömülü bir Mach-O'yu işaret eder. Modern macOS/iOS kernel bileşenlerini reverse engineering yapıyorsanız bu command, üst düzey container ile çıkarmak veya disassemble etmek istediğiniz gerçek image arasındaki bağlantıyı genellikle sağlar.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Pratik extraction iş akışları için [macOS kernel extensions ve kernelcache hakkındaki bu diğer sayfaya](../mac-os-architecture/macos-kernel-extensions.md) göz atın.

### **`LC_LOAD_DYLIB`**

Bu load command, **loader**'a (dyld) söz konusu **library**'yi **yükleyip bağlamasını** bildiren bir **dynamic** **library** bağımlılığını açıklar. Mach-O binary'nin ihtiyaç duyduğu **her library** için bir `LC_LOAD_DYLIB` load command bulunur.

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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t uyumluluk sürümü; / kütüphanenin uyumluluk sürüm numarası /](<../../../images/image (486).png>)

Bu bilgiyi cli üzerinden şu komutla da alabilirsiniz:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Bazı potansiyel malware ile ilişkili kütüphaneler şunlardır:

- **DiskArbitration**: USB sürücülerini izleme
- **AVFoundation:** Ses ve video yakalama
- **CoreWLAN**: WiFi taramaları.

> [!TIP]
> Bir Mach-O binary, **LC_MAIN** içinde belirtilen adresten önce **çalıştırılacak** bir veya **daha fazla** **constructor** içerebilir.\
> Herhangi bir constructor'ın offset değerleri, **\_\_DATA_CONST** segmentinin **\_\_mod_init_func** section'ında tutulur.

## **Mach-O Verileri**

Dosyanın merkezinde, load-commands bölgesinde tanımlanan birkaç segmentten oluşan veri bölgesi bulunur. **Her segment içinde çeşitli veri section'ları barındırılabilir** ve her section, belirli bir türe özgü **code veya data** içerir.

> [!TIP]
> Veriler temel olarak load command'ler tarafından yüklenen tüm **bilgileri** içeren ve **LC_SEGMENTS_64** tarafından yüklenen bölümdür.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Bunlar şunları içerir:

- **Function table:** Program fonksiyonları hakkındaki bilgileri tutar.
- **Symbol table**: Binary tarafından kullanılan external function hakkındaki bilgileri içerir.
- Ayrıca internal function'ları, variable name'lerini ve daha fazlasını da içerebilir.

Bunu kontrol etmek için [**Mach-O View**](https://sourceforge.net/projects/machoview/) aracını kullanabilirsiniz:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Veya cli üzerinden:
```bash
size -m /bin/ls
```
## Objective-C Common Sections

`__TEXT` segmentinde (r-x):

- `__objc_classname`: Sınıf adları (strings)
- `__objc_methname`: Method adları (strings)
- `__objc_methtype`: Method türleri (strings)

`__DATA` segmentinde (rw-):

- `__objc_classlist`: Tüm Objective-C sınıflarına işaretçiler
- `__objc_nlclslist`: Non-Lazy Objective-C sınıflarına işaretçiler
- `__objc_catlist`: Categories işaretçisi
- `__objc_nlcatlist`: Non-Lazy Categories işaretçisi
- `__objc_protolist`: Protocols listesi
- `__objc_const`: Sabit veriler
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## Kaynaklar

- [1] [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Reading Your Own Entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
