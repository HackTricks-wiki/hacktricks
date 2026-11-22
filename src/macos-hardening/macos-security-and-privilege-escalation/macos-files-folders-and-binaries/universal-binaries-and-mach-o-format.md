# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

macOS, **Mach-O** yürütülebilir dosya biçimini kullanır. **Universal** veya fat binary, tek bir dosyada birden fazla mimariye özgü Mach-O dilimi içerir. Apple'ın açık kaynaklı `fat.h` ve `loader.h` başlık dosyaları, bu sayfada açıklanan yapıları ve sabitleri tanımlar. <sup>[[5]](#references)</sup>

Bir Mach-O imajı şunlardan oluşur:

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

Header, **magic** baytlarını ve ardından dosyanın **içerdiği** **arch** sayısını (`nfat_arch`) taşır; her arch bir `fat_arch` yapısına sahiptir.

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

Tahmin edebileceğiniz gibi, genellikle 2 mimari için derlenen bir universal binary, yalnızca 1 arch için derlenenin **iki katı boyutundadır**.

> [!TIP]
> Malware veya şüpheli uygulamaları incelerken, `file` komutunun "en uygun" mimariyi bildirmesiyle yetinmeyin. Bir universal binary, her dilimde farklı import'lar, load command'ler veya derleyici metaverileri içerebilir; bu nedenle önce **tüm** dilimleri listeleyin, ardından her birini ayrı ayrı inceleyin:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Güncel macOS SDK’ları, `<mach-o/utils.h>` içinde `macho_for_each_slice()` ve `macho_best_slice()` işlevlerini de sunar. Apple Silicon’da `macho_best_slice()`, macOS 15’ten önce çalıştırılabilir bir üçüncü taraf `arm64` binary’si için yanlışlıkla `EBADARCH` döndürebilirdi; API, macOS 15’te düzeltildi. Her slice’ı envantere almak için `macho_for_each_slice()` veya `lipo -archs` kullanın; başarısız bir en iyi-slice aramasını hiçbir slice’ın çalışamayacağının kanıtı olarak değerlendirmeyin.<sup>[[1]](#references)[[7]](#references)</sup>

### Slice'lar arasındaki code signature'ları karşılaştırma

Universal binary içindeki her mimarinin kendine ait bir CodeDirectory ve CDHash’i vardır. İmzalı bir executable’ı veya ayrıcalıklı bir helper’ı denetlerken **her slice’ın signature’ını** inceleyin. CDHash’lerin farklı olması normaldir; bunun yerine imzalama kimliğini, CodeDirectory flag’lerini ve entitlements’ı karşılaştırın.<sup>[[8]](#references)</sup>

CDHash ile eşleşen politikalar için tek bir hash, mimariye özgü yalnızca bir yürütme yolunu tanımlar. Apple, slice’ları listelemeyi ve her birini incelemek için `codesign --arch` kullanmayı önerir.<sup>[[9]](#references)</sup>

```bash
BIN=/path/to/executable
for A in $(lipo -archs "$BIN"); do
  printf "\n== %s ==\n" "$A"
  codesign -dvvv --arch "$A" "$BIN" 2>&1
  codesign -d --entitlements - --arch "$A" "$BIN"
done
```

İmza yapısı ve doğrulama ayrıntıları için bkz. [macOS Code Signing](../macos-security-protections/macos-code-signing.md).

## **Mach-O Başlığı**

Başlık, dosyanın Mach-O dosyası olduğunu belirleyen magic byte'lar ve hedef mimari hakkındaki bilgiler gibi temel bilgileri içerir. Şurada bulabilirsiniz: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

Farklı dosya türleri vardır; bunları [**örneğin buradaki kaynak kodunda**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) bulabilirsiniz. En önemlileri şunlardır:

- `MH_OBJECT`: Yer değiştirebilir nesne dosyası (derlemenin ara ürünleri; henüz çalıştırılabilir dosya değildir).
- `MH_EXECUTE`: Çalıştırılabilir dosyalar.
- `MH_FVMLIB`: Sabit VM kütüphane dosyası.
- `MH_CORE`: Kod dökümleri.
- `MH_PRELOAD`: Önceden yüklenmiş çalıştırılabilir dosya (XNU'da artık desteklenmiyor).
- `MH_DYLIB`: Dinamik kütüphaneler.
- `MH_DYLINKER`: Dinamik bağlayıcı.
- `MH_BUNDLE`: "Eklenti dosyaları". gcc'de -bundle kullanılarak oluşturulur ve `NSBundle` veya `dlopen` tarafından açıkça yüklenir.
- `MH_DSYM`: Yardımcı `.dSYM` dosyası (hata ayıklama sembollerini içeren dosya).
- `MH_KEXT_BUNDLE`: Kernel uzantıları.

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

Kaynak kod, library yüklemek için yararlı olan birkaç flag de tanımlar:

- `MH_NOUNDEFS`: Tanımsız başvuru yok (tamamen linklenmiş)
- `MH_DYLDLINK`: Dyld bağlantısı
- `MH_PREBOUND`: Dynamic başvurular önceden bağlanmış.
- `MH_SPLIT_SEGS`: Dosya, r/o ve r/w segmentlerine ayrılır.
- `MH_WEAK_DEFINES`: Binary, weak tanımlı semboller içerir
- `MH_BINDS_TO_WEAK`: Binary, weak semboller kullanır
- `MH_ALLOW_STACK_EXECUTION`: Stack'in yürütülebilir olmasını sağlar
- `MH_NO_REEXPORTED_DYLIBS`: Library'de LC_REEXPORT komutları yok
- `MH_PIE`: Konumdan Bağımsız Yürütülebilir Dosya
- `MH_HAS_TLV_DESCRIPTORS`: Thread local değişkenleri içeren bir section vardır
- `MH_NO_HEAP_EXECUTION`: Heap/data sayfalarında yürütme yok
- `MH_HAS_OBJC`: Binary, Objective-C section'ları içerir
- `MH_SIM_SUPPORT`: Simulator desteği
- `MH_DYLIB_IN_CACHE`: Paylaşılan library cache'indeki dylib/framework'lerde kullanılır.

## **Mach-O Load commands**

**Dosyanın bellekteki düzeni** burada belirtilir; **sembol tablosunun konumu**, yürütme başlangıcında ana thread'in bağlamı ve gerekli **shared library'ler** ayrıntılandırılır. Dynamic loader'a **(dyld)** binary'nin belleğe yüklenme süreciyle ilgili talimatlar verilir.

Bahsedilen **`loader.h`** dosyasında tanımlanan **load_command** yapısını kullanır:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Sistemin farklı şekilde ele aldığı yaklaşık **50 farklı yükleme komutu türü** vardır. En yaygın olanları: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` ve `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Temel olarak bu tür Yükleme Komutu, binary çalıştırıldığında **Veri bölümünde belirtilen offset'lere** göre **\_\_TEXT** (çalıştırılabilir kod) ve **\_\_DATA** (sürece ait veriler) **segmentlerinin nasıl yükleneceğini tanımlar**.

Bu komutlar, bir süreç çalıştırıldığında sürecin **sanal bellek alanına eşlenen segmentleri tanımlar**.

**\_\_TEXT** segmenti (programın çalıştırılabilir kodunu içerir) ve sürecin kullandığı verileri içeren **\_\_DATA** segmenti gibi **farklı segment türleri** vardır. Bu **segmentler, Mach-O dosyasının veri bölümünde bulunur**.

**Her segment**, birden fazla **bölüme** ayrılabilir. **Yükleme komutu yapısı**, ilgili segment içindeki **bu bölümler hakkında bilgi** içerir.

Başlıkta önce **segment başlığını** bulursunuz:

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

Segment başlığı örneği:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Bu başlık, **başlığın ardından gelen bölüm başlıklarının sayısını** tanımlar:

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

**section offset** (0x37DC) değerini, bu durumda `0x18000` olan **arch starts** konumundaki **offset** değerine eklerseniz --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

**headers information** bilgisini **komut satırından** almak da mümkündür:

```bash
otool -lv /bin/ls
```

Bu komut tarafından yüklenen yaygın segmentler:

- **`__PAGEZERO`:** Kernel'e **sıfır adresini**, **okunamayacak, yazılamayacak veya çalıştırılamayacak** şekilde **eşlemesini** söyler. Yapıdaki maxprot ve minprot değişkenleri, **bu sayfada okuma-yazma-çalıştırma izinleri olmadığını** belirtmek için sıfıra ayarlanır.
  - Bu tahsis, **NULL pointer dereference güvenlik açıklarını azaltmak** için önemlidir. Bunun nedeni, XNU'nun ilk bellek sayfasının (yalnızca ilkinin) erişilemez olmasını sağlayan sabit bir page zero uygulamasıdır (i386 hariç). Bir binary, ilk 4k'yı kapsayacak küçük bir \_\_PAGEZERO oluşturarak (`-pagezero_size` kullanarak) ve 32 bit belleğin geri kalanını hem user hem de kernel mode'da erişilebilir kılarak bu gereksinimleri karşılayabilir.
- **`__TEXT`**: **Okuma** ve **çalıştırma** izinlerine sahip (yazma izni olmayan) **çalıştırılabilir** **kod** içerir. Bu segmentin yaygın bölümleri:
  - `__text`: Derlenmiş binary kodu
  - `__const`: Sabit veriler (salt okunur)
  - `__[c/u/os_log]string`: C, Unicode veya os log dizge sabitleri
  - `__stubs` ve `__stubs_helper`: Dinamik kütüphane yükleme sürecinde kullanılır
  - `__unwind_info`: Stack unwind verileri.
  - Tüm bu içeriğin imzalandığını, ancak aynı zamanda çalıştırılabilir olarak işaretlendiğini unutmayın. Bu durum, bu ayrıcalığa mutlaka ihtiyaç duymayan bölümlerin (ör. dizgelere ayrılmış bölümler) exploit edilmesi için daha fazla seçenek oluşturur.
- **`__DATA`**: **Okunabilir** ve **yazılabilir** (çalıştırılabilir olmayan) veriler içerir.
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Non-lazy (yükleme sırasında bağlanır) sembol işaretçisi
  - `__la_symbol_ptr`: Lazy (kullanım sırasında bağlanır) sembol işaretçisi
  - `__const`: Salt okunur veri olmalıdır (aslında değil)
  - `__cfstring`: CoreFoundation dizgeleri
  - `__data`: Global değişkenler (başlatılmış olanlar)
  - `__bss`: Statik değişkenler (başlatılmamış olanlar)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist vb.): Objective-C runtime tarafından kullanılan bilgiler
- **`__DATA_CONST`**: \_\_DATA.\_\_const'un sabit olması (yazma izinlerine sahip olması) garanti edilmez; diğer işaretçiler ve GOT da öyle. Bu bölüm, `mprotect` kullanarak `__const`'u, bazı başlatıcıları ve çözümlendikten sonra GOT tablosunu **salt okunur** yapar.
- **`__AUTH` / `__AUTH_CONST`**: Yeni Apple Silicon binary'lerinde yaygındır. Bu segmentler, yükleme veya kullanım sırasında doğrulanması gereken işaretçileri tutar (örneğin `__auth_got`). Bir rebinding, hook veya import-patching tekniği yalnızca eski `__got` / `__la_symbol_ptr` bölümlerini kontrol ederse modern `arm64e` binary'lerindeki gerçek çağrı noktalarını gözden kaçırabilir. Bu bölümler hakkında daha fazla bilgi için [bu sayfaya](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) bakın.
- **`__LINKEDIT`**: Sembol, dizge ve relocation tablosu girdileri gibi linker (dyld) bilgilerini içerir. `__TEXT` veya `__DATA` içinde bulunmayan içerikler için genel bir kapsayıcıdır; içeriği diğer load command'lerde açıklanır.
  - dyld bilgileri: Rebase, Non-lazy/lazy/weak binding opcode'ları ve export bilgileri
  - Fonksiyon başlangıçları: Fonksiyonların başlangıç adresleri tablosu
  - Data In Code: \_\_text içindeki veri adacıkları
  - Sembol Tablosu: Binary'deki semboller
  - Dolaylı Sembol Tablosu: İşaretçi/stub sembolleri
  - Dizge Tablosu
  - Code Signature
- **`__OBJC`**: Objective-C runtime tarafından kullanılan bilgileri içerir. Bu bilgiler \_\_DATA segmentinde, çeşitli \_\_objc\_\* bölümlerinde de bulunabilir.
- **`__RESTRICT`**: **`__restrict`** adlı tek bir bölümü bulunan içeriksiz bir segmenttir (bu bölüm de boştur). Binary çalışırken DYLD ortam değişkenlerini yok saymasını sağlar.

Kodda görülebileceği gibi, **segmentler bayrakları da destekler** (ancak bunlar pek kullanılmaz):

- `SG_HIGHVM`: Yalnızca Core (kullanılmıyor)
- `SG_FVMLIB`: Kullanılmıyor
- `SG_NORELOC`: Segmentte relocation yok
- `SG_PROTECTED_VERSION_1`: Şifreleme. Örneğin Finder tarafından `__TEXT` segmentindeki metni şifrelemek için kullanılır.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`**, giriş noktasını **entryoff özniteliğinde** içerir. Yükleme sırasında **dyld** bu değeri binary'nin (bellekteki) **taban adresine ekler**, ardından binary kodunun çalışmasını başlatmak için bu talimata **atlar**.

**`LC_UNIXTHREAD`**, ana thread başlatılırken register'ların sahip olması gereken değerleri içerir. Bu özellik kullanımdan kaldırılmış olsa da **`dyld`** hâlâ kullanır. Bununla ayarlanan register değerlerini şu şekilde görebilirsiniz:

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


**Mach-O dosyasının code signature'ı** hakkında bilgi içerir. Yalnızca **signature blob'a** **işaret eden** bir **offset** içerir. Bu genellikle dosyanın en sonundadır.\
Bu bölüm hakkında daha fazla bilgiyi [**bu blog yazısında**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) ve [**bu gist'te**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) bulabilirsiniz.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Binary encryption desteği sağlar. Ancak elbette, bir saldırgan süreci ele geçirmeyi başarırsa belleği şifrelenmemiş hâlde dump edebilir.

### **`LC_LOAD_DYLINKER`**

Paylaşılan kütüphaneleri sürecin adres alanına eşleyen **dynamic linker executable'ının yolunu** içerir. **Değer her zaman `/usr/lib/dyld` olarak ayarlanır**. macOS'te dylib eşlemesinin kernel mode'da değil, **user mode'da** gerçekleştiğini belirtmek önemlidir.

### **`LC_IDENT`**

Kullanım dışıdır; ancak panic durumunda dump oluşturacak şekilde yapılandırıldığında bir Mach-O core dump oluşturulur ve kernel sürümü `LC_IDENT` komutunda ayarlanır.

### **`LC_UUID`**

Rastgele bir UUID'dir. Doğrudan herhangi bir işe yaramaz, ancak XNU bunu süreç bilgilerinin geri kalanıyla birlikte önbelleğe alır. Crash report'larda kullanılabilir.

### **`LC_BUILD_VERSION`**

Modern binary'lerde genellikle **hedef platformu**, **minimum OS sürümünü**, **SDK sürümünü** ve isteğe bağlı olarak bu slice'ı derlemek için kullanılan **tool sürümlerini** belirten bu komut bulunur. Offensive/reversing açısından bu, bir sample'ın nasıl derlendiğini belirlemek ve bir slice'ı farklı bir SDK veya deployment target ile derlenmiş garip universal binary'leri hızlıca tespit etmek için çok kullanışlıdır. Daha eski binary'lerde bunun yerine `LC_VERSION_MIN_*` kullanılabilir.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Süreci yürütülmeden önce dyld'ye environment variable'lar iletilmesini sağlar. Sürecin içinde arbitrary code yürütülmesine olanak tanıyabileceğinden bu çok tehlikeli olabilir. Bu nedenle bu load command yalnızca `#define SUPPORT_LC_DYLD_ENVIRONMENT` ile derlenen dyld'de kullanılır ve işleme yalnızca load path'leri belirten `DYLD_..._PATH` biçimindeki variable'larla sınırlandırılır.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Güncel toolchain'ler, yalnızca eski `LC_DYLD_INFO[_ONLY]` opcode'larına güvenmek yerine export/bind/rebase metadata'sını sıklıkla bu command'lerde saklar. Her ikisi de **`__LINKEDIT`** içindeki bir bölüme işaret eden `linkedit_data_command` girdileridir:

- **`LC_DYLD_EXPORTS_TRIE`**: Image'ın export ettiği symbol'leri içeren kompakt bir trie.
- **`LC_DYLD_CHAINED_FIXUPS`**: dyld'nin rebase ve bind işlemlerini uygulamak için kullandığı, segment başına fixup zincirleri. Apple Silicon'da birçok modern authenticated pointer fixup'ıyla da burada karşılaşırsınız.

Bu metadata; import/export'ları yeniden oluştururken, `@rpath` ile yüklenen bir dependency'nin neden o şekilde çözümlendiğini anlamaya çalışırken veya modern bir `arm64e` hedefinde bir hook/rebinding girişiminin neden başarısız olduğunu incelerken çok kullanışlıdır. `dyld_info`, diskte bağımsız dosyalar olarak bulunmayan **yalnızca cache'te bulunan dylib path'leri** üzerinde de kullanılabilir. Birçok sistem kütüphanesinin yalnızca shared cache'te bulunduğu modern macOS'te bu çok kullanışlıdır.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Bu modern load command, çoğunlukla **kernel collections / kernelcache-style filesets** incelenirken önem kazanır. Dış Mach-O, tek başına bir image'ı temsil etmek yerine bir container görevi görür ve her `LC_FILESET_ENTRY`, kendine ait path benzeri bir **entry id**, VM adresi ve dosya offset'i olan gömülü bir Mach-O'yu işaret eder. Modern macOS/iOS kernel bileşenlerini reverse engineering yaparken bu command, genellikle üst düzey container ile çıkarmak veya disassemble etmek istediğiniz gerçek image arasındaki bağlantıyı sağlar.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Pratik çıkarım iş akışları için [macOS kernel extensions and kernelcache hakkındaki bu diğer sayfaya](../mac-os-architecture/macos-kernel-extensions.md) bakın.

### **`LC_LOAD_DYLIB`**

Bu yükleme komutu, **yükleyiciye** (dyld) söz konusu kütüphaneyi **yükleyip bağlamasını bildiren** bir **dinamik kütüphane** bağımlılığını açıklar. Mach-O ikilisinin gerektirdiği **her kütüphane için** bir `LC_LOAD_DYLIB` yükleme komutu bulunur.

- Bu yükleme komutu, **`dylib_command`** türünde bir yapıdır (gerçek bağımlı dinamik kütüphaneyi açıklayan bir struct dylib içerir):

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t uyumluluk sürümü; / kitaplığın uyumluluk sürüm numarası /](<../../../images/image (486).png>)

Bu bilgiyi CLI üzerinden de şu komutla alabilirsiniz:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Bazı olası malware ile ilişkili kütüphaneler:

- **DiskArbitration**: USB sürücülerini izleme
- **AVFoundation:** Ses ve video yakalama
- **CoreWLAN**: Wi-Fi taramaları.

> [!TIP]
> Bir Mach-O binary, **LC_MAIN** içinde belirtilen adresten **önce** **çalıştırılan** bir veya **daha fazla** **constructor** içerebilir.\
> Constructor'ların offset'leri, **\_\_DATA_CONST** segmentindeki **\_\_mod_init_func** bölümünde tutulur.

## **Mach-O Verileri**

Dosyanın merkezinde, load-command bölgesinde tanımlanan çeşitli segmentlerden oluşan veri bölgesi bulunur. **Her segmentte çeşitli veri bölümleri bulunabilir** ve her bölüm belirli bir türe ait **kod veya veri** içerir.

> [!TIP]
> Veriler, temel olarak load command'ler **LC_SEGMENTS_64** tarafından yüklenen tüm **bilgileri** içeren bölümdür.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Bunlar şunları içerir:

- **Function table:** Program işlevleriyle ilgili bilgileri tutar.
- **Symbol table**: Binary tarafından kullanılan harici işlevlerle ilgili bilgileri içerir.
- Ayrıca dahili işlevleri, değişken adlarını ve daha fazlasını da içerebilir.

Bunu kontrol etmek için [**Mach-O View**](https://sourceforge.net/projects/machoview/) aracını kullanabilirsiniz:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Veya cli üzerinden:

```bash
size -m /bin/ls
```

### Eklenen veriler ve geriye doğru ayrıştırılan ek katmanlar

Bir loader, yapılandırmayı adlandırılmış bir Mach-O bölümü yerine eklenen verilerde tutabilir. Ardından bir reverse parser, sondaki bir işaretçiyi referans alır, hemen öncesinde saklanan boyutu okur ve bu değeri kullanarak önceki blob'un konumunu bulup şifresini çözer. Gözlemlenen bir universal loader, XOR ile şifrelenmiş bir downloader URL'si için bu düzeni kullanıyordu:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Bilinmeyen bir binary'yi analiz ederken, tanınabilir son işaretçilerin çevresindeki baytları inceleyin ve dizelerin veya yapılandırmanın bir load-command bölümüne ait olduğunu varsaymadan önce geriye dönük tüm boyut hesaplamalarını izleyin. İşaretçi ve XOR anahtarı örneğe özgüdür; yeniden kullanılabilir teknik, kendi kendini tanımlayan sondur.

## Objective-C Yaygın Bölümleri

`__TEXT` segmentinde (r-x):

- `__objc_classname`: Sınıf adları (dizeler)
- `__objc_methname`: Metot adları (dizeler)
- `__objc_methtype`: Metot türleri (dizeler)

`__DATA` segmentinde (rw-):

- `__objc_classlist`: Tüm Objective-C sınıflarına işaretçiler
- `__objc_nlclslist`: Non-Lazy Objective-C sınıflarına işaretçiler
- `__objc_catlist`: Category'lere işaretçi
- `__objc_nlcatlist`: Non-Lazy Category'lere işaretçi
- `__objc_protolist`: Protocol listesi
- `__objc_const`: Sabit veriler
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

Ayrıca bkz.: [Reflective Mach-O Loading](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [1] [Mach-O dilimleri düşündüğünüz kadar basit değil](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) man sayfası](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Kendi Entitlements'ınızı Okuma](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source - Mach-O `fat.h` ve `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - MacSync macOS stealer'ın yeni sürümü kripto meraklılarını ve geliştiricileri hedef alıyor](https://securelist.com/macsync-new-version/121383/)
- [7] [The Art of Mac Malware, Volume 2 — Binary'leri Ayrıştırma](https://taomm.org/vol2/pdfs/CH%202%20Parsing%20Binaries.pdf)
- [8] [Apple Developer — TN3126: Code Signing'in İç Yüzü: Hash'ler](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes.md)
- [9] [Apple Developer — Uygulamalara ve binary'lere izin verme ve bunları reddetme](https://developer.apple.com/documentation/devicemanagement/allowing-and-denying-apps-and-binaries.md)
{{#include ../../../banners/hacktricks-training.md}}
