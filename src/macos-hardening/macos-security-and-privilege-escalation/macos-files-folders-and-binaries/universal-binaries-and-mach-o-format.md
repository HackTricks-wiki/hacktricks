# macOS Evrensel ikililer ve Mach-O biçimi

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

macOS, **Mach-O** yürütülebilir dosya biçimini kullanır. **Evrensel** veya fat ikili dosya, tek bir dosyada mimariye özgü birden fazla Mach-O dilimi içerir. Apple'ın açık kaynaklı `fat.h` ve `loader.h` başlık dosyaları, bu sayfada açıklanan yapıları ve sabitleri tanımlar. <sup>[[5]](#references)</sup>

Bir Mach-O görüntüsü şunlardan oluşur:

- Başlık
- Yükleme Komutları
- Veri

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Başlığı

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

Başlık, **magic** baytlarını ve ardından dosyanın **içerdiği** **mimari sayısını** (`nfat_arch`) barındırır; her mimari için bir `fat_arch` yapısı bulunur.

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

Tahmin edebileceğiniz gibi, 2 mimari için derlenen evrensel bir ikili dosyanın boyutu genellikle tek bir mimari için derlenen dosyanın **iki katıdır**.

> [!TIP]
> Malware veya şüpheli uygulamaları incelerken, `file` komutunun "en uygun" mimariyi bildirmesiyle yetinmeyin. Evrensel bir ikili dosyanın her diliminde farklı import'lar, yükleme komutları veya derleyici meta verileri bulunabilir; bu nedenle önce **tüm** dilimleri listeleyin, ardından her birini ayrı ayrı inceleyin:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Recent macOS SDK'ları `<mach-o/utils.h>` içinde `macho_for_each_slice()` ve `macho_best_slice()` gibi yardımcılar da sunar. İkincisi, dyld/kernel'in ne yükleyeceğini taklit etmek için kullanışlıdır; ancak tarayıcılar arch-specific içeriği gözden kaçırmamak için yine de her slice üzerinde gezinmelidir.<sup>[[1]](#references)</sup>

## **Mach-O Başlığı**

Başlık, dosyanın Mach-O dosyası olduğunu belirleyen magic byte'lar ve hedef mimari bilgileri gibi temel bilgileri içerir. Şu komutla bulabilirsiniz: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

Farklı dosya türleri vardır; bunları [**örneğin buradaki kaynak kodda**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) bulabilirsiniz. En önemlileri şunlardır:

- `MH_OBJECT`: Yeniden konumlandırılabilir nesne dosyası (derlemenin ara ürünleri; henüz yürütülebilir dosya değildir).
- `MH_EXECUTE`: Yürütülebilir dosyalar.
- `MH_FVMLIB`: Sabit VM kütüphane dosyası.
- `MH_CORE`: Kod dökümleri.
- `MH_PRELOAD`: Önceden yüklenmiş yürütülebilir dosya (XNU'da artık desteklenmiyor).
- `MH_DYLIB`: Dinamik kütüphaneler.
- `MH_DYLINKER`: Dinamik bağlayıcı.
- `MH_BUNDLE`: "Eklenti dosyaları". gcc'de -bundle kullanılarak oluşturulur ve `NSBundle` veya `dlopen` tarafından açıkça yüklenir.
- `MH_DYSM`: Eşlik eden `.dSym` dosyası (hata ayıklama için semboller içeren dosya).
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

## **Mach-O Bayrakları**

Kaynak kod, kütüphaneleri yüklemek için kullanışlı birkaç bayrak da tanımlar:

- `MH_NOUNDEFS`: Tanımsız başvuru yok (tamamen bağlanmış)
- `MH_DYLDLINK`: Dyld bağlantısı
- `MH_PREBOUND`: Dinamik başvurular önceden bağlanmış.
- `MH_SPLIT_SEGS`: Dosya, salt okunur ve okunabilir/yazılabilir segmentlere ayrılır.
- `MH_WEAK_DEFINES`: Binary, weak tanımlı sembollere sahiptir
- `MH_BINDS_TO_WEAK`: Binary, weak semboller kullanır
- `MH_ALLOW_STACK_EXECUTION`: Stack'i yürütülebilir yapar
- `MH_NO_REEXPORTED_DYLIBS`: Kütüphane, LC_REEXPORT komutlarını kullanmaz
- `MH_PIE`: Konumdan Bağımsız Yürütülebilir Dosya
- `MH_HAS_TLV_DESCRIPTORS`: Thread local değişkenleri içeren bir bölüm vardır
- `MH_NO_HEAP_EXECUTION`: Heap/data sayfalarında yürütme yoktur
- `MH_HAS_OBJC`: Binary, Object-C bölümlerine sahiptir
- `MH_SIM_SUPPORT`: Simülatör desteği
- `MH_DYLIB_IN_CACHE`: Paylaşılan kütüphane önbelleğindeki dylib/framework'lerde kullanılır.

## **Mach-O Yükleme komutları**

**Dosyanın bellekteki düzeni** burada belirtilir; **sembol tablosunun konumu**, yürütme başlangıcında ana thread'in bağlamı ve gereken **paylaşılan kütüphaneler** ayrıntılandırılır. Dinamik yükleyiciye **(dyld)** binary'nin belleğe yüklenme süreciyle ilgili talimatlar verilir.

Burada, adı geçen **`loader.h`** dosyasında tanımlanan **load_command** yapısı kullanılır:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

There are about **50 different types of load commands** that the system handles differently. The most common ones are: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, and `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Temel olarak, bu Load Command türü, binary yürütüldüğünde **Data bölümünde belirtilen offset'lere** göre **\_\_TEXT** (yürütülebilir kod) ve **\_\_DATA** (process için veriler) **segmentlerinin nasıl yükleneceğini tanımlar**.

Bu komutlar, process yürütüldüğünde **sanal bellek alanına eşlenen segmentleri tanımlar**.

Programın yürütülebilir kodunu tutan **\_\_TEXT** segmenti ve process tarafından kullanılan verileri içeren **\_\_DATA** segmenti gibi **farklı segment türleri** vardır. Bu **segmentler**, Mach-O dosyasının data bölümünde bulunur.

**Her segment** ayrıca birden fazla **bölüme ayrılabilir**. **Load command yapısı**, ilgili segmentteki **bu bölümler hakkında bilgi** içerir.

Başlıkta ilk olarak **segment başlığını** görürsünüz:

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

Bu başlık, başlığın **ardından bölüm başlıkları gelen bölüm sayısını** tanımlar:

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

**section offset** değerini (0x37DC), **arch**'ın başladığı **offset** değerine (bu durumda `0x18000`) eklerseniz --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

**headers information** bilgilerini şu komutla **command line** üzerinden almak da mümkündür:

```bash
otool -lv /bin/ls
```

Bu komut tarafından yüklenen yaygın segmentler:

- **`__PAGEZERO`:** Kernel'a **sıfır adresini eşlemesini (map)** ve bu adresin **okunamamasını, üzerine yazılamamasını veya çalıştırılamamasını** söyler. Yapıdaki maxprot ve minprot değişkenleri, **bu sayfada okuma-yazma-çalıştırma izinlerinin olmadığını** belirtmek için sıfıra ayarlanır.
  - Bu tahsis, **NULL pointer dereference açıklarını azaltmak** için önemlidir. Bunun nedeni, XNU'nun belleğin ilk sayfasının (yalnızca ilk sayfanın) erişilemez olmasını sağlayan kesin bir sıfır sayfası uygulamasıdır (i386 hariç). Bir binary, ilk 4k'yı kapsayacak küçük bir \_\_PAGEZERO oluşturarak (`-pagezero_size` kullanarak) ve 32 bit belleğin geri kalanını hem kullanıcı hem de kernel modunda erişilebilir kılarak bu gereksinimi karşılayabilir.
- **`__TEXT`**: **Okuma** ve **çalıştırma** izinlerine sahip (yazma izni olmayan) **çalıştırılabilir** **kod** içerir. Bu segmentteki yaygın bölümler:
  - `__text`: Derlenmiş binary kodu
  - `__const`: Sabit veriler (salt okunur)
  - `__[c/u/os_log]string`: C, Unicode veya os log dizgesi sabitleri
  - `__stubs` ve `__stubs_helper`: Dinamik kütüphane yükleme sürecinde kullanılır
  - `__unwind_info`: Stack çözümleme verileri.
  - Tüm bu içeriğin imzalı, ancak aynı zamanda çalıştırılabilir olarak işaretli olduğunu unutmayın (bu ayrıcalığa mutlaka ihtiyaç duymayan bölümlerin, örneğin dizgelere ayrılmış bölümlerin exploit edilmesi için daha fazla seçenek oluşturur).
- **`__DATA`**: **Okunabilir** ve **yazılabilir** (çalıştırılabilir olmayan) veriler içerir.
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Tembel olmayan (yükleme sırasında bağlanan) sembol işaretçisi
  - `__la_symbol_ptr`: Tembel (kullanım sırasında bağlanan) sembol işaretçisi
  - `__const`: Salt okunur veri olmalıdır (aslında değil)
  - `__cfstring`: CoreFoundation dizgeleri
  - `__data`: Global değişkenler (başlatılmış olanlar)
  - `__bss`: Statik değişkenler (başlatılmamış olanlar)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist vb.): Objective-C runtime tarafından kullanılan bilgiler
- **`__DATA_CONST`**: \_\_DATA.\_\_const'un sabit olması garanti edilmez (yazma izinleri vardır); diğer işaretçiler ve GOT da aynı şekilde sabit değildir. Bu bölüm, `mprotect` kullanarak `__const`'u, bazı başlatıcıları ve GOT tablosunu (çözümlendikten sonra) **salt okunur** yapar.
- **`__AUTH` / `__AUTH_CONST`**: Yeni Apple Silicon binary'lerinde yaygındır. Bu segmentler, yükleme veya kullanım sırasında kimliği doğrulanması gereken işaretçileri tutar (örneğin `__auth_got`). Bir rebinding, hook veya import-patching yöntemi yalnızca eski `__got` / `__la_symbol_ptr` bölümlerini kontrol ederse modern `arm64e` binary'lerindeki gerçek çağrı noktalarını gözden kaçırabilir. Bu bölümler hakkında daha fazla bilgi için [bu sayfaya](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) bakın.
- **`__LINKEDIT`**: Sembol, dizge ve relocation tablosu girdileri gibi linker (dyld) bilgilerini içerir. `__TEXT` veya `__DATA` içinde yer almayan içerikler için genel bir kapsayıcıdır ve içeriği diğer load command'lerde açıklanır.
  - dyld bilgileri: Rebase, tembel olmayan/tembel/zayıf binding opcode'ları ve export bilgileri
  - Fonksiyon başlangıçları: Fonksiyonların başlangıç adresleri tablosu
  - Kod içi veriler: \_\_text içindeki veri adacıkları
  - Sembol tablosu: Binary'deki semboller
  - Dolaylı sembol tablosu: İşaretçi/stub sembolleri
  - Dizge tablosu
  - Kod imzası
- **`__OBJC`**: Objective-C runtime tarafından kullanılan bilgileri içerir. Bu bilgiler \_\_DATA segmentinde, çeşitli \_\_objc\_\* bölümlerinde de bulunabilir.
- **`__RESTRICT`**: **`__restrict`** adlı tek bir bölümü bulunan (bu bölüm de boştur) içeriksiz bir segmenttir. Binary çalıştırılırken DYLD ortam değişkenlerinin yok sayılmasını sağlar.

Kodda görülebileceği gibi **segmentler ayrıca flag'leri de destekler** (ancak bunlar çok sık kullanılmaz):

- `SG_HIGHVM`: Yalnızca Core (kullanılmıyor)
- `SG_FVMLIB`: Kullanılmıyor
- `SG_NORELOC`: Segmentte relocation yok
- `SG_PROTECTED_VERSION_1`: Şifreleme. Örneğin Finder tarafından `__TEXT` segmentindeki metni şifrelemek için kullanılır.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`**, **entryoff niteliğinde** entrypoint'i içerir. Yükleme sırasında **dyld**, bu değeri binary'nin (bellek içindeki) **tabanına ekler**, ardından binary kodunun çalıştırılmasını başlatmak için bu komuta **atlar**.

**`LC_UNIXTHREAD`**, ana thread başlatılırken register'ların sahip olması gereken değerleri içerir. Bu kullanım artık kullanımdan kaldırılmıştır, ancak **`dyld`** hâlâ bunu kullanır. Bununla ayarlanan register değerlerini şu şekilde görebilirsiniz:

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


**Mach-O dosyasının code signature'ı** hakkında bilgi içerir. Yalnızca **signature blob'a** **işaret eden** bir **offset** içerir. Bu genellikle dosyanın en sonunda bulunur.\
Bu bölüm hakkında daha fazla bilgiyi [**bu blog gönderisinde**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) ve [**bu gist'te**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) bulabilirsiniz.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Binary encryption desteği. Ancak elbette bir saldırgan süreci ele geçirmeyi başarırsa belleği şifresi çözülmüş hâlde dökebilir.

### **`LC_LOAD_DYLINKER`**

Shared library'leri süreç adres alanına eşleyen **dynamic linker executable'ının yolunu** içerir. **Değer her zaman `/usr/lib/dyld` olarak ayarlanır**. macOS'te dylib eşlemesinin kernel mode'da değil, **user mode'da** gerçekleştiğini belirtmek önemlidir.

### **`LC_IDENT`**

Kullanımdan kaldırılmıştır; ancak panic durumunda dump oluşturacak şekilde yapılandırıldığında bir Mach-O core dump oluşturulur ve kernel sürümü `LC_IDENT` komutunda ayarlanır.

### **`LC_UUID`**

Rastgele UUID. Tek başına pek bir işe yaramaz, ancak XNU bunu süreç bilgilerinin geri kalanıyla birlikte önbelleğe alır. Crash report'larda kullanılabilir.

### **`LC_BUILD_VERSION`**

Modern binary'ler genellikle **hedef platformu**, **minimum OS sürümünü**, **SDK sürümünü** ve isteğe bağlı olarak o slice'ı oluşturmak için kullanılan **tool sürümlerini** belirtmek üzere bu komutu içerir. Offensive/reversing açısından bu, bir örneğin nasıl oluşturulduğunu belirlemek ve farklı bir SDK ya da deployment target ile derlenmiş slice içeren tuhaf universal binary'leri hızlıca tespit etmek için çok kullanışlıdır. Daha eski binary'lerde bunun yerine `LC_VERSION_MIN_*` kullanılabilir.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

İşlem yürütülmeden önce dyld'ye ortam değişkenleri belirtmeye olanak tanır. İşlem içinde keyfi kod yürütülmesine izin verebileceğinden bu çok tehlikeli olabilir. Bu nedenle bu load command yalnızca `#define SUPPORT_LC_DYLD_ENVIRONMENT` ile derlenen dyld'de kullanılır ve işlemeyi ayrıca yalnızca yükleme yollarını belirten `DYLD_..._PATH` biçimindeki değişkenlerle sınırlar.

### **`LC_DYLD_EXPORTS_TRIE` ve `LC_DYLD_CHAINED_FIXUPS`**

Yeni toolchain'ler, yalnızca eski `LC_DYLD_INFO[_ONLY]` opcode'larına güvenmek yerine export/bind/rebase meta verilerini sıklıkla bu komutlarda saklar. Her ikisi de **`__LINKEDIT`** içindeki bir alana işaret eden `linkedit_data_command` girdileridir:

- **`LC_DYLD_EXPORTS_TRIE`**: Görüntünün dışa aktardığı sembolleri içeren kompakt trie.
- **`LC_DYLD_CHAINED_FIXUPS`**: dyld'nin rebase ve bind işlemlerini uygulamak için kullandığı, segment başına fixup zincirleri. Apple Silicon'da birçok modern authenticated pointer fixup ile burada da karşılaşırsınız.

Bu meta veriler; import/export'ları yeniden oluştururken, `@rpath` ile yüklenen bir bağımlılığın neden o şekilde çözümlendiğini anlamaya çalışırken veya modern bir `arm64e` hedefinde hook/rebinding girişiminin neden başarısız olduğunu araştırırken çok kullanışlıdır. `dyld_info`, diskte bağımsız dosyalar olarak bulunmayan **yalnızca cache'de bulunan dylib yollarında** da kullanılabilir. Bu, birçok sistem kitaplığının yalnızca shared cache'de bulunduğu modern macOS'te çok kullanışlıdır.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Bu modern load command, en çok **kernel collections / kernelcache-style fileset** dosyalarını incelerken önem kazanır. Dıştaki Mach-O, tek başına duran bir image yerine bir kapsayıcı görevi görür ve her `LC_FILESET_ENTRY`, kendine ait path benzeri bir **entry id**, VM adresi ve dosya offset'i olan gömülü bir Mach-O'yu gösterir. Modern macOS/iOS kernel bileşenlerini reverse engineering yapıyorsanız, bu command çoğu zaman en üst düzey kapsayıcı ile çıkarmak veya disassemble etmek istediğiniz gerçek image arasındaki köprüdür.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Pratik çıkarma iş akışları için [macOS kernel extensions and kernelcache hakkındaki bu diğer sayfaya](../mac-os-architecture/macos-kernel-extensions.md) bakın.

### **`LC_LOAD_DYLIB`**

Bu load command, **loader**'a (dyld) söz konusu kütüphaneyi **yükleyip bağlamasını** **bildiren** bir **dinamik** **kütüphane** bağımlılığını tanımlar. Mach-O binary'nin ihtiyaç duyduğu **her kütüphane için** bir `LC_LOAD_DYLIB` load command bulunur.

- Bu load command, **`dylib_command`** türünde bir yapıdır (gerçek bağımlı dinamik kütüphaneyi tanımlayan bir struct dylib içerir):

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

Bu bilgiyi CLI üzerinden de alabilirsiniz:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Some potential malware related libraries are:

- **DiskArbitration**: USB sürücülerini izleme
- **AVFoundation:** Ses ve video yakalama
- **CoreWLAN**: Wi-Fi taramaları.

> [!TIP]
> Bir Mach-O binary, **LC_MAIN** içinde belirtilen adresten **önce** **çalıştırılacak** bir veya **daha fazla** **constructor** içerebilir.\
> Constructor'ların offset'leri, **\_\_DATA_CONST** segmentinin **\_\_mod_init_func** bölümünde tutulur.

## **Mach-O Verileri**

Dosyanın merkezinde, load-command bölgesinde tanımlanan çeşitli segmentlerden oluşan veri bölgesi yer alır. **Her segmentte çeşitli veri bölümleri bulunabilir** ve her bölüm belirli bir türde **kod veya veri** barındırır.

> [!TIP]
> Veriler, temelde load command'lar tarafından yüklenen tüm **bilgileri** içeren ve **LC_SEGMENTS_64** olarak adlandırılan bölümdür.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Bunlar şunları içerir:

- **Function table:** Program fonksiyonları hakkındaki bilgileri tutar.
- **Symbol table**: Binary tarafından kullanılan harici fonksiyonlar hakkındaki bilgileri içerir.
- Ayrıca dahili fonksiyon ve değişken adlarını da içerebilir.

Kontrol etmek için [**Mach-O View**](https://sourceforge.net/projects/machoview/) aracını kullanabilirsiniz:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Veya CLI'dan:

```bash
size -m /bin/ls
```

### Eklenmiş veriler ve tersine ayrıştırılan overlay'ler

Bir loader, yapılandırmayı adlandırılmış bir Mach-O bölümünde tutmak yerine eklenmiş verilerde saklayabilir. Ardından bir reverse parser, sondaki işaretçiyi referans alır, hemen öncesinde saklanan boyutu okur ve bu değeri kullanarak önceki blob'un yerini bulup şifresini çözer. Gözlemlenen bir universal loader, XOR ile şifrelenmiş bir downloader URL'si için bu düzeni kullanıyordu:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Yabancı bir binary'yi analiz ederken, tanınabilir bitiş işaretçilerinin çevresindeki byte'ları inceleyin ve string'lerin veya yapılandırmanın bir load-command bölümüne ait olduğunu varsaymadan önce geriye dönük tüm boyut hesaplamalarını izleyin. İşaretçi ve XOR key örneğe özeldir; yeniden kullanılabilir teknik, kendi kendini tanımlayan sondur.

## Objective-C Yaygın Bölümleri

`__TEXT` segmentinde (r-x):

- `__objc_classname`: Sınıf adları (string'ler)
- `__objc_methname`: Method adları (string'ler)
- `__objc_methtype`: Method türleri (string'ler)

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

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Mach-O slice'ları düşündüğünüz kadar basit değil](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) man sayfası](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Kendi Entitlements'larınızı Okumak](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source - Mach-O `fat.h` ve `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - MacSync macOS hırsızının yeni sürümü kripto meraklılarını ve geliştiricileri hedef alıyor](https://securelist.com/macsync-new-version/121383/)
