# macOS Universal ikili dosyalar & Mach-O Formatı

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Mac OS ikili dosyaları genellikle **evrensel ikili dosya** olarak derlenir. Bir **evrensel ikili dosya**, **aynı dosya içinde birden fazla mimariyi destekleyebilir**.

Bu ikili dosyalar temelde şu öğelerden oluşan **Mach-O yapısını** takip eder:

- Başlık
- Load Komutları
- Veri

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Başlığı

Dosyayı şu komutla ara: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Başlık, **magic** byte'larını ve ardından dosyanın **içerdiği** **mimarilerin** **sayı**sını (`nfat_arch`) içerir ve her mimari için bir `fat_arch` struct'ı olur.

Şununla kontrol et:

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

Muhtemelen düşüneceğiniz gibi, genellikle iki mimari için derlenen bir evrensel ikili dosya, sadece bir mimari için derlenene göre boyutunu **iki katına çıkarır**.

## **Mach-O Başlığı**

Başlık, dosya hakkında temel bilgileri içerir; örneğin dosyanın Mach-O dosyası olduğunu belirlemek için kullanılan magic byte'lar ve hedef mimariye ilişkin bilgiler. Şunu kullanarak bulabilirsiniz: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Farklı dosya türleri vardır, bunların tanımlamalarını [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) içinde bulabilirsiniz. En önemlileri şunlardır:

- `MH_OBJECT`: Yeniden konumlandırılabilir object dosyası (derlemenin ara ürünleri, henüz yürütülebilir değiller).
- `MH_EXECUTE`: Yürütülebilir dosyalar.
- `MH_FVMLIB`: Sabit VM kütüphane dosyası.
- `MH_CORE`: Kod dökümleri
- `MH_PRELOAD`: Önyüklenmiş yürütülebilir dosya (XNU'da artık desteklenmiyor)
- `MH_DYLIB`: Dinamik kütüphaneler
- `MH_DYLINKER`: Dinamik bağlayıcı
- `MH_BUNDLE`: "Eklenti dosyaları". -bundle in gcc kullanılarak oluşturulur ve `NSBundle` veya `dlopen` ile açıkça yüklenir.
- `MH_DYSM`: Eşlik eden `.dSym` dosyası (hata ayıklama için semboller içeren dosya).
- `MH_KEXT_BUNDLE`: Çekirdek uzantıları.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Veya [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Bayrakları**

Kaynak kod ayrıca kütüphanelerin yüklenmesi için faydalı birkaç bayrak tanımlar:

- `MH_NOUNDEFS`: Tanımsız referans yok (tam bağlanmış)
- `MH_DYLDLINK`: Dyld ile bağlama
- `MH_PREBOUND`: Dinamik referanslar önceden bağlanmış.
- `MH_SPLIT_SEGS`: Dosya, yalnızca okunur (r/o) ve okunur/yazılır (r/w) segmentlerine ayrılmıştır.
- `MH_WEAK_DEFINES`: İkili, zayıf tanımlı semboller içerir
- `MH_BINDS_TO_WEAK`: İkili zayıf semboller kullanır
- `MH_ALLOW_STACK_EXECUTION`: Yığını yürütülebilir yapar
- `MH_NO_REEXPORTED_DYLIBS`: Kütüphane LC_REEXPORT komutları içermez
- `MH_PIE`: Konumdan bağımsız yürütülebilir (PIE)
- `MH_HAS_TLV_DESCRIPTORS`: İş parçacığı yerel değişkenleri içeren bir bölüm vardır
- `MH_NO_HEAP_EXECUTION`: Heap/veri sayfalarında yürütme yok
- `MH_HAS_OBJC`: İkili, Objective-C bölümleri içerir
- `MH_SIM_SUPPORT`: Simülatör desteği
- `MH_DYLIB_IN_CACHE`: Paylaşılan kütüphane önbelleğindeki dylibs/framework'lerde kullanılır.

## **Mach-O Load commands**

Dosyanın bellekteki düzeni burada belirtilir; sembol tablosunun konumunu, yürütme başlangıcındaki ana iş parçacığının bağlamını ve gerekli paylaşılan kütüphaneleri detaylandırır. Dinamik yükleyiciye (dyld), ikilinin belleğe yüklenme süreci hakkında talimatlar sağlar.

Bunun için, bahsedilen `loader.h` içinde tanımlı olan load_command yapısı kullanılır:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
There are about **50 farklı load command türü** vardır ve sistem bunları farklı şekilde ele alır. En yaygın olanlar: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` ve `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Temelde, bu tür bir Load Command, binary çalıştırıldığında **__TEXT'in nasıl yükleneceğini** (çalıştırılabilir kod) **ve __DATA'nın** (işlem için veri) **segmentlerinin** **Data bölümünde belirtilen ofsetlere** göre tanımlar.

Bu komutlar, yürütüldüğünde bir işlemin **sanal bellek alanına** **haritalanan** **segmentleri tanımlar**.

Farklı türde segmentler vardır; örneğin programın çalıştırılabilir kodunu barındıran __TEXT segmenti ve işlem tarafından kullanılan verileri içeren __DATA segmenti. Bu segmentler Mach-O dosyasının data bölümünde bulunur.

Her segment daha sonra birden fazla section'a bölünebilir. Load command yapısı, ilgili segment içindeki bu bölümler hakkında bilgi içerir.

Başlıkta önce segment başlığı bulunur:

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

Bu başlık, **ardından gelen bölüm başlıklarının sayısını** tanımlar:
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
Örnek **bölüm başlığı**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Eğer **section offset** (0x37DC) ile **arch starts**'ın bulunduğu **offset**i toplarsanız, bu durumda `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Ayrıca **headers information**'ı **command line** üzerinden şu şekilde almak da mümkündür:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** Kernel'e **adres sıfırını haritalamasını** talimat verir; böylece bu adres **okunamaz, yazılamaz veya çalıştırılamaz**. Yapıdaki maxprot ve minprot değişkenleri bu sayfada **okuma-yazma-çalıştırma haklarının olmadığını** göstermek için sıfıra ayarlanır.
- Bu tahsis, **NULL pointer dereference zaafiyetlerini hafifletmek** için önemlidir. Bunun nedeni XNU'nun ilk sayfanın (sadece ilk) erişilemez olmasını sağlayan sert bir page zero uygulamasıdır (i386 hariç). Bir binary, bu gereksinimi karşılamak için küçük bir \_\_PAGEZERO ( `-pagezero_size` kullanarak) oluşturup ilk 4k'yı kapsayabilir ve kalan 32-bit belleği hem user hem de kernel modunda erişilebilir tutabilir.
- **`__TEXT`**: **yürütülebilir** **kod** içeren, **okuma** ve **çalıştırma** izinlerine sahip (yazılabilir olmayan) bir segmenttir. Bu segmentin yaygın bölümleri:
- `__text`: Derlenmiş ikili kod
- `__const`: Sabit veriler (yalnızca okunur)
- `__[c/u/os_log]string`: C, Unicode veya os log dize sabitleri
- `__stubs` and `__stubs_helper`: Dinamik kütüphane yükleme sürecinde rol alır
- `__unwind_info`: Yığın unwind verisi
- Not: Tüm bu içerikler imzalanmıştır ancak aynı zamanda yürütülebilir olarak işaretlenmiştir (bu, string gibi özel bölümlerin de gerekmese bile bu ayrıcalığa sahip olması durumunda sömürü için daha fazla seçenek yaratır).
- **`__DATA`**: **okunabilir** ve **yazılabilir** (yürütülemez) verileri içerir.
- `__got:` Global Offset Tablosu
- `__nl_symbol_ptr`: Non-lazy (yüklemede bağlanır) sembol işaretçisi
- `__la_symbol_ptr`: Lazy (kullanımda bağlanır) sembol işaretçisi
- `__const`: Okunur-yalnız veri olması gerekir (aslında çoğunlukla öyle değildir)
- `__cfstring`: CoreFoundation dizeleri
- `__data`: Başlatılmış global değişkenler
- `__bss`: Başlatılmamış statik değişkenler
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Objective-C runtime tarafından kullanılan bilgiler
- **`__DATA_CONST`**: \_\_DATA.\_\_const'ın gerçekten sabit olduğu garanti edilmez (yazma izinleri olabilir), diğer pointerlar ve GOT da aynı şekilde. Bu bölüm, `mprotect` kullanarak `__const`, bazı initializers ve GOT tablosunu (çözüldükten sonra) **salt okunur** yapar.
- **`__LINKEDIT`**: Linker (dyld) için sembol, dize ve relocation tablo girdileri gibi bilgileri içerir. `__TEXT` veya `__DATA` içinde olmayan içerikler için genel bir kapsayıcıdır ve içeriği diğer load command'ler ile tanımlanır.
- dyld bilgisi: Rebase, Non-lazy/lazy/weak binding opcode'ları ve export bilgisi
- Fonksiyon başlangıçları: Fonksiyonların başlangıç adresleri tablosu
- Data In Code: `__text` içindeki veri adacıkları
- Sembol Tablosu: Binary içindeki semboller
- Dolaylı Sembol Tablosu: Pointer/stub sembolleri
- Dize Tablosu
- Kod İmzası
- **`__OBJC`**: Objective-C runtime tarafından kullanılan bilgileri içerir. Bu bilgiler bazen \_\_DATA segmenti içindeki çeşitli \_\_objc\_\* bölümlerinde de bulunabilir.
- **`__RESTRICT`**: İçeriği olmayan ve tek bir bölüm olan **`__restrict`** (o da boş) adlı bir segmenttir; bu, binary çalıştırılırken DYLD çevresel değişkenlerinin göz ardı edilmesini sağlar.

As it was possible to see in the code, **segments also support flags** (although they aren't used very much):

- `SG_HIGHVM`: Core only (not used)
- `SG_FVMLIB`: Not used
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Used for example by Finder to encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** giriş noktasını **entryoff özniteliğinde** içerir. Yükleme sırasında **dyld** bu değeri (bellekteki) ikili dosyanın temel adresine ekler, sonra yürütmeyi başlatmak için bu yönergeye **atlar**.

**`LC_UNIXTHREAD`** ana thread başlatılırken registerların sahip olması gereken değerleri içerir. Bu zaten deprecated olsa da **`dyld`** hâlâ bunu kullanır. Bununla ayarlanan register değerlerini şu şekilde görmek mümkündür:
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


Macho-O dosyasının **kod imzası** hakkında bilgi içerir. Sadece **imza blob'una işaret eden bir offset** içerir. Bu genellikle dosyanın tam sonunda yer alır.\
Bununla ilgili bazı bilgileri [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) ve bu [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) üzerinde bulabilirsiniz.

### **`LC_ENCRYPTION_INFO[_64]`**

Binary şifreleme desteği. Ancak elbette, bir saldırgan süreci ele geçirirse, belleği şifresiz şekilde dump edebilecektir.

### **`LC_LOAD_DYLINKER`**

Paylaşılan kütüphaneleri işlem adres alanına eşleyen dynamic linker executable'ın **yolunu içerir**. **Değer her zaman `/usr/lib/dyld` olarak ayarlanır**. macOS'ta dylib eşlemenin **kernel modunda değil, kullanıcı modunda** gerçekleştiğini not etmek önemlidir.

### **`LC_IDENT`**

Artık modası geçmiştir, ancak panic durumunda dump oluşturacak şekilde yapılandırıldığında bir Mach-O core dump oluşturulur ve kernel sürümü `LC_IDENT` komutunda ayarlanır.

### **`LC_UUID`**

Rastgele UUID. Doğrudan her şey için kullanışlı olmasa da XNU bunu işlem bilgileriyle birlikte önbelleğe alır. Crash raporlarında kullanılabilir.

### **`LC_DYLD_ENVIRONMENT`**

Süreç çalıştırılmadan önce dyld'e ortam değişkenlerini belirtme imkanı sağlar. Bu oldukça tehlikeli olabilir çünkü süreç içinde rastgele kod çalıştırılmasına izin verebilir; bu yüzden bu load command sadece `#define SUPPORT_LC_DYLD_ENVIRONMENT` ile derlenmiş dyld yapılarında kullanılır ve işleme yalnızca `DYLD_..._PATH` biçimindeki yükleme yollarını belirten değişkenlerle sınırlandırılır.

### **`LC_LOAD_DYLIB`**

Bu load command, loader'ı (dyld) söz konusu kütüphaneyi **yüklemeye ve linklemeye** yönlendiren **dinamik kütüphane** bağımlılığını tanımlar. Mach-O binary'nin gerektirdiği **her kütüphane için bir `LC_LOAD_DYLIB` load command** vardır.

- Bu load command, içinde gerçek bağımlı dynamic library'yi tanımlayan bir struct dylib içeren **`dylib_command`** tipinde bir yapıdır:
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
![](<../../../images/image (486).png>)

Bu bilgiyi ayrıca cli ile şu şekilde alabilirsiniz:
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
- **CoreWLAN**: Wifi taramaları.

> [!TIP]
> Bir Mach-O ikili dosyası bir veya **daha fazla** **constructor** içerebilir; bunlar **LC_MAIN** ile belirtilen adresten **önce** **çalıştırılacaktır**.\
> Herhangi bir constructor'ın offsetleri **\_\_DATA_CONST** segmentinin **\_\_mod_init_func** bölümünde tutulur.

## **Mach-O Verisi**

Dosyanın merkezinde, load-commands bölgesinde tanımlanan birkaç segmentten oluşan veri bölgesi bulunur. **Her segment içinde çeşitli veri bölümleri bulunabilir**, her bölüm türüne özgü **kod veya veri** barındırır.

> [!TIP]
> Veri, temelde load commands **LC_SEGMENTS_64** tarafından yüklenen tüm **bilgileri** içeren kısımdır.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

This includes:

- **Function table:** Program fonksiyonları hakkında bilgi tutar.
- **Symbol table**: Binary tarafından kullanılan dış fonksiyonlar hakkında bilgi içerir.
- Ayrıca dahili fonksiyon ve değişken adlarını ve daha fazlasını da içerebilir.

To check it you could use the [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Veya cli üzerinden:
```bash
size -m /bin/ls
```
## Objetive-C Genel Bölümler

`__TEXT` segmentinde (r-x):

- `__objc_classname`: Sınıf isimleri (stringler)
- `__objc_methname`: Metod isimleri (stringler)
- `__objc_methtype`: Metod tipleri (stringler)

`__DATA` segmentinde (rw-):

- `__objc_classlist`: Tüm Objetive-C sınıflarına işaretçiler
- `__objc_nlclslist`: Non-Lazy Objective-C sınıflarına işaretçiler
- `__objc_catlist`: Kategorilere işaretçi
- `__objc_nlcatlist`: Non-Lazy Kategorilere işaretçi
- `__objc_protolist`: Protokoller listesi
- `__objc_const`: Sabit veri
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
