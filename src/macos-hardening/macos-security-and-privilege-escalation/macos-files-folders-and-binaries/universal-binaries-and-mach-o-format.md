# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

macOS hutumia format ya executable ya **Mach-O**. Binary **universal**, au fat, huwa na slices nyingi za Mach-O zinazolenga architecture tofauti ndani ya faili moja. Header za open-source za Apple `fat.h` na `loader.h` hufafanua miundo na constants zilizoelezwa kwenye ukurasa huu. <sup>[[5]](#references)</sup>

Image ya Mach-O imeundwa na:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Kichwa cha Fat

Tafuta faili kwa kutumia: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Header ina bytes za **magic** zikifuatiwa na **idadi** ya **archs** ambazo faili **ina** (`nfat_arch`), na kila arch itakuwa na struct ya `fat_arch`.

Ihakiki kwa:

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

au kwa kutumia zana ya [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Kama unavyoweza kufikiria, kwa kawaida binary universal iliyokompiliwa kwa architectures 2 **huwa na ukubwa mara mbili** ya ile iliyokompiliwa kwa arch 1 pekee.

> [!TIP]
> Unapochunguza malware au apps zinazotia shaka, usiishie baada ya `file` kuripoti architecture "bora". Binary universal inaweza kuficha imports tofauti, load commands au metadata ya compiler katika kila slice, kwa hiyo orodhesha **slices zote** kwanza kisha uzichunguze kila moja kivyake:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Recent macOS SDKs pia zinafichua `macho_for_each_slice()` na `macho_best_slice()` katika `<mach-o/utils.h>`. Kwenye Apple Silicon, kabla ya macOS 15, `macho_best_slice()` inaweza kurudisha `EBADARCH` kimakosa kwa binary ya `arm64` ya mtu mwingine inayoweza kutekelezwa; API hii ilirekebishwa katika macOS 15. Tumia `macho_for_each_slice()` au `lipo -archs` kuorodhesha kila slice badala ya kuchukulia utafutaji wa best-slice ulioshindwa kuwa uthibitisho kwamba hakuna slice inayoweza kutekelezwa.<sup>[[1]](#references)[[7]](#references)</sup>

### Linganisha saini za code katika slices

Kila architecture katika universal binary ina CodeDirectory na CDHash yake. Unakagua executable iliyotiwa saini au helper yenye ruhusa za juu, kagua **saini ya kila slice**. CDHash tofauti ni jambo la kawaida; badala yake, linganisha utambulisho wa kusaini, flags za CodeDirectory na entitlements.<sup>[[8]](#references)</sup>

Kwa sera zinazolingana na CDHash, hash moja hutambua njia moja tu ya utekelezaji inayohusiana na architecture maalum. Apple inapendekeza kuorodhesha slices na kutumia `codesign --arch` kukagua kila moja.<sup>[[9]](#references)</sup>

```bash
BIN=/path/to/executable
for A in $(lipo -archs "$BIN"); do
  printf "\n== %s ==\n" "$A"
  codesign -dvvv --arch "$A" "$BIN" 2>&1
  codesign -d --entitlements - --arch "$A" "$BIN"
done
```

Kwa maelezo kuhusu muundo wa signature na uthibitishaji, angalia [macOS Code Signing](../macos-security-protections/macos-code-signing.md).

## **Kichwa cha Mach-O**

Kichwa kina taarifa za msingi kuhusu faili, kama vile magic bytes zinazotambulisha kuwa faili ni Mach-O na taarifa kuhusu architecture lengwa. Unaweza kukipata hapa: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

### Aina za Faili za Mach-O

Kuna aina tofauti za faili, unaweza kuzipata zimefafanuliwa katika [**source code kwa mfano hapa**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Zilizo muhimu zaidi ni:

- `MH_OBJECT`: Faili ya object inayoweza kuunganishwa (matokeo ya kati ya compilation, bado si executables).
- `MH_EXECUTE`: Faili zinazotekelezeka.
- `MH_FVMLIB`: Faili ya maktaba ya Fixed VM.
- `MH_CORE`: Dumps za code.
- `MH_PRELOAD`: Faili ya executable iliyopakiwa awali (haitumiki tena katika XNU).
- `MH_DYLIB`: Maktaba zinazobadilika.
- `MH_DYLINKER`: Dynamic Linker.
- `MH_BUNDLE`: "Faili za plugin". Hutengenezwa kwa kutumia -bundle katika gcc na kupakiwa waziwazi na `NSBundle` au `dlopen`.
- `MH_DSYM`: Faili ya ziada ya `.dSYM` (faili yenye symbols za debugging).
- `MH_KEXT_BUNDLE`: Viendelezi vya Kernel.

```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

Au kwa kutumia [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

Msimbo chanzo pia hufafanua flags kadhaa zinazofaa kwa kupakia libraries:

- `MH_NOUNDEFS`: Hakuna marejeleo yasiyofafanuliwa (imeunganishwa kikamilifu)
- `MH_DYLDLINK`: Uunganishaji wa Dyld
- `MH_PREBOUND`: Marejeleo ya dynamic yameunganishwa mapema.
- `MH_SPLIT_SEGS`: Faili hugawanya segment za r/o na r/w.
- `MH_WEAK_DEFINES`: Binary ina alama zilizofafanuliwa kwa weak
- `MH_BINDS_TO_WEAK`: Binary hutumia alama za weak
- `MH_ALLOW_STACK_EXECUTION`: Fanya stack iweze kutekeleza
- `MH_NO_REEXPORTED_DYLIBS`: Library haina amri za LC_REEXPORT
- `MH_PIE`: Executable Isiyojitegemea na Nafasi
- `MH_HAS_TLV_DESCRIPTORS`: Kuna sehemu yenye vigeu vya thread-local
- `MH_NO_HEAP_EXECUTION`: Hakuna utekelezaji kwa kurasa za heap/data
- `MH_HAS_OBJC`: Binary ina sehemu za oBject-C
- `MH_SIM_SUPPORT`: Usaidizi wa simulator
- `MH_DYLIB_IN_CACHE`: Hutumika kwa dylibs/frameworks zilizo kwenye shared library cache.

## **Mach-O Load commands**

**Mpangilio wa faili kwenye kumbukumbu** umebainishwa hapa, ukifafanua **mahali pa jedwali la alama**, muktadha wa thread kuu wakati wa kuanza kutekeleza, na **shared libraries** zinazohitajika. Maagizo hutolewa kwa dynamic loader **(dyld)** kuhusu mchakato wa kupakia binary kwenye kumbukumbu.

Hii hutumia muundo wa **load_command**, uliofafanuliwa kwenye **`loader.h`** iliyotajwa:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Kuna takriban **aina 50 tofauti za load commands** ambazo mfumo huzishughulikia kwa njia tofauti. Zinazotumika zaidi ni: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, na `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Kimsingi, aina hii ya Load Command hufafanua **jinsi ya kupakia \_\_TEXT** (msimbo unaotekelezeka) **na \_\_DATA** (data ya mchakato) **segments** kulingana na **offsets zilizoonyeshwa katika sehemu ya Data** wakati binary inatekelezwa.

Amri hizi **hufafanua segments** ambazo **huwekwa** katika **nafasi ya kumbukumbu pepe** ya mchakato unapotekelezwa.

Kuna **aina tofauti** za segments, kama vile segment ya **\_\_TEXT**, inayohifadhi msimbo unaotekelezeka wa programu, na segment ya **\_\_DATA**, iliyo na data inayotumiwa na mchakato. **Segments hizi ziko katika sehemu ya data** ya faili ya Mach-O.

**Kila segment** inaweza kugawanywa zaidi katika **sections** nyingi. **Muundo wa load command** una **taarifa** kuhusu **sections hizi** ndani ya segment husika.

Kwanza kwenye header utapata **segment header**:

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

Mfano wa segment header:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Header hii hufafanua **idadi ya sections ambazo headers zake huonekana baada** yake:

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

Mfano wa **kichwa cha sehemu**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Ukiongeza **offset ya sehemu** (0x37DC) na **offset** ambapo **usanifu** huanza, katika hali hii `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Pia inawezekana kupata **maelezo ya vichwa** kutoka kwa **command line** kwa kutumia:

```bash
otool -lv /bin/ls
```

Sehemu za kawaida zinazopakiwa na cmd hii:

- **`__PAGEZERO`:** Inaelekeza kernel **kufanya map** ya **anwani sifuri** ili **isiweze kusomwa, kuandikiwa au kutekelezewa**. Vigeu vya maxprot na minprot katika muundo huwekwa kuwa sifuri kuashiria kuwa **hakuna ruhusa za kusoma-kuandika-kutekeleza kwenye ukurasa huu**.
  - Ugawaji huu ni muhimu ili **kupunguza hatari ya udhaifu wa NULL pointer dereference**. Hii ni kwa sababu XNU hutekeleza ukurasa sifuri usiobadilika, unaohakikisha kuwa ukurasa wa kwanza wa kumbukumbu (ukurasa wa kwanza pekee) hauwezi kufikiwa (isipokuwa kwenye i386). Binary inaweza kutimiza hitaji hili kwa kutengeneza \_\_PAGEZERO ndogo (kwa kutumia `-pagezero_size`) ili kufunika 4k za kwanza huku sehemu iliyobaki ya kumbukumbu ya 32bit ikifikika katika hali za mtumiaji na kernel.
- **`__TEXT`**: Ina **msimbo** **tekelezi** wenye ruhusa za **kusoma** na **kutekeleza** (bila ruhusa ya kuandika)**.** Sehemu za kawaida za segment hii:
  - `__text`: Msimbo wa binary uliokusanywa
  - `__const`: Data isiyobadilika (ya kusoma pekee)
  - `__[c/u/os_log]string`: Mifuatano isiyobadilika ya C, Unicode au kumbukumbu za os
  - `__stubs` na `__stubs_helper`: Hutumika wakati wa upakiaji wa dynamic library
  - `__unwind_info`: Data ya stack unwind.
  - Kumbuka kuwa maudhui haya yote yametiwa sahihi lakini pia yamewekewa alama ya kutekelezeka (jambo linalotoa chaguo zaidi za exploitation kwa sehemu ambazo hazihitaji lazima ruhusa hii, kama sehemu maalum za mifuatano).
- **`__DATA`**: Ina data ambayo **inaweza kusomwa** na **kuandikiwa** (haiwezi kutekelezwa)**.**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Kielekezi cha alama kisicho lazy (huunganishwa wakati wa upakiaji)
  - `__la_symbol_ptr`: Kielekezi cha alama cha lazy (huunganishwa kinapotumika)
  - `__const`: Inapaswa kuwa data ya kusoma pekee (lakini si hivyo kwa hakika)
  - `__cfstring`: Mifuatano ya CoreFoundation
  - `__data`: Vigeu vya kimataifa (vilivyoanzishwa)
  - `__bss`: Vigeu tuli (ambavyo havijaanzishwa)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, n.k.): Taarifa zinazotumiwa na Objective-C runtime
- **`__DATA_CONST`**: \_\_DATA.\_\_const haijahakikishiwa kuwa thabiti (ina ruhusa za kuandika), na vivyo hivyo kwa vielekezi vingine na GOT. Sehemu hii hutumia `mprotect` kufanya `__const`, baadhi ya vianzilishi na jedwali la GOT (baada ya kutatuliwa) **zisomwe pekee**.
- **`__AUTH` / `__AUTH_CONST`**: Hupatikana kwa kawaida katika binary za hivi karibuni za Apple Silicon. Segment hizi huhifadhi vielekezi vinavyopaswa kuthibitishwa wakati wa upakiaji au matumizi (kwa mfano `__auth_got`). Ikiwa mbinu ya rebinding, hook au import-patching hukagua tu sehemu za zamani za `__got` / `__la_symbol_ptr`, huenda ikakosa sehemu halisi za miito katika binary za kisasa za `arm64e`. Kwa maelezo zaidi kuhusu sehemu hizi, angalia [ukurasa huu](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Ina taarifa za linker (dyld), kama vile maingizo ya jedwali la alama, mifuatano na relocation. Ni chombo cha jumla cha maudhui ambayo hayako kwenye `__TEXT` wala `__DATA`, na maudhui yake yanafafanuliwa katika amri nyingine za upakiaji.
  - Taarifa za dyld: Rebase, opcode za binding zisizo-lazy/lazy/weak na taarifa za export
  - Functions starts: Jedwali la anwani za kuanzia za functions
  - Data In Code: Visiwa vya data ndani ya \_\_text
  - SYmbol Table: Alama katika binary
  - Indirect Symbol Table: Alama za pointer/stub
  - String Table
  - Code Signature
- **`__OBJC`**: Ina taarifa zinazotumiwa na Objective-C runtime. Hata hivyo, taarifa hii inaweza pia kupatikana katika segment ya \_\_DATA, ndani ya sehemu mbalimbali za \_\_objc\_\*.
- **`__RESTRICT`**: Segment isiyo na maudhui, yenye sehemu moja inayoitwa **`__restrict`** (ambayo pia haina maudhui), inayohakikisha kuwa binary inapotekelezwa, itapuuza vigeu vya mazingira vya DYLD.

Kama inavyoonekana kwenye msimbo, **segment pia zinaweza kuwa na flags** (ingawa hazitumiki sana):

- `SG_HIGHVM`: Core pekee (haitumiki)
- `SG_FVMLIB`: Haitumiki
- `SG_NORELOC`: Segment haina relocation
- `SG_PROTECTED_VERSION_1`: Usimbaji fiche. Kwa mfano, hutumiwa na Finder kusimba segment ya maandishi `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** ina entrypoint katika sifa ya **entryoff.** Wakati wa upakiaji, **dyld** huongeza tu thamani hii kwenye **msingi wa binary** (ulio kwenye kumbukumbu), kisha **hurukia** kwenye instruction hii ili kuanza kutekeleza msimbo wa binary.

**`LC_UNIXTHREAD`** ina thamani ambazo register lazima ziwe nazo wakati wa kuanzisha main thread. Hii tayari iliacha kutumika, lakini **`dyld`** bado huitumia. Inawezekana kuona thamani za register zilizowekwa na hii kwa kutumia:

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


Ina taarifa kuhusu **saini ya code ya faili la Mach-O**. Ina **offset** pekee inayoelekeza kwenye **signature blob**. Kwa kawaida huwa mwishoni kabisa mwa faili.\
Unaweza kupata maelezo zaidi kuhusu sehemu hii katika [**chapisho hili la blogu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) na [**gist hii**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Hutoa usaidizi kwa usimbaji fiche wa binary. Hata hivyo, bila shaka, mshambuliaji akifaulu kuathiri process, ataweza kutoa dump ya kumbukumbu bila usimbaji fiche.

### **`LC_LOAD_DYLINKER`**

Ina **path ya executable ya dynamic linker** inayopanga shared libraries kwenye address space ya process. **Thamani huwekwa kuwa `/usr/lib/dyld` kila wakati**. Ni muhimu kutambua kwamba katika macOS, upangaji wa dylib hufanyika katika **user mode**, si katika kernel mode.

### **`LC_IDENT`**

Imepitwa na wakati, lakini mipangilio inapowekwa ili kuzalisha dumps wakati wa panic, hutengenezwa core dump ya Mach-O na toleo la kernel huwekwa kwenye command ya `LC_IDENT`.

### **`LC_UUID`**

UUID ya nasibu. Haitumiki moja kwa moja kwa chochote, lakini XNU huihifadhi pamoja na taarifa nyingine za process. Inaweza kutumika katika crash reports.

### **`LC_BUILD_VERSION`**

Binary za kisasa kwa kawaida huwa na command hii ya kutangaza **platform lengwa**, **toleo la chini kabisa la OS**, **toleo la SDK**, na, kwa hiari, **matoleo ya tools** yaliyotumika kutengeneza slice hiyo. Kwa mtazamo wa offensive/reversing, hii ni muhimu sana kwa kutambua jinsi sample ilivyotengenezwa na kutambua haraka universal binaries zisizo za kawaida ambazo slice moja ilikompailiwa kwa SDK au deployment target tofauti. Binary za zamani zinaweza kutumia `LC_VERSION_MIN_*` badala yake.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Huruhusu kubainisha vigeu vya mazingira kwa dyld kabla ya mchakato kutekelezwa. Hili linaweza kuwa hatari sana kwa kuwa linaweza kuruhusu kutekeleza msimbo wowote ndani ya mchakato, kwa hiyo amri hii ya upakiaji hutumiwa tu katika build za dyld zenye `#define SUPPORT_LC_DYLD_ENVIRONMENT`, na uchakataji wake huzuiwa zaidi kwa vigeu vya muundo wa `DYLD_..._PATH` vinavyobainisha njia za upakiaji.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Toolchain za hivi karibuni mara nyingi huhifadhi metadata ya export/bind/rebase katika amri hizi badala ya kutegemea opcodes za zamani za `LC_DYLD_INFO[_ONLY]` pekee. Zote ni maingizo ya `linkedit_data_command` yanayoelekeza ndani ya **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Trie fupi yenye alama zinazotolewa na image.
- **`LC_DYLD_CHAINED_FIXUPS`**: Minyororo ya fixup kwa kila segment inayotumiwa na dyld kutekeleza rebases na binds. Kwenye Apple Silicon, hapa pia utakutana na fixup nyingi za kisasa za pointer zilizothibitishwa.

Metadata hii ni muhimu sana unapounda upya imports/exports, kuelewa kwa nini dependency iliyopakiwa kupitia `@rpath` ilitatuliwa kwa njia fulani, au kubaini kwa nini jaribio la hook/rebinding lilishindwa kwenye target ya kisasa ya `arm64e`. `dyld_info` inaweza pia kutumika kwenye **njia za dylib zinazopatikana kwenye cache pekee** ambazo hazipo kama faili huru kwenye diski. Hii ni muhimu sana kwenye macOS za kisasa ambapo maktaba nyingi za mfumo zinapatikana kwenye shared cache pekee.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Amri hii ya kisasa ya load inahusika zaidi unapokagua **kernel collections / kernelcache-style filesets**. Badala ya kuwakilisha image moja inayojitegemea, Mach-O ya nje hufanya kazi kama chombo, na kila `LC_FILESET_ENTRY` huelekeza kwenye Mach-O iliyopachikwa yenye entry id yake inayofanana na path, anwani ya VM na file offset. Unaporeverse vipengele vya kernel vya kisasa vya macOS/iOS, amri hii mara nyingi huwa kiungo kati ya chombo cha kiwango cha juu na image halisi unayotaka kutoa au ku-disassemble.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Kwa workflows za vitendo za uchimbaji, angalia [ukurasa huu mwingine kuhusu kernel extensions za macOS na kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Amri hii ya load inaelezea utegemezi wa **dynamic** **library** ambao **huielekeza** **loader** (dyld) **kupakia na ku-link library hiyo**. Kuna amri ya load ya `LC_LOAD_DYLIB` **kwa kila library** inayohitajika na binary ya Mach-O.

- Amri hii ya load ni muundo wa aina ya **`dylib_command`** (ambao una struct ya dylib, inayoelezea dynamic library halisi ambayo inategemewa):

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t toleo la uoanifu; / nambari ya toleo la uoanifu la maktaba /](<../../../images/image (486).png>)

Unaweza pia kupata taarifa hii kutoka kwenye CLI kwa kutumia:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Baadhi ya libraries zinazoweza kuhusishwa na malware ni:

- **DiskArbitration**: Kufuatilia viendeshi vya USB
- **AVFoundation:** Kunasa sauti na video
- **CoreWLAN**: Kuchanganua Wi-Fi.

> [!TIP]
> Binary ya Mach-O inaweza kuwa na **constructors** moja au **zaidi**, ambazo **zitatekelezwa** **kabla** ya anwani iliyobainishwa katika **LC_MAIN**.\
> Offsets za constructors zozote huhifadhiwa katika sehemu ya **\_\_mod_init_func** ya segment ya **\_\_DATA_CONST**.

## **Data ya Mach-O**

Kiini cha faili kina eneo la data, ambalo linajumuisha segments kadhaa kama zilivyobainishwa katika eneo la load-commands. **Aina mbalimbali za sehemu za data zinaweza kuwekwa ndani ya kila segment**, huku kila sehemu **ikiwa na code au data** maalum kwa aina fulani.

> [!TIP]
> Data kimsingi ni sehemu iliyo na **taarifa** zote zinazopakiwa na load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Hii inajumuisha:

- **Jedwali la functions:** Ambalo lina taarifa kuhusu functions za programu.
- **Jedwali la symbols**: Ambalo lina taarifa kuhusu function ya nje inayotumiwa na binary
- Pia linaweza kuwa na majina ya functions na variables za ndani, na mengineyo.

Ili kulikagua, unaweza kutumia zana ya [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Au kupitia CLI:

```bash
size -m /bin/ls
```

### Data iliyoongezwa na overlays zinazochanganuliwa kinyume

Loader inaweza kuhifadhi usanidi kwenye data iliyoongezwa badala ya sehemu ya Mach-O iliyopewa jina. Kisha reverse parser hujikita kwenye alama ya mwisho, husoma ukubwa uliohifadhiwa mara moja kabla yake, na hutumia thamani hiyo kupata na kusimbua blob iliyotangulia. Loader moja ya universal iliyozingatiwa ilitumia mpangilio huu kwa URL ya downloader iliyosimbwa kwa XOR:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Unapochunguza binary usiyoifahamu, kagua bytes zilizo karibu na alama za mwisho zinazotambulika, na fuatilia kila hesabu ya ukubwa inayofanywa kurudi nyuma kabla ya kudhani kwamba strings au usanidi lazima viwe sehemu ya load-command. Alama na ufunguo wa XOR hutegemea sampuli husika; mbinu inayoweza kutumika tena ni trailer inayojieleza yenyewe.

## Sehemu za Kawaida za Objective-C

Katika segment ya `__TEXT` (r-x):

- `__objc_classname`: Majina ya madarasa (strings)
- `__objc_methname`: Majina ya mbinu (strings)
- `__objc_methtype`: Aina za mbinu (strings)

Katika segment ya `__DATA` (rw-):

- `__objc_classlist`: Pointers kwa madarasa yote ya Objective-C
- `__objc_nlclslist`: Pointers kwa madarasa ya Objective-C yasiyo Lazy
- `__objc_catlist`: Pointer kwa Categories
- `__objc_nlcatlist`: Categories zisizo Lazy
- `__objc_protolist`: Orodha ya Protocols
- `__objc_const`: Data isiyobadilika
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

Tazama pia: [Upakiaji wa Mach-O kwa Reflective](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [1] [Vipande vya Mach-O si rahisi kuelewa kama unavyoweza kudhani](https://objective-see.org/blog/blog_0x80.html)
- [2] [Ukurasa wa man wa dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Kusoma Entitlements Zako Mwenyewe](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source - Mach-O `fat.h` na `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - Toleo jipya la MacSync macOS stealer linalenga wapenda crypto na developers](https://securelist.com/macsync-new-version/121383/)
- [7] [Sanaa ya Mac Malware, Juzuu ya 2 — Kuchanganua Binaries](https://taomm.org/vol2/pdfs/CH%202%20Parsing%20Binaries.pdf)
- [8] [Apple Developer — TN3126: Ndani ya Code Signing: Hashes](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes.md)
- [9] [Apple Developer — Kuruhusu na kukataa apps na binaries](https://developer.apple.com/documentation/devicemanagement/allowing-and-denying-apps-and-binaries.md)
{{#include ../../../banners/hacktricks-training.md}}
