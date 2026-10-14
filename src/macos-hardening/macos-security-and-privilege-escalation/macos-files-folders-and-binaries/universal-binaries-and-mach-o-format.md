# macOS Universal binaries & Muundo wa Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

macOS hutumia umbizo la executable la **Mach-O**. Binary ya **universal**, au fat, huwa na slices nyingi za Mach-O maalum kwa kila architecture ndani ya faili moja. Headers za chanzo huria za Apple `fat.h` na `loader.h` hufafanua miundo na constants zilizoelezwa kwenye ukurasa huu. <sup>[[5]](#references)</sup>

Image ya Mach-O ina:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Tafuta faili kwa: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Iangalie kwa:

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

Huenda unafikiria kuwa kwa kawaida binary ya universal iliyokompailiwa kwa architectures 2 huwa **na ukubwa mara mbili** ya iliyokompailiwa kwa arch 1 pekee.

> [!TIP]
> Unapochunguza malware au apps zinazotiliwa shaka, usisimame baada ya `file` kuripoti architecture “bora” zaidi. Binary ya universal inaweza kuficha imports, load commands au metadata ya compiler tofauti katika kila slice. Kwa hiyo, kwanza orodhesha **slices zote**, kisha uzichunguze kila moja kivyake:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

SDK za hivi karibuni za macOS pia hutoa helper kama `macho_for_each_slice()` na `macho_best_slice()` katika `<mach-o/utils.h>`. Ya mwisho ni muhimu kuiga kile ambacho dyld/kernel zingepakia, lakini scanners bado zinapaswa kupitia kila slice ili kuepuka kukosa maudhui mahususi ya architecture.<sup>[[1]](#references)</sup>

## **Kichwa cha Mach-O**

Kichwa kina taarifa za msingi kuhusu faili, kama vile magic bytes za kuitambua kama faili la Mach-O na taarifa kuhusu architecture lengwa. Unaweza kukipata kwa kutumia: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

Kuna aina tofauti za faili; unaweza kuzipata zimefafanuliwa katika [**msimbo chanzo, kwa mfano hapa**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Zilizo muhimu zaidi ni:

- `MH_OBJECT`: Faili ya object inayoweza kuunganishwa tena (bidhaa za kati za uundaji, bado si faili zinazotekelezeka).
- `MH_EXECUTE`: Faili zinazotekelezeka.
- `MH_FVMLIB`: Faili ya maktaba ya VM isiyobadilika.
- `MH_CORE`: Dump za msimbo
- `MH_PRELOAD`: Faili inayotekelezeka iliyopakiwa awali (haitumiki tena katika XNU)
- `MH_DYLIB`: Maktaba zinazobadilika
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Faili za Plugin". Hutengenezwa kwa kutumia `-bundle` katika gcc na kupakiwa waziwazi na `NSBundle` au `dlopen`.
- `MH_DYSM`: Faili saidizi ya `.dSym` (faili yenye alama za utatuzi).
- `MH_KEXT_BUNDLE`: Viendelezi vya Kernel.

```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

Au kutumia [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Bendera za Mach-O**

Msimbo chanzo pia hufafanua bendera kadhaa zinazotumika kupakia maktaba:

- `MH_NOUNDEFS`: Hakuna marejeleo yasiyofafanuliwa (imeunganishwa kikamilifu)
- `MH_DYLDLINK`: Uunganishaji wa Dyld
- `MH_PREBOUND`: Marejeleo yanayobadilika yameunganishwa mapema.
- `MH_SPLIT_SEGS`: Faili hugawanya segmenti za kusoma pekee na kusoma/kuandika.
- `MH_WEAK_DEFINES`: Binary ina alama zilizofafanuliwa kwa udhaifu
- `MH_BINDS_TO_WEAK`: Binary hutumia alama dhaifu
- `MH_ALLOW_STACK_EXECUTION`: Fanya stack iweze kutekelezwa
- `MH_NO_REEXPORTED_DYLIBS`: Maktaba haina amri za LC_REEXPORT
- `MH_PIE`: Executable Isiyofungamana na Nafasi
- `MH_HAS_TLV_DESCRIPTORS`: Kuna sehemu yenye vigeu vya ndani vya thread
- `MH_NO_HEAP_EXECUTION`: Hairuhusu utekelezaji kwenye kurasa za heap/data
- `MH_HAS_OBJC`: Binary ina sehemu za Object-C
- `MH_SIM_SUPPORT`: Usaidizi wa Simulator
- `MH_DYLIB_IN_CACHE`: Hutumika kwenye dylib/framework zilizo kwenye akiba ya maktaba zinazoshirikiwa.

## **Amri za kupakia za Mach-O**

**Mpangilio wa faili kwenye kumbukumbu** umebainishwa hapa, ukieleza **mahali ilipo jedwali la alama**, muktadha wa thread kuu wakati utekelezaji unapoanza, na **maktaba zinazoshirikiwa** zinazohitajika. Maelekezo hutolewa kwa kipakiaji kinachobadilika **(dyld)** kuhusu mchakato wa kupakia binary kwenye kumbukumbu.

Hutumika muundo wa **load_command**, uliofafanuliwa kwenye **`loader.h`** iliyotajwa:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Kuna takriban **aina 50 tofauti za load commands** ambazo mfumo huzishughulikia kwa njia tofauti. Zinazotumika zaidi ni: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, na `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Kimsingi, aina hii ya Load Command hufafanua **jinsi ya kupakia \_\_TEXT** (code inayoweza kutekelezwa) **na \_\_DATA** (data ya process) **segments** kulingana na **offsets zilizoonyeshwa katika sehemu ya Data** wakati binary inatekelezwa.

Commands hizi **hufafanua segments** ambazo **huwekwa kwenye ramani** katika **nafasi ya virtual memory** ya process inapoanza kutekelezwa.

Kuna **aina tofauti** za segments, kama vile segment ya **\_\_TEXT**, inayohifadhi code inayoweza kutekelezwa ya programu, na segment ya **\_\_DATA**, iliyo na data inayotumiwa na process. **Segments hizi ziko katika sehemu ya data** ya faili ya Mach-O.

**Kila segment** inaweza **kugawanywa** zaidi katika **sections** nyingi. **Muundo wa load command** una **taarifa** kuhusu **sections hizi** ndani ya segment husika.

Kwenye header, kwanza utapata **segment header**:

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

Header hii hufafanua **idadi ya sections ambazo headers zake zinaonekana baada yake**:

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

Mfano wa **section header**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Ukiongeza **section offset** (0x37DC) na **offset** ambapo **arch** inaanza, katika hali hii `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Pia inawezekana kupata maelezo ya **headers** kutoka kwa **command line** kwa kutumia:

```bash
otool -lv /bin/ls
```

Common segments zinazopakiwa na cmd hii:

- **`__PAGEZERO`:** Huelekeza kernel **ku-map** **address zero** ili isiweze **kusomwa, kuandikiwa au kutekelezwa**. Vigezo vya maxprot na minprot katika muundo huwekwa kuwa sifuri kuonyesha kwamba **ukurasa huu hauna ruhusa za kusoma-kuandika-kutekeleza**.
  - Ugawaji huu ni muhimu ili **kupunguza uwezekano wa udhaifu wa NULL pointer dereference**. Hii ni kwa sababu XNU hutekeleza hard page zero inayohakikisha kwamba ukurasa wa kwanza (wa kwanza tu) wa kumbukumbu hauwezi kufikiwa (isipokuwa katika i386). Binary inaweza kutimiza sharti hili kwa kutengeneza \_\_PAGEZERO ndogo (kwa kutumia `-pagezero_size`) inayofunika 4k za kwanza na kufanya sehemu nyingine ya kumbukumbu ya 32bit ipatikane katika user na kernel mode.
- **`__TEXT`**: Ina **code** inayoweza **kutekelezwa**, yenye ruhusa za **kusoma** na **kutekeleza** (bila ruhusa za kuandikwa)**.** Sehemu za kawaida za segment hii:
  - `__text`: Binary code iliyokompailiwa
  - `__const`: Data isiyobadilika (ya kusomwa tu)
  - `__[c/u/os_log]string`: String constants za C, Unicode au os logs
  - `__stubs` na `__stubs_helper`: Hutumika wakati wa mchakato wa kupakia dynamic library
  - `__unwind_info`: Data ya stack unwind.
  - Kumbuka kwamba maudhui haya yote yamesainiwa lakini pia yamewekewa alama ya kutekelezeka (jambo linalounda chaguo zaidi za exploitation ya sehemu ambazo hazihitaji lazima ruhusa hii, kama vile sehemu maalum za strings).
- **`__DATA`**: Ina data **inayoweza kusomwa** na **kuandikiwa** (isiyotekelezeka)**.**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Pointer ya symbol isiyo-lazy (hufungwa wakati wa kupakia)
  - `__la_symbol_ptr`: Pointer ya symbol ya lazy (hufungwa inapotumika)
  - `__const`: Inapaswa kuwa data ya kusomwa tu (lakini sivyo kwa hakika)
  - `__cfstring`: Strings za CoreFoundation
  - `__data`: Global variables (ambazo zimeanzishwa)
  - `__bss`: Static variables (ambazo hazijaanzishwa)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, n.k.): Taarifa zinazotumiwa na Objective-C runtime
- **`__DATA_CONST`**: \_\_DATA.\_\_const haijahakikishiwa kuwa constant (ina ruhusa za kuandikwa), wala pointers nyingine na GOT. Sehemu hii huweka `__const`, baadhi ya initializers na jedwali la GOT (baada ya kutatuliwa) kuwa **ya kusomwa tu** kwa kutumia `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Ni za kawaida katika binaries za hivi karibuni za Apple Silicon. Segments hizi huhifadhi pointers ambazo lazima zithibitishwe wakati wa kupakia au kuzitumia (kwa mfano `__auth_got`). Ikiwa mbinu ya rebinding, hook au import-patching inakagua tu sehemu za zamani za `__got` / `__la_symbol_ptr`, huenda ikakosa call sites halisi katika binaries za kisasa za `arm64e`. Kwa maelezo zaidi kuhusu sehemu hizi, angalia [ukurasa huu](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Ina taarifa za linker (dyld), kama vile entries za symbol, string na relocation table. Ni kontena la jumla la maudhui ambayo hayapo katika `__TEXT` au `__DATA`, na maudhui yake yanafafanuliwa katika load commands nyingine.
  - Taarifa za dyld: Rebase, opcodes za Non-lazy/lazy/weak binding na export info
  - Mwanzo wa functions: Jedwali la anwani za mwanzo za functions
  - Data In Code: Visiwa vya data ndani ya \_\_text
  - Jedwali la SYmbol: Symbols katika binary
  - Indirect Symbol Table: Symbols za pointer/stub
  - String Table
  - Code Signature
- **`__OBJC`**: Ina taarifa zinazotumiwa na Objective-C runtime. Hata hivyo, taarifa hizi zinaweza pia kupatikana katika segment ya \_\_DATA, ndani ya sehemu mbalimbali za \_\_objc\_\*.
- **`__RESTRICT`**: Segment isiyo na maudhui yenye sehemu moja inayoitwa **`__restrict`** (ambayo pia haina maudhui), inayohakikisha kwamba binary inapotekelezwa, itapuuza environment variables za DYLD.

Kama ilivyowezekana kuona kwenye code, **segments pia hutumia flags** (ingawa hazitumiki sana):

- `SG_HIGHVM`: Core pekee (haitumiki)
- `SG_FVMLIB`: Haitumiki
- `SG_NORELOC`: Segment haina relocation
- `SG_PROTECTED_VERSION_1`: Usimbaji fiche. Kwa mfano, hutumiwa na Finder kusimba kwa fiche segment ya maandishi `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** ina entrypoint katika **sifa ya entryoff.** Wakati wa kupakia, **dyld** huongeza tu thamani hii kwenye **base ya binary** (iliyo kwenye kumbukumbu), kisha **huruka** hadi kwenye instruction hii ili kuanza kutekeleza code ya binary.

**`LC_UNIXTHREAD`** ina thamani ambazo register lazima iwe nazo wakati main thread inapoanza. Hii iliondolewa matumizi tayari lakini **`dyld`** bado huitumia. Inawezekana kuona thamani za registers zilizowekwa na hii kwa kutumia:

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


Ina taarifa kuhusu **code signature ya faili la Macho-O**. Ina **offset** pekee inayoelekeza kwenye **signature blob**. Kwa kawaida, hii huwa mwishoni kabisa mwa faili.\
Unaweza kupata maelezo zaidi kuhusu sehemu hii katika [**chapisho hili la blogu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) na [**gist hii**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Hutoa uwezo wa kusimba binary. Hata hivyo, bila shaka, mshambuliaji akifaulu kuhujumu process, ataweza kutoa dump ya memory ambayo haijasimbwa.

### **`LC_LOAD_DYLINKER`**

Ina **njia ya executable ya dynamic linker** inayopanga shared libraries katika address space ya process. **Thamani yake huwa `/usr/lib/dyld` kila wakati**. Ni muhimu kutambua kwamba katika macOS, upangaji wa dylib hufanyika katika **user mode**, si kernel mode.

### **`LC_IDENT`**

Imepitwa na wakati, lakini dump zinapowekwa zitengenezwe panic inapotokea, hutengenezwa Mach-O core dump na kernel version huwekwa kwenye command ya `LC_IDENT`.

### **`LC_UUID`**

UUID ya nasibu. Haina matumizi ya moja kwa moja, lakini XNU huihifadhi pamoja na taarifa nyingine za process. Inaweza kutumika katika crash reports.

### **`LC_BUILD_VERSION`**

Binary za kisasa kwa kawaida huwa na command hii ya kutangaza **target platform**, **toleo la chini kabisa la OS**, **toleo la SDK**, na kwa hiari **matoleo ya tool** yaliyotumika kujenga slice hiyo. Kwa mtazamo wa offensive/reversing, hii ni muhimu sana kubaini jinsi sample ilivyojengwa na kutambua haraka universal binaries zisizo za kawaida ambapo slice moja ilicompilewa kwa SDK au deployment target tofauti. Binary za zamani bado zinaweza kutumia `LC_VERSION_MIN_*` badala yake.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Hurusu kubainisha vigezo vya mazingira kwa dyld kabla mchakato haujaendeshwa. Hili linaweza kuwa hatari sana kwa kuwa linaweza kuruhusu kutekeleza msimbo kiholela ndani ya mchakato, kwa hivyo amri hii ya upakiaji hutumika tu katika build ya dyld yenye `#define SUPPORT_LC_DYLD_ENVIRONMENT`, na uchakataji wake huzuiwa zaidi kwa vigezo vya muundo `DYLD_..._PATH` vinavyobainisha njia za upakiaji.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Toolchain za hivi karibuni mara nyingi huhifadhi metadata ya export/bind/rebase katika amri hizi badala ya kutegemea opcodes za zamani za `LC_DYLD_INFO[_ONLY]` pekee. Zote ni maingizo ya `linkedit_data_command` yanayoelekeza ndani ya **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Trie fupi yenye alama zinazotolewa na image.
- **`LC_DYLD_CHAINED_FIXUPS`**: Msururu wa fixup kwa kila segment unaotumiwa na dyld kutekeleza rebases na binds. Kwenye Apple Silicon, hapa pia utakutana na fixup nyingi za kisasa za pointer zilizo authenticated.

Metadata hii ni muhimu sana unapojenga upya imports/exports, kuelewa kwa nini dependency iliyopakiwa kupitia `@rpath` ilitatuliwa jinsi ilivyotatuliwa, au kubaini kwa nini jaribio la hook/rebinding lilishindwa kwenye target ya kisasa ya `arm64e`. `dyld_info` inaweza pia kutumika dhidi ya **njia za dylib zinazopatikana kwenye cache pekee** ambazo hazipo kama faili za kujitegemea kwenye diski. Hili ni muhimu sana kwenye macOS za kisasa ambako maktaba nyingi za mfumo huishi tu kwenye shared cache.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Amri hii ya kisasa ya kupakia inahusika zaidi unapokagua **kernel collections / kernelcache-style filesets**. Badala ya kuwakilisha image moja inayojitegemea, Mach-O ya nje hufanya kazi kama kontena, na kila `LC_FILESET_ENTRY` huelekeza kwenye Mach-O iliyopachikwa yenye **entry id** yake inayofanana na njia, anwani ya VM na file offset. Unaporeverse vipengele vya kernel vya kisasa vya macOS/iOS, amri hii mara nyingi ndiyo kiungo kati ya kontena la kiwango cha juu na image halisi unayotaka kutoa au kutenganisha.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Kwa workflows za vitendo za uchimbaji, angalia [ukurasa huu mwingine kuhusu macOS kernel extensions na kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Amri hii ya upakiaji inaeleza utegemezi wa **dynamic** **library** ambao **unaelekeza** **loader** (dyld) **kupakia na ku-link maktaba hiyo**. Kuna amri ya upakiaji ya `LC_LOAD_DYLIB` **kwa kila maktaba** inayohitajika na binary ya Mach-O.

- Amri hii ya upakiaji ni muundo wa aina ya **`dylib_command`** (ambao una struct dylib, inayoeleza dynamic library halisi inayotegemewa):

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t toleo la uoanifu; / namba ya toleo la uoanifu la maktaba /](<../../../images/image (486).png>)

Unaweza pia kupata maelezo haya kupitia CLI kwa:

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
> Binary ya Mach-O inaweza kuwa na **constructor** moja au **zaidi**, ambazo **zitatekelezwa** **kabla** ya anwani iliyobainishwa katika **LC_MAIN**.\
> Offsets za constructor zozote huhifadhiwa katika sehemu ya **\_\_mod_init_func** ya segment ya **\_\_DATA_CONST**.

## **Data ya Mach-O**

Katika kiini cha faili kuna eneo la data, ambalo linajumuisha segment kadhaa kama zilivyofafanuliwa katika eneo la load-commands. **Sehemu mbalimbali za data zinaweza kuwekwa ndani ya kila segment**, huku kila sehemu **ikiwa na code au data** mahususi kwa aina fulani.

> [!TIP]
> Kimsingi, data ni sehemu yenye **taarifa** zote zinazopakiwa na load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Hii inajumuisha:

- **Jedwali la functions:** Linalohifadhi taarifa kuhusu functions za programu.
- **Jedwali la symbols**: Linalohifadhi taarifa kuhusu function za nje zinazotumiwa na binary
- Linaweza pia kuwa na majina ya functions za ndani, variables na mengine mengi.

Unaweza kuitazama kwa kutumia zana ya [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Au kupitia cli:

```bash
size -m /bin/ls
```

### Data iliyoambatishwa na overlays zinazochanganuliwa kwa kurudi nyuma

Loader inaweza kuhifadhi usanidi kwenye data iliyoambatishwa badala ya sehemu ya Mach-O yenye jina. Kisha reverse parser hujikita kwenye alama ya mwisho, husoma ukubwa uliohifadhiwa mara moja kabla yake, na hutumia thamani hiyo kupata na kusimbua blob iliyotangulia. Loader moja ya universal iliyozingatiwa ilitumia mpangilio huu kwa URL ya downloader iliyosimbwa kwa XOR:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Unaporeverse binary usiyoifahamu, kagua bytes zilizo karibu na alama za mwisho zinazotambulika, na ufuatilie kila hesabu ya ukubwa inayofanywa kwa kurudi nyuma kabla ya kudhani kwamba strings au configuration lazima ziwe sehemu ya load-command section. Alama na ufunguo wa XOR hutegemea sampuli husika; mbinu inayoweza kutumika tena ni trailer inayojieleza.

## Sehemu za Kawaida za Objective-C

Katika segment ya `__TEXT` (r-x):

- `__objc_classname`: Majina ya class (strings)
- `__objc_methname`: Majina ya method (strings)
- `__objc_methtype`: Aina za method (strings)

Katika segment ya `__DATA` (rw-):

- `__objc_classlist`: Pointers za Objective-C classes zote
- `__objc_nlclslist`: Pointers za Objective-C Non-Lazy classes
- `__objc_catlist`: Pointer ya Categories
- `__objc_nlcatlist`: Pointer za Non-Lazy Categories
- `__objc_protolist`: Orodha ya Protocols
- `__objc_const`: Data isiyobadilika
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Sehemu za Mach-O si rahisi kuelewa kama unavyoweza kufikiri](https://objective-see.org/blog/blog_0x80.html)
- [2] [Ukurasa wa mwongozo wa dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Kusoma Entitlements Zako Mwenyewe](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source - Mach-O `fat.h` na `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - Toleo jipya la MacSync macOS stealer linalenga wapenda crypto na developers](https://securelist.com/macsync-new-version/121383/)
