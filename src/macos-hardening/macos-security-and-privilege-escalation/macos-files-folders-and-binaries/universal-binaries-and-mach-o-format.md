# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

Binaries za Mac OS kwa kawaida hu-compile kama **universal binaries**. **Universal binary** inaweza **ku-support architectures nyingi ndani ya file moja**.

Binaries hizi hufuata **Mach-O structure**, ambayo kimsingi imeundwa na:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Tafuta file kwa kutumia: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Header ina bytes za **magic**, zikifuatiwa na **idadi** ya **archs** ambazo file **ina** (`nfat_arch`), na kila arch itakuwa na `fat_arch` struct.

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

au kwa kutumia tool ya [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Kama unavyoweza kufikiria, kwa kawaida universal binary iliyocompile kwa architectures 2 **huongeza ukubwa mara mbili** ikilinganishwa na iliyocompile kwa arch 1 pekee.

> [!TIP]
> Unapofanya triage ya malware au apps zinazotia shaka, usisimame baada ya `file` kuripoti architecture "bora". Universal binary inaweza kuficha imports, load commands au compiler metadata tofauti katika kila slice, kwa hiyo kwanza enumerate **slices** zote, kisha uzikague kila moja kivyake:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Recent macOS SDKs pia hutoa helpers kama `macho_for_each_slice()` na `macho_best_slice()` katika `<mach-o/utils.h>`. Ya mwisho ni muhimu kuiga kile ambacho dyld/kernel ingepakia, lakini scanners bado zinapaswa kupitia kila slice ili kuepuka kukosa maudhui maalum kwa usanifu.<sup>[[1]](#references)</sup>

## **Mach-O Header**

Header ina taarifa za msingi kuhusu faili, kama vile magic bytes za kuitambua kama faili ya Mach-O na taarifa kuhusu usanifu lengwa. Unaweza kuipata kwa: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Kuna aina tofauti za faili, unaweza kuzipata zikiwa zimefafanuliwa katika [**source code kwa mfano hapa**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Muhimu zaidi ni:

- `MH_OBJECT`: Relocatable object file (bidhaa za kati za compilation, bado si executables).
- `MH_EXECUTE`: Executable files.
- `MH_FVMLIB`: Fixed VM library file.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Preloaded executable file (haitumiki tena katika XNU)
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin files". Hutengenezwa kwa kutumia -bundle katika gcc na kupakiwa waziwazi na `NSBundle` au `dlopen`.
- `MH_DYSM`: Companion `.dSym` file (faili yenye symbols kwa ajili ya debugging).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Au kutumia [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

Source code pia inafafanua flags kadhaa muhimu kwa kupakia libraries:

- `MH_NOUNDEFS`: Hakuna references zisizofafanuliwa (imeunganishwa kikamilifu)
- `MH_DYLDLINK`: Uunganishaji wa Dyld
- `MH_PREBOUND`: Dynamic references zimefungwa mapema.
- `MH_SPLIT_SEGS`: File inagawanya segments za r/o na r/w.
- `MH_WEAK_DEFINES`: Binary ina symbols zilizofafanuliwa kwa udhaifu
- `MH_BINDS_TO_WEAK`: Binary inatumia weak symbols
- `MH_ALLOW_STACK_EXECUTION`: Fanya stack iwe executable
- `MH_NO_REEXPORTED_DYLIBS`: Library haina commands za LC_REEXPORT
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Kuna section yenye thread local variables
- `MH_NO_HEAP_EXECUTION`: Hakuna execution kwa heap/data pages
- `MH_HAS_OBJC`: Binary ina sections za oBject-C
- `MH_SIM_SUPPORT`: Usaidizi wa Simulator
- `MH_DYLIB_IN_CACHE`: Hutumika kwenye dylibs/frameworks katika shared library cache.

## **Mach-O Load commands**

**Mpangilio wa file katika memory** umeainishwa hapa, ukieleza **mahali lilipo symbol table**, context ya main thread wakati execution inapoanza, pamoja na **shared libraries** zinazohitajika. Maelekezo hutolewa kwa dynamic loader **(dyld)** kuhusu mchakato wa kupakia binary kwenye memory.

Hutumia muundo wa **load_command**, uliofafanuliwa katika **`loader.h`** iliyotajwa:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Kuna takriban **aina 50 tofauti za load commands** ambazo mfumo huzishughulikia kwa njia tofauti. Zinazotumika zaidi ni: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, na `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Kimsingi, aina hii ya Load Command hufafanua **jinsi ya kupakia \_\_TEXT** (msimbo unaotekelezwa) **na \_\_DATA** (data ya process) **segments** kulingana na **offsets zilizoonyeshwa katika sehemu ya Data** wakati binary inatekelezwa.

Commands hizi **hufafanua segments** ambazo **huwekwa ramani** katika **virtual memory space** ya process inapotekelezwa.

Kuna **aina tofauti za segments**, kama vile **\_\_TEXT** segment, ambayo huhifadhi msimbo unaotekelezwa wa program, na **\_\_DATA** segment, ambayo ina data inayotumiwa na process. **Segments hizi zinapatikana katika sehemu ya data** ya faili ya Mach-O.

**Kila segment** inaweza kugawanywa zaidi katika **sections** nyingi. **Muundo wa load command** una **taarifa** kuhusu **sections hizi** ndani ya segment husika.

Katika header, kwanza unapata **segment header**:

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

Ukijumlisha **section offset** (0x37DC) na **offset** ambapo **arch** inaanza, katika hali hii `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Pia inawezekana kupata taarifa za **headers** kutoka kwenye **command line** kwa kutumia:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** Huagiza kernel **map** **address zero** ili isiweze **kusomwa, kuandikwa, au kutekelezwa**. Vigezo vya maxprot na minprot katika structure huwekwa kuwa sifuri kuonyesha kuwa **hakuna read-write-execute rights kwenye ukurasa huu**.
- Allocation hii ni muhimu kwa **mitigate NULL pointer dereference vulnerabilities**. Hii ni kwa sababu XNU huweka hard page zero inayohakikisha kuwa ukurasa wa kwanza (wa kwanza pekee) wa memory haupatikani (isipokuwa kwenye i386). Binary inaweza kutimiza mahitaji haya kwa kutengeneza \_\_PAGEZERO ndogo (kwa kutumia `-pagezero_size`) ili kufunika 4k ya kwanza na kufanya sehemu iliyobaki ya 32bit memory ipatikane katika user na kernel mode.
- **`__TEXT`**: Ina **executable** **code** yenye ruhusa za **read** na **execute** (si writable)**.** Common sections za segment hii:
- `__text`: Compiled binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode au os logs string constants
- `__stubs` na `__stubs_helper`: Hutumika wakati wa dynamic library loading process
- `__unwind_info`: Stack unwind data.
- Kumbuka kuwa content hii yote imesainiwa lakini pia imewekwa kama executable (na hivyo kuunda options zaidi za exploitation ya sections ambazo si lazima zihitaji privilege hii, kama string dedicated sections).
- **`__DATA`**: Ina data ambayo ni **readable** na **writable** (si executable)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Inapaswa kuwa read-only data (lakini si kweli kabisa)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (ambazo zimeinitialized)
- `__bss`: Static variables (ambazo hazija initialized)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, n.k.): Taarifa inayotumiwa na Objective-C runtime
- **`__DATA_CONST`**: \_\_DATA.\_\_const haijahakikishiwa kuwa constant (write permissions), wala pointers nyingine na GOT. Section hii hufanya `__const`, initializers fulani na GOT table (baada ya kutatuliwa) kuwa **read only** kwa kutumia `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Ni common katika Apple Silicon binaries za hivi karibuni. Segments hizi hushikilia pointers ambazo lazima zi-authenticate wakati wa load au matumizi (kwa mfano `__auth_got`). Ikiwa rebinding, hook au import-patching trick itaangalia tu sections za zamani za `__got` / `__la_symbol_ptr`, inaweza kukosa call sites halisi katika `arm64e` binaries za kisasa. Kwa maelezo zaidi kuhusu sections hizi, angalia [ukurasa huu](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Ina taarifa za linker (dyld), kama symbol, string na relocation table entries. Ni generic container ya contents ambazo haziko katika `__TEXT` au `__DATA`, na content yake inaelezwa katika load commands nyingine.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes na export info
- Functions starts: Table ya start addresses za functions
- Data In Code: Data islands katika \_\_text
- SYmbol Table: Symbols katika binary
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Ina taarifa inayotumiwa na Objective-C runtime. Ingawa taarifa hii inaweza pia kupatikana katika \_\_DATA segment, ndani ya sections mbalimbali za \_\_objc\_\*.
- **`__RESTRICT`**: Segment isiyo na content yenye section moja inayoitwa **`__restrict`** (ambayo pia ni tupu), inayohakikisha kuwa wakati binary inaendeshwa, itapuuza DYLD environmental variables.

Kama ilivyowezekana kuonekana katika code, **segments pia zinaunga mkono flags** (ingawa hazitumiki sana):

- `SG_HIGHVM`: Core only (haikutumiki)
- `SG_FVMLIB`: Haikutumiki
- `SG_NORELOC`: Segment haina relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Hutumiwa, kwa mfano, na Finder ku-encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** ina entrypoint katika **entryoff attribute.** Wakati wa load, **dyld** huongeza tu value hii kwenye (in-memory) **base ya binary**, kisha **huruka** kwenda kwenye instruction hii ili kuanza execution ya binary’s code.

**`LC_UNIXTHREAD`** ina values ambazo register lazima iwe nazo wakati wa kuanzisha main thread. Hii ilikuwa tayari deprecated lakini **`dyld`** bado huitumia. Inawezekana kuona **values** za registers zilizowekwa na hii kwa kutumia:
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


Ina taarifa kuhusu **code signature ya faili la Macho-O**. Ina **offset** pekee ambayo **inaelekeza** kwenye **signature blob**. Kwa kawaida hii huwa mwishoni kabisa mwa faili.\
Hata hivyo, unaweza kupata maelezo fulani kuhusu sehemu hii katika [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) na [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Hutoa support kwa binary encryption. Hata hivyo, bila shaka, ikiwa attacker ataweza ku-compromise process, ataweza kudump memory bila encryption.

### **`LC_LOAD_DYLINKER`**

Ina **path ya dynamic linker executable** ambayo hu-map shared libraries kwenye process address space. **Value huwekwa kila mara kuwa `/usr/lib/dyld`**. Ni muhimu kutambua kwamba katika macOS, dylib mapping hufanyika katika **user mode**, si katika kernel mode.

### **`LC_IDENT`**

Imepitwa na wakati, lakini inapoconfigured kutengeneza dumps wakati wa panic, Mach-O core dump huundwa na kernel version huwekwa katika command ya `LC_IDENT`.

### **`LC_UUID`**

UUID ya random. Si muhimu kwa kitu chochote moja kwa moja, lakini XNU hui-cache pamoja na taarifa nyingine za process. Inaweza kutumika katika crash reports.

### **`LC_BUILD_VERSION`**

Binaries za kisasa kwa kawaida huwa na command hii ya kutangaza **platform inayolengwa**, **toleo la chini kabisa la OS**, **toleo la SDK**, na kwa hiari **tool versions** zilizotumika kujenga slice hiyo. Kwa mtazamo wa offensive/reversing, hii ni muhimu sana katika kufingerprint jinsi sample ilivyojengwa na kutambua haraka universal binaries zisizo za kawaida ambapo slice moja ili-compile-tiwa kwa SDK au deployment target tofauti. Binaries za zamani huenda bado zikatumia `LC_VERSION_MIN_*` badala yake.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Huruhusu kubainisha environment variables kwa dyld kabla mchakato haujatekelezwa. Hili linaweza kuwa hatari sana kwa sababu linaweza kuruhusu kutekeleza arbitrary code ndani ya mchakato, hivyo load command hii hutumika tu katika dyld iliyojengwa kwa `#define SUPPORT_LC_DYLD_ENVIRONMENT`, na uchakataji wake huzuiwa zaidi kwa variables zenye muundo wa `DYLD_..._PATH` zinazobainisha load paths.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Toolchains za hivi karibuni mara nyingi huhifadhi metadata ya export/bind/rebase katika commands hizi badala ya kutegemea tu opcodes za zamani za `LC_DYLD_INFO[_ONLY]`. Zote ni entries za `linkedit_data_command` zinazoelekeza ndani ya **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Compact trie yenye symbols zilizo-export na image.
- **`LC_DYLD_CHAINED_FIXUPS`**: Fixup chains za kila segment zinazotumiwa na dyld kutekeleza rebases na binds. Kwenye Apple Silicon, hapa ndipo pia utakutana na authenticated pointer fixups nyingi za kisasa.

Metadata hii ni muhimu sana wakati wa kureconstruct imports/exports, kuelewa kwa nini dependency iliyopakiwa kwa `@rpath` iliresolve kwa njia hiyo, au kubaini kwa nini jaribio la hook/rebinding lilishindwa kwenye target ya kisasa ya `arm64e`. `dyld_info` pia inaweza kutumika dhidi ya **cache-only dylib paths** ambazo hazipo kama files zinazojitegemea kwenye disk, jambo ambalo ni muhimu sana kwenye macOS za kisasa ambapo system libraries nyingi zipo tu ndani ya shared cache.<sup>[[2]](#references)</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Hii ni load command ya kisasa inayohusiana zaidi na ukaguzi wa **kernel collections / kernelcache-style filesets**. Badala ya kuwakilisha image moja inayojitegemea, Mach-O ya nje hufanya kazi kama container, na kila `LC_FILESET_ENTRY` huelekeza kwenye Mach-O iliyopachikwa yenye **entry id** yake inayofanana na path, anwani ya VM na file offset. Ikiwa unafanya reversing ya components za kernel za kisasa za macOS/iOS, command hii mara nyingi huwa kiungo kati ya container ya kiwango cha juu na image halisi unayotaka kutoa au ku-disassemble.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Kwa workflows za vitendo za extraction, angalia [ukurasa huu mwingine kuhusu macOS kernel extensions na kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Load command hii inaeleza dependency ya **dynamic** **library** ambayo **inauagiza** **loader** (dyld) **kupakia na ku-link library hiyo**. Kuna load command ya `LC_LOAD_DYLIB` **kwa kila library** ambayo binary ya Mach-O inahitaji.

- Load command hii ni structure ya aina ya **`dylib_command`** (ambayo ina struct dylib, inayoeleza dynamic library tegemezi halisi):
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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t compatibility version; / nambari ya toleo la uoanifu la library /](<../../../images/image (486).png>)

Unaweza pia kupata maelezo haya kutoka kwa CLI kwa kutumia:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Baadhi ya libraries zinazoweza kuhusishwa na malware ni:

- **DiskArbitration**: Kufuatilia USB drives
- **AVFoundation:** Kunasa audio na video
- **CoreWLAN**: Scans za Wifi.

> [!TIP]
> Binary ya Mach-O inaweza kuwa na **constructor** **moja** au **zaidi**, ambazo **zitatekelezwa** **kabla** ya address iliyobainishwa katika **LC_MAIN**.\
> Offsets za constructors zozote huhifadhiwa katika section ya **\_\_mod_init_func** ya segment ya **\_\_DATA_CONST**.

## **Data ya Mach-O**

Kiini cha file kina region ya data, ambayo imeundwa na segments kadhaa kama zilivyobainishwa katika load-commands region. **Aina mbalimbali za data sections zinaweza kuhifadhiwa ndani ya kila segment**, huku kila section **ikiwa na code au data** maalum kwa aina fulani.

> [!TIP]
> Data kimsingi ni sehemu iliyo na **taarifa** zote zinazopakiwa na load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Hii inajumuisha:

- **Function table:** Huhifadhi taarifa kuhusu program functions.
- **Symbol table**: Ina taarifa kuhusu external function inayotumiwa na binary
- Pia inaweza kuwa na internal function, majina ya variables, na zaidi.

Ili kuikagua unaweza kutumia tool ya [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Au kutoka kwenye cli:
```bash
size -m /bin/ls
```
## Sehemu za Kawaida za Objetive-C

Katika segment ya `__TEXT` (r-x):

- `__objc_classname`: Majina ya classes (strings)
- `__objc_methname`: Majina ya methods (strings)
- `__objc_methtype`: Aina za methods (strings)

Katika segment ya `__DATA` (rw-):

- `__objc_classlist`: Pointers kwa classes zote za Objetive-C
- `__objc_nlclslist`: Pointers kwa Non-Lazy Objective-C classes
- `__objc_catlist`: Pointer kwa Categories
- `__objc_nlcatlist`: Pointer kwa Non-Lazy Categories
- `__objc_protolist`: Orodha ya Protocols
- `__objc_const`: Data ya kudumu
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## Marejeo

- [1] [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Reading Your Own Entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
