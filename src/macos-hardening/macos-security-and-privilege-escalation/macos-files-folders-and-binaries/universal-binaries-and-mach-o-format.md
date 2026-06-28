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

Search for the file with: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

The header has the **magic** bytes followed by the **number** of **archs** the file **contains** (`nfat_arch`) and each arch will have a `fat_arch` struct.

Check it with:

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

or using the [Mach-O View](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

As you may be thinking usually a universal binary compiled for 2 architectures **doubles the size** of one compiled for just 1 arch.

> [!TIP]
> When triaging malware or suspicious apps, don't stop after `file` reports the "best" architecture. A universal binary can hide different imports, load commands or compiler metadata in each slice, so enumerate **all** the slices first and then inspect them independently:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
SDK za hivi karibuni za macOS pia hutoa helpers kama `macho_for_each_slice()` na `macho_best_slice()` katika `<mach-o/utils.h>`. Ya pili ni muhimu kuiga kile ambacho dyld/kernel ingepakia, lakini scanners bado wanapaswa kupitia kila slice ili kuepuka kukosa maudhui mahususi kwa arch.

## **Mach-O Header**

Header ina taarifa za msingi kuhusu faili, kama magic bytes za kuitambulisha kama faili ya Mach-O na taarifa kuhusu target architecture. Unaweza kuipata katika: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Kuna aina tofauti za faili, unaweza kuzipata zimefafanuliwa kwenye [**msimbo chanzo kwa mfano hapa**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Zilizo muhimu zaidi ni:

- `MH_OBJECT`: Faili ya object inayoweza kuhamishwa (bidhaa za kati za ucompilation, bado si executables).
- `MH_EXECUTE`: Faili zinazoweza kuendeshwa.
- `MH_FVMLIB`: Faili ya maktaba ya Fixed VM.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Faili ya executable iliyopakiwa mapema (haiauniwi tena katika XNU)
- `MH_DYLIB`: Maktaba za Dynamic
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin files". Hutengenezwa kwa kutumia -bundle katika gcc na hupakiwa waziwazi na `NSBundle` au `dlopen`.
- `MH_DYSM`: Faili shirikishi `.dSym` (faili lenye symbols kwa ajili ya debugging).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Atau kwa kutumia [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

Msimbo wa chanzo pia hufafanua flags kadhaa muhimu kwa kupakia libraries:

- `MH_NOUNDEFS`: Hakuna marejeleo yasiyofafanuliwa (ime-linkiwa kikamilifu)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamic references prebound.
- `MH_SPLIT_SEGS`: Faili hugawanya r/o na r/w segments.
- `MH_WEAK_DEFINES`: Binary ina weak defined symbols
- `MH_BINDS_TO_WEAK`: Binary hutumia weak symbols
- `MH_ALLOW_STACK_EXECUTION`: Fanya stack iwe executable
- `MH_NO_REEXPORTED_DYLIBS`: Library haina amri za LC_REEXPORT
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Kuna section yenye thread local variables
- `MH_NO_HEAP_EXECUTION`: Hakuna execution kwa heap/data pages
- `MH_HAS_OBJC`: Binary ina sehemu za oBject-C
- `MH_SIM_SUPPORT`: Usaidizi wa simulator
- `MH_DYLIB_IN_CACHE`: Hutumika kwenye dylibs/frameworks katika shared library cache.

## **Mach-O Load commands**

**Mpangilio wa faili ndani ya memory** umebainishwa hapa, ukiweka bayana **mahali pa symbol table**, muktadha wa main thread wakati wa kuanza kwa execution, na **shared libraries** zinazohitajika. Maelekezo hutolewa kwa dynamic loader **(dyld)** kuhusu mchakato wa kupakia binary ndani ya memory.

Hii hutumia muundo wa **load_command**, uliofafanuliwa katika **`loader.h`** iliyotajwa:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Kuna takriban **aina 50 tofauti za load commands** ambazo mfumo hushughulikia kwa njia tofauti. Zilizozoeleka zaidi ni: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, na `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Kimsingi, aina hii ya Load Command hufafanua **jinsi ya kupakia sehemu za \_\_TEXT** (msimbo unaotekelezeka) **na \_\_DATA** (data ya process) **kulingana na offsets zilizoonyeshwa katika Data section** binary inapotekelezwa.

Amri hizi **hufafanua segments** ambazo **huwekwa (mapped)** ndani ya **virtual memory space** ya process wakati inatekelezwa.

Kuna **aina tofauti** za segments, kama vile segment ya **\_\_TEXT**, ambayo huhifadhi msimbo unaotekelezeka wa programu, na segment ya **\_\_DATA**, ambayo ina data inayotumiwa na process. Hizi **segments ziko katika data section** ya faili ya Mach-O.

**Kila segment** inaweza kugawanywa zaidi katika **sections** kadhaa. **Muundo wa load command** una **taarifa** kuhusu **hizi sections** ndani ya segment husika.

Kwenye header kwanza unapata **segment header**:

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

Header hii hufafanua **idadi ya sections ambazo headers zake huonekana baada ya** hiyo:
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

Uki **ongeza** **section offset** (0x37DC) + **offset** ambako **arch huanza**, katika kesi hii `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Pia inawezekana kupata **headers information** kutoka **command line** kwa:
```bash
otool -lv /bin/ls
```
Segimenti za kawaida zinazopakiwa na cmd hii:

- **`__PAGEZERO`:** Inaielekeza kernel **kuiweka** **address zero** ili **isiweze kusomwa, kuandikwa, au kutekelezwa**. Vigezo `maxprot` na `minprot` kwenye structure huwekwa kuwa zero kuonyesha kuwa **hakuna ruhusa za read-write-execute kwenye page hii**.
- Ugawaji huu ni muhimu ili **kupunguza NULL pointer dereference vulnerabilities**. Hii ni kwa sababu XNU inalazimisha hard page zero ambayo huhakikisha page ya kwanza (pekee ya kwanza) ya memory haiwezi kufikiwa (isipokuwa katika i386). Binary inaweza kutimiza sharti hili kwa kutengeneza **__PAGEZERO** ndogo (`-pagezero_size`) ili kufunika kwanza 4k na kufanya iliyobaki ya 32bit memory ipatikane katika user na kernel mode.
- **`__TEXT`**: Ina **code** inayoweza **kutekelezwa** yenye ruhusa za **read** na **execute** (hakuna writable)**.** Sehemu za kawaida za segment hii:
- `__text`: Compiled binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode or os logs string constants
- `__stubs` and `__stubs_helper`: Involved during the dynamic library loading process
- `__unwind_info`: Stack unwind data.
- Kumbuka kuwa maudhui haya yote yamesainiwa lakini pia yamewekwa kama executable (hii huleta chaguo zaidi za exploitation kwa sehemu ambazo si lazima ziwe na ruhusa hii, kama sehemu maalum za strings).
- **`__DATA`**: Ina data ambayo inaweza **kusomwa** na **kuandikwa** (hakuna executable)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Should be read-only data (not really)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (that have been initialized)
- `__bss`: Static variables (that have not been initialized)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Information used by the Objective-C runtime
- **`__DATA_CONST`**: \_\_DATA.\_\_const si hakikishiwi kuwa constant (write permissions), wala si guaranteed kuwa pointers nyingine na GOT. Sehemu hii hufanya `__const`, baadhi ya initializers na jedwali la GOT (mara tu likisharesolviwa) **read only** kwa kutumia `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Kawaida katika binaries mpya za Apple Silicon. Segimenti hizi huhifadhi pointers ambazo lazima zithibitishwe wakati wa load au use time (kwa mfano `__auth_got`). Ikiwa rebinding, hook au import-patching trick inakagua tu sehemu za urithi `__got` / `__la_symbol_ptr`, inaweza kukosa real call sites kwenye binaries za kisasa za `arm64e`. Kwa maelezo zaidi kuhusu sehemu hizi angalia [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Ina taarifa za linker (dyld) kama vile entries za symbol, string, na relocation table. Ni generic container kwa maudhui ambayo hayapo ndani ya `__TEXT` au `__DATA` na maudhui yake yanaelezewa kwenye load commands nyingine.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes and export info
- Functions starts: Table of start addresses of functions
- Data In Code: Data islands in \_\_text
- SYmbol Table: Symbols in binary
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Ina taarifa zinazotumiwa na Objective-C runtime. Ingawa taarifa hii pia inaweza kupatikana kwenye segment ya \_\_DATA, ndani ya sections mbalimbali za \_\_objc\_\*.
- **`__RESTRICT`**: Segimenti bila content yenye section moja iitwayo **`__restrict`** (pia tupu) inayohakikisha kwamba binary inapotekelezwa, itapuuza DYLD environmental variables.

Kama ilivyowezekana kuona kwenye code, **segments pia zinaunga mkono flags** (ingawa hazitumiwi sana):

- `SG_HIGHVM`: Core only (not used)
- `SG_FVMLIB`: Not used
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Used for example by Finder to encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** ina entrypoint ndani ya attribute ya **entryoff**. Wakati wa load, **dyld** huongeza tu value hii kwenye **base ya binary** iliyo kwenye memory, kisha **hujump** kwenda kwenye instruction hii ili kuanza execution ya code ya binary.

**`LC_UNIXTHREAD`** ina values ambazo register lazima ziwe nazo wakati wa kuanzisha main thread. Hii tayari ilikuwa deprecated lakini **`dyld`** bado inaitumia. Inawezekana kuona values za registers zilizowekwa na hii kwa:
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


Ina taarifa kuhusu **code signature ya faili la Macho-O**. Lina **offset** tu ambayo **inaelekeza** kwenye **signature blob**. Hii huwa kawaida iko mwishoni kabisa mwa faili.\
Hata hivyo, unaweza kupata baadhi ya taarifa kuhusu sehemu hii katika [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) na [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) hizi.

### **`LC_ENCRYPTION_INFO[_64]`**

Msaada kwa usimbaji fiche wa binary. Hata hivyo, bila shaka, ikiwa mshambuliaji ataweza kuathiri process, ataweza kufanya dump ya memory bila usimbaji fiche.

### **`LC_LOAD_DYLINKER`**

Ina **path hadi kwa executable ya dynamic linker** ambayo huweka shared libraries ndani ya address space ya process. **Thamani huwekwa kila wakati kuwa `/usr/lib/dyld`**. Ni muhimu kutambua kwamba katika macOS, mapping ya dylib hufanyika katika **user mode**, si katika kernel mode.

### **`LC_IDENT`**

Imepitwa na wakati lakini inapowekwa ili kugeenrate dumps on panic, Mach-O core dump huundwa na toleo la kernel huwekwa katika amri ya `LC_IDENT`.

### **`LC_UUID`**

UUID ya nasibu. Haina matumizi ya moja kwa moja, lakini XNU huiweka kwenye cache pamoja na taarifa nyingine za process. Inaweza kutumika katika crash reports.

### **`LC_BUILD_VERSION`**

Binary za kisasa kwa kawaida hubeba amri hii ili kutangaza **target platform**, **minimum OS version**, **SDK version**, na kwa hiari **tool versions** zilizotumika kujenga slice hiyo. Kwa mtazamo wa offensive/reversing, hii ni muhimu sana kwa fingerprint jinsi sample ilijengwa na kugundua haraka universal binaries za ajabu ambapo slice moja ilikompailiwa kwa SDK au deployment target tofauti. Binary za zamani bado zinaweza kutumia `LC_VERSION_MIN_*` badala yake.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Inaruhusu kuonyesha environment variables kwa dyld kabla ya process kutekelezwa. Hii inaweza kuwa hatari sana kwa sababu inaweza kuruhusu kutekeleza arbitrary code ndani ya process, hivyo hii load command hutumiwa tu katika build ya dyld yenye `#define SUPPORT_LC_DYLD_ENVIRONMENT` na pia huzuia zaidi uchakataji kwa variables za umbo la `DYLD_..._PATH` zinazobainisha load paths.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Recent toolchains mara nyingi huhifadhi export/bind/rebase metadata katika hizi commands badala ya kutegemea tu `LC_DYLD_INFO[_ONLY]` opcodes za zamani. Zote mbili ni `linkedit_data_command` entries zinazooana ndani ya **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Compact trie yenye symbols zilizotolewa na image.
- **`LC_DYLD_CHAINED_FIXUPS`**: Per-segment fixup chains zinazotumiwa na dyld kuapply rebases na binds. Kwenye Apple Silicon ndipo pia utakutana na authenticated pointer fixups nyingi za kisasa.

Hii metadata ni ya msaada sana wakati wa reconstructing imports/exports, kuelewa kwa nini dependency iliyopakiwa kupitia `@rpath` ilipatikana kwa njia ilivyopatikana, au kubaini kwa nini hook/rebinding attempt ilishindwa kwenye target ya kisasa ya `arm64e`. `dyld_info` inaweza pia kutumiwa dhidi ya **cache-only dylib paths** ambazo hazipo kama files za kujitegemea kwenye disk, jambo ambalo ni la msaada sana kwenye macOS ya kisasa ambapo system libraries nyingi huishi tu kwenye shared cache.
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Amri huu wa kisasa wa kupakia mara nyingi unahusiana zaidi unapokagua **kernel collections / kernelcache-style filesets**. Badala ya kuwakilisha image moja ya kujitegemea, outer Mach-O hufanya kazi kama container na kila `LC_FILESET_ENTRY` huashiria Mach-O iliyo ndani yenye **entry id** yake inayofanana na path, anwani ya VM na file offset. Ikiwa unafanya reversing ya modern macOS/iOS kernel components, amri hii mara nyingi huwa daraja kati ya top-level container na image halisi unayotaka ku-extract au ku-disassemble.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Kwa workflows za practical extraction, angalia [this other page about macOS kernel extensions and kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Hii load command inaelezea utegemezi wa **dynamic** **library** ambao **unaagiza** **loader** (dyld) **kupakia na ku-link library hiyo**. Kuna `LC_LOAD_DYLIB` load command **kwa kila library** ambayo Mach-O binary inahitaji.

- Hii load command ni muundo wa aina **`dylib_command`** (ambao una struct dylib, inayoelezea dynamic library tegemezi halisi):
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

Unaweza pia kupata taarifa hii kutoka kwa cli kwa:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Baadhi ya maktaba zinazohusiana na malware ni:

- **DiskArbitration**: Kufuatilia diski za USB
- **AVFoundation:** Kukamata sauti na video
- **CoreWLAN**: Uchanganuzi wa Wifi.

> [!TIP]
> Binari ya Mach-O inaweza kuwa na constructor mmoja au **zaidi**, ambazo zitatekelezwa **kabla** ya anwani iliyoainishwa katika **LC_MAIN**.\
> Offset za constructor zozote huhifadhiwa katika sehemu ya **\_\_mod_init_func** ya segment ya **\_\_DATA_CONST**.

## **Mach-O Data**

Katika kiini cha faili kuna eneo la data, ambalo limeundwa na segment kadhaa kama inavyofafanuliwa katika eneo la load-commands. **A variety of data sections can be housed within each segment**, ambapo kila sehemu **huhifadhi code au data** mahsusi kwa aina fulani.

> [!TIP]
> Data kimsingi ni sehemu inayobeba **information** yote inayopakiwa na load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Hii inajumuisha:

- **Function table:** Ambayo huhifadhi information kuhusu functions za programu.
- **Symbol table**: Ambayo ina information kuhusu external function inayotumiwa na binari
- Pia inaweza kuwa na internal function, variable names pia, na zaidi.

Ili kuikagua unaweza kutumia zana ya [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Au kutoka kwa cli:
```bash
size -m /bin/ls
```
## Sehemu za Kawaida za Objetive-C

Katika `__TEXT` segment (r-x):

- `__objc_classname`: Majina ya madarasa (strings)
- `__objc_methname`: Majina ya method (strings)
- `__objc_methtype`: Aina za method (strings)

Katika `__DATA` segment (rw-):

- `__objc_classlist`: Pointer kwa madarasa yote ya Objetive-C
- `__objc_nlclslist`: Pointer kwa madarasa ya Non-Lazy Objective-C
- `__objc_catlist`: Pointer kwa Categories
- `__objc_nlcatlist`: Pointer kwa Non-Lazy Categories
- `__objc_protolist`: Orodha ya protocols
- `__objc_const`: Data ya kudumu
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## Marejeo

- [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
{{#include ../../../banners/hacktricks-training.md}}
