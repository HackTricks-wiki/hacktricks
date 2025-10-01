# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Binaries za macOS kwa kawaida zimetengenezwa kama **universal binaries**. **Universal binary** inaweza **kuunga mkono architectures nyingi katika faili moja**.

Binaries hizi zinafuata **muundo wa Mach-O** ambao kwa msingi unajumuisha:

- Kichwa
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

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

Kichwa kina bytes za **magic** zikifuatiwa na **idadi** ya **archs** ambayo faili **ina** (`nfat_arch`) na kila arch itakuwa na struct ya `fat_arch`.

Angalia kwa kutumia:

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

au ukitumia zana ya [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Kama unavyoweza kufikiri, kawaida universal binary iliyojengwa kwa architectures 2 **inafanya ukubwa kuwa mara mbili** ikilinganishwa na ile iliyojengwa kwa arch 1.

## **Mach-O Header**

Kichwa kina taarifa za msingi kuhusu faili, kama vile magic bytes za kuitambulisha kama faili la Mach-O na taarifa kuhusu architecture lengwa. Unaweza kuipata katika: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Kuna aina mbalimbali za faili; unaweza kuziona zikiwa zimetangazwa katika [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Muhimu zaidi ni zifuatazo:

- `MH_OBJECT`: Relocatable object file (bidhaa za kati za utekelezaji wa compilation, bado si executable).
- `MH_EXECUTE`: Executable files.
- `MH_FVMLIB`: Faili la maktaba ya VM imara.
- `MH_CORE`: Dumpi za msimbo
- `MH_PRELOAD`: Preloaded executable file (haitegemewi tena katika XNU)
- `MH_DYLIB`: Maktaba za dynamic
- `MH_DYLINKER`: Kiunganishi cha dynamic
- `MH_BUNDLE`: "Faili za programu-jalizi". Zimetengenezwa kwa kutumia -bundle katika gcc na zinapakiwa waziwazi na `NSBundle` au `dlopen`.
- `MH_DYSM`: Companion `.dSym` file (faili yenye symbols kwa ajili ya debugging).
- `MH_KEXT_BUNDLE`: Upanuzi za Kernel.
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

Msimbo wa chanzo pia una bendera kadhaa zinazofaa kwa kupakia maktaba:

- `MH_NOUNDEFS`: Hakuna marejeleo yasiyoelezwa (imeunganishwa kikamilifu)
- `MH_DYLDLINK`: Uunganishaji wa dyld
- `MH_PREBOUND`: Marejeo ya dinamik yamekwishwa awali.
- `MH_SPLIT_SEGS`: Faili hugawa segments r/o na r/w.
- `MH_WEAK_DEFINES`: Binary ina symbols zilizofafanuliwa kama weak
- `MH_BINDS_TO_WEAK`: Binary inatumia symbols za aina weak
- `MH_ALLOW_STACK_EXECUTION`: Fanya stack iwe executable
- `MH_NO_REEXPORTED_DYLIBS`: Maktaba haina amri za LC_REEXPORT
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Kuna sehemu yenye thread local variables
- `MH_NO_HEAP_EXECUTION`: Hakuna utekelezaji kwa kurasa za heap/data
- `MH_HAS_OBJC`: Binary ina oBject-C sections
- `MH_SIM_SUPPORT`: Support ya simulator
- `MH_DYLIB_IN_CACHE`: Inatumiwa kwa dylibs/frameworks kwenye shared library cache.

## **Mach-O Load commands**

Mpangilio wa **faili katika kumbukumbu** umefafanuliwa hapa, ukielezea kwa undani **eneo la symbol table**, muktadha wa thread kuu wakati wa kuanza utekelezaji, na **maktaba za pamoja** zinazohitajika. Maelekezo hutolewa kwa dynamic loader **(dyld)** kuhusu mchakato wa kupakia binary kwenye kumbukumbu.

Hili linatumia muundo wa **load_command**, uliotajwa na kufafanuliwa katika **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Kuna karibu **50 different types of load commands** ambazo mfumo huzishughulikia kwa njia tofauti. Za kawaida zaidi ni: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, na `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Kwa msingi, aina hii ya Load Command inaelezea **jinsi ya kupakia the \_\_TEXT** (msimbo unaotekelezwa) **na \_\_DATA** (data kwa ajili ya mchakato) **segments** kulingana na **offsets zilizotajwa katika Data section** wakati binary inapoendeshwa.

Amri hizi **zinaelezea segments** ambazo **zina ramanishwa** ndani ya **virtual memory space** ya mchakato wakati inapoendeshwa.

Kuna **aina tofauti** za segments, kama segment ya **\_\_TEXT**, ambayo inashikilia msimbo unaotekelezwa wa programu, na segment ya **\_\_DATA**, ambayo ina data inayotumiwa na mchakato. Segments hizi **ziko katika data section** ya faili ya Mach-O.

**Kila segment** inaweza kugawanywa zaidi kuwa **sehemu nyingi (sections)**. Muundo wa **load command** una taarifa kuhusu **sections hizi** ndani ya segment husika.

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

Header hii inaelezea the **idadi ya sections ambazo header zao zinaonekana baada yake**:
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

Ikiwa uta**ongeza** **offset ya sehemu** (0x37DC) + **offset** ambapo **arch** inaanza, katika kesi hii `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Inawezekana pia kupata **taarifa za vichwa** kutoka kwa **mstari wa amri** kwa kutumia:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** Inaelekeza kernel ili **map** anwani sifuri ili **haiwezi kusomwa, kuandikwa, au kutekelezwa**. Vigezo maxprot na minprot katika muundo vimewekwa kuwa sifuri kuonyesha kuwa **hakuna haki za kusoma-kuandika-kutekeleza kwenye ukurasa huu**.
- Ugawaji huu ni muhimu kupunguza udhaifu wa **NULL pointer dereference vulnerabilities**. Hii ni kwa sababu XNU inatekeleza hard page zero inayohakikisha ukurasa wa kwanza (tu wa kwanza) wa kumbukumbu haupatikani (isipokuwa katika i386). Binary inaweza kutimiza mahitaji haya kwa kuunda kidogo `__PAGEZERO` (kwa kutumia `-pagezero_size`) ili kufunika 4k ya kwanza na kufanya sehemu iliyobaki ya kumbukumbu ya 32bit iwe inapatikana kwa mode ya user na kernel.
- **`__TEXT`**: Ina **executable** code yenye ruhusa za **read** na **execute** (bila writable). Sehemu za kawaida za segment hii:
- `__text`: Compiled binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode au os logs string constants
- `__stubs` and `__stubs_helper`: Zinahusiana wakati wa mchakato wa kupakia dynamic libraries
- `__unwind_info`: Stack unwind data.
- Kumbuka kwamba yaliyomo yote haya yamesainiwa lakini pia yamewekwa kama executable (hii inatoa chaguzi zaidi za exploitation ya sehemu ambazo hazihitaji lazima ruhusa hii, kama sehemu zilizotengwa kwa string).
- **`__DATA`**: Inayo data inayoweza kusomwa na kuandikwa (bila executable).
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Inapaswa kuwa read-only data (sio kweli)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (ambazo zimetanguliwa)
- `__bss`: Static variables (ambazo hazijatanguliwa)
- `__objc_*` (__objc_classlist, __objc_protolist, etc): Taarifa zinazotumika na Objective-C runtime
- **`__DATA_CONST`**: __DATA.__const si lazima iwe konstanti (ina ruhusa ya kuandika), wala pointers nyingine na GOT. Sehemu hii hufanya `__const`, baadhi ya initializers na jedwali la GOT (mara limekataliwa) kuwa read-only kwa kutumia `mprotect`.
- **`__LINKEDIT`**: Ina taarifa kwa linker (dyld) kama symbol, string, na viingizo vya jedwali la relocation. Ni kontena ya jumla kwa vitu ambavyo sio ndani ya `__TEXT` au `__DATA` na yaliyomo yake yameelezewa katika load commands nyingine.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes na export info
- Functions starts: Jedwali la anuani za kuanza za functions
- Data In Code: Visiwa vya data ndani ya `__text`
- SYmbol Table: Symbols katika binary
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Inabeba taarifa zinazotumika na Objective-C runtime. Ingawa taarifa hizi zinaweza kupatikana pia ndani ya segment ya `__DATA`, ndani ya sehemu mbalimbali za `__objc_*`.
- **`__RESTRICT`**: Segment isiyo na yaliyomo yenye sehemu moja iitwayo **`__restrict`** (pia tupu) ambayo inahakikisha kwamba wakati binary inapotekelezwa, itapuuzia mazingira ya DYLD.

Kama ilivyoweza kuonekana kwenye msimbo, **segments pia zinaunga mkono flags** (ingawa hazitumiki sana):

- `SG_HIGHVM`: Kwa Core pekee (haitumiki)
- `SG_FVMLIB`: Haitumiki
- `SG_NORELOC`: Segment haina relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Imetumika kwa mfano na Finder ku-encrypt segment ya `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** ina entrypoint katika attribute ya **entryoff.** Wakati wa kupakia, **dyld** kwa urahisi **huongeza** thamani hii kwa (in-memory) **base of the binary**, kisha **huruka** kwa maagizo haya kuanza utekelezaji wa code ya binary.

**`LC_UNIXTHREAD`** ina thamani ambazo rejista lazima ziwe nazo wakati wa kuanzisha main thread. Hii tayari ilifutwa lakini **`dyld`** bado inaitumia. Inawezekana kuona values za rejista zilizoamshwa na hii kwa:
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


Inabeba taarifa kuhusu **code signature of the Macho-O file**. Inajumuisha tu **offset** inayo **onyesha** kwenye **signature blob**. Hii kwa kawaida iko mwishoni kabisa wa faili.\
Hata hivyo, unaweza kupata baadhi ya taarifa kuhusu sehemu hii katika [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) na hii [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Inasaidia binary encryption. Hata hivyo, bila shaka, ikiwa mshambuliaji ataweza kuingilia mchakato, atakuwa na uwezo wa dump memory bila encryption.

### **`LC_LOAD_DYLINKER`**

Inahifadhi **path to the dynamic linker executable** inayofanya mapping ya shared libraries ndani ya process address space. Thamani imewekwa daima kuwa `/usr/lib/dyld`. Ni muhimu kutambua kwamba kwenye macOS, dylib mapping hufanyika katika **user mode**, si katika kernel mode.

### **`LC_IDENT`**

Zimetumika zamani, lakini pale zinapofanyiwa configure ili kuzalisha dumps wakati wa panic, Mach-O core dump huundwa na toleo la kernel huwekwa katika amri ya `LC_IDENT`.

### **`LC_UUID`**

UUID ya nasibu. Haifaidiki kwa kitu kwa njia ya moja kwa moja lakini XNU huwaicache pamoja na taarifa nyingine za mchakato. Inaweza kutumika katika crash reports.

### **`LC_DYLD_ENVIRONMENT`**

Inaruhusu kuonyesha environment variables kwa dyld kabla mchakato haujatekelezwa. Hii inaweza kuwa hatari sana kwani inaweza kuruhusu kutekelezwa kwa arbitrary code ndani ya mchakato, hivyo load command hii inatumika tu katika dyld build yenye `#define SUPPORT_LC_DYLD_ENVIRONMENT` na inaweka vikwazo zaidi kwa ku-processing tu variable za aina `DYLD_..._PATH` zinazoainisha load paths.

### **`LC_LOAD_DYLIB`**

Load command hii inaelezea utegemezi wa **dynamic** **library** ambao **inaamrisha** **loader** (dyld) ili kupakia na kuunganisha ile library. Kuna load command ya `LC_LOAD_DYLIB` **kwa kila library** ambayo Mach-O binary inahitaji.

- Load command hii ni muundo wa aina **`dylib_command`** (ambayo ina struct dylib, inayoelezea dynamic library inayotegemewa):
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

Unaweza pia kupata taarifa hii kutoka kwa cli kwa:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Baadhi ya maktaba zinazoweza kuhusiana na malware ni:

- **DiskArbitration**: Kufuatilia draivu za USB
- **AVFoundation:** Kukamata audio na video
- **CoreWLAN**: Skana za Wifi.

> [!TIP]
> A Mach-O binary can contain one or **more** **constructors**, that will be **executed** **before** the address specified in **LC_MAIN**.\
> The offsets of any constructors are held in the **\_\_mod_init_func** section of the **\_\_DATA_CONST** segment.

## **Mach-O Data**

Katikati ya faili kunapatikana eneo la data, ambalo limeundwa na segmenti kadhaa kama ilivyoainishwa katika load-commands region. **Aina mbalimbali za data sections zinaweza kuwekwa ndani ya kila segmenti**, ambapo kila section **inahifadhi code au data** maalum kwa aina yake.

> [!TIP]
> The data is basically the part containing all the **information** that is loaded by the load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Hii inajumuisha:

- **Function table:** Inayohifadhi taarifa kuhusu kazi za programu.
- **Symbol table**: Inayo taarifa kuhusu external functions zinazotumika na binary
- Inaweza pia kujumuisha internal functions, majina ya variables na mengine mengi.

To check it you could use the [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Or from the cli:
```bash
size -m /bin/ls
```
## Sehemu za kawaida za Objetive-C

Katika `__TEXT` segment (r-x):

- `__objc_classname`: Majina ya madarasa (strings)
- `__objc_methname`: Majina ya mbinu (strings)
- `__objc_methtype`: Aina za mbinu (strings)

Katika `__DATA` segment (rw-):

- `__objc_classlist`: Vielekezi kwa madarasa yote ya Objetive-C
- `__objc_nlclslist`: Vielekezi kwa madarasa ya Non-Lazy Objetive-C
- `__objc_catlist`: Kielekezo kwa Categories
- `__objc_nlcatlist`: Kielekezo kwa Non-Lazy Categories
- `__objc_protolist`: Orodha ya Protocols
- `__objc_const`: Data ya konstanti
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
