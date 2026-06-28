# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Mac OS binaries word gewoonlik saamgestel as **universal binaries**. ’n **universal binary** kan **meerdere architectures in dieselfde lêer ondersteun**.

Hierdie binaries volg die **Mach-O structure** wat basies uit die volgende bestaan:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Soek vir die lêer met: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Die header het die **magic** bytes gevolg deur die **number** van **archs** wat die lêer **bevat** (`nfat_arch`), en elke arch sal ’n `fat_arch` struct hê.

Kyk dit met:

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

of gebruik die [Mach-O View](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Soos jy dalk dink, gewoonlik verdubbel ’n universal binary wat vir 2 architectures saamgestel is die grootte van een wat net vir 1 arch saamgestel is.

> [!TIP]
> Wanneer jy malware of suspicious apps triage, moenie stop nadat `file` die "best" architecture rapporteer nie. ’n Universal binary kan verskillende imports, load commands of compiler metadata in elke slice wegsteek, so enumereer eers **al** die slices en inspecteer hulle dan onafhanklik:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Onlangse macOS SDKs stel ook helpers bloot soos `macho_for_each_slice()` en `macho_best_slice()` in `<mach-o/utils.h>`. Laasgenoemde is nuttig om na te boots wat dyld/kernel sou laai, maar scanners moet steeds elke slice deurgaan om te verhoed dat arch-spesifieke inhoud gemis word.

## **Mach-O Header**

Die header bevat basiese inligting oor die lêer, soos magic bytes om dit as ’n Mach-O-lêer te identifiseer en inligting oor die teikening-argitektuur. Jy kan dit vind in: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O Lêertipes

Daar is verskillende lêertipes, jy kan hulle gedefinieer vind in die [**bronkode byvoorbeeld hier**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Die belangrikstes is:

- `MH_OBJECT`: Verplasbare objeklêer (intermediêre produkte van samestelling, nog nie uitvoerbares nie).
- `MH_EXECUTE`: Uitvoerbare lêers.
- `MH_FVMLIB`: Vaste VM-biblioteeklêer.
- `MH_CORE`: Kode Dumps
- `MH_PRELOAD`: Vooraf gelaaide uitvoerbare lêer (word nie meer in XNU ondersteun nie)
- `MH_DYLIB`: Dinamiese biblioteke
- `MH_DYLINKER`: Dinamiese skakelaar
- `MH_BUNDLE`: "Plugin-lêers". Gegenereer met -bundle in gcc en eksplisiet gelaai deur `NSBundle` of `dlopen`.
- `MH_DYSM`: Begeleidende `.dSym`-lêer (lêer met symbols vir debugging).
- `MH_KEXT_BUNDLE`: Kerneluitbreidings.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Of using [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

Die bronkode definieer ook verskeie flags wat nuttig is vir die laai van libraries:

- `MH_NOUNDEFS`: Geen undefined references (volledig linked)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamic references prebound.
- `MH_SPLIT_SEGS`: File splits r/o and r/w segments.
- `MH_WEAK_DEFINES`: Binary het weak defined symbols
- `MH_BINDS_TO_WEAK`: Binary gebruik weak symbols
- `MH_ALLOW_STACK_EXECUTION`: Maak die stack executable
- `MH_NO_REEXPORTED_DYLIBS`: Library not LC_REEXPORT commands
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Daar is 'n section met thread local variables
- `MH_NO_HEAP_EXECUTION`: Geen execution vir heap/data pages
- `MH_HAS_OBJC`: Binary het oBject-C sections
- `MH_SIM_SUPPORT`: Simulator support
- `MH_DYLIB_IN_CACHE`: Used on dylibs/frameworks in shared library cache.

## **Mach-O Load commands**

Die **file se layout in memory** word hier gespesifiseer, met besonderhede oor die **symbol table se location**, die context van die main thread by execution start, en die vereiste **shared libraries**. Instructions word aan die dynamic loader **(dyld)** gegee oor die binary se loading process in memory.

Die gebruik die **load_command** structure, defined in die genoemde **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Daar is ongeveer **50 verskillende tipes load commands** wat die stelsel verskillend hanteer. Die algemeenstes is: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, en `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Basies definieer hierdie tipe Load Command **hoe om die \_\_TEXT** (uitvoerbare kode) **en \_\_DATA** (data vir die proses) **segments** te laai volgens die **offsets aangedui in die Data-afdeling** wanneer die binary uitgevoer word.

Hierdie commands **definieer segments** wat in die **virtuele geheue-ruimte** van ’n proses **gemap** word wanneer dit uitgevoer word.

Daar is **verskillende tipes** segments, soos die **\_\_TEXT** segment, wat die uitvoerbare kode van ’n program bevat, en die **\_\_DATA** segment, wat data bevat wat deur die proses gebruik word. Hierdie **segments is geleë in die data-afdeling** van die Mach-O-lêer.

**Elke segment** kan verder **verdeel** word in verskeie **sections**. Die **load command structure** bevat **inligting** oor **hierdie sections** binne die betrokke segment.

In die header vind jy eerste die **segment header**:

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

Voorbeeld van segment header:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Hierdie header definieer die **aantal sections waarvan die headers daarna verskyn**:
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
Voorbeeld van **seksie-kop**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

As jy die **seksie-offset** (0x37DC) + die **offset** waar die **arch begin**, in hierdie geval `0x18000` byvoeg --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Dit is ook moontlik om **kop-inligting** vanaf die **command line** te kry met:
```bash
otool -lv /bin/ls
```
Algemene segmente gelaai deur hierdie cmd:

- **`__PAGEZERO`:** Dit instrueer die kernel om die **adres nul** te **map** sodat dit **nie gelees, geskryf, of uitgevoer** kan word nie. Die maxprot- en minprot-veranderlikes in die struktuur word op nul gestel om aan te dui daar is **geen read-write-execute rights op hierdie bladsy**.
- Hierdie toekenning is belangrik om **NULL pointer dereference vulnerabilities** te **mitigate**. Dit is omdat XNU 'n harde page zero afdwing wat verseker dat die eerste bladsy (slegs die eerste) van memory ontoeganklik is (behalwe in i386). 'n Binary kan aan hierdie vereistes voldoen deur 'n klein \_\_PAGEZERO te skep (met die `-pagezero_size`) om die eerste 4k te dek en die res van die 32bit memory toeganklik te hê in beide user en kernel mode.
- **`__TEXT`**: Bevat **uitvoerbare** **code** met **read**- en **execute**-toestemmings (geen writable)**.** Algemene sections van hierdie segment:
- `__text`: Gecompileerde binary code
- `__const`: Konstante data (read only)
- `__[c/u/os_log]string`: C-, Unicode- of os logs string-konstantes
- `__stubs` and `__stubs_helper`: Betrokke tydens die dynamic library loading proses
- `__unwind_info`: Stack unwind data.
- Let daarop dat al hierdie content gesigned is maar ook gemerk as uitvoerbaar (wat meer opsies skep vir exploitation van sections wat nie noodwendig hierdie privilege nodig het nie, soos string dedicated sections).
- **`__DATA`**: Bevat data wat **leesbaar** en **skryfbaar** is (geen executable)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Moet read-only data wees (nie regtig nie)
- `__cfstring`: CoreFoundation strings
- `__data`: Globale veranderlikes (wat geïnisialiseer is)
- `__bss`: Statiese veranderlikes (wat nie geïnisialiseer is nie)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Inligting wat deur die Objective-C runtime gebruik word
- **`__DATA_CONST`**: \_\_DATA.\_\_const is nie gewaarborg om constant te wees nie (write permissions), en ook nie ander pointers en die GOT nie. Hierdie section maak `__const`, sommige initializers en die GOT table (sodra opgelos) **read only** met behulp van `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Algemeen in onlangse Apple Silicon binaries. Hierdie segmente hou pointers wat geauthentiseer moet word by load- of use-tyd (byvoorbeeld `__auth_got`). As 'n rebinding, hook of import-patching truuk net die legacy `__got` / `__la_symbol_ptr` sections nagaan, kan dit die werklike call sites in moderne `arm64e` binaries mis. Vir meer besonderhede oor hierdie sections, kyk [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Bevat inligting vir die linker (dyld) soos symbol-, string- en relocation table-inskrywings. Dit is 'n generiese houer vir contents wat nie in `__TEXT` of `__DATA` is nie en die content daarvan word in ander load commands beskryf.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes en export info
- Functions starts: Table of start addresses of functions
- Data In Code: Data-eilande in \_\_text
- SYmbol Table: Symbols in binary
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Bevat inligting wat deur die Objective-C runtime gebruik word. Hoewel hierdie inligting ook in die \_\_DATA segment gevind kan word, binne verskeie \_\_objc\_\* sections.
- **`__RESTRICT`**: 'n Segment sonder content met 'n enkele section genaamd **`__restrict`** (ook leeg) wat verseker dat wanneer die binary loop, dit DYLD environmental variables sal ignoreer.

Soos in die code gesien kon word, **segmente ondersteun ook flags** (hoewel hulle nie baie gebruik word nie):

- `SG_HIGHVM`: Core only (nie gebruik nie)
- `SG_FVMLIB`: Nie gebruik nie
- `SG_NORELOC`: Segment het geen relocation nie
- `SG_PROTECTED_VERSION_1`: Encryption. Gebruik byvoorbeeld deur Finder om die teks `__TEXT` segment te enkripteer.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** bevat die entrypoint in die **entryoff attribute.** Tydens load time, **dyld** **tel** eenvoudig hierdie waarde by die (in-memory) **base of the binary** op, en **spring** dan na hierdie instruction om die binary se code te begin uitvoer.

**`LC_UNIXTHREAD`** bevat die waardes wat die register moet hê wanneer die main thread begin. Dit was reeds deprecated maar **`dyld`** gebruik dit steeds. Dit is moontlik om die values van die registers wat hiermee ingestel word, te sien met:
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


Bevat inligting oor die **code signature van die Macho-O file**. Dit bevat slegs 'n **offset** wat **wys** na die **signature blob**. Dit is tipies heel aan die einde van die file.\
Jy kan egter wel 'n bietjie inligting oor hierdie section vind in [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) en hierdie [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Ondersteuning vir binary encryption. Maar natuurlik, as 'n attacker daarin slaag om die process te compromise, sal hy die memory unencrypted kan dump.

### **`LC_LOAD_DYLINKER`**

Bevat die **path na die dynamic linker executable** wat shared libraries in die process address space map. Die **waarde is altyd `/usr/lib/dyld`**. Dit is belangrik om daarop te let dat in macOS, dylib mapping in **user mode** gebeur, nie in kernel mode nie.

### **`LC_IDENT`**

Verouderd, maar wanneer dit ingestel is om dumps on panic te genereer, word 'n Mach-O core dump geskep en die kernel version word in die `LC_IDENT` command gestel.

### **`LC_UUID`**

Ewekansige UUID. Dit is nie direk nuttig vir enigiets nie, maar XNU cache dit saam met die res van die process info. Dit kan in crash reports gebruik word.

### **`LC_BUILD_VERSION`**

Moderne binaries dra gewoonlik hierdie command om die **target platform**, **minimum OS version**, **SDK version**, en opsioneel die **tool versions** wat gebruik is om daardie slice te bou, te verklaar. Vanuit 'n offensive/reversing perspective is dit baie nuttig om te fingerprint hoe 'n sample gebou is en om vinnig vreemde universal binaries raak te sien waar een slice met 'n ander SDK of deployment target gekompileer is. Ouer binaries mag steeds eerder `LC_VERSION_MIN_*` gebruik.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Laat toe om omgewingsveranderlikes aan die dyld aan te dui voor die proses uitgevoer word. Dit kan baie gevaarlik wees aangesien dit arbitrêre kode binne die proses kan laat uitvoer, so hierdie load command word slegs gebruik in `dyld` build met `#define SUPPORT_LC_DYLD_ENVIRONMENT` en beperk verdere verwerking net tot veranderlikes in die vorm `DYLD_..._PATH` wat load paths spesifiseer.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Onlangse toolchains stoor dikwels export/bind/rebase metadata in hierdie commands in plaas daarvan om slegs op die ouer `LC_DYLD_INFO[_ONLY]` opcodes staat te maak. Albei is `linkedit_data_command` entries wat na **`__LINKEDIT`** wys:

- **`LC_DYLD_EXPORTS_TRIE`**: Compact trie met die symbols wat deur die image exported word.
- **`LC_DYLD_CHAINED_FIXUPS`**: Per-segment fixup chains wat deur dyld gebruik word om rebases en binds toe te pas. Op Apple Silicon is dit ook waar jy baie moderne authenticated pointer fixups sal teëkom.

Hierdie metadata is baie handig wanneer imports/exports gerekonstrueer word, wanneer jy verstaan waarom ’n `@rpath`-gelaaide dependency op die manier resolved het, of wanneer jy uitwerk hoekom ’n hook/rebinding-poging op ’n moderne `arm64e` target misluk het. `dyld_info` kan ook gebruik word teen **cache-only dylib paths** wat nie as selfstandige files op disk bestaan nie, wat baie handig is op moderne macOS waar baie system libraries net in die shared cache leef.
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Hierdie moderne load command is meestal relevant wanneer jy **kernel collections / kernelcache-styl filesets** inspekteer. In plaas daarvan om 'n enkele selfstandige image voor te stel, tree die buitenste Mach-O op as 'n container en elke `LC_FILESET_ENTRY` wys na 'n embedded Mach-O met sy eie pad-agtige **entry id**, VM address en file offset. As jy moderne macOS/iOS kernel components reverse, is hierdie command dikwels die brug tussen die top-vlak container en die werklike image wat jy wil extract of disassemble.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Vir praktiese onttrekkingswerkvloeie, kyk [hierdie ander bladsy oor macOS-kernuitbreidings en kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Hierdie load command beskryf ’n **dynamic** **library** afhanklikheid wat die **loader** (dyld) **instruer** om **sodanige library te laai en te link**. Daar is ’n `LC_LOAD_DYLIB` load command **vir elke library** wat die Mach-O binary benodig.

- Hierdie load command is ’n struktuur van tipe **`dylib_command`** (wat ’n struct dylib bevat, wat die werklike afhanklike dynamic library beskryf):
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
![LC DYLD OMGEWING - LC LOAD DYLIB: uint32 t versoenbaarheidsweergawe; / biblioteek se versoenbaarheidsweergawenommer /](<../../../images/image (486).png>)

Jy kan ook hierdie inligting vanaf die cli kry met:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Some potential malware related libraries are:

- **DiskArbitration**: Monitoring USB drives
- **AVFoundation:** Capture audio and video
- **CoreWLAN**: Wifi scans.

> [!TIP]
> A Mach-O binary can contain one or **more** **constructors**, that will be **executed** **before** the address specified in **LC_MAIN**.\
> The offsets of any constructors are held in the **\_\_mod_init_func** section of the **\_\_DATA_CONST** segment.

## **Mach-O Data**

At the core of the file lies the data region, which is composed of several segments as defined in the load-commands region. **A variety of data sections can be housed within each segment**, with each section **holding code or data** specific to a type.

> [!TIP]
> The data is basically the part containing all the **information** that is loaded by the load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

This includes:

- **Function table:** Which holds information about the program functions.
- **Symbol table**: Which contains information about the external function used by the binary
- It could also contain internal function, variable names as well and more.

To check it you could use the [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Or from the cli:
```bash
size -m /bin/ls
```
## Objetive-C Common Sections

In `__TEXT` segment (r-x):

- `__objc_classname`: Klashname (strings)
- `__objc_methname`: Metode name (strings)
- `__objc_methtype`: Metode tipes (strings)

In `__DATA` segment (rw-):

- `__objc_classlist`: Wysers na all Objetive-C klashes
- `__objc_nlclslist`: Wysers na Non-Lazy Objective-C klashes
- `__objc_catlist`: Wyser na Categories
- `__objc_nlcatlist`: Wyser na Non-Lazy Categories
- `__objc_protolist`: Protocol lys
- `__objc_const`: Konstante data
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
{{#include ../../../banners/hacktricks-training.md}}
