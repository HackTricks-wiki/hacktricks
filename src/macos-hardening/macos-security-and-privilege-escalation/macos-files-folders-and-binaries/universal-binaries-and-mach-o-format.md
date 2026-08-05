# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Mac OS-binaries word gewoonlik as **universal binaries** gekompileer. ’n **universal binary** kan **veelvuldige argitekture in dieselfde lêer ondersteun**.

Hierdie binaries volg die **Mach-O-struktuur**, wat basies uit die volgende bestaan:

- Kop
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

Die kop bevat die **magic**-grepe, gevolg deur die **aantal** **argitekture** wat die lêer **bevat** (`nfat_arch`), en elke argitektuur sal ’n `fat_arch`-struktuur hê.

Kontroleer dit met:

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

of deur die [Mach-O View](https://sourceforge.net/projects/machoview/) tool te gebruik:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Soos jy dalk dink, verdubbel ’n universal binary wat vir 2 argitekture gekompileer is gewoonlik die **grootte** van een wat slegs vir 1 argitektuur gekompileer is.

> [!TIP]
> Wanneer jy malware of verdagte apps triage, moenie ophou nadat `file` die “beste” argitektuur gerapporteer het nie. ’n Universal binary kan verskillende imports, load commands of compiler-metadata in elke slice versteek. Lys dus eers **al** die slices en ondersoek hulle daarna onafhanklik:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Onlangse macOS SDK's stel ook helpers soos `macho_for_each_slice()` en `macho_best_slice()` in `<mach-o/utils.h>` beskikbaar. Laasgenoemde is nuttig om na te boots wat dyld/kernel sou laai, maar scanners behoort steeds deur elke slice te iterereer om te voorkom dat argitektuurspesifieke inhoud gemis word.<sup>[1]</sup>

## **Mach-O Header**

Die header bevat basiese inligting oor die lêer, soos magic bytes om dit as 'n Mach-O-lêer te identifiseer, asook inligting oor die teikenargitektuur. Jy kan dit vind met: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O-lêertipes

Daar is verskillende lêertipes; jy kan hulle gedefinieer vind in die [**bronkode, byvoorbeeld hier**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Die belangrikste is:

- `MH_OBJECT`: Herplaasbare objeklêer (intermediêre produkte van kompilering, nog nie uitvoerbare lêers nie).
- `MH_EXECUTE`: Uitvoerbare lêers.
- `MH_FVMLIB`: Vaste VM-biblioteeklêer.
- `MH_CORE`: Kode-stortings.
- `MH_PRELOAD`: Voorafgelaaide uitvoerbare lêer (word nie meer in XNU ondersteun nie).
- `MH_DYLIB`: Dinamiese biblioteke.
- `MH_DYLINKER`: Dinamiese skakelaar.
- `MH_BUNDLE`: "Inprop-lêers". Gegenereer met behulp van -bundle in gcc en uitdruklik gelaai deur `NSBundle` of `dlopen`.
- `MH_DYSM`: Metgesel-`.dSym`-lêer (lêer met simbole vir debugging).
- `MH_KEXT_BUNDLE`: Kernel-uitbreidings.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Of met [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O-vlaggies**

Die bronkode definieer ook verskeie vlaggies wat nuttig is vir die laai van libraries:

- `MH_NOUNDEFS`: Geen ongedefinieerde verwysings nie (volledig gekoppel)
- `MH_DYLDLINK`: Dyld-koppeling
- `MH_PREBOUND`: Dinamiese verwysings is vooraf gebind.
- `MH_SPLIT_SEGS`: Lêer verdeel r/o- en r/w-segmente.
- `MH_WEAK_DEFINES`: Binary het swak gedefinieerde simbole
- `MH_BINDS_TO_WEAK`: Binary gebruik swak simbole
- `MH_ALLOW_STACK_EXECUTION`: Maak die stack uitvoerbaar
- `MH_NO_REEXPORTED_DYLIBS`: Library het nie LC_REEXPORT-opdragte nie
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Daar is 'n afdeling met thread local variables
- `MH_NO_HEAP_EXECUTION`: Geen uitvoering vir heap/data-bladsye nie
- `MH_HAS_OBJC`: Binary het oBject-C-afdelings
- `MH_SIM_SUPPORT`: Simulator-ondersteuning
- `MH_DYLIB_IN_CACHE`: Word op dylibs/frameworks in die shared library cache gebruik.

## **Mach-O-laaikommando's**

Die **lêer se uitleg in geheue** word hier gespesifiseer, met besonderhede oor die **simboletabel se ligging**, die konteks van die hoofthread wanneer uitvoering begin, en die vereiste **shared libraries**. Instruksies word aan die dinamiese loader **(dyld)** verskaf oor hoe die binary in geheue gelaai moet word.

Die gebruik die **load_command**-struktuur, wat in die genoemde **`loader.h`** gedefinieer word:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Daar is ongeveer **50 verskillende tipes load commands** wat die stelsel verskillend hanteer. Die algemeenste is: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, en `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Basies definieer hierdie tipe Load Command **hoe om die \_\_TEXT** (uitvoerbare kode) **en \_\_DATA** (data vir die proses) **segments** te laai volgens die **offsets wat in die Data section aangedui word** wanneer die binary uitgevoer word.

Hierdie commands **definieer segments** wat in die **virtual memory space** van ’n proses **gemap** word wanneer dit uitgevoer word.

Daar is **verskillende tipes** segments, soos die **\_\_TEXT**-segment, wat die uitvoerbare kode van ’n program bevat, en die **\_\_DATA**-segment, wat data bevat wat deur die proses gebruik word. Hierdie **segments is in die data section geleë** van die Mach-O-lêer.

**Elke segment** kan verder in verskeie **sections** verdeel word. Die **load command-structuur** bevat **inligting** oor **hierdie sections** binne die onderskeie segment.

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

Voorbeeld van ’n segment header:

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
Voorbeeld van **seksie-opskrif**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

As jy die **seksie-offset** (0x37DC) + die **offset** waar die **argitektuur begin**, bytel, in hierdie geval `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Dit is ook moontlik om **opskrif-inligting** vanaf die **command line** te verkry met:
```bash
otool -lv /bin/ls
```
Common segments wat deur hierdie cmd gelaai word:

- **`__PAGEZERO`:** Dit instrueer die kernel om die **adres nul** te **map**, sodat dit nie **gelees, geskryf of uitgevoer** kan word nie. Die maxprot- en minprot-veranderlikes in die struktuur word op nul gestel om aan te dui dat daar **geen lees-skryf-uitvoer-regte op hierdie page is nie**.
- Hierdie allokasie is belangrik om **NULL pointer dereference vulnerabilities** te **versag**. Dit is omdat XNU ’n harde page zero afdwing wat verseker dat die eerste page (slegs die eerste een) van memory ontoeganklik is (behalwe in i386). ’n Binary kan aan hierdie vereiste voldoen deur ’n klein \_\_PAGEZERO te skep (met behulp van `-pagezero_size`) om die eerste 4k te dek, terwyl die res van 32bit memory in beide user- en kernel mode toeganklik is.
- **`__TEXT`**: Bevat **uitvoerbare** **code** met **lees-** en **uitvoer**-permissions (geen writable)**.** Algemene sections van hierdie segment:
- `__text`: Gecompileerde binary code
- `__const`: Konstante data (read only)
- `__[c/u/os_log]string`: C-, Unicode- of os logs-stringkonstantes
- `__stubs` en `__stubs_helper`: Betrokke tydens die dynamic library-laaiproses
- `__unwind_info`: Stack unwind-data.
- Let daarop dat al hierdie inhoud signed is, maar ook as uitvoerbaar gemerk is (wat meer opsies skep vir exploitation van sections wat nie noodwendig hierdie privilege benodig nie, soos string-toegewyde sections).
- **`__DATA`**: Bevat data wat **leesbaar** en **skryfbaar** is (nie executable nie)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind by load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind by use) symbol pointer
- `__const`: Behoort read-only data te wees (nie werklik nie)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (wat geïnisialiseer is)
- `__bss`: Static variables (wat nie geïnisialiseer is nie)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, ens.): Inligting wat deur die Objective-C runtime gebruik word
- **`__DATA_CONST`**: \_\_DATA.\_\_const word nie gewaarborg om konstant te wees nie (write permissions), en ander pointers en die GOT is ook nie noodwendig konstant nie. Hierdie section maak `__const`, sommige initializers en die GOT table (sodra dit resolved is) **read only** deur `mprotect` te gebruik.
- **`__AUTH` / `__AUTH_CONST`**: Algemeen in onlangse Apple Silicon binaries. Hierdie segments bevat pointers wat by load- of use-tyd authenticated moet word (byvoorbeeld `__auth_got`). As ’n rebinding-, hook- of import-patching-trick slegs die legacy `__got` / `__la_symbol_ptr` sections nagaan, kan dit die werklike call sites in moderne `arm64e` binaries mis. Vir meer besonderhede oor hierdie sections, kyk na [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Bevat inligting vir die linker (dyld), soos entries vir die symbol-, string- en relocation tables. Dit is ’n generiese container vir inhoud wat nie in `__TEXT` of `__DATA` is nie, en die inhoud daarvan word in ander load commands beskryf.
- dyld information: Rebase-, non-lazy/lazy/weak-binding-opcodes en export-info
- Functions starts: Table van beginadresse van functions
- Data In Code: Data islands in \_\_text
- SYmbol Table: Symbols in binary
- Indirect Symbol Table: Pointer/stub-symbols
- String Table
- Code Signature
- **`__OBJC`**: Bevat inligting wat deur die Objective-C runtime gebruik word. Hierdie inligting kan egter ook in die \_\_DATA-segment gevind word, binne verskeie \_\_objc\_\*-sections.
- **`__RESTRICT`**: ’n Segment sonder inhoud met ’n enkele section genaamd **`__restrict`** (ook leeg), wat verseker dat die binary, wanneer dit uitgevoer word, DYLD-omgewingsveranderlikes sal ignoreer.

Soos in die code gesien kon word, **ondersteun segments ook flags** (alhoewel hulle nie baie gebruik word nie):

- `SG_HIGHVM`: Slegs core (nie gebruik nie)
- `SG_FVMLIB`: Nie gebruik nie
- `SG_NORELOC`: Segment het geen relocation nie
- `SG_PROTECTED_VERSION_1`: Encryption. Word byvoorbeeld deur Finder gebruik om die `__TEXT`-segment te encrypt.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** bevat die entrypoint in die **entryoff-attribuut.** By load-time **tel dyld** eenvoudig hierdie waarde by die (in-memory) **basis van die binary**, en **spring** dan na hierdie instruction om uitvoering van die binary se code te begin.

**`LC_UNIXTHREAD`** bevat die waardes wat die registers moet hê wanneer die main thread begin. Dit is reeds deprecated, maar **`dyld`** gebruik dit steeds. Dit is moontlik om die waardes van die registers wat hierdeur gestel word, te sien met:
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


Bevat inligting oor die **code signature van die Macho-O-lêer**. Dit bevat slegs ’n **offset** wat na die **signature blob** **wys**. Dit is tipies heel aan die einde van die lêer.\
Jy kan egter inligting oor hierdie afdeling in [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) en hierdie [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) vind.<sup>[3][4]</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Ondersteuning vir binary encryption. Indien ’n aanvaller egter daarin slaag om die process te kompromitteer, sal hy die memory ongeënkripteerd kan dump.

### **`LC_LOAD_DYLINKER`**

Bevat die **path na die dynamic linker executable** wat shared libraries in die process se address space karteer. Die **waarde is altyd op `/usr/lib/dyld` gestel**. Dit is belangrik om daarop te let dat dylib mapping in macOS in **user mode**, en nie in kernel mode nie, plaasvind.

### **`LC_IDENT`**

Verouderd, maar wanneer dit gekonfigureer is om dumps tydens ’n panic te genereer, word ’n Mach-O core dump geskep en die kernel-weergawe word in die `LC_IDENT`-command gestel.

### **`LC_UUID`**

Random UUID. Dit is nie direk vir enigiets nuttig nie, maar XNU cache dit saam met die res van die process-inligting. Dit kan in crash reports gebruik word.

### **`LC_BUILD_VERSION`**

Moderne binaries bevat gewoonlik hierdie command om die **target platform**, **minimum OS-weergawe**, **SDK-weergawe** en opsioneel die **tool-weergawes** wat gebruik is om daardie slice te bou, te verklaar. Vanuit ’n offensive/reversing-perspektief is dit baie nuttig om vas te stel hoe ’n sample gebou is en om vinnig vreemde universal binaries raak te sien waar een slice met ’n ander SDK of deployment target gekompileer is. Ouer binaries gebruik moontlik steeds `LC_VERSION_MIN_*` in plaas daarvan.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Laat toe dat omgewingsveranderlikes aan dyld aangedui word voordat die proses uitgevoer word. Dit kan baie gevaarlik wees, aangesien dit die uitvoering van arbitrêre kode binne die proses kan toelaat. Daarom word hierdie load command slegs in dyld-builds gebruik wat `#define SUPPORT_LC_DYLD_ENVIRONMENT` bevat, en verwerking word verder beperk tot veranderlikes in die vorm `DYLD_..._PATH` wat load paths spesifiseer.

### **`LC_DYLD_EXPORTS_TRIE` en `LC_DYLD_CHAINED_FIXUPS`**

Onlangse toolchains stoor dikwels export/bind/rebase-metadata in hierdie commands, in plaas daarvan om slegs op die ouer `LC_DYLD_INFO[_ONLY]`-opcodes staat te maak. Albei is `linkedit_data_command`-entries wat na **`__LINKEDIT`** wys:

- **`LC_DYLD_EXPORTS_TRIE`**: Kompakte trie met die simbole wat deur die image geëksporteer word.
- **`LC_DYLD_CHAINED_FIXUPS`**: Per-segment fixup chains wat deur dyld gebruik word om rebases en binds toe te pas. Op Apple Silicon is dit ook waar jy baie moderne authenticated pointer fixups sal teëkom.

Hierdie metadata is baie nuttig wanneer imports/exports gerekonstrueer word, wanneer jy wil verstaan waarom ’n dependency wat met `@rpath` gelaai is, op die manier opgelos is, of wanneer jy probeer vasstel waarom ’n hook/rebinding-poging op ’n moderne `arm64e`-target misluk het. `dyld_info` kan ook teen **cache-only dylib paths** gebruik word wat nie as standalone files op die skyf bestaan nie. Dit is baie nuttig op moderne macOS, waar baie stelselbiblioteke slegs in die shared cache voorkom.<sup>[2]</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Hierdie moderne load command is meestal relevant wanneer **kernel collections / kernelcache-style filesets** geïnspekteer word. In plaas daarvan dat dit ’n enkele selfstandige image verteenwoordig, tree die buitenste Mach-O as ’n houer op, en elke `LC_FILESET_ENTRY` wys na ’n ingebedde Mach-O met sy eie padagtige **entry id**, VM-adres en file offset. As jy moderne macOS/iOS-kernelkomponente reverse, is hierdie command dikwels die skakel tussen die topvlak-houer en die werklike image wat jy wil ekstraheer of disassemble.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Vir praktiese ekstraksiewerkvloeie, kyk na [hierdie ander bladsy oor macOS-kernuitbreidings en kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Hierdie laa opdrag beskryf ’n **dinamiese** **biblioteek**-afhanklikheid wat die **laaier** (dyld) **opdrag gee om die genoemde biblioteek te laai en te koppel**. Daar is ’n `LC_LOAD_DYLIB`-laa opdrag **vir elke biblioteek** wat die Mach-O-binêre lêer benodig.

- Hierdie laa opdrag is ’n struktuur van die tipe **`dylib_command`** (wat ’n struct dylib bevat wat die werklike afhanklike dinamiese biblioteek beskryf):
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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t versoenbaarheidsweergawe; / biblioteek se versoenbaarheidsweergawenommer /](<../../../images/image (486).png>)

Jy kan hierdie inligting ook met die CLI kry:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Sommige potensiële malware-verwante biblioteke is:

- **DiskArbitration**: Monitering van USB-aandrywers
- **AVFoundation:** Vaslegging van oudio en video
- **CoreWLAN**: WiFi-skanderings.

> [!TIP]
> ’n Mach-O-binêre lêer kan een of **meer** **konstruktors** bevat, wat **uitgevoer** sal word **voor** die adres wat in **LC_MAIN** gespesifiseer word.\
> Die offsets van enige konstruktors word in die **\_\_mod_init_func**-seksie van die **\_\_DATA_CONST**-segment gehou.

## **Mach-O-data**

In die kern van die lêer lê die data-area, wat uit verskeie segmente bestaan soos in die load-commands-area gedefinieer. **’n Verskeidenheid data-seksies kan binne elke segment gehuisves word**, met elke seksie wat **kode of data** bevat wat spesifiek vir ’n tipe is.

> [!TIP]
> Die data is basies die deel wat al die **inligting** bevat wat deur die load commands **LC_SEGMENTS_64** gelaai word.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Dit sluit die volgende in:

- **Funksietabel:** Wat inligting oor die program se funksies bevat.
- **Simbooltabel**: Wat inligting bevat oor die eksterne funksie wat deur die binêre lêer gebruik word
- Dit kan ook interne funksie- en veranderlikename, sowel as meer, bevat.

Om dit na te gaan, kan jy die [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool gebruik:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Of vanaf die cli:
```bash
size -m /bin/ls
```
## Algemene Objective-C-afdelings

In `__TEXT`-segment (r-x):

- `__objc_classname`: Klassenname (stringe)
- `__objc_methname`: Metodename (stringe)
- `__objc_methtype`: Metodetipes (stringe)

In `__DATA`-segment (rw-):

- `__objc_classlist`: Aanwysers na alle Objective-C-klasse
- `__objc_nlclslist`: Aanwysers na Non-Lazy Objective-C-klasse
- `__objc_catlist`: Aanwyser na Kategorieë
- `__objc_nlcatlist`: Aanwysers na Non-Lazy Kategorieë
- `__objc_protolist`: Protokollys
- `__objc_const`: Konstante data
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## Verwysings

- [1] [Mach-O-skywe is nie so eenvoudig soos wat jy dalk dink nie](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1)-manbladsy](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Lees jou eie Entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
