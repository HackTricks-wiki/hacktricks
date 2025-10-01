# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Mac OS-binaries word gewoonlik as **universal binaries** gekompileer. 'n **universal binary** kan **verskeie argitekture in dieselfde lêer ondersteun**.

Hierdie binaries volg die **Mach-O structure**, wat basies bestaan uit:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Soek die lêer met: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Die header bevat die **magic** bytes gevolg deur die **aantal** **archs** wat die lêer **bevat** (`nfat_arch`) en elke arch sal 'n `fat_arch`-struktuur hê.

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

of deur die [Mach-O View](https://sourceforge.net/projects/machoview/) gereedskap te gebruik:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Soos jy dalk dink, 'n universal binary wat vir 2 argitekture gekompileer is, **verdubbel gewoonlik die grootte** van een wat slegs vir 1 arch gekompileer is.

## **Mach-O Header**

Die header bevat basiese inligting oor die lêer, soos magic bytes om dit as 'n Mach-O-lêer te identifiseer en inligting oor die teiken-argitektuur. Jy kan dit vind in: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O lêer-tipes

Daar is verskillende lêertipes; jy kan hulle gedefinieer vind in die [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Die belangrikste is:

- `MH_OBJECT`: Verplaasbare objeklêer (tussenprodukte van samestelling, nog nie uitvoerbare lêers nie).
- `MH_EXECUTE`: Uitvoerbare lêers.
- `MH_FVMLIB`: Vaste VM-biblioteeklêer.
- `MH_CORE`: Kode-dumps
- `MH_PRELOAD`: Voorafgelaaide uitvoerbare lêer (nie meer deur XNU ondersteun nie)
- `MH_DYLIB`: Dinamiese biblioteke
- `MH_DYLINKER`: Dinamiese linker
- `MH_BUNDLE`: "Plugin-lêers". Gegenereer met -bundle in gcc en eksplisiet gelaai deur `NSBundle` of `dlopen`.
- `MH_DYSM`: Geselskap `.dSym`-lêer (lêer met simbole vir foutopsporing).
- `MH_KEXT_BUNDLE`: Kernuitbreidings.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Of deur [Mach-O View](https://sourceforge.net/projects/machoview/) te gebruik:

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O vlae**

Die bronkode definieer ook verskeie vlae wat nuttig is vir die laai van biblioteke:

- `MH_NOUNDEFS`: No undefined references (fully linked)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamic references prebound.
- `MH_SPLIT_SEGS`: File splits r/o and r/w segments.
- `MH_WEAK_DEFINES`: Binary has weak defined symbols
- `MH_BINDS_TO_WEAK`: Binary uses weak symbols
- `MH_ALLOW_STACK_EXECUTION`: Make the stack executable
- `MH_NO_REEXPORTED_DYLIBS`: Library not LC_REEXPORT commands
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: There is a section with thread local variables
- `MH_NO_HEAP_EXECUTION`: No execution for heap/data pages
- `MH_HAS_OBJC`: Binary has oBject-C sections
- `MH_SIM_SUPPORT`: Simulator support
- `MH_DYLIB_IN_CACHE`: Used on dylibs/frameworks in shared library cache.

## **Mach-O Laai-opdragte**

Die lêer se uitleg in geheue word hier gespesifiseer, en beskryf die ligging van die simbooltabel, die konteks van die hoofdraad by die begin van uitvoering, en die vereiste gedeelde biblioteke. Instruksies word aan die dinamiese laaier (dyld) gegee oor die proses om die binêr in geheue te laai.

Dit gebruik die `load_command`-struktuur, gedefinieer in die genoemde `loader.h`:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Daar is omtrent **50 verskillende soorte load commands** wat die stelsel op verskillende maniere hanteer. Die mees algemene is: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, and `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Basies definieer hierdie tipe Load Command **hoe om die \_\_TEXT** (uitvoerbare kode) **en \_\_DATA** (data vir die proses) **segmente te laai** volgens die **offsets aangedui in die Data section** wanneer die binary uitgevoer word.

Hierdie commands **definieer segment** wat **gemap** word in die **virtuele geheue-ruimte** van 'n proses wanneer dit uitgevoer word.

Daar is **verskillende tipes** segment, soos die **\_\_TEXT** segment, wat die uitvoerbare kode van 'n program bevat, en die **\_\_DATA** segment, wat data bevat wat deur die proses gebruik word. Hierdie **segmente lê in die data section** van die Mach-O lêer.

**Elke segment** kan verder **verdeeld** word in meerdere **sections**. Die **load command structure** bevat **inligting** oor **hierdie sections** binne die betrokke segment.

In die header vind jy eers die **segment header**:

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

Voorbeeld van 'n segment header:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Hierdie header definieer die **aantal sections wie se headers daarna verskyn**:
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
Voorbeeld van **afdelingsopskrif**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

As jy die **afdelingsverskuiwing** (0x37DC) by die **verskuiwing** waar die **argitektuur** begin optel, in hierdie geval `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Dit is ook moontlik om **header-inligting** vanaf die **opdraglyn** te kry met:
```bash
otool -lv /bin/ls
```
Algemene segmente wat deur hierdie cmd gelaai word:

- **`__PAGEZERO`:** Dit beveel die kernel om die **adres nul** te **map** sodat dit **nie gelees, geskryf of uitgevoer kan word nie**. Die maxprot- en minprot-veranderlikes in die struktuur is op nul gestel om aan te dui dat daar **geen lees-skryf-uitvoer regte op hierdie bladsy is nie**.
- Hierdie toekenning is belangrik om **NULL pointer dereference vulnerabilities** te verminder. Dit is omdat XNU 'n harde page zero afdwing wat verseker dat die eerste bladsy (slegs die eerste) van geheue ontoeganklik is (behalwe in i386). 'n binary kan aan hierdie vereistes voldoen deur 'n klein \_\_PAGEZERO te vervaardig (gebruik `-pagezero_size`) om die eerste 4k te dek en die res van die 32bit geheue toeganklik te maak in beide user- en kernel-modus.
- **`__TEXT`**: Bevat **uitvoerbare** **kode** met **lees** en **uitvoering** regte (nie skryfbaar nie). Algemene afdelings van hierdie segment:
- `__text`: Gekomileerde kode
- `__const`: Konstantedata (slegs leesbaar)
- `__[c/u/os_log]string`: C-, Unicode- of os_log-string konstantes
- `__stubs` and `__stubs_helper`: Betrokke tydens die dinamiese biblioteek-laaiproses
- `__unwind_info`: Stack unwind-data.
- Let wel dat al hierdie inhoud gesigneer is maar ook as uitvoerbaar gemerk is (wat meer opsies skep vir die uitbuiting van afdelings wat nie noodwendig hierdie voorreg benodig nie, soos string-toegewyde afdelings).
- **`__DATA`**: Bevat data wat **leesbaar** en **skryfbaar** is (nie uitvoerbaar nie).
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Sou lees-alleen data wees (maar nie regtig nie)
- `__cfstring`: CoreFoundation strings
- `__data`: Globale veranderlikes (wat geïnitialiseer is)
- `__bss`: Statiese veranderlikes (wat nie geïnitialiseer is nie)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Inligting wat deur die Objective-C runtime gebruik word
- **`__DATA_CONST`**: \_\_DATA.\_\_const is nie gewaarborg om konstant te wees nie (skryfregte), en ander pointers en die GOT ook nie. Hierdie afdeling maak `__const`, sommige initialiseerders en die GOT-tabel (sodra dit opgelos is) **slegs-lees** deur `mprotect`.
- **`__LINKEDIT`**: Bevat inligting vir die linker (dyld) soos simbool-, string- en relocasie-tabelinskrywings. Dit is 'n generiese houer vir inhoud wat nie in `__TEXT` of `__DATA` is nie en sy inhoud word in ander load commands beskryf.
- dyld-inligting: Rebase, Non-lazy/lazy/weak binding opcodes en export-inligting
- Functions starts: Tabel van beginadresse van funksies
- Data In Code: Data-eilandjies in \_\_text
- SYmbol Table: Simbole in die binary
- Indirect Symbol Table: Pointer/stub-simbole
- String Table
- Code Signature
- **`__OBJC`**: Bevat inligting wat deur die Objective-C runtime gebruik word. Hierdie inligting kan egter ook in die \_\_DATA-segment voorkom, binne verskeie \_\_objc\_\* afdelings.
- **`__RESTRICT`**: 'n Segment sonder inhoud met 'n enkele afdeling genaamd **`__restrict`** (ook leeg) wat verseker dat wanneer die binary uitgevoer word, dit DYLD-omgewingsvariabeles sal ignoreer.

Soos in die kode gesien kan word, **ondersteun segmente ook vlae** (alhoewel hulle nie baie gebruik word nie):

- `SG_HIGHVM`: Core only (not used)
- `SG_FVMLIB`: Not used
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Used for example by Finder to encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** bevat die entrypoint in die **entryoff-atribuut.** Tydens laai voeg **dyld** bloot hierdie waarde by die (in-memory) **basis van die binary**, en **spring** dan na hierdie instruksie om die uitvoering van die binary se kode te begin.

**`LC_UNIXTHREAD`** bevat die waardes wat registers moet hê wanneer die hoofdraad begin word. Dit is reeds verouderd, maar **`dyld`** gebruik dit steeds. Dit is moontlik om die waardes van die registers wat daarmee gestel word te sien met:
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


Bevat inligting oor die **code signature of the Macho-O file**. Dit bevat slegs 'n **offset** wat **wys na** die **signature blob**. Dit is gewoonlik aan die einde van die lêer.\
Jy kan egter inligting oor hierdie afdeling vind in [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) en hierdie [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Ondersteun binary encryption. Uiteraard, as 'n attacker daarin slaag om die proses te kompromitteer, sal hy die geheue ongeënkripteerd kan dump.

### **`LC_LOAD_DYLINKER`**

Bevat die **pad na die dynamic linker executable** wat shared libraries in die proses adresruimte map. Die **waarde is altyd gestel op `/usr/lib/dyld`**. Dit is belangrik om daarop te let dat in macOS, dylib mapping in **user mode** plaasvind, nie in kernel mode nie.

### **`LC_IDENT`**

Verouderd — maar wanneer dit gekonfigureer is om dumps op panic te genereer, word 'n Mach-O core dump geskep en die kernel version in die `LC_IDENT` command gestel.

### **`LC_UUID`**

Willekeurige UUID. Dit is nie direk nuttig vir iets nie, maar XNU cache dit saam met die res van die prosesinligting. Dit kan in crash reports gebruik word.

### **`LC_DYLD_ENVIRONMENT`**

Laat toe om environment variables aan dyld aan te dui voordat die proses uitgevoer word. Dit kan baie gevaarlik wees aangesien dit toelaat om arbitrary code binne die proses uit te voer, daarom word hierdie load command slegs gebruik in dyld builds met `#define SUPPORT_LC_DYLD_ENVIRONMENT` en beperk verwerking verder slegs tot veranderlikes van die vorm `DYLD_..._PATH` wat load paths spesifiseer.

### **`LC_LOAD_DYLIB`**

Hierdie load command beskryf 'n **dynamic** **library** afhanklikheid wat die **loader** (dyld) **instrueer** om genoemde library te **load and link**. Daar is 'n `LC_LOAD_DYLIB` load command **vir elke library** wat die Mach-O binary benodig.

- Hierdie load command is 'n struktuur van tipe **`dylib_command`** (wat 'n struct dylib bevat, wat die werklike afhanklike dynamic library beskryf):
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

Jy kan hierdie inligting ook vanaf die cli kry met:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Sommige potensiële malware-verwante biblioteke is:

- **DiskArbitration**: Monitering van USB-stasies
- **AVFoundation:** Neem klank en video op
- **CoreWLAN**: Wi‑Fi-skanderings.

> [!TIP]
> 'n Mach-O binary kan een of **meer** **constructors** bevat, wat **uitgevoer** sal word **voor** die adres wat in **LC_MAIN** gespesifiseer is.\
> Die offsets van enige constructors word gehou in die **\_\_mod_init_func** afdeling van die **\_\_DATA_CONST** segment.

## **Mach-O Data**

In die kern van die lêer lê die data-streek, wat uit verskeie segmente saamgestel is soos gedefinieer in die load-commands streek. **'n Verskeidenheid data-afdelings kan binne elke segment gehuisves word**, met elke afdeling wat **kode of data bevat** spesifiek vir 'n tipe.

> [!TIP]
> Die data is basies die deel wat al die **inligting** bevat wat deur die load commands **LC_SEGMENTS_64** gelaai word

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Dit sluit in:

- **Function table:** Wat inligting oor die program se funksies bevat.
- **Symbol table**: Wat inligting bevat oor die eksterne funksies wat deur die binary gebruik word
- Dit kan ook interne funksies, veranderlike name en meer bevat.

To check it you could use the [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Of vanaf die cli:
```bash
size -m /bin/ls
```
## Objetive-C Algemene Afdelings

In die `__TEXT` segment (r-x):

- `__objc_classname`: Klasname (strings)
- `__objc_methname`: Metodenamme (strings)
- `__objc_methtype`: Metode tipes (strings)

In die `__DATA` segment (rw-):

- `__objc_classlist`: Wysigers na alle Objetive-C klasse
- `__objc_nlclslist`: Wysigers na Non-Lazy Objective-C klasse
- `__objc_catlist`: Wysiger na Categories
- `__objc_nlcatlist`: Wysiger na Non-Lazy Categories
- `__objc_protolist`: Protokollys
- `__objc_const`: Konstante data
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
