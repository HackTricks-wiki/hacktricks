# macOS Universal binaries en Mach-O-formaat

{{#include ../../../banners/hacktricks-training.md}}

## Basiese inligting

macOS gebruik die **Mach-O**-uitvoerbare formaat. ’n **universele**, of fat, binary bevat verskeie argitektuurspesifieke Mach-O-slices in een lêer. Apple se oopbron-`fat.h`- en `loader.h`-headers definieer die strukture en konstantes wat op hierdie bladsy beskryf word. <sup>[[5]](#references)</sup>

’n Mach-O-image bestaan uit:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat-header

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

Die header bevat die **magic**-bytes, gevolg deur die **aantal** **argitekture** wat die lêer **bevat** (`nfat_arch`), en elke argitektuur het ’n `fat_arch`-struct.

Kyk dit na met:

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

of met die [Mach-O View](https://sourceforge.net/projects/machoview/) -nutsding:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Soos jy dalk vermoed, is ’n universele binary wat vir 2 argitekture gecompileer is, gewoonlik **dubbel so groot** as een wat vir net 1 argitektuur gecompileer is.

> [!TIP]
> Wanneer jy malware of verdagte apps ondersoek, moenie ophou nadat `file` die "beste" argitektuur gerapporteer het nie. ’n Universele binary kan verskillende imports, load commands of compiler-metadata in elke slice versteek. Lys dus eers **al** die slices en ondersoek hulle daarna afsonderlik:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Onlangse macOS SDKs bied ook helpers soos `macho_for_each_slice()` en `macho_best_slice()` in `<mach-o/utils.h>`. Laasgenoemde is handig om na te boots wat dyld/kernel sou laai, maar scanners moet steeds deur elke slice loop om te voorkom dat argitektuurspesifieke inhoud gemis word.<sup>[[1]](#references)</sup>

## **Mach-O-kopstuk**

Die kopstuk bevat basiese inligting oor die lêer, soos magic bytes om dit as ’n Mach-O-lêer te identifiseer en inligting oor die teikenargitektuur. Jy kan dit hier vind: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

Daar is verskillende lêertipes; jy kan hulle byvoorbeeld in die [**bronkode hier**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) vind. Die belangrikste is:

- `MH_OBJECT`: Relokeerbare objeklêer (tussentydse produkte van samestelling, nog nie uitvoerbare lêers nie).
- `MH_EXECUTE`: Uitvoerbare lêers.
- `MH_FVMLIB`: Lêer vir ’n vaste VM-biblioteek.
- `MH_CORE`: Kodedumps
- `MH_PRELOAD`: Voorafgelaaide uitvoerbare lêer (word nie meer in XNU ondersteun nie)
- `MH_DYLIB`: Dinamiese biblioteke
- `MH_DYLINKER`: Dinamiese skakelaar
- `MH_BUNDLE`: "Inprop-lêers". Gegenereer met -bundle in gcc en eksplisiet deur `NSBundle` of `dlopen` gelaai.
- `MH_DYSM`: Gepaardgaande `.dSym`-lêer (lêer met simbole vir ontfouting).
- `MH_KEXT_BUNDLE`: Kernel-uitbreidings.

```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

Of gebruik [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O-vlae**

Die bronkode definieer ook verskeie vlae wat nuttig is om biblioteke te laai:

- `MH_NOUNDEFS`: Geen ongedefinieerde verwysings nie (volledig gekoppel)
- `MH_DYLDLINK`: Dyld-koppeling
- `MH_PREBOUND`: Dinamiese verwysings is vooraf gebind.
- `MH_SPLIT_SEGS`: Lêer verdeel leesalleen- en lees/skryf-segmente.
- `MH_WEAK_DEFINES`: Binêre lêer het swak gedefinieerde simbole
- `MH_BINDS_TO_WEAK`: Binêre lêer gebruik swak simbole
- `MH_ALLOW_STACK_EXECUTION`: Maak die stapel uitvoerbaar
- `MH_NO_REEXPORTED_DYLIBS`: Biblioteek het nie LC_REEXPORT-opdragte nie
- `MH_PIE`: Posisie-onafhanklike uitvoerbare lêer
- `MH_HAS_TLV_DESCRIPTORS`: Daar is 'n afdeling met thread-lokale veranderlikes
- `MH_NO_HEAP_EXECUTION`: Geen uitvoering vir heap-/databladsye nie
- `MH_HAS_OBJC`: Binêre lêer het oBject-C-afdelings
- `MH_SIM_SUPPORT`: Simulator-ondersteuning
- `MH_DYLIB_IN_CACHE`: Word vir dylibs/frameworks in die gedeelde biblioteekkas gebruik.

## **Mach-O-laaikommando's**

Die **lêer se uitleg in die geheue** word hier gespesifiseer, met besonderhede oor die **ligging van die simbooltabel**, die konteks van die hooftread aan die begin van uitvoering, en die vereiste **gedeelde biblioteke**. Instruksies word aan die dinamiese laaier **(dyld)** gegee oor hoe die binêre lêer in die geheue gelaai moet word.

Dit gebruik die **load_command**-struktuur, wat in die genoemde **`loader.h`** gedefinieer word:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Daar is ongeveer **50 verskillende tipes load commands** wat die stelsel verskillend hanteer. Die algemeenste is: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` en `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Basies definieer hierdie tipe Load Command **hoe om die \_\_TEXT** (uitvoerbare kode) **en \_\_DATA** (data vir die proses) **segmente te laai** volgens die **offsets wat in die Data-afdeling aangedui word** wanneer die binary uitgevoer word.

Hierdie opdragte **definieer segmente** wat **gemap word** na die **virtuele geheuespasie** van ’n proses wanneer dit uitgevoer word.

Daar is **verskillende tipes** segmente, soos die **\_\_TEXT**-segment, wat die uitvoerbare kode van ’n program bevat, en die **\_\_DATA**-segment, wat data bevat wat deur die proses gebruik word. Hierdie **segmente is in die data-afdeling** van die Mach-O-lêer geleë.

**Elke segment** kan verder in verskeie **afdelings verdeel** word. Die **load command-struktuur** bevat **inligting** oor **hierdie afdelings** binne die onderskeie segment.

In die kopstuk vind jy eers die **segmentkopstuk**:

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

Voorbeeld van ’n segmentkopstuk:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Hierdie kopstuk definieer die **aantal afdelings waarvan die kopstukke daarna verskyn**:

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

Voorbeeld van **seksiekop**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

As jy die **seksie-offset** (0x37DC) + die **offset** waar die **argitektuur begin**, in hierdie geval `0x18000`, **bytel** --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Dit is ook moontlik om **kopinligting** vanaf die **opdragreël** te kry met:

```bash
otool -lv /bin/ls
```

Common segmente wat deur hierdie cmd gelaai word:

- **`__PAGEZERO`:** Dit gee die kernel opdrag om **adres nul** te **map** sodat dit **nie gelees, geskryf of uitgevoer kan word nie**. Die maxprot- en minprot-veranderlikes in die struktuur word op nul gestel om aan te dui dat daar **geen lees-, skryf- of uitvoerregte op hierdie bladsy is nie**.
  - Hierdie toekenning is belangrik om **NULL pointer dereference-kwesbaarhede te versag**. Dit is omdat XNU ’n harde nulbladsy afdwing wat verseker dat die eerste geheuebladsy (slegs die eerste) ontoeganklik is (behalwe in i386). ’n Binêre lêer kan aan hierdie vereistes voldoen deur ’n klein \_\_PAGEZERO te skep (met `-pagezero_size`) wat die eerste 4k dek, en die res van die 32-bis-geheue toeganklik te maak in beide gebruikers- en kernelmodus.
- **`__TEXT`**: Bevat **uitvoerbare** **kode** met **lees-** en **uitvoer**toestemmings (nie skryfbaar nie)**.** Algemene seksies van hierdie segment:
  - `__text`: Gekompileerde binêre kode
  - `__const`: Konstante data (slegs leesbaar)
  - `__[c/u/os_log]string`: C-, Unicode- of os-log-stringkonstantes
  - `__stubs` en `__stubs_helper`: Betrokke tydens die laai van dinamiese biblioteke
  - `__unwind_info`: Stack-unwind-data.
  - Let daarop dat al hierdie inhoud onderteken is, maar ook as uitvoerbaar gemerk is (wat meer opsies vir uitbuiting skep van seksies wat nie noodwendig hierdie voorreg nodig het nie, soos seksies wat uitsluitlik vir stringe bedoel is).
- **`__DATA`**: Bevat data wat **leesbaar** en **skryfbaar** is (nie uitvoerbaar nie)**.**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Nie-lui (bind by laai) simboolwyser
  - `__la_symbol_ptr`: Lui (bind wanneer dit gebruik word) simboolwyser
  - `__const`: Behoort leesalleendata te wees (maar is nie werklik nie)
  - `__cfstring`: CoreFoundation-stringe
  - `__data`: Globale veranderlikes (wat geïnisialiseer is)
  - `__bss`: Statiese veranderlikes (wat nie geïnisialiseer is nie)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, ens.): Inligting wat deur die Objective-C-runtime gebruik word
- **`__DATA_CONST`**: \_\_DATA.\_\_const is nie gewaarborg om konstant te wees nie (skryftoestemmings), en dieselfde geld vir ander wysers en die GOT. Hierdie seksie maak `__const`, sommige inisialiseerders en die GOT-tabel (sodra dit opgelos is) **leesalleen** deur `mprotect` te gebruik.
- **`__AUTH` / `__AUTH_CONST`**: Algemeen in onlangse Apple Silicon-binêre lêers. Hierdie segmente bevat wysers wat tydens laai of gebruik geverifieer moet word (byvoorbeeld `__auth_got`). As ’n rebinding-, hook- of import-patching-tegniek slegs die verouderde `__got` / `__la_symbol_ptr`-seksies nagaan, kan dit die werklike oproeppunte in moderne `arm64e`-binêre lêers miskyk. Vir meer besonderhede oor hierdie seksies, kyk na [hierdie bladsy](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Bevat inligting vir die linker (dyld), soos simbool-, string- en relokasietabelinskrywings. Dit is ’n generiese houer vir inhoud wat nie in `__TEXT` of `__DATA` voorkom nie; die inhoud daarvan word in ander laaikommando’s beskryf.
  - dyld-inligting: Rebase-, nie-lui/lui/swak-bindings-opkodes en uitvoerinligting
  - Funksiebeginsels: Tabel met beginadresse van funksies
  - Data In Code: Data-eilande in \_\_text
  - SYmbol Table: Simbole in die binêre lêer
  - Indirect Symbol Table: Wysersimbole/stub-simbole
  - String Table
  - Code Signature
- **`__OBJC`**: Bevat inligting wat deur die Objective-C-runtime gebruik word. Hierdie inligting kan egter ook in die \_\_DATA-segment gevind word, binne verskeie \_\_objc\_\*-seksies.
- **`__RESTRICT`**: ’n Segment sonder inhoud met ’n enkele seksie genaamd **`__restrict`** (ook leeg), wat verseker dat die binêre lêer DYLD-omgewingsveranderlikes ignoreer wanneer dit uitgevoer word.

Soos in die kode gesien kon word, **ondersteun segmente ook vlae** (hoewel dit nie baie gebruik word nie):

- `SG_HIGHVM`: Slegs Core (nie gebruik nie)
- `SG_FVMLIB`: Nie gebruik nie
- `SG_NORELOC`: Segment het geen relokasie nie
- `SG_PROTECTED_VERSION_1`: Enkripsie. Word byvoorbeeld deur Finder gebruik om die teks in die `__TEXT`-segment te enkripteer.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** bevat die toegangspunt in die **entryoff-kenmerk.** Wanneer dit gelaai word, **tel** **dyld** hierdie waarde eenvoudig by die (in-geheue) **basisadres van die binêre lêer**, en **spring** dan na hierdie instruksie om die uitvoering van die binêre lêer se kode te begin.

**`LC_UNIXTHREAD`** bevat die waardes wat die registers moet hê wanneer die hooftoerd begin. Dit is reeds verouderd, maar **`dyld`** gebruik dit steeds. Dit is moontlik om die registerwaardes te sien wat hiermee gestel word deur:

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


Bevat inligting oor die **code signature van die Mach-O-lêer**. Dit bevat net ’n **offset** wat na die **signature blob** **wys**. Dit is gewoonlik heel aan die einde van die lêer.\
Jy kan meer inligting oor hierdie afdeling vind in [**hierdie blogplasing**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) en [**hierdie gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Ondersteuning vir binary encryption. As ’n aanvaller egter daarin slaag om die proses te kompromitteer, sal hy die geheue ongeënkripteer kan dump.

### **`LC_LOAD_DYLINKER`**

Bevat die **pad na die dynamic linker-uitvoerbare lêer** wat shared libraries in die proses se adresruimte laai. Die **waarde is altyd op `/usr/lib/dyld` gestel**. Dit is belangrik om daarop te let dat dylib-kartering in macOS in **gebruikersmodus** plaasvind, nie in kernmodus nie.

### **`LC_IDENT`**

Verouderd, maar wanneer dit ingestel is om dumps tydens ’n panic te genereer, word ’n Mach-O core dump geskep en word die kernel-weergawe in die `LC_IDENT`-opdrag gestel.

### **`LC_UUID`**

Willekeurige UUID. Dit is nie direk vir enigiets nuttig nie, maar XNU kas dit saam met die res van die prosesinligting. Dit kan in crash reports gebruik word.

### **`LC_BUILD_VERSION`**

Moderne binaries bevat gewoonlik hierdie opdrag om die **teikenplatform**, **minimum OS-weergawe**, **SDK-weergawe** en, opsioneel, die **tool-weergawes** wat gebruik is om daardie slice te bou, aan te dui. Vanuit ’n offensive/reversing-perspektief is dit baie nuttig om te bepaal hoe ’n sample gebou is en om vinnig vreemde universal binaries raak te sien waar een slice met ’n ander SDK of deployment target saamgestel is. Ouer binaries gebruik moontlik steeds `LC_VERSION_MIN_*` in plaas daarvan.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Laat toe dat omgewingsveranderlikes aan dyld aangedui word voordat die proses uitgevoer word. Dit kan baie gevaarlik wees, aangesien dit arbitrêre kode binne die proses kan laat uitvoer. Daarom word hierdie laaibevel slegs in dyld-builds met `#define SUPPORT_LC_DYLD_ENVIRONMENT` gebruik, en word verwerking verder beperk tot veranderlikes van die vorm `DYLD_..._PATH` wat laaipaaie spesifiseer.

### **`LC_DYLD_EXPORTS_TRIE` en `LC_DYLD_CHAINED_FIXUPS`**

Onlangse toolchains stoor uitvoer-/bind-/herbasis-metadata dikwels in hierdie bevele, eerder as om net op die ouer `LC_DYLD_INFO[_ONLY]`-opkodes staat te maak. Albei is `linkedit_data_command`-inskrywings wat na **`__LINKEDIT`** wys:

- **`LC_DYLD_EXPORTS_TRIE`**: Kompakte trie met die simbole wat deur die image uitgevoer word.
- **`LC_DYLD_CHAINED_FIXUPS`**: Fixup-kettings per segment wat dyld gebruik om herbasisse en bindings toe te pas. Op Apple Silicon sal jy ook baie moderne geverifieerde wyser-fixups hier teëkom.

Hierdie metadata is baie nuttig wanneer jy invoere/uitvoere rekonstrueer, verstaan waarom ’n `@rpath`-gelaaide afhanklikheid op ’n bepaalde manier opgelos is, of uitvind waarom ’n hook-/rebinding-poging op ’n moderne `arm64e`-teiken misluk het. `dyld_info` kan ook gebruik word op **cache-only dylib-paaie** wat nie as selfstandige lêers op skyf bestaan nie. Dit is baie nuttig op moderne macOS, waar baie stelselbiblioteke slegs in die shared cache voorkom.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Hierdie moderne lasopdrag is hoofsaaklik relevant wanneer **kernel collections / kernelcache-style filesets** geïnspekteer word. In plaas daarvan om ’n enkele selfstandige image voor te stel, tree die buitenste Mach-O as ’n houer op, en elke `LC_FILESET_ENTRY` wys na ’n ingebedde Mach-O met sy eie padagtige **entry id**, VM-adres en lêeroffset. Wanneer jy moderne macOS/iOS-kernelkomponente reverse, vorm hierdie opdrag dikwels die skakel tussen die topvlak-houer en die werklike image wat jy wil onttrek of disassemble.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Vir praktiese onttrekkingswerkvloeie, kyk na [hierdie ander bladsy oor macOS-kernuitbreidings en kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Hierdie laa opdrag beskryf ’n **dinamiese** **biblioteek**-afhanklikheid wat die **loader** (dyld) **opdrag gee om die genoemde biblioteek te laai en te skakel**. Daar is ’n `LC_LOAD_DYLIB`-laaiopdrag **vir elke biblioteek** wat die Mach-O-binêre lêer benodig.

- Hierdie laaiopdrag is ’n struktuur van die tipe **`dylib_command`** (wat ’n struct dylib bevat wat die werklike afhanklike dinamiese biblioteek beskryf):

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t verenigbaarheidsweergawe; / biblioteek se verenigbaarheidsweergawenommer /](<../../../images/image (486).png>)

Jy kan ook hierdie inligting vanaf die CLI kry met:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Sommige moontlike malwareverwante biblioteke is:

- **DiskArbitration**: Monitering van USB-aandrywers
- **AVFoundation:** Neem oudio en video op
- **CoreWLAN**: Wi-Fi-skanderings.

> [!TIP]
> ’n Mach-O-binêre lêer kan een of **meer** **konstruktors** bevat, wat **uitgevoer** sal word **voordat** die adres wat in **LC_MAIN** gespesifiseer word.\
> Die offsets van enige konstruktors word in die **\_\_mod_init_func**-afdeling van die **\_\_DATA_CONST**-segment gehou.

## **Mach-O-data**

In die kern van die lêer lê die data-area, wat uit verskeie segmente bestaan soos in die load-commands-area gedefinieer. **’n Verskeidenheid data-afdelings kan binne elke segment gehuisves word**, met elke afdeling wat **kode of data** bevat wat spesifiek vir ’n tipe is.

> [!TIP]
> Die data is basies die deel wat al die **inligting** bevat wat deur die load command **LC_SEGMENTS_64** gelaai word.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Dit sluit die volgende in:

- **Funksietabel:** Bevat inligting oor die program se funksies.
- **Simbooltabel**: Bevat inligting oor die eksterne funksie wat deur die binêre lêer gebruik word.
- Dit kan ook interne funksies, veranderlikename en meer bevat.

Om dit na te gaan, kan jy die [**Mach-O View**](https://sourceforge.net/projects/machoview/) hulpmiddel gebruik:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Of vanaf die CLI:

```bash
size -m /bin/ls
```

### Aangehegte data en omgekeerd geparseerde overlays

'n Loader kan konfigurasie in aangehegte data stoor in plaas van in 'n benoemde Mach-O-afdeling. 'n Omgekeerde parser anker hom dan aan 'n sleepmerker, lees 'n grootte wat onmiddellik daarvoor gestoor is en gebruik dié waarde om die voorafgaande blob op te spoor en te dekripteer. Een waargenome universele loader het hierdie uitleg vir 'n XOR-geënkripteerde downloader-URL gebruik:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Wanneer jy ’n onbekende binary reverse-engineer, ondersoek die grepe rondom herkenbare eindmerkers en volg elke terugwaartse grootteberekening voordat jy aanvaar dat stringe of konfigurasie noodwendig by ’n load-command-afdeling hoort. Die merker en XOR-sleutel is spesifiek vir die sample; die herbruikbare tegniek is die selfbeskrywende sleepstuk.

## Algemene Objective-C-afdelings

In die `__TEXT`-segment (r-x):

- `__objc_classname`: Klasname (stringe)
- `__objc_methname`: Metodename (stringe)
- `__objc_methtype`: Metodetipes (stringe)

In die `__DATA`-segment (rw-):

- `__objc_classlist`: Wysers na alle Objective-C-klasse
- `__objc_nlclslist`: Wysers na Non-Lazy Objective-C-klasse
- `__objc_catlist`: Wyser na Categories
- `__objc_nlcatlist`: Wysers na Non-Lazy Categories
- `__objc_protolist`: Lys van protokolle
- `__objc_const`: Konstante data
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Mach-O-skywe is nie so eenvoudig soos jy dalk dink nie](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1)-manblad](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Lees jou eie entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source - Mach-O `fat.h` en `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - ’n Nuwe weergawe van die MacSync macOS-stealer teiken kripto-entoesiaste en ontwikkelaars](https://securelist.com/macsync-new-version/121383/)
