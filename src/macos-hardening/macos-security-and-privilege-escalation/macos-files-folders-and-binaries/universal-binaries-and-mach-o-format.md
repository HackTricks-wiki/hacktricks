# macOS Universele binêre lêers & Mach-O-formaat

{{#include ../../../banners/hacktricks-training.md}}

## Basiese inligting

macOS gebruik die **Mach-O**-uitvoerbare formaat. ’n **Universele** of vet binêre lêer bevat verskeie argitektuurspesifieke Mach-O-snitte in een lêer. Apple se oopbron-`fat.h`- en `loader.h`-koplêers definieer die strukture en konstantes wat op hierdie bladsy beskryf word. <sup>[[5]](#references)</sup>

’n Mach-O-beeld bestaan uit:

- Kopskrif
- Laaikommando’s
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Vet kopskrif

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

Die kopskrif bevat die **magiese** grepe, gevolg deur die **aantal** **argitekture** wat die lêer **bevat** (`nfat_arch`), en elke argitektuur het ’n `fat_arch`-struktuur.

Kyk daarna met:

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

of met die [Mach-O View](https://sourceforge.net/projects/machoview/) nutsding:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Soos jy dalk vermoed, verdubbel ’n universele binêre lêer wat vir 2 argitekture gekompileer is gewoonlik **die grootte** van een wat vir net 1 argitektuur gekompileer is.

> [!TIP]
> Wanneer jy malware of verdagte toepassings ondersoek, moenie ophou nadat `file` die “beste” argitektuur gerapporteer het nie. ’n Universele binêre lêer kan verskillende invoere, laaikommando’s of samesteller-metadata in elke snit wegsteek. Lys dus eers **al** die snitte en ondersoek hulle dan afsonderlik:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Onlangse macOS SDK's stel ook `macho_for_each_slice()` en `macho_best_slice()` in `<mach-o/utils.h>` beskikbaar. Op Apple Silicon kon `macho_best_slice()` voor macOS 15 verkeerdelik `EBADARCH` teruggee vir 'n uitvoerbare derdeparty-`arm64`-binêre lêer; die API is in macOS 15 reggestel. Gebruik `macho_for_each_slice()` of `lipo -archs` om elke snit te inventariseer, eerder as om 'n mislukte soektog na die beste snit as bewys te beskou dat geen snit kan loop nie.<sup>[[1]](#references)[[7]](#references)</sup>

### Vergelyk kodesignature oor snitte

Elke argitektuur in 'n universele binêre lêer het sy eie CodeDirectory en CDHash. Wanneer jy 'n ondertekende uitvoerbare lêer of geprivilegieerde helper oudit, ondersoek die **signature van elke snit**. 'n Ander CDHash is normaal; vergelyk eerder die ondertekeningsidentiteit, CodeDirectory-vlae en entitlements.<sup>[[8]](#references)</sup>

Vir beleide wat met 'n CDHash ooreenstem, identifiseer een hash slegs een argitektuurspesifieke uitvoeringspad. Apple beveel aan dat jy snitte inventariseer en `codesign --arch` gebruik om elkeen te ondersoek.<sup>[[9]](#references)</sup>

```bash
BIN=/path/to/executable
for A in $(lipo -archs "$BIN"); do
  printf "\n== %s ==\n" "$A"
  codesign -dvvv --arch "$A" "$BIN" 2>&1
  codesign -d --entitlements - --arch "$A" "$BIN"
done
```

Vir die handtekeningstruktuur en valideringsbesonderhede, sien [macOS Code Signing](../macos-security-protections/macos-code-signing.md).

## **Mach-O-kop**

Die kop bevat basiese inligting oor die lêer, soos magiese grepe om dit as ’n Mach-O-lêer te identifiseer en inligting oor die teikenargitektuur. Jy kan dit hier vind: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

Daar is verskillende lêertipes; jy kan hulle byvoorbeeld [**hier in die bronkode vind**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Die belangrikste is:

- `MH_OBJECT`: Herplaasbare objeklêer (tussenprodukte van samestelling, nog nie uitvoerbare lêers nie).
- `MH_EXECUTE`: Uitvoerbare lêers.
- `MH_FVMLIB`: Vaste VM-biblioteeklêer.
- `MH_CORE`: Core dumps
- `MH_PRELOAD`: Voorafgelaaide uitvoerbare lêer (word nie meer in XNU ondersteun nie)
- `MH_DYLIB`: Dinamiese biblioteke
- `MH_DYLINKER`: Dinamiese skakelaar
- `MH_BUNDLE`: "Inprop-lêers". Gegenereer met `-bundle` in gcc en uitdruklik deur `NSBundle` of `dlopen` gelaai.
- `MH_DSYM`: Gepaardgaande `.dSYM`-lêer (lêer met simbole vir ontfouting).
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

Die bronkode definieer ook verskeie vlae wat nuttig is om libraries te laai:

- `MH_NOUNDEFS`: Geen ongedefinieerde verwysings nie (volledig gekoppel)
- `MH_DYLDLINK`: Dyld-koppeling
- `MH_PREBOUND`: Dinamiese verwysings is vooraf gekoppel.
- `MH_SPLIT_SEGS`: Lêer verdeel leesalleen- en lees/skryf-segmente.
- `MH_WEAK_DEFINES`: Binêre lêer het swak gedefinieerde simbole
- `MH_BINDS_TO_WEAK`: Binêre lêer gebruik swak simbole
- `MH_ALLOW_STACK_EXECUTION`: Maak die stack uitvoerbaar
- `MH_NO_REEXPORTED_DYLIBS`: Library het geen LC_REEXPORT-opdragte nie
- `MH_PIE`: Posisie-onafhanklike uitvoerbare lêer
- `MH_HAS_TLV_DESCRIPTORS`: Daar is ’n afdeling met thread-lokale veranderlikes
- `MH_NO_HEAP_EXECUTION`: Geen uitvoering vir heap-/databladsye nie
- `MH_HAS_OBJC`: Binêre lêer het Objective-C-afdelings
- `MH_SIM_SUPPORT`: Simulator-ondersteuning
- `MH_DYLIB_IN_CACHE`: Word op dylibs/frameworks in die gedeelde library-cache gebruik.

## **Mach-O-laaikommando's**

Die **lêer se uitleg in die geheue** word hier gespesifiseer, met besonderhede oor die **simbooltabel se ligging**, die konteks van die hoofdraad wanneer uitvoering begin, en die vereiste **gedeelde libraries**. Instruksies word aan die dynamic loader **(dyld)** gegee oor die proses om die binêre lêer in die geheue te laai.

Dit gebruik die **load_command**-struktuur, wat in die genoemde **`loader.h`** gedefinieer word:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Daar is ongeveer **50 verskillende tipes laaikommando’s** wat die stelsel op verskillende maniere hanteer. Die algemeenste is: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` en `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Basies definieer hierdie tipe laaikommando **hoe om die \_\_TEXT** (uitvoerbare kode) **en \_\_DATA** (data vir die proses) **segmente te laai** volgens die **offsets wat in die Data-afdeling aangedui word** wanneer die binêre lêer uitgevoer word.

Hierdie opdragte **definieer segmente** wat in die **virtuele geheuespasie** van ’n proses **gekoppel** word wanneer dit uitgevoer word.

Daar is **verskillende tipes** segmente, soos die **\_\_TEXT**-segment, wat die uitvoerbare kode van ’n program bevat, en die **\_\_DATA**-segment, wat data bevat wat deur die proses gebruik word. Hierdie **segmente is in die data-afdeling** van die Mach-O-lêer geleë.

**Elke segment** kan verder in verskeie **afdelings verdeel** word. Die **struktuur van die laaikommando** bevat **inligting** oor **hierdie afdelings** binne die onderskeie segment.

In die kopstuk verskyn die **segmentkopstuk** eerste:

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

Voorbeeld van **seksieopskrif**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

As jy die **seksie-offset** (0x37DC) by die **offset** voeg waar die **argitektuur begin**, in hierdie geval `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Dit is ook moontlik om **kopinligting** vanaf die **command line** te kry met:

```bash
otool -lv /bin/ls
```

Algemene segmente wat deur hierdie opdrag gelaai word:

- **`__PAGEZERO`:** Dit gee die kernel opdrag om die **nuladres te karteer** sodat dit **nie gelees, geskryf of uitgevoer kan word nie**. Die maxprot- en minprot-veranderlikes in die struktuur word op nul gestel om aan te dui dat daar **geen lees-, skryf- of uitvoerregte op hierdie bladsy is nie**.
  - Hierdie toewysing is belangrik om **NULL pointer dereference-kwesbaarhede te versag**. Dit is omdat XNU ’n harde nulbladsy afdwing wat verseker dat die eerste geheuebladsy (net die eerste een) ontoeganklik is (behalwe in i386). ’n Binêre lêer kan aan hierdie vereistes voldoen deur ’n klein \_\_PAGEZERO te skep (met `-pagezero_size`) wat die eerste 4k dek, terwyl die res van die 32-bis-geheue in beide gebruikers- en kernelmodus toeganklik is.
- **`__TEXT`**: Bevat **uitvoerbare** **kode** met **lees-** en **uitvoerregte** (nie skryfbaar nie)**.** Algemene afdelings in hierdie segment:
  - `__text`: Gekompileerde binêre kode
  - `__const`: Konstante data (leesalleen)
  - `__[c/u/os_log]string`: C-, Unicode- of os-logstringkonstantes
  - `__stubs` en `__stubs_helper`: Betrokke tydens die laai van dinamiese biblioteke
  - `__unwind_info`: Stack unwind-data.
  - Let daarop dat al hierdie inhoud onderteken is, maar ook as uitvoerbaar gemerk is (wat meer uitbuitingsmoontlikhede skep vir afdelings wat nie noodwendig hierdie voorreg nodig het nie, soos afdelings wat spesifiek vir stringe bedoel is).
- **`__DATA`**: Bevat data wat **leesbaar** en **skryfbaar** is (nie uitvoerbaar nie)**.**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Nie-lui (bind tydens laai) simboolwyser
  - `__la_symbol_ptr`: Lui (bind wanneer dit gebruik word) simboolwyser
  - `__const`: Behoort leesalleendata te wees (maar is dit nie regtig nie)
  - `__cfstring`: CoreFoundation-stringe
  - `__data`: Globale veranderlikes (wat geïnitialiseer is)
  - `__bss`: Statiese veranderlikes (wat nie geïnitialiseer is nie)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, ens.): Inligting wat deur die Objective-C-runtime gebruik word
- **`__DATA_CONST`**: \_\_DATA.\_\_const is nie gewaarborg om konstant te wees nie (skryftoestemmings), en dieselfde geld vir ander wysers en die GOT. Hierdie afdeling maak `__const`, sommige initialiseerders en die GOT-tabel (sodra dit opgelos is) **leesalleen** met behulp van `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Kom algemeen voor in onlangse Apple Silicon-binêre lêers. Hierdie segmente bevat wysers wat tydens laai of gebruik geverifieer moet word (byvoorbeeld `__auth_got`). As ’n rebinding-, hook- of import-patching-truuk net die verouderde `__got` / `__la_symbol_ptr`-afdelings nagaan, kan dit die werklike oproeppunte in moderne `arm64e`-binêre lêers miskyk. Vir meer besonderhede oor hierdie afdelings, raadpleeg [hierdie bladsy](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Bevat inligting vir die linker (dyld), soos simbool-, string- en hervestigingstabelinskrywings. Dit is ’n generiese houer vir inhoud wat nie in `__TEXT` of `__DATA` is nie, en die inhoud daarvan word in ander laaikommando’s beskryf.
  - dyld-inligting: Rebase-, non-lazy/lazy/weak-binding-opcodes en uitvoerinligting
  - Funksiebeginsels: Tabel met beginadresse van funksies
  - Data In Code: Data-eilande in \_\_text
  - Simbooltabel: Simbole in die binêre lêer
  - Indirekte simbooltabel: Wyser-/stub-simbole
  - Stringtabel
  - Kodesignatuur
- **`__OBJC`**: Bevat inligting wat deur die Objective-C-runtime gebruik word. Hierdie inligting kan egter ook in die \_\_DATA-segment gevind word, binne verskeie \_\_objc\_\*-afdelings.
- **`__RESTRICT`**: ’n Segment sonder inhoud, met ’n enkele afdeling genaamd **`__restrict`** (ook leeg), wat verseker dat DYLD-omgewingsveranderlikes geïgnoreer word wanneer die binêre lêer uitgevoer word.

Soos in die kode gesien kon word, **ondersteun segmente ook vlae** (hoewel dit nie baie gebruik word nie):

- `SG_HIGHVM`: Slegs core (nie gebruik nie)
- `SG_FVMLIB`: Nie gebruik nie
- `SG_NORELOC`: Segment het geen hervestiging nie
- `SG_PROTECTED_VERSION_1`: Enkripsie. Word byvoorbeeld deur Finder gebruik om die tekssegment `__TEXT` te enkripteer.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** bevat die ingangspunt in die **entryoff-kenmerk.** Tydens laai **tel** **dyld** hierdie waarde eenvoudig **by** die (in-geheue-)**basis van die binêre lêer** **by**, en **spring** dan na hierdie instruksie om die uitvoering van die binêre lêer se kode te begin.

**`LC_UNIXTHREAD`** bevat die waardes wat die registers moet hê wanneer die hooftoepassing begin. Dit is reeds verouderd, maar **`dyld`** gebruik dit steeds. Dit is moontlik om die registerwaardes te sien wat hierdeur gestel word met:

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


Bevat inligting oor die **code signature van die Mach-O-lêer**. Dit bevat slegs ’n **offset** wat na die **signature blob** **wys**. Dit is gewoonlik heel aan die einde van die lêer.\
Jy kan meer inligting oor hierdie afdeling vind in [**hierdie blogplasing**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) en [**hierdie gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Ondersteuning vir binary encryption. As ’n aanvaller egter daarin slaag om die proses te kompromitteer, sal hy die geheue ongeënkripteer kan dump.

### **`LC_LOAD_DYLINKER`**

Bevat die **pad na die dynamic linker-uitvoerbare lêer** wat shared libraries in die proses se address space karteer. Die **waarde is altyd op `/usr/lib/dyld` gestel**. Dit is belangrik om daarop te let dat dylib-karteerwerk in macOS in **user mode** plaasvind, nie in kernel mode nie.

### **`LC_IDENT`**

Verouderd, maar wanneer dit ingestel is om dumps tydens ’n panic te genereer, word ’n Mach-O core dump geskep en die kernel-weergawe word in die `LC_IDENT`-opdrag gestel.

### **`LC_UUID`**

Willekeurige UUID. Dit is nie direk vir enigiets nuttig nie, maar XNU kas dit saam met die res van die prosesinligting. Dit kan in crash reports gebruik word.

### **`LC_BUILD_VERSION`**

Moderne binaries bevat gewoonlik hierdie opdrag om die **target platform**, **minimum OS-weergawe**, **SDK-weergawe** en opsioneel die **tool-weergawes** wat gebruik is om daardie slice te bou, aan te dui. Vanuit ’n offensive/reversing-perspektief is dit baie nuttig om vas te stel hoe ’n sample gebou is en om vinnig ongewone universal binaries raak te sien waar een slice met ’n ander SDK of deployment target saamgestel is. Ouer binaries kan steeds `LC_VERSION_MIN_*` gebruik.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Laat toe dat omgewingsveranderlikes aan dyld aangedui word voordat die proses uitgevoer word. Dit kan baie gevaarlik wees, aangesien dit arbitrêre kode binne die proses kan laat loop. Daarom word hierdie load command slegs gebruik in dyld-builds met `#define SUPPORT_LC_DYLD_ENVIRONMENT`, en word verwerking verder beperk tot veranderlikes van die vorm `DYLD_..._PATH` wat load paths spesifiseer.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Onlangse toolchains stoor export-/bind-/rebase-metadata dikwels in hierdie commands, eerder as om slegs op die ouer `LC_DYLD_INFO[_ONLY]`-opcodes staat te maak. Albei is `linkedit_data_command`-inskrywings wat na **`__LINKEDIT`** wys:

- **`LC_DYLD_EXPORTS_TRIE`**: Kompakte trie met die simbole wat deur die image geëksporteer word.
- **`LC_DYLD_CHAINED_FIXUPS`**: Fixup-kettings per segment wat dyld gebruik om rebases en binds toe te pas. Op Apple Silicon sal jy ook baie moderne authenticated pointer-fixups hier teëkom.

Hierdie metadata is baie nuttig wanneer jy imports/exports rekonstrueer, verstaan waarom ’n `@rpath`-gelaaide dependency op ’n sekere manier opgelos is, of uitvind waarom ’n hook/rebinding-poging op ’n moderne `arm64e`-teiken misluk het. `dyld_info` kan ook gebruik word op **cache-only dylib paths** wat nie as selfstandige lêers op skyf bestaan nie. Dit is baie nuttig op moderne macOS, waar baie stelselbiblioteke slegs in die shared cache voorkom.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Hierdie moderne load command is hoofsaaklik relevant wanneer **kernel collections / kernelcache-style filesets** geïnspekteer word. In plaas daarvan om ’n enkele selfstandige image voor te stel, dien die buitenste Mach-O as ’n houer, en elke `LC_FILESET_ENTRY` verwys na ’n ingebedde Mach-O met sy eie padagtige **entry id**, VM-adres en lêeroffset. As jy moderne macOS/iOS-kernelkomponente reverse-engineer, vorm hierdie command dikwels die skakel tussen die boonstevlak-houer en die werklike image wat jy wil onttrek of disassemble.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Vir praktiese onttrekkingswerkvloeie, raadpleeg [hierdie ander bladsy oor macOS-kernuitbreidings en kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Hierdie laa opdrag beskryf ’n **dinamiese** **biblioteek**-afhanklikheid wat die **laaier** (dyld) **opdrag gee om genoemde biblioteek te laai en te skakel**. Daar is ’n `LC_LOAD_DYLIB`-laa opdrag **vir elke biblioteek** wat die Mach-O-binêre lêer benodig.

- Hierdie laai-opdrag is ’n struktuur van tipe **`dylib_command`** (wat ’n struct dylib bevat wat die werklike afhanklike dinamiese biblioteek beskryf):

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

Sommige moontlike wanwareverwante biblioteke is:

- **DiskArbitration**: Monitering van USB-aandrywers
- **AVFoundation:** Neem oudio en video op
- **CoreWLAN**: Wi-Fi-skanderings.

> [!TIP]
> ’n Mach-O-binêre lêer kan een of **meer** **konstruktors** bevat, wat **uitgevoer** word **voordat** die adres wat in **LC_MAIN** gespesifiseer word.\
> Die offsets van enige konstruktors word in die **\_\_mod_init_func**-afdeling van die **\_\_DATA_CONST**-segment gehou.

## **Mach-O-data**

Die data-area lê in die kern van die lêer en bestaan uit verskeie segmente soos in die load commands-area gedefinieer. **’n Verskeidenheid data-afdelings kan in elke segment gehuisves word**, met elke afdeling wat **kode of data bevat** wat spesifiek vir ’n tipe is.

> [!TIP]
> Die data is basies die deel wat al die **inligting** bevat wat deur die load command **LC_SEGMENTS_64** gelaai word

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Dit sluit in:

- **Funksietabel:** Bevat inligting oor die program se funksies.
- **Simbooltabel**: Bevat inligting oor die eksterne funksie wat deur die binêre lêer gebruik word.
- Dit kan ook interne funksies, veranderlikename en meer bevat.

Om dit na te gaan, kan jy die [**Mach-O View**](https://sourceforge.net/projects/machoview/) -nutsding gebruik:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Of vanaf die cli:

```bash
size -m /bin/ls
```

### Aangehegte data en omgekeerd geparseerde oorlegsels

’n Loader kan konfigurasie in aangehegte data hou in plaas van in ’n benoemde Mach-O-afdeling. ’n Omgekeerde parser anker hom dan op ’n eindmerker, lees ’n grootte wat onmiddellik daarvoor gestoor is en gebruik daardie waarde om die voorafgaande blob op te spoor en te dekripteer. Een waargenome universele loader het hierdie uitleg vir ’n XOR-geënkripteerde downloader-URL gebruik:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Wanneer jy ’n onbekende binary reverse-engineer, inspekteer die bytes rondom herkenbare eindmerkers en volg elke terugwaartse grootteberekening voordat jy aanneem dat stringe of konfigurasie by ’n load-command-afdeling moet hoort. Die merker en XOR-sleutel is spesifiek vir die sample; die herbruikbare tegniek is die selfbeskrywende trailer.

## Algemene Objective-C-afdelings

In die `__TEXT`-segment (r-x):

- `__objc_classname`: Klasname (stringe)
- `__objc_methname`: Metodename (stringe)
- `__objc_methtype`: Metodetipes (stringe)

In die `__DATA`-segment (rw-):

- `__objc_classlist`: Pointers na alle Objective-C-klasse
- `__objc_nlclslist`: Pointers na Non-Lazy Objective-C-klasse
- `__objc_catlist`: Pointer na Categories
- `__objc_nlcatlist`: Pointers na Non-Lazy Categories
- `__objc_protolist`: Protokollelys
- `__objc_const`: Konstante data
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

Sien ook: [Reflective Mach-O Loading](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [1] [Mach-O-slices is nie so eenvoudig soos jy dalk dink nie](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1)-manblad](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Lees jou eie Entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source - Mach-O `fat.h` en `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - ’n Nuwe weergawe van die MacSync macOS-stealer teiken kripto-entoesiaste en ontwikkelaars](https://securelist.com/macsync-new-version/121383/)
- [7] [The Art of Mac Malware, Volume 2 — Ontleding van binaries](https://taomm.org/vol2/pdfs/CH%202%20Parsing%20Binaries.pdf)
- [8] [Apple Developer — TN3126: Binne Code Signing: Hashes](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes.md)
- [9] [Apple Developer — Programme en binaries toelaat en weier](https://developer.apple.com/documentation/devicemanagement/allowing-and-denying-apps-and-binaries.md)
{{#include ../../../banners/hacktricks-training.md}}
