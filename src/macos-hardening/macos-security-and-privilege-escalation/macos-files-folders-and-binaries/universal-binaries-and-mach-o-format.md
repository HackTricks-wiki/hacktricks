# macOS Universele binêre & Mach-O Formaat

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Mac OS binêre word gewoonlik saamgekompileer as **universele binêre**. 'n **universale binêre** kan **meerdere argitekture in dieselfde lêer ondersteun**.

Hierdie binêre volg die **Mach-O struktuur** wat basies bestaan uit:

- Kop
- Laai Opdragte
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Vet Kop

Soek vir die lêer met: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC of FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* aantal strukture wat volg */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* cpu spesifiseerder (int) */
cpu_subtype_t	cpusubtype;	/* masjien spesifiseerder (int) */
uint32_t	offset;		/* lêer offset na hierdie objek lêer */
uint32_t	size;		/* grootte van hierdie objek lêer */
uint32_t	align;		/* uitlijning as 'n mag van 2 */
};
</code></pre>

Die kop het die **magiese** bytes gevolg deur die **aantal** **argitekture** wat die lêer **bevat** (`nfat_arch`) en elke argitektuur sal 'n `fat_arch` struktuur hê.

Kontroleer dit met:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universele binêre met 2 argitekture: [x86_64:Mach-O 64-bit uitvoerbare x86_64] [arm64e:Mach-O 64-bit uitvoerbare arm64e]
/bin/ls (vir argitektuur x86_64):	Mach-O 64-bit uitvoerbare x86_64
/bin/ls (vir argitektuur arm64e):	Mach-O 64-bit uitvoerbare arm64e

% otool -f -v /bin/ls
Vet koppe
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>argitektuur x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    offset 16384
</strong><strong>    grootte 72896
</strong>    uitlijning 2^14 (16384)
<strong>argitektuur arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    grootte 88816
</strong>    uitlijning 2^14 (16384)
</code></pre>

of deur die [Mach-O View](https://sourceforge.net/projects/machoview/) hulpmiddel te gebruik:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Soos jy dalk dink, verdubbel 'n universele binêre wat saamgekompileer is vir 2 argitekture gewoonlik die grootte van een wat net vir 1 argitektuur saamgekompileer is.

## **Mach-O Kop**

Die kop bevat basiese inligting oor die lêer, soos magiese bytes om dit as 'n Mach-O lêer te identifiseer en inligting oor die teikenargitektuur. Jy kan dit vind in: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Daar is verskillende lêertipes, jy kan hulle gedefinieer vind in die [**bronkode byvoorbeeld hier**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Die belangrikste is:

- `MH_OBJECT`: Herlokasiebare objeklêer (tussenprodukte van kompilasie, nog nie uitvoerbaar nie).
- `MH_EXECUTE`: Uitvoerbare lêers.
- `MH_FVMLIB`: Vaste VM-biblioteeklêer.
- `MH_CORE`: Kode-dumps
- `MH_PRELOAD`: Vooraf gelaaide uitvoerbare lêer (nie meer ondersteun in XNU nie)
- `MH_DYLIB`: Dinamiese biblioteke
- `MH_DYLINKER`: Dinamiese skakelaar
- `MH_BUNDLE`: "Pluginlêers". Genereer met -bundle in gcc en eksplisiet gelaai deur `NSBundle` of `dlopen`.
- `MH_DYSM`: Metgesel `.dSym` lêer (lêer met simbole vir foutopsporing).
- `MH_KEXT_BUNDLE`: Kernel-uitbreidings.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Of deur [Mach-O View](https://sourceforge.net/projects/machoview/) te gebruik:

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Vlaggies**

Die bronkode definieer ook verskeie vlaggies wat nuttig is vir die laai van biblioteke:

- `MH_NOUNDEFS`: Geen ongedefinieerde verwysings nie (volledig gekoppel)
- `MH_DYLDLINK`: Dyld-koppeling
- `MH_PREBOUND`: Dinamiese verwysings vooraf gekoppel.
- `MH_SPLIT_SEGS`: Lêer verdeel r/o en r/w segmente.
- `MH_WEAK_DEFINES`: Binêre het swak gedefinieerde simbole
- `MH_BINDS_TO_WEAK`: Binêre gebruik swak simbole
- `MH_ALLOW_STACK_EXECUTION`: Maak die stapel uitvoerbaar
- `MH_NO_REEXPORTED_DYLIBS`: Biblioteek het nie LC_REEXPORT opdragte nie
- `MH_PIE`: Posisie Onafhanklike Uitvoerbare
- `MH_HAS_TLV_DESCRIPTORS`: Daar is 'n afdeling met draad plaaslike veranderlikes
- `MH_NO_HEAP_EXECUTION`: Geen uitvoering vir heap/data bladsye nie
- `MH_HAS_OBJC`: Binêre het oBject-C afdelings
- `MH_SIM_SUPPORT`: Simulator ondersteuning
- `MH_DYLIB_IN_CACHE`: Gebruik op dylibs/raamwerke in gedeelde biblioteek kas.

## **Mach-O Laai opdragte**

Die **lêer se uitleg in geheue** word hier gespesifiseer, wat die **simbol tabel se ligging**, die konteks van die hoofdraad by uitvoering begin, en die vereiste **gedeelde biblioteke** detail. Instruksies word aan die dinamiese laaier **(dyld)** gegee oor die binêre se laai proses in geheue.

Die gebruik die **load_command** struktuur, gedefinieer in die genoemde **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Daar is ongeveer **50 verskillende tipes laaiopdragte** wat die stelsel anders hanteer. Die mees algemene is: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, en `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Basies definieer hierdie tipe Laaiopdrag **hoe om die \_\_TEXT** (uitvoerbare kode) **en \_\_DATA** (data vir die proses) **segmente** te laai volgens die **offsets wat in die Data afdeling aangedui word** wanneer die binêre uitgevoer word.

Hierdie opdragte **definieer segmente** wat in die **virtuele geheue ruimte** van 'n proses gemap word wanneer dit uitgevoer word.

Daar is **verskillende tipes** segmente, soos die **\_\_TEXT** segment, wat die uitvoerbare kode van 'n program bevat, en die **\_\_DATA** segment, wat data bevat wat deur die proses gebruik word. Hierdie **segmente is geleë in die data afdeling** van die Mach-O lêer.

**Elke segment** kan verder in meerdere **afdelings** **verdeeld** word. Die **laaiopdragstruktuur** bevat **inligting** oor **hierdie afdelings** binne die onderskeie segment.

In die kop vind jy eers die **segmentkop**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* vir 64-bis argitekture */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* sluit sizeof section_64 strukture in */
char		segname[16];	/* segmentnaam */
uint64_t	vmaddr;		/* geheueadres van hierdie segment */
uint64_t	vmsize;		/* geheuegrootte van hierdie segment */
uint64_t	fileoff;	/* lêer offset van hierdie segment */
uint64_t	filesize;	/* hoeveelheid om van die lêer te map */
int32_t		maxprot;	/* maksimum VM beskerming */
int32_t		initprot;	/* aanvanklike VM beskerming */
<strong>	uint32_t	nsects;		/* aantal afdelings in segment */
</strong>	uint32_t	flags;		/* vlae */
};
</code></pre>

Voorbeeld van segmentkop:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Hierdie kop definieer die **aantal afdelings waarvan die koppe na** dit verskyn:
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
Voorbeeld van **afdelingskop**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

As jy die **afdelingsoffset** (0x37DC) + die **offset** waar die **arch begin**, in hierdie geval `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Dit is ook moontlik om **kopinligting** van die **opdraglyn** te verkry met:
```bash
otool -lv /bin/ls
```
Algemene segmente wat deur hierdie cmd gelaai word:

- **`__PAGEZERO`:** Dit gee die kernel opdrag om die **adres nul** te **kaart**, sodat dit **nie gelees, geskryf of uitgevoer kan word** nie. Die maxprot en minprot veranderlikes in die struktuur is op nul gestel om aan te dui dat daar **geen lees-skrif-uitvoer regte op hierdie bladsy is** nie.
- Hierdie toewysing is belangrik om **NULL pointer dereference kwesbaarhede te verminder**. Dit is omdat XNU 'n harde bladsy nul afdwing wat verseker dat die eerste bladsy (slegs die eerste) van geheue ontoeganklik is (behalwe in i386). 'n Binêre kan aan hierdie vereistes voldoen deur 'n klein \_\_PAGEZERO te skep (met die `-pagezero_size`) om die eerste 4k te dek en die res van die 32-bit geheue in beide gebruiker- en kernelmodus toeganklik te hê.
- **`__TEXT`**: Bevat **uitvoerbare** **kode** met **lees** en **uitvoer** toestemmings (geen skryfbare)**.** Algemene afdelings van hierdie segment:
- `__text`: Gecompileerde binêre kode
- `__const`: Konstant data (slegs lees)
- `__[c/u/os_log]string`: C, Unicode of os logs string konstantes
- `__stubs` en `__stubs_helper`: Betrokke tydens die dinamiese biblioteek laai proses
- `__unwind_info`: Stapel ontrafel data.
- Let daarop dat al hierdie inhoud onderteken is, maar ook as uitvoerbaar gemerk is (wat meer opsies vir die uitbuiting van afdelings skep wat nie noodwendig hierdie voorreg benodig nie, soos string toegewyde afdelings).
- **`__DATA`**: Bevat data wat **leesbaar** en **skryfbaar** is (geen uitvoerbare)**.**
- `__got:` Globale Offset Tabel
- `__nl_symbol_ptr`: Nie lui (bind by laai) simbool pointer
- `__la_symbol_ptr`: Lui (bind by gebruik) simbool pointer
- `__const`: Moet slegs leesbare data wees (nie regtig nie)
- `__cfstring`: CoreFoundation strings
- `__data`: Globale veranderlikes (wat geinitialiseer is)
- `__bss`: Statiese veranderlikes (wat nie geinitialiseer is nie)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, ens): Inligting wat deur die Objective-C runtime gebruik word
- **`__DATA_CONST`**: \_\_DATA.\_\_const is nie gewaarborg om konstant te wees nie (skryf toestemmings), en ander pointers en die GOT ook nie. Hierdie afdeling maak `__const`, sommige inisialisators en die GOT tabel (sodra dit opgelos is) **slegs lees** met behulp van `mprotect`.
- **`__LINKEDIT`**: Bevat inligting vir die linker (dyld) soos simbool, string, en herlokasie tabel inskrywings. Dit is 'n generiese houer vir inhoud wat nie in `__TEXT` of `__DATA` is nie en sy inhoud word in ander laaiopdragte beskryf.
- dyld inligting: Rebase, Nie-lui/lui/swak binding opcodes en uitvoer info
- Funksies begin: Tabel van begin adresse van funksies
- Data In Kode: Data-eilande in \_\_text
- Simbool Tabel: Simbole in binêre
- Indirekte Simbool Tabel: Pointer/stub simbole
- String Tabel
- Kode Handtekening
- **`__OBJC`**: Bevat inligting wat deur die Objective-C runtime gebruik word. Alhoewel hierdie inligting ook in die \_\_DATA segment gevind kan word, binne verskeie in \_\_objc\_\* afdelings.
- **`__RESTRICT`**: 'n Segment sonder inhoud met 'n enkele afdeling genaamd **`__restrict`** (ook leeg) wat verseker dat wanneer die binêre uitgevoer word, dit DYLD omgewingsveranderlikes sal ignoreer.

Soos dit moontlik was om in die kode te sien, **ondersteun segmente ook vlae** (alhoewel hulle nie baie gebruik word nie):

- `SG_HIGHVM`: Slegs kern (nie gebruik nie)
- `SG_FVMLIB`: Nie gebruik nie
- `SG_NORELOC`: Segment het geen herlokasie nie
- `SG_PROTECTED_VERSION_1`: Enkripsie. Gebruik byvoorbeeld deur Finder om teks in die `__TEXT` segment te enkripteer.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** bevat die toegangspunt in die **entryoff attribuut.** Tydens laai, **dyld** voeg eenvoudig **hierdie waarde** by die (in-geheue) **basis van die binêre**, dan **spring** dit na hierdie instruksie om die uitvoering van die binêre se kode te begin.

**`LC_UNIXTHREAD`** bevat die waardes wat die register moet hê wanneer die hoofdraad begin. Dit is reeds verouderd, maar **`dyld`** gebruik dit steeds. Dit is moontlik om die waardes van die registers wat deur hierdie gestel is, te sien met:
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

Bevat inligting oor die **kodehandtekening van die Macho-O lêer**. Dit bevat slegs 'n **offset** wat na die **handtekening blob** **wys**. Dit is tipies aan die einde van die lêer.\
U kan egter 'n paar inligting oor hierdie afdeling vind in [**hierdie blogpos**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) en hierdie [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Ondersteuning vir binêre versleuteling. Dit gesê, as 'n aanvaller daarin slaag om die proses te kompromitteer, sal hy in staat wees om die geheue onversleuteld te dump.

### **`LC_LOAD_DYLINKER`**

Bevat die **pad na die dinamiese linker uitvoerbare lêer** wat gedeelde biblioteke in die prosesadresruimte in kaart bring. Die **waarde is altyd ingestel op `/usr/lib/dyld`**. Dit is belangrik om te noem dat in macOS, dylib-mapping in **gebruikermodus** plaasvind, nie in kernmodus nie.

### **`LC_IDENT`**

Verouderd, maar wanneer dit gekonfigureer is om dumps op paniek te genereer, word 'n Mach-O kern dump geskep en die kern weergawe word in die `LC_IDENT` opdrag ingestel.

### **`LC_UUID`**

Ewekansige UUID. Dit is nuttig vir enigiets direk, maar XNU kas dit saam met die res van die prosesinligting. Dit kan in ongelukverslae gebruik word.

### **`LC_DYLD_ENVIRONMENT`**

Stel in staat om omgewingsveranderlikes aan die dyld aan te dui voordat die proses uitgevoer word. Dit kan baie gevaarlik wees aangesien dit die uitvoering van arbitrêre kode binne die proses kan toelaat, so hierdie laaiopdrag word slegs in dyld-bou met `#define SUPPORT_LC_DYLD_ENVIRONMENT` gebruik en beperk die verwerking verder slegs tot veranderlikes van die vorm `DYLD_..._PATH` wat laai-pade spesifiseer.

### **`LC_LOAD_DYLIB`**

Hierdie laaiopdrag beskryf 'n **dinamiese** **biblioteek** afhanklikheid wat die **laaier** (dyld) **instrueer** om die **gesê biblioteek te laai en te koppel**. Daar is 'n `LC_LOAD_DYLIB` laaiopdrag **vir elke biblioteek** wat die Mach-O binêre benodig.

- Hierdie laaiopdrag is 'n struktuur van tipe **`dylib_command`** (wat 'n struktuur dylib bevat, wat die werklike afhanklike dinamiese biblioteek beskryf):
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

Jy kan ook hierdie inligting van die cli kry met:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Sommige potensiële malware-verwante biblioteke is:

- **DiskArbitration**: Monitering van USB skywe
- **AVFoundation:** Opname van audio en video
- **CoreWLAN**: Wifi skandeer.

> [!NOTE]
> 'n Mach-O binêre kan een of **meer** **konstruktore** bevat, wat **uitgevoer** sal word **voor** die adres wat in **LC_MAIN** gespesifiseer is.\
> Die offsets van enige konstruktore word in die **\_\_mod_init_func** afdeling van die **\_\_DATA_CONST** segment gehou.

## **Mach-O Data**

In die kern van die lêer lê die datastreek, wat uit verskeie segmente bestaan soos gedefinieer in die laai-opdragte streek. **'n Verskeidenheid dataseksies kan binne elke segment gehuisves word**, met elke afdeling **wat kode of data** spesifiek vir 'n tipe hou.

> [!TIP]
> Die data is basies die deel wat al die **inligting** bevat wat deur die laai-opdragte **LC_SEGMENTS_64** gelaai word.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Dit sluit in:

- **Funksietabel:** Wat inligting oor die programfunksies hou.
- **Simboltabel**: Wat inligting bevat oor die eksterne funksie wat deur die binêre gebruik word
- Dit kan ook interne funksie, veranderlike name sowel as meer bevat.

Om dit te kontroleer kan jy die [**Mach-O View**](https://sourceforge.net/projects/machoview/) hulpmiddel gebruik:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Of vanaf die cli:
```bash
size -m /bin/ls
```
## Objetive-C Algemene Afdelings

In `__TEXT` segment (r-x):

- `__objc_classname`: Klasname (strings)
- `__objc_methname`: Metode name (strings)
- `__objc_methtype`: Metode tipes (strings)

In `__DATA` segment (rw-):

- `__objc_classlist`: Pointers na alle Objetive-C klasse
- `__objc_nlclslist`: Pointers na Non-Lazy Objective-C klasse
- `__objc_catlist`: Pointer na Kategories
- `__objc_nlcatlist`: Pointer na Non-Lazy Kategories
- `__objc_protolist`: Protokolle lys
- `__objc_const`: Konstant data
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
