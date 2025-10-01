# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Mac OS binaries werden normalerweise als **universal binaries** kompiliert. Eine **universal binary** kann **mehrere Architekturen in derselben Datei unterstützen**.

Diese binaries folgen der **Mach-O-Struktur**, die im Wesentlichen aus folgenden Teilen besteht:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat-Header

Nach der Datei suchen mit: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Der Header enthält die **magic**-Bytes, gefolgt von der **Anzahl** der **archs**, die die Datei **enthält** (`nfat_arch`), und jede arch hat eine `fat_arch`-Struktur.

Prüfe das mit:

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

oder mit dem Tool [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Wie du dir vielleicht denkst, verdoppelt eine universal binary, die für 2 Architekturen kompiliert wurde, in der Regel die Größe im Vergleich zu einer, die nur für eine Arch kompiliert wurde.

## **Mach-O-Header**

Der Header enthält grundlegende Informationen über die Datei, wie z. B. magic-Bytes zur Identifikation als Mach-O-Datei und Informationen über die Zielarchitektur. Du findest ihn unter: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O-Dateitypen

Es gibt verschiedene Dateitypen; sie sind im [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) definiert. Die wichtigsten sind:

- `MH_OBJECT`: Relokierbare Objektdatei (Zwischenprodukt der Kompilierung, noch keine ausführbare Datei).
- `MH_EXECUTE`: Ausführbare Dateien.
- `MH_FVMLIB`: Fixed-VM-Bibliotheksdatei.
- `MH_CORE`: Core-Dumps
- `MH_PRELOAD`: Vorausgeladene ausführbare Datei (wird in XNU nicht mehr unterstützt)
- `MH_DYLIB`: Dynamische Bibliotheken
- `MH_DYLINKER`: Dynamischer Linker
- `MH_BUNDLE`: "Plugin-Dateien". Erzeugt mit -bundle in gcc und explizit geladen durch `NSBundle` oder `dlopen`.
- `MH_DYSM`: Begleitende `.dSym`-Datei (Datei mit Symbolen für das Debugging).
- `MH_KEXT_BUNDLE`: Kernel-Erweiterungen.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Oder mit [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O-Flags**

Der Quellcode definiert außerdem mehrere Flags, die beim Laden von Libraries nützlich sind:

- `MH_NOUNDEFS`: Keine undefinierten Referenzen (fully linked)
- `MH_DYLDLINK`: Dyld-Linking
- `MH_PREBOUND`: Dynamische Referenzen vorgebunden.
- `MH_SPLIT_SEGS`: Datei teilt r/o- und r/w-Segmente.
- `MH_WEAK_DEFINES`: Binary hat schwach definierte Symbole
- `MH_BINDS_TO_WEAK`: Binary verwendet schwache Symbole
- `MH_ALLOW_STACK_EXECUTION`: Macht den Stack ausführbar
- `MH_NO_REEXPORTED_DYLIBS`: Library hat keine LC_REEXPORT-Kommandos
- `MH_PIE`: Positionsunabhängiges ausführbares Programm (PIE)
- `MH_HAS_TLV_DESCRIPTORS`: Es gibt einen Abschnitt mit thread-localen Variablen
- `MH_NO_HEAP_EXECUTION`: Keine Ausführung für Heap-/Daten-Seiten
- `MH_HAS_OBJC`: Binary hat Objective-C-Abschnitte
- `MH_SIM_SUPPORT`: Simulator-Unterstützung
- `MH_DYLIB_IN_CACHE`: Wird für dylibs/frameworks im shared library cache verwendet.

## **Mach-O Load commands**

Hier wird das **Speicherlayout der Datei** festgelegt, mit Angaben zur **Position der Symboltabelle**, zum Kontext des Hauptthreads beim Start der Ausführung und zu den benötigten **shared libraries**. Es enthält Anweisungen an den dynamic loader **(dyld)**, wie das Binary in den Speicher geladen werden soll.

Dabei wird die Struktur **load_command** verwendet, definiert in der genannten **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Es gibt etwa **50 verschiedene Typen von Load Commands**, die das System unterschiedlich behandelt. Die gebräuchlichsten sind: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` und `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Im Grunde definiert dieser Typ von Load Command, **wie die __TEXT** (ausführbarer Code) **und die __DATA** (Daten für den Prozess) **Segmente** entsprechend den **Offsets, die im Datenabschnitt angegeben sind**, beim Ausführen des Binaries geladen werden.

Diese Befehle **definieren Segmente**, die beim Ausführen in den **virtuellen Adressraum** eines Prozesses **gemappt** werden.

Es gibt **verschiedene Typen** von Segmenten, wie das **\_\_TEXT**-Segment, das den ausführbaren Code eines Programms enthält, und das **\_\_DATA**-Segment, das die vom Prozess verwendeten Daten enthält. Diese **Segmente befinden sich im Datenabschnitt** der Mach-O-Datei.

**Jedes Segment** kann weiter in mehrere **Sections** unterteilt werden. Die **Load Command-Struktur** enthält **Informationen** über **diese Sections** innerhalb des jeweiligen Segments.

Im Header findet man zuerst den **Segment-Header**:

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

Beispiel für einen Segment-Header:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Dieser Header legt die **Anzahl der Sections fest, deren Header danach erscheinen**:
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
Beispiel für **section header**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Wenn du den **section offset** (0x37DC) + den **offset**, an dem die **arch** beginnt, in diesem Fall `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Man kann **headers information** auch über die **command line** bekommen mit:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** Es veranlasst den Kernel, die Adresse Null abzubilden, sodass von ihr weder gelesen, geschrieben noch ausgeführt werden kann. Die maxprot- und minprot-Variablen in der Struktur sind auf Null gesetzt, um anzuzeigen, dass es auf dieser Seite **keine Lese-/Schreib-/Ausführungsrechte** gibt.
- Diese Allokation ist wichtig, um **NULL-Pointer-Dereferenzierungsschwachstellen** zu mindern. Das liegt daran, dass XNU eine feste Page Zero erzwingt, die sicherstellt, dass die erste Seite (nur die erste) des Speichers unzugänglich ist (außer bei i386). Ein Binary kann diese Anforderung erfüllen, indem es ein kleines __PAGEZERO (mit dem `-pagezero_size`) erstellt, das die ersten 4k abdeckt, und den restlichen 32-Bit-Speicher sowohl im User- als auch im Kernel-Modus zugänglich macht.
- **`__TEXT`**: Enthält ausführbaren **Code** mit **Lese**- und **Ausführungs**rechten (nicht schreibbar). Übliche Sektionen dieses Segments:
- `__text`: Kompilierter Binärcode
- `__const`: Konstante Daten (nur lesbar)
- `__[c/u/os_log]string`: C-, Unicode- oder os-Log-String-Konstanten
- `__stubs` und `__stubs_helper`: Beteiligt am Prozess des dynamischen Ladens von Bibliotheken
- `__unwind_info`: Stack-Unwind-Daten
- Beachte, dass all dieser Inhalt signiert ist, aber auch als ausführbar markiert wird (was mehr Angriffsflächen für Abschnitte schafft, die diese Berechtigung nicht unbedingt benötigen, wie speziell für Strings vorgesehene Sektionen).
- **`__DATA`**: Enthält Daten, die **lesbar** und **beschreibbar** sind (nicht ausführbar).
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Nicht-lazy (bind beim Laden) Symbolzeiger
- `__la_symbol_ptr`: Lazy (bind bei Verwendung) Symbolzeiger
- `__const`: Sollte schreibgeschützte Daten sein (ist es nicht wirklich)
- `__cfstring`: CoreFoundation-Strings
- `__data`: Globale Variablen (die initialisiert wurden)
- `__bss`: Statische Variablen (die nicht initialisiert wurden)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Informationen, die von der Objective-C-Runtime verwendet werden
- **`__DATA_CONST`**: __DATA.__const ist nicht garantiert konstant (Schreibrechte), ebenso wenig wie andere Zeiger und die GOT. Dieser Abschnitt macht `__const`, einige Initialisierer und die GOT-Tabelle (sobald aufgelöst) mit `mprotect` **nur lesbar**.
- **`__LINKEDIT`**: Enthält Informationen für den Linker (dyld), wie Symbol-, String- und Relocation-Tabelleneinträge. Es ist ein generischer Container für Inhalte, die weder in `__TEXT` noch in `__DATA` liegen, und dessen Inhalt in anderen Load-Commands beschrieben wird.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes und Export-Informationen
- Function starts: Tabelle der Startadressen von Funktionen
- Data In Code: Dateninseln in `__text`
- Symbol Table: Symbole im Binary
- Indirect Symbol Table: Pointer/Stub-Symbole
- String Table
- Code Signature
- **`__OBJC`**: Enthält Informationen, die von der Objective-C-Runtime verwendet werden. Diese Informationen können allerdings auch im `__DATA`-Segment innerhalb der verschiedenen `__objc_*`-Sektionen zu finden sein.
- **`__RESTRICT`**: Ein Segment ohne Inhalt mit einer einzelnen Sektion namens **`__restrict`** (ebenfalls leer), das sicherstellt, dass beim Ausführen des Binaries die DYLD-Umgebungsvariablen ignoriert werden.

Wie im Code zu sehen ist, unterstützen **Segmente auch Flags** (obwohl sie nicht sehr oft verwendet werden):

- `SG_HIGHVM`: Core only (not used)
- `SG_FVMLIB`: Not used
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Used for example by Finder to encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** enthält den Entrypoint im **entryoff**-Attribut. Zur Ladezeit addiert **dyld** diesen Wert einfach zur (im Speicher befindlichen) Basis des Binaries und springt dann zu dieser Instruktion, um die Ausführung des Binary-Codes zu starten.

**`LC_UNIXTHREAD`** enthält die Werte, die die Register beim Start des Main-Threads haben müssen. Dies ist bereits veraltet, wird aber von **`dyld`** weiterhin verwendet. Es ist möglich, die durch dieses Kommando gesetzten Registerwerte mit folgendem Befehl zu sehen:
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


Enthält Informationen über die **code signature of the Macho-O file**. Es enthält nur einen **Offset**, der auf den **Signature Blob** zeigt. Dieser befindet sich typischerweise ganz am Ende der Datei.\
Allerdings finden Sie einige Informationen zu diesem Abschnitt in [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) und diesem [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Unterstützt die Verschlüsselung von Binaries. Wenn ein Angreifer jedoch den Prozess kompromittiert, kann er selbstverständlich den Speicher unverschlüsselt dumpen.

### **`LC_LOAD_DYLINKER`**

Enthält den **Pfad zur dynamic linker executable**, die shared libraries in den Adressraum des Prozesses einbindet. Der **Wert ist immer auf `/usr/lib/dyld` gesetzt**. Wichtig ist, dass unter macOS das Mapping von dylibs im **Benutzermodus** (user mode) und nicht im Kernel-Modus erfolgt.

### **`LC_IDENT`**

Obsolet, aber wenn so konfiguriert, dass bei Panic Dumps erzeugt werden, wird ein Mach-O Core-Dump erstellt und die Kernel-Version im `LC_IDENT`-Befehl gesetzt.

### **`LC_UUID`**

Zufällige UUID. Sie ist zwar nicht direkt nützlich, aber XNU cached sie zusammen mit den übrigen Prozessinformationen. Sie kann in Crash-Reports verwendet werden.

### **`LC_DYLD_ENVIRONMENT`**

Ermöglicht es, dem dyld Umgebungsvariablen anzugeben, bevor der Prozess ausgeführt wird. Das kann sehr gefährlich sein, da es das Ausführen beliebigen Codes im Prozess erlauben kann; deshalb wird dieser Load-Command nur in dyld-Builds mit `#define SUPPORT_LC_DYLD_ENVIRONMENT` verwendet und verarbeitet zusätzlich nur Variablen der Form `DYLD_..._PATH`, die Ladepfade spezifizieren.

### **`LC_LOAD_DYLIB`**

Dieser Load-Command beschreibt eine **dynamische** **Library**-Abhängigkeit, die den **Loader** (dyld) anweist, die betreffende Library zu **laden und zu verlinken**. Es gibt einen `LC_LOAD_DYLIB`-Load-Command **für jede Library**, die das Mach-O-Binary benötigt.

- Dieser Load-Command ist eine Struktur vom Typ **`dylib_command`** (die eine struct dylib enthält, welche die tatsächlich abhängige dynamische Library beschreibt):
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

Du kannst diese Informationen auch mit der cli abrufen:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Einige potenziell mit Malware verbundene Bibliotheken sind:

- **DiskArbitration**: Überwachung von USB-Laufwerken
- **AVFoundation:** Aufnahme von Audio und Video
- **CoreWLAN**: WLAN-Scans.

> [!TIP]
> Eine Mach-O-Binärdatei kann einen oder **mehrere** **Konstruktoren** enthalten, die **ausgeführt** werden **bevor** die in **LC_MAIN** angegebene Adresse.\
> Die Offsets von Konstruktoren werden im **\_\_mod_init_func** Abschnitt des **\_\_DATA_CONST** Segments gehalten.

## **Mach-O-Daten**

Im Kern der Datei liegt der Datenbereich, der aus mehreren Segmenten besteht, wie im Bereich load-commands definiert. **Innerhalb jedes Segments können verschiedene Datensektionen untergebracht sein**, wobei jede Sektion **Code oder Daten** enthält, die einem bestimmten Typ entsprechen.

> [!TIP]
> Die Daten sind im Grunde der Teil, der alle **Informationen** enthält, die durch die load commands **LC_SEGMENTS_64** geladen werden.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Dazu gehören:

- **Funktionstabelle:** Enthält Informationen über die Funktionen des Programms.
- **Symboltabelle**: Enthält Informationen über die externen Funktionen, die von der Binärdatei verwendet werden.
- Es kann auch interne Funktions- und Variablennamen sowie weiteres enthalten.

Um dies zu prüfen, können Sie das [**Mach-O View**](https://sourceforge.net/projects/machoview/) Tool verwenden:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Oder über die CLI:
```bash
size -m /bin/ls
```
## Objetive-C: Übliche Abschnitte

Im `__TEXT`-Segment (r-x):

- `__objc_classname`: Klassennamen (Strings)
- `__objc_methname`: Methodennamen (Strings)
- `__objc_methtype`: Methodentypen (Strings)

Im `__DATA`-Segment (rw-):

- `__objc_classlist`: Zeiger auf alle Objetive-C-Klassen
- `__objc_nlclslist`: Zeiger auf Non-Lazy Objetive-C-Klassen
- `__objc_catlist`: Zeiger auf Categories
- `__objc_nlcatlist`: Zeiger auf Non-Lazy-Categories
- `__objc_protolist`: Liste von Protocols
- `__objc_const`: Konstante Daten
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
