# macOS Universal-Binaries & Mach-O-Format

{{#include ../../../banners/hacktricks-training.md}}

## Grundinformationen

Mac OS-Binaries werden normalerweise als **universelle Binaries** kompiliert. Ein **universelles Binary** kann **mehrere Architekturen in derselben Datei unterstützen**.

Diese Binaries folgen der **Mach-O-Struktur**, die im Wesentlichen aus besteht:

- Header
- Ladebefehle
- Daten

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Suchen Sie die Datei mit: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC oder FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* Anzahl der folgenden Strukturen */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* CPU-Spezifizierer (int) */
cpu_subtype_t	cpusubtype;	/* Maschinen-Spezifizierer (int) */
uint32_t	offset;		/* Dateiverschiebung zu dieser Objektdatei */
uint32_t	size;		/* Größe dieser Objektdatei */
uint32_t	align;		/* Ausrichtung als Potenz von 2 */
};
</code></pre>

Der Header enthält die **magischen** Bytes, gefolgt von der **Anzahl** der **Architekturen**, die die Datei **enthält** (`nfat_arch`), und jede Architektur hat eine `fat_arch`-Struktur.

Überprüfen Sie es mit:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universelles Binary mit 2 Architekturen: [x86_64:Mach-O 64-Bit ausführbar x86_64] [arm64e:Mach-O 64-Bit ausführbar arm64e]
/bin/ls (für Architektur x86_64):	Mach-O 64-Bit ausführbar x86_64
/bin/ls (für Architektur arm64e):	Mach-O 64-Bit ausführbar arm64e

% otool -f -v /bin/ls
Fat-Header
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>architektur x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>architektur arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

oder mit dem [Mach-O View](https://sourceforge.net/projects/machoview/) Tool:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Wie Sie vielleicht denken, verdoppelt ein universelles Binary, das für 2 Architekturen kompiliert wurde, normalerweise die Größe eines, das nur für 1 Architektur kompiliert wurde.

## **Mach-O Header**

Der Header enthält grundlegende Informationen über die Datei, wie magische Bytes, um sie als Mach-O-Datei zu identifizieren, und Informationen über die Zielarchitektur. Sie finden es unter: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Es gibt verschiedene Dateitypen, die in dem [**Quellcode zum Beispiel hier**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) definiert sind. Die wichtigsten sind:

- `MH_OBJECT`: Umsetzbare Objektdatei (Zwischenprodukte der Kompilierung, noch keine ausführbaren Dateien).
- `MH_EXECUTE`: Ausführbare Dateien.
- `MH_FVMLIB`: Feste VM-Bibliotheksdatei.
- `MH_CORE`: Code-Dumps
- `MH_PRELOAD`: Vorgelegte ausführbare Datei (wird in XNU nicht mehr unterstützt)
- `MH_DYLIB`: Dynamische Bibliotheken
- `MH_DYLINKER`: Dynamischer Linker
- `MH_BUNDLE`: "Plugin-Dateien". Generiert mit -bundle in gcc und explizit geladen von `NSBundle` oder `dlopen`.
- `MH_DYSM`: Begleitende `.dSym`-Datei (Datei mit Symbolen für das Debugging).
- `MH_KEXT_BUNDLE`: Kernel-Erweiterungen.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Oder verwenden Sie [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O-Flags**

Der Quellcode definiert auch mehrere Flags, die nützlich sind, um Bibliotheken zu laden:

- `MH_NOUNDEFS`: Keine undefinierten Referenzen (vollständig verlinkt)
- `MH_DYLDLINK`: Dyld-Verlinkung
- `MH_PREBOUND`: Dynamische Referenzen vorgebunden.
- `MH_SPLIT_SEGS`: Datei teilt r/o und r/w Segmente.
- `MH_WEAK_DEFINES`: Binärdatei hat schwach definierte Symbole
- `MH_BINDS_TO_WEAK`: Binärdatei verwendet schwache Symbole
- `MH_ALLOW_STACK_EXECUTION`: Machen Sie den Stack ausführbar
- `MH_NO_REEXPORTED_DYLIBS`: Bibliothek hat keine LC_REEXPORT-Befehle
- `MH_PIE`: Positionsunabhängige ausführbare Datei
- `MH_HAS_TLV_DESCRIPTORS`: Es gibt einen Abschnitt mit thread-lokalen Variablen
- `MH_NO_HEAP_EXECUTION`: Keine Ausführung für Heap/Daten-Seiten
- `MH_HAS_OBJC`: Binärdatei hat oBject-C-Abschnitte
- `MH_SIM_SUPPORT`: Simulatorunterstützung
- `MH_DYLIB_IN_CACHE`: Wird bei dylibs/Frameworks im gemeinsamen Bibliothekscache verwendet.

## **Mach-O-Ladebefehle**

Das **Layout der Datei im Speicher** wird hier spezifiziert, wobei der **Standort der Symboltabelle**, der Kontext des Hauptthreads beim Start der Ausführung und die erforderlichen **gemeinsamen Bibliotheken** detailliert beschrieben werden. Anweisungen werden dem dynamischen Loader **(dyld)** zum Ladeprozess der Binärdatei in den Speicher bereitgestellt.

Es verwendet die **load_command**-Struktur, die in der erwähnten **`loader.h`** definiert ist:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Es gibt etwa **50 verschiedene Arten von Load Commands**, die das System unterschiedlich behandelt. Die häufigsten sind: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` und `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Grundsätzlich definiert dieser Typ von Load Command **wie man die \_\_TEXT** (ausführbarer Code) **und \_\_DATA** (Daten für den Prozess) **Segmente** gemäß den **Offsets, die im Datenbereich angegeben sind**, wenn die Binärdatei ausgeführt wird.

Diese Befehle **definieren Segmente**, die in den **virtuellen Adressraum** eines Prozesses gemappt werden, wenn er ausgeführt wird.

Es gibt **verschiedene Arten** von Segmenten, wie das **\_\_TEXT**-Segment, das den ausführbaren Code eines Programms enthält, und das **\_\_DATA**-Segment, das Daten enthält, die vom Prozess verwendet werden. Diese **Segmente befinden sich im Datenbereich** der Mach-O-Datei.

**Jedes Segment** kann weiter in mehrere **Sektionen** **unterteilt** werden. Die **Struktur des Load Commands** enthält **Informationen** über **diese Sektionen** innerhalb des jeweiligen Segments.

Im Header finden Sie zuerst den **Segment-Header**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* für 64-Bit-Architekturen */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* umfasst sizeof section_64 Strukturen */
char		segname[16];	/* Segmentname */
uint64_t	vmaddr;		/* Speicheradresse dieses Segments */
uint64_t	vmsize;		/* Speichergröße dieses Segments */
uint64_t	fileoff;	/* Dateiverschiebung dieses Segments */
uint64_t	filesize;	/* Menge, die aus der Datei gemappt werden soll */
int32_t		maxprot;	/* maximale VM-Schutz */
int32_t		initprot;	/* anfänglicher VM-Schutz */
<strong>	uint32_t	nsects;		/* Anzahl der Sektionen im Segment */
</strong>	uint32_t	flags;		/* Flags */
};
</code></pre>

Beispiel eines Segment-Headers:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Dieser Header definiert die **Anzahl der Sektionen, deren Header danach erscheinen**:
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
Beispiel für **Abschnittsüberschrift**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Wenn Sie den **Abschnittsversatz** (0x37DC) + den **Versatz**, wo der **Arch beginnt**, in diesem Fall `0x18000` hinzufügen --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Es ist auch möglich, **Header-Informationen** über die **Befehlszeile** zu erhalten mit:
```bash
otool -lv /bin/ls
```
Häufige Segmente, die von diesem Befehl geladen werden:

- **`__PAGEZERO`:** Es weist den Kernel an, die **Adresse null** zu **mappen**, sodass sie **nicht gelesen, beschrieben oder ausgeführt** werden kann. Die Variablen maxprot und minprot in der Struktur sind auf null gesetzt, um anzuzeigen, dass es **keine Lese-, Schreib- oder Ausführungsrechte auf dieser Seite** gibt.
- Diese Zuweisung ist wichtig, um **NULL-Zeiger-Dereferenzierungsanfälligkeiten** zu **mildern**. Dies liegt daran, dass XNU eine harte Seite null durchsetzt, die sicherstellt, dass die erste Seite (nur die erste) des Speichers unzugänglich ist (außer in i386). Ein Binärprogramm könnte diese Anforderungen erfüllen, indem es eine kleine \_\_PAGEZERO erstellt (unter Verwendung von `-pagezero_size`), um die ersten 4k abzudecken und den Rest des 32-Bit-Speichers sowohl im Benutzer- als auch im Kernelmodus zugänglich zu machen.
- **`__TEXT`**: Enthält **ausführbaren** **Code** mit **Lese-** und **Ausführungsberechtigungen** (kein schreibbarer)**.** Häufige Abschnitte dieses Segments:
- `__text`: Kompilierter Binärcode
- `__const`: Konstanten Daten (nur lesbar)
- `__[c/u/os_log]string`: C-, Unicode- oder os-Log-String-Konstanten
- `__stubs` und `__stubs_helper`: Beteiligt am Prozess des Ladens dynamischer Bibliotheken
- `__unwind_info`: Stack-Unwind-Daten.
- Beachten Sie, dass all dieser Inhalt signiert, aber auch als ausführbar markiert ist (was mehr Optionen für die Ausnutzung von Abschnitten schafft, die nicht unbedingt dieses Privileg benötigen, wie z.B. stringdedizierte Abschnitte).
- **`__DATA`**: Enthält Daten, die **lesbar** und **schreibbar** sind (nicht ausführbar)**.**
- `__got:` Globale Offset-Tabelle
- `__nl_symbol_ptr`: Nicht faul (Bindung beim Laden) Symbolzeiger
- `__la_symbol_ptr`: Faul (Bindung bei Verwendung) Symbolzeiger
- `__const`: Soll schreibgeschützte Daten sein (nicht wirklich)
- `__cfstring`: CoreFoundation-Strings
- `__data`: Globale Variablen (die initialisiert wurden)
- `__bss`: Statische Variablen (die nicht initialisiert wurden)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist usw.): Informationen, die von der Objective-C-Laufzeit verwendet werden
- **`__DATA_CONST`**: \_\_DATA.\_\_const ist nicht garantiert konstant (Schreibberechtigungen), noch sind andere Zeiger und die GOT. Dieser Abschnitt macht `__const`, einige Initialisierer und die GOT-Tabelle (einmal aufgelöst) **schreibgeschützt** mit `mprotect`.
- **`__LINKEDIT`**: Enthält Informationen für den Linker (dyld), wie z.B. Symbol-, String- und Relocation-Tabelleneinträge. Es ist ein generischer Container für Inhalte, die sich weder in `__TEXT` noch in `__DATA` befinden, und dessen Inhalt in anderen Ladebefehlen beschrieben wird.
- dyld-Informationen: Rebase, Nicht-faule/faul/schwache Bindungs-Opcode und Exportinformationen
- Funktionsstarts: Tabelle der Startadressen von Funktionen
- Daten im Code: Dateninseln in \_\_text
- Symboltabelle: Symbole im Binärformat
- Indirekte Symboltabelle: Zeiger/stub-Symbole
- Zeichenfolgen-Tabelle
- Codesignatur
- **`__OBJC`**: Enthält Informationen, die von der Objective-C-Laufzeit verwendet werden. Obwohl diese Informationen auch im \_\_DATA-Segment gefunden werden können, innerhalb verschiedener \_\_objc\_\* Abschnitte.
- **`__RESTRICT`**: Ein Segment ohne Inhalt mit einem einzigen Abschnitt namens **`__restrict`** (auch leer), das sicherstellt, dass beim Ausführen des Binärprogramms DYLD-Umgebungsvariablen ignoriert werden.

Wie im Code zu sehen war, **unterstützen Segmente auch Flags** (obwohl sie nicht sehr häufig verwendet werden):

- `SG_HIGHVM`: Nur Kern (nicht verwendet)
- `SG_FVMLIB`: Nicht verwendet
- `SG_NORELOC`: Segment hat keine Relokation
- `SG_PROTECTED_VERSION_1`: Verschlüsselung. Wird beispielsweise vom Finder verwendet, um den Text des `__TEXT`-Segments zu verschlüsseln.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** enthält den Einstiegspunkt im **entryoff-Attribut.** Zur Ladezeit **fügt dyld** einfach **diesen Wert** zur (im Speicher) **Basis des Binärprogramms** hinzu und **springt** dann zu dieser Anweisung, um die Ausführung des Codes des Binärprogramms zu starten.

**`LC_UNIXTHREAD`** enthält die Werte, die die Register haben müssen, wenn der Hauptthread gestartet wird. Dies wurde bereits als veraltet markiert, aber **`dyld`** verwendet es immer noch. Es ist möglich, die von diesem gesetzten Registerwerte zu sehen mit:
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

Enthält Informationen über die **Code-Signatur der Macho-O-Datei**. Es enthält nur einen **Offset**, der auf den **Signatur-Blob** zeigt. Dies befindet sich typischerweise am Ende der Datei.\
Sie können jedoch einige Informationen zu diesem Abschnitt in [**diesem Blogbeitrag**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) und diesen [**Gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) finden.

### **`LC_ENCRYPTION_INFO[_64]`**

Unterstützung für die binäre Verschlüsselung. Wenn ein Angreifer jedoch den Prozess kompromittiert, kann er den Speicher unverschlüsselt dumpen.

### **`LC_LOAD_DYLINKER`**

Enthält den **Pfad zur dynamischen Linker-Executable**, die gemeinsam genutzte Bibliotheken in den Adressraum des Prozesses einbindet. Der **Wert ist immer auf `/usr/lib/dyld`** gesetzt. Es ist wichtig zu beachten, dass in macOS das Dylib-Mapping im **Benutzermodus** und nicht im Kernelmodus erfolgt.

### **`LC_IDENT`**

Veraltet, aber wenn konfiguriert, um Dumps bei einem Panic zu erzeugen, wird ein Mach-O-Core-Dump erstellt und die Kernelversion wird im `LC_IDENT`-Befehl gesetzt.

### **`LC_UUID`**

Zufällige UUID. Es ist nützlich für alles direkt, aber XNU cached es mit dem Rest der Prozessinformationen. Es kann in Absturzberichten verwendet werden.

### **`LC_DYLD_ENVIRONMENT`**

Erlaubt es, Umgebungsvariablen an den dyld anzugeben, bevor der Prozess ausgeführt wird. Dies kann sehr gefährlich sein, da es die Ausführung beliebigen Codes innerhalb des Prozesses ermöglichen kann, sodass dieser Ladebefehl nur in dyld-Bauten mit `#define SUPPORT_LC_DYLD_ENVIRONMENT` verwendet wird und die Verarbeitung weiter auf Variablen der Form `DYLD_..._PATH` beschränkt ist, die Ladepfade angeben.

### **`LC_LOAD_DYLIB`**

Dieser Ladebefehl beschreibt eine **dynamische** **Bibliotheks**-Abhängigkeit, die den **Loader** (dyld) anweist, die **angegebene Bibliothek zu laden und zu verlinken**. Es gibt einen `LC_LOAD_DYLIB`-Ladebefehl **für jede Bibliothek**, die die Mach-O-Binärdatei benötigt.

- Dieser Ladebefehl ist eine Struktur vom Typ **`dylib_command`** (die eine Struktur dylib enthält, die die tatsächliche abhängige dynamische Bibliothek beschreibt):
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

Sie können diese Informationen auch über die CLI erhalten mit:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Einige potenzielle malwarebezogene Bibliotheken sind:

- **DiskArbitration**: Überwachung von USB-Laufwerken
- **AVFoundation:** Audio und Video erfassen
- **CoreWLAN**: Wifi-Scans.

> [!NOTE]
> Eine Mach-O-Binärdatei kann einen oder **mehrere** **Konstruktoren** enthalten, die **ausgeführt** werden, **bevor** die Adresse, die in **LC_MAIN** angegeben ist, erreicht wird.\
> Die Offsets aller Konstruktoren befinden sich im Abschnitt **\_\_mod_init_func** des Segments **\_\_DATA_CONST**.

## **Mach-O-Daten**

Im Kern der Datei liegt der Datenbereich, der aus mehreren Segmenten besteht, wie im Bereich der Ladebefehle definiert. **Eine Vielzahl von Datensektionen kann innerhalb jedes Segments untergebracht werden**, wobei jede Sektion **Code oder Daten** enthält, die spezifisch für einen Typ sind.

> [!TIP]
> Die Daten sind im Grunde der Teil, der alle **Informationen** enthält, die durch die Ladebefehle **LC_SEGMENTS_64** geladen werden.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Dazu gehören:

- **Funktionstabelle:** Die Informationen über die Programmfunktionen enthält.
- **Symboltabelle**: Die Informationen über die externen Funktionen enthält, die von der Binärdatei verwendet werden.
- Es könnte auch interne Funktionen, Variablennamen und mehr enthalten.

Um dies zu überprüfen, könnten Sie das [**Mach-O View**](https://sourceforge.net/projects/machoview/) Tool verwenden:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Oder über die CLI:
```bash
size -m /bin/ls
```
## Objetive-C Gemeinsame Abschnitte

Im `__TEXT` Segment (r-x):

- `__objc_classname`: Klassennamen (Strings)
- `__objc_methname`: Methodennamen (Strings)
- `__objc_methtype`: Methodentypen (Strings)

Im `__DATA` Segment (rw-):

- `__objc_classlist`: Zeiger auf alle Objective-C Klassen
- `__objc_nlclslist`: Zeiger auf Nicht-Lazy Objective-C Klassen
- `__objc_catlist`: Zeiger auf Kategorien
- `__objc_nlcatlist`: Zeiger auf Nicht-Lazy Kategorien
- `__objc_protolist`: Protokollliste
- `__objc_const`: Konstanten Daten
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
