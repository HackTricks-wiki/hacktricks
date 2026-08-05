# macOS Universal binaries & Mach-O-Format

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Mac-OS-Binaries werden normalerweise als **universal binaries** kompiliert. Ein **universal binary** kann **mehrere Architekturen in derselben Datei unterstützen**.

Diese Binaries folgen der **Mach-O-Struktur**, die grundsätzlich aus Folgendem besteht:

- Header
- Load Commands
- Daten

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Suche nach der Datei mit: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Der Header enthält die **magic**-Bytes, gefolgt von der **Anzahl** der **Architekturen**, die die Datei **enthält** (`nfat_arch`), und jede Architektur besitzt eine `fat_arch`-Struktur.

Überprüfe dies mit:

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

Wie du dir vielleicht schon denkst, **verdoppelt** ein universal binary, das für 2 Architekturen kompiliert wurde, normalerweise die Größe eines Binaries, das nur für 1 Architektur kompiliert wurde.

> [!TIP]
> Wenn du Malware oder verdächtige Apps triagierst, solltest du nicht aufhören, nachdem `file` die „beste“ Architektur gemeldet hat. Ein universal binary kann in jedem Slice unterschiedliche Imports, Load Commands oder Compiler-Metadaten verbergen. Zähle daher zuerst **alle** Slices auf und untersuche sie anschließend unabhängig voneinander:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Neuere macOS SDKs stellen außerdem Hilfsfunktionen wie `macho_for_each_slice()` und `macho_best_slice()` in `<mach-o/utils.h>` bereit. Letztere ist praktisch, um zu emulieren, was dyld/der Kernel laden würde. Scanner sollten dennoch jedes Slice durchlaufen, um architekturspezifische Inhalte nicht zu übersehen.<sup>[[1]](#references)</sup>

## **Mach-O-Header**

Der Header enthält grundlegende Informationen über die Datei, beispielsweise Magic Bytes, anhand derer sie als Mach-O-Datei identifiziert wird, sowie Informationen über die Zielarchitektur. Sie finden ihn mit: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Es gibt verschiedene Dateitypen, die im [**Quellcode beispielsweise hier**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) definiert sind. Die wichtigsten sind:

- `MH_OBJECT`: Relocatable Object File (Zwischenergebnisse der Kompilierung, noch keine Executables).
- `MH_EXECUTE`: Ausführbare Dateien.
- `MH_FVMLIB`: Fixed VM Library File.
- `MH_CORE`: Code-Dumps.
- `MH_PRELOAD`: Vorausgeladene ausführbare Datei (wird in XNU nicht mehr unterstützt).
- `MH_DYLIB`: Dynamic Libraries.
- `MH_DYLINKER`: Dynamic Linker.
- `MH_BUNDLE`: „Plugin-Dateien“. Werden mit `-bundle` in gcc erzeugt und explizit von `NSBundle` oder `dlopen` geladen.
- `MH_DYSM`: Zugehörige `.dSym`-Datei (Datei mit Symbolen zum Debugging).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Oder mit [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

Der Quellcode definiert außerdem mehrere Flags, die zum Laden von Libraries nützlich sind:

- `MH_NOUNDEFS`: Keine undefinierten Referenzen (vollständig gelinkt)
- `MH_DYLDLINK`: Dyld-Linking
- `MH_PREBOUND`: Dynamische Referenzen sind prebound.
- `MH_SPLIT_SEGS`: Die Datei teilt r/o- und r/w-Segmente auf.
- `MH_WEAK_DEFINES`: Das Binary enthält weak definierte Symbole
- `MH_BINDS_TO_WEAK`: Das Binary verwendet weak Symbole
- `MH_ALLOW_STACK_EXECUTION`: Macht den Stack ausführbar
- `MH_NO_REEXPORTED_DYLIBS`: Library ohne LC_REEXPORT-Befehle
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Es gibt einen Abschnitt mit thread-lokalen Variablen
- `MH_NO_HEAP_EXECUTION`: Keine Ausführung für Heap-/Datenseiten
- `MH_HAS_OBJC`: Das Binary enthält oBject-C-Abschnitte
- `MH_SIM_SUPPORT`: Simulator-Unterstützung
- `MH_DYLIB_IN_CACHE`: Wird für dylibs/frameworks im shared library cache verwendet.

## **Mach-O Load commands**

Das **Layout der Datei im Speicher** wird hier spezifiziert. Dabei werden der **Speicherort der Symboltabelle**, der Kontext des Haupt-Threads beim Start der Ausführung und die erforderlichen **shared libraries** beschrieben. Dem dynamischen Loader **(dyld)** werden Anweisungen zum Laden des Binarys in den Speicher gegeben.

Die Datei verwendet die **load_command**-Struktur, die im erwähnten **`loader.h`** definiert ist:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Es gibt etwa **50 verschiedene Typen von Load Commands**, die vom System unterschiedlich verarbeitet werden. Die häufigsten sind: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` und `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Dieser Typ von Load Command definiert im Wesentlichen, **wie die \_\_TEXT**- (ausführbarer Code) **und \_\_DATA**- (Daten für den Prozess) **Segmente** gemäß den **im Data-Abschnitt angegebenen Offsets** geladen werden, wenn die Binary ausgeführt wird.

Diese Commands **definieren Segmente**, die beim Ausführen eines Prozesses in dessen **virtuellen Speicherbereich** **eingeblendet** werden.

Es gibt **verschiedene Typen** von Segmenten, beispielsweise das **\_\_TEXT**-Segment, das den ausführbaren Code eines Programms enthält, und das **\_\_DATA**-Segment, das vom Prozess verwendete Daten enthält. Diese **Segmente befinden sich im Data-Abschnitt** der Mach-O-Datei.

**Jedes Segment** kann weiter in mehrere **Sections** unterteilt werden. Die **Struktur des Load Commands** enthält **Informationen** über **diese Sections** innerhalb des jeweiligen Segments.

Im Header befindet sich zuerst der **Segment-Header**:

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

Dieser Header definiert die **Anzahl der Sections, deren Header danach erscheinen**:
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
Beispiel für einen **section header**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Wenn du den **section offset** (0x37DC) und den **offset**, an dem die **arch beginnt**, addierst, in diesem Fall `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Es ist auch möglich, **headers information** über die **Kommandozeile** abzurufen mit:
```bash
otool -lv /bin/ls
```
Häufige Segmente, die von diesem cmd geladen werden:

- **`__PAGEZERO`:** Es weist den Kernel an, die **Adresse null** zu **map**, sodass sie **nicht gelesen, beschrieben oder ausgeführt** werden kann. Die Variablen maxprot und minprot in der Struktur werden auf null gesetzt, um anzuzeigen, dass es **keine Lese-, Schreib- oder Ausführungsrechte für diese Seite** gibt.
- Diese Allokation ist wichtig, um **NULL pointer dereference vulnerabilities** zu **mitigate**. Der Grund dafür ist, dass XNU eine harte Page Zero erzwingt, die sicherstellt, dass die erste Seite (nur die erste) des Speichers nicht zugänglich ist (außer in i386). Ein Binary könnte diese Anforderung erfüllen, indem es ein kleines \_\_PAGEZERO erstellt (mit `-pagezero_size`), das die ersten 4k abdeckt, und den restlichen 32-Bit-Speicher sowohl im User- als auch im Kernel-Modus zugänglich macht.
- **`__TEXT`**: Enthält **ausführbaren** **Code** mit **Lese-** und **Ausführungsberechtigungen (nicht beschreibbar)**.** Häufige Sections dieses Segments:
- `__text`: Kompilierter Binary-Code
- `__const`: Konstante Daten (nur lesbar)
- `__[c/u/os_log]string`: String-Konstanten für C, Unicode oder os logs
- `__stubs` und `__stubs_helper`: Werden während des Ladens der Dynamic Library verwendet
- `__unwind_info`: Stack-Unwind-Daten.
- Beachte, dass all diese Inhalte signiert, aber auch als ausführbar markiert sind (wodurch weitere Exploit-Optionen für Sections entstehen, die dieses Privileg nicht unbedingt benötigen, wie etwa für Strings vorgesehene Sections).
- **`__DATA`**: Enthält Daten, die **lesbar** und **beschreibbar (nicht ausführbar)** sind.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non-lazy (Bind beim Laden) Symbol-Pointer
- `__la_symbol_ptr`: Lazy (Bind bei Verwendung) Symbol-Pointer
- `__const`: Sollte nur lesbare Daten enthalten (ist es aber nicht wirklich)
- `__cfstring`: CoreFoundation-Strings
- `__data`: Globale Variablen (die initialisiert wurden)
- `__bss`: Statische Variablen (die nicht initialisiert wurden)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist usw.): Informationen, die von der Objective-C-Runtime verwendet werden
- **`__DATA_CONST`**: \_\_DATA.\_\_const ist nicht garantiert konstant (Schreibberechtigungen), ebenso wenig wie andere Pointer und die GOT. Diese Section macht `__const`, einige Initializer und die GOT-Tabelle (sobald sie aufgelöst wurde) mithilfe von `mprotect` **nur lesbar**.
- **`__AUTH` / `__AUTH_CONST`**: In neueren Apple-Silicon-Binaries häufig. Diese Segmente enthalten Pointer, die beim Laden oder bei der Verwendung authentifiziert werden müssen (zum Beispiel `__auth_got`). Wenn ein Rebinding-, Hook- oder Import-Patching-Trick nur die älteren Sections `__got` / `__la_symbol_ptr` überprüft, kann er die tatsächlichen Call Sites in modernen `arm64e`-Binaries übersehen. Weitere Details zu diesen Sections findest du auf [dieser Seite](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Enthält Informationen für den Linker (dyld), etwa Einträge der Symbol-, String- und Relocation-Tabellen. Es ist ein generischer Container für Inhalte, die sich weder in `__TEXT` noch in `__DATA` befinden, und deren Inhalt in anderen Load Commands beschrieben wird.
- dyld-Informationen: Rebase-, Non-lazy-/lazy-/weak-Binding-Opcodes und Export-Informationen
- Functions starts: Tabelle mit Startadressen von Funktionen
- Data In Code: Dateninseln in \_\_text
- SYmbol Table: Symbole im Binary
- Indirect Symbol Table: Pointer-/Stub-Symbole
- String Table
- Code Signature
- **`__OBJC`**: Enthält Informationen, die von der Objective-C-Runtime verwendet werden. Diese Informationen können sich jedoch auch im \_\_DATA-Segment innerhalb verschiedener \_\_objc\_\*-Sections befinden.
- **`__RESTRICT`**: Ein Segment ohne Inhalt mit einer einzelnen Section namens **`__restrict`** (ebenfalls leer), das sicherstellt, dass beim Ausführen des Binarys DYLD-Umgebungsvariablen ignoriert werden.

Wie im Code zu sehen war, unterstützen **Segmente auch Flags** (obwohl sie nicht sehr häufig verwendet werden):

- `SG_HIGHVM`: Nur Core (nicht verwendet)
- `SG_FVMLIB`: Nicht verwendet
- `SG_NORELOC`: Segment besitzt keine Relocation
- `SG_PROTECTED_VERSION_1`: Verschlüsselung. Wird beispielsweise vom Finder verwendet, um das `__TEXT`-Segment zu verschlüsseln.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** enthält den Entry Point im **Attribut `entryoff`.** Beim Laden addiert **dyld** diesen Wert einfach zur (im Speicher befindlichen) **Basis des Binarys** und **springt** anschließend zu dieser Instruktion, um mit der Ausführung des Binary-Codes zu beginnen.

**`LC_UNIXTHREAD`** enthält die Werte, die die Register beim Start des Main Threads haben müssen. Dies ist bereits veraltet, aber **`dyld`** verwendet es weiterhin. Die mit diesem Mechanismus gesetzten Registerwerte können folgendermaßen angezeigt werden:
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


Enthält Informationen über die **Code-Signatur der Mach-O-Datei**. Sie enthält nur einen **Offset**, der auf den **Signatur-Blob** **verweist**. Dieser befindet sich typischerweise ganz am Ende der Datei.\
Einige Informationen über diesen Abschnitt findest du jedoch in [**diesem Blogpost**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) und in diesen [**Gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Unterstützung für die Verschlüsselung von Binaries. Wenn es einem Angreifer jedoch gelingt, den Prozess zu kompromittieren, kann er den Speicher unverschlüsselt dumpen.

### **`LC_LOAD_DYLINKER`**

Enthält den **Pfad zur ausführbaren Datei des Dynamic Linkers**, der Shared Libraries in den Adressraum des Prozesses lädt. Der **Wert ist immer auf `/usr/lib/dyld` gesetzt**. Es ist wichtig zu beachten, dass das Mapping von dylibs in macOS im **User Mode** und nicht im **Kernel Mode** erfolgt.

### **`LC_IDENT`**

Veraltet, aber wenn konfiguriert ist, bei einem Panic Dumps zu erzeugen, wird ein Mach-O-Core-Dump erstellt und die Kernel-Version im `LC_IDENT`-Befehl festgelegt.

### **`LC_UUID`**

Zufällige UUID. Sie ist für sich genommen nicht direkt nützlich, aber XNU cached sie zusammen mit den übrigen Prozessinformationen. Sie kann in Crash Reports verwendet werden.

### **`LC_BUILD_VERSION`**

Moderne Binaries enthalten diesen Befehl normalerweise, um die **Zielplattform**, die **minimale OS-Version**, die **SDK-Version** und optional die **Tool-Versionen** anzugeben, die zum Erstellen dieses Slices verwendet wurden. Aus offensiver Sicht und beim Reversing ist dies sehr nützlich, um zu ermitteln, wie ein Sample erstellt wurde, und um schnell ungewöhnliche Universal Binaries zu erkennen, bei denen ein Slice mit einem anderen SDK oder Deployment Target kompiliert wurde. Ältere Binaries verwenden möglicherweise stattdessen weiterhin `LC_VERSION_MIN_*`.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Ermöglicht es, dyld Umgebungsvariablen anzugeben, bevor der Prozess ausgeführt wird. Dies kann sehr gefährlich sein, da dadurch beliebiger Code innerhalb des Prozesses ausgeführt werden kann. Daher wird dieser load command nur in dyld-Builds mit `#define SUPPORT_LC_DYLD_ENVIRONMENT` verwendet und die Verarbeitung zusätzlich auf Variablen der Form `DYLD_..._PATH` beschränkt, die load paths angeben.

### **`LC_DYLD_EXPORTS_TRIE` und `LC_DYLD_CHAINED_FIXUPS`**

Neuere Toolchains speichern Export-/Bind-/Rebase-Metadaten häufig in diesen commands, anstatt sich ausschließlich auf die älteren `LC_DYLD_INFO[_ONLY]`-Opcodes zu verlassen. Beide sind `linkedit_data_command`-Einträge, die auf **`__LINKEDIT`** verweisen:

- **`LC_DYLD_EXPORTS_TRIE`**: Kompakter Trie mit den von dem Image exportierten Symbolen.
- **`LC_DYLD_CHAINED_FIXUPS`**: Fixup-Ketten pro Segment, die von dyld verwendet werden, um Rebases und Binds anzuwenden. Auf Apple Silicon finden sich hier auch viele moderne authentifizierte Pointer-Fixups.

Diese Metadaten sind sehr nützlich, wenn man Imports/Exports rekonstruiert, verstehen möchte, warum eine über `@rpath` geladene Dependency auf diese Weise aufgelöst wurde, oder herausfinden möchte, warum ein Hook-/Rebinding-Versuch bei einem modernen `arm64e`-Target fehlgeschlagen ist. `dyld_info` kann auch auf **cache-only dylib paths** angewendet werden, die nicht als eigenständige Dateien auf der Festplatte existieren. Dies ist unter modernem macOS besonders nützlich, da viele Systembibliotheken ausschließlich im Shared Cache liegen.<sup>[[2]](#references)</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Dieser moderne Load Command ist vor allem bei der Untersuchung von **kernel collections / kernelcache-style filesets** relevant. Statt ein einzelnes eigenständiges Image darzustellen, fungiert das äußere Mach-O als Container, und jeder `LC_FILESET_ENTRY` verweist auf ein eingebettetes Mach-O mit einer eigenen pfadähnlichen **entry id**, einer VM-Adresse und einem Datei-Offset. Wenn du moderne macOS/iOS-Kernel-Komponenten reverse-engineerst, ist dieser Command oft die Verbindung zwischen dem übergeordneten Container und dem eigentlichen Image, das du extrahieren oder disassemblieren möchtest.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Für praktische Extraktions-Workflows siehe [diese andere Seite über macOS kernel extensions und kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Dieser Load Command beschreibt eine Abhängigkeit von einer **dynamischen** **Bibliothek**, die den **Loader** (dyld) anweist, diese **Bibliothek zu laden und zu verknüpfen**. Für **jede Bibliothek**, die das Mach-O-Binary benötigt, gibt es einen `LC_LOAD_DYLIB`-Load-Command.

- Dieser Load Command ist eine Struktur vom Typ **`dylib_command`** (die eine Struktur `dylib` enthält, welche die tatsächlich abhängige dynamische Bibliothek beschreibt):
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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t compatibility version; / Kompatibilitätsversionsnummer der Bibliothek /](<../../../images/image (486).png>)

Diese Informationen kannst du auch über die CLI erhalten:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Einige potenziell mit Malware verbundene Libraries sind:

- **DiskArbitration**: Überwachung von USB-Laufwerken
- **AVFoundation:** Aufnehmen von Audio und Video
- **CoreWLAN**: WLAN-Scans.

> [!TIP]
> Eine Mach-O-Binary kann einen oder **mehrere** **Konstruktoren** enthalten, die **vor** der in **LC_MAIN** angegebenen Adresse **ausgeführt** werden.\
> Die Offsets beliebiger Konstruktoren befinden sich im Abschnitt **\_\_mod_init_func** des Segments **\_\_DATA_CONST**.

## **Mach-O-Daten**

Im Kern der Datei befindet sich die Datenregion, die aus mehreren Segmenten besteht, wie sie in der Region der Load Commands definiert sind. **Jedes Segment kann eine Vielzahl von Datenabschnitten enthalten**, wobei jeder Abschnitt **Code oder Daten** enthält, die für einen bestimmten Typ spezifisch sind.

> [!TIP]
> Die Daten sind im Wesentlichen der Teil, der alle **Informationen** enthält, die von den Load Commands **LC_SEGMENTS_64** geladen werden.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Dazu gehören:

- **Funktionstabelle:** Enthält Informationen über die Programmfunktionen.
- **Symboltabelle**: Enthält Informationen über die von der Binary verwendete externe Funktion.
- Sie kann außerdem interne Funktions- und Variablennamen sowie weitere Informationen enthalten.

Um sie zu überprüfen, kannst du das Tool [**Mach-O View**](https://sourceforge.net/projects/machoview/) verwenden:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Oder über die CLI:
```bash
size -m /bin/ls
```
## Häufige Objective-C-Sections

Im `__TEXT`-Segment (r-x):

- `__objc_classname`: Klassennamen (Strings)
- `__objc_methname`: Methodennamen (Strings)
- `__objc_methtype`: Methodentypen (Strings)

Im `__DATA`-Segment (rw-):

- `__objc_classlist`: Zeiger auf alle Objective-C-Klassen
- `__objc_nlclslist`: Zeiger auf Non-Lazy-Objective-C-Klassen
- `__objc_catlist`: Zeiger auf Kategorien
- `__objc_nlcatlist`: Zeiger auf Non-Lazy-Kategorien
- `__objc_protolist`: Protokollliste
- `__objc_const`: Konstantendaten
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## Referenzen

- [1] [Mach-O-Slices sind nicht so unkompliziert, wie man vielleicht denkt](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1)-Handbuchseite](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Die eigenen Entitlements lesen](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (Gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
