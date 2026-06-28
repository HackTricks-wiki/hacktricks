# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Mac OS binaries werden normalerweise als **universal binaries** kompiliert. Ein **universal binary** kann **mehrere Architekturen in derselben Datei** unterstützen.

Diese binaries folgen der **Mach-O structure**, die im Wesentlichen aus Folgendem besteht:

- Header
- Load Commands
- Data

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

Der Header hat die **magic** Bytes, gefolgt von der **Anzahl** der **archs**, die die Datei **enthält** (`nfat_arch`), und jede arch hat eine `fat_arch` struct.

Prüfe es mit:

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

oder mit dem [Mach-O View](https://sourceforge.net/projects/machoview/) Tool:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Wie du vielleicht denkst, verdoppelt ein universal binary, das für 2 Architekturen kompiliert wurde, normalerweise die Größe eines nur für 1 arch kompilierten Binaries.

> [!TIP]
> Wenn du Malware oder verdächtige Apps triagierst, hör nicht auf, nachdem `file` die "beste" architecture meldet. Ein universal binary kann in jedem Slice unterschiedliche imports, load commands oder compiler metadata verstecken, also enumeriere zuerst **alle** Slices und inspiziere sie dann unabhängig voneinander:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Neuere macOS SDKs stellen außerdem Helfer wie `macho_for_each_slice()` und `macho_best_slice()` in `<mach-o/utils.h>` bereit. Letzteres ist praktisch, um zu emulieren, was dyld/kernel laden würden, aber Scanner sollten trotzdem jede Slice durchlaufen, um architekturspezifische Inhalte nicht zu übersehen.

## **Mach-O Header**

Der Header enthält grundlegende Informationen über die Datei, wie etwa die Magic Bytes zur Identifizierung als Mach-O-Datei und Informationen über die Zielarchitektur. Du findest ihn unter: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O File Types

Es gibt verschiedene Dateitypen, du kannst sie z.B. im [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) finden. Die wichtigsten sind:

- `MH_OBJECT`: Relocatable object file (Zwischenprodukt der Kompilierung, noch keine ausführbaren Dateien).
- `MH_EXECUTE`: Ausführbare Dateien.
- `MH_FVMLIB`: Fixed VM library file.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Vorab geladene ausführbare Datei (in XNU nicht mehr unterstützt)
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin files". Generiert mit `-bundle` in gcc und explizit geladen durch `NSBundle` oder `dlopen`.
- `MH_DYSM`: Begleitende `.dSym`-Datei (Datei mit Symbolen zum Debugging).
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

Der Quellcode definiert außerdem mehrere Flags, die nützlich für das Laden von Libraries sind:

- `MH_NOUNDEFS`: Keine undefinierten Referenzen (vollständig gelinkt)
- `MH_DYLDLINK`: Dyld linking
- `MH_PREBOUND`: Dynamische Referenzen vorab gebunden.
- `MH_SPLIT_SEGS`: Die Datei trennt r/o- und r/w-Segmente.
- `MH_WEAK_DEFINES`: Binary hat schwach definierte Symbole
- `MH_BINDS_TO_WEAK`: Binary verwendet schwache Symbole
- `MH_ALLOW_STACK_EXECUTION`: Mache den Stack ausführbar
- `MH_NO_REEXPORTED_DYLIBS`: Library hat keine LC_REEXPORT-Befehle
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Es gibt einen Abschnitt mit thread local variables
- `MH_NO_HEAP_EXECUTION`: Keine Ausführung für heap/data-Seiten
- `MH_HAS_OBJC`: Binary hat oBject-C-Abschnitte
- `MH_SIM_SUPPORT`: Simulator-Unterstützung
- `MH_DYLIB_IN_CACHE`: Verwendet bei dylibs/frameworks im shared library cache.

## **Mach-O Load commands**

Das **Layout der Datei im Speicher** wird hier angegeben und beschreibt die **Position der Symboltabelle**, den Kontext des Haupt-Threads beim Start der Ausführung und die benötigten **shared libraries**. Anweisungen werden dem dynamic loader **(dyld)** für den Ladevorgang des Binaries in den Speicher gegeben.

Es verwendet die **load_command**-Struktur, definiert in der erwähnten **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Es gibt etwa **50 verschiedene Arten von Load Commands**, die das System unterschiedlich behandelt. Die gängigsten sind: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` und `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Grundsätzlich definiert dieser Typ von Load Command **wie die \_\_TEXT**- (**ausführbarer Code**) **und \_\_DATA**-(**Daten für den Prozess**) **Segmente** gemäß den **im Data-Bereich angegebenen Offsets** geladen werden, wenn das Binary ausgeführt wird.

Diese Commands **definieren Segmente**, die beim Ausführen eines Prozesses in den **virtuellen Adressraum** **gemappt** werden.

Es gibt **verschiedene Segmenttypen**, wie zum Beispiel das **\_\_TEXT**-Segment, das den ausführbaren Code eines Programms enthält, und das **\_\_DATA**-Segment, das vom Prozess verwendete Daten enthält. Diese **Segmente befinden sich im Data-Bereich** der Mach-O-Datei.

**Jedes Segment** kann zusätzlich in mehrere **Sections** unterteilt werden. Die **Load-Command-Struktur** enthält **Informationen** über **diese Sections** innerhalb des jeweiligen Segments.

Im Header findest du zuerst den **Segment-Header**:

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
Beispiel für **section header**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Wenn du den **section offset** (0x37DC) + den **offset** addierst, an dem die **arch starts**, in diesem Fall `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Es ist auch möglich, **headers information** über die **command line** mit Folgendem zu erhalten:
```bash
otool -lv /bin/ls
```
Gängige Segmente, die von diesem cmd geladen werden:

- **`__PAGEZERO`:** Es weist den Kernel an, die **Adresse null** zu **zuordnen**, damit sie **nicht gelesen, beschrieben oder ausgeführt** werden kann. Die Variablen maxprot und minprot in der Struktur werden auf null gesetzt, um anzuzeigen, dass es auf dieser Seite **keine Read-Write-Execute-Rechte gibt**.
- Diese Zuordnung ist wichtig, um **NULL pointer dereference vulnerabilities** zu **mildern**. Das liegt daran, dass XNU eine harte page zero erzwingt, die sicherstellt, dass die erste Seite (nur die erste) des Speichers **nicht zugänglich** ist (außer in i386). Ein Binary könnte diese Anforderungen erfüllen, indem es ein kleines \_\_PAGEZERO erstellt (mit `-pagezero_size`), um die ersten 4k abzudecken, und den Rest des 32bit-Speichers sowohl im user- als auch im kernel-mode zugänglich macht.
- **`__TEXT`**: Enthält **ausführbaren** **Code** mit **read**- und **execute**-Berechtigungen (**nicht writable**)**.** Gängige Sections dieses Segments:
- `__text`: Kompilierter Binary-Code
- `__const`: Konstante Daten (read only)
- `__[c/u/os_log]string`: C-, Unicode- oder os log String-Konstanten
- `__stubs` und `__stubs_helper`: Beteiligt am Laden von dynamic libraries
- `__unwind_info`: Stack-Unwind-Daten.
- Beachte, dass all dieser Inhalt signiert, aber auch als ausführbar markiert ist (was mehr Möglichkeiten für Exploitation von Sections schafft, die diese Berechtigung nicht unbedingt benötigen, wie z. B. für Strings vorgesehene Sections).
- **`__DATA`**: Enthält Daten, die **lesbar** und **schreibbar** sind (**nicht ausführbar**)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Sollte read-only data sein (eigentlich nicht)
- `__cfstring`: CoreFoundation strings
- `__data`: Globale Variablen (die initialisiert wurden)
- `__bss`: Statische Variablen (die nicht initialisiert wurden)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Informationen, die von der Objective-C runtime verwendet werden
- **`__DATA_CONST`**: \_\_DATA.\_\_const ist nicht garantiert konstant (write permissions), ebenso wenig andere Pointer und die GOT. Dieser Abschnitt macht `__const`, einige Initializer und die GOT-Tabelle (nachdem sie aufgelöst wurde) mit `mprotect` **read only**.
- **`__AUTH` / `__AUTH_CONST`**: Häufig in neueren Apple-Silicon-Binaries. Diese Segmente enthalten Pointer, die beim Laden oder zur Laufzeit authentifiziert werden müssen (zum Beispiel `__auth_got`). Wenn ein Rebiding-, Hook- oder Import-Patching-Trick nur die alten `__got` / `__la_symbol_ptr`-Sektionen prüft, kann er die echten Call Sites in modernen `arm64e`-Binaries übersehen. Für weitere Details zu diesen Sections siehe [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Enthält Informationen für den Linker (dyld) wie Symbol-, String- und Relocation-Tabelleneinträge. Es ist ein generischer Container für Inhalte, die weder in `__TEXT` noch in `__DATA` liegen, und sein Inhalt wird in anderen load commands beschrieben.
- dyld information: Rebase-, Non-lazy/lazy/weak binding-OpCodes und Export-Info
- Functions starts: Tabelle der Startadressen von Funktionen
- Data In Code: Data Islands in \_\_text
- SYmbol Table: Symbole im binary
- Indirect Symbol Table: Pointer-/Stub-Symbole
- String Table
- Code Signature
- **`__OBJC`**: Enthält Informationen, die von der Objective-C runtime verwendet werden. Diese Informationen können zwar auch im \_\_DATA-Segment innerhalb verschiedener \_\_objc\_\*-Sektionen zu finden sein.
- **`__RESTRICT`**: Ein Segment ohne Inhalt mit einer einzigen Section namens **`__restrict`** (ebenfalls leer), das sicherstellt, dass beim Ausführen des Binarys DYLD-Umgebungsvariablen ignoriert werden.

Wie im code zu sehen war, **unterstützen Segmente auch Flags** (auch wenn sie nicht sehr oft verwendet werden):

- `SG_HIGHVM`: Nur Core (nicht verwendet)
- `SG_FVMLIB`: Nicht verwendet
- `SG_NORELOC`: Segment hat keine relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Wird zum Beispiel von Finder verwendet, um das Text-`__TEXT`-Segment zu verschlüsseln.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** enthält den entrypoint im Attribut **entryoff.** Zur Ladezeit **fügt dyld** diesen Wert einfach zur (im Speicher befindlichen) **base of the binary** hinzu und **springt** dann zu dieser Instruktion, um die Ausführung des Codes des Binarys zu starten.

**`LC_UNIXTHREAD`** enthält die Werte, die die Register beim Start des main thread haben müssen. Das ist bereits veraltet, aber **`dyld`** verwendet es immer noch. Es ist möglich, die von diesem gesetzten Registerwerte zu sehen mit:
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


Enthält Informationen über die **Code-Signatur der Macho-O-Datei**. Sie enthält nur einen **Offset**, der auf den **Signature Blob** **zeigt**. Dieser befindet sich typischerweise ganz am Ende der Datei.\
Allerdings findest du einige Informationen zu diesem Abschnitt in [**diesem Blogbeitrag**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) und in diesen [**Gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Unterstützung für Binary-Verschlüsselung. Allerdings kann ein Angreifer natürlich, wenn er den Prozess kompromittiert, den Speicher unverschlüsselt dumpen.

### **`LC_LOAD_DYLINKER`**

Enthält den **Pfad zur ausführbaren Dynamic Linker-Datei**, die Shared Libraries in den Adressraum des Prozesses mappt. Der **Wert ist immer auf `/usr/lib/dyld` gesetzt**. Wichtig ist, dass in macOS das Mapping von dylibs im **User Mode** und nicht im Kernel Mode erfolgt.

### **`LC_IDENT`**

Veraltet, aber wenn das Erzeugen von Dumps bei einem Panic konfiguriert ist, wird ein Mach-O-Core-Dump erstellt und die Kernel-Version im `LC_IDENT`-Command gesetzt.

### **`LC_UUID`**

Zufällige UUID. Direkt ist sie für nichts nützlich, aber XNU cached sie zusammen mit den übrigen Prozessinformationen. Sie kann in Crash Reports verwendet werden.

### **`LC_BUILD_VERSION`**

Moderne Binärdateien tragen normalerweise diesen Command, um die **Target-Plattform**, die **minimale OS-Version**, die **SDK-Version** und optional die **Tool-Versionen** anzugeben, die verwendet wurden, um diesen Slice zu bauen. Aus offensiver/Reversing-Sicht ist das sehr nützlich, um zu erkennen, wie ein Sample gebaut wurde, und um schnell auffällige Universal Binaries zu identifizieren, bei denen ein Slice mit einem anderen SDK oder Deployment Target kompiliert wurde. Ältere Binärdateien können stattdessen weiterhin `LC_VERSION_MIN_*` verwenden.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Ermöglicht es, dem dyld vor der Ausführung des Prozesses Umgebungsvariablen mitzugeben. Dies kann sehr gefährlich sein, da es das Ausführen beliebigen Codes innerhalb des Prozesses erlauben kann, daher wird dieser load command nur in dyld-Builds mit `#define SUPPORT_LC_DYLD_ENVIRONMENT` verwendet und schränkt die Verarbeitung zusätzlich auf Variablen der Form `DYLD_..._PATH` ein, die load paths angeben.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Neuere Toolchains speichern Export-/Bind-/Rebase-Metadaten häufig in diesen Commands statt sich nur auf die älteren `LC_DYLD_INFO[_ONLY]` opcodes zu verlassen. Beide sind `linkedit_data_command`-Einträge, die auf **`__LINKEDIT`** zeigen:

- **`LC_DYLD_EXPORTS_TRIE`**: Kompakter Trie mit den von dem Image exportierten Symbolen.
- **`LC_DYLD_CHAINED_FIXUPS`**: Fixup-Ketten pro Segment, die von dyld verwendet werden, um rebases und binds anzuwenden. Auf Apple Silicon wirst du hier auch viele moderne authenticated pointer fixups finden.

Diese Metadaten sind sehr hilfreich beim Rekonstruieren von imports/exports, beim Verstehen, warum eine mit `@rpath` geladene Abhängigkeit so aufgelöst wurde, oder beim Herausfinden, warum ein Hook-/Rebinding-Versuch auf einem modernen `arm64e`-Ziel fehlgeschlagen ist. `dyld_info` kann auch gegen **cache-only dylib paths** verwendet werden, die nicht als eigenständige Dateien auf der Festplatte existieren, was auf modernem macOS sehr nützlich ist, da viele Systembibliotheken nur im shared cache liegen.
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Dieser moderne Load-Command ist vor allem relevant, wenn man **kernel collections / kernelcache-style filesets** untersucht. Statt ein einzelnes, eigenständiges Image darzustellen, fungiert das äußere Mach-O als Container, und jeder `LC_FILESET_ENTRY` verweist auf ein eingebettetes Mach-O mit einer eigenen pfadähnlichen **entry id**, VM-Adresse und Datei-Offset. Wenn du moderne macOS/iOS Kernel-Komponenten rückentwickelst, ist dieser Command oft die Brücke zwischen dem Top-Level-Container und dem tatsächlichen Image, das du extrahieren oder disassemblen willst.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Für praktische Extraktions-Workflows siehe [diese andere Seite über macOS-Kernel-Extensions und kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Dieser Load-Command beschreibt eine **dynamische** **Library**-Abhängigkeit, die den **Loader** (dyld) **anweist**, die genannte Library **zu laden und zu verknüpfen**. Es gibt einen `LC_LOAD_DYLIB`-Load-Command **für jede Library**, die das Mach-O-Binary benötigt.

- Dieser Load-Command ist eine Struktur vom Typ **`dylib_command`** (die eine struct dylib enthält, welche die eigentliche abhängige dynamische Library beschreibt):
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
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t compatibility version; / library's compatibility vers number /](<../../../images/image (486).png>)

Diese Information könntest du auch über die CLI erhalten mit:
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
> Ein Mach-O-Binary kann einen oder **mehrere** **Konstruktoren** enthalten, die **vor** der in **LC_MAIN** angegebenen Adresse **ausgeführt** werden.\
> Die Offsets aller Konstruktoren werden im Abschnitt **\_\_mod_init_func** des Segments **\_\_DATA_CONST** gehalten.

## **Mach-O Data**

Im Kern der Datei liegt der Datenbereich, der aus mehreren Segmenten besteht, wie im load-commands-Bereich definiert. **Eine Vielzahl von Datenabschnitten kann innerhalb jedes Segments enthalten sein**, wobei jeder Abschnitt **Code oder Daten** enthält, die für einen Typ spezifisch sind.

> [!TIP]
> Die Daten sind im Grunde der Teil, der alle **Informationen** enthält, die von den load commands **LC_SEGMENTS_64** geladen werden

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Dies umfasst:

- **Function table:** Welche Informationen über die Programmfunktionen enthält.
- **Symbol table**: Welche Informationen über die vom Binary verwendete externe Funktion enthält
- Es könnte auch interne Funktionen, Variablennamen und mehr enthalten.

Um dies zu überprüfen, könntest du das Tool [**Mach-O View**](https://sourceforge.net/projects/machoview/) verwenden:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Oder über die cli:
```bash
size -m /bin/ls
```
## Objetive-C Common Sections

In `__TEXT` segment (r-x):

- `__objc_classname`: Klassennamen (strings)
- `__objc_methname`: Methodennamen (strings)
- `__objc_methtype`: Methodentypen (strings)

In `__DATA` segment (rw-):

- `__objc_classlist`: Pointer auf alle Objetive-C-Klassen
- `__objc_nlclslist`: Pointer auf Non-Lazy Objective-C-Klassen
- `__objc_catlist`: Pointer auf Categories
- `__objc_nlcatlist`: Pointer auf Non-Lazy Categories
- `__objc_protolist`: Protokollliste
- `__objc_const`: Konstante Daten
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
{{#include ../../../banners/hacktricks-training.md}}
