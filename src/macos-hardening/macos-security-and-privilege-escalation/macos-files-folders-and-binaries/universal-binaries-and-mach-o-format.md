# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

macOS verwendet das ausführbare Format **Mach-O**. Eine **Universal Binary** oder Fat Binary enthält mehrere architekturspezifische Mach-O-Slices in einer Datei. Apples Open-Source-Header `fat.h` und `loader.h` definieren die auf dieser Seite beschriebenen Strukturen und Konstanten. <sup>[[5]](#references)</sup>

Ein Mach-O-Image besteht aus:

- Header
- Load Commands
- Daten

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Suche die Datei mit: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Der Header enthält zuerst die **Magic Bytes**, gefolgt von der **Anzahl** der **Architekturen**, die die Datei **enthält** (`nfat_arch`). Jede Architektur verfügt über eine `fat_arch`-Struktur.

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

Oder mit dem Tool [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Wie du dir vielleicht schon denken kannst, ist eine Universal Binary, die für 2 Architekturen kompiliert wurde, normalerweise **doppelt so groß** wie eine, die nur für 1 Architektur kompiliert wurde.

> [!TIP]
> Wenn du Malware oder verdächtige Apps untersuchst, solltest du nicht aufhören, nachdem `file` die „beste“ Architektur gemeldet hat. Eine Universal Binary kann in jedem Slice unterschiedliche Imports, Load Commands oder Compiler-Metadaten verbergen. Ermittle daher zuerst **alle** Slices und untersuche sie dann einzeln:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Neuere macOS SDKs stellen außerdem Hilfsfunktionen wie `macho_for_each_slice()` und `macho_best_slice()` in `<mach-o/utils.h>` bereit. Letztere ist nützlich, um nachzubilden, was dyld/der Kernel laden würde. Scanner sollten jedoch weiterhin alle Slices durchlaufen, um architekturspezifische Inhalte nicht zu übersehen.<sup>[[1]](#references)</sup>

## **Mach-O-Header**

Der Header enthält grundlegende Informationen zur Datei, etwa Magic Bytes, die sie als Mach-O-Datei kennzeichnen, sowie Informationen zur Zielarchitektur. Du findest ihn unter: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

Es gibt verschiedene Dateitypen. Sie sind beispielsweise im [**Quellcode hier**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) definiert. Die wichtigsten sind:

- `MH_OBJECT`: Verschiebbares Objektfile (Zwischenprodukt der Kompilierung, noch keine ausführbare Datei).
- `MH_EXECUTE`: Ausführbare Dateien.
- `MH_FVMLIB`: Datei einer Fixed-VM-Bibliothek.
- `MH_CORE`: Core Dumps
- `MH_PRELOAD`: Vorab geladene ausführbare Datei (wird von XNU nicht mehr unterstützt)
- `MH_DYLIB`: Dynamische Bibliotheken
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: „Plug-in-Dateien“. Werden mit `-bundle` in gcc erstellt und explizit über `NSBundle` oder `dlopen` geladen.
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

Der Quellcode definiert außerdem mehrere Flags, die beim Laden von Bibliotheken nützlich sind:

- `MH_NOUNDEFS`: Keine undefinierten Verweise (vollständig gelinkt)
- `MH_DYLDLINK`: Dyld-Verlinkung
- `MH_PREBOUND`: Dynamische Verweise sind vorgebunden.
- `MH_SPLIT_SEGS`: Datei teilt Segmente in schreibgeschützt und lesbar/schreibbar auf.
- `MH_WEAK_DEFINES`: Binärdatei enthält schwach definierte Symbole
- `MH_BINDS_TO_WEAK`: Binärdatei verwendet schwache Symbole
- `MH_ALLOW_STACK_EXECUTION`: Stack ausführbar machen
- `MH_NO_REEXPORTED_DYLIBS`: Bibliothek ohne LC_REEXPORT-Befehle
- `MH_PIE`: Positionsunabhängige ausführbare Datei
- `MH_HAS_TLV_DESCRIPTORS`: Es gibt einen Abschnitt mit threadlokalen Variablen
- `MH_NO_HEAP_EXECUTION`: Keine Ausführung von Heap-/Datenseiten
- `MH_HAS_OBJC`: Binärdatei enthält Objective-C-Abschnitte
- `MH_SIM_SUPPORT`: Simulatorunterstützung
- `MH_DYLIB_IN_CACHE`: Wird für Dylibs/Frameworks im Shared-Library-Cache verwendet.

## **Mach-O-Ladebefehle**

Das **Layout der Datei im Speicher** wird hier festgelegt. Dazu gehören der **Speicherort der Symboltabelle**, der Kontext des Haupt-Threads bei Ausführungsbeginn und die erforderlichen **Shared Libraries**. Dem dynamischen Loader **(dyld)** werden Anweisungen zum Laden der Binärdatei in den Speicher gegeben.

Dabei wird die im genannten **`loader.h`** definierte Struktur **load_command** verwendet:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Es gibt etwa **50 verschiedene Arten von Load Commands**, die vom System unterschiedlich behandelt werden. Die häufigsten sind: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` und `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Im Wesentlichen legt diese Art von Load Command fest, **wie die \_\_TEXT**- (ausführbarer Code) **und \_\_DATA**- (Daten für den Prozess) **Segmente** beim Ausführen der Binärdatei entsprechend den **im Data-Abschnitt angegebenen Offsets** geladen werden.

Diese Commands **definieren Segmente**, die beim Ausführen eines Prozesses in dessen **virtuellen Speicherbereich** **abgebildet** werden.

Es gibt **verschiedene Segmenttypen**, etwa das **\_\_TEXT**-Segment, das den ausführbaren Code eines Programms enthält, und das **\_\_DATA**-Segment, das vom Prozess verwendete Daten enthält. Diese **Segmente befinden sich im Data-Abschnitt** der Mach-O-Datei.

**Jedes Segment** kann weiter in mehrere **Abschnitte** **unterteilt** werden. Die **Struktur des Load Commands** enthält **Informationen** zu **diesen Abschnitten** innerhalb des jeweiligen Segments.

Im Header befindet sich zunächst der **Segment-Header**:

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

Dieser Header gibt die **Anzahl der Abschnitte an, deren Header darauf folgen**:

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

Beispiel für einen **Section-Header**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Wenn du den **Section-Offset** (0x37DC) zum **Offset** addierst, an dem die **Architektur beginnt**, in diesem Fall `0x18000`, erhältst du `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Es ist auch möglich, **Header-Informationen** über die **Kommandozeile** abzurufen:

```bash
otool -lv /bin/ls
```

Gemeinsame Segmente, die von diesem Befehl geladen werden:

- **`__PAGEZERO`:** Weist den Kernel an, die **Adresse null** so zu **mappen**, dass sie **weder gelesen noch beschrieben noch ausgeführt werden kann**. Die Variablen maxprot und minprot in der Struktur werden auf null gesetzt, um anzuzeigen, dass es **auf dieser Seite keine Lese-, Schreib- oder Ausführungsrechte gibt**.
  - Diese Zuweisung ist wichtig, um **NULL-Pointer-Dereference-Schwachstellen zu entschärfen**. XNU erzwingt eine feste Nullseite, die sicherstellt, dass die erste Speicherseite (und nur die erste) nicht zugänglich ist (außer in i386). Eine Binärdatei könnte diese Anforderung erfüllen, indem sie eine kleine \_\_PAGEZERO erstellt (mit `-pagezero_size`), die die ersten 4k abdeckt, und den restlichen 32-Bit-Speicher sowohl im User- als auch im Kernel-Modus zugänglich macht.
- **`__TEXT`**: Enthält **ausführbaren** **Code** mit **Lese-** und **Ausführungsberechtigungen (nicht beschreibbar)**. Häufige Sections dieses Segments:
  - `__text`: Kompilierter Binärcode
  - `__const`: Konstanten (schreibgeschützt)
  - `__[c/u/os_log]string`: C-, Unicode- oder os-Log-Stringkonstanten
  - `__stubs` und `__stubs_helper`: Werden während des dynamischen Bibliotheksladevorgangs verwendet
  - `__unwind_info`: Stack-Unwind-Daten.
  - Beachte, dass all diese Inhalte signiert, aber auch als ausführbar markiert sind (wodurch mehr Möglichkeiten zur Ausnutzung von Sections entstehen, die dieses Privileg nicht unbedingt benötigen, etwa speziell für Strings vorgesehene Sections).
- **`__DATA`**: Enthält Daten, die **lesbar** und **beschreibbar (nicht ausführbar)** sind.
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Nicht-lazy (beim Laden gebundener) Symbolzeiger
  - `__la_symbol_ptr`: Lazy (bei Verwendung gebundener) Symbolzeiger
  - `__const`: Sollte schreibgeschützte Daten enthalten (ist es aber nicht unbedingt)
  - `__cfstring`: CoreFoundation-Strings
  - `__data`: Globale Variablen (die initialisiert wurden)
  - `__bss`: Statische Variablen (die nicht initialisiert wurden)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist usw.): Informationen, die von der Objective-C-Runtime verwendet werden
- **`__DATA_CONST`**: \_\_DATA.\_\_const ist nicht garantiert konstant (Schreibberechtigungen), ebenso wenig wie andere Zeiger und die GOT. Dieses Segment macht `__const`, einige Initialisierer und die GOT-Tabelle (nachdem sie aufgelöst wurde) mithilfe von `mprotect` **schreibgeschützt**.
- **`__AUTH` / `__AUTH_CONST`**: Häufig in neueren Apple-Silicon-Binärdateien. Diese Segmente enthalten Zeiger, die beim Laden oder bei der Verwendung authentifiziert werden müssen (zum Beispiel `__auth_got`). Wenn ein Rebinder, Hook oder Import-Patching-Trick nur die älteren Sections `__got` / `__la_symbol_ptr` prüft, übersieht er möglicherweise die tatsächlichen Aufrufstellen in modernen `arm64e`-Binärdateien. Weitere Informationen zu diesen Sections findest du auf [dieser Seite](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Enthält Informationen für den Linker (dyld), wie Symbol-, String- und Relocation-Tabelleneinträge. Es ist ein allgemeiner Container für Inhalte, die weder in `__TEXT` noch in `__DATA` liegen; seine Inhalte werden in anderen Load Commands beschrieben.
  - dyld-Informationen: Rebase-, Non-lazy-/Lazy-/Weak-Binding-Opcodes und Exportinformationen
  - Funktionsanfänge: Tabelle mit Startadressen von Funktionen
  - Daten im Code: Dateninseln in \_\_text
  - Symboltabelle: Symbole in der Binärdatei
  - Indirekte Symboltabelle: Zeiger-/Stub-Symbole
  - Stringtabelle
  - Codesignatur
- **`__OBJC`**: Enthält Informationen, die von der Objective-C-Runtime verwendet werden. Diese Informationen können jedoch auch im Segment \_\_DATA in verschiedenen \_\_objc\_\*-Sections vorkommen.
- **`__RESTRICT`**: Ein Segment ohne Inhalt mit einer einzelnen Section namens **`__restrict`** (ebenfalls leer), das sicherstellt, dass beim Ausführen der Binärdatei DYLD-Umgebungsvariablen ignoriert werden.

Wie im Code zu sehen war, **unterstützen Segmente auch Flags** (auch wenn sie nicht oft verwendet werden):

- `SG_HIGHVM`: Nur für Core-Dateien (nicht verwendet)
- `SG_FVMLIB`: Nicht verwendet
- `SG_NORELOC`: Segment hat keine Relocation
- `SG_PROTECTED_VERSION_1`: Verschlüsselung. Wird beispielsweise von Finder verwendet, um das `__TEXT`-Segment zu verschlüsseln.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** enthält den Einstiegspunkt im **Attribut entryoff.** Beim Laden **addiert** **dyld** diesen Wert einfach zur (im Speicher befindlichen) **Basis der Binärdatei** und **springt** dann zu dieser Anweisung, um die Ausführung des Binärcodes zu starten.

**`LC_UNIXTHREAD`** enthält die Werte, die die Register beim Start des Hauptthreads haben müssen. Dieser Befehl ist bereits veraltet, wird aber von **`dyld`** weiterhin verwendet. Die damit gesetzten Registerwerte lassen sich wie folgt anzeigen:

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


Enthält Informationen zur **Code-Signatur der Mach-O-Datei**. Es enthält lediglich einen **Offset**, der auf den **Signatur-Blob** **verweist**. Dieser befindet sich normalerweise ganz am Ende der Datei.\
Weitere Informationen zu diesem Abschnitt findest du in [**diesem Blogbeitrag**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) und [**diesem Gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Unterstützung für Binärdateiverschlüsselung. Wenn es einem Angreifer jedoch gelingt, den Prozess zu kompromittieren, kann er den Speicher unverschlüsselt auslesen.

### **`LC_LOAD_DYLINKER`**

Enthält den **Pfad zur ausführbaren Datei des dynamischen Linkers**, der Shared Libraries in den Adressraum des Prozesses lädt. Der **Wert ist immer auf `/usr/lib/dyld` gesetzt**. Wichtig ist, dass das Mapping von dylibs in macOS im **User-Modus** und nicht im Kernel-Modus stattfindet.

### **`LC_IDENT`**

Veraltet, aber wenn das Erstellen von Dumps bei einem Panic konfiguriert ist, wird ein Mach-O-Core-Dump erstellt und die Kernel-Version im Befehl `LC_IDENT` festgelegt.

### **`LC_UUID`**

Zufällige UUID. Sie ist für nichts direkt nützlich, aber XNU speichert sie zusammen mit den übrigen Prozessinformationen zwischen. Sie kann in Crash-Reports verwendet werden.

### **`LC_BUILD_VERSION`**

Moderne Binärdateien enthalten diesen Befehl üblicherweise, um die **Zielplattform**, die **Mindestversion des Betriebssystems**, die **SDK-Version** und optional die zum Erstellen dieses Slices verwendeten **Tool-Versionen** anzugeben. Aus offensiver Sicht und beim Reversing ist dies sehr nützlich, um zu erkennen, wie ein Sample erstellt wurde, und schnell ungewöhnliche Universal-Binärdateien zu entdecken, bei denen ein Slice mit einem anderen SDK oder Deployment Target kompiliert wurde. Ältere Binärdateien verwenden möglicherweise stattdessen noch `LC_VERSION_MIN_*`.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Ermöglicht, Umgebungsvariablen für dyld festzulegen, bevor der Prozess ausgeführt wird. Das kann sehr gefährlich sein, da dadurch beliebiger Code innerhalb des Prozesses ausgeführt werden kann. Daher wird dieses Load Command nur in dyld-Builds mit `#define SUPPORT_LC_DYLD_ENVIRONMENT` verwendet und die Verarbeitung zusätzlich auf Variablen der Form `DYLD_..._PATH` beschränkt, die Ladepfade angeben.

### **`LC_DYLD_EXPORTS_TRIE` und `LC_DYLD_CHAINED_FIXUPS`**

Neuere Toolchains speichern Export-/Bind-/Rebase-Metadaten häufig in diesen Commands, anstatt sich ausschließlich auf die älteren `LC_DYLD_INFO[_ONLY]`-Opcodes zu stützen. Beide sind `linkedit_data_command`-Einträge, die auf **`__LINKEDIT`** verweisen:

- **`LC_DYLD_EXPORTS_TRIE`**: Kompakter Trie mit den vom Image exportierten Symbolen.
- **`LC_DYLD_CHAINED_FIXUPS`**: Fixup-Ketten pro Segment, die dyld zum Anwenden von Rebases und Binds verwendet. Auf Apple Silicon finden sich hier auch viele moderne Fixups für authentifizierte Pointer.

Diese Metadaten sind sehr nützlich, um Imports/Exports zu rekonstruieren, zu verstehen, warum eine über `@rpath` geladene Abhängigkeit auf eine bestimmte Weise aufgelöst wurde, oder herauszufinden, warum ein Hook-/Rebinding-Versuch auf einem modernen `arm64e`-Ziel fehlgeschlagen ist. `dyld_info` kann auch für **Cache-only-Dylib-Pfade** verwendet werden, die nicht als eigenständige Dateien auf der Festplatte existieren. Das ist unter modernem macOS sehr nützlich, da viele Systembibliotheken nur im Shared Cache liegen.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Dieser moderne Ladebefehl ist vor allem relevant, wenn **kernel collections / kernelcache-style filesets** untersucht werden. Statt ein einzelnes eigenständiges Image darzustellen, dient das äußere Mach-O als Container. Jeder `LC_FILESET_ENTRY` verweist auf ein eingebettetes Mach-O mit einer eigenen pfadähnlichen **entry id**, einer VM-Adresse und einem Datei-Offset. Wenn du moderne macOS-/iOS-Kernelkomponenten reverse-engineerst, ist dieser Befehl oft die Verbindung zwischen dem Container der obersten Ebene und dem eigentlichen Image, das du extrahieren oder disassemblieren möchtest.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Für praktische Extraktionsabläufe siehe [diese andere Seite zu macOS-Kernel-Erweiterungen und kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Dieses Load-Kommando beschreibt eine Abhängigkeit von einer **dynamischen** **Bibliothek**, die den **Loader** (dyld) **anweist, diese Bibliothek zu laden und zu linken**. Für **jede Bibliothek**, die das Mach-O-Binary benötigt, gibt es ein `LC_LOAD_DYLIB`-Load-Kommando.

- Dieses Load-Kommando ist eine Struktur vom Typ **`dylib_command`** (die ein Struct dylib enthält, das die tatsächlich abhängige dynamische Bibliothek beschreibt):

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t Kompatibilitätsversion; / Kompatibilitätsversionsnummer der Bibliothek /](<../../../images/image (486).png>)

Du kannst diese Informationen auch über die CLI abrufen:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Einige potenziell malwarebezogene Bibliotheken sind:

- **DiskArbitration**: Überwachen von USB-Laufwerken
- **AVFoundation:** Audio und Video aufnehmen
- **CoreWLAN**: WLAN-Scans.

> [!TIP]
> Ein Mach-O-Binary kann einen oder **mehrere** **Konstruktoren** enthalten, die **ausgeführt** werden, **bevor** die in **LC_MAIN** angegebene Adresse erreicht wird.\
> Die Offsets aller Konstruktoren befinden sich im Abschnitt **\_\_mod_init_func** des Segments **\_\_DATA_CONST**.

## **Mach-O-Daten**

Im Kern der Datei befindet sich die Datenregion, die aus mehreren Segmenten besteht, wie sie in der Load-Commands-Region definiert sind. **Jedes Segment kann verschiedene Datensektionen enthalten**, wobei jede Sektion **Code oder Daten** eines bestimmten Typs enthält.

> [!TIP]
> Die Daten sind im Wesentlichen der Teil, der alle **Informationen** enthält, die von den Load Commands **LC_SEGMENTS_64** geladen werden

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Dazu gehören:

- **Funktionstabelle:** Enthält Informationen über die Programmfunktionen.
- **Symboltabelle**: Enthält Informationen über die vom Binary verwendeten externen Funktionen.
- Sie kann auch interne Funktionen, Variablennamen und mehr enthalten.

Zum Überprüfen können Sie das Tool [**Mach-O View**](https://sourceforge.net/projects/machoview/) verwenden:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Oder über die CLI:

```bash
size -m /bin/ls
```

### Angehängte Daten und rückwärts geparste Overlays

Ein Loader kann Konfigurationen in angehängten Daten statt in einem benannten Mach-O-Abschnitt speichern. Ein Reverse-Parser orientiert sich dann an einer Trailer-Markierung, liest eine unmittelbar davor gespeicherte Größe aus und verwendet diesen Wert, um den vorhergehenden Blob zu lokalisieren und zu entschlüsseln. Ein beobachteter Universal-Loader verwendete dieses Layout für eine XOR-verschlüsselte Downloader-URL:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Beim Reverse Engineering einer unbekannten Binärdatei solltest du die Bytes rund um erkennbare Endmarkierungen untersuchen und jede rückwärts gerichtete Größenberechnung nachvollziehen, bevor du annimmst, dass Strings oder Konfiguration zu einem Load-Command-Abschnitt gehören müssen. Die Markierung und der XOR-Schlüssel sind spezifisch für dieses Sample; die wiederverwendbare Technik ist der selbstbeschreibende Trailer.

## Allgemeine Objective-C-Abschnitte

Im Segment `__TEXT` (r-x):

- `__objc_classname`: Klassennamen (Strings)
- `__objc_methname`: Methodennamen (Strings)
- `__objc_methtype`: Methodentypen (Strings)

Im Segment `__DATA` (rw-):

- `__objc_classlist`: Zeiger auf alle Objective-C-Klassen
- `__objc_nlclslist`: Zeiger auf Non-Lazy-Objective-C-Klassen
- `__objc_catlist`: Zeiger auf Kategorien
- `__objc_nlcatlist`: Zeiger auf Non-Lazy-Kategorien
- `__objc_protolist`: Protokollliste
- `__objc_const`: Konstantendaten
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

Siehe auch: [Reflective Mach-O Loading](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Mach-O-Slices sind nicht so einfach, wie du vielleicht denkst](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1)-Manpage](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Eigene Entitlements auslesen](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source – Mach-O `fat.h` und `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist – Eine neue Version des MacSync-macOS-Stealers hat es auf Krypto-Enthusiasten und Entwickler abgesehen](https://securelist.com/macsync-new-version/121383/)
