# macOS Universal-Binaries & Mach-O-Format

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

macOS verwendet das ausführbare Format **Mach-O**. Eine **Universal-** oder Fat-Binärdatei enthält mehrere architekturspezifische Mach-O-Slices in einer Datei. Apples Open-Source-Header `fat.h` und `loader.h` definieren die auf dieser Seite beschriebenen Strukturen und Konstanten. <sup>[[5]](#references)</sup>

Ein Mach-O-Image besteht aus:

- Header
- Load Commands
- Daten

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat-Header

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

Der Header enthält die **Magic Bytes**, gefolgt von der **Anzahl** der **Architekturen**, die die Datei **enthält** (`nfat_arch`). Für jede Architektur gibt es eine `fat_arch`-Struktur.

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

oder mit dem Tool [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Wie du dir vielleicht schon denken kannst, ist eine Universal-Binärdatei, die für 2 Architekturen kompiliert wurde, in der Regel **doppelt so groß** wie eine, die nur für 1 Architektur kompiliert wurde.

> [!TIP]
> Wenn du Malware oder verdächtige Apps untersuchst, solltest du nicht aufhören, nachdem `file` die „beste“ Architektur gemeldet hat. Eine Universal-Binärdatei kann in jedem Slice unterschiedliche Imports, Load Commands oder Compiler-Metadaten verbergen. Ermittle deshalb zuerst **alle** Slices und untersuche sie dann einzeln:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Aktuelle macOS-SDKs stellen außerdem `macho_for_each_slice()` und `macho_best_slice()` in `<mach-o/utils.h>` bereit. Auf Apple Silicon konnte `macho_best_slice()` vor macOS 15 für ein ausführbares `arm64`-Binary eines Drittanbieters fälschlicherweise `EBADARCH` zurückgeben; die API wurde in macOS 15 korrigiert. Verwenden Sie `macho_for_each_slice()` oder `lipo -archs`, um alle Slices zu erfassen, statt eine fehlgeschlagene Best-Slice-Suche als Beweis dafür zu werten, dass kein Slice ausgeführt werden kann.<sup>[[1]](#references)[[7]](#references)</sup>

### Code-Signaturen über Slices hinweg vergleichen

Jede Architektur in einem Universal Binary hat ein eigenes CodeDirectory und einen eigenen CDHash. Prüfen Sie bei der Überprüfung eines signierten ausführbaren Programms oder eines privilegierten Helpers die **Signatur jedes Slices**. Ein anderer CDHash ist normal; vergleichen Sie stattdessen die Signieridentität, die CodeDirectory-Flags und die Entitlements.<sup>[[8]](#references)</sup>

Bei Richtlinien, die auf einen CDHash abgleichen, identifiziert ein Hash nur einen architekturspezifischen Ausführungspfad. Apple empfiehlt, die Slices aufzulisten und jedes einzelne mit `codesign --arch` zu prüfen.<sup>[[9]](#references)</sup>

```bash
BIN=/path/to/executable
for A in $(lipo -archs "$BIN"); do
  printf "\n== %s ==\n" "$A"
  codesign -dvvv --arch "$A" "$BIN" 2>&1
  codesign -d --entitlements - --arch "$A" "$BIN"
done
```

Für Details zur Signaturstruktur und Validierung siehe [macOS Code Signing](../macos-security-protections/macos-code-signing.md).

## **Mach-O-Header**

Der Header enthält grundlegende Informationen zur Datei, z. B. Magic Bytes zur Identifizierung als Mach-O-Datei sowie Informationen zur Zielarchitektur. Sie finden ihn mit: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

- `MH_OBJECT`: Verschiebbare Objektdatei (Zwischenprodukte der Kompilierung, noch keine ausführbaren Dateien).
- `MH_EXECUTE`: Ausführbare Dateien.
- `MH_FVMLIB`: Datei einer fest zugeordneten VM-Bibliothek.
- `MH_CORE`: Speicherabbilder
- `MH_PRELOAD`: Vorab geladene ausführbare Datei (wird von XNU nicht mehr unterstützt)
- `MH_DYLIB`: Dynamische Bibliotheken
- `MH_DYLINKER`: Dynamischer Linker
- `MH_BUNDLE`: „Plugin-Dateien“. Werden mit `-bundle` in gcc erstellt und explizit von `NSBundle` oder `dlopen` geladen.
- `MH_DSYM`: Zugehörige `.dSYM`-Datei (Datei mit Symbolen für das Debugging).
- `MH_KEXT_BUNDLE`: Kernel-Erweiterungen.

```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

Or using [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O-Flags**

Der Quellcode definiert außerdem mehrere Flags, die beim Laden von Bibliotheken hilfreich sind:

- `MH_NOUNDEFS`: Keine undefinierten Referenzen (vollständig gelinkt)
- `MH_DYLDLINK`: Dyld-Linking
- `MH_PREBOUND`: Dynamische Referenzen sind vorab gebunden.
- `MH_SPLIT_SEGS`: Die Datei teilt Segmente in schreibgeschützte und beschreibbare Segmente auf.
- `MH_WEAK_DEFINES`: Die Binärdatei enthält schwach definierte Symbole.
- `MH_BINDS_TO_WEAK`: Die Binärdatei verwendet schwache Symbole.
- `MH_ALLOW_STACK_EXECUTION`: Macht den Stack ausführbar.
- `MH_NO_REEXPORTED_DYLIBS`: Die Bibliothek enthält keine LC_REEXPORT-Befehle.
- `MH_PIE`: Positionsunabhängige ausführbare Datei
- `MH_HAS_TLV_DESCRIPTORS`: Es gibt einen Abschnitt mit Thread-Local-Variablen.
- `MH_NO_HEAP_EXECUTION`: Keine Ausführung auf Heap-/Datenseiten
- `MH_HAS_OBJC`: Die Binärdatei enthält Objective-C-Abschnitte.
- `MH_SIM_SUPPORT`: Simulator-Unterstützung
- `MH_DYLIB_IN_CACHE`: Wird für dylibs/Frameworks im Shared-Library-Cache verwendet.

## **Mach-O-Load-Commands**

Das **Speicherlayout der Datei** wird hier festgelegt. Dabei werden der **Speicherort der Symboltabelle**, der Kontext des Hauptthreads zu Beginn der Ausführung und die erforderlichen **Shared Libraries** angegeben. Der dynamische Loader **(dyld)** erhält Anweisungen dazu, wie die Binärdatei in den Speicher geladen werden soll.

Es verwendet die Struktur **load_command**, die in der erwähnten Datei **`loader.h`** definiert ist:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Es gibt etwa **50 verschiedene Arten von Load Commands**, die vom System unterschiedlich behandelt werden. Die häufigsten sind: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` und `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Dieser Typ von Load Command definiert im Wesentlichen, **wie die \_\_TEXT**- (ausführbarer Code) **und \_\_DATA**- (Daten für den Prozess) **Segmente** gemäß den **im Data-Abschnitt angegebenen Offsets** geladen werden, wenn die Binärdatei ausgeführt wird.

Diese Befehle **definieren Segmente**, die bei der Ausführung eines Prozesses in dessen **virtuellen Speicherbereich** **abgebildet** werden.

Es gibt **verschiedene Arten** von Segmenten, etwa das **\_\_TEXT**-Segment, das den ausführbaren Code eines Programms enthält, und das **\_\_DATA**-Segment, das vom Prozess verwendete Daten enthält. Diese **Segmente befinden sich im Data-Abschnitt** der Mach-O-Datei.

**Jedes Segment** kann weiter in mehrere **Abschnitte** **unterteilt** werden. Die **Struktur des Load Command** enthält **Informationen** zu **diesen Abschnitten** innerhalb des jeweiligen Segments.

Im Header kommt zuerst der **Segment-Header**:

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

Dieser Header definiert die **Anzahl der Abschnitte, deren Header danach folgen**:

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

Example eines **Abschnitt-Headers**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Wenn du den **Abschnitts-Offset** (0x37DC) zum **Offset** addierst, an dem die **Architektur beginnt**, in diesem Fall `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Es ist auch möglich, **Header-Informationen** über die **Kommandozeile** abzurufen mit:

```bash
otool -lv /bin/ls
```

Common-Segmente, die von diesem Befehl geladen werden:

- **`__PAGEZERO`:** Weist den Kernel an, die **Adresse null** so zu **mappen**, dass sie **weder gelesen noch beschrieben oder ausgeführt werden kann**. Die Variablen maxprot und minprot in der Struktur werden auf null gesetzt, um anzugeben, dass es für diese Seite **keine Lese-, Schreib- oder Ausführungsrechte gibt**.
  - Diese Zuweisung ist wichtig, um **NULL-Pointer-Dereferenzierungs-Schwachstellen zu entschärfen**. XNU erzwingt eine feste Nullseite, die sicherstellt, dass die erste Speicherseite (nur die erste) nicht zugänglich ist (außer bei i386). Ein Binary könnte diese Anforderungen erfüllen, indem es eine kleine \_\_PAGEZERO erstellt (mithilfe von `-pagezero_size`), die die ersten 4k abdeckt, während der restliche 32-Bit-Speicher im User- und Kernel-Modus zugänglich bleibt.
- **`__TEXT`**: Enthält **ausführbaren** **Code** mit **Lese-** und **Ausführungsberechtigungen** (nicht beschreibbar)**.** Häufige Sections dieses Segments:
  - `__text`: Kompilierter Binary-Code
  - `__const`: Konstanten (nur lesbar)
  - `__[c/u/os_log]string`: String-Konstanten aus C, Unicode oder os logs
  - `__stubs` und `__stubs_helper`: Werden beim Laden dynamischer Libraries verwendet
  - `__unwind_info`: Stack-Unwind-Daten.
  - Beachte, dass all diese Inhalte signiert, aber auch als ausführbar markiert sind (wodurch sich mehr Exploit-Möglichkeiten für Sections ergeben, die dieses Privileg nicht unbedingt benötigen, etwa dedizierte String-Sections).
- **`__DATA`**: Enthält Daten, die **lesbar** und **beschreibbar** (nicht ausführbar) sind)**.**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Non-lazy (Bindung beim Laden) Symbol-Pointer
  - `__la_symbol_ptr`: Lazy (Bindung bei Verwendung) Symbol-Pointer
  - `__const`: Sollte schreibgeschützte Daten enthalten (tut dies aber nicht unbedingt)
  - `__cfstring`: CoreFoundation-Strings
  - `__data`: Globale Variablen (die initialisiert wurden)
  - `__bss`: Statische Variablen (die nicht initialisiert wurden)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist usw.): Informationen, die von der Objective-C-Runtime verwendet werden
- **`__DATA_CONST`**: Für \_\_DATA.\_\_const ist nicht garantiert, dass die Daten konstant sind (Schreibberechtigungen); dasselbe gilt für andere Pointer und die GOT. Dieses Segment macht `__const`, einige Initialisierer und die GOT-Tabelle (nach ihrer Auflösung) mithilfe von `mprotect` **schreibgeschützt**.
- **`__AUTH` / `__AUTH_CONST`**: Häufig in aktuellen Apple-Silicon-Binaries. Diese Segmente enthalten Pointer, die beim Laden oder bei der Verwendung authentifiziert werden müssen (zum Beispiel `__auth_got`). Prüft ein Rebinder-, Hook- oder Import-Patching-Trick nur die alten Sections `__got` / `__la_symbol_ptr`, übersieht er möglicherweise die tatsächlichen Call-Sites in modernen `arm64e`-Binaries. Weitere Informationen zu diesen Sections findest du auf [dieser Seite](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Enthält Informationen für den Linker (dyld), etwa Einträge in Symbol-, String- und Relocation-Tabellen. Es ist ein generischer Container für Inhalte, die sich weder in `__TEXT` noch in `__DATA` befinden; seine Inhalte werden in anderen Load Commands beschrieben.
  - dyld-Informationen: Rebase-, Non-lazy-/Lazy-/Weak-Binding-OpCodes und Export-Informationen
  - Funktionsanfänge: Tabelle mit den Startadressen von Funktionen
  - Data In Code: Dateninseln in \_\_text
  - Symbol-Tabelle: Symbole im Binary
  - Indirect Symbol Table: Pointer-/Stub-Symbole
  - String-Tabelle
  - Code-Signatur
- **`__OBJC`**: Enthält Informationen, die von der Objective-C-Runtime verwendet werden. Diese Informationen können sich jedoch auch im Segment \_\_DATA befinden, und zwar in verschiedenen Sections namens \_\_objc\_\*.
- **`__RESTRICT`**: Ein Segment ohne Inhalt mit einer einzelnen Section namens **`__restrict`** (ebenfalls leer), die sicherstellt, dass beim Ausführen des Binary DYLD-Umgebungsvariablen ignoriert werden.

Wie im Code zu sehen war, **unterstützen Segmente auch Flags** (obwohl sie nicht oft verwendet werden):

- `SG_HIGHVM`: Nur Core (nicht verwendet)
- `SG_FVMLIB`: Nicht verwendet
- `SG_NORELOC`: Segment hat keine Relocation
- `SG_PROTECTED_VERSION_1`: Verschlüsselung. Wird beispielsweise von Finder verwendet, um das `__TEXT`-Segment zu verschlüsseln.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** enthält den Einstiegspunkt im **Attribut entryoff.** Beim Laden **addiert** **dyld** diesen Wert einfach zur (im Speicher befindlichen) **Basisadresse des Binary** und **springt** dann zu dieser Instruktion, um die Ausführung des Binary-Codes zu starten.

**`LC_UNIXTHREAD`** enthält die Werte, die die Register beim Start des Main-Threads haben müssen. Dieser Load Command ist bereits veraltet, wird von **`dyld`** aber weiterhin verwendet. Die damit gesetzten Registerwerte lassen sich wie folgt anzeigen:

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


Enthält Informationen über die **Codesignatur der Mach-O-Datei**. Sie enthält lediglich einen **Offset**, der auf den **Signatur-Blob** **verweist**. Dieser befindet sich typischerweise ganz am Ende der Datei.\
Weitere Informationen zu diesem Abschnitt findest du in [**diesem Blogpost**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) und [**diesem Gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Unterstützung für die Verschlüsselung von Binaries. Wenn es einem Angreifer jedoch gelingt, den Prozess zu kompromittieren, kann er den Speicher unverschlüsselt dumpen.

### **`LC_LOAD_DYLINKER`**

Enthält den **Pfad zum ausführbaren Dynamic Linker**, der Shared Libraries in den Adressraum des Prozesses einbindet. Der **Wert ist immer auf `/usr/lib/dyld` gesetzt**. Wichtig ist, dass in macOS das Mapping von dylibs im **User Mode** und nicht im Kernel Mode erfolgt.

### **`LC_IDENT`**

Veraltet, aber wenn das Erstellen von Dumps bei einem Panic konfiguriert ist, wird ein Mach-O-Core-Dump erstellt und die Kernel-Version im `LC_IDENT`-Befehl festgelegt.

### **`LC_UUID`**

Zufällige UUID. Sie ist für sich genommen nicht nützlich, aber XNU speichert sie zusammen mit den übrigen Prozessinformationen zwischen. Sie kann in Crash-Reports verwendet werden.

### **`LC_BUILD_VERSION`**

Moderne Binaries enthalten üblicherweise diesen Befehl, um die **Zielplattform**, die **minimale OS-Version**, die **SDK-Version** und optional die **zum Erstellen dieses Slices verwendeten Tool-Versionen** anzugeben. Aus offensiver Sicht und für das Reverse Engineering ist dies sehr nützlich, um zu ermitteln, wie ein Sample erstellt wurde, und um ungewöhnliche Universal Binaries schnell zu erkennen, bei denen ein Slice mit einem anderen SDK oder Deployment Target kompiliert wurde. Ältere Binaries können stattdessen weiterhin `LC_VERSION_MIN_*` verwenden.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Ermöglicht, `dyld` Umgebungsvariablen anzugeben, bevor der Prozess ausgeführt wird. Das kann sehr gefährlich sein, da dadurch beliebiger Code innerhalb des Prozesses ausgeführt werden kann. Dieser Load Command wird daher nur in `dyld`-Builds mit `#define SUPPORT_LC_DYLD_ENVIRONMENT` verwendet und beschränkt die Verarbeitung zusätzlich auf Variablen der Form `DYLD_..._PATH`, die Load Paths angeben.

### **`LC_DYLD_EXPORTS_TRIE` und `LC_DYLD_CHAINED_FIXUPS`**

Neuere Toolchains speichern Export-/Bind-/Rebase-Metadaten häufig in diesen Commands, anstatt sich ausschließlich auf die älteren `LC_DYLD_INFO[_ONLY]`-Opcodes zu stützen. Beide sind `linkedit_data_command`-Einträge, die auf **`__LINKEDIT`** verweisen:

- **`LC_DYLD_EXPORTS_TRIE`**: Kompakter Trie mit den vom Image exportierten Symbolen.
- **`LC_DYLD_CHAINED_FIXUPS`**: Fixup-Ketten pro Segment, die `dyld` zum Anwenden von Rebases und Binds verwendet. Auf Apple Silicon finden sich hier auch viele moderne Fixups für authentifizierte Pointer.

Diese Metadaten sind sehr nützlich, um Imports/Exports zu rekonstruieren, zu verstehen, warum eine über `@rpath` geladene Dependency auf eine bestimmte Weise aufgelöst wurde, oder herauszufinden, warum ein Hook-/Rebinding-Versuch auf einem modernen `arm64e`-Ziel fehlschlug. `dyld_info` kann auch auf **cache-only dylib paths** angewendet werden, die nicht als eigenständige Dateien auf dem Datenträger existieren. Das ist auf modernem macOS sehr nützlich, da viele Systembibliotheken nur im Shared Cache vorhanden sind.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Dieser moderne Load Command ist vor allem bei der Untersuchung von **Kernel Collections / Kernelcache-Dateien im Fileset-Format** relevant. Statt ein einzelnes eigenständiges Image darzustellen, dient das äußere Mach-O als Container, und jeder `LC_FILESET_ENTRY` verweist auf ein eingebettetes Mach-O mit einer pfadähnlichen **Entry-ID**, einer VM-Adresse und einem Datei-Offset. Wenn du moderne macOS-/iOS-Kernelkomponenten reverse-engineerst, ist dieser Command oft die Verbindung zwischen dem übergeordneten Container und dem eigentlichen Image, das du extrahieren oder disassemblieren möchtest.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Für praktische Extraktionsabläufe siehe [diese andere Seite über macOS-Kernel-Erweiterungen und kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Dieser Ladebefehl beschreibt eine Abhängigkeit von einer **dynamischen** **Bibliothek**, die den **Loader** (dyld) **anweist, diese Bibliothek zu laden und zu linken**. Für jede Bibliothek, die die Mach-O-Binärdatei benötigt, gibt es einen `LC_LOAD_DYLIB`-Ladebefehl.

- Dieser Ladebefehl ist eine Struktur vom Typ **`dylib_command`** (die eine Struct `dylib` enthält, welche die tatsächliche abhängige dynamische Bibliothek beschreibt):

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

Diese Informationen kannst du auch über die CLI abrufen:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Einige potenziell mit Malware in Verbindung stehende Bibliotheken sind:

- **DiskArbitration**: Überwachen von USB-Laufwerken
- **AVFoundation:** Audio und Video aufnehmen
- **CoreWLAN**: WLAN-Scans.

> [!TIP]
> Eine Mach-O-Binärdatei kann einen oder **mehrere** **Konstruktoren** enthalten, die **ausgeführt** werden, **bevor** die in **LC_MAIN** angegebene Adresse erreicht wird.\
> Die Offsets aller Konstruktoren befinden sich im Abschnitt **\_\_mod_init_func** des Segments **\_\_DATA_CONST**.

## **Mach-O-Daten**

Im Kern der Datei befindet sich der Datenbereich, der aus mehreren Segmenten besteht, wie sie im Bereich der Load Commands definiert sind. **Jedes Segment kann verschiedene Datenabschnitte enthalten**, wobei jeder Abschnitt **Code oder Daten** eines bestimmten Typs enthält.

> [!TIP]
> Die Daten bilden im Wesentlichen den Teil, der alle durch die Load Commands **LC_SEGMENTS_64** geladenen **Informationen** enthält.

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Dazu gehören:

- **Funktionstabelle:** Enthält Informationen zu den Programmfunktionen.
- **Symboltabelle**: Enthält Informationen zu den externen Funktionen, die von der Binärdatei verwendet werden.
- Sie kann auch interne Funktionen, Variablennamen und mehr enthalten.

Um dies zu überprüfen, können Sie das Tool [**Mach-O View**](https://sourceforge.net/projects/machoview/) verwenden:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Oder über die CLI:

```bash
size -m /bin/ls
```

### Angehängte Daten und rückwärts geparste Overlays

Ein Loader kann Konfiguration in angehängten Daten statt in einer benannten Mach-O-Sektion speichern. Ein Reverse-Parser orientiert sich dann an einer Trailer-Markierung, liest eine unmittelbar davor gespeicherte Größe und verwendet diesen Wert, um den vorangehenden Blob zu lokalisieren und zu entschlüsseln. Ein beobachteter universeller Loader verwendete dieses Layout für eine XOR-verschlüsselte Downloader-URL:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Beim Reverse Engineering einer unbekannten Binary solltest du Bytes in der Nähe erkennbarer Endmarker untersuchen und jede rückwärts ausgeführte Größenberechnung nachvollziehen, bevor du annimmst, dass Strings oder Konfiguration zu einem Load-Command-Abschnitt gehören müssen. Marker und XOR-Schlüssel sind spezifisch für das jeweilige Sample; die wiederverwendbare Technik ist der selbsterklärende Trailer.

## Gängige Objective-C-Sections

Im Segment `__TEXT` (r-x):

- `__objc_classname`: Klassennamen (Strings)
- `__objc_methname`: Methodennamen (Strings)
- `__objc_methtype`: Methodentypen (Strings)

Im Segment `__DATA` (rw-):

- `__objc_classlist`: Zeiger auf alle Objective-C-Klassen
- `__objc_nlclslist`: Zeiger auf nicht-lazy Objective-C-Klassen
- `__objc_catlist`: Zeiger auf Kategorien
- `__objc_nlcatlist`: Zeiger auf nicht-lazy Kategorien
- `__objc_protolist`: Protokollliste
- `__objc_const`: Konstantendaten
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

Siehe auch: [Reflective Mach-O Loading](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [1] [Mach-O-Slices sind nicht so unkompliziert, wie du vielleicht denkst](https://objective-see.org/blog/blog_0x80.html)
- [2] [dyld_info(1)-Manpage](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Die eigenen Entitlements auslesen](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source – Mach-O `fat.h` und `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist – Eine neue Version des MacSync-macOS-Stealers zielt auf Krypto-Enthusiasten und Entwickler ab](https://securelist.com/macsync-new-version/121383/)
- [7] [Die Kunst der Mac-Malware, Band 2 – Binaries parsen](https://taomm.org/vol2/pdfs/CH%202%20Parsing%20Binaries.pdf)
- [8] [Apple Developer — TN3126: Einblick in Code Signing: Hashes](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes.md)
- [9] [Apple Developer — Apps und Binaries erlauben und verweigern](https://developer.apple.com/documentation/devicemanagement/allowing-and-denying-apps-and-binaries.md)
{{#include ../../../banners/hacktricks-training.md}}
