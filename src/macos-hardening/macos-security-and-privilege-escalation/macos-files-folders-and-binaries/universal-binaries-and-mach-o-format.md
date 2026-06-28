# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Binaria Mac OS zwykle są kompilowane jako **universal binaries**. **Universal binary** może **obsługiwać wiele architektur w tym samym pliku**.

Te binaria są zgodne ze strukturą **Mach-O**, która zasadniczo składa się z:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Szukaj pliku za pomocą: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Nagłówek ma bajty **magic**, po których następuje **liczba** **archs**, które plik **zawiera** (`nfat_arch`), a każda arch będzie miała strukturę `fat_arch`.

Sprawdź to za pomocą:

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

albo używając narzędzia [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Jak możesz się domyślać, zwykle universal binary skompilowany dla 2 architektur **podwaja rozmiar** tego skompilowanego dla tylko 1 arch.

> [!TIP]
> When triaging malware or suspicious apps, don't stop after `file` reports the "best" architecture. A universal binary can hide different imports, load commands or compiler metadata in each slice, so enumerate **all** the slices first and then inspect them independently:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Nowsze macOS SDKs udostępniają także helpery takie jak `macho_for_each_slice()` i `macho_best_slice()` w `<mach-o/utils.h>`. Ten drugi jest przydatny do emulowania tego, co załadowałby dyld/kernel, ale skanery powinny nadal iterować po każdym slice, aby nie pominąć treści specyficznej dla architektury.

## **Mach-O Header**

Header zawiera podstawowe informacje o pliku, takie jak magic bytes identyfikujące go jako plik Mach-O oraz informacje o docelowej architekturze. Możesz go znaleźć w: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Typy plików Mach-O

Istnieją różne typy plików, możesz je znaleźć zdefiniowane w [**source code na przykład tutaj**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Najważniejsze z nich to:

- `MH_OBJECT`: Relocatable object file (produkty pośrednie kompilacji, jeszcze nie executables).
- `MH_EXECUTE`: Pliki wykonywalne.
- `MH_FVMLIB`: Fixed VM library file.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Preloaded executable file (już nieobsługiwany w XNU)
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin files". Generowane przy użyciu -bundle w gcc i ładowane jawnie przez `NSBundle` lub `dlopen`.
- `MH_DYSM`: Plik towarzyszący `.dSym` (plik z symbolami do debugowania).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Albo użyj [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

Kod źródłowy definiuje też kilka flag przydatnych do ładowania bibliotek:

- `MH_NOUNDEFS`: Brak niezdefiniowanych odwołań (w pełni zlinkowany)
- `MH_DYLDLINK`: Łączenie z Dyld
- `MH_PREBOUND`: Dynamiczne odwołania wstępnie związane.
- `MH_SPLIT_SEGS`: Plik dzieli segmenty r/o i r/w.
- `MH_WEAK_DEFINES`: Binary ma słabo zdefiniowane symbole
- `MH_BINDS_TO_WEAK`: Binary używa słabych symboli
- `MH_ALLOW_STACK_EXECUTION`: Uczyń stos wykonywalnym
- `MH_NO_REEXPORTED_DYLIBS`: Biblioteka nie ma komend LC_REEXPORT
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Istnieje sekcja ze zmiennymi lokalnymi wątku
- `MH_NO_HEAP_EXECUTION`: Brak wykonywania dla stron heap/data
- `MH_HAS_OBJC`: Binary ma sekcje oBject-C
- `MH_SIM_SUPPORT`: Wsparcie dla simulator
- `MH_DYLIB_IN_CACHE`: Używane na dylibs/frameworks w shared library cache.

## **Mach-O Load commands**

**Układ pliku w pamięci** jest tutaj określony, z wyszczególnieniem **lokalizacji tabeli symboli**, kontekstu głównego wątku przy starcie wykonania oraz wymaganych **shared libraries**. Instrukcje są przekazywane do dynamicznego loadera **(dyld)** dotyczące procesu ładowania binary do pamięci.

Używa struktury **load_command**, zdefiniowanej w wspomnianym **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Istnieje około **50 różnych typów load commands**, które system obsługuje w różny sposób. Najczęstsze z nich to: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` oraz `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Zasadniczo ten typ Load Command definiuje, **jak załadować segmenty \_\_TEXT** (wykonywalny kod) **i \_\_DATA** (dane procesu) **zgodnie z offsetami wskazanymi w sekcji Data** podczas wykonywania binarki.

Te polecenia **definiują segmenty**, które są **mapowane** do **przestrzeni pamięci wirtualnej** procesu podczas jego uruchomienia.

Istnieją **różne typy** segmentów, takie jak segment **\_\_TEXT**, który przechowuje wykonywalny kod programu, oraz segment **\_\_DATA**, który zawiera dane używane przez proces. Te **segmenty znajdują się w sekcji data** pliku Mach-O.

**Każdy segment** może być dalej **podzielony** na wiele **sekcji**. Struktura **load command** zawiera **informacje** o **tych sekcjach** w odpowiednim segmencie.

W nagłówku najpierw znajdujesz **nagłówek segmentu**:

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

Przykład nagłówka segmentu:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Ten nagłówek definiuje **liczbę sekcji, których nagłówki pojawiają się po nim**:
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
Przykład **nagłówka sekcji**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Jeśli **dodasz** **offset sekcji** (0x37DC) + **offset**, gdzie **zaczyna się architektura**, w tym przypadku `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Możliwe jest też uzyskanie **informacji o nagłówkach** z **wiersza poleceń** za pomocą:
```bash
otool -lv /bin/ls
```
Common segments ładowane przez ten cmd:

- **`__PAGEZERO`:** Nakazuje kernelowi **zmapować** **address zero**, tak aby **nie można było go czytać, zapisywać ani wykonywać**. Zmienne maxprot i minprot w strukturze są ustawione na zero, aby wskazać, że na tej stronie nie ma **uprawnień read-write-execute**.
- To przydzielenie jest ważne, aby **mitigate NULL pointer dereference vulnerabilities**. Dzieje się tak, ponieważ XNU wymusza hard page zero, co zapewnia, że pierwsza strona (tylko pierwsza) pamięci jest niedostępna (z wyjątkiem i386). Binary mógłby spełnić to wymaganie, tworząc małe \_\_PAGEZERO (używając `-pagezero_size`), aby pokryć pierwsze 4k, i mając resztę 32bit memory dostępną zarówno w user, jak i kernel mode.
- **`__TEXT`**: Zawiera **wykonywalny** **code** z uprawnieniami **read** i **execute** (bez writable)**.** Common sections tego segmentu:
- `__text`: Skompilowany binary code
- `__const`: Constant data (read only)
- `__[c/u/os_log]string`: C, Unicode lub os logs string constants
- `__stubs` and `__stubs_helper`: Uczestniczą podczas procesu ładowania dynamic library
- `__unwind_info`: Stack unwind data.
- Zwróć uwagę, że cały ten content jest signed, ale też oznaczony jako wykonywalny (co daje więcej opcji exploitation sekcji, które niekoniecznie potrzebują tego privilege, jak sekcje przeznaczone na stringi).
- **`__DATA`**: Zawiera data, która jest **readable** i **writable** (bez executable)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Should be read-only data (not really)
- `__cfstring`: CoreFoundation strings
- `__data`: Global variables (that have been initialized)
- `__bss`: Static variables (that have not been initialized)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Information used by the Objective-C runtime
- **`__DATA_CONST`**: \_\_DATA.\_\_const nie ma gwarancji, że jest constant (write permissions), podobnie jak inne pointers i GOT. Ta sekcja sprawia, że `__const`, niektóre initializers i tabela GOT (po rozwiązaniu) są **read only** przy użyciu `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Częste w nowszych binary Apple Silicon. Te segmenty przechowują pointers, które muszą zostać authenticated przy load albo use time (na przykład `__auth_got`). Jeśli rebinding, hook albo trik import-patching sprawdza tylko legacy sekcje `__got` / `__la_symbol_ptr`, może pominąć prawdziwe call sites w nowoczesnych binary `arm64e`. Po więcej szczegółów o tych sekcjach sprawdź [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Zawiera informacje dla linkera (dyld), takie jak wpisy w tabeli symbol, string i relocation. To ogólny container dla zawartości, które nie są ani w `__TEXT`, ani w `__DATA`, a jego content jest opisany w innych load commands.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes i export info
- Functions starts: Tabela adresów startowych functions
- Data In Code: Data islands w \_\_text
- SYmbol Table: Symbols w binary
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Zawiera informacje używane przez Objective-C runtime. Chociaż te informacje mogą też znajdować się w segmencie \_\_DATA, w różnych sekcjach \_\_objc\_\*.
- **`__RESTRICT`**: Segment bez contentu z pojedynczą sekcją o nazwie **`__restrict`** (też pustą), która zapewnia, że podczas uruchamiania binary zignoruje DYLD environmental variables.

Jak było widać w code, **segments also support flags** (choć nie są używane zbyt często):

- `SG_HIGHVM`: Tylko core (not used)
- `SG_FVMLIB`: Not used
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Używane na przykład przez Finder do encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** zawiera entrypoint w atrybucie **entryoff.** W czasie load, **dyld** po prostu **dodaje** tę wartość do (w pamięci) **base of the binary**, a następnie **jumps** do tej instrukcji, aby rozpocząć execution code binary.

**`LC_UNIXTHREAD`** zawiera wartości, jakie register musi mieć przy uruchamianiu main thread. To było już deprecated, ale **`dyld`** nadal tego używa. Można zobaczyć wartości register ustawione przez to za pomocą:
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


Zawiera informacje o **code signature pliku Macho-O**. Zawiera tylko **offset**, który **wskazuje** na **signature blob**. Zwykle znajduje się on na samym końcu pliku.\
Możesz jednak znaleźć pewne informacje o tej sekcji w [**tym poście na blogu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) oraz w tym [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Obsługa szyfrowania binariów. Jednak oczywiście jeśli atakujący zdoła skompromitować proces, będzie mógł zrzucić pamięć w postaci nieszyfrowanej.

### **`LC_LOAD_DYLINKER`**

Zawiera **ścieżkę do wykonywalnego dynamicznego linkera**, który mapuje biblioteki współdzielone do przestrzeni adresowej procesu. **Wartość jest zawsze ustawiona na `/usr/lib/dyld`**. Warto zauważyć, że w macOS mapowanie dylib odbywa się w **trybie użytkownika**, a nie w trybie jądra.

### **`LC_IDENT`**

Przestarzałe, ale gdy skonfigurowano generowanie zrzutów przy panic, tworzony jest Mach-O core dump, a wersja jądra jest ustawiana w poleceniu `LC_IDENT`.

### **`LC_UUID`**

Losowy UUID. Nie jest bezpośrednio użyteczny do niczego, ale XNU buforuje go razem z pozostałymi informacjami o procesie. Może być używany w crash reports.

### **`LC_BUILD_VERSION`**

Nowoczesne binaria zwykle zawierają to polecenie, aby określić **target platform**, **minimalną wersję OS**, **wersję SDK** oraz opcjonalnie **wersje narzędzi** użytych do zbudowania tego slice. Z perspektywy ofensywnej/odwracania to bardzo przydatne do fingerprintingu sposobu budowy próbki i do szybkiego wykrywania dziwnych universal binaries, gdzie jeden slice został skompilowany z innym SDK lub deployment target. Starsze binaria mogą nadal używać zamiast tego `LC_VERSION_MIN_*`.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Pozwala wskazać zmienne środowiskowe dyld przed uruchomieniem procesu. Może to być bardzo niebezpieczne, ponieważ może umożliwić wykonanie arbitralnego kodu wewnątrz procesu, więc ten load command jest używany tylko w buildzie dyld z `#define SUPPORT_LC_DYLD_ENVIRONMENT` i dodatkowo ogranicza przetwarzanie wyłącznie do zmiennych w formie `DYLD_..._PATH`, określających ścieżki ładowania.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Nowsze toolchains często przechowują metadane export/bind/rebase w tych komendach zamiast polegać wyłącznie na starszych opcode'ach `LC_DYLD_INFO[_ONLY]`. Oba są wpisami `linkedit_data_command`, które wskazują do **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Kompaktowe trie z symbolami exportowanymi przez obraz.
- **`LC_DYLD_CHAINED_FIXUPS`**: Łańcuchy fixupów dla poszczególnych segmentów używane przez dyld do wykonywania rebases i binds. Na Apple Silicon to także miejsce, w którym napotkasz wiele nowoczesnych uwierzytelnionych fixupów wskaźników.

Te metadane są bardzo przydatne przy odtwarzaniu imports/exports, zrozumieniu, dlaczego zależność załadowana przez `@rpath` została rozwiązana w taki, a nie inny sposób, albo ustalaniu, dlaczego próba hook/rebinding nie powiodła się na nowoczesnym celu `arm64e`. `dyld_info` można też użyć wobec ścieżek `cache-only` dylib, które nie istnieją jako samodzielne pliki na dysku, co jest bardzo przydatne w nowoczesnym macOS, gdzie wiele bibliotek systemowych istnieje wyłącznie w shared cache.
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

To nowoczesne polecenie ładowania jest głównie istotne podczas analizy **kernel collections / kernelcache-style filesets**. Zamiast reprezentować pojedynczy samodzielny obraz, zewnętrzny Mach-O działa jako kontener, a każdy `LC_FILESET_ENTRY` wskazuje na osadzony Mach-O z własnym, podobnym do ścieżki **entry id**, adresem VM i offsetem pliku. Jeśli odwracasz nowoczesne komponenty jądra macOS/iOS, to polecenie często stanowi most między kontenerem najwyższego poziomu a rzeczywistym obrazem, który chcesz wyodrębnić lub zdeasemblować.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Dla praktycznych workflow ekstrakcji sprawdź [this other page about macOS kernel extensions and kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

To polecenie ładowania opisuje zależność od **dynamicznej** **biblioteki**, która **nakazuje** **loaderowi** (dyld) **załadować i połączyć wskazaną bibliotekę**. Istnieje polecenie ładowania `LC_LOAD_DYLIB` **dla każdej biblioteki**, której wymaga binarka Mach-O.

- To polecenie ładowania jest strukturą typu **`dylib_command`** (która zawiera struct dylib, opisującą rzeczywistą zależną dynamiczną bibliotekę):
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

Możesz też uzyskać te informacje z CLI za pomocą:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Some potential malware related libraries are:

- **DiskArbitration**: Monitorowanie dysków USB
- **AVFoundation:** Przechwytywanie audio i wideo
- **CoreWLAN**: Skanowanie Wifi.

> [!TIP]
> Binarny plik Mach-O może zawierać jeden lub **więcej** **konstruktorów**, które zostaną **wykonane** **przed** adresem określonym w **LC_MAIN**.\
> Offsety wszystkich konstruktorów są przechowywane w sekcji **\_\_mod_init_func** segmentu **\_\_DATA_CONST**.

## **Mach-O Data**

W centrum pliku znajduje się region danych, który składa się z kilku segmentów zdefiniowanych w regionie load-commands. **W każdym segmencie może znajdować się wiele sekcji danych**, a każda sekcja **zawiera kod lub dane** specyficzne dla danego typu.

> [!TIP]
> Dane to zasadniczo część zawierająca wszystkie **informacje** ładowane przez load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Obejmuje to:

- **Function table:** Która zawiera informacje o funkcjach programu.
- **Symbol table**: Która zawiera informacje o funkcji zewnętrznej używanej przez binarkę
- Może też zawierać funkcje wewnętrzne, nazwy zmiennych i więcej.

Aby to sprawdzić, możesz użyć narzędzia [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Albo z poziomu cli:
```bash
size -m /bin/ls
```
## Common sections Objective-C

W segmencie `__TEXT` (r-x):

- `__objc_classname`: Nazwy klas (napisy)
- `__objc_methname`: Nazwy metod (napisy)
- `__objc_methtype`: Typy metod (napisy)

W segmencie `__DATA` (rw-):

- `__objc_classlist`: Wskaźniki do wszystkich klas Objective-C
- `__objc_nlclslist`: Wskaźniki do nie-lazy klas Objective-C
- `__objc_catlist`: Wskaźnik do Categories
- `__objc_nlcatlist`: Wskaźnik do nie-lazy Categories
- `__objc_protolist`: Lista protokołów
- `__objc_const`: Dane stałe
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
{{#include ../../../banners/hacktricks-training.md}}
