# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Binaries dla Mac OS są zwykle kompilowane jako **universal binaries**. **Universal binary** może **obsługiwać wiele architektur w tym samym pliku**.

Te binaries są zgodne ze **strukturą Mach-O**, która zasadniczo składa się z:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Wyszukaj plik za pomocą: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

Header zawiera bajty **magic**, po których następuje **liczba** **architektur**, które plik **zawiera** (`nfat_arch`), a każda architektura będzie miała strukturę `fat_arch`.

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

lub za pomocą narzędzia [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Jak można się domyślać, universal binary skompilowany dla 2 architektur zwykle **podwaja rozmiar** w porównaniu z binary skompilowanym tylko dla 1 architektury.

> [!TIP]
> Podczas triage malware lub podejrzanych aplikacji nie kończ pracy po tym, jak `file` zgłosi „najlepszą” architekturę. Universal binary może ukrywać różne imports, load commands lub metadane compilera w każdym slice, dlatego najpierw wylicz **wszystkie** slice, a następnie analizuj je niezależnie:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Nowsze macOS SDK udostępniają również funkcje pomocnicze, takie jak `macho_for_each_slice()` i `macho_best_slice()` w `<mach-o/utils.h>`. Ta druga jest przydatna do emulowania tego, co załadowałyby dyld/kernel, ale skanery nadal powinny iterować po każdym slice, aby uniknąć pominięcia zawartości specyficznej dla danej architektury.<sup>[1]</sup>

## **Nagłówek Mach-O**

Nagłówek zawiera podstawowe informacje o pliku, takie jak magic bytes identyfikujące go jako plik Mach-O oraz informacje o docelowej architekturze. Można go znaleźć za pomocą: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Istnieją różne typy plików, można je znaleźć zdefiniowane w [**kodzie źródłowym, na przykład tutaj**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Najważniejsze z nich to:

- `MH_OBJECT`: Relokowalny plik obiektowy (pośrednie produkty kompilacji, które nie są jeszcze plikami wykonywalnymi).
- `MH_EXECUTE`: Pliki wykonywalne.
- `MH_FVMLIB`: Plik biblioteki stałej VM.
- `MH_CORE`: Zrzuty kodu.
- `MH_PRELOAD`: Wstępnie załadowany plik wykonywalny (nie jest już obsługiwany w XNU).
- `MH_DYLIB`: Biblioteki dynamiczne.
- `MH_DYLINKER`: Dynamiczny linker.
- `MH_BUNDLE`: „Pliki wtyczek”. Generowane za pomocą `-bundle` w gcc i jawnie ładowane przez `NSBundle` lub `dlopen`.
- `MH_DYSM`: Towarzyszący plik `.dSym` (plik z symbolami używanymi podczas debugowania).
- `MH_KEXT_BUNDLE`: Rozszerzenia jądra.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Lub za pomocą [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Flagi Mach-O**

Kod źródłowy definiuje również kilka flag przydatnych podczas ładowania bibliotek:

- `MH_NOUNDEFS`: Brak niezdefiniowanych odwołań (w pełni zlinkowany)
- `MH_DYLDLINK`: Linkowanie przez Dyld
- `MH_PREBOUND`: Dynamiczne odwołania są prebound.
- `MH_SPLIT_SEGS`: Plik dzieli segmenty tylko do odczytu i do odczytu/zapisu.
- `MH_WEAK_DEFINES`: Binary zawiera symbole zdefiniowane jako weak
- `MH_BINDS_TO_WEAK`: Binary używa symboli weak
- `MH_ALLOW_STACK_EXECUTION`: Ustawia stos jako wykonywalny
- `MH_NO_REEXPORTED_DYLIBS`: Biblioteka nie zawiera poleceń LC_REEXPORT
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Istnieje sekcja zawierająca zmienne lokalne dla wątków
- `MH_NO_HEAP_EXECUTION`: Brak wykonywania dla stron heap/data
- `MH_HAS_OBJC`: Binary zawiera sekcje oBject-C
- `MH_SIM_SUPPORT`: Obsługa Simulator
- `MH_DYLIB_IN_CACHE`: Używane dla dylib/frameworks w shared library cache.

## **Polecenia ładowania Mach-O**

**Układ pliku w pamięci** jest określony tutaj, z uwzględnieniem **lokalizacji tablicy symboli**, kontekstu głównego wątku w momencie rozpoczęcia wykonywania oraz wymaganych **shared libraries**. Dynamic loaderowi **(dyld)** przekazywane są instrukcje dotyczące procesu ładowania binary do pamięci.

Wykorzystuje strukturę **load_command**, zdefiniowaną we wspomnianym pliku **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Istnieje około **50 różnych typów load commands**, które system obsługuje w różny sposób. Najczęściej używane to: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` oraz `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Zasadniczo ten typ Load Command definiuje **sposób ładowania segmentów \_\_TEXT** (kodu wykonywalnego) **i \_\_DATA** (danych procesu) **zgodnie z offsetami wskazanymi w sekcji Data**, gdy binary jest wykonywany.

Te commands **definiują segmenty**, które są **mapowane** do **wirtualnej przestrzeni pamięci** procesu podczas jego wykonywania.

Istnieją **różne typy** segmentów, takie jak segment **\_\_TEXT**, zawierający kod wykonywalny programu, oraz segment **\_\_DATA**, zawierający dane używane przez proces. Te **segmenty znajdują się w sekcji danych** pliku Mach-O.

**Każdy segment** może być dodatkowo **podzielony** na wiele **sekcji**. **Struktura load command** zawiera **informacje** o **tych sekcjach** w obrębie odpowiedniego segmentu.

W nagłówku najpierw znajduje się **nagłówek segmentu**:

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

Ten nagłówek definiuje **liczbę sekcji, których nagłówki znajdują się za nim**:
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

Jeśli **dodasz** **offset sekcji** (0x37DC) do **offsetu**, pod którym zaczyna się **arch**, w tym przypadku `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Możliwe jest również uzyskanie **informacji o nagłówkach** z poziomu **wiersza poleceń** za pomocą:
```bash
otool -lv /bin/ls
```
Typowe segmenty ładowane przez to polecenie:

- **`__PAGEZERO`:** Nakazuje kernelowi **zmapować** **adres zero**, aby nie można było z niego **czytać, zapisywać do niego ani wykonywać z niego kodu**. Zmienne maxprot i minprot w strukturze są ustawione na zero, co wskazuje, że **ta strona nie ma praw odczytu-zapisu-wykonania**.
- Ta alokacja jest ważna, ponieważ **ogranicza podatności typu NULL pointer dereference**. Dzieje się tak, ponieważ XNU wymusza twardą stronę zero, która zapewnia, że pierwsza strona (i tylko pierwsza) pamięci jest niedostępna (z wyjątkiem i386). Binary może spełnić to wymaganie, tworząc mały \_\_PAGEZERO (przy użyciu `-pagezero_size`), aby objąć pierwsze 4k, a następnie udostępniając resztę pamięci 32-bitowej zarówno w trybie użytkownika, jak i kernela.
- **`__TEXT`**: Zawiera **wykonywalny** **kod** z uprawnieniami **odczytu** i **wykonania** (bez możliwości zapisu)**.** Typowe sekcje tego segmentu:
- `__text`: Skompilowany kod binary
- `__const`: Stałe dane (tylko do odczytu)
- `__[c/u/os_log]string`: Stałe tekstowe C, Unicode lub os log
- `__stubs` i `__stubs_helper`: Używane podczas procesu ładowania dynamic library
- `__unwind_info`: Dane do odwijania stosu.
- Należy zauważyć, że cała ta zawartość jest podpisana, ale również oznaczona jako wykonywalna (co stwarza więcej możliwości exploitacji sekcji, które niekoniecznie wymagają tego uprawnienia, takich jak sekcje przeznaczone na stringi).
- **`__DATA`**: Zawiera dane, które można **odczytywać** i **modyfikować** (bez możliwości wykonywania)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Wskaźnik symbolu non-lazy (bind podczas ładowania)
- `__la_symbol_ptr`: Wskaźnik symbolu lazy (bind podczas użycia)
- `__const`: Powinny to być dane tylko do odczytu (w praktyce nie)
- `__cfstring`: Stringi CoreFoundation
- `__data`: Zmienne globalne (które zostały zainicjalizowane)
- `__bss`: Zmienne statyczne (które nie zostały zainicjalizowane)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist itd.): Informacje używane przez runtime Objective-C
- **`__DATA_CONST`**: \_\_DATA.\_\_const nie gwarantuje stałości (uprawnienia do zapisu), podobnie jak inne wskaźniki i GOT. Ta sekcja sprawia, że `__const`, niektóre initializery oraz tablica GOT (po rozwiązaniu) stają się **tylko do odczytu** przy użyciu `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Często spotykane w nowszych binary dla Apple Silicon. Te segmenty przechowują wskaźniki, które muszą zostać uwierzytelnione podczas ładowania lub użycia (na przykład `__auth_got`). Jeśli trick związany z rebindingiem, hookiem lub patchowaniem importów sprawdza tylko starsze sekcje `__got` / `__la_symbol_ptr`, może pominąć rzeczywiste miejsca wywołań w nowoczesnych binary `arm64e`. Więcej informacji o tych sekcjach znajdziesz na [tej stronie](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Zawiera informacje dla linkera (dyld), takie jak wpisy tablic symboli, stringów i relokacji. Jest to ogólny kontener na zawartość, która nie znajduje się ani w `__TEXT`, ani w `__DATA`, a jego zawartość jest opisana w innych load commands.
- Informacje dyld: Rebase, opcodes wiązania non-lazy/lazy/weak oraz informacje o exportach
- Początki funkcji: Tablica adresów początkowych funkcji
- Data In Code: Wyspy danych w \_\_text
- Tablica symboli: Symbole w binary
- Pośrednia tablica symboli: Symbole wskaźników/stubów
- Tablica stringów
- Code Signature
- **`__OBJC`**: Zawiera informacje używane przez runtime Objective-C. Informacje te mogą również znajdować się w segmencie \_\_DATA, w różnych sekcjach \_\_objc\_\*.
- **`__RESTRICT`**: Segment bez zawartości, z pojedynczą sekcją o nazwie **`__restrict`** (również pustą), który zapewnia, że podczas uruchamiania binary zignoruje zmienne środowiskowe DYLD.

Jak można było zobaczyć w kodzie, **segmenty obsługują również flagi** (chociaż nie są one często używane):

- `SG_HIGHVM`: Tylko Core (nieużywane)
- `SG_FVMLIB`: Nieużywane
- `SG_NORELOC`: Segment nie zawiera relokacji
- `SG_PROTECTED_VERSION_1`: Szyfrowanie. Używane na przykład przez Finder do szyfrowania segmentu tekstowego `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** zawiera punkt wejścia w **atrybucie entryoff**. Podczas ładowania **dyld** po prostu **dodaje** tę wartość do (znajdującej się w pamięci) **bazy binary**, a następnie **przeskakuje** do tej instrukcji, aby rozpocząć wykonywanie kodu binary.

**`LC_UNIXTHREAD`** zawiera wartości, które rejestry muszą mieć podczas uruchamiania głównego wątku. Zostało to już uznane za deprecated, ale **`dyld`** nadal z tego korzysta. Wartości rejestrów ustawione w ten sposób można zobaczyć za pomocą:
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


Zawiera informacje o **code signature pliku Macho-O**. Zawiera jedynie **offset**, który **wskazuje** na **signature blob**. Zwykle znajduje się on na samym końcu pliku.\
Jednak informacje o tej sekcji można znaleźć w [**tym wpisie na blogu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) oraz w tych [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[3][4]</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Obsługa szyfrowania binarnego. Jednak oczywiście, jeśli atakującemu uda się przejąć proces, będzie on w stanie wykonać dump pamięci w postaci niezaszyfrowanej.

### **`LC_LOAD_DYLINKER`**

Zawiera **ścieżkę do pliku wykonywalnego dynamic linker**, który mapuje shared libraries w przestrzeni adresowej procesu. **Wartość jest zawsze ustawiona na `/usr/lib/dyld`**. Należy pamiętać, że w macOS mapowanie dylib odbywa się w **user mode**, a nie w kernel mode.

### **`LC_IDENT`**

Przestarzałe, ale gdy skonfigurowano generowanie dumpów w przypadku panic, tworzony jest Mach-O core dump, a wersja kernela jest ustawiana w komendzie `LC_IDENT`.

### **`LC_UUID`**

Losowy UUID. Sam w sobie nie jest do niczego bezpośrednio przydatny, ale XNU cache’uje go wraz z pozostałymi informacjami o procesie. Może być używany w crash reports.

### **`LC_BUILD_VERSION`**

Nowoczesne binaria zwykle zawierają tę komendę, aby zadeklarować **platformę docelową**, **minimalną wersję systemu operacyjnego**, **wersję SDK** oraz opcjonalnie **wersje narzędzi** użytych do zbudowania danego slice. Z perspektywy offensive/reversing jest to bardzo przydatne do identyfikowania sposobu zbudowania próbki oraz szybkiego wykrywania nietypowych universal binaries, w których jeden slice został skompilowany przy użyciu innego SDK lub deployment target. Starsze binaria mogą zamiast tego nadal używać `LC_VERSION_MIN_*`.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Pozwala wskazać zmienne środowiskowe dla dyld przed wykonaniem procesu. Może to być bardzo niebezpieczne, ponieważ umożliwia wykonanie dowolnego kodu wewnątrz procesu, dlatego ten load command jest używany wyłącznie w buildach dyld z `#define SUPPORT_LC_DYLD_ENVIRONMENT` i dodatkowo ogranicza przetwarzanie tylko do zmiennych w formacie `DYLD_..._PATH`, określających load paths.

### **`LC_DYLD_EXPORTS_TRIE` i `LC_DYLD_CHAINED_FIXUPS`**

Nowsze toolchains często przechowują metadane export/bind/rebase w tych commands zamiast polegać wyłącznie na starszych opcodes `LC_DYLD_INFO[_ONLY]`. Oba są entries typu `linkedit_data_command`, które wskazują na **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Kompaktowe trie zawierające symbols eksportowane przez image.
- **`LC_DYLD_CHAINED_FIXUPS`**: Łańcuchy fixups dla poszczególnych segmentów, używane przez dyld do stosowania rebases i binds. Na Apple Silicon znajduje się tu również wiele współczesnych authenticated pointer fixups.

Te metadane są bardzo przydatne podczas odtwarzania imports/exports, analizowania, dlaczego dependency załadowane przez `@rpath` zostało rozwiązane w określony sposób, lub ustalania, dlaczego próba wykonania hook/rebinding nie powiodła się na nowoczesnym celu `arm64e`. `dyld_info` można również wykorzystać względem **cache-only dylib paths**, które nie istnieją jako samodzielne pliki na dysku. Jest to bardzo przydatne w nowoczesnym macOS, gdzie wiele bibliotek systemowych znajduje się wyłącznie we shared cache.<sup>[2]</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

To nowoczesne polecenie ładowania jest istotne głównie podczas analizowania **kernel collections / kernelcache-style filesets**. Zamiast reprezentować pojedynczy samodzielny obraz, zewnętrzny Mach-O działa jako kontener, a każdy `LC_FILESET_ENTRY` wskazuje osadzony Mach-O z własnym przypominającym ścieżkę **entry id**, adresem VM i przesunięciem w pliku. Jeśli przeprowadzasz reverse engineering nowoczesnych komponentów jądra macOS/iOS, to polecenie często stanowi łącznik między kontenerem najwyższego poziomu a właściwym obrazem, który chcesz wyodrębnić lub zdezasemblować.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
W przypadku praktycznych procedur ekstrakcji sprawdź [tę inną stronę dotyczącą macOS kernel extensions i kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

To polecenie ładowania opisuje zależność od **dynamicznej** **biblioteki**, która **instruuje** **loader** (dyld), aby **załadował i połączył wspomnianą bibliotekę**. Istnieje polecenie ładowania `LC_LOAD_DYLIB` **dla każdej biblioteki**, której wymaga binarny plik Mach-O.

- To polecenie ładowania jest strukturą typu **`dylib_command`** (która zawiera strukturę dylib opisującą faktycznie zależną bibliotekę dynamiczną):
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

Te informacje można również uzyskać z cli za pomocą:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Niektóre biblioteki potencjalnie powiązane ze złośliwym oprogramowaniem to:

- **DiskArbitration**: Monitorowanie dysków USB
- **AVFoundation:** Przechwytywanie dźwięku i obrazu
- **CoreWLAN**: Skanowanie sieci Wi-Fi.

> [!TIP]
> Plik binarny Mach-O może zawierać jeden lub **więcej** **konstruktorów**, które zostaną **wykonane** **przed adresem określonym w** **LC_MAIN**.\
> Offsety dowolnych konstruktorów są przechowywane w sekcji **\_\_mod_init_func** segmentu **\_\_DATA_CONST**.

## **Dane Mach-O**

W centrum pliku znajduje się region danych, który składa się z kilku segmentów zdefiniowanych w regionie load commands. **W każdym segmencie może znajdować się wiele sekcji danych**, a każda sekcja **zawiera kod lub dane** charakterystyczne dla danego typu.

> [!TIP]
> Dane to zasadniczo część zawierająca wszystkie **informacje**, które są ładowane przez load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Obejmuje to:

- **Tabela funkcji:** Zawiera informacje o funkcjach programu.
- **Tabela symboli**: Zawiera informacje o zewnętrznych funkcjach używanych przez plik binarny
- Może również zawierać nazwy funkcji wewnętrznych, zmiennych i inne informacje.

Aby to sprawdzić, możesz użyć narzędzia [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Lub z poziomu CLI:
```bash
size -m /bin/ls
```
## Typowe sekcje Objective-C

W segmencie `__TEXT` (r-x):

- `__objc_classname`: Nazwy klas (ciągi znaków)
- `__objc_methname`: Nazwy metod (ciągi znaków)
- `__objc_methtype`: Typy metod (ciągi znaków)

W segmencie `__DATA` (rw-):

- `__objc_classlist`: Wskaźniki do wszystkich klas Objective-C
- `__objc_nlclslist`: Wskaźniki do Non-Lazy klas Objective-C
- `__objc_catlist`: Wskaźnik do kategorii
- `__objc_nlcatlist`: Wskaźniki do Non-Lazy kategorii
- `__objc_protolist`: Lista protokołów
- `__objc_const`: Dane stałe
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## Odnośniki

- [1] [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [2] [Strona man dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Reading Your Own Entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
