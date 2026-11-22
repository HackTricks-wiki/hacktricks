# Uniwersalne pliki binarne macOS i format Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

macOS używa formatu plików wykonywalnych **Mach-O**. **Uniwersalny** plik binarny, nazywany też plikiem fat, zawiera w jednym pliku wiele wycinków Mach-O przeznaczonych dla różnych architektur. Nagłówki `fat.h` i `loader.h` z kodu open source Apple definiują struktury i stałe opisane na tej stronie. <sup>[[5]](#references)</sup>

Obraz Mach-O składa się z:

- Nagłówka
- Poleceń ładowania
- Danych

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Nagłówek fat

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

Nagłówek zawiera bajty **magic**, po których następuje **liczba** **architektur**, które **zawiera** plik (`nfat_arch`); każda architektura ma strukturę `fat_arch`.

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

Jak można się domyślić, uniwersalny plik binarny skompilowany dla 2 architektur **zwykle zajmuje dwa razy więcej miejsca** niż plik skompilowany tylko dla 1 architektury.

> [!TIP]
> Podczas analizy malware lub podejrzanych aplikacji nie poprzestawaj na architekturze „najlepiej” rozpoznanej przez `file`. Uniwersalny plik binarny może zawierać różne importy, polecenia ładowania lub metadane kompilatora w poszczególnych wycinkach, dlatego najpierw wyodrębnij **wszystkie** wycinki, a następnie sprawdź każdy z nich osobno:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Nowsze SDK macOS udostępniają również funkcje `macho_for_each_slice()` i `macho_best_slice()` w `<mach-o/utils.h>`. Na Apple Silicon przed macOS 15 funkcja `macho_best_slice()` mogła nieprawidłowo zwracać `EBADARCH` dla uruchamialnego pliku binarnego `arm64` innej firmy; ten błąd poprawiono w macOS 15. Używaj `macho_for_each_slice()` lub `lipo -archs`, aby wyświetlić wszystkie slice’y, zamiast traktować nieudaną próbę znalezienia najlepszego slice’a jako dowód, że żaden z nich nie może zostać uruchomiony.<sup>[[1]](#references)[[7]](#references)</sup>

### Porównywanie podpisów kodu między slice’ami

Każda architektura w uniwersalnym pliku binarnym ma własne CodeDirectory i CDHash. Podczas audytu podpisanego pliku wykonywalnego lub uprzywilejowanego helpera sprawdź **podpis każdego slice’a**. Różne wartości CDHash są normalne; porównuj tożsamość podpisującego, flagi CodeDirectory i uprawnienia.<sup>[[8]](#references)</sup>

W przypadku zasad dopasowujących CDHash jeden hash identyfikuje tylko jedną ścieżkę wykonania dla konkretnej architektury. Apple zaleca wyliczenie slice’ów i użycie `codesign --arch`, aby sprawdzić każdy z nich.<sup>[[9]](#references)</sup>

```bash
BIN=/path/to/executable
for A in $(lipo -archs "$BIN"); do
  printf "\n== %s ==\n" "$A"
  codesign -dvvv --arch "$A" "$BIN" 2>&1
  codesign -d --entitlements - --arch "$A" "$BIN"
done
```

W sekcji [macOS Code Signing](../macos-security-protections/macos-code-signing.md) znajdziesz informacje o strukturze podpisu i szczegółach jego weryfikacji.

## **Nagłówek Mach-O**

Nagłówek zawiera podstawowe informacje o pliku, takie jak magic bytes identyfikujące go jako plik Mach-O oraz informacje o docelowej architekturze. Można go znaleźć za pomocą polecenia: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

Istnieją różne typy plików. Można je znaleźć na przykład w [**kodzie źródłowym tutaj**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Najważniejsze z nich to:

- `MH_OBJECT`: Relokowalny plik obiektowy (produkty pośrednie kompilacji, które nie są jeszcze plikami wykonywalnymi).
- `MH_EXECUTE`: Pliki wykonywalne.
- `MH_FVMLIB`: Plik biblioteki Fixed VM.
- `MH_CORE`: Zrzuty kodu
- `MH_PRELOAD`: Wstępnie załadowany plik wykonywalny (nie jest już obsługiwany w XNU)
- `MH_DYLIB`: Biblioteki dynamiczne
- `MH_DYLINKER`: Linker dynamiczny
- `MH_BUNDLE`: „Pliki pluginów”. Generowane za pomocą `-bundle` w gcc i jawnie ładowane przez `NSBundle` lub `dlopen`.
- `MH_DSYM`: Towarzyszący plik `.dSYM` (plik z symbolami do debugowania).
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

- `MH_NOUNDEFS`: Brak niezdefiniowanych odwołań (w pełni połączony)
- `MH_DYLDLINK`: Łączenie przez dyld
- `MH_PREBOUND`: Odwołania dynamiczne są wstępnie powiązane.
- `MH_SPLIT_SEGS`: Plik dzieli segmenty tylko do odczytu i do odczytu/zapisu.
- `MH_WEAK_DEFINES`: Binarny plik zawiera symbole ze słabą definicją
- `MH_BINDS_TO_WEAK`: Binarny plik używa słabych symboli
- `MH_ALLOW_STACK_EXECUTION`: Umożliwia wykonywanie kodu ze stosu
- `MH_NO_REEXPORTED_DYLIBS`: Biblioteka nie zawiera poleceń LC_REEXPORT
- `MH_PIE`: Plik wykonywalny niezależny od położenia
- `MH_HAS_TLV_DESCRIPTORS`: Zawiera sekcję ze zmiennymi lokalnymi dla wątków
- `MH_NO_HEAP_EXECUTION`: Brak możliwości wykonywania kodu ze stron sterty/danych
- `MH_HAS_OBJC`: Binarny plik zawiera sekcje Objective-C
- `MH_SIM_SUPPORT`: Obsługa symulatora
- `MH_DYLIB_IN_CACHE`: Używane w bibliotekach dylib/frameworkach w pamięci podręcznej bibliotek współdzielonych.

## **Polecenia ładowania Mach-O**

**Układ pliku w pamięci** jest określony w tym miejscu. Opisuje położenie **tablicy symboli**, kontekst głównego wątku w chwili rozpoczęcia wykonywania oraz wymagane **biblioteki współdzielone**. Instrukcje dla dynamicznego loadera **(dyld)** określają proces ładowania pliku binarnego do pamięci.

Wykorzystywana jest struktura **load_command**, zdefiniowana we wspomnianym pliku **`loader.h`**:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Istnieje około **50 różnych typów poleceń ładowania**, które system obsługuje na różne sposoby. Najczęściej spotykane to: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` i `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Zasadniczo ten typ polecenia ładowania określa, **jak załadować segmenty \_\_TEXT** (kod wykonywalny) **i \_\_DATA** (dane procesu), **zgodnie z offsetami wskazanymi w sekcji Data**, gdy plik binarny jest uruchamiany.

Te polecenia **definiują segmenty**, które są **mapowane** do **wirtualnej przestrzeni pamięci** procesu podczas jego uruchamiania.

Istnieją **różne typy** segmentów, takie jak segment **\_\_TEXT**, zawierający kod wykonywalny programu, oraz segment **\_\_DATA**, zawierający dane wykorzystywane przez proces. Te **segmenty znajdują się w sekcji danych** pliku Mach-O.

**Każdy segment** można dodatkowo **podzielić** na wiele **sekcji**. **Struktura polecenia ładowania** zawiera **informacje** o **tych sekcjach** w obrębie odpowiedniego segmentu.

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

Ten nagłówek określa **liczbę sekcji, których nagłówki znajdują się po nim**:

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

Jeśli **dodasz** **offset sekcji** (0x37DC) do **offsetu**, pod którym zaczyna się **architektura** — w tym przypadku `0x18000` — otrzymasz `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Informacje o **nagłówkach** można też uzyskać z **wiersza poleceń** za pomocą:

```bash
otool -lv /bin/ls
```

Common segments ładowane przez to cmd:

- **`__PAGEZERO`:** Instruuje kernel, aby **zmapował** **adres zero**, tak by nie można było z niego **odczytywać, zapisywać do niego ani wykonywać kodu**. Zmienne `maxprot` i `minprot` w strukturze są ustawione na zero, co oznacza, że **ta strona nie ma praw do odczytu, zapisu ani wykonywania**.
  - Ta alokacja jest ważna, ponieważ **ogranicza podatności typu NULL pointer dereference**. Dzieje się tak, ponieważ XNU wymusza istnienie strony zerowej, która sprawia, że pierwsza strona pamięci (i tylko ona) jest niedostępna (z wyjątkiem i386). Binarium może spełnić te wymagania, tworząc mały segment \_\_PAGEZERO (za pomocą `-pagezero_size`), który obejmuje pierwsze 4k, i udostępniając pozostałą pamięć 32-bitową zarówno w trybie użytkownika, jak i jądra.
- **`__TEXT`**: Zawiera **wykonywalny** **kod** z uprawnieniami **odczytu** i **wykonywania** (bez zapisu)**.** Typowe sekcje tego segmentu:
  - `__text`: skompilowany kod binarny
  - `__const`: dane stałe (tylko do odczytu)
  - `__[c/u/os_log]string`: stałe łańcuchy znaków C, Unicode lub os_log
  - `__stubs` i `__stubs_helper`: używane podczas procesu ładowania bibliotek dynamicznych
  - `__unwind_info`: dane do odwijania stosu.
  - Zauważ, że cała ta zawartość jest podpisana, ale oznaczona również jako wykonywalna (co daje więcej możliwości wykorzystania sekcji, które niekoniecznie wymagają tych uprawnień, takich jak sekcje przeznaczone na łańcuchy znaków).
- **`__DATA`**: Zawiera dane z uprawnieniami **odczytu** i **zapisu** (bez wykonywania)**.**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: wskaźnik symbolu non-lazy (wiązanie podczas ładowania)
  - `__la_symbol_ptr`: wskaźnik symbolu lazy (wiązanie przy użyciu)
  - `__const`: powinny to być dane tylko do odczytu (w praktyce nie są)
  - `__cfstring`: łańcuchy CoreFoundation
  - `__data`: zmienne globalne (zainicjalizowane)
  - `__bss`: zmienne statyczne (niezainicjalizowane)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist itd.): informacje używane przez runtime Objective-C
- **`__DATA_CONST`**: \_\_DATA.\_\_const nie ma gwarancji stałości (uprawnienia zapisu), podobnie jak inne wskaźniki i GOT. Ta sekcja sprawia, że `__const`, niektóre inicjalizatory i tablica GOT (po rozwiązaniu odwołań) stają się **tylko do odczytu** za pomocą `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Często występują w nowszych binariach Apple Silicon. Te segmenty przechowują wskaźniki, które muszą zostać uwierzytelnione podczas ładowania lub użycia (na przykład `__auth_got`). Jeśli technika rebindingu, hookowania lub modyfikowania importów sprawdza tylko starsze sekcje `__got` / `__la_symbol_ptr`, może nie wykryć rzeczywistych miejsc wywołań we współczesnych binariach `arm64e`. Więcej informacji o tych sekcjach znajdziesz na [tej stronie](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Zawiera informacje dla linkera (dyld), takie jak wpisy tabel symboli, łańcuchów znaków i relokacji. Jest to ogólny kontener na zawartość, która nie znajduje się w `__TEXT` ani `__DATA`; jej zawartość opisują inne polecenia ładowania.
  - Informacje dyld: rebase, opkody wiązania non-lazy/lazy/weak oraz informacje o eksportach
  - Początki funkcji: tabela adresów początkowych funkcji
  - Data In Code: fragmenty danych w \_\_text
  - Tablica symboli: symbole w binarium
  - Tablica symboli pośrednich: symbole wskaźników/stubów
  - Tablica łańcuchów znaków
  - Podpis kodu
- **`__OBJC`**: Zawiera informacje używane przez runtime Objective-C. Informacje te mogą jednak znajdować się również w segmencie \_\_DATA, w różnych sekcjach \_\_objc\_\*.
- **`__RESTRICT`**: Segment bez zawartości, zawierający jedną sekcję o nazwie **`__restrict`** (również pustą), która sprawia, że podczas uruchamiania binarium ignorowane są zmienne środowiskowe DYLD.

Jak było widać w kodzie, **segmenty obsługują również flagi** (choć nie są one zbyt często używane):

- `SG_HIGHVM`: tylko Core (nieużywane)
- `SG_FVMLIB`: nieużywane
- `SG_NORELOC`: segment nie zawiera relokacji
- `SG_PROTECTED_VERSION_1`: szyfrowanie. Używane na przykład przez Finder do szyfrowania segmentu tekstowego `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** zawiera punkt wejścia w atrybucie **entryoff**. Podczas ładowania **dyld** po prostu **dodaje** tę wartość do (znajdującej się w pamięci) **bazy binarium**, a następnie **przeskakuje** do tej instrukcji, aby rozpocząć wykonywanie kodu binarium.

**`LC_UNIXTHREAD`** zawiera wartości, jakie rejestry muszą mieć przy uruchamianiu głównego wątku. To rozwiązanie zostało już wycofane, ale **`dyld`** nadal z niego korzysta. Wartości rejestrów ustawione w ten sposób można zobaczyć za pomocą:

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


Zawiera informacje o **podpisie kodu pliku Macho-O**. Zawiera jedynie **offset**, który **wskazuje** na **blob podpisu**. Zazwyczaj znajduje się on na samym końcu pliku.\
Więcej informacji o tej sekcji znajdziesz w [**tym wpisie na blogu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) i [**tym giscie**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Obsługa szyfrowania binarnego. Jeśli jednak atakującemu uda się przejąć proces, będzie mógł zrzucić jego pamięć w postaci niezaszyfrowanej.

### **`LC_LOAD_DYLINKER`**

Zawiera **ścieżkę do pliku wykonywalnego dynamicznego linkera**, który mapuje biblioteki współdzielone do przestrzeni adresowej procesu. **Wartość jest zawsze ustawiona na `/usr/lib/dyld`**. Warto zauważyć, że w macOS mapowanie dylib odbywa się w **trybie użytkownika**, a nie w trybie jądra.

### **`LC_IDENT`**

Przestarzały, ale gdy skonfigurowano generowanie zrzutów przy panic, tworzony jest zrzut pamięci Mach-O, a wersja jądra jest ustawiana w poleceniu `LC_IDENT`.

### **`LC_UUID`**

Losowy UUID. Nie jest bezpośrednio przydatny do niczego, ale XNU buforuje go wraz z pozostałymi informacjami o procesie. Może być używany w raportach o awariach.

### **`LC_BUILD_VERSION`**

Nowoczesne pliki binarne zwykle zawierają to polecenie, aby zadeklarować **platformę docelową**, **minimalną wersję systemu operacyjnego**, **wersję SDK** oraz opcjonalnie **wersje narzędzi** użytych do zbudowania tego slice’a. Z perspektywy ofensywnej analizy i reverse engineeringu jest to bardzo przydatne do ustalenia, jak zbudowano próbkę, oraz szybkiego wykrywania nietypowych plików universal binary, w których jeden slice został skompilowany z innym SDK lub innym deployment targetem. Starsze pliki binarne mogą zamiast tego używać `LC_VERSION_MIN_*`.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Pozwala określić zmienne środowiskowe dla dyld przed uruchomieniem procesu. Może to być bardzo niebezpieczne, ponieważ umożliwia wykonanie dowolnego kodu wewnątrz procesu, dlatego to polecenie ładowania jest używane tylko w kompilacjach dyld z `#define SUPPORT_LC_DYLD_ENVIRONMENT` i dodatkowo ogranicza przetwarzanie do zmiennych w formacie `DYLD_..._PATH`, określających ścieżki ładowania.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Nowsze toolchainy często przechowują metadane export/bind/rebase w tych poleceniach, zamiast polegać wyłącznie na starszych opcode’ach `LC_DYLD_INFO[_ONLY]`. Oba są wpisami `linkedit_data_command`, które wskazują dane w **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Zwarte trie zawierające symbole eksportowane przez obraz.
- **`LC_DYLD_CHAINED_FIXUPS`**: Łańcuchy fixupów dla poszczególnych segmentów, używane przez dyld do stosowania rebases i binds. Na Apple Silicon można tu również znaleźć wiele nowoczesnych fixupów uwierzytelnionych wskaźników.

Te metadane są bardzo przydatne przy odtwarzaniu importów/eksportów, zrozumieniu, dlaczego zależność załadowana przez `@rpath` została rozwiązana w określony sposób, lub ustaleniu, dlaczego próba hookowania/rebindingu nie powiodła się na nowoczesnym celu `arm64e`. `dyld_info` można również uruchomić na ścieżkach dylib dostępnych wyłącznie w cache, które nie istnieją jako samodzielne pliki na dysku. Jest to bardzo przydatne w nowoczesnym macOS, gdzie wiele bibliotek systemowych znajduje się wyłącznie we współdzielonym cache’u.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

To nowoczesna komenda ładowania, która ma znaczenie głównie podczas analizowania **kernel collections / filesetów w stylu kernelcache**. Zamiast reprezentować pojedynczy, samodzielny obraz, zewnętrzny Mach-O pełni rolę kontenera, a każdy `LC_FILESET_ENTRY` wskazuje na osadzony plik Mach-O z własnym, przypominającym ścieżkę **identyfikatorem wpisu**, adresem VM i offsetem w pliku. Podczas reverse engineeringu współczesnych komponentów jądra macOS/iOS ta komenda często stanowi pomost między kontenerem najwyższego poziomu a właściwym obrazem, który chcesz wyodrębnić lub poddać deasemblacji.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

W przypadku praktycznych procedur ekstrakcji zajrzyj na [tę stronę o rozszerzeniach jądra macOS i kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

To polecenie ładowania opisuje zależność od **dynamicznej** **biblioteki**, która **nakazuje** **loaderowi** (dyld) **załadować i połączyć daną bibliotekę**. Dla **każdej biblioteki**, której wymaga plik binarny Mach-O, istnieje polecenie ładowania `LC_LOAD_DYLIB`.

- To polecenie ładowania jest strukturą typu **`dylib_command`** (zawierającą strukturę dylib, która opisuje właściwą zależną bibliotekę dynamiczną):

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t wersja zgodności; / numer wersji zgodności biblioteki /](<../../../images/image (486).png>)

Te informacje można również uzyskać z CLI za pomocą:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Niektóre biblioteki potencjalnie związane ze złośliwym oprogramowaniem:

- **DiskArbitration**: Monitorowanie dysków USB
- **AVFoundation:** Przechwytywanie dźwięku i obrazu
- **CoreWLAN**: Skanowanie sieci Wi-Fi.

> [!TIP]
> Binarny plik Mach-O może zawierać jeden lub **więcej** **konstruktorów**, które zostaną **wykonane** **przed** adresem określonym w **LC_MAIN**.\
> Przesunięcia dowolnych konstruktorów są przechowywane w sekcji **\_\_mod_init_func** segmentu **\_\_DATA_CONST**.

## **Dane Mach-O**

W centrum pliku znajduje się obszar danych, który składa się z kilku segmentów zdefiniowanych w obszarze load commands. **Każdy segment może zawierać różne sekcje danych**, z których każda **przechowuje kod lub dane** właściwe dla danego typu.

> [!TIP]
> Dane to w zasadzie część zawierająca wszystkie **informacje** ładowane przez load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Obejmuje to:

- **Tabela funkcji:** Zawiera informacje o funkcjach programu.
- **Tabela symboli**: Zawiera informacje o funkcjach zewnętrznych używanych przez plik binarny.
- Może również zawierać nazwy funkcji wewnętrznych, zmiennych i inne informacje.

Możesz to sprawdzić za pomocą narzędzia [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Lub z poziomu CLI:

```bash
size -m /bin/ls
```

### Dołączone dane i nakładki parsowane od końca

Loader może przechowywać konfigurację w dołączonych danych zamiast w nazwanej sekcji Mach-O. Parser działający od końca zaczyna od znacznika końcowego, odczytuje rozmiar zapisany bezpośrednio przed nim i używa tej wartości, aby zlokalizować i odszyfrować poprzedzający blob. W jednym zaobserwowanym loaderze uniwersalnym ten układ służył do przechowywania zaszyfrowanego XOR-em URL-a downloadera:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Podczas analizowania nieznanego pliku binarnego zacznij od sprawdzenia bajtów wokół rozpoznawalnych znaczników końcowych i prześledź wszystkie obliczenia rozmiaru wykonywane wstecz, zanim założysz, że ciągi znaków lub konfiguracja muszą należeć do sekcji load-command. Znacznik i klucz XOR są specyficzne dla próbki; techniką, którą można ponownie wykorzystać, jest samookreślająca się końcówka.

## Typowe sekcje Objective-C

W segmencie `__TEXT` (r-x):

- `__objc_classname`: Nazwy klas (ciągi znaków)
- `__objc_methname`: Nazwy metod (ciągi znaków)
- `__objc_methtype`: Typy metod (ciągi znaków)

W segmencie `__DATA` (rw-):

- `__objc_classlist`: Wskaźniki do wszystkich klas Objective-C
- `__objc_nlclslist`: Wskaźniki do nie-leniwych klas Objective-C
- `__objc_catlist`: Wskaźniki do kategorii
- `__objc_nlcatlist`: Wskaźniki do nie-leniwych kategorii
- `__objc_protolist`: Lista protokołów
- `__objc_const`: Dane stałe
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

Zobacz także: [Ładowanie refleksyjne Mach-O](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [1] [Wycinanie Mach-O nie jest tak proste, jak mogłoby się wydawać](https://objective-see.org/blog/blog_0x80.html)
- [2] [Strona podręcznika dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Odczytywanie własnych uprawnień](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source — Mach-O `fat.h` i `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist — Nowa wersja macOS stealera MacSync atakuje entuzjastów kryptowalut i deweloperów](https://securelist.com/macsync-new-version/121383/)
- [7] [Sztuka złośliwego oprogramowania na Maca, tom 2 — Analizowanie plików binarnych](https://taomm.org/vol2/pdfs/CH%202%20Parsing%20Binaries.pdf)
- [8] [Apple Developer — TN3126: Wewnątrz podpisywania kodu: skróty](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes.md)
- [9] [Apple Developer — Zezwalanie na aplikacje i pliki binarne oraz ich blokowanie](https://developer.apple.com/documentation/devicemanagement/allowing-and-denying-apps-and-binaries.md)
{{#include ../../../banners/hacktricks-training.md}}
