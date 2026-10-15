# Uniwersalne pliki binarne macOS i format Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

macOS używa formatu plików wykonywalnych **Mach-O**. **Uniwersalny** plik binarny, zwany też fat, zawiera wiele wycinków Mach-O specyficznych dla danej architektury w jednym pliku. Nagłówki open source Apple `fat.h` i `loader.h` definiują struktury i stałe opisane na tej stronie. <sup>[[5]](#references)</sup>

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

Nagłówek zawiera bajty **magic**, po których następuje **liczba** **architektur** zawartych w pliku (`nfat_arch`); dla każdej architektury znajduje się struktura `fat_arch`.

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

Jak można się domyślić, uniwersalny plik binarny skompilowany dla 2 architektur zwykle ma **dwukrotnie większy rozmiar** niż plik skompilowany tylko dla 1 architektury.

> [!TIP]
> Podczas analizy malware lub podejrzanych aplikacji nie poprzestawaj na wyniku `file` wskazującym „najlepszą” architekturę. Uniwersalny plik binarny może zawierać różne importy, polecenia ładowania lub metadane kompilatora w każdym wycinku, więc najpierw wylicz **wszystkie** wycinki, a następnie sprawdź każdy z nich osobno:

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Najnowsze SDK macOS udostępniają też funkcje pomocnicze, takie jak `macho_for_each_slice()` i `macho_best_slice()` z `<mach-o/utils.h>`. Ta druga przydaje się do emulowania tego, co załadowałby dyld/kernel, ale skanery powinny nadal iterować po wszystkich slice’ach, aby nie przeoczyć treści specyficznych dla danej architektury.<sup>[[1]](#references)</sup>

## **Nagłówek Mach-O**

Nagłówek zawiera podstawowe informacje o pliku, takie jak bajty magiczne identyfikujące go jako plik Mach-O oraz informacje o docelowej architekturze. Można go znaleźć za pomocą polecenia: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

Istnieją różne typy plików, które można znaleźć w [**kodzie źródłowym, na przykład tutaj**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Najważniejsze z nich to:

- `MH_OBJECT`: Relokowalny plik obiektowy (pośredni produkt kompilacji, który nie jest jeszcze plikiem wykonywalnym).
- `MH_EXECUTE`: Pliki wykonywalne.
- `MH_FVMLIB`: Plik biblioteki Fixed VM.
- `MH_CORE`: Zrzuty pamięci.
- `MH_PRELOAD`: Wstępnie załadowany plik wykonywalny (nie jest już obsługiwany w XNU).
- `MH_DYLIB`: Biblioteki dynamiczne.
- `MH_DYLINKER`: Dynamiczny linker.
- `MH_BUNDLE`: „Pliki wtyczek”. Generowane za pomocą opcji `-bundle` w gcc i jawnie ładowane przez `NSBundle` lub `dlopen`.
- `MH_DYSM`: Towarzyszący plik `.dSym` (plik z symbolami do debugowania).
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

## **Mach-O Flags**

Kod źródłowy definiuje również kilka flag przydatnych podczas ładowania bibliotek:

- `MH_NOUNDEFS`: Brak niezdefiniowanych odwołań (pełne linkowanie)
- `MH_DYLDLINK`: Linkowanie przez dyld
- `MH_PREBOUND`: Dynamiczne odwołania są wstępnie powiązane.
- `MH_SPLIT_SEGS`: Plik dzieli segmenty r/o i r/w.
- `MH_WEAK_DEFINES`: Binarium zawiera słabo zdefiniowane symbole
- `MH_BINDS_TO_WEAK`: Binarium używa słabych symboli
- `MH_ALLOW_STACK_EXECUTION`: Ustawia stos jako wykonywalny
- `MH_NO_REEXPORTED_DYLIBS`: Biblioteka nie używa poleceń LC_REEXPORT
- `MH_PIE`: Wykonywalny plik niezależny od położenia
- `MH_HAS_TLV_DESCRIPTORS`: Istnieje sekcja zawierająca zmienne lokalne dla wątków
- `MH_NO_HEAP_EXECUTION`: Brak wykonywania na stronach sterty/danych
- `MH_HAS_OBJC`: Binarium zawiera sekcje Objective-C
- `MH_SIM_SUPPORT`: Obsługa symulatora
- `MH_DYLIB_IN_CACHE`: Używane w bibliotekach dylib/frameworkach znajdujących się w pamięci podręcznej bibliotek współdzielonych.

## **Mach-O Load commands**

**Układ pliku w pamięci** jest określony tutaj. Opisano lokalizację **tablicy symboli**, kontekst głównego wątku na początku wykonywania oraz wymagane **biblioteki współdzielone**. Dynamiczny program ładujący **(dyld)** otrzymuje instrukcje dotyczące procesu ładowania binarium do pamięci.

Wykorzystywana jest struktura **load_command**, zdefiniowana w wymienionym pliku **`loader.h`**:

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Istnieje około **50 różnych typów poleceń ładowania**, które system obsługuje na różne sposoby. Najczęściej spotykane to: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` i `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Zasadniczo ten typ polecenia ładowania definiuje, **jak załadować segmenty \_\_TEXT** (kod wykonywalny) **i \_\_DATA** (dane procesu) **na podstawie offsetów wskazanych w sekcji danych** podczas uruchamiania pliku binarnego.

Te polecenia **definiują segmenty**, które są **mapowane** do **wirtualnej przestrzeni pamięci** procesu podczas jego uruchamiania.

Istnieją **różne typy** segmentów, takie jak segment **\_\_TEXT**, który zawiera kod wykonywalny programu, oraz segment **\_\_DATA**, który zawiera dane używane przez proces. Te **segmenty znajdują się w sekcji danych** pliku Mach-O.

**Każdy segment** można dodatkowo **podzielić** na wiele **sekcji**. **Struktura polecenia ładowania** zawiera **informacje** o **tych sekcjach** w obrębie danego segmentu.

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

Ten nagłówek określa **liczbę sekcji, których nagłówki znajdują się za nim**:

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

Jeśli **dodasz** **przesunięcie sekcji** (0x37DC) do **przesunięcia**, pod którym zaczyna się **architektura** — w tym przypadku `0x18000` — otrzymasz `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Informacje o **nagłówkach** można też uzyskać z **wiersza poleceń** za pomocą:

```bash
otool -lv /bin/ls
```

Common segments ładowane przez to cmd:

- **`__PAGEZERO`:** Instrukcja dla kernela, aby **zmapował** **adres zero** w taki sposób, by nie można było z niego **odczytywać, zapisywać do niego ani wykonywać** kodu. Zmienne maxprot i minprot w strukturze mają wartość zero, co oznacza, że **ta strona nie ma praw do odczytu, zapisu ani wykonywania**.
  - Ta alokacja jest ważna, by **ograniczyć podatności typu NULL pointer dereference**. Dzieje się tak, ponieważ XNU wymusza ochronę strony zerowej, która sprawia, że pierwsza strona pamięci (i tylko ona) jest niedostępna (z wyjątkiem i386). Binarny plik może spełnić ten wymóg, tworząc mały segment \_\_PAGEZERO (za pomocą `-pagezero_size`), który obejmuje pierwsze 4k, a pozostałą część pamięci 32-bitowej pozostawia dostępną zarówno w trybie użytkownika, jak i kernela.
- **`__TEXT`**: Zawiera **wykonywalny** **kod** z uprawnieniami do **odczytu** i **wykonywania** (bez prawa zapisu)**.** Typowe sekcje tego segmentu:
  - `__text`: Skompilowany kod binarny
  - `__const`: Dane stałe (tylko do odczytu)
  - `__[c/u/os_log]string`: Stałe tekstowe C, Unicode lub os logs
  - `__stubs` i `__stubs_helper`: Używane podczas procesu ładowania dynamicznych bibliotek
  - `__unwind_info`: Dane dotyczące odwijania stosu.
  - Zwróć uwagę, że cała ta zawartość jest podpisana, ale oznaczona jako wykonywalna (co daje więcej możliwości wykorzystania sekcji, które niekoniecznie potrzebują tego uprawnienia, takich jak sekcje przeznaczone na ciągi znaków).
- **`__DATA`**: Zawiera dane, które można **odczytywać** i **zapisywać** (bez prawa wykonywania)**.**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr`: Wskaźnik symbolu non-lazy (wiązany podczas ładowania)
  - `__la_symbol_ptr`: Wskaźnik symbolu lazy (wiązany podczas użycia)
  - `__const`: Powinny to być dane tylko do odczytu (w praktyce nie są)
  - `__cfstring`: Ciągi znaków CoreFoundation
  - `__data`: Zmienne globalne (którym przypisano wartość początkową)
  - `__bss`: Zmienne statyczne (którym nie przypisano wartości początkowej)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist itp.): Informacje używane przez runtime Objective-C
- **`__DATA_CONST`**: Nie ma gwarancji, że \_\_DATA.\_\_const jest stała (ma uprawnienia do zapisu); to samo dotyczy innych wskaźników i GOT. Ta sekcja sprawia, że `__const`, niektóre inicjalizatory i tabela GOT (po rozwiązaniu) stają się **tylko do odczytu** za pomocą `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Często występują w nowszych binarnych plikach Apple Silicon. Te segmenty przechowują wskaźniki, które muszą zostać uwierzytelnione podczas ładowania lub użycia (na przykład `__auth_got`). Jeśli metoda rebindingu, hook lub patchowania importów sprawdza tylko starsze sekcje `__got` / `__la_symbol_ptr`, może nie wykryć rzeczywistych miejsc wywołań w nowoczesnych binarnych plikach `arm64e`. Więcej informacji o tych sekcjach znajdziesz na [tej stronie](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Zawiera informacje dla linkera (dyld), takie jak wpisy w tablicach symboli, ciągów znaków i relokacji. To ogólny kontener na zawartość, która nie znajduje się w `__TEXT` ani `__DATA`, a jego zawartość jest opisana w innych load commands.
  - Informacje dyld: operacje rebase, wiązania non-lazy/lazy/weak oraz informacje o eksporcie
  - Początki funkcji: Tabela adresów początkowych funkcji
  - Data In Code: Obszary danych w \_\_text
  - SYmbol Table: Symbole w pliku binarnym
  - Indirect Symbol Table: Symbole wskaźników/stubów
  - String Table
  - Code Signature
- **`__OBJC`**: Zawiera informacje używane przez runtime Objective-C. Informacje te mogą jednak również znajdować się w segmencie \_\_DATA, w różnych sekcjach \_\_objc\_\*.
- **`__RESTRICT`**: Segment bez zawartości, z jedną sekcją o nazwie **`__restrict`** (również pustą), która sprawia, że podczas uruchamiania plik binarny ignoruje zmienne środowiskowe DYLD.

Jak można było zobaczyć w kodzie, **segmenty obsługują również flagi** (choć nie są one zbyt często używane):

- `SG_HIGHVM`: Tylko Core (nieużywana)
- `SG_FVMLIB`: Nieużywana
- `SG_NORELOC`: Segment nie zawiera relokacji
- `SG_PROTECTED_VERSION_1`: Szyfrowanie. Używane na przykład przez Finder do szyfrowania segmentu tekstowego `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** zawiera punkt wejścia w atrybucie **entryoff**. Podczas ładowania **dyld** po prostu **dodaje** tę wartość do (znajdującej się w pamięci) **bazy pliku binarnego**, a następnie **przeskakuje** do tej instrukcji, aby rozpocząć wykonywanie kodu pliku binarnego.

**`LC_UNIXTHREAD`** zawiera wartości, jakie rejestry muszą mieć podczas uruchamiania głównego wątku. To rozwiązanie zostało już wycofane, ale **`dyld`** nadal z niego korzysta. Wartości rejestrów ustawione w ten sposób można wyświetlić za pomocą:

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


Zawiera informacje o **podpisie kodu pliku Mach-O**. Zawiera jedynie **przesunięcie**, które **wskazuje** na **blob podpisu**. Zazwyczaj znajduje się on na samym końcu pliku.\
Więcej informacji o tej sekcji znajdziesz w [**tym wpisie na blogu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) i [**tym giscie**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Obsługa szyfrowania plików binarnych. Jeśli jednak atakującemu uda się przejąć proces, będzie mógł zrzucić jego pamięć w postaci niezaszyfrowanej.

### **`LC_LOAD_DYLINKER`**

Zawiera **ścieżkę do pliku wykonywalnego dynamicznego linkera**, który mapuje biblioteki współdzielone w przestrzeni adresowej procesu. **Wartość jest zawsze ustawiona na `/usr/lib/dyld`**. Warto zauważyć, że w macOS mapowanie dylib odbywa się w **trybie użytkownika**, a nie w trybie jądra.

### **`LC_IDENT`**

Przestarzałe, ale gdy skonfigurowano generowanie zrzutów po awarii, tworzony jest zrzut pamięci Mach-O, a wersja jądra jest ustawiana w poleceniu `LC_IDENT`.

### **`LC_UUID`**

Losowy UUID. Sam w sobie nie jest bezpośrednio do niczego przydatny, ale XNU buforuje go wraz z pozostałymi informacjami o procesie. Może być używany w raportach awarii.

### **`LC_BUILD_VERSION`**

Współczesne pliki binarne zwykle zawierają to polecenie, aby określić **platformę docelową**, **minimalną wersję systemu operacyjnego**, **wersję SDK** oraz, opcjonalnie, **wersje narzędzi** użytych do zbudowania danego slice’a. Z perspektywy offensive/reversingu jest to bardzo przydatne do ustalenia, jak zbudowano próbkę, oraz szybkiego wykrywania nietypowych plików universal binaries, w których jeden slice został skompilowany z innym SDK lub dla innego deployment target. Starsze pliki binarne mogą zamiast tego używać `LC_VERSION_MIN_*`.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Pozwala wskazać zmienne środowiskowe dla dyld przed uruchomieniem procesu. Może to być bardzo niebezpieczne, ponieważ umożliwia wykonanie dowolnego kodu wewnątrz procesu, dlatego ta komenda ładowania jest używana tylko w kompilacjach dyld z `#define SUPPORT_LC_DYLD_ENVIRONMENT` i dodatkowo ogranicza przetwarzanie do zmiennych w formacie `DYLD_..._PATH`, określających ścieżki ładowania.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Nowsze toolchainy często przechowują metadane export/bind/rebase w tych komendach, zamiast polegać wyłącznie na starszych opcode’ach `LC_DYLD_INFO[_ONLY]`. Obie są wpisami `linkedit_data_command`, które wskazują na dane w **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Kompaktowe trie zawierające symbole eksportowane przez obraz.
- **`LC_DYLD_CHAINED_FIXUPS`**: Łańcuchy fixupów dla poszczególnych segmentów, używane przez dyld do stosowania rebase’ów i bindów. Na Apple Silicon można tu również znaleźć wiele nowoczesnych fixupów uwierzytelnionych wskaźników.

Te metadane są bardzo przydatne podczas odtwarzania importów/eksportów, ustalania, dlaczego zależność załadowana przez `@rpath` została rozwiązana w określony sposób, lub sprawdzania, dlaczego hook/rebinding nie powiódł się na nowoczesnym celu `arm64e`. `dyld_info` można również uruchomić na ścieżkach dylibów dostępnych wyłącznie w cache’u, które nie istnieją jako samodzielne pliki na dysku. Jest to bardzo przydatne we współczesnym macOS, gdzie wiele bibliotek systemowych znajduje się wyłącznie w shared cache.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Ta nowoczesna komenda ładowania jest istotna głównie podczas inspekcji **kernel collections / plików typu kernelcache**. Zamiast reprezentować pojedynczy, samodzielny obraz, zewnętrzny Mach-O pełni funkcję kontenera, a każdy `LC_FILESET_ENTRY` wskazuje osadzony Mach-O z własnym identyfikatorem wpisu przypominającym ścieżkę, adresem VM i offsetem w pliku. Podczas analizy wstecznej nowoczesnych komponentów jądra macOS/iOS ta komenda często stanowi pomost między kontenerem najwyższego poziomu a właściwym obrazem, który chcesz wyodrębnić lub zdezasemblować.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

For praktycznych procedur ekstrakcji sprawdź [tę stronę o rozszerzeniach jądra macOS i kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

To polecenie ładowania opisuje zależność od **dynamicznej** **biblioteki** i **instruuje** **loader** (dyld), aby **załadował i połączył tę bibliotekę**. Plik binarny Mach-O zawiera polecenie ładowania `LC_LOAD_DYLIB` **dla każdej biblioteki**, od której zależy.

- To polecenie ładowania jest strukturą typu **`dylib_command`** (która zawiera strukturę dylib opisującą faktyczną zależną bibliotekę dynamiczną):

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

Te informacje można też uzyskać z CLI za pomocą:

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Niektóre potencjalne biblioteki związane ze złośliwym oprogramowaniem to:

- **DiskArbitration**: Monitorowanie dysków USB
- **AVFoundation:** Przechwytywanie dźwięku i obrazu
- **CoreWLAN**: Skanowanie sieci Wi-Fi.

> [!TIP]
> Plik binarny Mach-O może zawierać jeden lub **więcej** **konstruktorów**, które zostaną **wykonane** **przed** adresem określonym w **LC_MAIN**.\
> Przesunięcia dowolnych konstruktorów są przechowywane w sekcji **\_\_mod_init_func** segmentu **\_\_DATA_CONST**.

## **Dane Mach-O**

W rdzeniu pliku znajduje się obszar danych, złożony z kilku segmentów zdefiniowanych w obszarze load commands. **W każdym segmencie może znajdować się wiele sekcji danych**, a każda sekcja **zawiera kod lub dane** określonego typu.

> [!TIP]
> Dane to zasadniczo część zawierająca wszystkie **informacje** ładowane przez load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Obejmuje to:

- **Tabela funkcji:** Zawiera informacje o funkcjach programu.
- **Tabela symboli**: Zawiera informacje o funkcjach zewnętrznych używanych przez plik binarny.
- Może również zawierać nazwy funkcji wewnętrznych, zmiennych i inne informacje.

Aby to sprawdzić, możesz użyć narzędzia [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Lub z poziomu CLI:

```bash
size -m /bin/ls
```

### Dołączone dane i nakładki analizowane wstecz

Loader może przechowywać konfigurację w dołączonych danych zamiast w nazwanej sekcji Mach-O. Parser analizujący dane wstecz opiera się na znaczniku końcowym, odczytuje rozmiar zapisany bezpośrednio przed nim i używa tej wartości, aby zlokalizować i odszyfrować poprzedzający blob. W jednym zaobserwowanym loaderze uniwersalnym użyto tego układu dla zaszyfrowanego XOR-em URL-a downloadera:<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Podczas analizowania nieznanego pliku binarnego sprawdzaj bajty wokół rozpoznawalnych znaczników końcowych i prześledź każde obliczenie rozmiaru wykonywane wstecz, zanim założysz, że ciągi znaków lub konfiguracja muszą należeć do sekcji load command. Znacznik i klucz XOR są specyficzne dla próbki; możliwa do ponownego wykorzystania jest technika z samookreślającym się trailerem.

## Typowe sekcje Objective-C

W segmencie `__TEXT` (r-x):

- `__objc_classname`: Nazwy klas (ciągi znaków)
- `__objc_methname`: Nazwy metod (ciągi znaków)
- `__objc_methtype`: Typy metod (ciągi znaków)

W segmencie `__DATA` (rw-):

- `__objc_classlist`: Wskaźniki do wszystkich klas Objective-C
- `__objc_nlclslist`: Wskaźniki do klas Objective-C Non-Lazy
- `__objc_catlist`: Wskaźnik do kategorii
- `__objc_nlcatlist`: Wskaźniki do kategorii Non-Lazy
- `__objc_protolist`: Lista protokołów
- `__objc_const`: Dane stałe
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

Zobacz też: [Reflective Mach-O Loading](../macos-proces-abuse/reflective-mach-o-loading.md#activating-objective-c-metadata).

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Wycinki Mach-O nie są tak proste, jak mogłoby się wydawać](https://objective-see.org/blog/blog_0x80.html)
- [2] [Strona podręcznika dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Odczytywanie własnych uprawnień](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source — Mach-O `fat.h` i `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist — Nowa wersja stealera MacSync na macOS atakuje entuzjastów kryptowalut i deweloperów](https://securelist.com/macsync-new-version/121383/)
