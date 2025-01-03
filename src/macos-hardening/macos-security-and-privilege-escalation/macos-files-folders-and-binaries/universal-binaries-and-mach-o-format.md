# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Binaries Mac OS są zazwyczaj kompilowane jako **universal binaries**. **Universal binary** może **obsługiwać wiele architektur w tym samym pliku**.

Te binaries mają **strukturę Mach-O**, która składa się zasadniczo z:

- Nagłówka
- Komend ładowania
- Danych

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Szukaj pliku za pomocą: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC lub FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* liczba struktur, które następują */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* specyfikator CPU (int) */
cpu_subtype_t	cpusubtype;	/* specyfikator maszyny (int) */
uint32_t	offset;		/* przesunięcie pliku do tego pliku obiektowego */
uint32_t	size;		/* rozmiar tego pliku obiektowego */
uint32_t	align;		/* wyrównanie jako potęga 2 */
};
</code></pre>

Nagłówek zawiera **magiczne** bajty, a następnie **liczbę** **architektur**, które plik **zawiera** (`nfat_arch`), a każda architektura będzie miała strukturę `fat_arch`.

Sprawdź to za pomocą:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universal binary z 2 architekturami: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (dla architektury x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (dla architektury arm64e):	Mach-O 64-bit executable arm64e

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

lub używając narzędzia [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Jak możesz myśleć, zazwyczaj **universal binary** skompilowane dla 2 architektur **podwaja rozmiar** jednego skompilowanego tylko dla 1 architektury.

## **Nagłówek Mach-O**

Nagłówek zawiera podstawowe informacje o pliku, takie jak magiczne bajty identyfikujące go jako plik Mach-O oraz informacje o docelowej architekturze. Możesz go znaleźć w: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Istnieją różne typy plików, które można znaleźć zdefiniowane w [**kodzie źródłowym, na przykład tutaj**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Najważniejsze z nich to:

- `MH_OBJECT`: Plik obiektowy do relokacji (produkty pośrednie kompilacji, jeszcze nie wykonywalne).
- `MH_EXECUTE`: Pliki wykonywalne.
- `MH_FVMLIB`: Plik biblioteki VM o stałej wielkości.
- `MH_CORE`: Zrzuty kodu
- `MH_PRELOAD`: Wstępnie załadowany plik wykonywalny (już nieobsługiwany w XNU)
- `MH_DYLIB`: Biblioteki dynamiczne
- `MH_DYLINKER`: Ładowarka dynamiczna
- `MH_BUNDLE`: "Pliki wtyczek". Generowane za pomocą -bundle w gcc i ładowane explicite przez `NSBundle` lub `dlopen`.
- `MH_DYSM`: Towarzyszący plik `.dSym` (plik z symbolami do debugowania).
- `MH_KEXT_BUNDLE`: Rozszerzenia jądra.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Lub używając [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Flagi Mach-O**

Kod źródłowy definiuje również kilka flag przydatnych do ładowania bibliotek:

- `MH_NOUNDEFS`: Brak niezdefiniowanych odniesień (w pełni powiązane)
- `MH_DYLDLINK`: Łączenie Dyld
- `MH_PREBOUND`: Dynamiczne odniesienia wstępnie powiązane.
- `MH_SPLIT_SEGS`: Plik dzieli segmenty r/o i r/w.
- `MH_WEAK_DEFINES`: Plik binarny ma słabo zdefiniowane symbole
- `MH_BINDS_TO_WEAK`: Plik binarny używa słabych symboli
- `MH_ALLOW_STACK_EXECUTION`: Umożliwia wykonanie na stosie
- `MH_NO_REEXPORTED_DYLIBS`: Biblioteka nie ma poleceń LC_REEXPORT
- `MH_PIE`: Wykonywalny niezależny od pozycji
- `MH_HAS_TLV_DESCRIPTORS`: Istnieje sekcja z lokalnymi zmiennymi wątku
- `MH_NO_HEAP_EXECUTION`: Brak wykonania dla stron heap/data
- `MH_HAS_OBJC`: Plik binarny ma sekcje oBject-C
- `MH_SIM_SUPPORT`: Wsparcie dla symulatora
- `MH_DYLIB_IN_CACHE`: Używane w dylibach/frameworkach w pamięci podręcznej biblioteki współdzielonej.

## **Polecenia ładowania Mach-O**

**Układ pliku w pamięci** jest określony tutaj, szczegółowo opisując **lokalizację tabeli symboli**, kontekst głównego wątku na początku wykonania oraz wymagane **biblioteki współdzielone**. Instrukcje są przekazywane do dynamicznego loadera **(dyld)** dotyczące procesu ładowania pliku binarnego do pamięci.

Używa struktury **load_command**, zdefiniowanej w wspomnianym **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Są około **50 różnych typów poleceń ładujących**, które system obsługuje w różny sposób. Najczęstsze z nich to: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` i `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Zasadniczo ten typ polecenia ładującego definiuje **jak załadować \_\_TEXT** (kod wykonywalny) **i \_\_DATA** (dane dla procesu) **segmenty** zgodnie z **offsetami wskazanymi w sekcji danych** podczas wykonywania binarnego.

Te polecenia **definiują segmenty**, które są **mapowane** do **przestrzeni pamięci wirtualnej** procesu, gdy jest on wykonywany.

Istnieją **różne typy** segmentów, takie jak segment **\_\_TEXT**, który zawiera kod wykonywalny programu, oraz segment **\_\_DATA**, który zawiera dane używane przez proces. Te **segmenty znajdują się w sekcji danych** pliku Mach-O.

**Każdy segment** może być dalej **podzielony** na wiele **sekcji**. Struktura **polecenia ładującego** zawiera **informacje** o **tych sekcjach** w odpowiednim segmencie.

W nagłówku najpierw znajdziesz **nagłówek segmentu**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* dla architektur 64-bitowych */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* obejmuje sizeof section_64 structs */
char		segname[16];	/* nazwa segmentu */
uint64_t	vmaddr;		/* adres pamięci tego segmentu */
uint64_t	vmsize;		/* rozmiar pamięci tego segmentu */
uint64_t	fileoff;	/* offset pliku tego segmentu */
uint64_t	filesize;	/* ilość do zmapowania z pliku */
int32_t		maxprot;	/* maksymalna ochrona VM */
int32_t		initprot;	/* początkowa ochrona VM */
<strong>	uint32_t	nsects;		/* liczba sekcji w segmencie */
</strong>	uint32_t	flags;		/* flagi */
};
</code></pre>

Przykład nagłówka segmentu:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Ten nagłówek definiuje **liczbę sekcji, których nagłówki pojawiają się po** nim:
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

Jeśli **dodasz** **przesunięcie sekcji** (0x37DC) + **przesunięcie**, w którym **arch zaczyna się**, w tym przypadku `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Możliwe jest również uzyskanie **informacji o nagłówkach** z **linii poleceń** za pomocą:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** Instrukcja dla jądra, aby **mapować** **adres zero**, aby **nie można go było odczytać, zapisać ani wykonać**. Zmienne maxprot i minprot w strukturze są ustawione na zero, aby wskazać, że **nie ma praw do odczytu-zapisu-wykonania na tej stronie**.
- Ta alokacja jest ważna, aby **złagodzić podatności na dereferencję wskaźnika NULL**. Dzieje się tak, ponieważ XNU egzekwuje twardą stronę zero, która zapewnia, że pierwsza strona (tylko pierwsza) pamięci jest niedostępna (z wyjątkiem i386). Plik binarny może spełniać te wymagania, tworząc mały \_\_PAGEZERO (używając `-pagezero_size`), aby pokryć pierwsze 4k i mając resztę pamięci 32-bitowej dostępną zarówno w trybie użytkownika, jak i jądra.
- **`__TEXT`**: Zawiera **wykonywalny** **kod** z **uprawnieniami do odczytu** i **wykonywania** (brak zapisu)**.** Typowe sekcje tego segmentu:
- `__text`: Skonstruowany kod binarny
- `__const`: Dane stałe (tylko do odczytu)
- `__[c/u/os_log]string`: Stałe ciągi C, Unicode lub os logów
- `__stubs` i `__stubs_helper`: Uczestniczą w procesie ładowania dynamicznej biblioteki
- `__unwind_info`: Dane o rozwijaniu stosu.
- Zauważ, że cała ta zawartość jest podpisana, ale również oznaczona jako wykonywalna (tworząc więcej opcji do wykorzystania sekcji, które niekoniecznie potrzebują tego przywileju, jak sekcje dedykowane ciągom).
- **`__DATA`**: Zawiera dane, które są **czytelne** i **zapisywalne** (brak wykonywalnych)**.**
- `__got:` Globalna tabela przesunięć
- `__nl_symbol_ptr`: Wskaźnik symbolu non lazy (wiąże przy ładowaniu)
- `__la_symbol_ptr`: Wskaźnik symbolu lazy (wiąże przy użyciu)
- `__const`: Powinny być danymi tylko do odczytu (nie do końca)
- `__cfstring`: Ciągi CoreFoundation
- `__data`: Zmienne globalne (które zostały zainicjowane)
- `__bss`: Zmienne statyczne (które nie zostały zainicjowane)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, itd): Informacje używane przez środowisko uruchomieniowe Objective-C
- **`__DATA_CONST`**: \_\_DATA.\_\_const nie jest gwarantowane jako stałe (uprawnienia do zapisu), ani inne wskaźniki i GOT. Ta sekcja sprawia, że `__const`, niektóre inicjalizatory i tabela GOT (po rozwiązaniu) są **tylko do odczytu** przy użyciu `mprotect`.
- **`__LINKEDIT`**: Zawiera informacje dla linkera (dyld), takie jak symbole, ciągi i wpisy tabeli relokacji. Jest to ogólny kontener dla treści, które nie znajdują się w `__TEXT` ani `__DATA`, a jego zawartość jest opisana w innych poleceniach ładowania.
- Informacje dyld: Rebase, opcodes wiązania non-lazy/lazy/weak i informacje o eksporcie
- Funkcje startowe: Tabela adresów startowych funkcji
- Dane w kodzie: Wyspy danych w \_\_text
- Tabela symboli: Symbole w binarnym
- Tabela symboli pośrednich: Wskaźniki/stuby symboli
- Tabela ciągów
- Podpis kodu
- **`__OBJC`**: Zawiera informacje używane przez środowisko uruchomieniowe Objective-C. Chociaż te informacje mogą być również znalezione w segmencie \_\_DATA, w różnych sekcjach \_\_objc\_\*.
- **`__RESTRICT`**: Segment bez zawartości z jedną sekcją o nazwie **`__restrict`** (również pusta), która zapewnia, że podczas uruchamiania binarnego zignoruje zmienne środowiskowe DYLD.

Jak można było zobaczyć w kodzie, **segmenty również wspierają flagi** (chociaż nie są zbyt często używane):

- `SG_HIGHVM`: Tylko rdzeń (nieużywane)
- `SG_FVMLIB`: Nie używane
- `SG_NORELOC`: Segment nie ma relokacji
- `SG_PROTECTED_VERSION_1`: Szyfrowanie. Używane na przykład przez Findera do szyfrowania tekstu w segmencie `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** zawiera punkt wejścia w atrybucie **entryoff.** W czasie ładowania, **dyld** po prostu **dodaje** tę wartość do (w pamięci) **bazy binarnej**, a następnie **skacze** do tej instrukcji, aby rozpocząć wykonanie kodu binarnego.

**`LC_UNIXTHREAD`** zawiera wartości, jakie rejestry muszą mieć przy uruchamianiu głównego wątku. To już zostało wycofane, ale **`dyld`** nadal to wykorzystuje. Można zobaczyć wartości rejestrów ustawione przez to za pomocą:
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

Zawiera informacje o **podpisie kodu pliku Macho-O**. Zawiera tylko **offset**, który **wskazuje** na **blob podpisu**. Zazwyczaj znajduje się on na samym końcu pliku.\
Jednak można znaleźć pewne informacje na temat tej sekcji w [**tym wpisie na blogu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) oraz w tym [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Wsparcie dla szyfrowania binarnego. Jednak, oczywiście, jeśli atakujący zdoła skompromitować proces, będzie mógł zrzucić pamięć w postaci nieszyfrowanej.

### **`LC_LOAD_DYLINKER`**

Zawiera **ścieżkę do wykonywalnego pliku dynamicznego linkera**, który mapuje biblioteki współdzielone w przestrzeni adresowej procesu. **Wartość jest zawsze ustawiona na `/usr/lib/dyld`**. Ważne jest, aby zauważyć, że w macOS, mapowanie dylib odbywa się w **trybie użytkownika**, a nie w trybie jądra.

### **`LC_IDENT`**

Nieaktualne, ale gdy jest skonfigurowane do generowania zrzutów w przypadku paniki, tworzony jest zrzut rdzenia Mach-O, a wersja jądra jest ustawiana w poleceniu `LC_IDENT`.

### **`LC_UUID`**

Losowy UUID. Jest przydatny do czegokolwiek bezpośrednio, ale XNU buforuje go z resztą informacji o procesie. Może być używany w raportach o awariach.

### **`LC_DYLD_ENVIRONMENT`**

Pozwala wskazać zmienne środowiskowe dla dyld przed wykonaniem procesu. Może to być bardzo niebezpieczne, ponieważ może pozwolić na wykonanie dowolnego kodu wewnątrz procesu, więc to polecenie ładowania jest używane tylko w dyld zbudowanym z `#define SUPPORT_LC_DYLD_ENVIRONMENT` i dodatkowo ogranicza przetwarzanie tylko do zmiennych w formie `DYLD_..._PATH` określających ścieżki ładowania.

### **`LC_LOAD_DYLIB`**

To polecenie ładowania opisuje zależność od **dynamicznej** **biblioteki**, która **instrukuje** **ładowarkę** (dyld) do **załadowania i powiązania wspomnianej biblioteki**. Istnieje polecenie ładowania `LC_LOAD_DYLIB` **dla każdej biblioteki**, której wymaga binarny plik Mach-O.

- To polecenie ładowania jest strukturą typu **`dylib_command`** (która zawiera strukturę dylib, opisującą rzeczywistą zależną dynamiczną bibliotekę):
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

Możesz również uzyskać te informacje z cli za pomocą:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Niektóre potencjalne biblioteki związane z złośliwym oprogramowaniem to:

- **DiskArbitration**: Monitorowanie dysków USB
- **AVFoundation:** Rejestracja audio i wideo
- **CoreWLAN**: Skanowanie Wifi.

> [!NOTE]
> Plik binarny Mach-O może zawierać jednego lub **więcej** **konstruktorów**, które będą **wykonywane** **przed** adresem określonym w **LC_MAIN**.\
> Offsety wszelkich konstruktorów są przechowywane w sekcji **\_\_mod_init_func** segmentu **\_\_DATA_CONST**.

## **Dane Mach-O**

W rdzeniu pliku znajduje się obszar danych, który składa się z kilku segmentów zdefiniowanych w obszarze poleceń ładujących. **W każdym segmencie może być przechowywanych wiele sekcji danych**, z których każda **zawiera kod lub dane** specyficzne dla danego typu.

> [!TIP]
> Dane to zasadniczo część zawierająca wszystkie **informacje**, które są ładowane przez polecenia ładujące **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

To obejmuje:

- **Tabela funkcji:** Która zawiera informacje o funkcjach programu.
- **Tabela symboli**: Która zawiera informacje o zewnętrznych funkcjach używanych przez plik binarny
- Może również zawierać wewnętrzne funkcje, nazwy zmiennych oraz inne.

Aby to sprawdzić, możesz użyć narzędzia [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Lub z poziomu cli:
```bash
size -m /bin/ls
```
## Sekcje wspólne Objective-C

W segmencie `__TEXT` (r-x):

- `__objc_classname`: Nazwy klas (ciągi)
- `__objc_methname`: Nazwy metod (ciągi)
- `__objc_methtype`: Typy metod (ciągi)

W segmencie `__DATA` (rw-):

- `__objc_classlist`: Wskaźniki do wszystkich klas Objective-C
- `__objc_nlclslist`: Wskaźniki do klas Objective-C bez leniwego ładowania
- `__objc_catlist`: Wskaźnik do Kategorii
- `__objc_nlcatlist`: Wskaźnik do Kategorii bez leniwego ładowania
- `__objc_protolist`: Lista protokołów
- `__objc_const`: Dane stałe
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
