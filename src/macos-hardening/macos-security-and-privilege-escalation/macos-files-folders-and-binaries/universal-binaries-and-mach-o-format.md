# macOS Uniwersalne binaria i format Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Binarne pliki macOS są zwykle kompilowane jako **uniwersalne binaria**. **Uniwersalne binarium** może **obsługiwać wiele architektur w tym samym pliku**.

Te binaria mają strukturę **Mach-O**, która zasadniczo składa się z:

- Nagłówek
- Load Commands
- Dane

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

Nagłówek zawiera bajty **magic**, a następnie **liczbę** **architektur** zawartych w pliku (`nfat_arch`), a każda architektura ma strukturę `fat_arch`.

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

or using the [Mach-O View](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Jak można się spodziewać, uniwersalne binarium skompilowane dla 2 architektur **zwykle podwaja rozmiar** w porównaniu z binarium skompilowanym tylko dla 1 architektury.

## **Nagłówek Mach-O**

Nagłówek zawiera podstawowe informacje o pliku, takie jak magic bytes służące do identyfikacji pliku Mach-O oraz informacje o docelowej architekturze. Można go znaleźć w: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Istnieją różne typy plików — można je znaleźć zdefiniowane w [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Najważniejsze z nich to:

- `MH_OBJECT`: Plik obiektowy do relokacji (produkty pośrednie kompilacji, jeszcze nie wykonywalne).
- `MH_EXECUTE`: Pliki wykonywalne.
- `MH_FVMLIB`: Plik biblioteki Fixed VM.
- `MH_CORE`: Zrzuty pamięci.
- `MH_PRELOAD`: Wstępnie załadowany plik wykonywalny (już nieobsługiwany w XNU).
- `MH_DYLIB`: Biblioteki dynamiczne.
- `MH_DYLINKER`: Dynamiczny linker.
- `MH_BUNDLE`: Pliki wtyczek. Generowane przy użyciu -bundle w gcc i jawnie ładowane przez `NSBundle` lub `dlopen`.
- `MH_DYSM`: Plik towarzyszący `.dSym` (plik z symbolami do debugowania).
- `MH_KEXT_BUNDLE`: Rozszerzenia jądra.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Or using [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Flagi Mach-O**

Kode źródłowy definiuje również kilka flag przydatnych przy ładowaniu bibliotek:

- `MH_NOUNDEFS`: Brak niezdefiniowanych referencji (w pełni połączony)
- `MH_DYLDLINK`: Linkowanie przez dyld
- `MH_PREBOUND`: Dynamiczne referencje wstępnie powiązane
- `MH_SPLIT_SEGS`: Plik rozdziela segmenty tylko do odczytu (r/o) i do zapisu (r/w)
- `MH_WEAK_DEFINES`: Binar posiada słabo zdefiniowane symbole (weak)
- `MH_BINDS_TO_WEAK`: Binar używa słabych (weak) symboli
- `MH_ALLOW_STACK_EXECUTION`: Pozwala na wykonywanie na stosie
- `MH_NO_REEXPORTED_DYLIBS`: Biblioteka nie zawiera poleceń LC_REEXPORT
- `MH_PIE`: Wykonywalny niezależny od położenia (PIE)
- `MH_HAS_TLV_DESCRIPTORS`: Zawiera sekcję ze zmiennymi lokalnymi w wątku
- `MH_NO_HEAP_EXECUTION`: Brak wykonywania na stronach sterty/danych
- `MH_HAS_OBJC`: Binar zawiera sekcje Objective-C
- `MH_SIM_SUPPORT`: Wsparcie dla symulatora
- `MH_DYLIB_IN_CACHE`: Używane dla dylibów/frameworków w udostępnionej pamięci podręcznej bibliotek

## **Polecenia ładowania Mach-O**

Układ pliku w pamięci jest tu określony, wraz ze szczegółami dotyczącymi położenia tablicy symboli, kontekstu głównego wątku na początku wykonania oraz wymaganych bibliotek współdzielonych. Dostarczane są instrukcje dla dynamicznego loadera (dyld) dotyczące procesu ładowania binarki do pamięci.

Używa struktury load_command, zdefiniowanej w wymienionym `loader.h`:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Istnieje około **50 różnych typów poleceń ładowania**, które system obsługuje w odmienny sposób. Do najczęstszych należą: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` i `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> W praktyce ten typ Load Command określa, **jak załadować \_\_TEXT** (kod wykonywalny) **i \_\_DATA** (dane procesu) **segmenty** zgodnie z **offsetami wskazanymi w sekcji Data** podczas wykonywania binarki.

Te polecenia definiują segmenty, które są mapowane do wirtualnej przestrzeni pamięci procesu podczas jego wykonywania.

Istnieją różne typy segmentów, takie jak \_\_TEXT, który zawiera kod wykonywalny programu, oraz \_\_DATA, który zawiera dane używane przez proces. Segmenty te znajdują się w sekcji danych pliku Mach-O.

Każdy segment może być dalej podzielony na wiele sekcji. Struktura load command zawiera informacje o tych sekcjach w ramach odpowiedniego segmentu.

W nagłówku najpierw znajduje się nagłówek segmentu:

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

Ten nagłówek określa liczbę sekcji, których nagłówki pojawiają się po nim:
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

Jeśli **dodasz** **offset sekcji** (0x37DC) + **offset**, gdzie **arch** się zaczyna, w tym przypadku `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Można też uzyskać **informacje o nagłówkach** z **wiersza poleceń** przy użyciu:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** Wskazuje jądru, aby **zmapowało** **adres zero**, tak żeby **nie można było z niego czytać, zapisywać ani wykonywać**. Zmienne maxprot i minprot w strukturze są ustawione na zero, aby wskazać, że **na tej stronie nie ma praw do odczytu-zapisu-wykonania**.
- Ta alokacja jest ważna, aby **łagodzić luki wynikające z dereferencji NULL pointera**. XNU wymusza twardą stronę zero, która zapewnia, że pierwsza strona (tylko pierwsza) pamięci jest niedostępna (oprócz i386). Binarna może spełnić te wymagania przez stworzenie małego __PAGEZERO (używając `-pagezero_size`) aby pokryć pierwsze 4k i udostępnienie reszty pamięci 32-bitowej zarówno w trybie użytkownika, jak i jądra.
- **`__TEXT`**: Zawiera **kod wykonywalny** z prawami **odczytu** i **wykonania** (bez zapisu)**.** Typowe sekcje tego segmentu:
- `__text`: Skompilowany kod binarny
- `__const`: Dane stałe (tylko do odczytu)
- `__[c/u/os_log]string`: Stałe łańcuchy znaków C, Unicode lub logów os
- `__stubs` i `__stubs_helper`: Używane podczas procesu ładowania bibliotek dynamicznych
- `__unwind_info`: Dane do rozwijania stosu
- Należy zauważyć, że cała ta zawartość jest podpisana, ale także oznaczona jako wykonywalna (co stwarza więcej możliwości wykorzystania sekcji, które niekoniecznie potrzebują tego przywileju, jak sekcje przeznaczone dla łańcuchów znaków).
- **`__DATA`**: Zawiera dane, które są **do odczytu** i **zapisu** (bez możliwości wykonania)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Wskaźnik symbolu niedługiego (bind at load)
- `__la_symbol_ptr`: Wskaźnik symbolu leniwego (bind on use)
- `__const`: Powinny to być dane tylko do odczytu (w praktyce nie zawsze)
- `__cfstring`: Stringi CoreFoundation
- `__data`: Zmienne globalne (zainicjalizowane)
- `__bss`: Zmienne statyczne (niezainicjalizowane)
- `__objc_*` (__objc_classlist, __objc_protolist, itd): Informacje używane przez runtime Objective-C
- **`__DATA_CONST`**: __DATA.__const nie jest gwarantowane jako stałe (ma prawa zapisu), podobnie inne wskaźniki i GOT. Ta sekcja ustawia `__const`, niektóre inicjalizatory i tabelę GOT (po rozwiązaniu) jako tylko do odczytu przy użyciu `mprotect`.
- **`__LINKEDIT`**: Zawiera informacje dla linkera (dyld), takie jak wpisy tablic symboli, łańcuchów i relokacji. To ogólny kontener dla treści, które nie znajdują się w `__TEXT` ani `__DATA`, a jego zawartość jest opisana w innych poleceniach ładowania.
- informacje dyld: Rebase, Non-lazy/lazy/weak binding opcodes oraz informacje o eksporcie
- Początki funkcji: Tabela adresów początkowych funkcji
- Data In Code: Wyspy danych w __text
- Tabela symboli: Symbole w binarce
- Indirect Symbol Table: Symbole wskaźników/stubów
- String Table
- Code Signature
- **`__OBJC`**: Zawiera informacje używane przez runtime Objective-C. Chociaż te informacje mogą też występować w segmencie __DATA, w różnych sekcjach __objc_*.
- **`__RESTRICT`**: Segment bez zawartości z pojedynczą sekcją o nazwie **`__restrict`** (również pustą), który zapewnia, że podczas uruchamiania binarki będą ignorowane zmienne środowiskowe DYLD.

Jak można było zobaczyć w kodzie, **segmenty również obsługują flagi** (chociaż nie są one zbyt często używane):

- `SG_HIGHVM`: Tylko Core (nieużywane)
- `SG_FVMLIB`: Nieużywane
- `SG_NORELOC`: Segment nie ma relokacji
- `SG_PROTECTED_VERSION_1`: Szyfrowanie. Używane na przykład przez Finder do zaszyfrowania segmentu tekstowego `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** zawiera punkt wejścia w atrybucie **entryoff.** Podczas ładowania **dyld** po prostu **dodaje** tę wartość do (w pamięci) **bazy binarki**, a następnie **skacze** do tej instrukcji, aby rozpocząć wykonywanie kodu binarki.

**`LC_UNIXTHREAD`** zawiera wartości, jakie rejestry muszą mieć przy uruchamianiu głównego wątku. To zostało już zdeprecjonowane, ale **`dyld`** nadal z tego korzysta. Można zobaczyć ustawione wartości rejestrów za pomocą:
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


Zawiera informacje o **podpisie kodu pliku Macho-O**. Zawiera jedynie **offset**, który **wskazuje** na **signature blob**. Zazwyczaj znajduje się to na samym końcu pliku.\
However, you can find some information about this section in [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) and this [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Obsługa szyfrowania binarnego. Oczywiście, jeśli atakującemu uda się przejąć proces, będzie mógł zrzucić pamięć w formie nieszyfrowanej.

### **`LC_LOAD_DYLINKER`**

Zawiera **ścieżkę do wykonywalnego dynamic linker-a**, który mapuje shared libraries do przestrzeni adresowej procesu. **Wartość jest zawsze ustawiona na `/usr/lib/dyld`**. Ważne jest, że w macOS mapowanie dylib odbywa się w **trybie użytkownika**, a nie w **trybie jądra**.

### **`LC_IDENT`**

Przestarzały, lecz jeśli skonfigurowano generowanie zrzutów przy panic, tworzony jest core dump Mach-O, a wersja kernela jest zapisywana w poleceniu `LC_IDENT`.

### **`LC_UUID`**

Losowy UUID. Sam w sobie nie jest bezpośrednio bardzo użyteczny, ale XNU buforuje go wraz z resztą informacji o procesie. Może być używany w raportach awarii.

### **`LC_DYLD_ENVIRONMENT`**

Pozwala wskazać zmienne środowiskowe dla dyld przed uruchomieniem procesu. Może to być bardzo niebezpieczne, ponieważ może umożliwić wykonanie dowolnego kodu wewnątrz procesu, dlatego to polecenie ładowania jest używane tylko w buildzie dyld z `#define SUPPORT_LC_DYLD_ENVIRONMENT` i dodatkowo ogranicza przetwarzanie tylko do zmiennych w formie `DYLD_..._PATH` określających ścieżki ładowania.

### **`LC_LOAD_DYLIB`**

To polecenie ładowania opisuje zależność od **dynamic library**, które **nakazuje** loader-owi (dyld) **załadować i zlinkować tę bibliotekę**. Istnieje polecenie `LC_LOAD_DYLIB` **dla każdej biblioteki**, której wymaga binarka Mach-O.

- This load command is a structure of type **`dylib_command`** (which contains a struct dylib, describing the actual dependent dynamic library):
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

Możesz też uzyskać te informacje z cli za pomocą:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Niektóre potencjalne biblioteki związane z malware to:

- **DiskArbitration**: monitorowanie dysków USB
- **AVFoundation:** przechwytywanie audio i wideo
- **CoreWLAN**: skanowanie Wifi.

> [!TIP]
> Plik **Mach-O** może zawierać jednego lub **więcej** **konstruktorów**, które zostaną **wykonane** **przed** adresem określonym w **LC_MAIN**.\
> Offsety wszystkich konstruktorów znajdują się w sekcji **\_\_mod_init_func** segmentu **\_\_DATA_CONST**.

## **Dane Mach-O**

W rdzeniu pliku znajduje się obszar danych, który składa się z kilku segmentów zdefiniowanych w obszarze load-commands. **W każdym segmencie może być umieszczona różnorodność sekcji danych**, z każdą sekcją **zawierającą kod lub dane** specyficzne dla typu.

> [!TIP]
> Dane to zasadniczo część zawierająca wszystkie **informacje**, które są ładowane przez load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

To obejmuje:

- **Tabela funkcji:** która zawiera informacje o funkcjach programu.
- **Tablica symboli**: która zawiera informacje o funkcjach zewnętrznych używanych przez plik binarny
- Może też zawierać nazwy funkcji wewnętrznych, nazw zmiennych oraz inne informacje.

Aby to sprawdzić, możesz użyć narzędzia [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Albo z poziomu CLI:
```bash
size -m /bin/ls
```
## Sekcje wspólne Objective-C

W segmencie `__TEXT` (r-x):

- `__objc_classname`: Nazwy klas (łańcuchy znaków)
- `__objc_methname`: Nazwy metod (łańcuchy znaków)
- `__objc_methtype`: Typy metod (łańcuchy znaków)

W segmencie `__DATA` (rw-):

- `__objc_classlist`: Wskaźniki do wszystkich klas Objective-C
- `__objc_nlclslist`: Wskaźniki do Non-Lazy klas Objective-C
- `__objc_catlist`: Wskaźnik do kategorii
- `__objc_nlcatlist`: Wskaźnik do Non-Lazy kategorii
- `__objc_protolist`: Lista protokołów
- `__objc_const`: Dane stałe
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
