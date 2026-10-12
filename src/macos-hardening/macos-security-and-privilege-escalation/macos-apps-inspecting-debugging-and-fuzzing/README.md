# Aplikacje macOS — inspekcja, debugowanie i fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Analiza statyczna

### otool & objdump & nm

```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```

```bash
nm -m ./tccd # List of symbols
```

### Disarm (old jtool2)

Możesz [**pobrać disarm stąd**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Pamiętaj, że **`disarm`** może działać również ze skompresowanymi plikami IM4P (takimi jak `kernelcache`) i wyodrębniać tylko wymagane części, a nawet analizować wymaganą część bez jej wyodrębniania.

```bash
export JCOLOR=1
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled

disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache
JDEBUG=1 disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache with debug info
disarm -r "code signature" /bin/ps # Check code signature of a binary
disarm -e "code signature" /bin/ps # Extract code signature of a binary
```


### Codesign / ldid

> [!TIP]
> **`Codesign`** można znaleźć w **macOS**, a **`ldid`** w **iOS**.

```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```

### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) to przydatne narzędzie do inspekcji plików **.pkg** (instalatorów) i sprawdzania ich zawartości przed instalacją.\
Te instalatory zawierają skrypty bash `preinstall` i `postinstall`, które autorzy malware zwykle wykorzystują do zapewnienia **trwałości** **malware**.

### hdiutil

To narzędzie **montuje** pliki obrazów dysków Apple (`.dmg`), aby można je było sprawdzić przed uruchomieniem jakichkolwiek elementów:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

It zostanie zamontowany w `/Volumes`

### Spakowane pliki binarne

- Sprawdź, czy entropia jest wysoka
- Sprawdź ciągi znaków (jeśli prawie nie ma zrozumiałych ciągów, plik jest spakowany)
- Packer UPX dla macOS tworzy sekcję o nazwie `__XHDR`.

## Statyczna analiza Objective-C

### Metadane

> [!CAUTION]
> Zwróć uwagę, że programy napisane w Objective-C **zachowują** deklaracje klas **po** **skompilowaniu** do [plików binarnych Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Takie deklaracje klas **zawierają** nazwy i typy:

- Zdefiniowanych interfejsów
- Metod interfejsów
- Zmiennych instancji interfejsów
- Zdefiniowanych protokołów

Zwróć uwagę, że te nazwy mogą być zaciemnione, aby utrudnić analizę wsteczną pliku binarnego.

### Wywoływanie funkcji

Gdy w pliku binarnym używającym Objective-C wywoływana jest funkcja, skompilowany kod zamiast wywołać tę funkcję, wywołuje **`objc_msgSend`**. To właśnie ona wywoła właściwą funkcję:

![Metadane — wywoływanie funkcji: Gdy w pliku binarnym używającym Objective-C wywoływana jest funkcja, skompilowany kod zamiast wywołać tę funkcję, wywołuje objc msgSend. To właśnie ona...](<../../../images/image (305).png>)

Ta funkcja przyjmuje następujące parametry:

- Pierwszy parametr (**self**) to „wskaźnik wskazujący na **instancję klasy, która ma otrzymać wiadomość**”. Mówiąc prościej, jest to obiekt, na którym wywoływana jest metoda. Jeśli metoda jest metodą klasy, będzie to instancja obiektu klasy (jako całości), natomiast w przypadku metody instancji `self` będzie wskazywać na utworzoną instancję klasy jako obiekt.
- Drugi parametr (**op**) to „selektor metody obsługującej wiadomość”. Mówiąc prościej, jest to po prostu **nazwa metody**.
- Pozostałe parametry to dowolne **wartości wymagane przez metodę** (op).

Zobacz, jak **łatwo uzyskać te informacje za pomocą `lldb` w ARM64** na tej stronie:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Rejestr**                                                     | **(dla) objc_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1. argument**   | **rdi**                                                         | **self: obiekt, na którym wywoływana jest metoda**     |
| **2. argument**   | **rsi**                                                         | **op: nazwa metody**                                   |
| **3. argument**   | **rdx**                                                         | **1. argument metody**                                 |
| **4. argument**   | **rcx**                                                         | **2. argument metody**                                 |
| **5. argument**   | **r8**                                                          | **3. argument metody**                                 |
| **6. argument**   | **r9**                                                          | **4. argument metody**                                 |
| **7. i kolejne**  | <p><strong>rsp+</strong><br><strong>(na stosie)</strong></p>    | **5. i kolejne argumenty metody**                      |

### Zrzut metadanych ObjectiveC

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) to narzędzie do wykonywania class-dump plików binarnych Objective-C. Opis na GitHubie wspomina o dylibach, ale narzędzie działa również z plikami wykonywalnymi.

```bash
./dynadump dump /path/to/bin
```

W chwili pisania tego tekstu **to obecnie działa najlepiej**.

#### Standardowe narzędzia

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) to oryginalne narzędzie do generowania deklaracji klas, kategorii i protokołów w kodzie Objective-C.

Jest stare i nie jest już rozwijane, więc prawdopodobnie nie będzie działać poprawnie.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) to nowoczesne, wieloplatformowe narzędzie do zrzucania klas Objective-C. W przeciwieństwie do istniejących narzędzi iCDump może działać niezależnie od ekosystemu Apple i udostępnia powiązania z Pythonem.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Statyczna analiza Swift

W przypadku plików binarnych Swift, ze względu na zgodność z Objective-C, czasami można wyodrębnić deklaracje za pomocą [class-dump](https://github.com/nygard/class-dump/), ale nie zawsze.

Za pomocą poleceń **`jtool -l`** lub **`otool -l`** można znaleźć kilka sekcji, których nazwy zaczynają się od prefiksu **`__swift5`**:

```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
    [...]
    Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
    Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
    Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
    Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
    [...]
```

Więcej informacji o [**informacjach przechowywanych w tych sekcjach znajdziesz w tym wpisie na blogu**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Ponadto **pliki binarne Swift mogą zawierać symbole** (na przykład biblioteki muszą przechowywać symbole, aby można było wywoływać ich funkcje). **Symbole zwykle zawierają informacje o nazwie funkcji** i jej atrybutach, ale w nieczytelnej postaci, dlatego są bardzo przydatne. Istnieją też „**demanglery**”, które potrafią odtworzyć oryginalną nazwę:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Analiza dynamiczna

> [!WARNING]
> Pamiętaj, że aby debugować pliki binarne, **SIP musi być wyłączone** (`csrutil disable` lub `csrutil enable --without debug`). Możesz też skopiować pliki binarne do folderu tymczasowego i **usunąć podpis** poleceniem `codesign --remove-signature <binary-path>` albo zezwolić na debugowanie pliku binarnego (możesz użyć [tego skryptu](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Pamiętaj, że aby **instrumentować pliki binarne systemu** (takie jak `cloudconfigurationd`) w macOS, **SIP musi być wyłączone** (samo usunięcie podpisu nie wystarczy).

### API

macOS udostępnia kilka interesujących API, które dostarczają informacji o procesach:

- `proc_info`: To główne API dostarczające wielu informacji o każdym procesie. Aby uzyskać informacje o innych procesach, musisz mieć uprawnienia roota, ale nie potrzebujesz specjalnych entitlements ani portów mach.
- `libsysmon.dylib`: Udostępnia informacje o procesach za pośrednictwem funkcji XPC, ale wywołujący muszą mieć entitlement `com.apple.sysmond.client`.

### Stackshot i microstackshots

**Tworzenie stackshotów** to technika służąca do przechwytywania stanu procesów, w tym stosów wywołań wszystkich uruchomionych wątków. Jest szczególnie przydatna podczas debugowania, analizy wydajności i badania zachowania systemu w określonym momencie. W iOS i macOS stackshoty można tworzyć za pomocą kilku narzędzi i metod, takich jak **`sample`** i **`spindump`**.

### Sysdiagnose

To narzędzie (`/usr/bini/ysdiagnose`) zbiera wiele informacji z komputera, wykonując dziesiątki różnych poleceń, takich jak `ps`, `zprint`...

Musi być uruchomione jako **root**, a demon `/usr/libexec/sysdiagnosed` ma bardzo interesujące entitlements, takie jak `com.apple.system-task-ports` i `get-task-allow`.

Jego plist znajduje się w `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` i deklaruje 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Usuwa stare archiwa z /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Specjalny port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Interfejs w trybie użytkownika za pośrednictwem klasy Obj-C `Libsysdiagnose`. Można przekazać trzy argumenty w słowniku (`compress`, `display`, `run`)

### Ujednolicone logi

macOS generuje obszerne logi, które są przydatne podczas analizy zachowania aplikacji.

Niektóre pola logów zawierają tag `<private>`, aby ukryć informacje pozwalające zidentyfikować użytkownika lub urządzenie. Starsze instrukcje czasami opisują instalowanie certyfikatu, aby ujawnić te pola; aktualne wskazówki dotyczące debugowania zalecają natomiast użycie jawnie ograniczonego profilu konfiguracyjnego z `Enable-Private-Data` albo ustawienia `OSLogPreferences` dla poszczególnych aplikacji. Działanie może zależeć od podsystemu i wersji macOS. Omówienie starszego certyfikatu/profilu zachowano w źródłach. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Lewy panel

W lewym panelu Hoppera można zobaczyć symbole (**Labels**) pliku binarnego, listę procedur i funkcji (**Proc**) oraz ciągi znaków (**Str**). Nie są to wszystkie ciągi znaków, lecz te zdefiniowane w kilku częściach pliku Mac-O (takich jak _cstring lub_ `objc_methname`).

#### Środkowy panel

W środkowym panelu można zobaczyć **zdeasemblowany kod**. Można wyświetlić go jako **surowy** deasemblat, **graf**, **zdekompilowany kod** lub **kod binarny**, klikając odpowiednią ikonę:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Po kliknięciu prawym przyciskiem myszy obiektu kodu można zobaczyć **odwołania do tego obiektu i z niego** albo zmienić jego nazwę (nie działa to w zdekompilowanym pseudokodzie):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Ponadto, **w dolnej części środkowego panelu można wpisywać polecenia Pythona**.

#### Prawy panel

W prawym panelu można zobaczyć przydatne informacje, takie jak **historia nawigacji** (pozwalająca sprawdzić, jak dotarło się do bieżącego miejsca), **graf wywołań**, który pokazuje wszystkie **funkcje wywołujące daną funkcję** oraz wszystkie funkcje **wywoływane przez daną funkcję**, a także informacje o **zmiennych lokalnych**.

### dtrace

Umożliwia użytkownikom dostęp do aplikacji na niezwykle **niskim poziomie** oraz pozwala **śledzić** **programy**, a nawet zmieniać przebieg ich wykonania. Dtrace korzysta z **probe’ów** umieszczonych **w różnych miejscach jądra**, na przykład na początku i końcu wywołań systemowych.

DTrace używa funkcji **`dtrace_probe_create`** do utworzenia probe’a dla każdego wywołania systemowego. Probe’y te mogą być uruchamiane w **punkcie wejścia i wyjścia każdego wywołania systemowego**. Komunikacja z DTrace odbywa się przez /dev/dtrace, dostępne wyłącznie dla użytkownika root.<sup>[[1]](#references)</sup>

> [!TIP]
> Aby włączyć Dtrace bez całkowitego wyłączania ochrony SIP, możesz uruchomić w trybie odzyskiwania: `csrutil enable --without dtrace`
>
> Możesz też używać **`dtrace`** lub **`dtruss`** na plikach binarnych, które **zostały skompilowane przez Ciebie**.

Dostępne probe’y dtrace można wyświetlić za pomocą:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Nazwa sondy składa się z czterech części: dostawcy, modułu, funkcji i nazwy (`fbt:mach_kernel:ptrace:entry`). Jeśli nie określisz którejś części nazwy, DTrace potraktuje ją jako symbol wieloznaczny.

Aby skonfigurować DTrace tak, by aktywował sondy i określić, jakie działania mają być wykonywane po ich uruchomieniu, musimy użyć języka D.

Bardziej szczegółowe omówienie i więcej przykładów znajdziesz na stronie [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Przykłady

Uruchom `man -k dtrace`, aby wyświetlić **dostępne skrypty DTrace**. Przykład: `sudo dtruss -n binary`

- W linii

```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```

- skrypt

```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
    printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
        printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
        ;
}
syscall:::return
{
        printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```

### dtruss

```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```

### kdebug

To narzędzie do śledzenia działania jądra. Udokumentowane kody można znaleźć w **`/usr/share/misc/trace.codes`**.

Narzędzia takie jak `latency`, `sc_usage`, `fs_usage` i `trace` korzystają z niego wewnętrznie.

Do komunikacji z `kdebug` używa się `sysctl` w przestrzeni nazw `kern.kdebug`. MIB-y, których należy użyć, można znaleźć w `sys/sysctl.h`, a ich implementacje znajdują się w `bsd/kern/kdebug.c`.

Aby komunikować się z kdebug za pomocą własnego klienta, zwykle wykonuje się następujące kroki:

- Usuń istniejące ustawienia za pomocą KERN_KDSETREMOVE
- Skonfiguruj śledzenie za pomocą KERN_KDSETBUF i KERN_KDSETUP
- Użyj KERN_KDGETBUF, aby pobrać liczbę wpisów w buforze
- Pobierz własnego klienta ze śledzenia za pomocą KERN_KDPINDEX
- Włącz śledzenie za pomocą KERN_KDENABLE
- Odczytaj bufor, wywołując KERN_KDREADTR
- Aby przypisać każdy wątek do procesu, wywołaj KERN_KDTHRMAP.

Aby uzyskać te informacje, można użyć narzędzia Apple **`trace`** lub własnego narzędzia [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Pamiętaj, że z Kdebug może korzystać tylko jeden klient naraz.** Dlatego w danym momencie może działać tylko jedno narzędzie korzystające z k-debug.

### ktrace

API `ktrace_*` pochodzi z `libktrace.dylib`, która opakowuje funkcje Kdebug. Klient może więc po prostu wywołać `ktrace_session_create` oraz `ktrace_events_[single/class]`, aby ustawić callbacki dla określonych kodów, a następnie uruchomić śledzenie za pomocą `ktrace_start`.

Można z niego korzystać również przy **włączonym SIP**.

Jako klienta można użyć narzędzia `ktrace`:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Lub `tailspin`.

### kperf

Służy do profilowania na poziomie jądra i jest zbudowany z użyciem punktów wywołań `Kdebug`.

Zasadniczo sprawdzana jest zmienna globalna `kernel_debug_active`. Jeśli jest ustawiona, wywoływana jest funkcja `kperf_kdebug_handler` z kodem `Kdebug` i adresem ramki jądra, która ją wywołała. Jeśli kod `Kdebug` pasuje do jednego z wybranych kodów, pobierane są skonfigurowane „akcje” w postaci bitmapy (dostępne opcje można sprawdzić w `osfmk/kperf/action.h`).

Kperf ma również tabelę MIB sysctl: (jako root) `sysctl kperf`. Kod ten znajduje się w `osfmk/kperf/kperfbsd.c`.

Ponadto część funkcjonalności Kperf znajduje się w `kpc`, który udostępnia informacje o licznikach wydajności maszyny.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) to bardzo przydatne narzędzie do sprawdzania działań związanych z procesami, które wykonuje dany proces (na przykład do monitorowania, jakie nowe procesy tworzy).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) to narzędzie, które wyświetla relacje między procesami.\
Należy monitorować komputer Mac za pomocą polecenia takiego jak **`sudo eslogger fork exec rename create > cap.json`** (terminal, z którego uruchamiane jest polecenie, wymaga FDA). Następnie można wczytać plik JSON do tego narzędzia, aby wyświetlić wszystkie relacje:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) monitoruje zdarzenia dotyczące plików, takie jak ich tworzenie, modyfikowanie i usuwanie.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) to narzędzie GUI, którego wygląd i obsługa mogą być znane użytkownikom Windows z programu _Procmon_ firmy Microsoft Sysinternals. Umożliwia rozpoczęcie i zatrzymanie rejestrowania różnych typów zdarzeń, filtrowanie ich według kategorii, takich jak pliki, procesy, sieć itp., oraz zapisywanie zarejestrowanych zdarzeń w formacie JSON.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) wchodzi w skład narzędzi deweloperskich Xcode — służy do monitorowania wydajności aplikacji, wykrywania wycieków pamięci i śledzenia aktywności systemu plików.

![Crescendo - Apple Instruments: Apple Instruments wchodzi w skład narzędzi deweloperskich Xcode — służy do monitorowania wydajności aplikacji, wykrywania wycieków pamięci i śledzenia aktywności systemu plików](<../../../images/image (1138).png>)

### fs_usage

Umożliwia śledzenie działań wykonywanych przez procesy:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) jest przydatny do przeglądania **bibliotek** używanych przez plik binarny, **plików**, z których korzysta, oraz **połączeń sieciowych**.\
Sprawdza też procesy binarne w **virustotal** i wyświetla informacje o pliku binarnym.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

W [**tym wpisie na blogu**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) znajdziesz przykład tego, jak **debugować działający daemon**, który używał **`PT_DENY_ATTACH`**, aby uniemożliwić debugowanie, nawet gdy SIP był wyłączony.<sup>[[6]](#references)</sup>

### lldb

**lldb** to de facto **narzędzie** do **debugowania** binariów **macOS**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Możesz ustawić wariant składni Intel podczas korzystania z lldb, tworząc plik **`.lldbinit`** w folderze domowym z następującym wierszem:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> W lldb zrzuć proces za pomocą `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Command</strong></td><td><strong>Opis</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Uruchamia wykonanie, które będzie kontynuowane do momentu trafienia na breakpoint lub zakończenia procesu.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Uruchamia wykonanie i zatrzymuje je w punkcie wejścia.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Wznawia wykonanie debugowanego procesu.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Wykonuje następną instrukcję. To polecenie pomija wywołania funkcji.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Wykonuje następną instrukcję. W odróżnieniu od polecenia <code>nexti</code>, to polecenie wchodzi do wywoływanych funkcji.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Wykonuje pozostałe instrukcje bieżącej funkcji (ramki), wraca z niej i zatrzymuje wykonanie.</td></tr>
<tr><td><strong>control + c</strong></td><td>Wstrzymuje wykonanie. Jeśli proces został uruchomiony (<code>r</code>) lub wznowiony (<code>c</code>), powoduje jego zatrzymanie w miejscu, w którym aktualnie się wykonuje.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Dowolna funkcja o nazwie main</p>
<p><code>b &lt;binname&gt;`main</code> # Funkcja główna pliku binarnego</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Funkcja główna wskazanego pliku binarnego</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Dowolna metoda NSFileManager</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Breakpoint we wszystkich funkcjach tej biblioteki</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Lista breakpointów</p>
<p><code>br e/dis &lt;num&gt;</code> # Włączenie/wyłączenie breakpointu</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Wyświetla pomoc dotyczącą polecenia breakpoint</p>
<p><code>help memory write</code> # Wyświetla pomoc dotyczącą zapisu do pamięci</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Wyświetla pamięć jako ciąg znaków zakończony znakiem null.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Wyświetla pamięć jako instrukcję asemblera.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Wyświetla pamięć jako bajt.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Wyświetla obiekt wskazany przez parametr.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
Większość interfejsów API lub metod Apple Objective-C zwraca obiekty, dlatego należy je wyświetlać poleceniem „print object” (<code>po</code>). Jeśli <code>po</code> nie zwraca przydatnych wyników, użyj <code>x/b</code>.
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Zapisuje AAAA pod tym adresem<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Zapisuje AAAA pod tym adresem
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Dezasembluje bieżącą funkcję</p>
<p><code>dis -n &lt;funcname&gt;</code> # Dezasembluje funkcję</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Dezasembluje funkcję<br>
<code>dis -c 6</code> # Dezasembluje sześć wierszy<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Dezasembluje kod od jednego adresu do drugiego<br>
<code>dis -p -c 4</code> # Rozpoczyna dezasemblację od bieżącego adresu</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Sprawdza tablicę złożoną z trzech elementów w rejestrze <code>x1</code></td></tr>
<tr><td><strong>image dump sections</strong></td><td>Wyświetla mapę pamięci bieżącego procesu.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Wyświetla adres każdego symbolu z CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> Podczas wywoływania funkcji **`objc_sendMsg`** rejestr **rsi** zawiera **nazwę metody** jako ciąg znaków zakończony znakiem null („C”). Aby wyświetlić nazwę za pomocą lldb, wykonaj:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Analiza antydynamiczna

#### Wykrywanie VM

- Polecenie **`sysctl hw.model`** zwykle zwraca identyfikator modelu Maca na fizycznym sprzęcie, a w VM może zwrócić inną wartość.<sup>[[3]](#references)</sup>
- Manipulując wartościami **`hw.logicalcpu`** i **`hw.physicalcpu`**, niektóre malware próbują wykryć, czy działają w VM.<sup>[[4]](#references)</sup>
- Niektóre malware mogą też **wykryć**, czy maszyna korzysta z **VMware**, na podstawie adresu MAC (00:50:56).
- Można również sprawdzić, **czy proces jest debugowany**, za pomocą prostego kodu, takiego jak:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Proces może też wywołać wywołanie systemowe **`ptrace`** z flagą **`PT_DENY_ATTACH`**. Zapobiega to dołączeniu debuggera i śledzeniu procesu.
  - Możesz sprawdzić, czy funkcja **`sysctl`** lub **`ptrace`** jest **importowana** (ale malware może importować ją dynamicznie).
  - Jak opisano w tym writeupie, „[Pokonywanie technik antydebugowania: warianty macOS ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    „_Komunikat Process # exited with **status = 45 (0x0000002d)** zwykle wskazuje, że debugowany proces używa **PT_DENY_ATTACH**_”

#### Przekazanie procesu `fork()`

Proces może uniknąć debuggera, który pozostaje podłączony do pierwotnego PID, wywołując `fork()` tuż po uruchomieniu, kończąc działanie procesu nadrzędnego (`fork()` zwraca dodatni PID procesu potomnego) i kontynuując chronioną logikę wyłącznie w procesie potomnym (`fork()` zwraca `0`). Rozwiązanie symbolu `fork` za pomocą `dlsym(RTLD_DEFAULT, "fork")` usuwa również bezpośrednie miejsce wywołania `_fork`, ale stanowi jedynie przeszkodę dla analizy: ciąg znaków z nazwą symbolu i przepływ danych związany z jego dynamicznym rozwiązywaniem pozostają widoczne w pliku binarnym Mach-O.<sup>[[10]](#references)[[11]](#references)</sup>

Na arm64 wykrywaj ten wzorzec, śledząc przepływ danych, a nie stałe adresy: pierwsze dwa argumenty `dlsym` są przekazywane w `x0` i `x1`, `RTLD_DEFAULT` może występować jako `-2` (na przykład `movn x0, #1`), a para `adrp`/`add` często tworzy adres ciągu `"fork"`. Po instrukcji `bl` wywołującej stub `dlsym` śledź zwrócony wskaźnik z `x0` przez sprawdzenie wartości null i zapis, aż do późniejszej pośredniej instrukcji `blr`. Następnie śledź wynik `fork()` w `w0`: wartość zero wybiera dalszą ścieżkę procesu potomnego, natomiast wartości dodatnie i `-1` wybierają ścieżkę procesu nadrzędnego lub obsługi błędu.<sup>[[10]](#references)[[11]](#references)</sup>

Statyczne obejście polega na pominięciu pośredniego wywołania i wymuszeniu, by istniejące sprawdzenie wyniku wybrało ścieżkę procesu potomnego. Na przykład, jeśli kompilator wygenerował pokazaną poniżej sekwencję, zastąp instrukcje `blr` i zapisu wyniku instrukcją `nop`, ustaw syntetyczny wynik na zero i pozostaw logikę porównania oraz skoku. Aplikacja będzie wtedy kontynuować działanie pod pierwotnym PID bez tworzenia procesu potomnego; rejestry instrukcji i cele skoków należy dostosować do analizowanej wersji.<sup>[[10]](#references)[[11]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## Zrzuty pamięci

Zrzuty pamięci są tworzone, jeśli:

- sysctl `kern.coredump` jest ustawiony na 1 (domyślnie)
- Proces nie działał jako suid/sgid lub `kern.sugid_coredump` jest ustawiony na 1 (domyślnie 0)
- Limit `AS_CORE` zezwala na tę operację. Można zablokować tworzenie zrzutów pamięci, wywołując `ulimit -c 0`, i ponownie je włączyć za pomocą `ulimit -c unlimited`.

W takich przypadkach zrzuty pamięci są generowane zgodnie z ustawieniem sysctl `kern.corefile` i zwykle zapisywane w `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizuje procesy, które uległy awarii, i zapisuje raport o awarii na dysku**. Raport o awarii zawiera informacje, które mogą **pomóc deweloperowi zdiagnozować** przyczynę awarii.\
W przypadku aplikacji i innych procesów **działających w kontekście launchd danego użytkownika** ReportCrash działa jako LaunchAgent i zapisuje raporty o awarii w katalogu użytkownika `~/Library/Logs/DiagnosticReports/`\
W przypadku demonów, innych procesów **działających w kontekście systemowego launchd** oraz innych uprzywilejowanych procesów ReportCrash działa jako LaunchDaemon i zapisuje raporty o awarii w systemowym katalogu `/Library/Logs/DiagnosticReports`

Jeśli obawiasz się, że raporty o awarii **są wysyłane do Apple**, możesz je wyłączyć. W przeciwnym razie raporty o awarii mogą pomóc **ustalić, dlaczego serwer uległ awarii**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Uśpienie

Podczas fuzzingu w macOS zapobiegaj usypianiu Maca:

- systemsetup -setsleep Never
- pmset, Preferencje systemowe
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Rozłączanie SSH

Jeśli przeprowadzasz fuzzing przez połączenie SSH, ważne jest, aby sesja nie została rozłączona. Zmień więc plik sshd_config, ustawiając:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Wewnętrzne procedury obsługi

**Sprawdź poniższą stronę**, aby dowiedzieć się, jak znaleźć aplikację odpowiedzialną za **obsługę określonego schematu lub protokołu:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerowanie procesów sieciowych

To przydatne przy wyszukiwaniu procesów obsługujących dane sieciowe:

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

Lub użyj `netstat` lub `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Działa z narzędziami CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

„**po prostu działa**” z wieloma narzędziami GUI w macOS. Niektóre aplikacje mają dodatkowe wymagania, takie jak unikalne nazwy plików, określone rozszerzenie lub odczytywanie plików z kontenera sandbox (`~/Library/Containers/com.apple.Safari/Data`).

Przykłady:

```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```

### Więcej informacji o fuzzingu w macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [Reagowanie na incydenty w OS X: skrypty i analiza](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Sztuka złośliwego oprogramowania na Maca, tom I: analiza](https://taomm.org/)
- [4] [No Starch Press - Sztuka złośliwego oprogramowania na Maca: przewodnik po analizie złośliwego oprogramowania](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - informacje przechowywane w tych sekcjach we wpisie na blogu](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Debugowanie plików binarnych Apple korzystających z Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Omijanie technik anti-debug: warianty ptrace w macOS](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Fora Apple Developer - ustrukturyzowane logi Xcode i `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - Wyświetlanie prywatnych danych w ujednoliconym logu macOS](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [tony-go/antidebug-examples - przykłady fork](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [11] [Reverse Society - technika anti-debug z użyciem dlsym i fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
{{#include ../../../banners/hacktricks-training.md}}
