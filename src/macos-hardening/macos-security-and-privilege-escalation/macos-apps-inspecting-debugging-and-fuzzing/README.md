# Aplikacje macOS - Inspekcja, debugowanie i Fuzzing

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
> Pamiętaj, że **`disarm`** może również pracować ze skompresowanymi plikami IM4P (takimi jak `kernelcache`) i wyodrębniać tylko wymagane części lub nawet analizować wymaganą część bez jej wyodrębniania.
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
> **`Codesign`** można znaleźć w **macOS**, natomiast **`ldid`** można znaleźć w **iOS**
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) to narzędzie przydatne do inspekcji plików **.pkg** (instalatorów) i sprawdzania ich zawartości przed instalacją.\
Te instalatory zawierają skrypty bash `preinstall` i `postinstall`, które autorzy malware często wykorzystują do **utrwalania** **tego** **malware**.

### hdiutil

To narzędzie umożliwia **montowanie** obrazów dysków Apple (**.dmg**) w celu ich inspekcji przed uruchomieniem czegokolwiek:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Zostanie zamontowany w `/Volumes`

### Spakowane pliki binarne

- Sprawdź wysoką entropię
- Sprawdź strings (jeśli prawie nie ma zrozumiałych stringów, plik jest spakowany)
- Packer UPX dla MacOS generuje sekcję o nazwie "\_\_XHDR"

## Analiza statyczna Objective-C

### Metadane

> [!CAUTION]
> Pamiętaj, że programy napisane w Objective-C **zachowują** swoje deklaracje klas po **skompilowaniu** do [plików binarnych Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Takie deklaracje klas **zawierają** nazwę i typ:

- Zdefiniowanych interfejsów
- Metod interfejsów
- Zmiennych instancji interfejsów
- Zdefiniowanych protokołów

Pamiętaj, że te nazwy mogą zostać zaciemnione, aby utrudnić reverse engineering pliku binarnego.

### Wywoływanie funkcji

Gdy funkcja jest wywoływana w pliku binarnym wykorzystującym Objective-C, skompilowany kod zamiast wywoływać tę funkcję, wywoła **`objc_msgSend`**, które wywoła funkcję docelową:

![Metadane — wywoływanie funkcji: Gdy funkcja jest wywoływana w pliku binarnym wykorzystującym Objective-C, skompilowany kod zamiast wywoływać tę funkcję, wywoła objc msgSend. Które będzie...](<../../../images/image (305).png>)

Parametry oczekiwane przez tę funkcję to:

- Pierwszy parametr (**self**) to „wskaźnik wskazujący na **instancję klasy, która ma odebrać wiadomość**”. Mówiąc prościej, jest to obiekt, na którym wywoływana jest metoda. Jeśli metoda jest metodą klasową, będzie to instancja obiektu klasy (jako całości), natomiast w przypadku metody instancji self będzie wskazywać na utworzoną instancję klasy jako obiekt.
- Drugi parametr (**op**) to „selector metody obsługującej wiadomość”. Mówiąc prościej, jest to po prostu **nazwa metody**.
- Pozostałe parametry to wszelkie **wartości wymagane przez metodę** (op).

Zobacz, jak łatwo **uzyskać te informacje za pomocą `lldb` w ARM64** na tej stronie:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**       | **Rejestr**                                                     | **(dla) objc_msgSend**                                  |
| ------------------ | -------------------------------------------------------------- | ------------------------------------------------------ |
| **1. argument**    | **rdi**                                                         | **self: obiekt, na którym wywoływana jest metoda**     |
| **2. argument**    | **rsi**                                                         | **op: nazwa metody**                                    |
| **3. argument**    | **rdx**                                                         | **1. argument metody**                                  |
| **4. argument**    | **rcx**                                                         | **2. argument metody**                                  |
| **5. argument**    | **r8**                                                          | **3. argument metody**                                  |
| **6. argument**    | **r9**                                                          | **4. argument metody**                                  |
| **7.+ argument**   | <p><strong>rsp+</strong><br><strong>(na stosie)</strong></p> | **5.+ argument metody**                             |

### Zrzut metadanych ObjectiveC

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) to narzędzie do class-dump plików binarnych Objective-C. Na GitHubie podano dylibs, ale działa ono również z plikami wykonywalnymi.
```bash
./dynadump dump /path/to/bin
```
W momencie pisania jest to **obecnie rozwiązanie, które działa najlepiej**.

#### Standardowe narzędzia
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) to oryginalne narzędzie generujące deklaracje klas, kategorii i protokołów w sformatowanym kodzie Objective-C.

Jest stare i nieutrzymywane, więc prawdopodobnie nie będzie działać poprawnie.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) to nowoczesne i wieloplatformowe narzędzie do wykonywania class dump w Objective-C. W porównaniu z istniejącymi narzędziami iCDump może działać niezależnie od ekosystemu Apple i udostępnia powiązania Python.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Statyczna analiza Swift

W przypadku plików binarnych Swift, ze względu na zgodność z Objective-C, czasami można wyodrębnić deklaracje za pomocą [class-dump](https://github.com/nygard/class-dump/), ale nie zawsze.

Za pomocą wierszy poleceń **`jtool -l`** lub **`otool -l`** można znaleźć kilka sekcji, których nazwy zaczynają się od prefiksu **`__swift5`**:
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
Dalsze informacje o [**informacjach przechowywanych w tych sekcjach znajdziesz w tym wpisie na blogu**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Ponadto **Swift binaries mogą zawierać symbols** (na przykład biblioteki muszą przechowywać symbols, aby można było wywoływać ich funkcje). **Symbols zwykle zawierają informacje o nazwie funkcji** i jej atrybutach w nieczytelnej formie, dlatego są bardzo przydatne, a dostępne są narzędzia typu **"demanglers"**, które mogą uzyskać oryginalną nazwę:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Analiza dynamiczna

> [!WARNING]
> Pamiętaj, że aby debugować pliki binarne, **SIP musi być wyłączony** (`csrutil disable` lub `csrutil enable --without debug`) albo należy skopiować pliki binarne do folderu tymczasowego i **usunąć podpis** za pomocą `codesign --remove-signature <binary-path>`, ewentualnie zezwolić na debugowanie pliku binarnego (możesz użyć [tego skryptu](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Pamiętaj, że aby **instrumentować systemowe pliki binarne** (takie jak `cloudconfigurationd`) w macOS, **SIP musi być wyłączony** (samo usunięcie podpisu nie zadziała).

### APIs

macOS udostępnia interesujące APIs, które dostarczają informacji o procesach:

- `proc_info`: To główny mechanizm dostarczający wiele informacji o każdym procesie. Aby uzyskać informacje o innych procesach, musisz być użytkownikiem root, ale nie potrzebujesz specjalnych entitlements ani portów mach.
- `libsysmon.dylib`: Umożliwia uzyskiwanie informacji o procesach za pośrednictwem funkcji udostępnianych przez XPC, jednak wymagane jest entitlement `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** to technika używana do przechwytywania stanu procesów, w tym call stacks wszystkich uruchomionych wątków. Jest szczególnie przydatna podczas debugowania, analizy wydajności i poznawania zachowania systemu w określonym momencie. W systemach iOS i macOS stackshotting można wykonywać za pomocą kilku narzędzi i metod, takich jak narzędzia **`sample`** i **`spindump`**.

### Sysdiagnose

To narzędzie (`/usr/bini/ysdiagnose`) zasadniczo zbiera wiele informacji z komputera, wykonując dziesiątki różnych poleceń, takich jak `ps`, `zprint`...

Musi być uruchamiane jako **root**, a daemon `/usr/libexec/sysdiagnosed` ma bardzo interesujące entitlements, takie jak `com.apple.system-task-ports` i `get-task-allow`.

Jego plist znajduje się w `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, który deklaruje 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Usuwa stare archiwa z /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Special port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Interfejs user mode za pośrednictwem klasy Obj-C `Libsysdiagnose`. Można przekazać trzy argumenty w dict (`compress`, `display`, `run`)

### Unified Logs

macOS generuje wiele logów, które mogą być bardzo przydatne podczas uruchamiania aplikacji i próby zrozumienia **co ona robi**.

Ponadto niektóre logi będą zawierać tag `<private>`, aby **ukryć** niektóre informacje umożliwiające **identyfikację** **użytkownika** lub **komputera**. Możliwe jest jednak **zainstalowanie certyfikatu w celu ujawnienia tych informacji**. Postępuj zgodnie z wyjaśnieniami [**tutaj**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Lewy panel

W lewym panelu Hoppera można zobaczyć symbole (**Labels**) pliku binarnego, listę procedur i funkcji (**Proc**) oraz stringi (**Str**). Nie są to wszystkie stringi, lecz te zdefiniowane w kilku częściach pliku Mac-O (takich jak _cstring lub `objc_methname`).

#### Środkowy panel

W środkowym panelu można zobaczyć **zdisassemblowany kod**. Można go wyświetlić jako disassemble **raw**, **graph**, **decompiled** lub **binary**, klikając odpowiednią ikonę:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Klikając prawym przyciskiem myszy obiekt kodu, można zobaczyć **references to/from that object** lub nawet zmienić jego nazwę (nie działa to w zdekompilowanym pseudokodzie):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Ponadto w **dolnej części środkowego panelu można wpisywać polecenia Pythona**.

#### Prawy panel

W prawym panelu można zobaczyć interesujące informacje, takie jak **historia nawigacji** (dzięki czemu wiadomo, jak dotarło się do bieżącej sytuacji), **graf wywołań**, w którym można zobaczyć wszystkie **funkcje wywołujące tę funkcję** oraz wszystkie funkcje, które **ta funkcja wywołuje**, a także informacje o **zmiennych lokalnych**.

### dtrace

Umożliwia użytkownikom dostęp do aplikacji na niezwykle **niskim poziomie** i zapewnia sposób na **śledzenie** **programów**, a nawet zmianę ich przebiegu wykonywania. Dtrace używa **probes**, które są **rozmieszczone w całym kernelu**, w lokalizacjach takich jak początek i koniec wywołań systemowych.

DTrace używa funkcji **`dtrace_probe_create`** do utworzenia probe dla każdego wywołania systemowego. Probes te mogą być uruchamiane w **punkcie wejścia i wyjścia każdego wywołania systemowego**. Interakcja z DTrace odbywa się za pośrednictwem /dev/dtrace, który jest dostępny wyłącznie dla użytkownika root.<sup>[[1]](#references)</sup>

> [!TIP]
> Aby włączyć Dtrace bez całkowitego wyłączania ochrony SIP, możesz wykonać w trybie recovery: `csrutil enable --without dtrace`
>
> Możesz także używać plików binarnych **`dtrace`** lub **`dtruss`**, które **skompilowałeś**.

Dostępne probes dtrace można uzyskać za pomocą:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Nazwa probe składa się z czterech części: provider, module, function oraz name (`fbt:mach_kernel:ptrace:entry`). Jeśli nie określisz którejś części nazwy, DTrace zastosuje dla niej wildcard.

Aby skonfigurować DTrace tak, by aktywował probe oraz określić, jakie działania mają być wykonywane po ich uruchomieniu, musimy użyć języka D.

Bardziej szczegółowe wyjaśnienie i więcej przykładów można znaleźć pod adresem [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Przykłady

Uruchom `man -k dtrace`, aby wyświetlić **dostępne skrypty DTrace**. Przykład: `sudo dtruss -n binary`

- W wierszu
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

To mechanizm śledzenia jądra. Udokumentowane kody można znaleźć w **`/usr/share/misc/trace.codes`**.

Narzędzia takie jak `latency`, `sc_usage`, `fs_usage` i `trace` używają go wewnętrznie.

Do komunikacji z `kdebug` używa się `sysctl` w przestrzeni nazw `kern.kdebug`, a MIB-y, których należy użyć, można znaleźć w `sys/sysctl.h`; funkcje te są zaimplementowane w `bsd/kern/kdebug.c`.

Aby komunikować się z kdebug za pomocą niestandardowego klienta, zwykle wykonuje się następujące kroki:

- Usuń istniejące ustawienia za pomocą KERN_KDSETREMOVE
- Ustaw trace za pomocą KERN_KDSETBUF i KERN_KDSETUP
- Użyj KERN_KDGETBUF, aby pobrać liczbę wpisów bufora
- Usuń własnego klienta z trace za pomocą KERN_KDPINDEX
- Włącz tracing za pomocą KERN_KDENABLE
- Odczytaj bufor, wywołując KERN_KDREADTR
- Aby powiązać każdy wątek z jego procesem, wywołaj KERN_KDTHRMAP.

Aby uzyskać te informacje, można użyć narzędzia Apple **`trace`** lub niestandardowego narzędzia [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Pamiętaj, że Kdebug jest dostępny tylko dla 1 klienta jednocześnie.** Oznacza to, że w danym momencie można uruchomić tylko jedno narzędzie korzystające z k-debug.

### ktrace

API `ktrace_*` pochodzą z `libktrace.dylib`, która opakowuje API Kdebug. Następnie klient może po prostu wywołać `ktrace_session_create` oraz `ktrace_events_[single/class]`, aby ustawić callbacki dla określonych kodów, a następnie uruchomić je za pomocą `ktrace_start`.

Możesz używać tego także przy **aktywowanym SIP**

Jako klientów możesz używać narzędzia `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Lub `tailspin`.

### kperf

Służy do profilowania na poziomie kernela i jest zbudowane przy użyciu wywołań `Kdebug`.

Zasadniczo sprawdzana jest zmienna globalna `kernel_debug_active`; jeśli jest ustawiona, wywołuje `kperf_kdebug_handler` z kodem `Kdebug` oraz adresem ramki kernela, która ją wywołuje. Jeśli kod `Kdebug` pasuje do jednego z wybranych kodów, pobiera skonfigurowane „actions” w postaci bitmapy (sprawdź `osfmk/kperf/action.h`, aby zobaczyć dostępne opcje).

Kperf ma również tabelę sysctl MIB: (jako root) `sysctl kperf`. Kod można znaleźć w `osfmk/kperf/kperfbsd.c`.

Ponadto podzbiór funkcjonalności Kperf znajduje się w `kpc`, które dostarcza informacji o licznikach wydajności maszyny.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) to bardzo przydatne narzędzie do sprawdzania działań związanych z procesami (na przykład monitorowania, jakie nowe procesy dany proces tworzy).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) to narzędzie wyświetlające relacje między procesami.\
Musisz monitorować komputer Mac za pomocą polecenia takiego jak **`sudo eslogger fork exec rename create > cap.json`** (terminal uruchamiający to polecenie wymaga FDA). Następnie możesz załadować plik json do tego narzędzia, aby wyświetlić wszystkie relacje:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) umożliwia monitorowanie zdarzeń dotyczących plików (takich jak ich tworzenie, modyfikowanie i usuwanie), dostarczając szczegółowych informacji o tych zdarzeniach.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) to narzędzie GUI o wyglądzie i sposobie działania znanym użytkownikom Windows z Microsoft Sysinternal’s _Procmon_. Narzędzie umożliwia rozpoczynanie i zatrzymywanie rejestrowania różnych typów zdarzeń, filtrowanie tych zdarzeń według kategorii, takich jak pliki, procesy, sieć itd., a także zapisywanie zarejestrowanych zdarzeń w formacie json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) wchodzą w skład narzędzi deweloperskich Xcode – służą do monitorowania wydajności aplikacji, identyfikowania memory leaks oraz śledzenia aktywności systemu plików.

![Crescendo - Apple Instruments: Apple Instruments wchodzą w skład narzędzi deweloperskich Xcode – służą do monitorowania wydajności aplikacji, identyfikowania memory leaks oraz śledzenia aktywności systemu plików](<../../../images/image (1138).png>)

### fs_usage

Umożliwia śledzenie działań wykonywanych przez procesy:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) jest przydatny do przeglądania **bibliotek** używanych przez plik binarny, **plików**, z których korzysta, oraz **połączeń** sieciowych.\
Sprawdza również procesy pliku binarnego w **virustotal** i wyświetla informacje o pliku binarnym.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

W [**tym wpisie na blogu**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) znajdziesz przykład tego, jak **debugować uruchomiony daemon**, który używał **`PT_DENY_ATTACH`**, aby uniemożliwić debugowanie, nawet gdy SIP było wyłączone.<sup>[[6]](#references)</sup>

### lldb

**lldb** to de facto narzędzie do **debugowania** plików binarnych systemu **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Możesz ustawić składnię intel podczas korzystania z lldb, tworząc w swoim folderze domowym plik **`.lldbinit`** zawierający następującą linię:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Wewnątrz lldb zrzuć proces za pomocą `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Command</strong></td><td><strong>Opis</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Rozpoczęcie wykonywania, które będzie kontynuowane bez przerwy do momentu napotkania breakpointu lub zakończenia procesu.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Rozpoczęcie wykonywania z zatrzymaniem w punkcie wejścia</td></tr><tr><td><strong>continue (c)</strong></td><td>Kontynuowanie wykonywania debugowanego procesu.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Wykonanie następnej instrukcji. To polecenie pomija wywołania funkcji.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Wykonanie następnej instrukcji. W przeciwieństwie do polecenia nexti, to polecenie wchodzi do wywołań funkcji.</td></tr><tr><td><strong>finish (f)</strong></td><td>Wykonanie pozostałych instrukcji w bieżącej funkcji („frame”), powrót i zatrzymanie.</td></tr><tr><td><strong>control + c</strong></td><td>Wstrzymanie wykonywania. Jeśli proces został uruchomiony za pomocą (r) lub wznowiony za pomocą (c), spowoduje to zatrzymanie procesu ...w miejscu, w którym aktualnie wykonuje kod.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Any func called main</p><p><code>b <binname>`main</code> #Main func of the bin</p><p><code>b set -n main --shlib <lib_name></code> #Main func of the indicated bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Any NSFileManager method</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Breakpoint list</p><p><code>br e/dis <num></code> #Enable/Disable breakpoint</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Get help of breakpoint command</p><p>help memory write #Get help to write into the memory</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>Wyświetlenie pamięci jako ciągu znaków zakończonego znakiem null.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>Wyświetlenie pamięci jako instrukcji asemblera.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>Wyświetlenie pamięci jako bajtu.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Spowoduje to wyświetlenie obiektu wskazywanego przez parametr</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Należy pamiętać, że większość API lub metod Objective-C firmy Apple zwraca obiekty, dlatego należy je wyświetlać za pomocą polecenia „print object” (po). Jeśli po nie generuje sensownego wyniku, użyj <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address<br>memory write -f s $rip+0x11f+7 "AAAA" #Write AAAA in the addr</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas current function</p><p>dis -n <funcname> #Disas func</p><p>dis -n <funcname> -b <basename> #Disas func<br>dis -c 6 #Disas 6 lines<br>dis -c 0x100003764 -e 0x100003768 # From one add until the other<br>dis -p -c 4 # Start in current address disassembling</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Check array of 3 components in x1 reg</td></tr><tr><td><strong>image dump sections</strong></td><td>Wyświetlenie mapy pamięci bieżącego procesu</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Get the address of all the symbols from CoreNLP</td></tr></tbody></table>

> [!TIP]
> Podczas wywoływania funkcji **`objc_sendMsg`** rejestr **rsi** zawiera **nazwę metody** jako ciąg znaków zakończony znakiem null („C”). Aby wyświetlić nazwę za pomocą lldb, wykonaj:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### Wykrywanie VM

- Polecenie **`sysctl hw.model`** zwraca „Mac”, gdy **hostem jest MacOS**, ale inną wartość, gdy system działa na VM.<sup>[[3]](#references)</sup>
- Manipulując wartościami **`hw.logicalcpu`** i **`hw.physicalcpu`**, niektóre malware próbują wykryć, czy działają na VM.<sup>[[4]](#references)</sup>
- Niektóre malware mogą również **wykryć**, czy komputer korzysta z **VMware**, na podstawie adresu MAC (00:50:56).
- Możliwe jest także ustalenie, **czy proces jest debugowany**, za pomocą prostego kodu, takiego jak:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Można również wywołać wywołanie systemowe **`ptrace`** z flagą **`PT_DENY_ATTACH`**. Uniemożliwia to **debuggerowi** dołączenie do procesu i jego śledzenie.
- Możesz sprawdzić, czy funkcja **`sysctl`** lub **`ptrace`** jest **importowana** (malware może jednak importować ją dynamicznie)
- Jak zauważono w tym writeupie „[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)”:<sup>[[7]](#references)</sup>\
„_Komunikat Process # exited with **status = 45 (0x0000002d)** jest zwykle wyraźnym sygnałem, że debugowany cel używa **PT_DENY_ATTACH**_”

## Zrzuty core

Zrzuty core są tworzone, gdy:

- sysctl `kern.coredump` jest ustawiony na 1 (domyślnie)
- Proces nie był suid/sgid lub `kern.sugid_coredump` ma wartość 1 (domyślnie jest to 0)
- Limit `AS_CORE` zezwala na wykonanie operacji. Można wyłączyć tworzenie zrzutów core za pomocą `ulimit -c 0` i ponownie je włączyć za pomocą `ulimit -c unlimited`.

W takich przypadkach zrzut core jest generowany zgodnie z sysctl `kern.corefile` i zwykle przechowywany w `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizuje procesy, które uległy awarii, i zapisuje raport o awarii na dysku**. Raport o awarii zawiera informacje, które mogą **pomóc developerowi zdiagnozować** przyczynę awarii.\
W przypadku aplikacji i innych procesów **działających w kontekście per-user launchd**, ReportCrash działa jako LaunchAgent i zapisuje raporty o awariach w katalogu użytkownika `~/Library/Logs/DiagnosticReports/`\
W przypadku daemonów, innych procesów **działających w kontekście systemowego launchd** oraz innych uprzywilejowanych procesów ReportCrash działa jako LaunchDaemon i zapisuje raporty o awariach w systemowym katalogu `/Library/Logs/DiagnosticReports`

Jeśli obawiasz się, że raporty o awariach **są wysyłane do Apple**, możesz je wyłączyć. W przeciwnym razie raporty o awariach mogą być przydatne do **ustalenia, dlaczego serwer uległ awarii**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Uśpienie

Podczas fuzzingu na MacOS ważne jest, aby nie pozwolić Macowi przejść w tryb uśpienia:

- systemsetup -setsleep Never
- pmset, Preferencje systemowe
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Rozłączenie SSH

Jeśli wykonujesz fuzzing za pośrednictwem połączenia SSH, ważne jest, aby upewnić się, że sesja nie zostanie rozłączona. Zmień więc plik sshd_config, używając:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Wewnętrzne Handlery

**Sprawdź poniższą stronę**, aby dowiedzieć się, jak znaleźć aplikację odpowiedzialną za **obsługę określonego schematu lub protokołu:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerowanie procesów sieciowych

Jest to przydatne do znalezienia procesów zarządzających danymi sieciowymi:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Lub użyj `netstat` albo `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Działa z narzędziami CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

**Po prostu działa** z narzędziami GUI macOS. Należy zauważyć, że niektóre aplikacje macOS mają określone wymagania, takie jak unikalne nazwy plików, właściwe rozszerzenie czy konieczność odczytywania plików z sandboxa (`~/Library/Containers/com.apple.Safari/Data`)...

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

## Odnośniki

- [1] [Reagowanie na incydenty w systemie OS X: skrypty i analiza](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Sztuka malware na Macu, tom I: analiza](https://taomm.org/vol1/analysis.html)
- [4] [Sztuka malware na Macu: przewodnik po analizie złośliwego oprogramowania](https://taomm.org/)
- [5] [knight.sc - informacje przechowywane w tej sekcji tego wpisu na blogu](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - debugowanie binariów Apple wykorzystujących Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - omijanie technik Anti-Debug: warianty ptrace w macOS](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)

{{#include ../../../banners/hacktricks-training.md}}
