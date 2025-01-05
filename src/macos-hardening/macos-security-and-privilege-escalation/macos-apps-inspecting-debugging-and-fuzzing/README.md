# macOS Apps - Inspekcja, debugowanie i Fuzzing

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
### jtool2 & Disarm

Możesz [**pobrać disarm stąd**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
Możesz [**pobrać jtool2 tutaj**](http://www.newosxbook.com/tools/jtool.html) lub zainstalować go za pomocą `brew`.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
> [!CAUTION] > **jtool jest przestarzały na rzecz disarm**

### Codesign / ldid

> [!TIP] > **`Codesign`** można znaleźć w **macOS**, podczas gdy **`ldid`** można znaleźć w **iOS**
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) to narzędzie przydatne do inspekcji plików **.pkg** (instalatorów) i sprawdzenia, co się w nich znajduje przed ich zainstalowaniem.\
Te instalatory mają skrypty bash `preinstall` i `postinstall`, które autorzy złośliwego oprogramowania zazwyczaj nadużywają, aby **utrzymać** **złośliwe** **oprogramowanie**.

### hdiutil

To narzędzie pozwala na **zamontowanie** obrazów dysków Apple (**.dmg**) w celu ich inspekcji przed uruchomieniem czegokolwiek:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Będzie zamontowane w `/Volumes`

### Spakowane binaria

- Sprawdź wysoką entropię
- Sprawdź ciągi (jeśli prawie nie ma zrozumiałego ciągu, spakowane)
- Packer UPX dla MacOS generuje sekcję o nazwie "\_\_XHDR"

## Statyczna analiza Objective-C

### Metadane

> [!CAUTION]
> Zauważ, że programy napisane w Objective-C **zachowują** swoje deklaracje klas **gdy** **są kompilowane** do [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Takie deklaracje klas **zawierają** nazwę i typ:

- Zdefiniowanych interfejsów
- Metod interfejsu
- Zmiennych instancji interfejsu
- Zdefiniowanych protokołów

Zauważ, że te nazwy mogą być zafałszowane, aby utrudnić odwracanie binariów.

### Wywoływanie funkcji

Gdy funkcja jest wywoływana w binarium, które używa Objective-C, skompilowany kod zamiast wywoływać tę funkcję, wywoła **`objc_msgSend`**. Które wywoła finalną funkcję:

![](<../../../images/image (305).png>)

Parametry, których ta funkcja oczekuje, to:

- Pierwszy parametr (**self**) to "wskaźnik, który wskazuje na **instancję klasy, która ma otrzymać wiadomość**". Mówiąc prościej, jest to obiekt, na którym wywoływana jest metoda. Jeśli metoda jest metodą klasy, będzie to instancja obiektu klasy (jako całość), natomiast dla metody instancji, self będzie wskazywać na zainicjowaną instancję klasy jako obiekt.
- Drugi parametr (**op**) to "selekcja metody, która obsługuje wiadomość". Innymi słowy, to po prostu **nazwa metody.**
- Pozostałe parametry to wszelkie **wartości wymagane przez metodę** (op).

Zobacz, jak **łatwo uzyskać te informacje za pomocą `lldb` w ARM64** na tej stronie:

{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Rejestr**                                                    | **(dla) objc_msgSend**                                 |
| ----------------- | ------------------------------------------------------------- | ------------------------------------------------------ |
| **1. argument**   | **rdi**                                                       | **self: obiekt, na którym wywoływana jest metoda**    |
| **2. argument**   | **rsi**                                                       | **op: nazwa metody**                                   |
| **3. argument**   | **rdx**                                                       | **1. argument do metody**                              |
| **4. argument**   | **rcx**                                                       | **2. argument do metody**                              |
| **5. argument**   | **r8**                                                        | **3. argument do metody**                              |
| **6. argument**   | **r9**                                                        | **4. argument do metody**                              |
| **7. i więcej**   | <p><strong>rsp+</strong><br><strong>(na stosie)</strong></p> | **5. i więcej argumentów do metody**                  |

### Zrzut metadanych ObjectiveC

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) to narzędzie do zrzutu klas binariów Objective-C. Github określa dyliby, ale działa to również z plikami wykonywalnymi.
```bash
./dynadump dump /path/to/bin
```
W momencie pisania, to jest **aktualnie to, co działa najlepiej**.

#### Regularne narzędzia
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) to oryginalne narzędzie do generowania deklaracji dla klas, kategorii i protokołów w kodzie sformatowanym w ObjectiveC.

Jest stare i nieutrzymywane, więc prawdopodobnie nie będzie działać poprawnie.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) to nowoczesny i wieloplatformowy zrzut klas Objective-C. W porównaniu do istniejących narzędzi, iCDump może działać niezależnie od ekosystemu Apple i udostępnia powiązania Pythona.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Statyczna analiza Swift

Z binariów Swift, ponieważ istnieje kompatybilność z Objective-C, czasami można wyodrębnić deklaracje za pomocą [class-dump](https://github.com/nygard/class-dump/), ale nie zawsze.

Za pomocą poleceń **`jtool -l`** lub **`otool -l`** można znaleźć kilka sekcji, które zaczynają się od prefiksu **`__swift5`**:
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
Możesz znaleźć więcej informacji na temat [**informacji przechowywanych w tej sekcji w tym poście na blogu**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Ponadto, **binarne pliki Swift mogą mieć symbole** (na przykład biblioteki muszą przechowywać symbole, aby ich funkcje mogły być wywoływane). **Symbole zazwyczaj zawierają informacje o nazwie funkcji** i atrybutach w nieczytelny sposób, więc są bardzo przydatne, a istnieją "**demanglery**", które mogą uzyskać oryginalną nazwę:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Dynamic Analysis

> [!WARNING]
> Zauważ, że aby debugować binaria, **SIP musi być wyłączony** (`csrutil disable` lub `csrutil enable --without debug`) lub skopiować binaria do tymczasowego folderu i **usunąć podpis** za pomocą `codesign --remove-signature <binary-path>` lub zezwolić na debugowanie binariów (możesz użyć [tego skryptu](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Zauważ, że aby **instrumentować binaria systemowe**, (takie jak `cloudconfigurationd`) na macOS, **SIP musi być wyłączony** (same usunięcie podpisu nie zadziała).

### APIs

macOS udostępnia kilka interesujących API, które dostarczają informacji o procesach:

- `proc_info`: To główne API, które dostarcza wiele informacji o każdym procesie. Musisz być rootem, aby uzyskać informacje o innych procesach, ale nie potrzebujesz specjalnych uprawnień ani portów mach.
- `libsysmon.dylib`: Umożliwia uzyskanie informacji o procesach za pomocą funkcji XPC, jednak potrzebne jest posiadanie uprawnienia `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** to technika używana do uchwycenia stanu procesów, w tym stosów wywołań wszystkich działających wątków. Jest to szczególnie przydatne do debugowania, analizy wydajności i zrozumienia zachowania systemu w określonym momencie. Na iOS i macOS stackshotting można przeprowadzić za pomocą kilku narzędzi i metod, takich jak narzędzia **`sample`** i **`spindump`**.

### Sysdiagnose

To narzędzie (`/usr/bini/ysdiagnose`) zasadniczo zbiera wiele informacji z twojego komputera, wykonując dziesiątki różnych poleceń, takich jak `ps`, `zprint`...

Musi być uruchamiane jako **root**, a demon `/usr/libexec/sysdiagnosed` ma bardzo interesujące uprawnienia, takie jak `com.apple.system-task-ports` i `get-task-allow`.

Jego plist znajduje się w `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, który deklaruje 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Usuwa stare archiwa w /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Specjalny port 23 (jądro)
- `com.apple.sysdiagnose.service.xpc`: Interfejs w trybie użytkownika przez klasę Obj-C `Libsysdiagnose`. Można przekazać trzy argumenty w słowniku (`compress`, `display`, `run`)

### Unified Logs

MacOS generuje wiele logów, które mogą być bardzo przydatne podczas uruchamiania aplikacji, próbując zrozumieć **co ona robi**.

Co więcej, są pewne logi, które będą zawierać tag `<private>`, aby **ukryć** niektóre **identyfikowalne** informacje o **użytkowniku** lub **komputerze**. Jednak możliwe jest **zainstalowanie certyfikatu, aby ujawnić te informacje**. Postępuj zgodnie z wyjaśnieniami [**tutaj**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Left panel

W lewym panelu Hopper można zobaczyć symbole (**Labels**) binariów, listę procedur i funkcji (**Proc**) oraz ciągi (**Str**). To nie są wszystkie ciągi, ale te zdefiniowane w różnych częściach pliku Mac-O (takich jak _cstring lub_ `objc_methname`).

#### Middle panel

W środkowym panelu można zobaczyć **zdekompilowany kod**. Można go zobaczyć jako **surowy** dezasembl, jako **graf**, jako **dekompilowany** i jako **binarne** klikając na odpowiednią ikonę:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Klikając prawym przyciskiem myszy na obiekt kodu, można zobaczyć **odniesienia do/od tego obiektu** lub nawet zmienić jego nazwę (to nie działa w zdekompilowanym pseudokodzie):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Co więcej, w **dolnej części środkowego panelu można pisać polecenia Pythona**.

#### Right panel

W prawym panelu można zobaczyć interesujące informacje, takie jak **historia nawigacji** (aby wiedzieć, jak dotarłeś do obecnej sytuacji), **graf wywołań**, w którym można zobaczyć wszystkie **funkcje, które wywołują tę funkcję** oraz wszystkie funkcje, które **ta funkcja wywołuje**, oraz informacje o **zmiennych lokalnych**.

### dtrace

Umożliwia użytkownikom dostęp do aplikacji na niezwykle **niskim poziomie** i zapewnia sposób dla użytkowników na **śledzenie** **programów** i nawet zmianę ich przepływu wykonania. Dtrace używa **probes**, które są **umieszczane w całym jądrze** i znajdują się w miejscach takich jak początek i koniec wywołań systemowych.

DTrace używa funkcji **`dtrace_probe_create`**, aby utworzyć sondę dla każdego wywołania systemowego. Te sondy mogą być uruchamiane w **punkcie wejścia i wyjścia każdego wywołania systemowego**. Interakcja z DTrace odbywa się przez /dev/dtrace, które jest dostępne tylko dla użytkownika root.

> [!TIP]
> Aby włączyć Dtrace bez całkowitego wyłączania ochrony SIP, możesz wykonać w trybie odzyskiwania: `csrutil enable --without dtrace`
>
> Możesz również **`dtrace`** lub **`dtruss`** binaria, które **sam skompilowałeś**.

Dostępne sondy dtrace można uzyskać za pomocą:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Nazwa sondy składa się z czterech części: dostawcy, modułu, funkcji i nazwy (`fbt:mach_kernel:ptrace:entry`). Jeśli nie określisz jakiejś części nazwy, Dtrace zastosuje tę część jako symbol wieloznaczny.

Aby skonfigurować DTrace do aktywacji sond i określenia, jakie działania wykonać, gdy zostaną uruchomione, będziemy musieli użyć języka D.

Bardziej szczegółowe wyjaśnienie i więcej przykładów można znaleźć w [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

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

To jest narzędzie do śledzenia jądra. Udokumentowane kody można znaleźć w **`/usr/share/misc/trace.codes`**.

Narzędzia takie jak `latency`, `sc_usage`, `fs_usage` i `trace` używają go wewnętrznie.

Aby interfejsować z `kdebug`, używa się `sysctl` w przestrzeni nazw `kern.kdebug`, a MIB-y do użycia można znaleźć w `sys/sysctl.h`, mając funkcje zaimplementowane w `bsd/kern/kdebug.c`.

Aby interagować z kdebug za pomocą niestandardowego klienta, zazwyczaj wykonuje się następujące kroki:

- Usuń istniejące ustawienia za pomocą KERN_KDSETREMOVE
- Ustaw śledzenie za pomocą KERN_KDSETBUF i KERN_KDSETUP
- Użyj KERN_KDGETBUF, aby uzyskać liczbę wpisów w buforze
- Wyciągnij własnego klienta z śledzenia za pomocą KERN_KDPINDEX
- Włącz śledzenie za pomocą KERN_KDENABLE
- Odczytaj bufor, wywołując KERN_KDREADTR
- Aby dopasować każdy wątek do jego procesu, wywołaj KERN_KDTHRMAP.

Aby uzyskać te informacje, można użyć narzędzia Apple **`trace`** lub niestandardowego narzędzia [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Uwaga: Kdebug jest dostępny tylko dla 1 klienta na raz.** Więc tylko jedno narzędzie zasilane k-debug może być uruchomione w tym samym czasie.

### ktrace

API `ktrace_*` pochodzi z `libktrace.dylib`, które opakowuje te z `Kdebug`. Następnie klient może po prostu wywołać `ktrace_session_create` i `ktrace_events_[single/class]`, aby ustawić wywołania zwrotne dla konkretnych kodów, a następnie rozpocząć je za pomocą `ktrace_start`.

Możesz używać tego nawet z **aktywnym SIP**

Możesz używać jako klientów narzędzia `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Or `tailspin`.

### kperf

Jest używany do profilowania na poziomie jądra i jest zbudowany przy użyciu wywołań `Kdebug`.

W zasadzie, globalna zmienna `kernel_debug_active` jest sprawdzana, a jeśli jest ustawiona, wywołuje `kperf_kdebug_handler` z kodem `Kdebug` i adresem ramki jądra, która wywołuje. Jeśli kod `Kdebug` pasuje do jednego z wybranych, uzyskuje "akcje" skonfigurowane jako bitmapa (sprawdź `osfmk/kperf/action.h` dla opcji).

Kperf ma również tabelę MIB sysctl: (jako root) `sysctl kperf`. Te kody można znaleźć w `osfmk/kperf/kperfbsd.c`.

Ponadto, podzbiór funkcjonalności Kperf znajduje się w `kpc`, który dostarcza informacji o licznikach wydajności maszyny.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) to bardzo przydatne narzędzie do sprawdzania działań związanych z procesami, które wykonuje dany proces (na przykład, monitorowanie, które nowe procesy tworzy dany proces).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) to narzędzie do drukowania relacji między procesami.\
Musisz monitorować swój Mac za pomocą polecenia **`sudo eslogger fork exec rename create > cap.json`** (terminal uruchamiający to wymaga FDA). Następnie możesz załadować json w tym narzędziu, aby zobaczyć wszystkie relacje:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) pozwala monitorować zdarzenia plików (takie jak tworzenie, modyfikacje i usunięcia), dostarczając szczegółowych informacji o takich zdarzeniach.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) to narzędzie GUI, które wygląda i działa jak znane użytkownikom Windows narzędzie Microsoft Sysinternal’s _Procmon_. To narzędzie pozwala na rozpoczęcie i zatrzymanie nagrywania różnych typów zdarzeń, umożliwia filtrowanie tych zdarzeń według kategorii, takich jak plik, proces, sieć itp., oraz zapewnia funkcjonalność zapisywania nagranych zdarzeń w formacie json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) są częścią narzędzi deweloperskich Xcode – używane do monitorowania wydajności aplikacji, identyfikowania wycieków pamięci i śledzenia aktywności systemu plików.

![](<../../../images/image (1138).png>)

### fs_usage

Pozwala śledzić działania wykonywane przez procesy:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) jest przydatny do przeglądania **bibliotek** używanych przez binarny plik, **plików**, które wykorzystuje oraz **połączeń** sieciowych.\
Sprawdza również procesy binarne w stosunku do **virustotal** i pokazuje informacje o binarnym pliku.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

W [**tym wpisie na blogu**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) znajdziesz przykład, jak **debugować działający demon**, który używał **`PT_DENY_ATTACH`** do zapobiegania debugowaniu, nawet jeśli SIP był wyłączony.

### lldb

**lldb** jest de **facto narzędziem** do **debugowania** binarnych plików **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Możesz ustawić smak intel podczas używania lldb, tworząc plik o nazwie **`.lldbinit`** w swoim katalogu domowym z następującą linią:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Wewnątrz lldb, zrzutuj proces za pomocą `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Komenda</strong></td><td><strong>Opis</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Rozpoczęcie wykonania, które będzie kontynuowane bez przerwy, aż do osiągnięcia punktu przerwania lub zakończenia procesu.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Rozpocznij wykonanie zatrzymując się w punkcie wejścia</td></tr><tr><td><strong>continue (c)</strong></td><td>Kontynuuj wykonanie debugowanego procesu.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Wykonaj następną instrukcję. Ta komenda pominie wywołania funkcji.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Wykonaj następną instrukcję. W przeciwieństwie do komendy nexti, ta komenda wejdzie w wywołania funkcji.</td></tr><tr><td><strong>finish (f)</strong></td><td>Wykonaj pozostałe instrukcje w bieżącej funkcji (“ramce”), zwróć i zatrzymaj.</td></tr><tr><td><strong>control + c</strong></td><td>Wstrzymaj wykonanie. Jeśli proces był uruchomiony (r) lub kontynuowany (c), spowoduje to zatrzymanie procesu ...gdziekolwiek aktualnie się wykonuje.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Każda funkcja o nazwie main</p><p><code>b <binname>`main</code> #Funkcja main bin</p><p><code>b set -n main --shlib <lib_name></code> #Funkcja main wskazanej bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Każda metoda NSFileManager</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Zatrzymaj w wszystkich funkcjach tej biblioteki</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Lista punktów przerwania</p><p><code>br e/dis <num></code> #Włącz/wyłącz punkt przerwania</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Uzyskaj pomoc dla komendy breakpoint</p><p>help memory write #Uzyskaj pomoc w zapisywaniu do pamięci</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/adres pamięci></strong></td><td>Wyświetl pamięć jako łańcuch zakończony zerem.</td></tr><tr><td><strong>x/i <reg/adres pamięci></strong></td><td>Wyświetl pamięć jako instrukcję asemblera.</td></tr><tr><td><strong>x/b <reg/adres pamięci></strong></td><td>Wyświetl pamięć jako bajt.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>To wydrukuje obiekt wskazywany przez parametr</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Uwaga, że większość API lub metod Objective-C firmy Apple zwraca obiekty, a zatem powinny być wyświetlane za pomocą komendy “print object” (po). Jeśli po nie produkuje sensownego wyniku, użyj <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Zapisz AAAA w tym adresie<br>memory write -f s $rip+0x11f+7 "AAAA" #Zapisz AAAA w adresie</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas bieżącą funkcję</p><p>dis -n <funcname> #Disas funkcję</p><p>dis -n <funcname> -b <basename> #Disas funkcję<br>dis -c 6 #Disas 6 linii<br>dis -c 0x100003764 -e 0x100003768 # Od jednego adresu do drugiego<br>dis -p -c 4 # Rozpocznij w bieżącym adresie disasembli</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Sprawdź tablicę 3 komponentów w rejestrze x1</td></tr><tr><td><strong>image dump sections</strong></td><td>Wydrukuj mapę pamięci bieżącego procesu</td></tr><tr><td><strong>image dump symtab <biblioteka></strong></td><td><code>image dump symtab CoreNLP</code> #Uzyskaj adres wszystkich symboli z CoreNLP</td></tr></tbody></table>

> [!NOTE]
> Przy wywoływaniu funkcji **`objc_sendMsg`**, rejestr **rsi** przechowuje **nazwę metody** jako łańcuch zakończony zerem (“C”). Aby wydrukować nazwę za pomocą lldb, zrób:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### Wykrywanie VM

- Komenda **`sysctl hw.model`** zwraca "Mac", gdy **host jest MacOS**, ale coś innego, gdy jest to VM.
- Bawiąc się wartościami **`hw.logicalcpu`** i **`hw.physicalcpu`**, niektóre złośliwe oprogramowanie próbują wykryć, czy to VM.
- Niektóre złośliwe oprogramowanie mogą również **wykrywać**, czy maszyna jest **oparta na VMware** na podstawie adresu MAC (00:50:56).
- Możliwe jest również sprawdzenie **czy proces jest debugowany** za pomocą prostego kodu, takiego jak:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //proces jest debugowany }`
- Może również wywołać wywołanie systemowe **`ptrace`** z flagą **`PT_DENY_ATTACH`**. To **zapobiega** dołączeniu i śledzeniu przez debuger.
- Możesz sprawdzić, czy funkcja **`sysctl`** lub **`ptrace`** jest **importowana** (ale złośliwe oprogramowanie mogłoby zaimportować ją dynamicznie)
- Jak zauważono w tym opisie, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Wiadomość Process # exited with **status = 45 (0x0000002d)** jest zazwyczaj wyraźnym znakiem, że cel debugowania używa **PT_DENY_ATTACH**_”

## Zrzuty rdzenia

Zrzuty rdzenia są tworzone, jeśli:

- `kern.coredump` sysctl jest ustawiony na 1 (domyślnie)
- Jeśli proces nie był suid/sgid lub `kern.sugid_coredump` jest 1 (domyślnie 0)
- Limit `AS_CORE` pozwala na operację. Możliwe jest stłumienie tworzenia zrzutów rdzenia, wywołując `ulimit -c 0` i ponowne włączenie ich za pomocą `ulimit -c unlimited`.

W tych przypadkach zrzut rdzenia jest generowany zgodnie z `kern.corefile` sysctl i zazwyczaj przechowywany w `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizuje procesy, które uległy awarii i zapisuje raport o awarii na dysku**. Raport o awarii zawiera informacje, które mogą **pomóc programiście zdiagnozować** przyczynę awarii.\
Dla aplikacji i innych procesów **uruchamianych w kontekście launchd dla użytkownika**, ReportCrash działa jako LaunchAgent i zapisuje raporty o awariach w `~/Library/Logs/DiagnosticReports/` użytkownika.\
Dla demonów, innych procesów **uruchamianych w kontekście launchd systemu** i innych procesów z uprawnieniami, ReportCrash działa jako LaunchDaemon i zapisuje raporty o awariach w `/Library/Logs/DiagnosticReports` systemu.

Jeśli obawiasz się, że raporty o awariach **są wysyłane do Apple**, możesz je wyłączyć. Jeśli nie, raporty o awariach mogą być przydatne do **ustalenia, jak serwer uległ awarii**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sen

Podczas fuzzingu w MacOS ważne jest, aby nie pozwolić Macowi na uśpienie:

- systemsetup -setsleep Never
- pmset, Preferencje systemowe
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Rozłączenie SSH

Jeśli fuzzujesz przez połączenie SSH, ważne jest, aby upewnić się, że sesja nie wygasnie. Zmień plik sshd_config na:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Internal Handlers

**Sprawdź następującą stronę**, aby dowiedzieć się, jak znaleźć, która aplikacja jest odpowiedzialna za **obsługę określonego schematu lub protokołu:**

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerating Network Processes

To interesujące, aby znaleźć procesy, które zarządzają danymi sieciowymi:
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

To "**po prostu działa"** z narzędziami GUI macOS. Należy zauważyć, że niektóre aplikacje macOS mają specyficzne wymagania, takie jak unikalne nazwy plików, odpowiednie rozszerzenie, konieczność odczytu plików z piaskownicy (`~/Library/Containers/com.apple.Safari/Data`)...

Kilka przykładów:
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
### Więcej informacji o fuzzingu MacOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Odniesienia

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
