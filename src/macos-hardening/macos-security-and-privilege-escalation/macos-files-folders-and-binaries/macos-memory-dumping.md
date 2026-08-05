# Zrzut pamięci macOS

{{#include ../../../banners/hacktricks-training.md}}

## Artefakty pamięci

### Pliki swap

Pliki swap, takie jak `/private/var/vm/swapfile0`, służą jako **pamięć podręczna, gdy pamięć fizyczna jest pełna**. Gdy w pamięci fizycznej nie ma już miejsca, dane są przenoszone do pliku swap, a następnie w razie potrzeby przywracane do pamięci fizycznej. Może istnieć wiele plików swap o nazwach takich jak swapfile0, swapfile1 itd.

### Obraz hibernacji

Plik znajdujący się w `/private/var/vm/sleepimage` ma kluczowe znaczenie podczas **trybu hibernacji**. **Dane z pamięci są przechowywane w tym pliku, gdy OS X przechodzi w stan hibernacji**. Po wybudzeniu komputera system pobiera dane pamięci z tego pliku, umożliwiając użytkownikowi kontynuowanie pracy od miejsca, w którym ją przerwał.

Warto zauważyć, że we współczesnych systemach MacOS plik ten jest zazwyczaj szyfrowany ze względów bezpieczeństwa, co utrudnia odzyskanie danych.

- Aby sprawdzić, czy szyfrowanie jest włączone dla pliku sleepimage, można uruchomić polecenie `sysctl vm.swapusage`. Wyświetli ono informację, czy plik jest zaszyfrowany.

### Logi presji pamięci

Kolejnym ważnym plikiem związanym z pamięcią w systemach MacOS jest **log presji pamięci**. Logi te znajdują się w `/var/log` i zawierają szczegółowe informacje o wykorzystaniu pamięci systemu oraz zdarzeniach związanych z presją pamięci. Mogą być szczególnie przydatne podczas diagnozowania problemów związanych z pamięcią lub analizowania sposobu zarządzania pamięcią przez system w czasie.

## Dumping pamięci za pomocą osxpmem

Aby wykonać dump pamięci na komputerze MacOS, można użyć [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Uwaga**: Obecnie jest to głównie **legacy workflow**. `osxpmem` wymaga załadowania kernel extension, projekt [Rekall](https://github.com/google/rekall) jest zarchiwizowany, najnowsze wydanie pochodzi z **2017 roku**, a opublikowany binary jest przeznaczony dla komputerów Mac z procesorami **Intel**. W obecnych wydaniach macOS, szczególnie na urządzeniach z **Apple Silicon**, pozyskiwanie pełnej pamięci RAM za pomocą kext jest zazwyczaj blokowane przez współczesne ograniczenia dotyczące kernel extension, SIP oraz wymagania związane z podpisywaniem platformy. W praktyce na nowoczesnych systemach częściej wykonuje się **process-scoped dump** zamiast obrazu całej pamięci RAM.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Jeśli napotkasz ten błąd: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Możesz go naprawić, wykonując:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Inne błędy** można naprawić, **zezwalając na załadowanie kext** w „Security & Privacy --> General” — po prostu kliknij **allow**.

Możesz również użyć tego **onelinera**, aby pobrać aplikację, załadować kext i zrzucić pamięć:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Zrzucanie pamięci działającego procesu za pomocą LLDB

W przypadku **nowszych wersji macOS** najbardziej praktycznym podejściem jest zazwyczaj zrzucenie pamięci **konkretnego procesu**, zamiast próby utworzenia obrazu całej pamięci fizycznej.

LLDB może zapisać plik core Mach-O z działającego celu:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Domyślnie zazwyczaj tworzy to **skinny core**. Aby wymusić uwzględnienie przez LLDB całej zmapowanej pamięci procesu:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Przydatne polecenia uzupełniające przed dumpingiem:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Zwykle wystarcza to, gdy celem jest odzyskanie:

- Odszyfrowanych blobów konfiguracyjnych
- Tokenów, cookies lub poświadczeń znajdujących się w pamięci
- Sekretów w plaintext, które są chronione wyłącznie w stanie spoczynku
- Odszyfrowanych stron Mach-O po unpackingu / JIT / runtime patchingu

Jeśli cel jest chroniony przez **hardened runtime** lub `taskgated` odmawia attachu, zazwyczaj potrzebny jest jeden z poniższych warunków:

- Cel posiada **`get-task-allow`**
- Twój debugger jest podpisany z użyciem odpowiedniego **debugger entitlement**
- Jesteś **rootem**, a cel jest procesem innej firmy bez hardened runtime

Więcej informacji na temat uzyskiwania task portu i tego, co można z nim zrobić:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Szybkie kontrole przed attach

Zanim poświęcisz czas na LLDB/Frida, szybko sprawdź, czy cel jest realistycznie **dumpable**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
W praktyce zwykle oznacza to:

- Aplikacja innej firmy dostarczona z **`get-task-allow`** często umożliwia bezpośrednie wykonanie dumpa za pomocą LLDB, a wynikowy dump może ujawnić dane chronione przez TCC, do których aplikacja już uzyskała dostęp.<sup>[1]</sup>
- **Hardened** target bez `get-task-allow` zazwyczaj odrzuci próby attach, nawet z uprawnieniami `root`, chyba że kontrolujesz odpowiednie debugger entitlements / policy path.
- Niezabezpieczone procesy aplikacji innych firm nadal są najłatwiejszym miejscem do użycia `lldb`, `vmmap`, Frida lub własnych readerów `task_for_pid`/`vm_read`.

### Wyszukiwanie zrzucalnych zagnieżdżonych helperów

Najnowsze badania dotyczące notarowanych aplikacji macOS nadal często wykrywają **`get-task-allow`** w zagnieżdżonych helperach zamiast w głównym pliku binarnym GUI. Gdy aplikacja najwyższego poziomu wygląda na hardened, przed rezygnacją wylicz jej **usługi XPC**, **login items**, **helper tools** oraz dołączone pliki CLI:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Zagnieżdżony executable z `get-task-allow` jest często najłatwiejszym miejscem do podłączenia się za pomocą `lldb`, zrzucenia core dump lub pobrania pamięci przy użyciu własnego klienta `task_for_pid`, nawet gdy główna aplikacja jest lepiej zabezpieczona.

## Selective dumps with Frida or userland readers

Gdy pełny core dump zawiera zbyt dużo zbędnych danych, szybszym rozwiązaniem jest zrzucenie tylko **interesujących, dostępnych do odczytu zakresów pamięci**. Frida jest szczególnie przydatna, ponieważ dobrze sprawdza się przy **targeted extraction**, gdy można już podłączyć się do procesu.

Przykładowe podejście:

1. Wylicz zakresy pamięci dostępne do odczytu i zapisu
2. Odfiltruj je według modułu, heap, stack lub anonymous memory
3. Zrzuć tylko regiony zawierające potencjalne stringi, klucze, protobufy, bloby plist/XML lub odszyfrowany kod/dane

Minimalny przykład Frida do zrzucenia wszystkich anonimowych zakresów dostępnych do odczytu:
```javascript
Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(function (range) {
try {
if (range.file) return;
var dump = range.base.readByteArray(range.size);
var f = new File('/tmp/' + range.base + '.bin', 'wb');
f.write(dump);
f.close();
} catch (e) {}
});
```
Jest to przydatne, gdy chcesz uniknąć ogromnych plików core i zebrać tylko:

- Fragmenty heap aplikacji zawierające sekrety
- Anonimowe regiony utworzone przez niestandardowe packery lub loadery
- Strony kodu JIT / unpacked po zmianie zabezpieczeń

Gdy target nadal **przydziela / zwalnia** pamięć podczas wykonywania dumpa, w przypadku niestabilnych zakresów preferuj primitive Fridy **`readVolatile()`** zamiast **`readByteArray()`**. Jest wolniejszy, ale zapobiega zakończeniu targetu, jeśli strona stanie się nieczytelna w trakcie odczytu. W przypadku większych akwizycji czystsze może być również przesyłanie fragmentów z powrotem za pomocą `send(..., data)` i kompresowanie ich po stronie kontrolera, zamiast tworzenia tysięcy małych plików wewnątrz targetu.

Istnieją również starsze narzędzia userland, takie jak [`readmem`](https://github.com/gdbinit/readmem), ale są one przydatne głównie jako **referencje źródłowe** dla dumpowania w stylu bezpośredniego `task_for_pid`/`vm_read` i nie są dobrze utrzymywane pod kątem współczesnych workflow na Apple Silicon.

## Migawki Heap / VM z `.memgraph`

Jeśli interesują Cię głównie **obiekty heap**, **proweniencja alokacji** lub migawka, którą można przenieść na inną maszynę, plik `.memgraph` jest często bardziej praktyczny niż ogromny core Mach-O. Narzędzia `leaks` mogą wygenerować go z aktywnego procesu:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Następnie wykonaj triage offline przy użyciu standardowych narzędzi Apple:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` to główny powód, aby zachować przechwycenie `-fullContent`, ponieważ etykiety opisujące zawartość pamięci są pomijane w minimalnym pliku `.memgraph`.

Jest to szczególnie przydatne, gdy:

- Potrzebujesz **mniejszego, możliwego do udostępnienia snapshotu** zamiast pełnego core
- Włączono `MallocStackLogging` i potrzebujesz **allocation backtraces**
- Znasz już **interesujący adres heap** i chcesz przejść dalej za pomocą `malloc_history`
- Potrzebujesz szybkiego **podziału VM/heap** przed podjęciem decyzji, czy pełny dump jest wart dodatkowego szumu

### Triage różnicowy memgraph

Jeśli kontrolujesz sposób uruchamiania targetu, włącz **historical allocation logging** przed uruchomieniem, aby późniejsze snapshoty zachowały użyteczne backtraces alloc/free:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Następnie wykonaj migawki przed interesującą akcją i po niej, a różnice porównaj offline:
```bash
# Baseline before login / decrypt / unpack
leaks <pid> -outputGraph /tmp/pre.memgraph -fullContent -fullStackHistory

# Snapshot after the sensitive action
leaks <pid> -outputGraph /tmp/post.memgraph -fullContent -fullStackHistory

# Show only new leaks introduced after the baseline
leaks /tmp/post.memgraph -diffFrom=/tmp/pre.memgraph

# Walk from roots to one candidate allocation, or filter the whole tree by class / VM type
leaks /tmp/post.memgraph -traceTree 0xADDR
leaks /tmp/post.memgraph -referenceTree='CFData[50k+]'

# Pivot into the preserved stack history at the interesting high-water mark
malloc_history /tmp/post.memgraph -callTree -highWaterMark
```
To praktyczny sposób na wyizolowanie **obiektów post-authentication**, **dużych buforów `CFData`** lub **anonimowych regionów VM**, które pojawiają się dopiero po etapie deszyfrowania, unpackingu albo pobierania sekretów.

## Cele oparte w dużej mierze na Swift: `swift-inspect`

W przypadku aplikacji, które przechowują dane o wysokiej wartości w **obiektach Swift runtime**, `swift-inspect` może być dobrym uzupełnieniem LLDB lub Frida. Zamiast najpierw zrzucać wszystko, możesz odpytywać konkretne struktury Swift runtime z działającego procesu:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Jest to przydatne do identyfikowania:

- Dużych tablic Swift buforujących interesujące dane
- Alokacji metadanych ujawniających typy załadowane w czasie wykonywania
- Stanu Swift concurrency (`Task`, actor, relacje między wątkami) przed wykonaniem bardziej ukierunkowanego dumpu

Aby przeprowadzić dokładniejszy runtime triage na poziomie obiektów, gdy można już inspekcjonować proces, sprawdź [dedykowaną stronę dotyczącą obiektów w pamięci](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Szybkie notatki dotyczące triage

- `sysctl vm.swapusage` nadal jest szybkim sposobem sprawdzenia **użycia swapu** oraz tego, czy swap jest **szyfrowany**.
- `sleepimage` pozostaje istotny głównie w scenariuszach **hibernacji/safe sleep**, ale współczesne systemy często go chronią, dlatego należy traktować go jako **źródło artefaktów do sprawdzenia**, a nie jako niezawodną metodę pozyskiwania danych.
- W nowszych wydaniach macOS **dumpowanie na poziomie procesu** jest zazwyczaj bardziej realistyczne niż **tworzenie pełnego obrazu pamięci fizycznej**, chyba że masz kontrolę nad boot policy, stanem SIP i ładowaniem kextów.

## Referencje

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
