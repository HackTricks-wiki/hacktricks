# Zrzuty pamięci macOS

{{#include ../../../banners/hacktricks-training.md}}

## Artefakty pamięci

### Pliki swap

Pliki swap, takie jak `/private/var/vm/swapfile0`, służą jako **cache, gdy pamięć fizyczna jest pełna**. Gdy w pamięci fizycznej nie ma już miejsca, jej dane są przenoszone do pliku swap, a następnie w razie potrzeby przywracane do pamięci fizycznej. Może być obecnych wiele plików swap o nazwach takich jak swapfile0, swapfile1 itd.

### Obraz hibernacji

Plik znajdujący się w `/private/var/vm/sleepimage` ma kluczowe znaczenie podczas **trybu hibernacji**. **Dane z pamięci są przechowywane w tym pliku, gdy OS X przechodzi w stan hibernacji**. Po wybudzeniu komputera system pobiera dane pamięci z tego pliku, umożliwiając użytkownikowi kontynuowanie pracy od miejsca, w którym ją przerwał.

Warto zauważyć, że we współczesnych systemach MacOS plik ten jest zazwyczaj szyfrowany ze względów bezpieczeństwa, co utrudnia jego odzyskanie.

- Aby sprawdzić, czy szyfrowanie jest włączone dla sleepimage, można uruchomić polecenie `sysctl vm.swapusage`. Wyświetli ono informację, czy plik jest zaszyfrowany.

### Logi presji pamięci

Kolejnym ważnym plikiem związanym z pamięcią w systemach MacOS jest **log presji pamięci**. Logi te znajdują się w `/var/log` i zawierają szczegółowe informacje o wykorzystaniu pamięci systemu oraz zdarzeniach związanych z presją pamięci. Mogą być szczególnie przydatne podczas diagnozowania problemów związanych z pamięcią lub analizowania sposobu zarządzania pamięcią przez system w czasie.

## Dumping pamięci za pomocą osxpmem

Aby wykonać dumping pamięci na komputerze MacOS, można użyć [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Uwaga**: Jest to obecnie głównie **legacy workflow**. `osxpmem` wymaga załadowania rozszerzenia jądra, projekt [Rekall](https://github.com/google/rekall) jest zarchiwizowany, jego najnowsze wydanie pochodzi z **2017 roku**, a opublikowany plik binarny jest przeznaczony dla komputerów Mac z procesorami **Intel**. W aktualnych wydaniach macOS, szczególnie na urządzeniach z **Apple Silicon**, pozyskiwanie pełnej pamięci RAM oparte na kext jest zazwyczaj blokowane przez nowoczesne ograniczenia dotyczące rozszerzeń jądra, SIP oraz wymagania związane z podpisywaniem platformy. W praktyce na współczesnych systemach częściej będzie można wykonać **process-scoped dump** zamiast obrazu całej pamięci RAM.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Jeśli napotkasz ten błąd: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)`, możesz go naprawić, wykonując:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Inne błędy** mogą zostać naprawione poprzez **zezwolenie na załadowanie kext** w "Security & Privacy --> General" — po prostu **zezwól**.

Możesz również użyć tego **oneliner**, aby pobrać aplikację, załadować kext i zrzucić pamięć:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Zrzucanie pamięci działającego procesu za pomocą LLDB

W przypadku **nowszych wersji macOS** najbardziej praktycznym podejściem jest zwykle zrzucenie pamięci **konkretnego procesu**, zamiast próby utworzenia obrazu całej pamięci fizycznej.

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
Przydatne polecenia uzupełniające przed zrzutem pamięci:
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
- Tokenów, cookies lub credentials znajdujących się w pamięci
- Sekretów w plaintext, które są chronione wyłącznie w spoczynku
- Odszyfrowanych stron Mach-O po unpackingu / JIT / runtime patchingu

Jeśli target jest chroniony przez **hardened runtime** lub `taskgated` odrzuca attach, zazwyczaj potrzebny jest jeden z poniższych warunków:

- Target posiada **`get-task-allow`**
- Twój debugger jest podpisany za pomocą właściwego **debugger entitlement**
- Jesteś **rootem**, a target jest procesem firm trzecich bez hardened runtime

Więcej informacji o uzyskiwaniu task portu i możliwościach jego wykorzystania:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Szybkie kontrole przed attach

Zanim poświęcisz czas na LLDB/Frida, szybko sprawdź, czy target jest realistycznie **dumpowalny**:
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

- Aplikacja third-party dostarczona z **`get-task-allow`** często może być bezpośrednio zrzucana za pomocą LLDB, a uzyskany dump może ujawnić dane chronione przez TCC, do których aplikacja miała już dostęp.<sup>[[1]](#references)</sup>
- **Hardened** target bez `get-task-allow` zazwyczaj odrzuci próby attach, nawet gdy działasz jako `root`, chyba że kontrolujesz odpowiednie entitlements debuggera / ścieżkę policy.
- Niezabezpieczone procesy third-party nadal są najłatwiejszym miejscem do użycia `lldb`, `vmmap`, Frida lub własnych readerów `task_for_pid`/`vm_read`.

### Hunt dumpable nested helpers

Najnowsze badania dotyczące notaryzowanych aplikacji macOS wciąż wykrywają **`get-task-allow` w nested helpers**, zamiast w głównym pliku binarnym GUI. Gdy aplikacja najwyższego poziomu wygląda na hardened, przed rezygnacją wylicz jej **usługi XPC**, **login items**, **helper tools** oraz dołączone CLI:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Zagnieżdżony plik wykonywalny z `get-task-allow` jest często najłatwiejszym miejscem do podłączenia się za pomocą `lldb`, zrzucenia core lub pobrania pamięci przy użyciu niestandardowego klienta `task_for_pid`, nawet gdy główna aplikacja jest lepiej zabezpieczona.

## Selektywne zrzuty za pomocą Frida lub czytników userland

Gdy pełny core zawiera zbyt dużo nieistotnych danych, zrzucenie tylko **interesujących, odczytywalnych zakresów** jest często szybsze. Frida jest szczególnie przydatna, ponieważ dobrze sprawdza się przy **targeted extraction**, gdy można już podłączyć się do procesu.

Przykładowe podejście:

1. Wylicz odczytywalne/zapisywalne zakresy
2. Odfiltruj je według modułu, sterty, stosu lub pamięci anonimowej
3. Zrzuć tylko regiony zawierające potencjalne stringi, klucze, protobufy, obiekty plist/XML lub odszyfrowany kod/dane

Minimalny przykład Frida do zrzucenia wszystkich odczytywalnych anonimowych zakresów:
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

- fragmenty heap aplikacji zawierające sekrety
- anonimowe regiony utworzone przez custom packers lub loaders
- strony kodu JIT / unpacked po zmianie uprawnień

Gdy target nadal **alokuje / zwalnia** pamięć podczas wykonywania dumpu, w przypadku niestabilnych zakresów używaj prymitywu **`readVolatile()`** z Frida zamiast **`readByteArray()`**. Jest wolniejszy, ale zapobiega zakończeniu targetu, jeśli strona stanie się nieczytelna w trakcie odczytu. W przypadku większych akwizycji czystsze może być również przesyłanie fragmentów za pomocą `send(..., data)` i kompresowanie ich po stronie kontrolera, zamiast tworzenia tysięcy małych plików wewnątrz targetu.

Istnieją również starsze narzędzia userland, takie jak [`readmem`](https://github.com/gdbinit/readmem), ale są one przydatne głównie jako **odniesienia do kodu źródłowego** dla dumpowania w stylu `task_for_pid`/`vm_read` i nie są dobrze utrzymywane pod kątem współczesnych workflow z Apple Silicon.

## Snapshoty heap / VM z `.memgraph`

Jeśli interesują Cię głównie **obiekty heap**, **pochodzenie alokacji** lub snapshot, który można przenieść na inną maszynę, plik `.memgraph` jest często praktyczniejszy niż ogromny core Mach-O. Narzędzia `leaks` mogą wygenerować go z działającego procesu:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Następnie przeprowadź jego triage offline przy użyciu standardowych narzędzi Apple:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` to główny powód, aby zachować przechwycenie `-fullContent`, ponieważ etykiety opisujące zawartość pamięci są pomijane w minimalnym pliku `.memgraph`.

Jest to szczególnie przydatne, gdy:

- Chcesz uzyskać **mniejszy, łatwy do udostępnienia snapshot** zamiast pełnego core
- Włączono `MallocStackLogging` i chcesz uzyskać **allocation backtraces**
- Znasz już **interesujący adres heap** i chcesz przejść dalej za pomocą `malloc_history`
- Potrzebujesz szybkiego **podziału VM/heap** przed podjęciem decyzji, czy pełny dump jest wart dodatkowego szumu

### Triage różnicowy memgraph

Jeśli kontrolujesz sposób uruchamiania targetu, włącz **historical allocation logging** przed uruchomieniem, aby późniejsze snapshoty zachowały przydatne backtraces alokacji:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Następnie przechwyć migawki przed interesującą operacją i po niej, a różnice porównaj offline:
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
Jest to praktyczny sposób na wyizolowanie **obiektów post-authentication**, **dużych buforów `CFData`** lub **anonimowych regionów VM**, które pojawiają się dopiero po etapie deszyfrowania, unpacking lub pobrania sekretu.

## Cele oparte w dużej mierze na Swift: `swift-inspect`

W przypadku aplikacji, które przechowują dane o wysokiej wartości w **obiektach runtime Swift**, `swift-inspect` może być dobrym uzupełnieniem LLDB lub Frida. Zamiast najpierw zrzucać wszystko, możesz odpytywać konkretne struktury runtime Swift z poziomu działającego procesu:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Jest to przydatne do identyfikowania:

- Dużych tablic Swift buforujących interesujące dane
- Alokacji metadanych ujawniających typy ładowane w runtime
- Stanu Swift concurrency (`Task`, actor, relacji między wątkami) przed wykonaniem bardziej ukierunkowanego dumpu

Aby przeprowadzić dokładniejszy runtime triage na poziomie obiektów, gdy można już inspektować proces, sprawdź [dedykowaną stronę dotyczącą obiektów w pamięci](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Szybkie uwagi dotyczące triage

- `sysctl vm.swapusage` nadal jest szybkim sposobem sprawdzenia **użycia swapu** oraz tego, czy swap jest **zaszyfrowany**.
- `sleepimage` pozostaje istotny głównie w scenariuszach **hibernacji/safe sleep**, jednak współczesne systemy często go chronią, dlatego należy traktować go jako **źródło artefaktów do sprawdzenia**, a nie jako niezawodną ścieżkę pozyskiwania danych.
- W nowszych wersjach macOS **zrzucanie danych na poziomie procesu** jest zazwyczaj bardziej realistyczne niż **tworzenie pełnego obrazu pamięci fizycznej**, chyba że masz kontrolę nad polityką rozruchu, stanem SIP i ładowaniem kextów.

## References

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
