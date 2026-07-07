# Zrzut pamięci macOS

{{#include ../../../banners/hacktricks-training.md}}

## Artefakty pamięci

### Pliki swap

Pliki swap, takie jak `/private/var/vm/swapfile0`, służą jako **bufory, gdy pamięć fizyczna jest pełna**. Gdy w pamięci fizycznej nie ma już miejsca, jej dane są przenoszone do pliku swap, a następnie w razie potrzeby przywracane do pamięci fizycznej. Może istnieć wiele plików swap, o nazwach takich jak swapfile0, swapfile1 i tak dalej.

### Obraz hibernacji

Plik znajdujący się w `/private/var/vm/sleepimage` ma kluczowe znaczenie w trybie **hibernacji**. **Dane z pamięci są zapisywane w tym pliku, gdy OS X przechodzi w stan hibernacji**. Po wybudzeniu komputera system odczytuje dane pamięci z tego pliku, umożliwiając użytkownikowi kontynuowanie pracy od miejsca, w którym przerwał.

Warto zauważyć, że na nowoczesnych systemach MacOS ten plik jest zazwyczaj szyfrowany ze względów bezpieczeństwa, co utrudnia odzyskanie danych.

- Aby sprawdzić, czy szyfrowanie jest włączone dla sleepimage, można uruchomić polecenie `sysctl vm.swapusage`. Pokaże ono, czy plik jest zaszyfrowany.

### Logi presji pamięci

Innym ważnym plikiem związanym z pamięcią w systemach MacOS jest **log presji pamięci**. Te logi znajdują się w `/var/log` i zawierają szczegółowe informacje o użyciu pamięci przez system oraz zdarzeniach presji pamięci. Mogą być szczególnie przydatne do diagnozowania problemów związanych z pamięcią lub zrozumienia, jak system zarządza pamięcią w czasie.

## Zrzut pamięci za pomocą osxpmem

Aby zrzucić pamięć na maszynie MacOS, możesz użyć [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Uwaga**: To obecnie głównie **legacy workflow**. `osxpmem` wymaga załadowania rozszerzenia jądra, projekt [Rekall](https://github.com/google/rekall) jest zarchiwizowany, najnowsze wydanie pochodzi z **2017**, a opublikowany binarny plik docelowy to **Intel Macs**. We współczesnych wersjach macOS, zwłaszcza na **Apple Silicon**, pełne pozyskiwanie RAM oparte na kext jest zwykle blokowane przez nowoczesne ograniczenia dotyczące rozszerzeń jądra, SIP oraz wymagania podpisywania platformy. W praktyce na nowoczesnych systemach częściej kończy się na **process-scoped dump** zamiast obrazu całego RAM.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Jeśli napotkasz ten błąd: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` możesz to naprawić, wykonując:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Inne błędy** mogą zostać naprawione przez **zezwolenie na załadowanie kext** w "Security & Privacy --> General", po prostu **zezwól** na to.

Możesz też użyć tego **onelinera**, aby pobrać aplikację, załadować kext i zrzucić pamięć:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Zrzut pamięci działającego procesu za pomocą LLDB

W przypadku **nowszych wersji macOS**, najbardziej praktycznym podejściem jest zwykle zrzucenie pamięci **konkretnego procesu** zamiast próby wykonania obrazu całej pamięci fizycznej.

LLDB może zapisać plik core Mach-O z działającego celu:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Domyślnie zwykle tworzy to **skinny core**. Aby wymusić, żeby LLDB uwzględniał całą mapowaną pamięć procesu:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Przydatne polecenia do wykonania przed dumpingiem:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Zwykle to wystarcza, gdy celem jest odzyskanie:

- Zdeszyfrowanych blobów konfiguracji
- Tokenów, cookies lub poświadczeń z pamięci
- Sekretów w plaintext, które są chronione tylko at rest
- Zdeszyfrowanych stron Mach-O po unpacking / JIT / runtime patching

Jeśli cel jest chroniony przez **hardened runtime**, albo jeśli `taskgated` odmawia attach, zwykle potrzebujesz jednego z tych warunków:

- Cel ma **`get-task-allow`**
- Twój debugger jest podpisany z odpowiednim **debugger entitlement**
- Jesteś **root** i cel jest procesem firm trzecich bez hardened runtime

Więcej informacji o uzyskiwaniu task port i o tym, co można z nim zrobić:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Szybkie kontrole przed attach

Zanim poświęcisz czas na LLDB/Frida, szybko sprawdź, czy cel jest realnie **dumpable**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Operacyjnie oznacza to zwykle:

- Aplikacja firm trzecich dostarczona z **`get-task-allow`** często daje się bezpośrednio zrzucić przez LLDB, a wynikowy dump może ujawnić dane chronione przez TCC, do których aplikacja już uzyskała dostęp.
- **Hardened** cel bez `get-task-allow` zwykle odrzuci attach, nawet jako `root`, chyba że kontrolujesz odpowiednie entitlements debugera / ścieżkę polityki.
- Niezahardenowane procesy firm trzecich nadal są najłatwiejszym miejscem do użycia `lldb`, `vmmap`, Frida albo własnych czytników `task_for_pid`/`vm_read`.

## Selective dumps with Frida or userland readers

Gdy pełny core jest zbyt zaszumiony, zrzucanie tylko **interesujących czytelnych zakresów** jest często szybsze. Frida jest szczególnie użyteczna, ponieważ dobrze sprawdza się przy **targeted extraction** raz, gdy możesz już attach do procesu.

Przykładowe podejście:

1. Wylicz readable/writable ranges
2. Odfiltruj po module, heap, stack albo anonymous memory
3. Zrzuć tylko te regiony, które zawierają kandydackie stringi, klucze, protobufs, blobs plist/XML albo odszyfrowany kod/dane

Minimalny przykład Frida do zrzucenia wszystkich czytelnych anonymous ranges:
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

- App heap chunks zawierające sekrety
- Anonymous regions utworzone przez niestandardowe packery lub loadery
- JIT / unpacked code pages po zmianie protection

Starsze narzędzia userland, takie jak [`readmem`](https://github.com/gdbinit/readmem), również istnieją, ale są głównie przydatne jako **source references** do bezpośredniego dumpingu w stylu `task_for_pid`/`vm_read` i nie są dobrze utrzymywane pod kątem nowoczesnych workflow na Apple Silicon.

## Heap / VM snapshots z `.memgraph`

Jeśli najbardziej interesują Cię **heap objects**, **allocation provenance** albo snapshot, który można przenieść na inną maszynę, `.memgraph` często jest praktyczniejsze niż ogromny Mach-O core. Narzędzia `leaks` mogą wygenerować taki plik z działającego procesu:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Następnie przeprowadź jego triage offline za pomocą standardowych narzędzi Apple:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` to główny powód, aby zachować `-fullContent` capture, ponieważ etykiety opisujące zawartość pamięci są pomijane w minimalnym `.memgraph`.

Jest to szczególnie przydatne, gdy:

- Chcesz **mniejszy, łatwy do udostępnienia snapshot** zamiast pełnego core
- `MallocStackLogging` było włączone i chcesz **allocation backtraces**
- Znasz już **interesujący heap address** i chcesz przejść dalej za pomocą `malloc_history`
- Potrzebujesz szybkiego **VM/heap breakdown** przed decyzją, czy pełny dump jest wart szumu

## Swift-heavy targets: `swift-inspect`

W aplikacjach, które przechowują dane o dużej wartości wewnątrz **Swift runtime objects**, `swift-inspect` może być dobrym uzupełnieniem LLDB lub Frida. Zamiast najpierw zrzucać wszystko, możesz odpytać konkretne struktury Swift runtime z działającego procesu:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
This is handy to identify:

- Large Swift arrays buffering interesting data
- Metadata allocations that reveal types loaded at runtime
- Swift concurrency state (`Task`, actor, thread relationships) before doing a more targeted dump

For more object-level runtime triage once you can already inspect the process, check [the dedicated page on objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Quick triage notes

- `sysctl vm.swapusage` is still a quick way to check **swap usage** and whether swap is **encrypted**.
- `sleepimage` remains relevant mainly for **hibernate/safe sleep** scenarios, but modern systems commonly protect it, so it should be treated as an **artifact source to check**, not as a reliable acquisition path.
- On recent macOS releases, **process-level dumping** is generally more realistic than **full physical memory imaging** unless you control boot policy, SIP state, and kext loading.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
