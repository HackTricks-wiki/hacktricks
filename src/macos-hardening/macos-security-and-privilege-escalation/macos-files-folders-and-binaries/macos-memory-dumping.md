# Zrzucanie pamięci w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Artefakty pamięci

### Pliki swap

Pliki swap, takie jak `/private/var/vm/swapfile0`, służą jako **cache, gdy pamięć fizyczna jest pełna**. Gdy w pamięci fizycznej nie ma już miejsca, jej dane są przenoszone do pliku swap, a następnie w razie potrzeby przywracane do pamięci fizycznej. Może istnieć wiele plików swap, o nazwach takich jak swapfile0, swapfile1 itd.

### Obraz hibernacji

Plik znajdujący się pod adresem `/private/var/vm/sleepimage` ma kluczowe znaczenie podczas **trybu hibernacji**. **Dane z pamięci są przechowywane w tym pliku, gdy OS X przechodzi w stan hibernacji**. Po wybudzeniu komputera system pobiera dane pamięci z tego pliku, umożliwiając użytkownikowi kontynuowanie pracy od miejsca, w którym ją przerwał.

Warto zauważyć, że na współczesnych systemach MacOS plik ten jest zazwyczaj szyfrowany ze względów bezpieczeństwa, co utrudnia odzyskanie danych.

- Aby sprawdzić, czy szyfrowanie jest włączone dla sleepimage, można uruchomić polecenie `sysctl vm.swapusage`. Wyświetli ono, czy plik jest zaszyfrowany.

### Logi presji pamięci

Kolejnym ważnym plikiem związanym z pamięcią w systemach MacOS jest **log presji pamięci**. Logi te znajdują się w `/var/log` i zawierają szczegółowe informacje o wykorzystaniu pamięci systemu oraz zdarzeniach związanych z presją pamięci. Mogą być szczególnie przydatne podczas diagnozowania problemów związanych z pamięcią lub analizowania sposobu zarządzania pamięcią przez system w czasie.

## Zrzucanie pamięci za pomocą osxpmem

Aby zrzucić pamięć na komputerze MacOS, można użyć narzędzia [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Uwaga**: Obecnie jest to głównie **legacy workflow**. `osxpmem` zależy od załadowania rozszerzenia jądra, projekt [Rekall](https://github.com/google/rekall) został zarchiwizowany, najnowsze wydanie pochodzi z **2017 roku**, a opublikowany binary jest przeznaczony dla komputerów Mac z procesorami **Intel**. W obecnych wydaniach macOS, szczególnie na urządzeniach z **Apple Silicon**, pozyskiwanie pełnej pamięci RAM za pomocą kext jest zazwyczaj blokowane przez współczesne ograniczenia dotyczące rozszerzeń jądra, SIP oraz wymagania dotyczące podpisywania platformy. W praktyce na nowoczesnych systemach częściej wykonuje się **dump ograniczony do procesu** zamiast obrazu całej pamięci RAM.
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
**Inne błędy** można naprawić, **zezwalając na załadowanie kext** w sekcji „Security & Privacy --> General” — po prostu **zezwól**.

Możesz również użyć tego **oneliner**, aby pobrać aplikację, załadować kext i zrzucić pamięć:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Zrzucanie pamięci działającego procesu za pomocą LLDB

W przypadku **nowszych wersji macOS** najbardziej praktycznym podejściem jest zazwyczaj zrzucenie pamięci **konkretnego procesu** zamiast próby utworzenia obrazu całej pamięci fizycznej.

LLDB może zapisać plik core Mach-O z działającego celu:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Domyślnie zazwyczaj tworzy to **skinny core**. Aby wymusić, by LLDB dołączył całą zmapowaną pamięć procesu:
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
- Sekretów w plaintext, które są chronione wyłącznie podczas przechowywania
- Odszyfrowanych stron Mach-O po unpackingu / JIT / patchingu w czasie działania

Jeśli cel jest chroniony przez **hardened runtime** lub `taskgated` odmawia attach, zazwyczaj potrzebny jest jeden z poniższych warunków:

- Cel posiada **`get-task-allow`**
- Twój debugger jest podpisany z właściwym **debugger entitlement**
- Jesteś **root**, a cel jest procesem zewnętrznym, który nie korzysta z hardened runtime

Więcej informacji o uzyskiwaniu task portu i możliwościach jego wykorzystania:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Szybkie kontrole przed attach

Zanim poświęcisz czas na LLDB/Frida, szybko sprawdź, czy cel jest realistycznie **dumpowalny**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
W praktyce oznacza to zwykle:

- Aplikację innej firmy dostarczoną z **`get-task-allow`** można często bezpośrednio dumpować za pomocą LLDB, a wynikowy dump może ujawnić dane chronione przez TCC, do których aplikacja już uzyskała dostęp.
- **Hardened** target bez **`get-task-allow`** zwykle odrzuci próby attachowania, nawet gdy działasz jako `root`, chyba że kontrolujesz odpowiednie entitlements debuggera / ścieżkę policy.
- Niezabezpieczone procesy aplikacji innych firm nadal są najłatwiejszym miejscem do użycia `lldb`, `vmmap`, Frida lub niestandardowych readerów `task_for_pid`/`vm_read`.

### Wyszukuj dumpowalne zagnieżdżone helpery

Nowsze badania dotyczące notaryzowanych aplikacji macOS stale wykrywają **`get-task-allow`** w zagnieżdżonych helperach zamiast w głównym binarium GUI. Gdy aplikacja najwyższego poziomu wygląda na hardened, wylicz jej **usługi XPC**, **login items**, **helper tools** i dołączone CLI, zanim zrezygnujesz:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Zagnieżdżony executable z `get-task-allow` jest często najłatwiejszym miejscem do podłączenia się za pomocą `lldb`, zrzucenia core lub pobrania pamięci przy użyciu niestandardowego klienta `task_for_pid`, nawet gdy główna aplikacja jest lepiej zabezpieczona.

## Selektywne dumpy za pomocą Frida lub czytników userland

Gdy pełny core zawiera zbyt dużo nieistotnych danych, szybszym rozwiązaniem jest zrzucenie tylko **interesujących, czytelnych zakresów**. Frida jest szczególnie przydatna, ponieważ dobrze sprawdza się przy **targeted extraction**, gdy można już podłączyć się do procesu.

Przykładowe podejście:

1. Wylicz czytelne/zapisywalne zakresy
2. Odfiltruj je według modułu, heap, stack lub anonymous memory
3. Zrzuć tylko regiony zawierające potencjalne stringi, klucze, protobufy, bloby plist/XML lub odszyfrowany kod/dane

Minimalny przykład Frida zrzucający wszystkie czytelne anonymous ranges:
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

- fragmenty app heap zawierające sekrety
- anonimowe regiony utworzone przez custom packers lub loaders
- strony kodu JIT / unpacked po zmianie zabezpieczeń

Gdy target nadal **alokuje / zwalnia** pamięć podczas dumpowania, w przypadku niestabilnych zakresów preferuj primitive Fridy **`readVolatile()`** zamiast **`readByteArray()`**. Jest wolniejszy, ale zapobiega zabiciu targetu, jeśli strona stanie się nieczytelna w trakcie odczytu. W przypadku większych akwizycji czystsze może być również przesyłanie fragmentów z powrotem za pomocą `send(..., data)` i kompresowanie ich po stronie controllera zamiast tworzenia tysięcy małych plików wewnątrz targetu.

Istnieją również starsze narzędzia userland, takie jak [`readmem`](https://github.com/gdbinit/readmem), ale są one głównie przydatne jako **referencje źródłowe** dla dumpowania w stylu `task_for_pid`/`vm_read` i nie są dobrze utrzymywane pod kątem nowoczesnych workflow na Apple Silicon.

## Snapshoty heap / VM z `.memgraph`

Jeśli interesują Cię przede wszystkim **obiekty heap**, **pochodzenie alokacji** lub snapshot, który można przenieść na inną maszynę, plik `.memgraph` jest często praktyczniejszy niż ogromny core Mach-O. Narzędzie `leaks` może wygenerować go z działającego procesu:
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

- Chcesz **mniejszy, możliwy do udostępnienia snapshot** zamiast pełnego core
- `MallocStackLogging` było włączone i chcesz uzyskać **backtrace alokacji**
- Znasz już **interesujący adres heap** i chcesz wykonać pivot za pomocą `malloc_history`
- Potrzebujesz szybkiego **zestawienia VM/heap** przed podjęciem decyzji, czy pełny dump jest wart dodatkowego szumu

### Triaging różnicowy memgraph

Jeśli kontrolujesz sposób uruchamiania targetu, włącz **historyczne logowanie alokacji** przed uruchomieniem, aby późniejsze snapshoty zachowały przydatne backtrace alokacji/zwolnień:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Następnie wykonaj snapshoty przed i po interesującym działaniu i porównaj je offline:
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
To praktyczny sposób na wyizolowanie **obiektów post-authentication**, **dużych buforów `CFData`** lub **anonimowych regionów VM**, które pojawiają się dopiero po etapie deszyfrowania, unpacking lub pobrania sekretu.

## Cele oparte w dużej mierze na Swift: `swift-inspect`

W przypadku aplikacji, które przechowują dane o wysokiej wartości w **obiektach runtime Swift**, `swift-inspect` może być dobrym uzupełnieniem LLDB lub Frida. Zamiast najpierw zrzucać wszystko, możesz odpytywać konkretne struktury runtime Swift z działającego procesu:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Jest to przydatne do identyfikowania:

- Dużych tablic Swift buforujących interesujące dane
- Alokacji metadanych ujawniających typy załadowane w czasie wykonywania
- Stanu współbieżności Swift (`Task`, actor, relacje między wątkami) przed wykonaniem bardziej ukierunkowanego dump

Aby przeprowadzić dokładniejszy runtime triage na poziomie obiektów, gdy możesz już kontrolować proces, sprawdź [dedykowaną stronę o obiektach w pamięci](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Szybkie notatki dotyczące triage

- `sysctl vm.swapusage` nadal jest szybkim sposobem na sprawdzenie **użycia swap** oraz tego, czy swap jest **zaszyfrowany**.
- `sleepimage` pozostaje istotny głównie w scenariuszach **hibernacji/safe sleep**, ale współczesne systemy często go chronią, dlatego należy traktować go jako **źródło artefaktów do sprawdzenia**, a nie jako niezawodną ścieżkę pozyskiwania danych.
- W nowszych wydaniach macOS **dump na poziomie procesu** jest zazwyczaj bardziej realistyczny niż **obrazowanie całej pamięci fizycznej**, chyba że masz kontrolę nad polityką uruchamiania, stanem SIP i ładowaniem kextów.

## References

- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [https://keith.github.io/xcode-man-pages/leaks.1.html](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
