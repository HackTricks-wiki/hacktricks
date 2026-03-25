# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Artefakty pamięci

### Pliki swap

Pliki swap, takie jak `/private/var/vm/swapfile0`, służą jako **cache, gdy pamięć fizyczna jest pełna**. Gdy nie ma już miejsca w pamięci fizycznej, jej dane są przenoszone do pliku swap i w razie potrzeby przywracane do pamięci fizycznej. Może istnieć wiele plików swap, o nazwach takich jak swapfile0, swapfile1 itd.

### Obraz hibernacji

Plik znajdujący się pod ścieżką `/private/var/vm/sleepimage` jest kluczowy podczas **trybu hibernacji**. **Dane z pamięci są zapisywane w tym pliku, gdy OS X przechodzi w hibernację**. Po wybudzeniu komputera system odczytuje dane pamięci z tego pliku, dzięki czemu użytkownik może kontynuować pracę tam, gdzie przerwał.

Warto zauważyć, że na nowoczesnych systemach MacOS ten plik jest zwykle szyfrowany ze względów bezpieczeństwa, co utrudnia odzyskiwanie danych.

- Aby sprawdzić, czy szyfrowanie jest włączone dla sleepimage, można uruchomić polecenie `sysctl vm.swapusage`. Pokaże ono, czy plik jest zaszyfrowany.

### Logi memory pressure

Innym istotnym plikiem związanym z pamięcią w systemach MacOS jest **memory pressure log**. Logi te znajdują się w `/var/log` i zawierają szczegółowe informacje o użyciu pamięci przez system i zdarzeniach związanych z memory pressure. Mogą być szczególnie przydatne przy diagnozowaniu problemów z pamięcią lub zrozumieniu, jak system zarządza pamięcią w czasie.

## Dumping memory with osxpmem

Aby zrzucić pamięć na maszynie MacOS możesz użyć [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Uwaga**: To obecnie w dużej mierze **przestarzałe rozwiązanie**. `osxpmem` wymaga załadowania rozszerzenia jądra, projekt [Rekall](https://github.com/google/rekall) jest archiwalny, ostatnie wydanie pochodzi z **2017**, a opublikowany binarny celuje w **Intel Macs**. Na aktualnych wydaniach macOS, szczególnie na **Apple Silicon**, zrzut pamięci oparty na kext jest zwykle blokowany przez nowoczesne ograniczenia dotyczące kernel-extension, SIP i wymogi podpisywania platformy. W praktyce na współczesnych systemach częściej wykonuje się **process-scoped dump** zamiast image całej pamięci (whole-RAM image).
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Jeśli napotkasz ten błąd: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Możesz to naprawić, wykonując:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Inne błędy** mogą być naprawione przez **zezwolenie na załadowanie kext** w "Security & Privacy --> General" — po prostu **allow**.

Możesz także użyć tego **oneliner** aby download the application, load the kext and dump the memory:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Zrzucanie pamięci procesu na żywo za pomocą LLDB

Dla **nowszych wersji macOS**, najbardziej praktyczne podejście zwykle polega na zrzuceniu pamięci **konkretnego procesu** zamiast próby utworzenia obrazu całej pamięci fizycznej.

LLDB może zapisać plik core Mach-O z działającego procesu docelowego:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Domyślnie zazwyczaj tworzy to **skinny core**. Aby zmusić LLDB do uwzględnienia całej zmapowanej pamięci procesu:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Przydatne polecenia do wykonania przed zrzutem pamięci:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Zazwyczaj wystarcza, gdy celem jest odzyskanie:

- Odszyfrowane bloby konfiguracji
- Tokenów, cookies lub poświadczeń znajdujących się w pamięci
- Sekretów w postaci tekstu jawnego, które są chronione tylko w stanie spoczynku
- Odszyfrowanych stron Mach-O po unpackingu / JIT / runtime patchingu

Jeśli cel jest chroniony przez **hardened runtime**, lub jeśli `taskgated` odmawia attachu, zwykle potrzebujesz jednego z poniższych warunków:

- Cel posiada **`get-task-allow`**
- Twój debugger jest podpisany z odpowiednim **debugger entitlement**
- Jesteś **root** i cel to proces third-party bez hardened runtime

For more background on obtaining a task port and what can be done with it:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## Selektywne zrzuty z użyciem Frida lub readerów userland

Gdy pełny zrzut pamięci jest zbyt „hałaśliwy”, zrzucanie tylko **interesujących zakresów do odczytu** jest zwykle szybsze. Frida jest szczególnie przydatna, ponieważ dobrze sprawdza się przy **ekstrakcji ukierunkowanej** po uzyskaniu możliwości attachu do procesu.

Przykładowe podejście:

1. Wypisz zakresy możliwe do odczytu/zapisu
2. Filtruj według modułu, heap, stack lub pamięci anonimowej
3. Zrzucaj tylko regiony zawierające potencjalne ciągi znaków, klucze, protobufs, plist/XML bloby lub odszyfrowany kod/dane

Minimalny przykład Frida do zrzutu wszystkich czytelnych zakresów anonimowych:
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
To przydatne, gdy chcesz uniknąć ogromnych plików core i zebrać jedynie:

- fragmenty heap aplikacji zawierające sekrety
- anonimowe regiony tworzone przez custom packers lub loaders
- strony kodu JIT / unpacked po zmianie protections

Starsze narzędzia userland, takie jak [`readmem`](https://github.com/gdbinit/readmem), również istnieją, ale są głównie przydatne jako **źródła odniesienia** dla bezpośredniego zrzucania w stylu `task_for_pid`/`vm_read` i nie są dobrze utrzymywane dla nowoczesnych workflowów Apple Silicon.

## Szybka ocena (triage)

- `sysctl vm.swapusage` wciąż jest szybkim sposobem na sprawdzenie **użycia swap** i czy swap jest **szyfrowany**.
- `sleepimage` pozostaje istotny głównie w scenariuszach **hibernate/safe sleep**, ale nowoczesne systemy zwykle go chronią, więc należy go traktować jako **źródło artefaktów do sprawdzenia**, a nie jako niezawodną ścieżkę pozyskania.
- W nowszych wydaniach macOS, **process-level dumping** jest zazwyczaj bardziej realistyczny niż **full physical memory imaging**, chyba że kontrolujesz boot policy, stan SIP i ładowanie kext.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
