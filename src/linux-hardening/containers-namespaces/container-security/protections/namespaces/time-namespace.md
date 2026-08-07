# Namespace czasu

{{#include ../../../../../banners/hacktricks-training.md}}

## Omówienie

Namespace czasu wirtualizuje wybrane zegary w stylu monotonicznym zamiast zegara ściennego hosta. W praktyce oznacza to prywatne przesunięcia dla **`CLOCK_MONOTONIC`** i **`CLOCK_BOOTTIME`**, a także powiązane widoki **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** i **`CLOCK_BOOTTIME_ALARM`**. Nie wirtualizuje **`CLOCK_REALTIME`**, dlatego `date` i logika wygasania certyfikatów nadal obserwują zegar ścienny hosta, chyba że zakłóca to inny mechanizm.<sup>[[1]](#references)</sup>

Głównym celem jest umożliwienie procesowi obserwowania kontrolowanych przesunięć upływu czasu bez zmieniania globalnego widoku czasu hosta. Jest to przydatne w workflows checkpoint/restore, testowaniu deterministycznym i zaawansowanym działaniu runtime'u. Zwykle nie jest to najważniejszy mechanizm izolacji, tak jak mount lub user namespaces, ale nadal pomaga w zwiększeniu samodzielności środowiska procesu.

Z ofensywnego punktu widzenia ten namespace jest zwykle bardziej istotny dla **rozpoznania, przesunięcia timerów i zrozumienia działania runtime'u** niż dla bezpośredniego breakoutu. Mimo to ma znaczenie, ponieważ coraz więcej container runtimes i workflows checkpoint/restore może jawnie o niego poprosić.

## Lab

Jeśli kernel hosta i userspace go obsługują, możesz sprawdzić namespace za pomocą:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
cat /proc/uptime
date
```
Obsługa różni się w zależności od wersji kernela i narzędzi, dlatego ta strona koncentruje się bardziej na zrozumieniu mechanizmu niż na oczekiwaniu, że będzie on widoczny w każdym środowisku laboratoryjnym. Ważna obserwacja jest taka, że `date` powinno nadal odzwierciedlać zegar systemowy hosta, podczas gdy wartości oparte na monotonic/boottime zmieniają się po skonfigurowaniu niezerowych przesunięć.

### Niuans tworzenia

Time namespaces są nieco nietypowe w porównaniu z mount, PID lub network namespaces:<sup>[[1]](#references)</sup>

- `unshare(CLONE_NEWTIME)` tworzy nowy time namespace dla **przyszłych procesów potomnych**.
- Wywołujące zadanie pozostaje w swoim bieżącym time namespace.
- Dlatego podczas debugowania konfiguracji runtime `/proc/<pid>/ns/time_for_children` jest często bardziej interesujące niż `/proc/<pid>/ns/time`.

Okno zapisu również jest szczególne. Przesunięcia w `/proc/<pid>/timens_offsets` muszą zostać zapisane, zanim nowy time namespace zostanie w pełni zapełniony uruchomionymi zadaniami; w praktyce runtime wykonują tę czynność podczas krótkiego okna konfiguracji między utworzeniem namespace a uruchomieniem końcowego payloadu. Gdy zadanie już działa w tym namespace, późniejsze zapisy kończą się błędem `EACCES`. Dlatego niskopoziomowe runtime traktują konfigurację time namespace jako wczesny krok bootstrapu, zamiast próbować zmieniać przesunięcia z poziomu już uruchomionego procesu kontenera.<sup>[[1]](#references)</sup>

### Przesunięcia czasu

Linux time namespaces udostępniają przesunięcia właściwe dla danego namespace za pośrednictwem `/proc/<pid>/timens_offsets`. Format obejmuje zestaw nazw lub identyfikatorów zegarów oraz przesunięcia w sekundach i nanosekundach względem initial time namespace.<sup>[[1]](#references)</sup>

W praktyce najbardziej niezawodnym workflow dostępnym dla użytkownika jest pozwolenie, aby `unshare` zapisał te przesunięcia:
```bash
sudo unshare -UrT --fork --mount-proc --monotonic 86400 --boottime 604800 bash
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Ważną kwestią nie jest dokładna składnia polecenia, lecz zachowanie: kontener może obserwować inny widok podobny do czasu działania systemu bez zmiany zegara ściennego hosta.

### Flagi pomocnicze `unshare`

Nowsze wersje `util-linux` udostępniają wygodne flagi, które automatycznie zapisują przesunięcia podczas tworzenia namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Flagi te są głównie usprawnieniem użyteczności, ale ułatwiają również rozpoznanie tej funkcji w dokumentacji, harnessach testowych i wrapperach runtime.

## Użycie runtime

Time namespaces są nowsze i rzadziej stosowane niż mount lub PID namespaces. OCI Runtime Specification v1.1 dodała jawną obsługę namespace `time` oraz pola `linux.timeOffsets`, a nowoczesne runtime'y mogą mapować te dane do przepływu uruchamiania jądra. Minimalny fragment OCI wygląda następująco:
```json
{
"linux": {
"namespaces": [
{ "type": "time" }
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Ma to znaczenie, ponieważ przekształca time namespacing z niszowego kernel primitive w coś, o co runtime'y mogą prosić w sposób przenośny. Wyjaśnia to również, dlaczego wewnętrzne mechanizmy runtime'ów potrzebują jawnego kroku synchronizacji: offset musi zostać zapisany w `/proc/<pid>/timens_offsets`, zanim payload kontenera w pełni wejdzie do nowej przestrzeni nazw.

Stosy checkpoint/restore, takie jak CRIU, są jednym z głównych praktycznych powodów istnienia tej funkcji. Bez time namespaces przywrócenie wstrzymanego workloadu spowodowałoby skok zegarów monotonicznych i boot-time o czas, przez jaki workload był zawieszony.<sup>[[2]](#references)</sup>

## Wpływ na bezpieczeństwo

Istnieje mniej klasycznych historii breakout koncentrujących się na time namespace niż na innych typach namespaces. Ryzyko zwykle nie polega na tym, że time namespace bezpośrednio umożliwia escape, lecz na tym, że czytelnicy całkowicie je ignorują i przez to nie dostrzegają, jak zaawansowane runtime'y mogą kształtować zachowanie procesów.

W wyspecjalizowanych środowiskach zmienione widoki zegarów monotonicznych lub boottime mogą wpływać na:

- zachowanie timeoutów i retry
- watchdogi oraz logikę lease
- zachowanie `timerfd`, `nanosleep` i `clock_nanosleep`
- forensics związane z checkpoint/restore
- telemetrię czasu upływającego oraz heurystyki oparte na uptime

Dlatego, choć rzadko jest to pierwszy namespace, który abuse'ujesz, może on zdecydowanie wyjaśniać „niemożliwe” zachowanie związane z czasem podczas assessmentu.

## Nadużycie

Zwykle nie ma tu bezpośredniego breakout primitive, ale zmienione zachowanie zegara nadal może być przydatne do zrozumienia środowiska wykonawczego, identyfikowania zaawansowanych funkcji runtime'u oraz wykrywania logiki opartej na timerach, która mierzy czas względem zegarów monotonicznych zamiast czasu ściennego:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Jeśli porównujesz dwa procesy, różnice w tym miejscu mogą pomóc wyjaśnić nietypowe zachowanie związane z czasem, artefakty checkpoint/restore lub rozbieżności w logowaniu zależne od środowiska.

Praktyczne aspekty istotne dla atakującego:

- zakłócanie logiki backoff, sleep lub watchdog zaimplementowanej z użyciem zegarów monotonicznych
- wyjaśnienie, dlaczego `/proc/uptime` i zachowanie sterowane timerami nie zgadzają się z oczekiwaniami dotyczącymi czasu systemowego hosta
- rozpoznawanie przepływów pracy CRIU/checkpoint-restore i innych zaawansowanych funkcji runtime
- wykrywanie środowisk, w których dołączenie do docelowej time namespace za pomocą `nsenter -T -t <pid> -- ...` może odtworzyć lokalne dla kontenera zachowanie timerów na potrzeby debugowania lub post-exploitation

Wpływ:

- niemal zawsze reconnaissance lub analiza środowiska
- przydatne do wyjaśniania anomalii związanych z logowaniem, uptime lub checkpoint/restore
- przydatne do analizy sleep, retry i timerów opartych na czasie monotonicznym
- samo w sobie zazwyczaj nie stanowi bezpośredniego mechanizmu container escape

Istotny niuans związany z abuse polega na tym, że time namespaces nie wirtualizują `CLOCK_REALTIME`, więc same w sobie nie pozwalają atakującemu sfałszować czasu systemowego hosta ani bezpośrednio obejść systemowych kontroli wygaśnięcia certyfikatów. Ich wartość polega głównie na zakłócaniu logiki opartej na czasie monotonicznym, odtwarzaniu błędów zależnych od środowiska lub analizowaniu zaawansowanego zachowania runtime.

## Kontrole

Te kontrole dotyczą głównie potwierdzenia, czy runtime w ogóle korzysta z prywatnej time namespace oraz czy rzeczywiście ustawił niezerowe offsety.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
lsns -t time 2>/dev/null                    # Host-side inventory when available
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
```
Co jest tutaj interesujące:

- W wielu środowiskach te wartości nie doprowadzą do natychmiastowego wykrycia problemu bezpieczeństwa, ale wskazują, czy używana jest wyspecjalizowana funkcja runtime.
- Jeśli `time_for_children` różni się od `time`, wywołujący mógł przygotować przestrzeń nazw czasu przeznaczoną wyłącznie dla procesów potomnych, do której sam nie wszedł.
- Jeśli `date` odpowiada wartości na hoście, ale wartości oparte na monotonic/boottime nie, prawdopodobnie masz do czynienia z namespacingiem czasu, a nie z manipulowaniem zegarem ściennym.
- Jeśli porównujesz dwa procesy, różnice w tych wartościach mogą wyjaśniać niejasne zachowanie związane z pomiarem czasu lub checkpoint/restore.

W przypadku większości container breakouts przestrzeń nazw czasu nie jest pierwszym mechanizmem, który będziesz analizować. Mimo to kompletna sekcja dotycząca container security powinna o niej wspominać, ponieważ stanowi część współczesnego modelu kernela i czasami ma znaczenie w zaawansowanych scenariuszach runtime.

## Referencje

- [1] [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [2] [Time Namespaces: Per-Container Clock Offsets for CLOCK_MONOTONIC / CLOCK_BOOTTIME - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
