# Przestrzeń nazw czasu

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw czasu wirtualizuje wybrane zegary typu monotonic-style zamiast zegara ściennego hosta. W praktyce oznacza to prywatne przesunięcia dla **`CLOCK_MONOTONIC`** i **`CLOCK_BOOTTIME`**, a także powiązane widoki **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** i **`CLOCK_BOOTTIME_ALARM`**. Nie wirtualizuje **`CLOCK_REALTIME`**, więc `date` i logika wygasania certyfikatów nadal obserwują zegar ścienny hosta, chyba że zakłóca to jakiś inny mechanizm.

Głównym celem jest umożliwienie procesowi obserwowania kontrolowanych przesunięć upływu czasu bez zmieniania globalnego widoku czasu hosta. Jest to przydatne w przepływach pracy checkpoint/restore, testowaniu deterministycznym oraz zaawansowanym działaniu runtime. Zwykle nie jest to najważniejszy mechanizm izolacji, tak jak namespaces montowania lub użytkowników, ale nadal pomaga uczynić środowisko procesu bardziej samodzielnym.

Z ofensywnego punktu widzenia ta przestrzeń nazw jest zwykle bardziej istotna dla **rekonesansu, rozbieżności timerów i zrozumienia działania runtime** niż dla bezpośredniego breakout. Ma jednak znaczenie, ponieważ coraz więcej container runtimes i przepływów pracy checkpoint/restore może jawnie o nią poprosić.

## Lab

Jeśli kernel hosta i userspace to obsługują, możesz sprawdzić tę przestrzeń nazw za pomocą:
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
Obsługa różni się w zależności od wersji kernela i narzędzi, dlatego ta strona służy przede wszystkim zrozumieniu mechanizmu, a nie oczekiwaniu, że będzie on widoczny w każdym środowisku laboratoryjnym. Najważniejsza obserwacja jest taka, że `date` nadal powinno odzwierciedlać zegar ścienny hosta, natomiast wartości oparte na zegarach monotonicznym/boottime to te, które zmieniają się po skonfigurowaniu niezerowych przesunięć.

### Niuans tworzenia

Namespaces czasu są nieco nietypowe w porównaniu z namespaces montowania, PID lub sieciowymi:

- `unshare(CLONE_NEWTIME)` tworzy nowy time namespace dla **przyszłych procesów potomnych**.
- Wywołujące zadanie pozostaje w swoim bieżącym time namespace.
- Dlatego `/proc/<pid>/ns/time_for_children` jest często bardziej interesujące niż `/proc/<pid>/ns/time` podczas debugowania konfiguracji runtime.

Okno zapisu również jest wyjątkowe. Przesunięcia w `/proc/<pid>/timens_offsets` muszą zostać zapisane, zanim nowy time namespace zostanie w pełni wypełniony działającymi zadaniami; w praktyce runtime'y robią to podczas krótkiego okna konfiguracji między utworzeniem namespace a uruchomieniem końcowego payloadu. Gdy działa tam już jakieś zadanie, późniejsze zapisy kończą się błędem `EACCES`. Dlatego runtime'y niskiego poziomu obsługują konfigurację time namespace jako wczesny etap bootstrapu, zamiast próbować modyfikować przesunięcia z poziomu już uruchomionego procesu kontenera.

### Przesunięcia czasu

Linux time namespaces udostępniają przesunięcia charakterystyczne dla danego namespace za pośrednictwem `/proc/<pid>/timens_offsets`. Format obejmuje zestaw nazw lub identyfikatorów zegarów oraz różnice w sekundach i nanosekundach względem początkowego time namespace.

W praktyce najbardziej niezawodnym workflow dostępnym dla użytkownika jest pozwolenie, aby `unshare` zapisał te przesunięcia za Ciebie:
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
Ważną kwestią nie jest dokładna składnia polecenia, lecz jego zachowanie: kontener może obserwować inny widok czasu działania systemu bez zmiany zegara ściennego hosta.

### Flagi pomocnicze `unshare`

Nowsze wersje `util-linux` udostępniają wygodne flagi, które automatycznie zapisują przesunięcia podczas tworzenia namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Te flagi stanowią głównie usprawnienie użyteczności, ale ułatwiają również rozpoznawanie tej funkcji w dokumentacji, harnessach testowych i wrapperach runtime.

## Użycie w runtime

Przestrzenie nazw czasu są nowsze i rzadziej używane niż przestrzenie nazw mount lub PID. OCI Runtime Specification v1.1 dodała jawną obsługę przestrzeni nazw `time` oraz pola `linux.timeOffsets`, a współczesne runtime'y mogą mapować te dane na przepływ uruchamiania kernela. Minimalny fragment OCI wygląda następująco:
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
Ma to znaczenie, ponieważ przekształca time namespacing z niszowego prymitywu kernela w coś, o co runtimes mogą prosić w sposób przenośny. Wyjaśnia to również, dlaczego wewnętrzne mechanizmy runtime potrzebują jawnego kroku synchronizacji: offset musi zostać zapisany do `/proc/<pid>/timens_offsets`, zanim payload kontenera w pełni przejdzie do nowego namespace.

Stosy checkpoint/restore, takie jak CRIU, są jednym z głównych praktycznych powodów istnienia tej funkcji. Bez time namespaces przywrócenie wstrzymanego workloadu spowodowałoby skok zegarów monotonicznych i zegarów czasu uruchomienia o czas, przez który workload był zawieszony.

## Wpływ na bezpieczeństwo

Istnieje mniej klasycznych historii breakout skoncentrowanych na time namespace niż na innych typach namespaces. Ryzyko zwykle nie polega na tym, że time namespace bezpośrednio umożliwia escape, lecz na tym, że czytelnicy całkowicie je ignorują i przez to nie dostrzegają, jak zaawansowane runtimes mogą kształtować zachowanie procesów.

W wyspecjalizowanych środowiskach zmodyfikowane widoki czasu monotonicznego lub boottime mogą wpływać na:

- zachowanie timeoutów i retry
- watchdogy oraz logikę lease
- zachowanie `timerfd`, `nanosleep` i `clock_nanosleep`
- forensics związane z checkpoint/restore
- telemetrykę upływu czasu i heurystyki oparte na uptime

Dlatego, choć rzadko jest to pierwszy namespace, który wykorzystujesz, może on zdecydowanie wyjaśniać „niemożliwe” zachowanie związane z czasem podczas assessmentu.

## Abuse

Zwykle nie ma tu bezpośredniego prymitywu breakout, ale zmienione zachowanie zegara nadal może być przydatne do zrozumienia środowiska wykonawczego, identyfikowania zaawansowanych funkcji runtime oraz wykrywania logiki opartej na timerach, w której pomiary są wykonywane względem zegarów monotonicznych zamiast czasu ściennego:
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
Jeśli porównujesz dwa procesy, występujące tu różnice mogą pomóc wyjaśnić nietypowe zachowanie związane z czasem, artefakty checkpoint/restore lub rozbieżności w logowaniu zależne od środowiska.

Praktyczne aspekty istotne dla attackera:

- wprowadzanie w błąd logiki backoff, sleep lub watchdog zaimplementowanej z użyciem zegarów monotonicznych
- wyjaśnianie, dlaczego `/proc/uptime` i zachowanie sterowane timerami nie zgadzają się z oczekiwaniami dotyczącymi wall-clock po stronie hosta
- rozpoznawanie przepływów pracy CRIU/checkpoint-restore i innych zaawansowanych funkcji runtime
- wykrywanie środowisk, w których dołączenie do time namespace celu za pomocą `nsenter -T -t <pid> -- ...` może odtworzyć lokalne dla containera zachowanie timerów na potrzeby debugowania lub post-exploitation

Wpływ:

- niemal zawsze reconnaissance lub rozpoznawanie środowiska
- przydatne do wyjaśniania anomalii w logowaniu, uptime lub checkpoint/restore
- przydatne do analizy sleep, retry i timerów opartych na czasie monotonicznym
- samo w sobie zwykle nie stanowi bezpośredniego mechanizmu container-escape

Ważne jest to, że time namespaces nie wirtualizują `CLOCK_REALTIME`, więc same w sobie nie pozwalają attackerowi sfałszować wall clock hosta ani bezpośrednio zakłócić systemowego sprawdzania wygaśnięcia certyfikatów. Ich wartość polega głównie na wprowadzaniu w błąd logiki opartej na czasie monotonicznym, odtwarzaniu błędów zależnych od środowiska lub rozumieniu zaawansowanego zachowania runtime.

## Checks

Te checks dotyczą głównie potwierdzenia, czy runtime w ogóle korzysta z prywatnego time namespace oraz czy rzeczywiście ustawił niezerowe offsety.
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

- W wielu środowiskach te wartości nie doprowadzą do natychmiastowego wykrycia problemu bezpieczeństwa, ale pokażą, czy używana jest wyspecjalizowana funkcja runtime.
- Jeśli `time_for_children` różni się od `time`, wywołujący mógł przygotować przestrzeń nazw czasu przeznaczoną wyłącznie dla procesów potomnych, do której sam nie wszedł.
- Jeśli `date` odpowiada wartości na hoście, ale wartości oparte na czasie monotonicznym lub czasie od uruchomienia systemu nie, prawdopodobnie mamy do czynienia z przestrzenią nazw czasu, a nie manipulacją zegarem ściennym.
- Jeśli porównujesz dwa procesy, występujące tu różnice mogą wyjaśniać nietypowe zachowanie związane z pomiarem czasu lub mechanizmem checkpoint/restore.

W przypadku większości container breakouts przestrzeń nazw czasu nie będzie pierwszym mechanizmem, który zbadasz. Mimo to kompletna sekcja dotycząca bezpieczeństwa kontenerów powinna o niej wspominać, ponieważ stanowi część współczesnego modelu kernela i czasami ma znaczenie w zaawansowanych scenariuszach użycia runtime.

## Odnośniki

- [Strona podręcznika Linux `time_namespaces(7)`](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
