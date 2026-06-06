# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

time namespace wirtualizuje wybrane zegary w stylu monotonicznym zamiast host wall clock. W praktyce oznacza to prywatne offsety dla **`CLOCK_MONOTONIC`** i **`CLOCK_BOOTTIME`**, plus ściśle powiązane widoki **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** oraz **`CLOCK_BOOTTIME_ALARM`**. Nie wirtualizuje **`CLOCK_REALTIME`**, więc `date` i logika wygasania certyfikatów nadal widzą host wall clock, chyba że jakiś inny mechanizm to zakłóca.

Głównym celem jest pozwolenie procesowi obserwować kontrolowane offsety czasu, bez zmieniania globalnego widoku czasu hosta. Jest to przydatne w workflow checkpoint/restore, deterministycznym testowaniu oraz zaawansowanym zachowaniu runtime. Zwykle nie jest to kluczowy mechanizm izolacji w takim samym stopniu jak mount czy user namespaces, ale nadal pomaga uczynić środowisko procesu bardziej samowystarczalnym.

Z ofensywnego punktu widzenia ten namespace jest zwykle bardziej istotny dla **reconnaissance, timer skew i runtime understanding** niż dla bezpośredniego breakout. Mimo to ma znaczenie, bo coraz więcej container runtimes i workflow checkpoint/restore może teraz żądać go jawnie.

## Lab

Jeśli kernel hosta i userspace wspierają tę funkcję, możesz sprawdzić namespace za pomocą:
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
Wsparcie zależy od wersji kernel i tool, więc ta strona bardziej dotyczy zrozumienia mechanizmu niż oczekiwania, że będzie widoczny w każdym lab environment. Ważna obserwacja jest taka, że `date` nadal powinno odzwierciedlać host wall clock, podczas gdy wartości oparte na monotonic/boottime są tymi, które zmieniają się po skonfigurowaniu niezerowych offsetów.

### Creation Nuance

Time namespaces są nieco nietypowe w porównaniu z mount, PID lub network namespaces:

- `unshare(CLONE_NEWTIME)` tworzy nowy time namespace dla **future children**.
- Task wywołujący pozostaje w swoim obecnym time namespace.
- `/proc/<pid>/ns/time_for_children` jest więc często bardziej interesujące niż `/proc/<pid>/ns/time` podczas debugowania runtime setup.

Okno zapisu jest też specjalne. Offsety w `/proc/<pid>/timens_offsets` muszą zostać zapisane zanim nowy time namespace zostanie w pełni zapełniony działającymi taskami; w praktyce runtimes robią to podczas wąskiego okna setup między utworzeniem namespace a uruchomieniem final payload. Gdy task już tam działa, późniejsze zapisy kończą się `EACCES`. Dlatego low-level runtimes obsługują setup time-namespace jako wczesny krok bootstrap zamiast próbować patchować offsety z wnętrza już uruchomionego container process.

### Time Offsets

Linux time namespaces udostępniają offsety per-namespace przez `/proc/<pid>/timens_offsets`. Format to zestaw nazw lub ID clock plus delty sekund/nanosekund względem initial time namespace.

W praktyce najbardziej niezawodnym workflow widocznym dla użytkownika jest pozwolić `unshare` zapisać te offsety za ciebie:
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
Ważne jest nie dokładne składni polecenia, ale zachowanie: kontener może obserwować inny widok podobny do uptime bez zmieniania zegara ściennego hosta.

### `unshare` Helper Flags

Najnowsze wersje `util-linux` zapewniają wygodne flagi, które automatycznie zapisują offsety podczas tworzenia namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Te flagi to głównie usprawnienie użyteczności, ale także ułatwiają rozpoznanie tej funkcji w dokumentacji, test harnesses i runtime wrappers.

## Runtime Usage

Time namespaces są nowsze i mniej powszechnie używane niż mount lub PID namespaces. OCI Runtime Specification v1.1 dodała jawne wsparcie dla `time` namespace oraz pola `linux.timeOffsets`, a nowoczesne runtimes mogą mapować te dane do przepływu bootstrapu jądra. Minimalny fragment OCI wygląda tak:
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
To ma znaczenie, ponieważ przekształca time namespacing z niszowego kernel primitive w coś, o co runtimes mogą prosić w sposób przenośny. Wyjaśnia też, dlaczego wnętrza runtime potrzebują jawnego kroku synchronizacji: offset musi zostać zapisany do `/proc/<pid>/timens_offsets` zanim container payload w pełni wejdzie do nowego namespace.

Stosy checkpoint/restore, takie jak CRIU, są jednym z głównych real-world powodów, dla których to w ogóle istnieje. Bez time namespaces przywrócenie wstrzymanego workload spowodowałoby, że monotonic i boot-time clocks przeskoczyłyby o czas, przez jaki workload był zawieszony.

## Security Impact

Jest mniej klasycznych breakout stories skoncentrowanych na time namespace niż w przypadku innych typów namespace. Ryzyko tutaj zwykle nie polega na tym, że time namespace bezpośrednio umożliwia escape, ale na tym, że czytelnicy całkowicie go ignorują i przez to nie zauważają, jak zaawansowane runtimes mogą kształtować zachowanie process.

W wyspecjalizowanych środowiskach zmienione widoki monotonic lub boottime mogą wpływać na:

- timeout i retry behavior
- watchdogs i lease logic
- `timerfd`, `nanosleep`, i `clock_nanosleep` behavior
- checkpoint/restore forensics
- elapsed-time telemetry i heurystyki oparte na uptime

Więc choć rzadko jest to pierwszy namespace, który abuse, może całkowicie wyjaśnić "impossible" timing behavior podczas assessment.

## Abuse

Zwykle nie ma tu bezpośredniego breakout primitive, ale zmienione zachowanie clock może nadal być użyteczne do zrozumienia execution environment, identyfikowania zaawansowanych funkcji runtime i wykrywania logiki opartej na timerach, mierzonej względem monotonic clocks zamiast wall clock time:
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
Jeśli porównujesz dwa procesy, różnice tutaj mogą pomóc wyjaśnić dziwne zachowanie czasowe, artefakty checkpoint/restore lub niedopasowania logowania zależne od środowiska.

Praktyczne, istotne z perspektywy atakującego kierunki:

- zmylić logikę backoff, sleep lub watchdog zaimplementowaną z użyciem monotonic clocks
- wyjaśnić, dlaczego `/proc/uptime` i zachowanie sterowane przez timery nie zgadza się z oczekiwaniami host-side dotyczącymi wall-clock
- rozpoznać workflow CRIU/checkpoint-restore i inne zaawansowane funkcje runtime
- wykryć środowiska, gdzie dołączenie do docelowej time namespace za pomocą `nsenter -T -t <pid> -- ...` może odtworzyć container-local timer behavior na potrzeby debugowania lub post-exploitation

Impact:

- prawie zawsze reconnaissance albo zrozumienie środowiska
- przydatne do wyjaśniania anomalii logowania, uptime lub checkpoint/restore
- przydatne do analizy sleepów, retry i timerów opartych na monotonic-time
- zwykle nie jest to samo w sobie bezpośredni mechanizm container-escape

Ważny niuans nadużycia jest taki, że time namespaces nie wirtualizują `CLOCK_REALTIME`, więc same w sobie nie pozwalają atakującemu fałszować host wall clock ani bezpośrednio łamać sprawdzania wygaśnięcia certyfikatów w całym systemie. Ich wartość polega głównie na zmylaniu logiki opartej na monotonic-time, odtwarzaniu błędów zależnych od środowiska lub rozumieniu zaawansowanego zachowania runtime.

## Checks

Te checks dotyczą głównie potwierdzenia, czy runtime w ogóle używa prywatnej time namespace i czy faktycznie ustawił niezerowe offsety.
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

- W wielu środowiskach te wartości nie doprowadzą do natychmiastowego findingu bezpieczeństwa, ale pokażą Ci, czy używana jest specjalistyczna funkcja runtime.
- Jeśli `time_for_children` różni się od `time`, wywołujący mógł przygotować child-only time namespace, do którego sam nie wszedł.
- Jeśli `date` zgadza się z hostem, ale wartości oparte na monotonic/boottime już nie, to prawdopodobnie masz do czynienia z time namespacing, a nie z manipulacją wall-clock.
- Jeśli porównujesz dwa procesy, różnice tutaj mogą wyjaśniać mylące zachowanie związane z timingiem lub checkpoint/restore.

W przypadku większości container breakout, time namespace nie jest pierwszym kontrolnym elementem, który będziesz analizować. Mimo to pełna sekcja dotycząca container-security powinna go uwzględniać, ponieważ jest częścią nowoczesnego modelu jądra i czasami ma znaczenie w zaawansowanych scenariuszach runtime.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
