# Namespace czasu

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Namespace czasu wirtualizuje wybrane zegary, w szczególności **`CLOCK_MONOTONIC`** i **`CLOCK_BOOTTIME`**. Jest to nowsza i bardziej wyspecjalizowana przestrzeń nazw niż mount, PID, network, lub user namespaces, i rzadko jest pierwszą rzeczą, o której operator myśli przy omawianiu hardeningu kontenerów. Mimo to jest częścią nowoczesnej rodziny namespaces i warto ją zrozumieć koncepcyjnie.

Głównym celem jest umożliwienie procesowi obserwowania kontrolowanych przesunięć dla niektórych zegarów bez zmieniania globalnego widoku czasu hosta. Jest to przydatne w checkpoint/restore workflows, deterministycznym testowaniu oraz w niektórych zaawansowanych zachowaniach runtime. Zwykle nie jest to nagłówkowy mechanizm izolacji w taki sam sposób jak mount czy user namespaces, ale wciąż przyczynia się do uczynienia środowiska procesu bardziej samodzielnym.

## Laboratorium

Jeśli kernel hosta i userspace to wspierają, możesz zbadać przestrzeń nazw za pomocą:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Wsparcie różni się w zależności od wersji jądra i narzędzi, więc ta strona ma raczej na celu zrozumienie mechanizmu niż zakładanie, że będzie on widoczny w każdym środowisku laboratoryjnym.

### Time Offsets

Przestrzenie nazw czasu w Linuxie wirtualizują przesunięcia dla `CLOCK_MONOTONIC` i `CLOCK_BOOTTIME`. Aktualne przesunięcia dla poszczególnych przestrzeni nazw są udostępniane przez `/proc/<pid>/timens_offsets`; na jądrze, które to obsługuje, plik ten może być także modyfikowany przez proces posiadający `CAP_SYS_TIME` wewnątrz odpowiedniej przestrzeni nazw:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Plik zawiera delty w nanosekundach. Zmiana `monotonic` o dwa dni powoduje zmianę obserwacji przypominających uptime wewnątrz tej przestrzeni nazw, bez zmiany zegara ściennego hosta.

### `unshare` Helper Flags

Nowsze wersje `util-linux` udostępniają wygodne flagi, które automatycznie zapisują przesunięcia:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Te flagi są w większości poprawą użyteczności, ale także ułatwiają rozpoznawanie tej funkcji w dokumentacji i testach.

## Użycie w czasie wykonywania

Przestrzenie nazw `time` są nowsze i mniej powszechnie stosowane niż przestrzenie nazw mount lub PID. OCI Runtime Specification v1.1 dodała jawne wsparcie dla przestrzeni nazw `time` oraz pola `linux.timeOffsets`, a nowsze wydania `runc` implementują tę część modelu. Minimalny fragment OCI wygląda tak:
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
Ma to znaczenie, ponieważ zamienia time namespacing z niszowego prymitywu jądra w coś, o co runtimes mogą żądać w sposób przenośny.

## Wpływ na bezpieczeństwo

Jest mniej klasycznych przypadków breakout skupionych wokół time namespace niż wokół innych typów namespace'ów. Ryzyko zwykle nie polega na tym, że time namespace bezpośrednio umożliwia escape, lecz na tym, że czytelnicy całkowicie go ignorują i przez to przeoczają, jak advanced runtimes mogą kształtować zachowanie procesów. W wyspecjalizowanych środowiskach zmienione widoki zegara mogą wpływać na checkpoint/restore, observability lub forensic assumptions.

## Nadużycie

Zazwyczaj nie ma tu bezpośredniego prymitywu pozwalającego na breakout, ale zmienione zachowanie zegara może być nadal przydatne do zrozumienia środowiska wykonawczego i identyfikacji advanced runtime features:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Jeśli porównujesz dwa procesy, różnice tutaj mogą pomóc wyjaśnić nietypowe zachowania związane z czasem, artefakty checkpoint/restore lub niespójności w logach specyficzne dla środowiska.

Impact:

- praktycznie zawsze rozpoznanie lub zrozumienie środowiska
- przydatne do wyjaśniania problemów z logowaniem, uptime lub anomalii checkpoint/restore
- zazwyczaj samo w sobie nie stanowi bezpośredniego mechanizmu ucieczki z kontenera

Istotnym niuansem nadużycia jest to, że time namespaces nie wirtualizują `CLOCK_REALTIME`, więc same w sobie nie pozwalają atakującemu sfałszować zegara hosta ani bezpośrednio obejść systemowych kontroli wygaśnięcia certyfikatów. Ich wartość polega głównie na komplikowaniu logiki opartej na czasie monotonicznym, reprodukowaniu błędów specyficznych dla środowiska lub zrozumieniu zaawansowanego zachowania runtime.

## Checks

Te sprawdzenia dotyczą głównie potwierdzenia, czy runtime w ogóle używa prywatnego time namespace.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Co jest tu interesujące:

- W wielu środowiskach te wartości nie prowadzą do natychmiastowego wykrycia problemu bezpieczeństwa, ale informują, czy używana jest wyspecjalizowana funkcja runtime.
- Jeśli porównujesz dwa procesy, różnice tutaj mogą wyjaśnić mylące zachowanie związane z czasowaniem lub z checkpoint/restore.

W przypadku większości container breakouts, time namespace nie jest pierwszą kontrolą, którą będziesz badać. Mimo to kompletna sekcja container-security powinna o nim wspomnieć, ponieważ jest częścią nowoczesnego modelu jądra i sporadycznie ma znaczenie w zaawansowanych scenariuszach runtime.
