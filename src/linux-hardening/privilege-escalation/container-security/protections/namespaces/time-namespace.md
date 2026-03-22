# Namespace czasu

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

The time namespace virtualizes selected clocks, especially **`CLOCK_MONOTONIC`** and **`CLOCK_BOOTTIME`**. Jest nowszym i bardziej wyspecjalizowanym namespace niż mount, PID, network, or user namespaces, i rzadko jest pierwszą rzeczą, o której operator myśli przy omawianiu zabezpieczania kontenerów. Mimo to należy do nowoczesnej rodziny namespaces i warto go zrozumieć konceptualnie.

Głównym celem jest umożliwienie procesowi obserwowania kontrolowanych przesunięć (offsetów) dla niektórych zegarów bez zmiany globalnego widoku czasu hosta. Jest to użyteczne w checkpoint/restore workflows, deterministycznym testowaniu oraz przy zaawansowanym zachowaniu runtime. Zazwyczaj nie stanowi to głównego mechanizmu izolacji w ten sam sposób co mount czy user namespaces, ale nadal przyczynia się do uczynienia środowiska procesu bardziej samodzielnym.

## Laboratorium

If the host kernel and userspace support it, you can inspect the namespace with:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Support varies by kernel and tool versions, so this page is more about understanding the mechanism than expecting it to be visible in every lab environment.

### Przesunięcia czasu

Namespaces czasu w Linuxie wirtualizują przesunięcia dla `CLOCK_MONOTONIC` i `CLOCK_BOOTTIME`. Bieżące przesunięcia dla każdego namespace są udostępnione przez `/proc/<pid>/timens_offsets`, które na wspierających jądrach mogą być również modyfikowane przez proces posiadający `CAP_SYS_TIME` wewnątrz odpowiedniego namespace:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Plik zawiera różnice w nanosekundach. Dopasowanie `monotonic` o dwa dni zmienia obserwacje podobne do uptime wewnątrz tej przestrzeni nazw bez zmiany zegara ściennego hosta.

### `unshare` Flagi pomocnicze

Nowsze wersje `util-linux` dostarczają wygodne flagi, które automatycznie zapisują przesunięcia:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Te flagi są w większości ulepszeniem użyteczności, ale także ułatwiają rozpoznanie funkcji w dokumentacji i testach.

## Użycie w czasie wykonywania

Przestrzenie nazw czasu są nowsze i rzadziej wykorzystywane niż przestrzenie nazw mount lub PID. OCI Runtime Specification v1.1 dodała jawne wsparcie dla `time` namespace i pola `linux.timeOffsets`, a nowsze wydania `runc` implementują tę część modelu. Minimalny fragment OCI wygląda tak:
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
To ma znaczenie, ponieważ przekształca time namespacing z niszowego prymitywu jądra w coś, o co runtimes mogą żądać przenośnie.

## Wpływ na bezpieczeństwo

Jest mniej klasycznych historii o breakout skoncentrowanych na time namespace niż na innych typach namespace. Ryzyko zwykle nie polega na tym, że time namespace bezpośrednio umożliwia escape, lecz na tym, że czytelnicy całkowicie go ignorują i w związku z tym nie zauważają, jak zaawansowane runtimes mogą kształtować zachowanie procesów. W wyspecjalizowanych środowiskach zmienione widoki zegara mogą wpływać na checkpoint/restore, observability lub założenia śledcze.

## Nadużycia

Zazwyczaj nie ma tu bezpośredniego prymitywu umożliwiającego breakout, ale zmienione zachowanie zegara może być nadal użyteczne do zrozumienia środowiska wykonawczego i identyfikacji zaawansowanych funkcji runtime:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Jeżeli porównujesz dwa procesy, różnice tutaj mogą pomóc wyjaśnić dziwne zachowania związane z czasem, artefakty checkpoint/restore lub niespójności w logowaniu zależne od środowiska.

Wpływ:

- praktycznie zawsze rozpoznanie lub zrozumienie środowiska
- przydatne do wyjaśniania anomalii w logowaniu, czasie działania lub checkpoint/restore
- zazwyczaj nie stanowi samo w sobie bezpośredniego mechanizmu container-escape

Istotna niuans nadużycia polega na tym, że przestrzenie nazw czasu nie wirtualizują `CLOCK_REALTIME`, więc same w sobie nie pozwalają atakującemu sfałszować zegara systemowego hosta ani bezpośrednio złamać sprawdzania ważności certyfikatów w całym systemie. Ich wartość polega głównie na wprowadzaniu w błąd logiki opartej na czasie monotonicznym, odtwarzaniu błędów specyficznych dla środowiska lub zrozumieniu zaawansowanego zachowania runtime.

## Sprawdzenia

Te sprawdzenia dotyczą głównie potwierdzenia, czy runtime w ogóle używa prywatnej przestrzeni nazw czasu.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Co jest tu interesujące:

- W wielu środowiskach te wartości nie doprowadzą do natychmiastowego problemu bezpieczeństwa, ale informują, czy używana jest wyspecjalizowana funkcja runtime.
- Jeśli porównujesz dwa procesy, różnice tutaj mogą wyjaśnić mylące zachowanie związane z timingiem lub checkpoint/restore.

W przypadku większości container breakouts, time namespace nie będzie pierwszym mechanizmem kontroli, który sprawdzisz. Niemniej jednak kompletna sekcja container-security powinna o nim wspomnieć, ponieważ jest częścią nowoczesnego modelu jądra i od czasu do czasu ma znaczenie w zaawansowanych scenariuszach runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
