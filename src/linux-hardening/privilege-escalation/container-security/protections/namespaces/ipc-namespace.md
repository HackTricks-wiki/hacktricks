# Przestrzeń nazw IPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw IPC izoluje **System V IPC objects** i **POSIX message queues**. Obejmuje to segmenty pamięci współdzielonej, semafory i kolejki komunikatów, które w przeciwnym razie byłyby widoczne dla niezwiązanych procesów na hoście. W praktyce uniemożliwia to kontenerowi przypadkowe podłączenie się do obiektów IPC należących do innych zadań lub hosta.

W porównaniu z mount, PID czy user namespaces, przestrzeń nazw IPC jest omawiana rzadziej, ale nie należy tego mylić z brakiem znaczenia. Pamięć współdzielona i powiązane mechanizmy IPC mogą zawierać bardzo przydatny stan. Jeśli przestrzeń nazw IPC hosta zostanie ujawniona, zadanie może uzyskać widoczność obiektów koordynacji międzyprocesowej lub danych, które nigdy nie miały przekraczać granicy kontenera.

## Działanie

Gdy runtime tworzy nową przestrzeń nazw IPC, proces otrzymuje własny, izolowany zestaw identyfikatorów IPC. Oznacza to, że polecenia takie jak `ipcs` pokazują tylko obiekty dostępne w tej przestrzeni nazw. Jeśli kontener zamiast tego dołączy do przestrzeni nazw IPC hosta, te obiekty stają się częścią wspólnego widoku globalnego.

Ma to znaczenie zwłaszcza w środowiskach, gdzie aplikacje lub usługi intensywnie korzystają z pamięci współdzielonej. Nawet gdy kontener nie może bezpośrednio uciec przy użyciu samego IPC, przestrzeń nazw może leak informacje lub umożliwić interferencję międzyprocesową, która znacząco ułatwi późniejszy atak.

## Laboratorium

Możesz utworzyć prywatną przestrzeń nazw IPC za pomocą:
```bash
sudo unshare --ipc --fork bash
ipcs
```
I porównaj zachowanie w czasie wykonania z:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Użycie w czasie wykonywania

Docker i Podman domyślnie izolują IPC. Kubernetes zazwyczaj przypisuje Podowi własną przestrzeń nazw IPC, współdzieloną przez kontenery w tym samym Podzie, ale domyślnie niewspółdzieloną z hostem. Udostępnienie IPC hosta jest możliwe, ale należy to traktować jako znaczące osłabienie izolacji, a nie jako drobną opcję uruchomieniową.

## Błędy konfiguracji

Oczywistym błędem jest `--ipc=host` lub `hostIPC: true`. Może to być zrobione dla kompatybilności ze starym oprogramowaniem lub dla wygody, ale znacząco zmienia model zaufania. Innym powtarzającym się problemem jest po prostu przeoczenie IPC, ponieważ wydaje się mniej dramatyczne niż host PID lub host networking. W rzeczywistości, jeśli workload obsługuje przeglądarki, bazy danych, obciążenia naukowe lub inne oprogramowanie intensywnie korzystające z pamięci współdzielonej, powierzchnia IPC może być bardzo istotna.

## Wykorzystanie

Gdy host IPC jest współdzielony, atakujący może analizować lub ingerować w obiekty pamięci współdzielonej, uzyskać nowe informacje o zachowaniu hosta lub sąsiedniego workloadu, albo łączyć zdobyte informacje z widocznością procesów i możliwościami ptrace-style. Udostępnianie IPC często jest słabością wspierającą, a nie pełną ścieżką escape, ale słabości wspierające mają znaczenie, ponieważ skracają i stabilizują rzeczywiste łańcuchy ataku.

Pierwszym użytecznym krokiem jest wyliczenie, jakie obiekty IPC są w ogóle widoczne:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Jeśli host IPC namespace jest współdzielony, duże segmenty pamięci współdzielonej lub interesujący właściciele obiektów mogą natychmiast ujawnić zachowanie aplikacji:
```bash
ipcs -m -p
ipcs -q -p
```
W niektórych środowiskach zawartość `/dev/shm` sama w sobie ujawnia nazwy plików, artefakty lub tokeny warte sprawdzenia:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Udostępnianie IPC rzadko samo w sobie daje natychmiastowy host root, ale może ujawnić dane i kanały koordynacyjne, które znacznie ułatwiają późniejsze ataki na procesy.

### Pełny przykład: `/dev/shm` odzyskiwanie sekretów

Najbardziej realistycznym scenariuszem nadużycia jest kradzież danych, a nie bezpośredni escape. Jeśli host IPC lub szeroki układ pamięci współdzielonej zostanie ujawniony, wrażliwe artefakty czasami można odzyskać bezpośrednio:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Wpływ:

- wydobycie sekretów lub materiału sesji pozostawionego w pamięci współdzielonej
- wgląd w aplikacje aktualnie aktywne na hoście
- lepsze ukierunkowanie późniejszych ataków opartych na PID-namespace lub ptrace

Dzielenie IPC jest zatem lepiej rozumiane jako **wzmacniacz ataku** niż jako samodzielny host-escape primitive.

## Checks

Te polecenia mają odpowiedzieć, czy workload ma prywatny widok IPC, czy widoczne są istotne obiekty pamięci współdzielonej lub obiekty wiadomości, oraz czy sam katalog `/dev/shm` ujawnia przydatne artefakty.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
- Jeśli `ipcs -a` ujawnia obiekty należące do nieoczekiwanych użytkowników lub usług, namespace może nie być tak odizolowany, jak się oczekuje.
- Warto przyjrzeć się dużym lub nietypowym shared memory segments.
- Szeroki `/dev/shm` mount nie jest automatycznie bugiem, ale w niektórych środowiskach leaks filenames, artifacts, and transient secrets.

IPC rzadko otrzymuje tyle uwagi co większe typy namespace, ale w środowiskach, które go intensywnie używają, dzielenie go z hostem jest w istocie decyzją bezpieczeństwa.
