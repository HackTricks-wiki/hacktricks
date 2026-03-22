# Przestrzeń nazw IPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw IPC izoluje **System V IPC objects** i **POSIX message queues**. Obejmuje to segmenty pamięci współdzielonej, semafory oraz kolejki komunikatów, które w przeciwnym razie byłyby widoczne dla niespowinowaconych procesów na hoście. W praktyce zapobiega to temu, by container mógł swobodnie dołączać do obiektów IPC należących do innych workloadów lub hosta.

W porównaniu z mount, PID czy user namespaces, przestrzeń nazw IPC bywa omawiana rzadziej, ale nie oznacza to, że jest nieistotna. Pamięć współdzielona i powiązane mechanizmy IPC mogą zawierać bardzo użyteczny stan. Jeśli host IPC namespace zostanie ujawniony, workload może zyskać wgląd w obiekty koordynacji międzyprocesowej lub dane, które nigdy nie miały przekraczać granicy kontenera.

## Działanie

Kiedy runtime tworzy nową przestrzeń nazw IPC, proces otrzymuje własny, izolowany zestaw identyfikatorów IPC. Oznacza to, że polecenia takie jak `ipcs` pokażą tylko obiekty dostępne w tej przestrzeni nazw. Jeśli kontener zamiast tego dołączy do host IPC namespace, te obiekty staną się częścią wspólnego, globalnego widoku.

Ma to szczególne znaczenie w środowiskach, gdzie aplikacje lub usługi intensywnie używają pamięci współdzielonej. Nawet jeśli kontener nie może bezpośrednio wydostać się przez samo IPC, przestrzeń nazw może leak informacji lub umożliwić interferencję międzyprocesową, co istotnie ułatwi późniejszy atak.

## Laboratorium

Możesz utworzyć prywatną przestrzeń nazw IPC za pomocą:
```bash
sudo unshare --ipc --fork bash
ipcs
```
I porównaj zachowanie podczas działania z:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Użycie w czasie wykonywania

Docker i Podman domyślnie izolują IPC. Kubernetes zazwyczaj przydziela Podowi własną przestrzeń nazw IPC, współdzieloną przez kontenery w tym samym Podzie, ale domyślnie nie z hostem. Udostępnianie IPC hosta jest możliwe, lecz powinno być traktowane jako znaczące osłabienie izolacji, a nie drobna opcja w czasie wykonywania.

## Nieprawidłowe konfiguracje

Oczywistym błędem jest `--ipc=host` lub `hostIPC: true`. Może to być stosowane dla kompatybilności ze starszym oprogramowaniem lub ze względów wygody, ale znacząco zmienia model zaufania. Innym powtarzającym się problemem jest po prostu pomijanie IPC, ponieważ wydaje się mniej dramatyczne niż PID hosta czy sieć hosta. W rzeczywistości, jeśli obciążenie obsługuje przeglądarki, bazy danych, obciążenia naukowe lub inne oprogramowanie intensywnie korzystające z pamięci współdzielonej, powierzchnia IPC może być bardzo istotna.

## Wykorzystanie

Gdy IPC hosta jest udostępnione, atakujący może przeglądać lub ingerować w obiekty pamięci współdzielonej, uzyskać nowe informacje o zachowaniu hosta lub sąsiedniego obciążenia, albo połączyć zdobyte tam informacje z widocznością procesów i możliwościami ptrace-style. Udostępnianie IPC często jest słabością wspierającą, a nie pełną ścieżką przełamania, jednak słabości wspierające mają znaczenie, ponieważ skracają i stabilizują realne łańcuchy ataku.

Pierwszym użytecznym krokiem jest wyenumerowanie, które obiekty IPC są w ogóle widoczne:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Jeśli przestrzeń nazw IPC hosta jest współdzielona, duże segmenty pamięci współdzielonej lub interesujący właściciele obiektów mogą natychmiast ujawnić zachowanie aplikacji:
```bash
ipcs -m -p
ipcs -q -p
```
W niektórych środowiskach, zawartość `/dev/shm` sama w sobie może leak nazwy plików, artefakty lub tokeny warte sprawdzenia:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Udostępnianie IPC rzadko samo w sobie daje natychmiastowy host root, ale może ujawnić kanały danych i koordynacji, które znacznie ułatwiają późniejsze ataki na procesy.

### Pełny przykład: `/dev/shm` — odzyskiwanie sekretów

Najbardziej realistycznym pełnym przypadkiem nadużycia jest kradzież danych, a nie bezpośrednie wydostanie się. Jeśli host IPC lub szeroki układ pamięci współdzielonej jest ujawniony, wrażliwe artefakty czasami można odzyskać bezpośrednio:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Wpływ:

- ekstrakcja sekretów lub materiału sesji pozostawionego w pamięci współdzielonej
- wgląd w aplikacje aktualnie aktywne na hoście
- lepsze ukierunkowanie dla późniejszych ataków opartych na PID-namespace lub ptrace

Udostępnianie IPC jest zatem lepiej rozumiane jako **wzmacniacz ataku** niż jako samodzielny mechanizm umożliwiający ucieczkę z hosta.

## Sprawdzenia

Te polecenia mają na celu odpowiedzieć, czy workload ma prywatny widok IPC, czy widoczne są istotne obiekty pamięci współdzielonej lub wiadomości, oraz czy sam `/dev/shm` ujawnia przydatne artefakty.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
- Jeśli `ipcs -a` ujawnia obiekty należące do nieoczekiwanych użytkowników lub usług, przestrzeń nazw może nie być tak odizolowana, jak oczekiwano.
- Duże lub nietypowe segmenty pamięci współdzielonej często warto poddać dalszej analizie.
- Szerokie zamontowanie `/dev/shm` nie jest automatycznie błędem, ale w niektórych środowiskach leaks nazwy plików, artefakty i tymczasowe sekrety.

IPC rzadko otrzymuje tyle uwagi co większe typy przestrzeni nazw, ale w środowiskach, które go intensywnie używają, dzielenie go z hostem to w istocie decyzja bezpieczeństwa.
{{#include ../../../../../banners/hacktricks-training.md}}
