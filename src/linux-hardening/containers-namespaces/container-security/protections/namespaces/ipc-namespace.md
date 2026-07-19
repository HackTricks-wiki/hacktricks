# Przestrzeń nazw IPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw IPC izoluje **obiekty IPC System V** oraz **kolejki komunikatów POSIX**. Obejmuje to segmenty pamięci współdzielonej, semafory i kolejki komunikatów, które w przeciwnym razie byłyby widoczne dla niezwiązanych ze sobą procesów na hoście. W praktyce uniemożliwia to kontenerowi swobodne dołączanie do obiektów IPC należących do innych workloadów lub hosta.

W porównaniu z przestrzeniami nazw mount, PID lub user, przestrzeń nazw IPC jest omawiana rzadziej, ale nie należy mylić tego z brakiem znaczenia. Pamięć współdzielona i powiązane mechanizmy IPC mogą zawierać bardzo przydatny stan. Jeśli przestrzeń nazw IPC hosta jest udostępniona, workload może uzyskać wgląd w obiekty koordynacji międzyprocesowej lub dane, które nigdy nie miały przekroczyć granicy kontenera.

## Działanie

Gdy runtime tworzy nową przestrzeń nazw IPC, proces otrzymuje własny, odizolowany zestaw identyfikatorów IPC. Oznacza to, że polecenia takie jak `ipcs` wyświetlają tylko obiekty dostępne w tej przestrzeni nazw. Jeśli kontener zamiast tego dołączy do przestrzeni nazw IPC hosta, obiekty te stają się częścią współdzielonego globalnego widoku.

Ma to szczególne znaczenie w środowiskach, w których aplikacje lub usługi intensywnie korzystają z pamięci współdzielonej. Nawet jeśli kontener nie może przeprowadzić bezpośredniego breakout wyłącznie za pośrednictwem IPC, przestrzeń nazw może ujawnić informacje lub umożliwić zakłócanie działania innych procesów, co może znacząco pomóc w późniejszym ataku.

## Lab

Możesz utworzyć prywatną przestrzeń nazw IPC za pomocą:
```bash
sudo unshare --ipc --fork bash
ipcs
```
I porównaj zachowanie w czasie wykonywania z:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Użycie w czasie działania

Docker i Podman domyślnie izolują IPC. Kubernetes zazwyczaj przydziela Pod własną przestrzeń nazw IPC, współdzieloną przez kontenery w tym samym Podzie, ale domyślnie nie przez hosta. Współdzielenie IPC z hostem jest możliwe, ale należy je traktować jako istotne zmniejszenie poziomu izolacji, a nie jako drobną opcję runtime.

## Błędne konfiguracje

Oczywistym błędem jest `--ipc=host` lub `hostIPC: true`. Może to wynikać z potrzeby zapewnienia kompatybilności ze starszym oprogramowaniem albo z wygody, ale znacząco zmienia model zaufania. Innym często występującym problemem jest zwykłe pomijanie IPC, ponieważ wydaje się ono mniej istotne niż host PID lub host networking. W rzeczywistości, jeśli workload obsługuje przeglądarki, bazy danych, scientific workloads lub inne oprogramowanie intensywnie korzystające ze współdzielonej pamięci, powierzchnia IPC może mieć duże znaczenie.

## Abuse

Gdy IPC z hostem jest współdzielone, attacker może analizować obiekty współdzielonej pamięci lub ingerować w nie, uzyskać nowe informacje o zachowaniu hosta albo sąsiednich workloadów oraz połączyć zdobytą tam wiedzę z widocznością procesów i możliwościami w stylu ptrace. Współdzielenie IPC często stanowi weakness wspierający, a nie pełną ścieżkę breakout, ale supporting weaknesses mają znaczenie, ponieważ skracają i stabilizują rzeczywiste attack chains.

Pierwszym użytecznym krokiem jest sprawdzenie, jakie obiekty IPC są w ogóle widoczne:
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
W niektórych środowiskach sama zawartość `/dev/shm` może leakować nazwy plików, artefakty lub tokeny warte sprawdzenia:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Udostępnianie IPC rzadko samo w sobie zapewnia natychmiastowy host root, ale może ujawnić dane i kanały koordynacji, które znacznie ułatwiają późniejsze ataki na procesy.

### Pełny przykład: odzyskiwanie sekretów z `/dev/shm`

Najbardziej realistycznym pełnym przypadkiem nadużycia jest kradzież danych, a nie bezpośredni escape. Jeśli host IPC lub szeroki układ shared-memory zostanie ujawniony, wrażliwe artefakty można czasem odzyskać bezpośrednio:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Wpływ:

- pozyskanie sekretów lub danych sesji pozostawionych we współdzielonej pamięci
- uzyskanie informacji o aplikacjach aktualnie aktywnych na hoście
- lepsze ukierunkowanie późniejszych ataków opartych na PID-namespace lub ptrace

Udostępnianie IPC należy więc postrzegać raczej jako **wzmacniacz ataku** niż jako samodzielny mechanizm ucieczki z hosta.

## Sprawdzenia

Te polecenia mają pomóc ustalić, czy workload ma prywatny widok IPC, czy widoczne są istotne obiekty pamięci współdzielonej lub komunikatów oraz czy samo `/dev/shm` udostępnia przydatne artefakty.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Na co warto zwrócić uwagę:

- Jeśli `ipcs -a` ujawnia obiekty należące do nieoczekiwanych użytkowników lub usług, namespace może nie być tak odizolowany, jak oczekiwano.
- Duże lub nietypowe segmenty pamięci współdzielonej często wymagają dalszego sprawdzenia.
- Szerokie zamontowanie `/dev/shm` nie jest automatycznie błędem, ale w niektórych środowiskach leak nazw plików, artefaktów i tymczasowych sekretów.

IPC rzadko otrzymuje tyle uwagi co większe typy namespace, ale w środowiskach, które intensywnie z niego korzystają, współdzielenie go z hostem jest zdecydowanie decyzją dotyczącą bezpieczeństwa.
{{#include ../../../../../banners/hacktricks-training.md}}
