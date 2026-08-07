# Przestrzeń nazw IPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw IPC izoluje **obiekty IPC System V** oraz **kolejki komunikatów POSIX**. Obejmuje to segmenty pamięci współdzielonej, semafory i kolejki komunikatów, które w przeciwnym razie byłyby widoczne dla niezależnych procesów na hoście. W praktyce uniemożliwia to kontenerowi swobodne dołączanie do obiektów IPC należących do innych workloadów lub hosta.

W porównaniu z przestrzeniami nazw mount, PID lub user, przestrzeń nazw IPC jest często omawiana rzadziej, ale nie należy tego mylić z brakiem znaczenia. Pamięć współdzielona i powiązane mechanizmy IPC mogą zawierać bardzo przydatny stan. Jeśli przestrzeń nazw IPC hosta jest udostępniona, workload może uzyskać wgląd w obiekty koordynacji międzyprocesowej lub dane, które nigdy nie miały przekraczać granicy kontenera.

## Działanie

Gdy runtime tworzy nową przestrzeń nazw IPC, proces otrzymuje własny, odizolowany zestaw identyfikatorów IPC. Oznacza to, że polecenia takie jak `ipcs` pokazują tylko obiekty dostępne w tej przestrzeni nazw. Jeśli kontener zamiast tego dołączy do przestrzeni nazw IPC hosta, obiekty te stają się częścią współdzielonego globalnego widoku.

Ma to szczególne znaczenie w środowiskach, w których aplikacje lub usługi intensywnie korzystają z pamięci współdzielonej. Nawet jeśli kontener nie może bezpośrednio wydostać się z niego wyłącznie przez IPC, przestrzeń nazw może leakować informacje lub umożliwiać ingerencję między procesami, która znacząco pomoże w późniejszym ataku.

## Lab

Możesz utworzyć prywatną przestrzeń nazw IPC za pomocą:
```bash
sudo unshare --ipc --fork bash
ipcs
```
I porównaj zachowanie w czasie działania z:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Użycie w czasie działania

Docker i Podman domyślnie izolują IPC. Kubernetes zazwyczaj przydziela Pod własną przestrzeń nazw IPC, współdzieloną przez kontenery w tym samym Podzie, ale domyślnie nie przez hosta. Współdzielenie IPC z hostem jest możliwe, ale należy je traktować jako istotne zmniejszenie izolacji, a nie jako drobną opcję runtime.

## Błędne konfiguracje

Oczywistym błędem jest `--ipc=host` lub `hostIPC: true`. Może to wynikać z potrzeby zapewnienia kompatybilności ze starszym oprogramowaniem albo z wygody, ale znacznie zmienia model zaufania. Innym powtarzającym się problemem jest zwykłe pomijanie IPC, ponieważ wydaje się mniej istotne niż host PID lub host networking. W rzeczywistości, jeśli workload obsługuje przeglądarki, bazy danych, workloady naukowe lub inne oprogramowanie intensywnie korzystające ze shared memory, powierzchnia IPC może mieć duże znaczenie.

## Abuse

Gdy host IPC jest współdzielony, attacker może przeglądać obiekty shared memory lub ingerować w nie, uzyskać nowe informacje o działaniu hosta lub sąsiedniego workloadu, a także łączyć zdobyte tam informacje z widocznością procesów i capabilities w stylu ptrace. Współdzielenie IPC często stanowi supporting weakness, a nie pełną ścieżkę breakout, ale supporting weaknesses mają znaczenie, ponieważ skracają i stabilizują rzeczywiste attack chains.

Pierwszym przydatnym krokiem jest enumeracja wszystkich widocznych obiektów IPC:
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
Udostępnianie IPC rzadko samo w sobie zapewnia natychmiastowy host root, ale może ujawnić kanały danych i koordynacji, które znacznie ułatwiają późniejsze ataki na procesy.

### Pełny przykład: odzyskiwanie sekretów z `/dev/shm`

Najbardziej realistyczny przypadek nadużycia to kradzież danych, a nie bezpośredni escape. Jeśli IPC hosta lub szeroki układ shared memory jest ujawniony, poufne artefakty można czasami odzyskać bezpośrednio:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Wpływ:

- wydobycie sekretów lub materiału sesyjnego pozostawionego we współdzielonej pamięci
- uzyskanie informacji o aplikacjach aktualnie aktywnych na hoście
- lepsze ukierunkowanie późniejszych ataków opartych na przestrzeni nazw PID lub ptrace

Udostępnianie IPC należy zatem rozumieć raczej jako **wzmacniacz ataku** niż jako samodzielny mechanizm ucieczki z hosta.

## Sprawdzenia

Te polecenia mają odpowiedzieć na pytania, czy workload ma prywatny widok IPC, czy widoczne są istotne obiekty pamięci współdzielonej lub komunikatów oraz czy samo `/dev/shm` ujawnia przydatne artefakty.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Co jest tutaj interesujące:

- Jeśli `ipcs -a` ujawnia obiekty należące do nieoczekiwanych użytkowników lub usług, namespace może nie być tak odizolowany, jak zakładano.
- Duże lub nietypowe segmenty pamięci współdzielonej często warto dokładniej zbadać.
- Szerokie zamontowanie `/dev/shm` nie jest automatycznie błędem, ale w niektórych środowiskach leaks nazwy plików, artefakty i tymczasowe sekrety.

IPC rzadko otrzymuje tyle uwagi co większe typy namespace, ale w środowiskach, które intensywnie z niego korzystają, współdzielenie go z hostem jest zdecydowanie decyzją dotyczącą bezpieczeństwa.

{{#include ../../../../../banners/hacktricks-training.md}}
