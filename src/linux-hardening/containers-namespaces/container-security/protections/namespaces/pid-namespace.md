# Przestrzeń nazw PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Omówienie

Przestrzeń nazw PID kontroluje sposób numerowania procesów oraz to, które procesy są widoczne. Dzięki temu kontener może mieć własny PID 1, mimo że nie jest prawdziwą maszyną. Wewnątrz przestrzeni nazw workload widzi coś, co wygląda jak lokalne drzewo procesów. Poza przestrzenią nazw host nadal widzi rzeczywiste PID-y hosta oraz pełny obraz procesów.

Z punktu widzenia bezpieczeństwa przestrzeń nazw PID ma znaczenie, ponieważ widoczność procesów jest cenna. Gdy workload może zobaczyć procesy hosta, może być w stanie obserwować nazwy usług, argumenty wiersza poleceń, sekrety przekazane w argumentach procesów, stan wynikający ze zmiennych środowiskowych za pośrednictwem `/proc` oraz potencjalne cele wejścia do przestrzeni nazw. Jeśli może zrobić więcej niż tylko zobaczyć te procesy, na przykład wysyłać sygnały lub używać ptrace w odpowiednich warunkach, problem staje się znacznie poważniejszy.

## Działanie

Nowa przestrzeń nazw PID rozpoczyna działanie z własnym wewnętrznym numerowaniem procesów. Pierwszy proces utworzony w jej obrębie staje się PID 1 z punktu widzenia tej przestrzeni nazw, co oznacza również, że otrzymuje specjalną semantykę podobną do init w zakresie osieroconych procesów potomnych i obsługi sygnałów. Wyjaśnia to wiele nietypowych zachowań kontenerów związanych z procesami init, usuwaniem procesów zombie oraz tym, dlaczego w kontenerach czasami używa się małych wrapperów init.

Ważna lekcja dotycząca bezpieczeństwa jest taka, że proces może wyglądać na odizolowany, ponieważ widzi tylko własne drzewo PID, ale izolację tę można celowo usunąć. Docker udostępnia tę funkcję za pomocą `--pid=host`, natomiast Kubernetes robi to za pomocą `hostPID: true`. Gdy kontener dołącza do przestrzeni nazw PID hosta, workload widzi bezpośrednio procesy hosta, a wiele kolejnych ścieżek ataku staje się znacznie bardziej realistycznych.

## Lab

Aby ręcznie utworzyć przestrzeń nazw PID:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Powłoka widzi teraz prywatny widok procesów. Flaga `--mount-proc` jest istotna, ponieważ montuje instancję procfs odpowiadającą nowej przestrzeni nazw PID, dzięki czemu lista procesów jest spójna z jej wnętrza.

Aby porównać zachowanie kontenera:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Różnica jest natychmiastowa i łatwa do zrozumienia, dlatego jest to dobre pierwsze laboratorium dla czytelników.

## Użycie w runtime

Standardowe kontenery w Dockerze, Podmanie, containerd i CRI-O otrzymują własny PID namespace. Pody Kubernetes również zwykle otrzymują izolowany widok procesów, chyba że workload jawnie zażąda współdzielenia PID hosta. Środowiska LXC/Incus korzystają z tego samego prymitywu jądra, choć przypadki użycia system-container mogą ujawniać bardziej złożone drzewa procesów i zachęcać do stosowania większej liczby skrótów debugowania.

Ta sama zasada obowiązuje wszędzie: jeśli runtime nie odizolował PID namespace, oznacza to celowe osłabienie granicy kontenera.

## Błędne konfiguracje

Typową błędną konfiguracją jest współdzielenie PID hosta. Zespoły często uzasadniają je potrzebą debugowania, monitorowania lub wygodniejszego zarządzania usługami, ale zawsze należy traktować je jako istotny wyjątek bezpieczeństwa. Nawet jeśli kontener nie ma bezpośredniej możliwości zapisu do procesów hosta, sama widoczność może ujawnić wiele informacji o systemie. Po dodaniu capabilities, takich jak `CAP_SYS_PTRACE`, lub użytecznego dostępu do procfs ryzyko znacznie wzrasta.

Kolejnym błędem jest założenie, że skoro workload domyślnie nie może zabijać procesów hosta ani wykonywać na nich ptrace, to współdzielenie PID hosta jest nieszkodliwe. Taki wniosek pomija wartość enumeration, dostępność celów dla `nsenter` oraz sposób, w jaki widoczność PID łączy się z innymi osłabionymi mechanizmami kontroli.

## Nadużycie

Jeśli PID namespace hosta jest współdzielony, attacker może sprawdzać procesy hosta, pozyskiwać argumenty procesów, identyfikować interesujące usługi, lokalizować potencjalne PID-y dla `nsenter` lub łączyć widoczność procesów z privilege związanym z ptrace, aby ingerować w workloady hosta lub sąsiednie workloady. W niektórych przypadkach samo znalezienie właściwego, długotrwale działającego procesu wystarcza, aby zmienić dalszy plan ataku.

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
Jeśli `nsenter` jest dostępne i istnieją wystarczające uprawnienia, sprawdź, czy widoczny proces hosta może zostać użyty jako most do przestrzeni nazw:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Nawet gdy wejście jest zablokowane, współdzielenie PID hosta jest już wartościowe, ponieważ ujawnia układ usług, komponenty runtime oraz potencjalne uprzywilejowane procesy, które można następnie obrać za cel.

Widoczność PID hosta sprawia również, że nadużywanie deskryptorów plików staje się bardziej realistyczne. Jeśli uprzywilejowany proces hosta lub sąsiedni workload ma otwarty wrażliwy plik albo socket, attacker może być w stanie przejrzeć `/proc/<pid>/fd/` i ponownie wykorzystać ten uchwyt — zależnie od własności, opcji montowania procfs oraz modelu docelowej usługi.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Te polecenia są przydatne, ponieważ pokazują, czy `hidepid=1` lub `hidepid=2` ogranicza widoczność między procesami oraz czy oczywiście interesujące deskryptory, takie jak otwarte pliki z sekretami, logi lub Unix sockets, są w ogóle widoczne.

### Pełny przykład: host PID + `nsenter`

Udostępnianie host PID staje się bezpośrednim host escape, gdy proces ma również wystarczające uprawnienia, aby dołączyć do namespace’ów hosta:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Jeśli polecenie zakończy się powodzeniem, proces kontenera wykonuje się teraz w hostowych przestrzeniach nazw mount, UTS, network, IPC i PID. Skutek to natychmiastowe przejęcie hosta.

Nawet gdy brakuje samego `nsenter`, ten sam rezultat można osiągnąć za pośrednictwem pliku binarnego hosta, jeśli system plików hosta jest zamontowany:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Najnowsze uwagi dotyczące Runtime

Niektóre ataki istotne dla PID namespace nie są tradycyjnymi błędnymi konfiguracjami `hostPID: true`, lecz błędami implementacji Runtime dotyczącymi sposobu stosowania ochrony procfs podczas konfiguracji kontenera.

#### `maskedPaths` race do host procfs

W podatnych wersjach `runc` atakujący, którzy mogą kontrolować obraz kontenera lub workload `runc exec`, mogą przeprowadzić race fazy maskowania, zastępując kontenerowy `/dev/null` symlinkiem do wrażliwej ścieżki procfs, takiej jak `/proc/sys/kernel/core_pattern`. Jeśli race się powiedzie, bind mount masked-path może trafić do niewłaściwego celu i ujawnić globalne dla hosta ustawienia procfs nowemu kontenerowi.<sup>[[1]](#references)</sup>

Przydatne polecenie do przeglądu:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Jest to istotne, ponieważ ostateczny skutek może być taki sam jak w przypadku bezpośredniej ekspozycji procfs: zapisywalne `core_pattern` lub `sysrq-trigger`, a następnie wykonanie kodu na hoście albo odmowa usługi.

#### Wstrzykiwanie do namespace za pomocą `insject`

Narzędzia do wstrzykiwania do namespace, takie jak `insject`, pokazują, że interakcja z PID namespace nie zawsze wymaga wcześniejszego wejścia do docelowego namespace przed utworzeniem procesu. Helper może dołączyć później, użyć `setns()` i wykonać kod, zachowując widoczność docelowej przestrzeni PID:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Ten rodzaj techniki ma znaczenie głównie w zaawansowanym debugowaniu, offensive tooling oraz workflow post-exploitation, w których kontekst namespace musi zostać dołączony po wcześniejszym zainicjalizowaniu workloadu.

### Powiązane wzorce nadużywania FD

Warto wyraźnie wskazać dwa wzorce, gdy widoczne są host PIDs. Po pierwsze, uprzywilejowany proces może utrzymywać wrażliwy file descriptor otwarty podczas `execve()`, ponieważ nie został oznaczony jako `O_CLOEXEC`. Po drugie, usługi mogą przekazywać file descriptors przez Unix sockets za pośrednictwem `SCM_RIGHTS`. W obu przypadkach interesującym obiektem nie jest już pathname, lecz już otwarty handle, który proces o niższych uprawnieniach może odziedziczyć lub otrzymać.

Ma to znaczenie w pracy z kontenerami, ponieważ handle może wskazywać na `docker.sock`, uprzywilejowany log, plik z sekretem hosta lub inny obiekt o wysokiej wartości, nawet gdy sama ścieżka nie jest bezpośrednio dostępna z filesystemu kontenera.

## Sprawdzanie

Celem tych poleceń jest ustalenie, czy proces ma prywatny widok PID, czy może już wyliczać znacznie szerszy obraz procesów.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Co jest tutaj interesujące:

- Jeśli lista procesów zawiera oczywiste usługi hosta, współdzielenie PID-ów hosta prawdopodobnie już działa.
- Widoczna wyłącznie niewielka, lokalna dla kontenera hierarchia procesów to normalny stan bazowy; obecność `systemd`, `dockerd` lub niezwiązanych demonów już nie.
- Gdy PID-y hosta są widoczne, nawet informacje o procesach dostępne tylko do odczytu stają się przydatne podczas rekonesansu.

Jeśli wykryjesz kontener działający ze współdzieleniem PID-ów hosta, nie traktuj tego jako kosmetycznej różnicy. To istotna zmiana zakresu informacji, które workload może obserwować, oraz potencjalnie zasobów, na które może wpływać.

## Referencje

- [1] [runc security advisory: container escape via "masked path" abuse due to mount race conditions (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject: A Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../../banners/hacktricks-training.md}}
