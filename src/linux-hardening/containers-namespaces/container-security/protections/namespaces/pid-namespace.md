# Przestrzeń nazw PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw PID kontroluje sposób numerowania procesów i określa, które procesy są widoczne. Dlatego kontener może mieć własny PID 1, mimo że nie jest prawdziwą maszyną. Wewnątrz przestrzeni nazw workload widzi coś, co wygląda jak lokalne drzewo procesów. Poza nią host nadal widzi rzeczywiste PID-y hosta i pełny obraz procesów.<sup>[[3]](#references)</sup>

Z punktu widzenia bezpieczeństwa przestrzeń nazw PID ma znaczenie, ponieważ widoczność procesów jest cenna. Gdy workload może zobaczyć procesy hosta, może być w stanie odczytać nazwy usług, argumenty wiersza poleceń, sekrety przekazane jako argumenty procesów, stan pochodzący ze zmiennych środowiskowych za pośrednictwem `/proc` oraz potencjalne cele dołączenia do przestrzeni nazw. Jeśli może zrobić więcej niż tylko zobaczyć te procesy, na przykład wysyłać sygnały lub używać ptrace w odpowiednich warunkach, problem staje się znacznie poważniejszy.

## Działanie

Nowa przestrzeń nazw PID zaczyna od własnej numeracji procesów. Pierwszy proces utworzony w jej obrębie otrzymuje PID 1 z punktu widzenia tej przestrzeni nazw, co oznacza również, że zapewnia specjalną semantykę podobną do init w zakresie osieroconych procesów potomnych i obsługi sygnałów. Wyjaśnia to wiele nietypowych zachowań kontenerów związanych z procesami init, zbieraniem zombie i używaniem w kontenerach lekkich wrapperów init.<sup>[[3]](#references)</sup>

Przestrzenie nazw PID tworzą hierarchię. Proces w nadrzędnej przestrzeni nazw może odwoływać się do procesów potomnych, używając PID przypisanego im w tej nadrzędnej przestrzeni, ale proces potomny nie może odwoływać się do zadań dostępnych wyłącznie w przestrzeni nadrzędnej za pomocą zwykłych wywołań systemowych opartych na PID ani użyć `setns()` do przejścia w górę, do nadrzędnej przestrzeni nazw PID. System plików procfs należący do przestrzeni nadrzędnej, celowo udostępniony procesowi potomnemu, nadal może leakować widok procesów z przestrzeni nadrzędnej. Ponadto dołączenie do przestrzeni nazw PID za pomocą `setns()` zmienia przestrzeń nazw dla **przyszłych procesów potomnych**, a nie dla samego wywołującego; dlatego narzędzia wykonują fork po dołączeniu. Montowanie procfs zachowuje widok PID procesu, który je zamontował. Dlatego utworzenie nowego procfs po `unshare(CLONE_NEWPID)` ma znaczenie dla bezpieczeństwa i nie jest jedynie kwestią kosmetyczną.<sup>[[3]](#references)</sup>

Ważna lekcja dotycząca bezpieczeństwa jest taka, że proces może wyglądać na odizolowany, ponieważ widzi wyłącznie własne drzewo PID, ale tę izolację można celowo znieść. Docker udostępnia tę możliwość przez `--pid=host`, a Kubernetes przez `hostPID: true`. Gdy kontener dołącza do przestrzeni nazw PID hosta, workload widzi bezpośrednio procesy hosta, przez co wiele późniejszych ścieżek ataku staje się znacznie bardziej realnych.

## Laboratorium

Aby ręcznie utworzyć przestrzeń nazw PID:

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

Powłoka widzi teraz prywatny widok procesów. Flaga `--mount-proc` jest ważna, ponieważ montuje instancję procfs odpowiadającą nowej przestrzeni nazw PID, dzięki czemu lista procesów jest spójna z jej wnętrza.<sup>[[3]](#references)</sup>

Aby porównać zachowanie kontenerów:

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

Różnica jest natychmiastowa i łatwa do zrozumienia, dlatego to dobre pierwsze ćwiczenie dla czytelników.

## Użycie w czasie działania

Zwykłe kontenery w Dockerze, Podmanie, containerd i CRI-O otrzymują własną przestrzeń nazw PID. Kontenery Kubernetes zazwyczaj mają oddzielne widoki PID; `shareProcessNamespace: true` celowo tworzy wspólny widok dla całego Poda.<sup>[[4]](#references)</sup> Natomiast `hostPID: true` wybiera przestrzeń nazw PID węzła. Środowiska LXC/Incus korzystają z tego samego mechanizmu jądra, choć przypadki użycia kontenerów systemowych mogą ujawniać bardziej złożone drzewa procesów i skłaniać do stosowania dodatkowych skrótów na potrzeby debugowania.

Ta sama zasada obowiązuje wszędzie: jeśli runtime zdecydował się nie izolować przestrzeni nazw PID, oznacza to celowe osłabienie granicy kontenera.

## Błędne konfiguracje

Typowym błędem konfiguracji jest współdzielenie PID hosta. Zespoły często uzasadniają je wygodą debugowania, monitorowania lub zarządzania usługami, ale zawsze należy traktować je jako istotny wyjątek od zasad bezpieczeństwa. Nawet jeśli kontener nie ma bezpośredniej możliwości zapisu do procesów hosta, sama ich widoczność może ujawnić wiele informacji o systemie. Dodanie możliwości takich jak `CAP_SYS_PTRACE` lub użytecznego dostępu do procfs znacznie zwiększa ryzyko.

Kolejnym błędem jest założenie, że skoro obciążenie domyślnie nie może zabijać procesów hosta ani używać wobec nich ptrace, to współdzielenie PID hosta jest nieszkodliwe. Taki wniosek pomija wartość enumeracji, dostępność celów do wejścia do przestrzeni nazw oraz sposób, w jaki widoczność PID łączy się z innymi osłabionymi zabezpieczeniami.

### Współdzielenie procesów w całym Podzie Kubernetes

`shareProcessNamespace: true` różni się od `hostPID`: udostępnia procesy **innych kontenerów w tym samym Podzie**, a nie procesy węzła. Przejęty sidecar lub kontener debugujący może wtedy enumerować wiersze poleceń i dane środowiskowe kontenerów siostrzanych, z zastrzeżeniem kontroli dostępu procfs, wysyłać sygnały, jeśli pozwalają na to poświadczenia, oraz przeglądać system plików kontenera siostrzanego przez `/proc/<pid>/root`. Kubernetes wyraźnie ostrzega, że w takiej sytuacji wiersze poleceń, sekrety ze zmiennych środowiskowych i systemy plików kontenerów są chronione wyłącznie przez obowiązujące uprawnienia Unix.<sup>[[4]](#references)</sup>

Przydatna kontrola po stronie klastra:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

Z przejętego kontenera w przestrzeni nazw PID obejmującej cały Pod najpierw sprawdź faktyczny dostęp, zamiast zakładać, że widoczność oznacza możliwość odczytu:<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

### Ukierunkowane kontenery ephemeral w istniejącym Kubernetes Pod

Tożsamość Kubernetes z uprawnieniami do modyfikowania `pods/ephemeralcontainers` może dodać debugger do działającego Pod, nawet gdy `shareProcessNamespace` nie jest ustawione. Za pomocą `--target` debugger dołącza do namespace procesów wskazanego kontenera, jeśli runtime obsługuje wybór namespace. Zapewnia to wgląd w procesy tego kontenera, a nie w hostowy namespace PID węzła.<sup>[[5]](#references)</sup>

API korzysta z osobnego subresource, więc sprawdź uprawnienia `patch`/`update`, zamiast zakładać, że obejmują je zwykłe uprawnienia do zapisu Pod.<sup>[[6]](#references)</sup>

W przypadku Pod i kontenera w autoryzowanym namespace przetestuj widok ukierunkowany:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
ns=default; pod=myapp; container=app
kubectl auth can-i get pods -n "$ns"
kubectl auth can-i patch pods/ephemeralcontainers -n "$ns"
kubectl auth can-i update pods/ephemeralcontainers -n "$ns"
kubectl auth can-i create pods/attach -n "$ns"
kubectl -n "$ns" debug -it "pod/$pod" --image=busybox:1.36 --target="$container" -- sh
# In the debug shell: verify the target processes are actually visible.
ps -ef
```

Jeśli runtime nie implementuje targetowania, debugger może nie uruchomić się lub pozostać w odizolowanej przestrzeni nazw PID.<sup>[[5]](#references)</sup> Jeśli targetowanie działa, użyj kontroli opisanych w sekcji [Współdzielenie procesów w całym Podzie Kubernetes](#kubernetes-pod-wide-process-sharing), aby przetestować dostęp do `/proc/<pid>`. Widoczność nie oznacza uprawnień do odczytu sekretów celu ani wysyłania do niego sygnałów: nadal obowiązują poświadczenia Unix i kontrole dostępu procfs.<sup>[[4]](#references)[[8]](#references)</sup> Pod Security Standards ograniczają również ustawienia uprzywilejowane w kontenerach efemerycznych.<sup>[[7]](#references)</sup>

## Nadużycia

Jeśli współdzielona jest przestrzeń nazw PID hosta, atakujący może sprawdzać procesy hosta, zbierać argumenty procesów, identyfikować interesujące usługi, wyszukiwać potencjalne PID-y do użycia z `nsenter` albo łączyć widoczność procesów z uprawnieniami powiązanymi z ptrace, aby ingerować w obciążenia hosta lub sąsiednie. W niektórych przypadkach samo dostrzeżenie właściwego, długotrwale działającego procesu wystarczy, by zmienić dalszy plan ataku.

Pierwszym praktycznym krokiem jest zawsze potwierdzenie, że procesy hosta są rzeczywiście widoczne:

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

Gdy widoczne są PID-y hosta, argumenty procesów i cele dołączania do namespace’ów często stają się najbardziej przydatnym źródłem informacji:

```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
  echo "PID=$p"
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```

Jeśli dostępne jest `nsenter` i masz wystarczające uprawnienia, sprawdź, czy widoczny proces hosta może posłużyć jako most między przestrzeniami nazw:

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

Nawet gdy wejście jest zablokowane, widoczność PID-ów hosta jest już cenna, ponieważ ujawnia układ usług, komponenty środowiska uruchomieniowego oraz potencjalne uprzywilejowane procesy, które można zaatakować w następnej kolejności. Sama widoczność PID-ów **nie** daje uprawnień do wysyłania sygnałów, śledzenia procesów, odczytu wrażliwych wpisów `/proc/<pid>` ani dołączenia do innych przestrzeni nazw celu; nadal mają znaczenie poświadczenia, dumpability, możliwości w przestrzeni nazw użytkownika, do której należy przestrzeń nazw celu, polityka Yama/LSM oraz seccomp.<sup>[[3]](#references)</sup> Przykłady wstrzykiwania procesów znajdziesz w sekcji [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace).

Widoczność PID-ów hosta sprawia również, że nadużywanie deskryptorów plików staje się bardziej realne. Jeśli uprzywilejowany proces hosta lub sąsiedni workload ma otwarty wrażliwy plik lub socket, atakujący może być w stanie sprawdzić `/proc/<pid>/fd/` i uzyskać dostęp do bazowego obiektu — zależnie od kontroli podobnych do ptrace, właściciela, opcji montowania procfs, typu obiektu oraz modelu usługi docelowej. Samo zobaczenie dowiązania symbolicznego FD nie oznacza, że można je otworzyć, a socketu nie da się zduplikować przez samo otwarcie dowiązania `/proc/<pid>/fd/N`. Informacje o odrębnym mechanizmie `pidfd_getfd()` i jego kontrolach autoryzacji znajdziesz w sekcji [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

Te polecenia są przydatne, ponieważ pozwalają sprawdzić, czy `hidepid=1` lub `hidepid=2` ogranicza widoczność między procesami oraz czy widoczne są w ogóle oczywiście interesujące deskryptory, takie jak otwarte pliki z sekretami, logi lub Unix sockets.

### Pełny przykład: host PID + `nsenter`

Współdzielenie host PID może umożliwić host escape, gdy proces ma wymagane capabilities, aby dołączyć do namespaces hosta i przejąć root procesu hosta. Do tego ostatniego potrzebne jest `nsenter --root` (`-r`): sama zmiana mount namespace nie zmienia katalogu root wywołującego.<sup>[[9]](#references)</sup> Dostęp do `/proc/1/root` podlega kontroli odczytu ptrace, natomiast zmiana root wymaga `CAP_SYS_CHROOT` w user namespace wywołującego.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
ps -ef | head -n 50
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh
```

Jeśli polecenie się powiedzie, nowa powłoka korzysta z przestrzeni nazw mount, UTS, network, IPC i PID hosta oraz z głównego systemu plików PID 1. Sprawdź efektywną tożsamość i uprawnienia dostępu, zamiast zakładać, że sama widoczność PID zapewnia uprawnienia hosta.<sup>[[9]](#references)</sup>

Nawet jeśli brakuje samego `nsenter`, ten sam rezultat można czasem osiągnąć za pomocą pliku binarnego hosta, jeśli zamontowany jest system plików hosta:

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh 2>/dev/null
```

### Uwagi dotyczące najnowszych wersji runtime

Niektóre ataki związane z PID namespace nie wynikają z tradycyjnych błędnych konfiguracji `hostPID: true`, lecz z błędów implementacji runtime dotyczących stosowania zabezpieczeń procfs podczas konfiguracji kontenera.

#### Wyścig `maskedPaths` prowadzący do hostowego procfs

W podatnych wersjach `runc` atakujący, którzy mogli kontrolować obraz kontenera lub workload uruchamiany przez `runc exec`, mogli wywołać wyścig podczas etapu maskowania, zastępując kontenerowy `/dev/null` symlinkiem do wrażliwej ścieżki procfs, takiej jak `/proc/sys/kernel/core_pattern`. Jeśli wyścig się powiódł, bind mount maskowanej ścieżki mógł trafić w niewłaściwy cel i ujawnić nowemu kontenerowi globalne dla hosta parametry procfs.<sup>[[1]](#references)</sup>

Przydatne polecenie do przeglądu:

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

Jest to istotne, ponieważ ostateczny skutek może być taki sam jak przy bezpośrednim ujawnieniu procfs: zapisywalne `core_pattern` lub `sysrq-trigger`, a następnie wykonanie kodu na hoście lub odmowa usługi. Dedykowane strony [masked paths](../masked-paths.md) i [sensitive host mounts](../../sensitive-host-mounts.md) omawiają ogólną powierzchnię ataku procfs, nie powielając jej tutaj.

#### Wstrzykiwanie do namespace za pomocą `insject`

Narzędzia do wstrzykiwania do namespace, takie jak `insject`, pokazują, że interakcja z PID namespace nie zawsze wymaga wcześniejszego wejścia do docelowego namespace przed utworzeniem procesu. Pomocniczy proces może dołączyć później, użyć `setns()` i wykonać kod, zachowując widoczność docelowej przestrzeni PID:<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

Ten rodzaj techniki ma znaczenie głównie w zaawansowanym debugowaniu, offensive tooling i workflow post-exploitation, w których kontekst namespace trzeba dołączyć dopiero po zainicjowaniu workloadu przez runtime.

### Powiązane wzorce nadużywania FD

Warto wyraźnie wskazać dwa wzorce, gdy widoczne są hostowe PID-y. Po pierwsze, uprzywilejowany proces może zachować otwarty wrażliwy file descriptor po `execve()`, jeśli nie oznaczono go flagą `O_CLOEXEC`. Po drugie, usługi mogą przekazywać file descriptory przez Unix sockety za pomocą `SCM_RIGHTS`. W obu przypadkach interesującym obiektem nie jest już ścieżka, lecz otwarty uchwyt, który proces o niższych uprawnieniach może odziedziczyć lub otrzymać.

Ma to znaczenie w pracy z kontenerami, ponieważ uchwyt może wskazywać na `docker.sock`, uprzywilejowany log, plik z sekretem hosta lub inny obiekt o wysokiej wartości, nawet jeśli sama ścieżka nie jest bezpośrednio dostępna z systemu plików kontenera.

## Sprawdzenia

Celem tych poleceń jest ustalenie, czy proces ma prywatny widok PID, czy też może już wyliczać znacznie szerszy zestaw procesów.

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

Co jest tutaj interesujące:<sup>[[3]](#references)</sup>

- Jeśli lista procesów zawiera oczywiste usługi hosta, współdzielenie PID hosta jest prawdopodobnie już aktywne.
- Widok jedynie niewielkiego drzewa procesów lokalnego kontenera to normalny punkt odniesienia; obecność `systemd`, `dockerd` lub niezwiązanych demonów — nie.
- `NSpid` może ujawnić mapowanie PID-ów między zagnieżdżonymi przestrzeniami nazw. Wartość skrajnie lewa odnosi się do przestrzeni nazw PID powiązanej z montowaniem procfs, a kolejne wartości — do coraz głębiej zagnieżdżonych przestrzeni nazw.
- Samo `readlink /proc/self/ns/pid` nie dowodzi, że używane jest `hostPID`: odizolowany kontener również ma prawidłowy inode przestrzeni nazw PID. Porównaj go z listą procesów, montowaniem procfs, konfiguracją runtime’u oraz inode przestrzeni nazw po stronie hosta, jeśli jest dostępny.
- Gdy widoczne są PID-y hosta, nawet informacje o procesach dostępne tylko do odczytu są przydatne do rozpoznania.

Jeśli odkryjesz, że kontener działa z włączonym współdzieleniem PID hosta, nie traktuj tego jako kosmetycznej różnicy. To istotna zmiana w zakresie tego, co obciążenie może obserwować i potencjalnie na co wpływać.





## References

- [1] [Komunikat bezpieczeństwa runc: ucieczka z kontenera przez nadużycie „masked path” spowodowane wyścigiem warunków podczas montowania (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Wydanie narzędzia — insject: wstrzykiwacz do Linux Namespace](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Podręcznik Linux man-pages 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Współdzielenie przestrzeni nazw procesów między kontenerami w podzie](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
- [5] [Debugowanie działających podów](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [6] [KEP dotyczący kontenerów efemerycznych](https://www.kubernetes.dev/resources/keps/277/)
- [7] [Standardy bezpieczeństwa podów](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [8] [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [9] [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [10] [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
