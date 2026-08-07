# Ocena i hardening

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Dobra ocena kontenera powinna odpowiadać na dwa równoległe pytania. Po pierwsze, co attacker może zrobić z poziomu bieżącego workloadu? Po drugie, które decyzje operatora to umożliwiły? Narzędzia enumeracyjne pomagają odpowiedzieć na pierwsze pytanie, a wskazówki dotyczące hardeningu — na drugie. Umieszczenie obu elementów na jednej stronie sprawia, że sekcja jest bardziej użyteczna jako materiał referencyjny w terenie, a nie tylko katalog technik escape.

Jedną z praktycznych zmian we współczesnych środowiskach jest to, że wiele starszych opisów kontenerów po cichu zakłada **rootful runtime**, **brak izolacji user namespace** i często **cgroup v1**. Tych założeń nie można już uznawać za bezpieczne. Zanim poświęcisz czas na stare prymitywy escape, najpierw sprawdź, czy workload działa w trybie rootless lub userns-remapped, czy host używa cgroup v2 oraz czy Kubernetes albo runtime stosuje domyślne profile seccomp i AppArmor. Te szczegóły często decydują o tym, czy znany breakout nadal ma zastosowanie.

## Narzędzia enumeracyjne

Wiele narzędzi nadal jest przydatnych do szybkiej charakterystyki środowiska kontenera:

- `linpeas` może identyfikować wiele wskaźników obecności kontenera, zamontowane sockety, zestawy capabilities, niebezpieczne filesystemy oraz wskazówki dotyczące breakout.
- `CDK` koncentruje się konkretnie na środowiskach kontenerowych i obejmuje enumerację oraz automatyczne testy escape.
- `amicontained` jest lekkim narzędziem przydatnym do identyfikowania ograniczeń kontenera, capabilities, ekspozycji namespace'ów i prawdopodobnych klas breakout.
- `deepce` to kolejny enumerator skoncentrowany na kontenerach, zawierający testy ukierunkowane na breakout.
- `grype` jest przydatny, gdy assessment obejmuje analizę podatności pakietów w image, a nie tylko analizę escape w runtime.
- `Tracee` jest przydatny, gdy potrzebujesz **dowodów z runtime**, a nie wyłącznie statycznej oceny posture, szczególnie w przypadku podejrzanego uruchamiania procesów, dostępu do plików i zbierania zdarzeń związanych z kontenerami.
- `Inspektor Gadget` jest przydatny podczas analiz Kubernetes i hostów Linux, gdy potrzebujesz widoczności opartej na eBPF, powiązanej z podami, kontenerami, namespace'ami i innymi pojęciami wyższego poziomu.

Wartość tych narzędzi polega na szybkości i szerokim pokryciu, a nie na pewności. Pomagają szybko ujawnić ogólny posture, ale interesujące ustalenia nadal wymagają ręcznej interpretacji w odniesieniu do rzeczywistego modelu runtime, namespace'ów, capabilities i mountów.

## Priorytety hardeningu

Najważniejsze zasady hardeningu są koncepcyjnie proste, choć ich implementacja różni się w zależności od platformy. Unikaj kontenerów privileged. Unikaj montowania socketów runtime. Nie udostępniaj kontenerom zapisywalnych ścieżek hosta, chyba że istnieje ku temu konkretny powód. Tam, gdzie to możliwe, używaj user namespaces lub uruchamiania rootless. Usuń wszystkie capabilities i dodaj wyłącznie te, których workload rzeczywiście potrzebuje. Pozostaw seccomp, AppArmor i SELinux włączone, zamiast je wyłączać w celu rozwiązania problemów ze zgodnością aplikacji. Ograniczaj zasoby, aby przejęty kontener nie mógł w prosty sposób doprowadzić do odmowy usługi na hoście.

Higiena image i procesu build ma równie duże znaczenie jak posture runtime. Używaj minimalnych image, często je przebudowuj, skanuj je, tam gdzie to praktyczne wymagaj provenance i nie umieszczaj sekretów w layerach. Kontener działający jako non-root, z małym image oraz wąską powierzchnią syscalli i capabilities, jest znacznie łatwiejszy do ochrony niż duży convenience image działający jako root równoważny rootowi hosta, z preinstalowanymi narzędziami debuggingowymi.

W Kubernetes aktualne baseline'y hardeningu są bardziej restrykcyjne, niż nadal zakłada wielu operatorów. Wbudowane **Pod Security Standards** uznają `restricted` za profil będący "current best practice": `allowPrivilegeEscalation` powinno mieć wartość `false`, workloady powinny działać jako non-root, seccomp powinien być jawnie ustawiony na `RuntimeDefault` lub `Localhost`, a zestawy capabilities powinny być agresywnie redukowane. Podczas assessment ma to znaczenie, ponieważ klaster używający wyłącznie etykiet `warn` lub `audit` może wyglądać na hardened na papierze, a jednocześnie w praktyce nadal dopuszczać ryzykowne pody.<sup>[[1]](#references)</sup>

## Współczesne pytania triage

Zanim przejdziesz do stron poświęconych konkretnym przypadkom escape, odpowiedz na te krótkie pytania:

1. Czy workload działa w trybie **rootful**, **rootless**, czy **userns-remapped**?
2. Czy node używa **cgroup v1**, czy **cgroup v2**?
3. Czy **seccomp** i **AppArmor/SELinux** są jawnie skonfigurowane, czy jedynie dziedziczone, gdy są dostępne?
4. W Kubernetes, czy namespace faktycznie **wymusza** `baseline` lub `restricted`, czy tylko ostrzega/rejestruje zdarzenia?

Przydatne sprawdzenia:
```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```
Co jest tutaj interesujące:

- Jeśli `/proc/self/uid_map` pokazuje, że root w kontenerze jest mapowany na **wysoki zakres UID hosta**, wiele starszych opisów uzyskiwania uprawnień root na hoście staje się mniej istotnych, ponieważ root w kontenerze nie jest już odpowiednikiem root na hoście.
- Jeśli `/sys/fs/cgroup` to `cgroup2fs`, stare opisy charakterystyczne dla **cgroup v1**, takie jak nadużywanie `release_agent`, nie powinny być już pierwszym podejrzeniem.
- Jeśli seccomp i AppArmor są tylko niejawnie dziedziczone, przenośność może być słabsza, niż oczekują tego obrońcy. W Kubernetes jawne ustawienie `RuntimeDefault` jest często bezpieczniejsze niż ciche poleganie na domyślnych ustawieniach węzła.
- Jeśli `supplementalGroupsPolicy` jest ustawione na `Strict`, pod powinien unikać cichego dziedziczenia dodatkowych członkostw grup z `/etc/group` wewnątrz obrazu, dzięki czemu zachowanie dostępu grupowego do wolumenów i plików jest bardziej przewidywalne.
- Warto bezpośrednio sprawdzać etykiety namespace, takie jak `pod-security.kubernetes.io/enforce=restricted`. `warn` i `audit` są przydatne, ale nie powstrzymują przed utworzeniem ryzykownego poda.

## Wstępna ocena bazowa środowiska uruchomieniowego

Bazowa ocena środowiska uruchomieniowego to szybkie sprawdzenie, które informuje, czy kontener wygląda jak zwykły odizolowany workload, czy jak foothold w control plane umożliwiający wpływanie na hosta. Należy zebrać wystarczającą ilość informacji, aby ustalić, którą sekcję przeczytać w następnej kolejności: nadużywanie runtime socket, mounty hosta, namespace, cgroups, capabilities czy analiza sekretów obrazu.

Przydatne sprawdzenia wykonywane wewnątrz workloadu:
```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Interpretacja:

- Brak ograniczeń lub nieograniczone wartości `memory.max` / `pids.max` wskazują na słabe mechanizmy kontroli zakresu skutków, nawet bez udanej ucieczki.
- Powłoka root z `NoNewPrivs: 0`, szerokim zakresem capabilities i permissive seccomp jest znacznie ciekawsza niż wąskie obciążenie działające jako non-root.
- Runtime sockets i zapisywalne host mounts zwykle mają wyższy priorytet niż kernel exploits, ponieważ już zapewniają ścieżkę kontroli zarządzania lub systemu plików.
- Współdzielone przestrzenie nazw PID, network, IPC lub cgroup nie zawsze same w sobie prowadzą do pełnej ucieczki, ale ułatwiają znalezienie kolejnego kroku.

## Przykłady wyczerpywania zasobów

Kontrole zasobów nie są efektowne, ale stanowią część container security, ponieważ ograniczają zakres skutków kompromitacji. Bez limitów pamięci, CPU lub PID prosta powłoka może wystarczyć do pogorszenia działania hosta lub sąsiednich obciążeń.

Przykładowe testy wpływające na hosta:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Te przykłady są przydatne, ponieważ pokazują, że nie każdy niebezpieczny rezultat działania kontenera jest całkowitym „escape”. Słabe limity cgroup nadal mogą przekształcić code execution w rzeczywisty wpływ operacyjny.

W środowiskach opartych na Kubernetes sprawdź również, czy mechanizmy kontroli zasobów w ogóle istnieją, zanim uznasz DoS za czysto teoretyczne zagrożenie:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Narzędzia hardeningu

W środowiskach skoncentrowanych na Dockerze `docker-bench-security` pozostaje użytecznym bazowym narzędziem audytowym po stronie hosta, ponieważ sprawdza typowe problemy z konfiguracją w odniesieniu do powszechnie uznanych wytycznych benchmarków:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Narzędzie nie zastępuje modelowania zagrożeń, ale nadal jest wartościowe przy wykrywaniu nieostrożnych domyślnych ustawień daemonów, montowań, sieci i środowiska wykonawczego, które z czasem się kumulują.

W przypadku Kubernetes i środowisk intensywnie korzystających ze środowiska wykonawczego połącz statyczne kontrole z widocznością środowiska wykonawczego:

- `Tracee` jest przydatne do wykrywania aktywności w środowisku wykonawczym z uwzględnieniem kontenerów oraz do szybkiej analizy kryminalistycznej, gdy trzeba potwierdzić, do czego faktycznie uzyskał dostęp zainfekowany workload.
- `Inspektor Gadget` jest przydatne, gdy ocena wymaga telemetryki na poziomie kernela, przypisanej z powrotem do podów, kontenerów, aktywności DNS, wykonywania plików lub zachowania sieciowego.

## Kontrole

Użyj ich jako szybkich poleceń wstępnej kontroli podczas oceny:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Co jest tutaj interesujące:

- Proces `root` z szerokimi capabilities i `Seccomp: 0` zasługuje na natychmiastową uwagę.
- Proces `root`, który ma również **mapowanie UID 1:1**, jest znacznie bardziej interesujący niż „root” wewnątrz prawidłowo odizolowanego user namespace.
- `cgroup2fs` zazwyczaj oznacza, że wiele starszych **łańcuchów ucieczki cgroup v1** nie jest najlepszym punktem wyjścia, podczas gdy brak `memory.max` lub `pids.max` nadal wskazuje na słabe mechanizmy ograniczania zasięgu skutków.
- Podejrzane mounty i sockety runtime często zapewniają szybszą drogę do uzyskania wpływu niż jakikolwiek exploit kernela.
- Połączenie słabej konfiguracji runtime i słabych limitów zasobów zwykle wskazuje na ogólnie liberalne środowisko kontenerów, a nie pojedynczy odizolowany błąd.

## Referencje

- [1] [Standardy bezpieczeństwa Pod Security Standards Kubernetes](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Porada bezpieczeństwa Docker: wiele podatności w runc, BuildKit i Moby](https://docs.docker.com/security/security-announcements/)

{{#include ../../../banners/hacktricks-training.md}}
