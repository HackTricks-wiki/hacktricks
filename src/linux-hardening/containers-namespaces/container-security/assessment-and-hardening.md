# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Dobra ocena kontenera powinna odpowiadać na dwa równoległe pytania. Po pierwsze, co atakujący może zrobić z poziomu bieżącego workloadu? Po drugie, które decyzje operatora to umożliwiły? Narzędzia enumeracyjne pomagają odpowiedzieć na pierwsze pytanie, a wskazówki dotyczące hardeningu — na drugie. Umieszczenie obu elementów na jednej stronie sprawia, że sekcja jest bardziej użyteczna jako materiał referencyjny w terenie, a nie tylko katalog technik escape.

Jedną z praktycznych zmian we współczesnych środowiskach jest to, że wiele starszych opisów kontenerów po cichu zakłada **rootful runtime**, **brak izolacji user namespace** i często **cgroup v1**. Takie założenia nie są już bezpieczne. Zanim poświęcisz czas na stare primitive escape, najpierw sprawdź, czy workload działa w trybie rootless lub userns-remapped, czy host korzysta z cgroup v2 oraz czy Kubernetes albo runtime stosuje domyślne profile seccomp i AppArmor. Te szczegóły często decydują o tym, czy znany breakout nadal ma zastosowanie.

## Enumeration Tools

Wiele narzędzi nadal jest przydatnych do szybkiego scharakteryzowania środowiska kontenera:

- `linpeas` może wykrywać wiele wskaźników obecności kontenera, zamontowane sockety, zestawy capabilities, niebezpieczne filesystemy i wskazówki dotyczące breakout.
- `CDK` koncentruje się konkretnie na środowiskach kontenerowych i zawiera enumerację oraz kilka automatycznych testów escape.
- `amicontained` jest lekkim narzędziem przydatnym do identyfikowania ograniczeń kontenera, capabilities, ekspozycji namespace'ów i prawdopodobnych klas breakout.
- `deepce` to kolejny enumerator skoncentrowany na kontenerach, zawierający testy ukierunkowane na breakout.
- `grype` jest przydatny, gdy ocena obejmuje analizę podatności pakietów w image'ach, a nie tylko analizę runtime escape.
- `Tracee` jest przydatny, gdy potrzebujesz **dowodów runtime**, a nie tylko statycznego obrazu posture, szczególnie w przypadku podejrzanego uruchamiania procesów, dostępu do plików i zbierania zdarzeń z uwzględnieniem kontenerów.
- `Inspektor Gadget` jest przydatny podczas dochodzeń dotyczących Kubernetes i hostów Linux, gdy potrzebujesz widoczności opartej na eBPF, powiązanej z podami, kontenerami, namespace'ami i innymi pojęciami wyższego poziomu.

Wartość tych narzędzi polega na szybkości i szerokim zakresie działania, a nie na pewności. Pomagają szybko ujawnić ogólny poziom posture, ale interesujące wyniki nadal wymagają ręcznej interpretacji w odniesieniu do rzeczywistego runtime, namespace, modelu capabilities i modelu mountów.

## Hardening Priorities

Najważniejsze zasady hardeningu są koncepcyjnie proste, mimo że ich implementacja różni się w zależności od platformy. Unikaj uprzywilejowanych kontenerów. Unikaj montowania socketów runtime. Nie udostępniaj kontenerom zapisywalnych ścieżek hosta, chyba że istnieje ku temu konkretny powód. Korzystaj z user namespace'ów lub rootless execution, jeśli jest to wykonalne. Usuń wszystkie capabilities i dodawaj wyłącznie te, których workload rzeczywiście potrzebuje. Utrzymuj włączone seccomp, AppArmor i SELinux, zamiast je wyłączać w celu rozwiązania problemów ze zgodnością aplikacji. Ograniczaj zasoby, aby przejęty kontener nie mógł łatwo doprowadzić do odmowy usługi na hoście.

Higiena image'ów i procesu build ma równie duże znaczenie jak posture runtime. Używaj minimalnych image'ów, często je przebudowuj, skanuj je, wymagaj provenance tam, gdzie jest to praktyczne, i nie umieszczaj sekretów w layerach. Kontener uruchamiany jako non-root, z małym image'em oraz wąskim zakresem syscalli i capabilities, jest znacznie łatwiejszy do zabezpieczenia niż duży, wygodny image uruchamiany jako root równoważny uprawnieniami hosta, z preinstalowanymi narzędziami debugującymi.

W przypadku Kubernetes obecne baseline'y hardeningu są bardziej jednoznaczne, niż wciąż zakłada wielu operatorów. Wbudowane **Pod Security Standards** uznają `restricted` za profil będący "current best practice": `allowPrivilegeEscalation` powinno mieć wartość `false`, workloady powinny działać jako non-root, seccomp powinien być jawnie ustawiony na `RuntimeDefault` lub `Localhost`, a zestawy capabilities powinny być agresywnie redukowane. Podczas oceny ma to znaczenie, ponieważ klaster korzystający wyłącznie z labeli `warn` lub `audit` może wyglądać na hardened na papierze, jednocześnie nadal dopuszczając w praktyce ryzykowne pody.

## Modern Triage Questions

Przed przejściem do stron dotyczących konkretnych escape odpowiedz na następujące krótkie pytania:

1. Czy workload działa jako **rootful**, **rootless** czy **userns-remapped**?
2. Czy node korzysta z **cgroup v1** czy **cgroup v2**?
3. Czy **seccomp** i **AppArmor/SELinux** są jawnie skonfigurowane, czy tylko dziedziczone, gdy są dostępne?
4. W Kubernetes czy namespace faktycznie **enforcing** `baseline` lub `restricted`, czy tylko ostrzega/rejestruje zdarzenia?

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

- Jeśli `/proc/self/uid_map` pokazuje, że container root jest mapowany na **wysoki zakres host UID**, wiele starszych writeupów dotyczących host root staje się mniej istotnych, ponieważ root w containerze nie jest już odpowiednikiem host root.
- Jeśli `/sys/fs/cgroup` to `cgroup2fs`, stare writeupy specyficzne dla **cgroup v1**, takie jak `release_agent` abuse, nie powinny być już Twoim pierwszym podejrzeniem.
- Jeśli seccomp i AppArmor są tylko dziedziczone w sposób niejawny, przenośność może być słabsza, niż oczekują tego obrońcy. W Kubernetes jawne ustawienie `RuntimeDefault` jest często silniejsze niż ciche poleganie na domyślnych ustawieniach noda.
- Jeśli `supplementalGroupsPolicy` jest ustawione na `Strict`, pod powinien unikać cichego dziedziczenia dodatkowych członkostw grup z `/etc/group` wewnątrz image, dzięki czemu zachowanie dostępu grupowego do volume i plików jest bardziej przewidywalne.
- Warto bezpośrednio sprawdzać labels namespace, takie jak `pod-security.kubernetes.io/enforce=restricted`. `warn` i `audit` są przydatne, ale nie uniemożliwiają utworzenia ryzykownego poda.

## Wstępna analiza Runtime Baseline

Runtime baseline to szybkie sprawdzenie, które informuje, czy container wygląda jak zwykły odizolowany workload, czy jak foothold w control plane mający wpływ na hosta. Należy zebrać wystarczająco dużo informacji, aby ustalić priorytet kolejnej sekcji do sprawdzenia: runtime socket abuse, mounty hosta, namespace’y, cgroups, capabilities lub analiza image-secret.

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

- Brak lub nieograniczone wartości `memory.max` / `pids.max` wskazują na słabą kontrolę blast radius, nawet bez uzyskania bezpośredniego escape.
- root shell z `NoNewPrivs: 0`, szerokim zakresem capabilities i permissive seccomp jest znacznie ciekawszy niż wąskie workload uruchomione jako non-root.
- Runtime sockets i zapisywalne host mounts zwykle mają wyższy priorytet niż kernel exploits, ponieważ już zapewniają ścieżkę kontroli zarządzania lub systemu plików.
- Współdzielone przestrzenie nazw PID, network, IPC lub cgroup nie zawsze same w sobie prowadzą do pełnego escape, ale ułatwiają znalezienie kolejnego kroku.

## Przykłady wyczerpania zasobów

Kontrola zasobów nie jest efektowna, ale stanowi część container security, ponieważ ogranicza blast radius kompromitacji. Bez limitów pamięci, CPU lub PID prosty shell może wystarczyć do pogorszenia działania hosta lub sąsiednich workloadów.

Przykładowe testy wpływające na hosta:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Te przykłady są przydatne, ponieważ pokazują, że nie każdy niebezpieczny rezultat działania kontenera jest pełnym „escape”. Słabe limity cgroup nadal mogą przekształcić code execution w rzeczywisty wpływ operacyjny.

W środowiskach opartych na Kubernetes sprawdź również, czy w ogóle istnieją mechanizmy kontroli zasobów, zanim uznasz DoS za czysto teoretyczne zagrożenie:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Narzędzia hardeningu

W środowiskach skoncentrowanych na Dockerze `docker-bench-security` pozostaje przydatną bazą do audytu po stronie hosta, ponieważ sprawdza typowe problemy z konfiguracją w odniesieniu do powszechnie uznanych wytycznych benchmarków:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Narzędzie nie zastępuje modelowania zagrożeń, ale nadal jest przydatne do wykrywania niedbałych domyślnych ustawień daemonów, mountów, sieci i runtime, które z czasem się kumulują.

W środowiskach Kubernetes i runtime-heavy połącz statyczne kontrole z widocznością runtime:

- `Tracee` jest przydatne do wykrywania zdarzeń w runtime z uwzględnieniem kontenerów oraz do szybkiej analizy kryminalistycznej, gdy trzeba potwierdzić, do czego faktycznie uzyskał dostęp przejęty workload.
- `Inspektor Gadget` jest przydatne, gdy assessment wymaga telemetryki na poziomie kernela powiązanej z podami, kontenerami, aktywnością DNS, wykonywaniem plików lub zachowaniem sieci.

## Kontrole

Użyj ich jako szybkich poleceń do wstępnej oceny:
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

- Proces root z szerokimi capabilities i `Seccomp: 0` zasługuje na natychmiastową uwagę.
- Proces root, który ma również **mapowanie UID 1:1**, jest znacznie bardziej interesujący niż „root” we właściwie odizolowanym user namespace.
- `cgroup2fs` zwykle oznacza, że wiele starszych **cgroup v1** escape chains nie jest najlepszym punktem wyjścia, natomiast brak `memory.max` lub `pids.max` nadal wskazuje na słabe mechanizmy kontroli blast radius.
- Podejrzane mounty i runtime sockets często zapewniają szybszą drogę do uzyskania wpływu niż dowolny kernel exploit.
- Połączenie słabej konfiguracji runtime i słabych limitów zasobów zwykle wskazuje na ogólnie permisywne środowisko kontenerowe, a nie pojedynczy odizolowany błąd.

## Referencje

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
