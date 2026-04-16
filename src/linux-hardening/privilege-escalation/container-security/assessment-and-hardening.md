# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Dobra ocena kontenera powinna odpowiadać na dwa równoległe pytania. Po pierwsze, co może zrobić atakujący z bieżącego workload? Po drugie, które wybory operatora to umożliwiły? Narzędzia do enumeracji pomagają w pierwszym pytaniu, a wskazówki dotyczące hardening pomagają w drugim. Trzymanie obu rzeczy na jednej stronie sprawia, że sekcja jest bardziej użyteczna jako referencja terenowa, a nie tylko katalog tricków escape.

Jedna praktyczna aktualizacja dla nowoczesnych środowisk jest taka, że wiele starszych opisów kontenerów po cichu zakłada **rootful runtime**, **brak izolacji user namespace** i często **cgroup v1**. Te założenia nie są już bezpieczne. Zanim poświęcisz czas na stare primitive escape, najpierw potwierdź, czy workload działa rootless lub z userns-remapping, czy host używa cgroup v2 oraz czy Kubernetes lub runtime stosuje teraz domyślne profile seccomp i AppArmor. Te szczegóły często decydują o tym, czy słynny breakout nadal ma zastosowanie.

## Narzędzia do enumeracji

Wiele narzędzi pozostaje przydatnych do szybkiego scharakteryzowania środowiska kontenera:

- `linpeas` może wykryć wiele wskaźników kontenera, zamontowane sockets, zestawy capabilities, niebezpieczne filesystems i wskazówki dotyczące breakout.
- `CDK` koncentruje się konkretnie na środowiskach kontenerowych i obejmuje enumerację oraz pewne automatyczne sprawdzenia escape.
- `amicontained` jest lekkie i przydatne do identyfikowania ograniczeń kontenera, capabilities, ekspozycji namespace oraz prawdopodobnych klas breakout.
- `deepce` to kolejny enumerator skoncentrowany na kontenerach z testami ukierunkowanymi na breakout.
- `grype` jest przydatny, gdy ocena obejmuje przegląd podatności image-package zamiast tylko analizy escape w runtime.
- `Tracee` jest przydatny, gdy potrzebujesz **dowodów z runtime** zamiast wyłącznie statycznego obrazu, szczególnie dla podejrzanego wykonywania procesów, dostępu do plików i zbierania zdarzeń świadomych kontenerów.
- `Inspektor Gadget` jest przydatny w Kubernetes i podczas analizy hostów Linux, gdy potrzebujesz widoczności opartej na eBPF powiązanej z podami, kontenerami, namespace i innymi pojęciami wyższego poziomu.

Wartość tych narzędzi to szybkość i pokrycie, a nie pewność. Pomagają szybko ujawnić ogólny stan, ale interesujące wyniki nadal wymagają ręcznej interpretacji względem rzeczywistego modelu runtime, namespace, capabilities i mount.

## Priorytety hardening

Najważniejsze zasady hardening są koncepcyjnie proste, choć ich implementacja różni się zależnie od platformy. Unikaj privileged containers. Unikaj montowanych runtime sockets. Nie dawaj kontenerom zapisywalnych host paths, chyba że istnieje bardzo konkretny powód. Używaj user namespaces lub rootless execution tam, gdzie to możliwe. Odrzucaj wszystkie capabilities i dodawaj z powrotem tylko te, których naprawdę potrzebuje workload. Utrzymuj włączone seccomp, AppArmor i SELinux zamiast wyłączać je w celu rozwiązania problemów ze zgodnością aplikacji. Ograniczaj zasoby tak, aby przejęty kontener nie mógł trywialnie odmówić usługi hostowi.

Higiena image i build ma znaczenie tak samo jak postura runtime. Używaj minimalnych image, przebudowuj je często, skanuj je, wymagaj provenance tam, gdzie to praktyczne, i trzymaj secrets poza layers. Kontener uruchamiany jako non-root z małym image i wąską powierzchnią syscall i capabilities jest znacznie łatwiejszy do obrony niż duży convenience image uruchamiany jako root równoważny hostowi z preinstalowanymi narzędziami debug.

W przypadku Kubernetes obecne baselines hardening są bardziej opiniotwórcze, niż wielu operatorów nadal zakłada. Wbudowane **Pod Security Standards** traktują `restricted` jako profil „current best practice”: `allowPrivilegeEscalation` powinno być `false`, workload powinny działać jako non-root, seccomp powinno być jawnie ustawione na `RuntimeDefault` lub `Localhost`, a zestawy capabilities powinny być agresywnie usuwane. Podczas oceny ma to znaczenie, ponieważ klaster używający tylko etykiet `warn` lub `audit` może wyglądać na utwardzony na papierze, a mimo to w praktyce nadal dopuszczać ryzykowne pody.

## Pytania do modern triage

Zanim przejdziesz do stron dotyczących konkretnych escape, odpowiedz na te szybkie pytania:

1. Czy workload jest **rootful**, **rootless** czy **userns-remapped**?
2. Czy node używa **cgroup v1** czy **cgroup v2**?
3. Czy **seccomp** i **AppArmor/SELinux** są jawnie skonfigurowane, czy tylko dziedziczone, gdy są dostępne?
4. W Kubernetes, czy namespace faktycznie **enforcing** `baseline` lub `restricted`, czy tylko warning/auditing?

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

- Jeśli `/proc/self/uid_map` pokazuje, że root kontenera jest mapowany na **wysoki zakres host UID**, wiele starszych writeupów dotyczących host-root staje się mniej istotnych, ponieważ root w kontenerze nie jest już równoważny host-root.
- Jeśli `/sys/fs/cgroup` to `cgroup2fs`, stare writeupy specyficzne dla **cgroup v1**, takie jak nadużycie `release_agent`, nie powinny już być Twoim pierwszym strzałem.
- Jeśli seccomp i AppArmor są dziedziczone tylko pośrednio, przenośność może być słabsza, niż zakładają defenderzy. W Kubernetes, jawne ustawienie `RuntimeDefault` jest często silniejsze niż ciche poleganie na domyślnych ustawieniach noda.
- Jeśli `supplementalGroupsPolicy` jest ustawione na `Strict`, pod powinien unikać cichego dziedziczenia dodatkowych członkostw grup z `/etc/group` wewnątrz obrazu, co sprawia, że zachowanie dostępu do wolumenów i plików oparte na grupach jest bardziej przewidywalne.
- Warto bezpośrednio sprawdzać etykiety namespace, takie jak `pod-security.kubernetes.io/enforce=restricted`. `warn` i `audit` są użyteczne, ale nie zatrzymują utworzenia ryzykownego poda.

## Resource-Exhaustion Examples

Kontrole zasobów nie są efektowne, ale są częścią bezpieczeństwa kontenerów, ponieważ ograniczają promień rażenia kompromitacji. Bez limitów pamięci, CPU lub PID, zwykły shell może wystarczyć, aby zdegradować hosta lub sąsiednie workloady.

Przykładowe testy wpływające na host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Te przykłady są przydatne, ponieważ pokazują, że nie każdy niebezpieczny wynik działania kontenera jest czystym „escape”. Słabe limity cgroup nadal mogą zamienić code execution w realny wpływ operacyjny.

W środowiskach opartych na Kubernetesie sprawdź też, czy w ogóle istnieją jakiekolwiek kontrole zasobów, zanim uznasz DoS za czysto teoretyczny:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Tooling

Dla środowisk skoncentrowanych na Docker, `docker-bench-security` pozostaje przydatną bazą audytu po stronie hosta, ponieważ sprawdza typowe problemy konfiguracyjne względem powszechnie uznanych wytycznych benchmarku:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Narzędzie nie jest substytutem threat modeling, ale nadal jest cenne do znajdowania nieostrożnych domyślnych ustawień daemon, mount, network i runtime, które gromadzą się z czasem.

W środowiskach Kubernetes i runtime-heavy, łącz statyczne checks z widocznością runtime:

- `Tracee` jest przydatne do container-aware runtime detection i szybkiej forensics, gdy trzeba potwierdzić, czego faktycznie dotknął przejęty workload.
- `Inspektor Gadget` jest przydatne, gdy assessment wymaga telemetry na poziomie kernela mapowanej z powrotem do pods, containers, DNS activity, file execution lub network behavior.

## Checks

Użyj tego jako szybkich poleceń pierwszego przejścia podczas assessment:
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
- Proces root, który ma również **mapowanie UID 1:1**, jest znacznie ciekawszy niż „root” we właściwie odizolowanym user namespace.
- `cgroup2fs` zwykle oznacza, że wiele starszych ścieżek escape dla **cgroup v1** nie jest najlepszym punktem wyjścia, a brak `memory.max` lub `pids.max` nadal wskazuje na słabe kontrole blast-radius.
- Podejrzane mounty i runtime sockets często dają szybszą drogę do impact niż jakikolwiek kernel exploit.
- Połączenie słabego runtime posture i słabych limitów zasobów zwykle wskazuje na ogólnie permissive środowisko kontenerowe, a nie pojedynczy izolowany błąd.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
