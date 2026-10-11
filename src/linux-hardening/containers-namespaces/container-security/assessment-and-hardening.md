# Ocena i hardening

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Dobra ocena kontenera powinna odpowiadać na dwa równoległe pytania. Po pierwsze: co atakujący może zrobić z poziomu bieżącego workloadu? Po drugie: które decyzje operatora to umożliwiły? Narzędzia enumeracyjne pomagają odpowiedzieć na pierwsze pytanie, a zalecenia dotyczące hardeningu — na drugie. Umieszczenie obu tych kwestii na jednej stronie sprawia, że sekcja jest bardziej użyteczna jako podręczna pomoc w terenie, a nie tylko katalog technik ucieczki.

Warto pamiętać, że wiele starszych opisów kontenerów po cichu zakłada **rootful runtime**, **brak izolacji user namespace** i często **cgroup v1**. Te założenia nie są już bezpieczne. Zanim poświęcisz czas na stare prymitywy ucieczki, najpierw sprawdź, czy workload działa w trybie rootless lub z userns-remapped, czy host używa cgroup v2 oraz czy Kubernetes lub runtime stosuje domyślne profile seccomp i AppArmor. Te szczegóły często decydują o tym, czy znany breakout nadal jest możliwy.

## Narzędzia enumeracyjne

Wiele narzędzi nadal przydaje się do szybkiego scharakteryzowania środowiska kontenera:

- `linpeas` może wykryć wiele oznak konteneryzacji, zamontowane sockety, zestawy capabilities, niebezpieczne systemy plików i wskazówki dotyczące breakoutów.
- `CDK` koncentruje się na środowiskach kontenerowych i obejmuje enumerację oraz zautomatyzowane kontrole pod kątem niektórych metod ucieczki.
- `amicontained` jest lekkim narzędziem przydatnym do identyfikowania ograniczeń kontenera, capabilities, ekspozycji namespace’ów i prawdopodobnych klas breakoutów.
- `deepce` to kolejne narzędzie do enumeracji skoncentrowane na kontenerach, obejmujące kontrole ukierunkowane na breakouts.
- `grype` przydaje się, gdy ocena obejmuje analizę podatności pakietów w obrazie, a nie tylko analizę ucieczek z runtime.
- `Tracee` przydaje się, gdy potrzebujesz **dowodów z runtime**, a nie tylko statycznej oceny zabezpieczeń, szczególnie do wykrywania podejrzanego uruchamiania procesów, dostępu do plików i zbierania zdarzeń z uwzględnieniem kontenerów.
- `Inspektor Gadget` przydaje się w dochodzeniach dotyczących Kubernetes i hostów Linux, gdy potrzebujesz widoczności opartej na eBPF, powiązanej z podami, kontenerami, namespace’ami i innymi pojęciami wyższego poziomu.

Wartość tych narzędzi wynika z szybkości i zakresu działania, a nie z pewności. Pomagają szybko zorientować się w ogólnym stanie zabezpieczeń, ale interesujące ustalenia nadal wymagają ręcznej interpretacji w kontekście faktycznego modelu runtime, namespace’ów, capabilities i mountów.

## Priorytety hardeningu

Najważniejsze zasady hardeningu są proste w założeniu, choć ich wdrożenie zależy od platformy. Unikaj uprzywilejowanych kontenerów. Unikaj montowania socketów runtime. Nie udostępniaj kontenerom zapisywalnych ścieżek hosta, chyba że istnieje ku temu konkretny powód. Jeśli to możliwe, używaj user namespace’ów lub uruchamiaj kontenery w trybie rootless. Odbierz wszystkie capabilities i przywróć tylko te, których workload rzeczywiście potrzebuje. Nie wyłączaj seccomp, AppArmor ani SELinux, aby rozwiązać problemy ze zgodnością aplikacji. Ogranicz zasoby, aby przejęty kontener nie mógł łatwo doprowadzić do odmowy usługi na hoście.

Higiena obrazów i procesu budowania jest równie ważna jak zabezpieczenia runtime. Używaj minimalnych obrazów, często je przebudowuj i skanuj, w miarę możliwości wymagaj potwierdzenia pochodzenia oraz nie umieszczaj sekretów w warstwach. Kontener działający jako użytkownik niebędący rootem, z małym obrazem i ograniczonym zakresem wywołań systemowych oraz capabilities, jest znacznie łatwiejszy do obrony niż duży, uniwersalny obraz uruchomiony z uprawnieniami roota równoważnymi uprawnieniom hosta, z preinstalowanymi narzędziami do debugowania.

W przypadku Kubernetes aktualne standardy hardeningu są bardziej rygorystyczne, niż wciąż zakłada wielu operatorów. Wbudowane **Pod Security Standards** określają profil `restricted` jako „aktualnie najlepszą praktykę”: `allowPrivilegeEscalation` powinno mieć wartość `false`, workloady powinny działać jako użytkownik niebędący rootem, seccomp powinien być jawnie ustawiony na `RuntimeDefault` lub `Localhost`, a zestawy capabilities powinny być agresywnie ograniczane. Podczas oceny ma to znaczenie, ponieważ klaster używający jedynie etykiet `warn` lub `audit` może wyglądać na zabezpieczony na papierze, a jednocześnie w praktyce nadal dopuszczać ryzykowne pody.<sup>[[1]](#references)</sup>

Jeśli Pod ma zamontowany token service account, oceniaj jego uprawnienia **dla każdej docelowej namespace osobno**. Reguła zezwalająca na wyświetlanie Podów w jednej namespace nie potwierdza uprawnień w innej; token zamontowany w innym Podzie może mieć inne uprawnienia. Użyj poleceń `kubectl auth can-i list pods -n <target-namespace>` i `kubectl auth can-i list secrets -n <target-namespace>`, sprawdzając tożsamość będącą przedmiotem oceny. Dozwolone wyświetlanie listy Secretów to poważny trop, ponieważ odpowiedź może zawierać ich treść, ale nie dowodzi, że dostępny jest uprzywilejowany token. Dostęp do hosta wymaga ponadto użytecznego uprawnienia do tworzenia workloadów, dopuszczenia proponowanego mountu `hostPath` oraz kontekstu bezpieczeństwa node’a/poda, który pozwala wykonać planowaną operację na plikach. Zobacz dokumentację Kubernetes dotyczącą [sprawdzania autoryzacji](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) oraz [zaleceń RBAC dotyczących eskalacji uprawnień](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).

## Pytania do wstępnej oceny nowoczesnych środowisk

Zanim przejdziesz do stron poświęconych konkretnym metodom ucieczki, odpowiedz na kilka krótkich pytań:

1. Czy workload działa w trybie **rootful**, **rootless** czy **userns-remapped**?
2. Czy node używa **cgroup v1** czy **cgroup v2**?
3. Czy **seccomp** i **AppArmor/SELinux** są jawnie skonfigurowane, czy jedynie dziedziczone, jeśli są dostępne?
4. W Kubernetes: czy namespace faktycznie **wymusza** `baseline` lub `restricted`, czy tylko ostrzega/rejestruje naruszenia?

Przydatne kontrole:

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

Co jest tu interesujące:

- Jeśli `/proc/self/uid_map` pokazuje, że root w kontenerze jest mapowany na **wysoki zakres UID hosta**, wiele starszych opracowań o uzyskaniu uprawnień roota na hoście ma mniejsze zastosowanie, ponieważ root w kontenerze nie jest już odpowiednikiem roota na hoście.
- Jeśli `/sys/fs/cgroup` ma typ `cgroup2fs`, starsze opracowania dotyczące **cgroup v1**, takie jak nadużycie `release_agent`, nie powinny być już pierwszym tropem.
- Jeśli seccomp i AppArmor są tylko dziedziczone niejawnie, przenośność może być słabsza, niż oczekują obrońcy. W Kubernetes jawne ustawienie `RuntimeDefault` jest często lepsze niż ciche poleganie na domyślnych ustawieniach węzła.
- Jeśli `supplementalGroupsPolicy` ma wartość `Strict`, pod nie powinien po cichu dziedziczyć dodatkowych członkostw w grupach z `/etc/group` wewnątrz obrazu, co sprawia, że zachowanie dostępu do woluminów i plików opartego na grupach jest bardziej przewidywalne.
- Warto bezpośrednio sprawdzać etykiety przestrzeni nazw, takie jak `pod-security.kubernetes.io/enforce=restricted`. `warn` i `audit` są przydatne, ale nie zapobiegają utworzeniu ryzykownego poda.

## Wstępna ocena bazowej konfiguracji środowiska uruchomieniowego

Wstępna ocena bazowej konfiguracji środowiska uruchomieniowego to szybkie sprawdzenie, które pozwala ustalić, czy kontener wygląda na zwykłe, odizolowane obciążenie, czy raczej na punkt zaczepienia w płaszczyźnie sterowania mający wpływ na hosta. Powinna zebrać wystarczająco dużo informacji, by ustalić, który temat sprawdzić dalej: nadużycie socketu środowiska uruchomieniowego, montowania hosta, przestrzenie nazw, cgroups, capabilities czy przegląd sekretów obrazu.

Przydatne kontrole wykonywane z poziomu obciążenia:

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

- Brak limitu lub nielimitowana wartość `memory.max` / `pids.max` wskazuje na słabą kontrolę zasięgu skutków, nawet bez pełnego escape.
- Root shell z `NoNewPrivs: 0`, szerokim zakresem capabilities i permisywnym seccomp jest znacznie bardziej interesujący niż ograniczony workload działający jako użytkownik nieuprzywilejowany.
- Runtime sockets i zapisywalne mounty hosta zwykle mają wyższy priorytet niż exploity jądra, ponieważ zapewniają już ścieżkę dostępu do mechanizmów zarządzania lub systemu plików.
- Współdzielone przestrzenie nazw PID, sieci, IPC lub cgroup same w sobie nie zawsze oznaczają pełny escape, ale ułatwiają znalezienie kolejnego kroku.

## Przykłady wyczerpania zasobów

Limity zasobów nie są efektowne, ale stanowią część bezpieczeństwa kontenerów, ponieważ ograniczają zasięg skutków włamania. Bez limitów pamięci, CPU lub PID zwykły shell może wystarczyć, by pogorszyć działanie hosta lub sąsiednich workloadów.

Przykładowe testy wpływające na hosta:

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

Te przykłady są przydatne, ponieważ pokazują, że nie każdy niebezpieczny skutek działania kontenera oznacza czysty „escape”. Słabe limity cgroup mogą sprawić, że wykonanie kodu przełoży się na rzeczywisty wpływ operacyjny.

W środowiskach opartych na Kubernetes sprawdź też, czy w ogóle istnieją mechanizmy kontroli zasobów, zanim uznasz DoS za czysto teoretyczne zagrożenie:

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## Narzędzia do hardeningu

W środowiskach opartych na Dockerze `docker-bench-security` nadal stanowi przydatny punkt odniesienia do audytu po stronie hosta, ponieważ sprawdza typowe problemy z konfiguracją w odniesieniu do powszechnie uznawanych wytycznych benchmarkowych. Zalecenia dotyczące runtime’u należy weryfikować osobno, ponieważ benchmark konfiguracji nie pozwala ustalić, czy zainstalowany runtime jest podatny na nowo ujawnioną lukę. <sup>[[2]](#references)</sup>

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

Narzędzie nie zastępuje modelowania zagrożeń, ale nadal jest przydatne do wykrywania nieostrożnych ustawień domyślnych daemonów, mountów, sieci i runtime, które z czasem się kumulują.

W środowiskach Kubernetes i środowiskach intensywnie wykorzystujących runtime połącz kontrole statyczne z widocznością w runtime:

- `Tracee` przydaje się do wykrywania zagrożeń w runtime z uwzględnieniem kontenerów oraz do szybkiej analizy kryminalistycznej, gdy trzeba potwierdzić, do czego faktycznie uzyskał dostęp skompromitowany workload.
- `Inspektor Gadget` przydaje się, gdy ocena wymaga telemetrii na poziomie jądra powiązanej z podami, kontenerami, aktywnością DNS, wykonywaniem plików lub zachowaniem sieci.

## Kontrole

Użyj tych poleceń jako szybkich kontroli wstępnych podczas oceny:

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

- Proces root z szerokim zakresem capabilities i `Seccomp: 0` wymaga natychmiastowej uwagi.
- Proces root, który ma również **mapowanie UID 1:1**, jest znacznie bardziej interesujący niż „root” wewnątrz prawidłowo odizolowanej user namespace.
- `cgroup2fs` zwykle oznacza, że wiele starszych ścieżek ucieczki z **cgroup v1** nie jest najlepszym punktem wyjścia, natomiast brak `memory.max` lub `pids.max` wskazuje na słabą kontrolę zasięgu skutków awarii.
- Podejrzane mounty i sockety runtime często zapewniają szybszą drogę do uzyskania dostępu niż jakikolwiek kernel exploit.
- Połączenie słabych zabezpieczeń runtime ze słabymi limitami zasobów zwykle wskazuje na ogólnie zbyt liberalnie skonfigurowane środowisko kontenerowe, a nie pojedynczy odosobniony błąd.

## References

- [1] [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
