# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` to funkcja hardening jądra, która uniemożliwia procesowi uzyskanie większych uprawnień podczas `execve()`. W praktyce oznacza to, że gdy flaga jest ustawiona, uruchomienie binarki setuid, binarki setgid albo pliku z Linux file capabilities nie daje dodatkowych uprawnień poza tymi, które proces już miał. W środowiskach kontenerowych jest to ważne, ponieważ wiele łańcuchów privilege-escalation opiera się na znalezieniu wykonywalnego pliku w obrazie, który zmienia uprawnienia po uruchomieniu.

Z defensywnego punktu widzenia `no_new_privs` nie jest zamiennikiem dla namespaces, seccomp ani capability dropping. To warstwa wzmacniająca. Blokuje ona konkretną klasę późniejszej eskalacji po tym, jak kod został już wykonany. Czyni to ją szczególnie przydatną w środowiskach, gdzie obrazy zawierają pomocnicze binarki, artefakty package-managera lub narzędzia legacy, które w połączeniu z częściowym kompromisem byłyby niebezpieczne.

## Operation

Flaga jądra odpowiedzialna za to zachowanie to `PR_SET_NO_NEW_PRIVS`. Gdy zostanie ustawiona dla procesu, późniejsze wywołania `execve()` nie mogą zwiększyć uprawnień. Ważnym szczegółem jest to, że proces nadal może uruchamiać binarki; po prostu nie może użyć tych binarek do przekroczenia granicy uprawnień, którą jądro normalnie by uznało.

Zachowanie jądra jest też **dziedziczone i nieodwracalne**: gdy zadanie ustawi `no_new_privs`, bit jest dziedziczony przez `fork()`, `clone()` i `execve()`, i nie można go później wyłączyć. Jest to przydatne podczas ocen, ponieważ pojedyncze `NoNewPrivs: 1` dla procesu kontenera zwykle oznacza, że potomkowie też powinni pozostać w tym trybie, chyba że patrzysz na całkowicie inne drzewo procesów.

W środowiskach opartych na Kubernetes `allowPrivilegeEscalation: false` mapuje się na to zachowanie dla procesu kontenera. W runtime'ach w stylu Docker i Podman odpowiednik jest zwykle włączany jawnie przez opcję bezpieczeństwa. Na warstwie OCI ta sama koncepcja pojawia się jako `process.noNewPrivileges`.

## Important Nuances

`no_new_privs` blokuje wzrost uprawnień w czasie `exec`, a nie każdą zmianę uprawnień. W szczególności:

- przejścia setuid i setgid przestają działać podczas `execve()`
- file capabilities nie są dodawane do zbioru permitted podczas `execve()`
- LSMs takie jak AppArmor czy SELinux nie luzują ograniczeń po `execve()`
- już posiadane uprawnienia nadal są już posiadanymi uprawnieniami

Ten ostatni punkt ma znaczenie operacyjne. Jeśli proces już działa jako root, już ma niebezpieczną capability albo już ma dostęp do potężnego runtime API lub zapisywalnego host mount, ustawienie `no_new_privs` nie neutralizuje tych ekspozycji. Usuwa ono tylko jeden częsty **następny krok** w łańcuchu privilege-escalation.

Zwróć też uwagę, że flaga nie blokuje zmian uprawnień, które nie zależą od `execve()`. Na przykład zadanie, które jest już wystarczająco uprzywilejowane, może nadal wywołać bezpośrednio `setuid(2)` albo otrzymać uprzywilejowany file descriptor przez gniazdo Unix. Dlatego `no_new_privs` należy czytać razem z [seccomp](seccomp.md), capability sets i ekspozycją namespace, a nie jako samodzielną odpowiedź.

## Lab

Inspect the current process state:
```bash
grep NoNewPrivs /proc/self/status
```
Porównaj to z containerem, w którym runtime włącza flagę:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Na utwardzonym workload, wynik powinien pokazać `NoNewPrivs: 1`.

Możesz także zademonstrować rzeczywisty efekt na binarium setuid:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Punkt porównania nie polega na tym, że `su` jest uniwersalnie exploitable. Chodzi o to, że ten sam image może zachowywać się bardzo różnie w zależności od tego, czy `execve()` nadal może przekroczyć granicę uprawnień.

## Security Impact

Jeśli `no_new_privs` jest nieobecne, foothold wewnątrz kontenera może nadal zostać podniesiony przez setuid helpers lub binary z file capabilities. Jeśli jest obecne, te post-exec zmiany uprawnień są odcięte. Efekt jest szczególnie istotny w szerokich base images, które dostarczają wiele utilities, których aplikacja i tak nigdy nie potrzebowała.

Istnieje też ważna interakcja z seccomp. Zadania bez uprawnień zazwyczaj muszą mieć ustawione `no_new_privs`, zanim będą mogły zainstalować seccomp filter w trybie filter mode. To jeden z powodów, dla których hardened containers często pokazują jednocześnie włączone `Seccomp` i `NoNewPrivs`. Z perspektywy atakującego, zobaczenie obu zwykle oznacza, że środowisko zostało skonfigurowane celowo, a nie przypadkowo.

## Misconfigurations

Najczęstszy problem to po prostu niewłączanie tego mechanizmu w środowiskach, gdzie byłby zgodny. W Kubernetes pozostawienie `allowPrivilegeEscalation` włączonego jest często domyślnym błędem operacyjnym. W Docker i Podman pominięcie odpowiedniej opcji security daje ten sam efekt. Innym powtarzającym się trybem błędu jest założenie, że skoro kontener nie jest "privileged", to przejścia uprawnień w czasie exec są automatycznie nieistotne.

Bardziej subtelną pułapką w Kubernetes jest to, że `allowPrivilegeEscalation: false` **nie** jest honorowane tak, jak ludzie się spodziewają, gdy kontener jest `privileged` albo gdy ma `CAP_SYS_ADMIN`. Dokumentacja API Kubernetes mówi, że `allowPrivilegeEscalation` jest w takich przypadkach w praktyce zawsze true. W praktyce oznacza to, że to pole należy traktować jako jeden z sygnałów końcowej postawy, a nie jako gwarancję, że runtime zakończył z `NoNewPrivs: 1`.

## Abuse

Jeśli `no_new_privs` nie jest ustawione, pierwsze pytanie brzmi, czy image zawiera binary, które nadal mogą podnieść privilege:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interesujące wyniki obejmują:

- `NoNewPrivs: 0`
- setuid helpers takie jak `su`, `mount`, `passwd` lub narzędzia administracyjne specyficzne dla dystrybucji
- binaries z file capabilities, które przyznają uprawnienia sieciowe lub filesystem

W rzeczywistej ocenie takie wyniki same w sobie nie dowodzą działającej eskalacji, ale wskazują dokładnie binaries, które warto przetestować jako następne.

W Kubernetes sprawdź też, czy YAML intent zgadza się z rzeczywistością kernel:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Interesujące kombinacje obejmują:

- `allowPrivilegeEscalation: false` w specyfikacji Pod, ale `NoNewPrivs: 0` w kontenerze
- obecny `cap_sys_admin`, który sprawia, że pole Kubernetes jest znacznie mniej godne zaufania
- `Seccomp: 0` i `NoNewPrivs: 0`, co zwykle wskazuje na szeroko osłabioną postawę runtime, a nie pojedynczy odizolowany błąd

### Full Example: In-Container Privilege Escalation Through setuid

To zabezpieczenie zwykle zapobiega **in-container privilege escalation** bardziej niż bezpośrednio escape z hosta. Jeśli `NoNewPrivs` ma wartość `0` i istnieje helper setuid, przetestuj go jawnie:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Jeśli obecny jest znany binarny plik setuid i działa poprawnie, spróbuj uruchomić go w sposób, który zachowa przejście uprawnień:
```bash
/bin/su -c id 2>/dev/null
```
To samo w sobie nie powoduje ucieczki z kontenera, ale może przekształcić nisko uprzywilejowany foothold wewnątrz kontenera w container-root, co często staje się warunkiem wstępnym późniejszej ucieczki na hosta przez mounty, runtime sockets lub interfejsy skierowane do jądra.

## Checks

Celem tych checks jest ustalenie, czy podniesienie uprawnień w czasie exec jest zablokowane oraz czy image nadal zawiera helpery, które miałyby znaczenie, gdyby nie było.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Co jest tutaj interesujące:

- `NoNewPrivs: 1` jest zwykle bezpieczniejszym wynikiem.
- `NoNewPrivs: 0` oznacza, że ścieżki eskalacji oparte na setuid i file-cap nadal mają znaczenie.
- `NoNewPrivs: 1` plus `Seccomp: 2` to częsty znak bardziej świadomego podejścia do hardeningu.
- Manifest Kubernetes, który mówi `allowPrivilegeEscalation: false`, jest przydatny, ale stan kernela jest źródłem prawdy.
- Minimalny obraz z niewielką liczbą binarek setuid/file-cap albo bez nich daje atakującemu mniej opcji post-exploitation, nawet gdy `no_new_privs` jest brak.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges=true`; daemon-wide default also exists via `dockerd --no-new-privileges` | pominięcie flagi, `--privileged` |
| Podman | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges` or equivalent security configuration | pominięcie opcji, `--privileged` |
| Kubernetes | Controlled by workload policy | `allowPrivilegeEscalation: false` requests the effect, but `privileged: true` and `CAP_SYS_ADMIN` keep it effectively true | `allowPrivilegeEscalation: true`, `privileged: true`, dodanie `CAP_SYS_ADMIN` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes workload settings / OCI `process.noNewPrivileges` | Usually inherited from the Pod security context and translated into OCI runtime config | same as Kubernetes row |

Ta ochrona często jest nieobecna po prostu dlatego, że nikt jej nie włączył, a nie dlatego, że runtime jej nie obsługuje.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
