# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` to funkcja hardeningu kernela, która uniemożliwia procesowi uzyskanie większych uprawnień podczas `execve()`. W praktyce po ustawieniu tej flagi uruchomienie pliku binarnego setuid, pliku binarnego setgid lub pliku z Linux file capabilities nie nadaje dodatkowych uprawnień wykraczających poza te, które proces już posiadał. W środowiskach kontenerowych jest to istotne, ponieważ wiele łańcuchów privilege-escalation opiera się na znalezieniu w obrazie pliku wykonywalnego, który zmienia uprawnienia po uruchomieniu.

Z defensywnego punktu widzenia `no_new_privs` nie zastępuje namespaces, seccomp ani capability dropping. Jest warstwą wzmacniającą ochronę. Blokuje konkretną klasę kolejnych eskalacji po uzyskaniu code execution. Dzięki temu jest szczególnie wartościowa w środowiskach, w których obrazy zawierają helper binaries, artefakty package-managerów lub starsze narzędzia, które w połączeniu z częściowym przejęciem byłyby niebezpieczne.

## Działanie

Flaga kernela stojąca za tym zachowaniem to `PR_SET_NO_NEW_PRIVS`. Po jej ustawieniu dla procesu kolejne wywołania `execve()` nie mogą zwiększyć uprawnień. Istotny szczegół polega na tym, że proces nadal może uruchamiać pliki binarne; nie może jednak używać ich do przekroczenia granicy uprawnień, którą kernel w innym przypadku by honorował.

Zachowanie kernela jest również **dziedziczone i nieodwracalne**: po ustawieniu przez task `no_new_privs` bit jest dziedziczony przez `fork()`, `clone()` i `execve()` i nie można go później wyłączyć. Jest to przydatne podczas assessments, ponieważ pojedyncze `NoNewPrivs: 1` na procesie kontenera zwykle oznacza, że procesy potomne również powinny działać w tym trybie, chyba że analizujesz całkowicie inne drzewo procesów.

W środowiskach zorientowanych na Kubernetes `allowPrivilegeEscalation: false` odwzorowuje to zachowanie dla procesu kontenera. W runtime'ach w stylu Docker i Podman odpowiednik jest zwykle włączany jawnie za pomocą security option. Na poziomie OCI ta sama koncepcja występuje jako `process.noNewPrivileges`.

## Ważne niuanse

`no_new_privs` blokuje uzyskiwanie uprawnień **w czasie exec**, ale nie każdą zmianę uprawnień. W szczególności:

- przejścia setuid i setgid przestają działać podczas `execve()`
- file capabilities nie są dodawane do permitted set podczas `execve()`
- LSM-y, takie jak AppArmor lub SELinux, nie łagodzą ograniczeń po `execve()`
- już posiadane uprawnienia nadal pozostają posiadanymi uprawnieniami

Ostatni punkt ma znaczenie operacyjne. Jeśli proces już działa jako root, ma już niebezpieczną capability albo ma już dostęp do potężnego runtime API lub zapisywalnego host mount, ustawienie `no_new_privs` nie neutralizuje tych zagrożeń. Usuwa tylko jeden z typowych **kolejnych kroków** w łańcuchu privilege-escalation.

Należy również pamiętać, że flaga nie blokuje zmian uprawnień, które nie zależą od `execve()`. Na przykład task, który ma już wystarczające uprawnienia, nadal może bezpośrednio wywołać `setuid(2)` albo otrzymać uprzywilejowany file descriptor przez Unix socket. Dlatego `no_new_privs` należy analizować razem z [seccomp](seccomp.md), capability sets i ekspozycją namespaces, a nie jako samodzielne rozwiązanie.

## Laboratorium

Sprawdź bieżący stan procesu:
```bash
grep NoNewPrivs /proc/self/status
```
Porównaj to z kontenerem, w którym runtime włącza tę flagę:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
W przypadku hardened workload wynik powinien wskazywać `NoNewPrivs: 1`.

Możesz również zademonstrować rzeczywisty efekt na pliku binarnym setuid:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Celem porównania nie jest stwierdzenie, że `su` jest uniwersalnie exploitable. Chodzi o to, że ten sam image może zachowywać się zupełnie inaczej w zależności od tego, czy `execve()` nadal może przekraczać granicę uprawnień.

## Wpływ na bezpieczeństwo

Jeśli `no_new_privs` nie jest ustawione, foothold wewnątrz kontenera może nadal zostać wykorzystany do podniesienia uprawnień za pomocą helperów setuid lub binariów z file capabilities. Jeśli jest ustawione, te zmiany uprawnień po `exec` zostają zablokowane. Efekt ten jest szczególnie istotny w przypadku szerokich base images, które zawierają wiele utilities, których aplikacja nigdy nie potrzebowała.

Istnieje również ważna interakcja z seccomp. Unprivileged tasks zazwyczaj muszą mieć ustawione `no_new_privs`, zanim będą mogły zainstalować filtr seccomp w trybie filter. Jest to jeden z powodów, dla których hardened containers często mają jednocześnie włączone `Seccomp` i `NoNewPrivs`. Z perspektywy attackera obecność obu zwykle oznacza, że środowisko zostało skonfigurowane celowo, a nie przypadkowo.

## Błędne konfiguracje

Najczęstszym problemem jest po prostu niewłączenie tego mechanizmu w środowiskach, w których byłby kompatybilny. W Kubernetes pozostawienie włączonego `allowPrivilegeEscalation` jest często domyślnym błędem operacyjnym. W Docker i Podman pominięcie odpowiedniej security option daje ten sam efekt. Innym powtarzającym się failure mode jest założenie, że skoro kontener nie jest „privileged”, to przejścia uprawnień podczas `exec` automatycznie nie mają znaczenia.

Bardziej subtelny problem w Kubernetes polega na tym, że `allowPrivilegeEscalation: false` **nie jest respektowane w oczekiwany sposób**, gdy kontener jest `privileged` lub ma `CAP_SYS_ADMIN`. Dokumentacja Kubernetes API wskazuje, że w tych przypadkach `allowPrivilegeEscalation` jest efektywnie zawsze ustawione na true. W praktyce oznacza to, że to pole należy traktować jako jeden z sygnałów w finalnej ocenie posture, a nie jako gwarancję, że runtime zakończył działanie z `NoNewPrivs: 1`.

## Abuse

Jeśli `no_new_privs` nie jest ustawione, pierwsze pytanie brzmi: czy image zawiera binaries, które nadal mogą podnosić uprawnienia:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interesujące wyniki obejmują:

- `NoNewPrivs: 0`
- helpery setuid, takie jak `su`, `mount`, `passwd` lub narzędzia administracyjne specyficzne dla danej dystrybucji
- binaria z file capabilities przyznającymi uprawnienia sieciowe lub do systemu plików

W rzeczywistym assessment te ustalenia same w sobie nie dowodzą działającej eskalacji, ale dokładnie wskazują binaria, które warto następnie przetestować.

W Kubernetes należy również sprawdzić, czy założenia YAML odpowiadają rzeczywistości kernela:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Interesujące kombinacje obejmują:

- `allowPrivilegeEscalation: false` w specyfikacji Pod, ale `NoNewPrivs: 0` w kontenerze
- obecność `cap_sys_admin`, co sprawia, że pole Kubernetes jest znacznie mniej wiarygodne
- `Seccomp: 0` i `NoNewPrivs: 0`, co zwykle wskazuje na ogólnie osłabioną konfigurację runtime, a nie pojedynczy odizolowany błąd

### Pełny przykład: eskalacja uprawnień w kontenerze przez setuid

Ta kontrola zwykle zapobiega **eskalacji uprawnień w kontenerze**, a nie bezpośredniemu ucieczce z hosta. Jeśli `NoNewPrivs` ma wartość `0`, a narzędzie setuid jest dostępne, przetestuj je bezpośrednio:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Jeśli znany plik binarny setuid jest obecny i działa poprawnie, spróbuj uruchomić go w sposób zachowujący przejście uprawnień:
```bash
/bin/su -c id 2>/dev/null
```
Nie powoduje to samo w sobie ucieczki z kontenera, ale może przekształcić foothold z niskimi uprawnieniami wewnątrz kontenera w container-root, co często staje się warunkiem wstępnym późniejszego host escape przez mounts, runtime sockets lub interfejsy komunikujące się z kernelem.

## Kontrole

Celem tych kontroli jest ustalenie, czy uzyskanie uprawnień w czasie wykonywania exec jest blokowane oraz czy obraz nadal zawiera helpery, które miałyby znaczenie, gdyby nie było blokowane.
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

- `NoNewPrivs: 1` jest zazwyczaj bezpieczniejszym wynikiem.
- `NoNewPrivs: 0` oznacza, że ścieżki eskalacji oparte na setuid i file-cap pozostają istotne.
- `NoNewPrivs: 1` w połączeniu z `Seccomp: 2` jest częstym oznakiem bardziej celowego podejścia do hardeningu.
- Manifest Kubernetes zawierający `allowPrivilegeEscalation: false` jest przydatny, ale status kernela jest źródłem prawdy.
- Minimalny image zawierający niewiele plików binarnych setuid/file-cap lub nieposiadający ich wcale daje attackerowi mniej opcji po post-exploitation, nawet gdy brakuje `no_new_privs`.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Częste ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie wyłączone | Włączane jawnie za pomocą `--security-opt no-new-privileges=true`; dostępne jest również ustawienie domyślne dla całego daemona za pomocą `dockerd --no-new-privileges` | pominięcie flagi, `--privileged` |
| Podman | Domyślnie wyłączone | Włączane jawnie za pomocą `--security-opt no-new-privileges` lub równoważnej konfiguracji security | pominięcie opcji, `--privileged` |
| Kubernetes | Kontrolowane przez politykę workloadu | `allowPrivilegeEscalation: false` żąda tego efektu, ale `privileged: true` i `CAP_SYS_ADMIN` sprawiają, że pozostaje on efektywnie włączony | `allowPrivilegeEscalation: true`, `privileged: true`, dodanie `CAP_SYS_ADMIN` |
| containerd / CRI-O w Kubernetes | Zgodne z ustawieniami workloadu Kubernetes / OCI `process.noNewPrivileges` | Zazwyczaj dziedziczone z security context Pod i tłumaczone na konfigurację OCI runtime | tak samo jak w wierszu Kubernetes |

Ta ochrona często nie występuje po prostu dlatego, że nikt jej nie włączył, a nie dlatego, że runtime nie obsługuje tej funkcji.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
