# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` to funkcja hardeningu kernela, która uniemożliwia procesowi uzyskanie większych uprawnień podczas `execve()`. W praktyce po ustawieniu tej flagi uruchomienie pliku setuid, pliku setgid lub pliku z Linux file capabilities nie nadaje dodatkowych uprawnień ponad te, które proces już posiadał. W środowiskach kontenerowych jest to istotne, ponieważ wiele łańcuchów privilege-escalation opiera się na znalezieniu w obrazie pliku wykonywalnego, który zmienia uprawnienia po uruchomieniu.

Z defensywnego punktu widzenia `no_new_privs` nie zastępuje namespaces, seccomp ani usuwania capabilities. Jest warstwą wzmacniającą ochronę. Blokuje określoną klasę kolejnych eskalacji po uzyskaniu code execution. Dzięki temu jest szczególnie przydatna w środowiskach, w których obrazy zawierają pomocnicze pliki wykonywalne, artefakty package-managerów lub starsze narzędzia, które w połączeniu z częściowym przejęciem mogłyby być niebezpieczne.

## Działanie

Flaga kernela odpowiadająca za to zachowanie to `PR_SET_NO_NEW_PRIVS`. Po ustawieniu jej dla procesu kolejne wywołania `execve()` nie mogą zwiększyć uprawnień. Istotny szczegół polega na tym, że proces nadal może uruchamiać pliki wykonywalne; nie może jednak używać tych plików do przekroczenia granicy uprawnień, którą kernel w innym przypadku by zaakceptował.<sup>[[1]](#references)</sup>

Zachowanie kernela jest również **dziedziczone i nieodwracalne**: po ustawieniu przez task `no_new_privs` bit jest dziedziczony przez `fork()`, `clone()` i `execve()` i nie można go później wyłączyć.<sup>[[1]](#references)</sup> Jest to przydatne podczas assessmentów, ponieważ pojedyncze `NoNewPrivs: 1` w procesie kontenera zwykle oznacza, że procesy potomne również powinny działać w tym trybie, chyba że analizujesz całkowicie inną hierarchię procesów.

W środowiskach ukierunkowanych na Kubernetes `allowPrivilegeEscalation: false` odwzorowuje to zachowanie dla procesu kontenera.<sup>[[2]](#references)</sup> W runtime’ach w stylu Docker i Podman odpowiednik jest zwykle włączany jawnie za pomocą opcji bezpieczeństwa. Na poziomie OCI ta sama koncepcja występuje jako `process.noNewPrivileges`.

## Istotne niuanse

`no_new_privs` blokuje uzyskanie uprawnień **w czasie exec**, ale nie każdą zmianę uprawnień.<sup>[[1]](#references)</sup> W szczególności:

- przejścia setuid i setgid przestają działać podczas `execve()`
- file capabilities nie są dodawane do zbioru permitted podczas `execve()`
- LSM-y, takie jak AppArmor lub SELinux, nie łagodzą ograniczeń po `execve()`
- uprawnienia już posiadane nadal pozostają posiadanymi uprawnieniami

Ostatni punkt ma znaczenie operacyjne. Jeśli proces już działa jako root, już posiada niebezpieczną capability albo ma już dostęp do potężnego runtime API lub zapisywalnego host mount, ustawienie `no_new_privs` nie neutralizuje tych zagrożeń. Usuwa tylko jeden częsty **kolejny krok** w łańcuchu privilege-escalation.

Należy również pamiętać, że flaga nie blokuje zmian uprawnień, które nie zależą od `execve()`.<sup>[[1]](#references)</sup> Na przykład task, który ma już wystarczające uprawnienia, nadal może bezpośrednio wywołać `setuid(2)` albo otrzymać uprzywilejowany file descriptor przez Unix socket. Dlatego `no_new_privs` należy analizować razem z [seccomp](seccomp.md), zbiorami capabilities i ekspozycją namespaces, a nie traktować jako samodzielnego rozwiązania.

## Laboratorium

Sprawdź stan bieżącego procesu:
```bash
grep NoNewPrivs /proc/self/status
```
Porównaj to z kontenerem, w którym runtime włącza flagę:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
W odpowiednio zabezpieczonym workloadzie wynik powinien wskazywać `NoNewPrivs: 1`.

Możesz również zademonstrować rzeczywisty efekt na pliku binarnym setuid:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Punkt porównania nie polega na tym, że `su` jest zawsze możliwe do wykorzystania. Chodzi o to, że ten sam image może zachowywać się zupełnie inaczej w zależności od tego, czy `execve()` nadal może przekraczać granicę uprawnień.

## Wpływ na bezpieczeństwo

Jeśli `no_new_privs` nie jest ustawione, uzyskany dostęp do kontenera może nadal zostać podniesiony za pomocą helperów setuid lub plików binarnych z file capabilities. Jeśli jest ustawione, takie zmiany uprawnień po wykonaniu procesu zostają zablokowane. Efekt ten ma szczególne znaczenie w przypadku rozbudowanych base images, które zawierają wiele narzędzi, których aplikacja nigdy nie potrzebowała.

Istnieje również ważna interakcja z seccomp. Zadania bez uprawnień zazwyczaj muszą mieć ustawione `no_new_privs`, zanim będą mogły zainstalować filtr seccomp w trybie filter.<sup>[[1]](#references)</sup> To jeden z powodów, dla których hardened containers często mają jednocześnie włączone `Seccomp` i `NoNewPrivs`. Z perspektywy attackera obecność obu zwykle oznacza, że środowisko zostało skonfigurowane celowo, a nie przypadkowo.

## Błędne konfiguracje

Najczęstszym problemem jest po prostu niewłączenie tego mechanizmu w środowiskach, w których byłby kompatybilny. W Kubernetes pozostawienie włączonego `allowPrivilegeEscalation` jest często domyślnym błędem operacyjnym. W Docker i Podman pominięcie odpowiedniej opcji bezpieczeństwa daje ten sam efekt. Innym często występującym błędem jest założenie, że skoro kontener nie jest „privileged”, przejścia uprawnień podczas `exec` automatycznie nie mają znaczenia.

Bardziej subtelny problem w Kubernetes polega na tym, że `allowPrivilegeEscalation: false` **nie jest respektowane w oczekiwany sposób**, gdy kontener jest `privileged` lub ma `CAP_SYS_ADMIN`. Dokumentacja Kubernetes API wskazuje, że w takich przypadkach `allowPrivilegeEscalation` jest efektywnie zawsze ustawione na true.<sup>[[2]](#references)</sup> W praktyce oznacza to, że to pole należy traktować jako jeden z sygnałów opisujących końcowy poziom zabezpieczeń, a nie jako gwarancję, że runtime ostatecznie ustawił `NoNewPrivs: 1`.

## Nadużycie

Jeśli `no_new_privs` nie jest ustawione, pierwsze pytanie brzmi: czy image zawiera pliki binarne, które nadal mogą podnosić uprawnienia:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interesujące wyniki obejmują:

- `NoNewPrivs: 0`
- helpery setuid, takie jak `su`, `mount`, `passwd` lub narzędzia administracyjne specyficzne dla danej dystrybucji
- pliki binarne z capabilities plików, które przyznają uprawnienia do sieci lub systemu plików

W rzeczywistym assessment te ustalenia same w sobie nie dowodzą skutecznej eskalacji, ale dokładnie wskazują pliki binarne, które warto przetestować w następnej kolejności.

W Kubernetes należy również sprawdzić, czy założenia YAML odpowiadają rzeczywistości kernela:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Ciekawe kombinacje obejmują:

- `allowPrivilegeEscalation: false` w specyfikacji Pod, ale `NoNewPrivs: 0` w kontenerze
- obecność `cap_sys_admin`, co sprawia, że pole Kubernetes jest znacznie mniej wiarygodne
- `Seccomp: 0` i `NoNewPrivs: 0`, co zwykle wskazuje na ogólnie osłabioną konfigurację runtime, a nie pojedynczy odizolowany błąd

### Pełny przykład: eskalacja uprawnień w kontenerze przez setuid

Ta kontrola zwykle zapobiega **eskalacji uprawnień w kontenerze**, a nie bezpośredniemu ucieczki z hosta. Jeśli `NoNewPrivs` wynosi `0`, a istnieje helper setuid, przetestuj go jawnie:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Jeśli znany plik binarny setuid jest obecny i działa poprawnie, spróbuj uruchomić go w sposób zachowujący zmianę poziomu uprawnień:
```bash
/bin/su -c id 2>/dev/null
```
Samo w sobie nie powoduje to ucieczki z kontenera, ale może przekształcić foothold z niskimi uprawnieniami wewnątrz kontenera w uprawnienia container-root, co często staje się warunkiem wstępnym późniejszej ucieczki na hosta przez mounty, sockety runtime lub interfejsy komunikujące się z kernelem.

## Checks

Celem tych checks jest ustalenie, czy uzyskanie uprawnień w czasie exec jest zablokowane oraz czy obraz nadal zawiera helpery, które miałyby znaczenie, gdyby nie było zablokowane.
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
- `NoNewPrivs: 0` oznacza, że ścieżki eskalacji oparte na setuid i file-cap nadal są istotne.
- `NoNewPrivs: 1` wraz z `Seccomp: 2` jest częstym oznakiem bardziej celowego podejścia do hardeningu.
- Manifest Kubernetes zawierający `allowPrivilegeEscalation: false` jest przydatny, ale status kernela jest źródłem prawdy.
- Minimalny image z niewielką liczbą plików binarnych setuid/file-cap lub bez nich daje attackerowi mniej opcji post-exploitation, nawet gdy brakuje `no_new_privs`.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Częste ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie wyłączone | Włączane jawnie za pomocą `--security-opt no-new-privileges=true`; istnieje również domyślne ustawienie dla całego daemona za pomocą `dockerd --no-new-privileges` | pominięcie flagi, `--privileged` |
| Podman | Domyślnie wyłączone | Włączane jawnie za pomocą `--security-opt no-new-privileges` lub równoważnej konfiguracji security | pominięcie opcji, `--privileged` |
| Kubernetes | Kontrolowane przez policy workloadu | `allowPrivilegeEscalation: false` żąda tego efektu, ale `privileged: true` i `CAP_SYS_ADMIN` sprawiają, że pozostaje on efektywnie włączony | `allowPrivilegeEscalation: true`, `privileged: true`, dodanie `CAP_SYS_ADMIN` |
| containerd / CRI-O w Kubernetes | Zgodne z ustawieniami workloadu Kubernetes / OCI `process.noNewPrivileges` | Zazwyczaj dziedziczone z security context Poda i tłumaczone na konfigurację OCI runtime | tak samo jak w wierszu Kubernetes |

Ta ochrona często nie występuje po prostu dlatego, że nikt jej nie włączył, a nie dlatego, że runtime nie obsługuje tej funkcji.

## References

- [1] [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
